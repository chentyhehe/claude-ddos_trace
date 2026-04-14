"""
DDoS 攻击溯源分析器 - 主编排器

本模块是整个溯源分析系统的核心编排层，串联以下流水线阶段:

    Phase 0: 数据加载与预处理
        → 从 ClickHouse 加载 NetFlow 原始数据，进行时间解析和类型转换
    Phase 1: 特征工程
        → 按源 IP 聚合提取 30+ 维攻击指纹特征
    Phase 1.5: 基线建模
        → 基于正常流量统计量计算动态阈值
    Phase 2: 异常源检测
        → 多因子加权评分，将源 IP 分为 confirmed/suspicious/borderline/background
    Phase 3: 指纹聚类
        → 对异常源进行聚类，识别同一僵尸网络的攻击团伙
    Phase 4: 攻击路径重构
        → 分析入口路由器、地理来源、监测对象关联、时间分布
    Phase 5: 报告生成与导出
        → 生成文字报告、CSV 文件和雷达图

支持三种入口模式:
    1. 基于告警 ID（推荐）: 自动获取目标、阈值、时间窗口
    2. 基于攻击目标: 从告警表匹配，兜底使用默认阈值
    3. 手动传参: 直接指定目标IP和参数（兼容旧接口）

核心类:
    DDoSTracebackAnalyzer: 分析器主类
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd

from ddos_trace.config.models import (
    ClickHouseConfig,
    ThresholdConfig,
    TracebackConfig,
)
from ddos_trace.data.alert_loader import AlertLoader, AttackContext
from ddos_trace.data.loader import ClickHouseLoader, DataPreprocessor
from ddos_trace.features.extraction import FeatureExtractor
from ddos_trace.detection.anomaly import AnomalyDetector, TrafficBaseline
from ddos_trace.clustering.fingerprint import AttackFingerprintClusterer
from ddos_trace.traceback.path import AttackPathReconstructor
from ddos_trace.reports.generator import ReportGenerator


def _build_file_tag(
    attack_id: Optional[str] = None,
    target_ips: Optional[List[str]] = None,
) -> str:
    """
    构建输出文件的标识标签，防止多次分析的输出文件互相覆盖。

    规则:
    - 有 attack_id 时: _{attack_id}
    - 无 attack_id 但有 target_ips 时: _{第一个IP}_{当前时间戳}
    - 都没有时: _{当前时间戳}

    Examples:
        _ATK-20260401-001
        _192.168.1.100_20260414_163500
        _20260414_163500
    """
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    if attack_id:
        return f"_{attack_id}"
    if target_ips:
        safe_ip = target_ips[0].replace(".", "-")
        return f"_{safe_ip}_{now_str}"
    return f"_{now_str}"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class DDoSTracebackAnalyzer:
    """
    DDoS 攻击溯源分析器

    支持三种入口:
    1. 基于告警 ID: run_analysis_by_alert(attack_id)
       → 自动从告警表获取目标IP、阈值、时间窗口（推荐方式）
    2. 基于攻击目标: run_analysis_by_target(attack_target)
       → 从告警表匹配目标，获取阈值；若未找到则使用配置默认值
    3. 手动传参: run_full_analysis(target_ips, target_mo_codes, start_time, end_time)
       → 使用配置文件中的默认阈值（兼容旧接口）
    """

    def __init__(
        self,
        threshold_config: Optional[ThresholdConfig] = None,
        traceback_config: Optional[TracebackConfig] = None,
        clickhouse_config: Optional[ClickHouseConfig] = None,
        output_dir: str = ".",
    ):
        """
        初始化分析器，创建各处理模块的实例

        Args:
            threshold_config: 阈值配置，None 时使用默认值
            traceback_config: 溯源配置，None 时使用默认值
            clickhouse_config: ClickHouse 连接配置，None 时使用默认值
            output_dir: 报告输出目录
        """
        self.threshold_config = threshold_config or ThresholdConfig()
        self.traceback_config = traceback_config or TracebackConfig()
        self.clickhouse_config = clickhouse_config or ClickHouseConfig()
        self.output_dir = output_dir

        # 初始化各流水线阶段的处理器
        # 这些模块按 Phase 0~5 顺序串联执行
        self._loader = ClickHouseLoader(self.clickhouse_config)       # Phase 0: 数据加载
        self._preprocessor = DataPreprocessor()                        # Phase 0: 数据预处理
        self._alert_loader = AlertLoader(self.clickhouse_config)       # 告警上下文加载
        self._extractor = FeatureExtractor()                           # Phase 1: 特征提取
        self._baseline = TrafficBaseline(self.threshold_config, self.traceback_config)  # Phase 1.5: 基线
        self._detector = AnomalyDetector(self.threshold_config, self.traceback_config)  # Phase 2: 异常检测
        self._clusterer = AttackFingerprintClusterer(self.traceback_config)              # Phase 3: 聚类
        self._reconstructor = AttackPathReconstructor()                # Phase 4: 路径重构
        self._reporter = ReportGenerator(self.output_dir)              # Phase 5: 报告生成

    # ------------------------------------------------------------------
    # 入口1: 基于告警 ID 分析（推荐）
    # ------------------------------------------------------------------

    def run_analysis_by_alert(self, attack_id: str) -> Dict:
        """
        通过告警 ID 执行溯源分析（推荐入口）

        自动从告警表获取: target_ips、阈值、时间窗口、攻击类型，
        无需用户手动指定任何参数。

        Args:
            attack_id: 告警系统生成的攻击ID（如 "ATK-20260401-001"）

        Returns:
            包含所有分析结果的字典:
            - attack_context: 攻击上下文（AttackContext 对象）
            - features: 完整的特征 DataFrame（含分类标签）
            - traffic_classification: 仅分类结果的 DataFrame
            - anomaly_sources: 仅异常源（confirmed + suspicious）的 DataFrame
            - clusters: 聚类报告 DataFrame（可能为 None）
            - path_analysis: 路径分析结果字典
            - effective_thresholds: 有效阈值
            - baseline_stats: 基线统计量
            - report: 文字分析报告文本
        """
        logger.info("=" * 60)
        logger.info("DDoS 攻击溯源分析器 - 告警驱动模式")
        logger.info("attack_id: %s", attack_id)
        logger.info("=" * 60)

        # 1. 从告警表加载上下文
        ctx = self._alert_loader.load_by_attack_id(attack_id)
        if ctx is None:
            logger.error("未找到告警记录 / attack_id[%s]", attack_id)
            return {"error": f"未找到告警记录: attack_id={attack_id}"}

        logger.info(
            "[ALERT] 告警上下文 / target[%s] / type[%s] / "
            "threshold_pps[%s] / threshold_bps[%s] / "
            "attack_types%s / time[%s ~ %s]",
            ctx.attack_target, ctx.attack_target_type,
            ctx.threshold_pps, ctx.threshold_bps,
            ctx.attack_types, ctx.start_time, ctx.end_time,
        )

        # 2. 使用告警阈值覆盖配置阈值
        # 告警表中的阈值更准确（由告警系统根据历史基线动态计算）
        pps_threshold = int(ctx.get_pps_threshold(self.threshold_config.pps_threshold))
        bps_threshold = int(ctx.get_bps_threshold(self.threshold_config.bps_threshold))

        # 检测阈值来源：如果告警表未提供阈值，记录 warning
        if ctx.threshold_pps is None and ctx.threshold_bps is None:
            logger.warning(
                "[ALERT] 告警表缺少阈值信息，使用配置默认值 / "
                "pps[%d] / bps[%d] / 请检查告警表 threshold 和 threshold_unit 字段",
                pps_threshold, bps_threshold,
            )

        effective_threshold = ThresholdConfig(
            pps_threshold=pps_threshold,
            bps_threshold=bps_threshold,
        )
        # 临时创建使用告警阈值的基线和检测器实例
        # 不修改 self._baseline/_detector，保证下次调用仍使用原始配置
        baseline = TrafficBaseline(effective_threshold, self.traceback_config)
        detector = AnomalyDetector(effective_threshold, self.traceback_config)

        # 3. 加载 NetFlow 数据
        raw_df = self._load_data(
            target_ips=ctx.target_ips or None,
            target_mo_codes=ctx.target_mo_codes or None,
            start_time=ctx.start_time,
            end_time=ctx.end_time,
        )
        if raw_df.empty:
            return {"error": "查询结果为空", "attack_context": ctx}

        # 4. 特征工程
        features = self._extract_features(raw_df)

        # 5. 基线建模（使用告警阈值）
        eff_thresholds, baseline_stats = baseline.compute(features)

        # 6. 异常检测（使用告警阈值）
        features = detector.detect(features, baseline_stats, eff_thresholds)

        # 7. 指纹聚类
        anomaly_sources = features[features["traffic_class"].isin(["confirmed", "suspicious"])]
        cluster_report = self._cluster_fingerprints(anomaly_sources)

        # 8. 路径重构
        path_analysis = self._reconstruct_path(raw_df, features)

        # 9. 报告生成（用 attack_id 标识输出文件）
        file_tag = _build_file_tag(attack_id=attack_id)
        report = self._generate_reports(
            features, cluster_report, path_analysis, eff_thresholds, file_tag,
            raw_df=raw_df,
        )

        result = {
            "attack_context": ctx,
            "features": features,
            "traffic_classification": features[["traffic_class", "attack_confidence", "confidence_reasons"]],
            "anomaly_sources": anomaly_sources,
            "clusters": cluster_report,
            "path_analysis": path_analysis,
            "effective_thresholds": eff_thresholds,
            "baseline_stats": baseline_stats,
            "report": report,
        }

        logger.info("=" * 60)
        logger.info("DDoS 攻击溯源分析器 - 分析完成")
        logger.info("=" * 60)
        return result

    # ------------------------------------------------------------------
    # 入口2: 基于攻击目标 + 时间范围
    # ------------------------------------------------------------------

    def run_analysis_by_target(
        self,
        attack_target: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict:
        """
        通过攻击目标执行溯源分析

        自动从告警表匹配目标，获取阈值和攻击类型信息。
        若未找到告警记录，则使用配置文件中的默认阈值。

        Args:
            attack_target: 攻击目标（IP 地址或监测对象编码）
            start_time: 可选的开始时间，不传则使用告警时间窗口
            end_time: 可选的结束时间

        Returns:
            包含所有分析结果的字典（结构同 run_analysis_by_alert）
        """
        logger.info("=" * 60)
        logger.info("DDoS 攻击溯源分析器 - 目标驱动模式")
        logger.info("attack_target: %s", attack_target)
        logger.info("=" * 60)

        ctx = self._alert_loader.load_by_target(attack_target, start_time, end_time)
        if ctx is None:
            # 未找到告警记录：创建最小化的 AttackContext，使用默认阈值
            logger.warning("未找到告警记录，使用配置文件默认阈值")
            ctx = AttackContext(
                attack_target=attack_target,
                target_ips=[attack_target],
                start_time=start_time,
                end_time=end_time,
            )

        # 优先使用用户传入的时间，其次使用告警时间窗口
        actual_start = start_time or ctx.start_time
        actual_end = end_time or ctx.end_time

        effective_threshold = ThresholdConfig(
            pps_threshold=int(ctx.get_pps_threshold(self.threshold_config.pps_threshold)),
            bps_threshold=int(ctx.get_bps_threshold(self.threshold_config.bps_threshold)),
        )

        raw_df = self._load_data(
            target_ips=ctx.target_ips or [attack_target],
            target_mo_codes=ctx.target_mo_codes or None,
            start_time=actual_start,
            end_time=actual_end,
        )
        if raw_df.empty:
            return {"error": "查询结果为空", "attack_context": ctx}

        features = self._extract_features(raw_df)
        baseline = TrafficBaseline(effective_threshold, self.traceback_config)
        detector = AnomalyDetector(effective_threshold, self.traceback_config)

        eff_thresholds, baseline_stats = baseline.compute(features)
        features = detector.detect(features, baseline_stats, eff_thresholds)

        anomaly_sources = features[features["traffic_class"].isin(["confirmed", "suspicious"])]
        cluster_report = self._cluster_fingerprints(anomaly_sources)
        path_analysis = self._reconstruct_path(raw_df, features)
        file_tag = _build_file_tag(
            attack_id=ctx.attack_id,
            target_ips=ctx.target_ips or [attack_target],
        )
        report = self._generate_reports(
            features, cluster_report, path_analysis, eff_thresholds, file_tag,
            raw_df=raw_df,
        )

        logger.info("=" * 60)
        logger.info("DDoS 攻击溯源分析器 - 分析完成")
        logger.info("=" * 60)

        return {
            "attack_context": ctx,
            "features": features,
            "traffic_classification": features[["traffic_class", "attack_confidence", "confidence_reasons"]],
            "anomaly_sources": anomaly_sources,
            "clusters": cluster_report,
            "path_analysis": path_analysis,
            "effective_thresholds": eff_thresholds,
            "baseline_stats": baseline_stats,
            "report": report,
        }

    # ------------------------------------------------------------------
    # 入口3: 手动传参（兼容旧接口）
    # ------------------------------------------------------------------

    def run_full_analysis(
        self,
        target_ips: Optional[List[str]] = None,
        target_mo_codes: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict:
        """
        手动传参执行溯源分析（使用配置文件中的默认阈值，兼容旧接口）

        Args:
            target_ips: 目的IP列表
            target_mo_codes: 目的监测对象编码列表
            start_time: 开始时间
            end_time: 结束时间

        Returns:
            包含所有分析结果的字典（不含 attack_context）
        """
        logger.info("=" * 60)
        logger.info("DDoS 攻击溯源分析器 - 手动模式")
        logger.info("=" * 60)

        raw_df = self._load_data(target_ips, target_mo_codes, start_time, end_time)
        if raw_df.empty:
            return {"error": "查询结果为空"}

        features = self._extract_features(raw_df)
        effective_thresholds, baseline_stats = self._compute_baseline(features)
        features = self._detect_anomalies(features, baseline_stats, effective_thresholds)

        anomaly_sources = features[features["traffic_class"].isin(["confirmed", "suspicious"])]
        cluster_report = self._cluster_fingerprints(anomaly_sources)
        path_analysis = self._reconstruct_path(raw_df, features)
        file_tag = _build_file_tag(target_ips=target_ips)
        report = self._generate_reports(
            features, cluster_report, path_analysis, effective_thresholds, file_tag,
            raw_df=raw_df,
        )

        return {
            "features": features,
            "traffic_classification": features[["traffic_class", "attack_confidence", "confidence_reasons"]],
            "anomaly_sources": anomaly_sources,
            "clusters": cluster_report,
            "path_analysis": path_analysis,
            "effective_thresholds": effective_thresholds,
            "baseline_stats": baseline_stats,
            "report": report,
        }

    # ------------------------------------------------------------------
    # 各阶段封装方法（Phase 0 ~ Phase 5）
    # ------------------------------------------------------------------

    def _load_data(
        self,
        target_ips: Optional[List[str]],
        target_mo_codes: Optional[List[str]],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> pd.DataFrame:
        """
        Phase 0: 数据加载与预处理

        从 ClickHouse 查询 NetFlow 原始数据，执行时间解析和类型转换。
        """
        logger.info("[Phase 0] 数据加载与过滤")
        raw_df = self._loader.load_data(target_ips, target_mo_codes, start_time, end_time)
        raw_df = self._preprocessor.process(raw_df)
        return raw_df

    def _extract_features(self, raw_df: pd.DataFrame) -> pd.DataFrame:
        """Phase 1: 特征工程 — 按 src_ip_addr 聚合提取多维特征"""
        logger.info("[Phase 1] 特征工程")
        return self._extractor.extract(raw_df)

    def _compute_baseline(self, features: pd.DataFrame):
        """Phase 1.5: 流量基线建模 — 计算正常流量统计量和动态阈值"""
        logger.info("[Phase 1.5] 流量基线建模")
        return self._baseline.compute(features)

    def _detect_anomalies(self, features, baseline_stats, effective_thresholds):
        """Phase 2: 异常源检测 — 多因子评分和四级分类"""
        logger.info("[Phase 2] 异常源检测")
        return self._detector.detect(features, baseline_stats, effective_thresholds)

    def _cluster_fingerprints(self, anomaly_sources: pd.DataFrame):
        """Phase 3: 攻击指纹聚类 — 三级算法降级策略"""
        logger.info("[Phase 3] 攻击指纹聚类")
        if len(anomaly_sources) < self.traceback_config.min_cluster_size:
            logger.info("异常源数量[%d]不足，跳过聚类", len(anomaly_sources))
            return None
        return self._clusterer.cluster(anomaly_sources)

    def _reconstruct_path(self, raw_df: pd.DataFrame, features: pd.DataFrame):
        """Phase 4: 攻击路径重构 — 入口路由器/地理/监测对象/时间分析"""
        logger.info("[Phase 4] 攻击路径重构")
        return self._reconstructor.reconstruct(raw_df, features)

    def _generate_reports(self, features, cluster_report, path_analysis,
                          effective_thresholds, file_tag="", raw_df=None):
        """Phase 5: 报告生成与导出 — 文字报告 + CSV + 雷达图 + 威胁情报"""
        logger.info("[Phase 5] 报告生成与导出")
        report_text = self._reporter.generate_text_report(
            features, cluster_report, path_analysis, effective_thresholds
        )
        self._reporter.export_traffic_classification_csv(features, file_tag=file_tag)
        self._reporter.export_cluster_report_csv(cluster_report, file_tag=file_tag)
        self._reporter.plot_cluster_radar_chart(cluster_report, file_tag=file_tag)
        # 威胁情报输出: 攻击源黑名单 + 攻击时间线
        self._reporter.export_attack_blacklist_csv(features, cluster_report, file_tag=file_tag)
        self._reporter.export_attack_timeline_csv(
            path_analysis, raw_df=raw_df, features=features, file_tag=file_tag,
        )
        return report_text
