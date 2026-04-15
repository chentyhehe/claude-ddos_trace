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
    MySQLConfig,
    ThresholdConfig,
    TracebackConfig,
)
from ddos_trace.data.alert_loader import AlertLoader, AttackContext
from ddos_trace.data.loader import ClickHouseLoader, DataPreprocessor
from ddos_trace.data.mysql_loader import ThresholdLoader, filter_flows_by_attack_type, get_attack_type_matching_rules
from ddos_trace.config.models import MonitorThreshold
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
        mysql_config: Optional[MySQLConfig] = None,
        output_dir: str = ".",
        csv_path: str = "",
    ):
        """
        初始化分析器，创建各处理模块的实例

        Args:
            threshold_config: 阈值配置，None 时使用默认值
            traceback_config: 溯源配置，None 时使用默认值
            clickhouse_config: ClickHouse 连接配置，None 时使用默认值
            mysql_config: MySQL 阈值配置数据库连接，None 时使用默认值
            output_dir: 报告输出目录
            csv_path: 攻击类型定义 CSV 降级文件路径
        """
        self.threshold_config = threshold_config or ThresholdConfig()
        self.traceback_config = traceback_config or TracebackConfig()
        self.clickhouse_config = clickhouse_config or ClickHouseConfig()
        self.mysql_config = mysql_config or MySQLConfig()
        self.output_dir = output_dir

        # 初始化各流水线阶段的处理器
        # 这些模块按 Phase 0~5 顺序串联执行
        self._loader = ClickHouseLoader(self.clickhouse_config)       # Phase 0: 数据加载
        self._preprocessor = DataPreprocessor()                        # Phase 0: 数据预处理
        self._alert_loader = AlertLoader(self.clickhouse_config)       # 告警上下文加载
        self._threshold_loader = ThresholdLoader(self.mysql_config, csv_path=csv_path)
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

        主流程: 加载告警上下文 → 加载全量 Flow → 加载攻击类型定义/阈值
        → 按攻击类型分项分析（特征→基线→检测→聚类→路径）
        → 聚合总览 → 报告生成

        Args:
            attack_id: 告警系统生成的攻击ID（如 "ATK-20260401-001"）

        Returns:
            包含所有分析结果的字典:
            - attack_context: 攻击上下文（AttackContext 对象）
            - per_type_results: 各攻击类型的分析结果
            - overview: 从分项结果聚合的总览统计
            - report: 文字分析报告文本
            以及向后兼容的聚合字段（features, anomaly_sources, clusters 等）
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

        # 2. 加载 NetFlow 数据
        raw_df = self._load_data(
            target_ips=ctx.target_ips or None,
            target_mo_codes=ctx.target_mo_codes or None,
            start_time=ctx.start_time,
            end_time=ctx.end_time,
        )
        if raw_df.empty:
            return {"error": "查询结果为空", "attack_context": ctx}

        # 3. 加载攻击类型定义和阈值（MySQL 优先，CSV 降级）
        ip_version = ThresholdLoader.detect_ip_version(ctx.target_ips or [])
        attack_types, monitor_threshold = self._load_attack_type_definitions(
            ctx, ip_version,
        )

        # 4. 按攻击类型分项分析（主流程）
        per_type_results = {}
        if attack_types and monitor_threshold:
            per_type_results = self._run_per_type_analysis(
                raw_df, attack_types, monitor_threshold, ip_version,
            )
        else:
            logger.warning(
                "[ANALYZER] 无攻击类型定义，无法进行分项分析 / "
                "attack_types[%s] / monitor_threshold[%s]",
                attack_types, "有" if monitor_threshold else "无",
            )

        # 5. 从分项结果聚合总览
        overview = self._build_overview_from_per_type(per_type_results, raw_df, ctx)

        # 6. 聚合分项结果为统一视图（向后兼容 + 报告生成）
        agg_features, agg_clusters, agg_path, agg_thresholds = \
            self._aggregate_per_type_results(per_type_results)

        # 7. 报告生成（用 attack_id 标识输出文件）
        file_tag = _build_file_tag(attack_id=attack_id)
        report = self._generate_reports(
            agg_features, agg_clusters, agg_path, agg_thresholds, file_tag,
            raw_df=raw_df, per_type_results=per_type_results,
        )

        # 构建结果（含向后兼容字段）
        anomaly_sources = (
            agg_features[agg_features["traffic_class"].isin(["confirmed", "suspicious"])]
            if not agg_features.empty else pd.DataFrame()
        )

        result = {
            "attack_context": ctx,
            # 新结构: 分项分析
            "per_type_results": per_type_results,
            "overview": overview,
            # 向后兼容: 聚合后的统一视图
            "features": agg_features,
            "traffic_classification": (
                agg_features[["traffic_class", "attack_confidence", "confidence_reasons"]]
                if not agg_features.empty else pd.DataFrame()
            ),
            "anomaly_sources": anomaly_sources,
            "clusters": agg_clusters,
            "path_analysis": agg_path,
            "effective_thresholds": agg_thresholds,
            "baseline_stats": {},
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

        主流程: 加载告警上下文 → 加载全量 Flow → 加载攻击类型定义/阈值
        → 按攻击类型分项分析 → 聚合总览 → 报告生成

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

        # 加载 NetFlow 数据
        raw_df = self._load_data(
            target_ips=ctx.target_ips or [attack_target],
            target_mo_codes=ctx.target_mo_codes or None,
            start_time=actual_start,
            end_time=actual_end,
        )
        if raw_df.empty:
            return {"error": "查询结果为空", "attack_context": ctx}

        # 加载攻击类型定义和阈值
        ip_version = ThresholdLoader.detect_ip_version(ctx.target_ips or [attack_target])
        attack_types, monitor_threshold = self._load_attack_type_definitions(
            ctx, ip_version,
        )

        # 按攻击类型分项分析（主流程）
        per_type_results = {}
        if attack_types and monitor_threshold:
            per_type_results = self._run_per_type_analysis(
                raw_df, attack_types, monitor_threshold, ip_version,
            )

        # 从分项结果聚合总览
        overview = self._build_overview_from_per_type(per_type_results, raw_df, ctx)

        # 聚合分项结果为统一视图
        agg_features, agg_clusters, agg_path, agg_thresholds = \
            self._aggregate_per_type_results(per_type_results)

        # 报告生成
        file_tag = _build_file_tag(
            attack_id=ctx.attack_id,
            target_ips=ctx.target_ips or [attack_target],
        )
        report = self._generate_reports(
            agg_features, agg_clusters, agg_path, agg_thresholds, file_tag,
            raw_df=raw_df, per_type_results=per_type_results,
        )

        anomaly_sources = (
            agg_features[agg_features["traffic_class"].isin(["confirmed", "suspicious"])]
            if not agg_features.empty else pd.DataFrame()
        )

        return {
            "attack_context": ctx,
            "per_type_results": per_type_results,
            "overview": overview,
            "features": agg_features,
            "traffic_classification": (
                agg_features[["traffic_class", "attack_confidence", "confidence_reasons"]]
                if not agg_features.empty else pd.DataFrame()
            ),
            "anomaly_sources": anomaly_sources,
            "clusters": agg_clusters,
            "path_analysis": agg_path,
            "effective_thresholds": agg_thresholds,
            "baseline_stats": {},
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
    # 按攻击类型分项分析
    # ------------------------------------------------------------------

    def _run_per_type_analysis(
        self,
        raw_df: pd.DataFrame,
        attack_types: List[str],
        monitor_threshold: MonitorThreshold,
        ip_version: str,
    ) -> Dict[str, Dict]:
        """
        对每种触发的攻击类型运行完整分析流水线

        对每种攻击类型：
        1. 用匹配规则过滤 flow 子集
        2. 对子集提取特征
        3. 用该类型的 MySQL 阈值进行基线计算和异常检测
        4. 聚类识别该类型下的僵尸网络
        5. 路径重构
        6. 生成分项统计摘要

        Args:
            raw_df: 预处理后的全量 NetFlow DataFrame
            attack_types: 告警触发的攻击类型名称列表
            monitor_threshold: MySQL 加载的监测对象阈值体系
            ip_version: "ipv4" 或 "ipv6"

        Returns:
            {attack_type_name: {分析结果字典}}
        """
        per_type_results: Dict[str, Dict] = {}

        for at_name in attack_types:
            at_name = at_name.strip()
            if not at_name:
                continue

            # 获取该攻击类型的匹配规则定义
            at_info = monitor_threshold.attack_type_info.get(at_name)
            if at_info is None:
                logger.warning(
                    "[PER-TYPE] 攻击类型[%s] 未在 MySQL 定义中找到，跳过",
                    at_name,
                )
                continue

            # 过滤 flow 子集
            type_df = filter_flows_by_attack_type(raw_df, at_info)
            if type_df.empty or len(type_df) < 10:
                logger.info(
                    "[PER-TYPE] 攻击类型[%s] 匹配 flow 数[%d] 过少，跳过",
                    at_name, len(type_df),
                )
                continue

            matching_rules = get_attack_type_matching_rules(at_info)
            logger.info(
                "[PER-TYPE] 攻击类型[%s] / 规则[%s] / flow数[%d] / 占比[%.1f%%]",
                at_name, matching_rules, len(type_df),
                len(type_df) / len(raw_df) * 100,
            )

            # 构建该攻击类型的专用阈值
            type_pps = self.threshold_config.pps_threshold
            type_bps = self.threshold_config.bps_threshold
            type_thresh_dict = monitor_threshold.get_threshold_by_attack_type(
                at_name, ip_version
            )
            if type_thresh_dict:
                type_pps = int(type_thresh_dict["pps_threshold"]) or type_pps
                type_bps = int(type_thresh_dict["bps_threshold"]) or type_bps

            effective_threshold = ThresholdConfig(
                pps_threshold=type_pps,
                bps_threshold=type_bps,
            )

            # 运行完整流水线
            try:
                features = self._extract_features(type_df)

                baseline = TrafficBaseline(
                    effective_threshold, self.traceback_config,
                )
                detector = AnomalyDetector(
                    effective_threshold, self.traceback_config,
                )

                eff_thresholds, baseline_stats = baseline.compute(features)
                features = detector.detect(features, baseline_stats, eff_thresholds)

                anomaly_sources = features[
                    features["traffic_class"].isin(["confirmed", "suspicious"])
                ]
                cluster_report = self._cluster_fingerprints(anomaly_sources)
                path_analysis = self._reconstruct_path(type_df, features)

                # 统计摘要
                summary = self._build_per_type_summary(
                    type_df, features, at_name, at_info,
                    effective_threshold, matching_rules,
                )

                per_type_results[at_name] = {
                    "features": features,
                    "anomaly_sources": anomaly_sources,
                    "clusters": cluster_report,
                    "path_analysis": path_analysis,
                    "effective_thresholds": eff_thresholds,
                    "baseline_stats": baseline_stats,
                    "attack_type_info": at_info,
                    "matching_rules": matching_rules,
                    "flow_count": len(type_df),
                    "flow_pct": round(len(type_df) / len(raw_df) * 100, 1),
                    "threshold_pps": type_pps,
                    "threshold_bps": type_bps,
                    "summary": summary,
                }

                logger.info(
                    "[PER-TYPE] 攻击类型[%s] 分析完成 / 源IP[%d] / confirmed[%d] / suspicious[%d]",
                    at_name, len(features),
                    len(features[features["traffic_class"] == "confirmed"]),
                    len(features[features["traffic_class"] == "suspicious"]),
                )

            except Exception as e:
                logger.error(
                    "[PER-TYPE] 攻击类型[%s] 分析失败 / error[%s]",
                    at_name, e,
                )
                continue

        return per_type_results

    def _build_per_type_summary(
        self,
        type_df: pd.DataFrame,
        features: pd.DataFrame,
        at_name: str,
        at_info: "AttackTypeInfo",
        effective_threshold: ThresholdConfig,
        matching_rules: str,
    ) -> Dict:
        """构建单个攻击类型的统计摘要"""
        confirmed = features[features["traffic_class"] == "confirmed"]
        suspicious = features[features["traffic_class"] == "suspicious"]

        # 流量统计
        total_pps = features["packets_per_sec"].sum() if "packets_per_sec" in features else 0
        total_bps = features["bytes_per_sec"].sum() if "bytes_per_sec" in features else 0

        # Top-5 确认攻击源
        top_ips = []
        if not confirmed.empty and "packets_per_sec" in confirmed.columns:
            top5 = confirmed.nlargest(5, "packets_per_sec")
            for _, row in top5.iterrows():
                top_ips.append({
                    "ip": row.name if isinstance(row.name, str) else str(row.name),
                    "pps": round(row.get("packets_per_sec", 0), 0),
                    "bps": round(row.get("bytes_per_sec", 0), 0),
                    "score": round(row.get("attack_confidence", 0), 1),
                    "country": row.get("country", ""),
                    "province": row.get("province", ""),
                    "isp": row.get("isp", ""),
                })

        return {
            "attack_type": at_name,
            "sub_classify": at_info.sub_classify_type,
            "matching_rules": matching_rules,
            "flow_count": len(type_df),
            "total_pps": round(total_pps, 0),
            "total_bps": round(total_bps, 0),
            "source_ip_count": len(features),
            "confirmed_count": len(confirmed),
            "suspicious_count": len(suspicious),
            "borderline_count": len(features[features["traffic_class"] == "borderline"]),
            "background_count": len(features[features["traffic_class"] == "background"]),
            "confirmed_pps_ratio": round(
                confirmed["packets_per_sec"].sum() / max(total_pps, 1) * 100, 1
            ) if not confirmed.empty and "packets_per_sec" in confirmed.columns else 0,
            "top_attackers": top_ips,
            "threshold_pps": effective_threshold.pps_threshold,
            "threshold_bps": effective_threshold.bps_threshold,
            "exceeds_pps_threshold": total_pps > effective_threshold.pps_threshold,
            "exceeds_bps_threshold": total_bps > effective_threshold.bps_threshold,
        }

    # ------------------------------------------------------------------
    # 攻击类型定义加载 + 结果聚合
    # ------------------------------------------------------------------

    def _load_attack_type_definitions(
        self, ctx: "AttackContext", ip_version: str,
    ) -> tuple:
        """
        加载攻击类型定义和阈值

        加载策略: MySQL 优先 → CSV 降级
        攻击类型列表: 优先使用告警中的类型 → 否则使用所有已定义类型

        Args:
            ctx: 攻击上下文
            ip_version: "ipv4" 或 "ipv6"

        Returns:
            (attack_types_list, monitor_threshold) 元组
        """
        monitor_threshold = None

        # 从 MySQL 加载（含 CSV 降级逻辑）
        if ctx.target_mo_codes:
            mo_code = ctx.target_mo_codes[0]
            monitor_threshold = self._threshold_loader.load_threshold(
                mo_code, ip_version,
            )
            if monitor_threshold is not None:
                logger.info(
                    "[INIT] 攻击类型定义已加载 / mo_code[%s] / "
                    "阈值类型数[%d] / 定义类型数[%d]",
                    mo_code,
                    len(monitor_threshold.attack_thresholds),
                    len(monitor_threshold.attack_type_info),
                )

        # 确定要分析的攻击类型列表
        attack_types = []
        if ctx.attack_types:
            # 优先使用告警中的攻击类型
            attack_types = [t.strip() for t in ctx.attack_types if t.strip()]
        elif monitor_threshold and monitor_threshold.attack_type_info:
            # 无告警类型时，使用所有已定义类型
            attack_types = list(monitor_threshold.attack_type_info.keys())
            logger.info(
                "[INIT] 告警无攻击类型，使用全部已定义类型 / count[%d]",
                len(attack_types),
            )

        if not attack_types:
            logger.warning("[INIT] 无可用的攻击类型定义")

        return attack_types, monitor_threshold

    def _aggregate_per_type_results(
        self, per_type_results: Dict[str, Dict],
    ) -> tuple:
        """
        将分项分析结果聚合为统一视图

        聚合策略:
        - features: 去重合并（同一 IP 取首次出现）
        - clusters: 直接拼接
        - path_analysis: 地理/路由器按维度聚合
        - thresholds: 取各类型最大值

        Args:
            per_type_results: {attack_type: {分析结果}}

        Returns:
            (features_df, cluster_report, path_analysis, effective_thresholds)
        """
        if not per_type_results:
            return (
                pd.DataFrame(),
                None,
                {"geo_distribution": pd.DataFrame(), "entry_routers": pd.DataFrame()},
                {"pps_threshold": 0, "bps_threshold": 0},
            )

        all_features = []
        all_clusters = []
        all_geo = []
        all_routers = []
        max_pps = 0
        max_bps = 0

        for at_name, type_result in per_type_results.items():
            # 特征
            features = type_result.get("features")
            if features is not None and not features.empty:
                all_features.append(features)

            # 聚类
            clusters = type_result.get("clusters")
            if clusters is not None and not clusters.empty:
                all_clusters.append(clusters)

            # 路径
            pa = type_result.get("path_analysis", {})
            geo = pa.get("geo_distribution")
            if geo is not None and not geo.empty:
                all_geo.append(geo)
            routers = pa.get("entry_routers")
            if routers is not None and not routers.empty:
                all_routers.append(routers)

            # 阈值
            max_pps = max(max_pps, type_result.get("threshold_pps", 0))
            max_bps = max(max_bps, type_result.get("threshold_bps", 0))

        # 去重合并特征
        if all_features:
            features = pd.concat(all_features)
            features = features[~features.index.duplicated(keep="first")]
        else:
            features = pd.DataFrame()

        # 拼接聚类
        cluster_report = pd.concat(all_clusters, ignore_index=True) if all_clusters else None

        # 聚合路径分析
        if all_geo:
            geo_df = pd.concat(all_geo).groupby(
                ["src_country", "src_province", "src_city", "src_isp"], as_index=False,
            ).agg({
                "unique_source_ips": "sum",
                "total_packets": "sum",
                "total_bytes": "sum",
            })
        else:
            geo_df = pd.DataFrame()

        if all_routers:
            router_df = pd.concat(all_routers).groupby(
                ["flow_ip_addr", "input_if_index"], as_index=False,
            ).agg({
                "flow_count": "sum",
                "unique_source_ips": "sum",
                "total_packets": "sum",
                "total_bytes": "sum",
            })
        else:
            router_df = pd.DataFrame()

        path_analysis = {
            "geo_distribution": geo_df,
            "entry_routers": router_df,
        }

        effective_thresholds = {
            "pps_threshold": max_pps,
            "bps_threshold": max_bps,
        }

        return features, cluster_report, path_analysis, effective_thresholds

    @staticmethod
    def _build_overview_from_per_type(
        per_type_results: Dict[str, Dict],
        raw_df: pd.DataFrame,
        ctx: Optional["AttackContext"] = None,
    ) -> Dict:
        """
        从分项分析结果聚合总览统计

        聚合维度:
        - 各分类的源 IP 总数（去重）
        - Top 攻击源（跨类型去重，取最高分）
        - 攻击类型维度的统计摘要

        Args:
            per_type_results: 分项分析结果字典
            raw_df: 原始 NetFlow DataFrame
            ctx: 攻击上下文（可选）

        Returns:
            总览统计字典
        """
        empty_overview = {
            "total_source_ips": 0,
            "confirmed": 0,
            "suspicious": 0,
            "borderline": 0,
            "background": 0,
            "anomaly_total": 0,
            "top_attackers": [],
            "attack_type_count": 0,
            "attack_type_names": [],
            "max_pps_threshold": 0,
            "max_bps_threshold": 0,
        }

        if not per_type_results:
            return empty_overview

        total_confirmed = 0
        total_suspicious = 0
        total_borderline = 0
        total_background = 0
        all_ips = set()
        ip_best = {}  # ip -> {score, info} 跨类型去重取最高分
        max_pps_threshold = 0
        max_bps_threshold = 0

        for at_name, type_result in per_type_results.items():
            features = type_result.get("features")
            if features is None or features.empty:
                continue

            all_ips.update(features.index.tolist())

            class_counts = features["traffic_class"].value_counts().to_dict()
            total_confirmed += class_counts.get("confirmed", 0)
            total_suspicious += class_counts.get("suspicious", 0)
            total_borderline += class_counts.get("borderline", 0)
            total_background += class_counts.get("background", 0)

            # Top 攻击源（跨类型去重，取最高置信度）
            confirmed = features[features["traffic_class"] == "confirmed"]
            if not confirmed.empty and "packets_per_sec" in confirmed.columns:
                for ip, row in confirmed.iterrows():
                    ip_str = str(ip)
                    score = round(float(row.get("attack_confidence", 0)), 1)
                    if ip_str not in ip_best or score > ip_best[ip_str]["score"]:
                        ip_best[ip_str] = {
                            "ip": ip_str,
                            "attack_type": at_name,
                            "score": score,
                            "pps": round(float(row.get("packets_per_sec", 0)), 0),
                            "bps": round(float(row.get("bytes_per_sec", 0)), 0),
                            "country": row.get("country", ""),
                            "province": row.get("province", ""),
                            "isp": row.get("isp", ""),
                        }

            max_pps_threshold = max(
                max_pps_threshold, type_result.get("threshold_pps", 0),
            )
            max_bps_threshold = max(
                max_bps_threshold, type_result.get("threshold_bps", 0),
            )

        top_attackers = sorted(
            ip_best.values(), key=lambda x: x["score"], reverse=True,
        )[:10]

        return {
            "total_source_ips": len(all_ips),
            "confirmed": total_confirmed,
            "suspicious": total_suspicious,
            "borderline": total_borderline,
            "background": total_background,
            "anomaly_total": total_confirmed + total_suspicious,
            "top_attackers": top_attackers,
            "attack_type_count": len(per_type_results),
            "attack_type_names": list(per_type_results.keys()),
            "max_pps_threshold": max_pps_threshold,
            "max_bps_threshold": max_bps_threshold,
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
                          effective_thresholds, file_tag="", raw_df=None,
                          per_type_results=None):
        """Phase 5: 报告生成与导出 — 文字报告 + CSV + 雷达图 + 威胁情报 + 分项"""
        logger.info("[Phase 5] 报告生成与导出")
        report_text = self._reporter.generate_text_report(
            features, cluster_report, path_analysis, effective_thresholds,
            per_type_results=per_type_results,
        )
        self._reporter.export_traffic_classification_csv(features, file_tag=file_tag)
        self._reporter.export_cluster_report_csv(cluster_report, file_tag=file_tag)
        self._reporter.plot_cluster_radar_chart(cluster_report, file_tag=file_tag)
        # 威胁情报输出: 攻击源黑名单 + 攻击时间线
        self._reporter.export_attack_blacklist_csv(features, cluster_report, file_tag=file_tag)
        self._reporter.export_attack_timeline_csv(
            path_analysis, raw_df=raw_df, features=features, file_tag=file_tag,
        )
        # 分项报告导出
        self._reporter.export_per_type_csv(per_type_results or {}, file_tag=file_tag)
        return report_text
