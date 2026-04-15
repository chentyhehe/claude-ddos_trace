"""
基线建模与异常源检测模块

本模块实现基于统计基线的多因子异常检测算法，分为两个阶段:

阶段1 - 流量基线建模 (TrafficBaseline):
    对所有源 IP 的特征计算正常流量基线，包括均值、中位数、标准差、
    P75/P90/P95/P99 等分位数。
    阈值策略:
    - 单源 IP 自适应阈值 = 正常流量 P95 × 1.5（比正常峰值高 50% 缓冲）
    - 告警阈值作为"聚合参考"，用于计算攻击贡献度（该IP占总攻击流量的比例）
    - 不再将告警阈值直接作为单源 IP 的检测阈值

    设计理由:
    告警表的阈值（如 100M bps）是攻击目标收到的聚合总流量阈值，
    而溯源分析需要逐源 IP 判断"这个 IP 是否是攻击者"。
    单个 IP 的流量可能远低于告警阈值，但相比其他正常 IP 仍然异常高。
    因此用正常流量的 P95 分布作为单源基线，更合理地识别"异常偏离者"。

阶段2 - 多因子异常检测 (AnomalyDetector):
    使用 6 个独立评分因子对每个源 IP 进行加权打分:
    - 因子1: PPS 相对偏离 (权重 25%) — 该 IP 的 PPS 相对正常基线的偏离程度
    - 因子2: BPS 相对偏离 (权重 20%) — 该 IP 的 BPS 相对正常基线的偏离程度
    - 因子3: 包大小异常 (权重 15%) — 双侧检测小包和大包攻击
    - 因子4: 突发模式 (权重 15%) — 检测脉冲式/突发式攻击
    - 因子5: 行为模式异常 (权重 10%) — 检测自动化工具特征
    - 因子6: 攻击贡献度 (权重 15%) — 该 IP 流量占告警阈值的比例

    综合得分 = 0.25*f1 + 0.20*f2 + 0.15*f3 + 0.15*f4 + 0.10*f5 + 0.15*f6
    按阈值分为 4 个等级: confirmed / suspicious / borderline / background

核心类:
    - TrafficBaseline: 流量基线建模与有效阈值计算
    - AnomalyDetector: 多因子异常检测评分
"""

import logging
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

from ddos_trace.config.models import ThresholdConfig, TracebackConfig

logger = logging.getLogger(__name__)

# 用于基线计算的 6 个核心指标
# 这些指标涵盖了流量"量"（速率）、"形"（包大小）、"节奏"（突发性和规律性）三个维度
BASELINE_METRICS = [
    "packets_per_sec",       # 包速率
    "bytes_per_sec",         # 字节速率
    "bytes_per_packet",      # 平均包大小
    "burst_ratio",           # 突发比（最大/平均包数）
    "flow_interval_mean",    # 流平均间隔
    "flow_interval_cv",      # 流间隔变异系数
]

# 基线统计量名称列表
BASELINE_STAT_NAMES = ["mean", "median", "std", "p75", "p90", "p95", "p99", "max", "min"]


class TrafficBaseline:
    """
    流量基线建模

    从所有源 IP 的特征中计算正常流量基线，生成两类阈值:

    1. 自适应单源阈值（adaptive_thresholds）:
       - 基于正常流量 P95 × 1.5 计算，比正常峰值高 50% 缓冲区
       - 用于判断单个源 IP 的流量是否"异常偏离正常同侪"
       - 这比直接用告警阈值更合理，因为告警阈值是聚合维度的

    2. 告警贡献度阈值（alert_thresholds）:
       - 直接使用 threshold_config 中的 PPS/BPS 值
       - per-type 场景下 threshold_config 是该攻击类型的 MySQL trigger_rate
       - 旧场景下 threshold_config 是配置文件的硬阈值
       - 用于计算"攻击贡献度"：该 IP 的流量占告警阈值的比例

    排除攻击 IP 策略:
    先用"超过均值+3σ"的启发式方法初步排除明显异常的 IP，
    再对剩余"疑似正常"的 IP 计算统计量。
    """

    # P95 缓冲系数：正常流量 P95 的 1.5 倍作为单源自适应阈值
    P95_BUFFER_FACTOR = 1.5

    def __init__(
        self,
        threshold_config: ThresholdConfig,
        traceback_config: TracebackConfig,
    ):
        self.threshold_config = threshold_config
        self.traceback_config = traceback_config
        # 基线过滤结果标记，由 _filter_normal_ips 设置，供 _compute_effective_thresholds 读取
        self._filter_excluded_any = False
        self._filter_method_used = ""

    def compute(self, features: pd.DataFrame) -> Tuple[Dict, Dict]:
        """
        计算流量基线

        Args:
            features: 特征 DataFrame（以 src_ip_addr 为索引）

        Returns:
            (effective_thresholds, baseline_stats)
            - effective_thresholds: 包含两类阈值的字典:
                - packets_per_sec: 自适应单源 PPS 阈值（P95 × 1.5）
                - bytes_per_sec: 自适应单源 BPS 阈值（P95 × 1.5）
                - alert_pps_threshold: 告警聚合 PPS 阈值（用于贡献度计算）
                - alert_bps_threshold: 告警聚合 BPS 阈值（用于贡献度计算）
            - baseline_stats: 每个指标的完整统计量字典
        """
        logger.info("[BASELINE] 开始基线计算 / 源IP数[%d]", len(features))

        # 步骤1: 初步排除明显异常的 IP（均值+3σ 以上的视为疑似攻击）
        # 排除后用剩余的"疑似正常"IP 计算统计量，避免攻击流量拉偏基线
        normal_df = self._filter_normal_ips(features)

        # 步骤2: 计算 6 个核心指标的统计量
        baseline_stats = self._compute_stats(normal_df)

        # 步骤3: 计算有效阈值（自适应 + 告警贡献度两类）
        effective_thresholds = self._compute_effective_thresholds(baseline_stats)
        logger.info(
            "[BASELINE] 基线计算完成 / 方法[%s] / 指标数[%d] / "
            "自适应PPS阈值[%.0f] / 自适应BPS阈值[%.0f] / "
            "告警PPS阈值[%.0f] / 告警BPS阈值[%.0f]",
            self._filter_method_used,
            len(baseline_stats),
            effective_thresholds.get("packets_per_sec", 0),
            effective_thresholds.get("bytes_per_sec", 0),
            effective_thresholds.get("alert_pps_threshold", 0),
            effective_thresholds.get("alert_bps_threshold", 0),
        )
        return effective_thresholds, baseline_stats

    def _filter_normal_ips(self, features: pd.DataFrame) -> pd.DataFrame:
        """
        初步过滤疑似攻击 IP，保留"疑似正常"IP 子集

        三级过滤策略（auto 模式下逐级降级）:
        1. 均值+σ 过滤: 超过 PPS 或 BPS 均值+σ 倍数的 IP 被排除
           - 使用 OR 逻辑（任一维度超标即排除）
           - σ 倍数由 outlier_sigma 配置（默认 3）
        2. 中位数+MAD 过滤: 当 σ 过滤排除 0 个 IP 时降级
           - MAD（中位数绝对偏差）对极端值更鲁棒
           - 1.4826 是正态分布下 MAD 到 σ 的转换系数
        3. 百分位过滤: 当 MAD 仍排除 0 个 IP 时兜底
           - 排除 PPS 或 BPS 排名前 N% 的 IP（默认 20%）
           - 确保在最均匀的分布式攻击场景下也能分离出基线

        percentile 模式下直接使用第 3 级策略。
        sigma 模式下只使用第 1 级策略，不做降级。

        若排除后剩余 IP 不足 10 个，退化使用全量数据（保证统计量有意义）。
        """
        pps = features["packets_per_sec"].fillna(0)
        bps = features["bytes_per_sec"].fillna(0)

        method = self.traceback_config.outlier_method
        sigma = self.traceback_config.outlier_sigma

        # ---------- percentile 模式: 直接使用百分位排除 ----------
        if method == "percentile":
            pps_outlier, bps_outlier = self._percentile_filter(pps, bps)
            self._filter_method_used = "percentile"
        else:
            # ---------- auto / sigma 模式: 先尝试均值+σ ----------
            pps_mean, pps_std = pps.mean(), pps.std()
            bps_mean, bps_std = bps.mean(), bps.std()

            pps_outlier = pps > (pps_mean + sigma * max(pps_std, 1))
            bps_outlier = bps > (bps_mean + sigma * max(bps_std, 1))
            n_excluded = (pps_outlier | bps_outlier).sum()

            if n_excluded > 0:
                self._filter_method_used = f"sigma({sigma})"
            else:
                # σ 过滤排除 0 个 IP → 降级到 median+MAD
                logger.info(
                    "[BASELINE] sigma(%.1f)排除0个IP，降级到 median+MAD",
                    sigma,
                )
                pps_outlier, bps_outlier = self._median_mad_filter(pps, bps, sigma)
                n_excluded = (pps_outlier | bps_outlier).sum()

                if n_excluded > 0:
                    self._filter_method_used = "median_mad"
                else:
                    # MAD 仍然排除 0 个 → 百分位兜底
                    logger.info(
                        "[BASELINE] median+MAD 仍排除0个IP，降级到百分位 Top%.0f%%",
                        self.traceback_config.outlier_top_percent,
                    )
                    pps_outlier, bps_outlier = self._percentile_filter(pps, bps)
                    self._filter_method_used = "percentile_fallback"

            # sigma 模式不做降级（上面 auto 走完降级链，sigma 则 n_excluded > 0 分支结束）
            if method == "sigma" and n_excluded == 0:
                self._filter_method_used = f"sigma({sigma})"

        normal_mask = ~(pps_outlier | bps_outlier)
        normal_df = features.loc[normal_mask]
        self._filter_excluded_any = len(normal_df) < len(features)

        # 退化保护: 正常 IP 不足 10 个时使用全量数据
        if len(normal_df) < 10:
            logger.warning(
                "[BASELINE] 正常IP不足10个(实际%d)，退化使用全量数据",
                len(normal_df),
            )
            normal_df = features
            self._filter_excluded_any = False

        logger.info(
            "[BASELINE] 正常IP过滤 / 方法[%s] / 全量[%d] / 正常[%d] / 排除[%d]",
            self._filter_method_used,
            len(features), len(normal_df), len(features) - len(normal_df),
        )
        return normal_df

    def _median_mad_filter(
        self, pps: pd.Series, bps: pd.Series, sigma: float
    ) -> Tuple[pd.Series, pd.Series]:
        """
        中位数+MAD 过滤（对极端值更鲁棒的异常检测）

        MAD（Median Absolute Deviation）相比标准差对极端值不敏感:
        - std 会被少数极端值拉大，导致 mean+3σ 阈值过高
        - MAD 保持稳定，能更准确地识别偏离中位数的异常值
        - 1.4826 是正态分布假设下 MAD 到 σ 的转换系数
        """
        pps_median = pps.median()
        bps_median = bps.median()
        pps_mad = np.median(np.abs(pps - pps_median)) * 1.4826
        bps_mad = np.median(np.abs(bps - bps_median)) * 1.4826

        pps_outlier = pps > (pps_median + sigma * max(pps_mad, 1))
        bps_outlier = bps > (bps_median + sigma * max(bps_mad, 1))

        logger.info(
            "[BASELINE] median+MAD / PPS_median[%.0f] PPS_MAD[%.0f] "
            "BPS_median[%.0f] BPS_MAD[%.0f]",
            pps_median, pps_mad, bps_median, bps_mad,
        )
        return pps_outlier, bps_outlier

    def _percentile_filter(
        self, pps: pd.Series, bps: pd.Series
    ) -> Tuple[pd.Series, pd.Series]:
        """
        百分位过滤 — 排除 PPS/BPS 排名前 N% 的 IP

        适用于所有 IP 流量分布非常均匀的分布式 DDoS 场景，
        此时 σ 和 MAD 均无法分离，按排名强制排除最高流量 IP。
        """
        top_pct = self.traceback_config.outlier_top_percent
        pps_cutoff = np.percentile(pps, 100 - top_pct) if len(pps) > 5 else pps.max()
        bps_cutoff = np.percentile(bps, 100 - top_pct) if len(bps) > 5 else bps.max()

        pps_outlier = pps >= pps_cutoff
        bps_outlier = bps >= bps_cutoff

        logger.info(
            "[BASELINE] 百分位过滤 / Top%.0f%% / PPS_cutoff[%.0f] BPS_cutoff[%.0f]",
            top_pct, pps_cutoff, bps_cutoff,
        )
        return pps_outlier, bps_outlier

    def _compute_stats(self, normal_df: pd.DataFrame) -> Dict:
        """
        对正常流量子集计算各指标的统计量
        """
        baseline_stats = {}
        for metric in BASELINE_METRICS:
            if metric not in normal_df.columns:
                continue
            series = normal_df[metric].dropna()
            if series.empty:
                continue
            baseline_stats[metric] = {
                "mean": float(series.mean()),
                "median": float(series.median()),
                "std": float(series.std()) if len(series) > 1 else 0.0,
                "p75": float(series.quantile(0.75)),
                "p90": float(series.quantile(0.90)),
                "p95": float(series.quantile(0.95)),
                "p99": float(series.quantile(0.99)),
                "max": float(series.max()),
                "min": float(series.min()),
            }
        return baseline_stats

    def _compute_effective_thresholds(self, baseline_stats: Dict) -> Dict[str, float]:
        """
        计算有效阈值 — 自适应阈值 + 告警贡献度阈值

        返回阈值项:
        - packets_per_sec: 自适应单源 PPS 阈值 = 正常P95 × 1.5
        - bytes_per_sec: 自适应单源 BPS 阈值 = 正常P95 × 1.5
        - alert_pps_threshold: 告警 PPS 阈值（用于贡献度计算分母）
        - alert_bps_threshold: 告警 BPS 阈值（用于贡献度计算分母）

        自适应阈值的意义:
        如果正常 IP 的 PPS P95 是 5000，则自适应阈值 = 7500。
        任何源 IP 超过 7500 PPS 就被视为"相对同侪异常"。

        安全下界策略:
        当告警阈值来自 fallback 默认值时，不应让 fallback 值影响自适应阈值。
        安全下界取 max(实际数据P99, P95 × 2) 而非固定比例。

        过滤失败时的降级:
        当 _filter_normal_ips 无法分离攻击IP（所有IP流量相似，如均匀分布式DDoS），
        基线被攻击流量污染，P95 × 1.5 会远高于正常水平。
        此时用中位数 × 2 作为上限，确保自适应阈值仍能检测到偏离。
        """
        effective = {}

        # 自适应单源阈值: 正常 P95 × 1.5
        if self.traceback_config.use_dynamic_baseline:
            pps_p95 = baseline_stats.get("packets_per_sec", {}).get("p95", 0)
            bps_p95 = baseline_stats.get("bytes_per_sec", {}).get("p95", 0)
            pps_p99 = baseline_stats.get("packets_per_sec", {}).get("p99", 0)
            bps_p99 = baseline_stats.get("bytes_per_sec", {}).get("p99", 0)

            effective["packets_per_sec"] = pps_p95 * self.P95_BUFFER_FACTOR
            effective["bytes_per_sec"] = bps_p95 * self.P95_BUFFER_FACTOR

            # 安全下界: 取实际数据 P99 和 P95×2 的较大值
            min_pps = max(pps_p99, pps_p95 * 2) if pps_p95 > 0 else 1
            min_bps = max(bps_p99, bps_p95 * 2) if bps_p95 > 0 else 1
            effective["packets_per_sec"] = max(effective["packets_per_sec"], min_pps)
            effective["bytes_per_sec"] = max(effective["bytes_per_sec"], min_bps)

            # 过滤失败降级: 当无法分离攻击IP时，用中位数 × 2 封顶
            # 防止基线被攻击流量污染导致自适应阈值过高
            if not self._filter_excluded_any:
                pps_median = baseline_stats.get("packets_per_sec", {}).get("median", 0)
                bps_median = baseline_stats.get("bytes_per_sec", {}).get("median", 0)
                cap_pps = pps_median * 2
                cap_bps = bps_median * 2

                if cap_pps > 0 and effective["packets_per_sec"] > cap_pps:
                    logger.info(
                        "[BASELINE] 自适应PPS阈值封顶 / %.0f → %.0f (median×2)",
                        effective["packets_per_sec"], cap_pps,
                    )
                    effective["packets_per_sec"] = cap_pps
                if cap_bps > 0 and effective["bytes_per_sec"] > cap_bps:
                    logger.info(
                        "[BASELINE] 自适应BPS阈值封顶 / %.0f → %.0f (median×2)",
                        effective["bytes_per_sec"], cap_bps,
                    )
                    effective["bytes_per_sec"] = cap_bps
        else:
            effective["packets_per_sec"] = float(self.threshold_config.pps_threshold)
            effective["bytes_per_sec"] = float(self.threshold_config.bps_threshold)

        # 告警贡献度阈值: 直接使用 threshold_config
        effective["alert_pps_threshold"] = float(self.threshold_config.pps_threshold)
        effective["alert_bps_threshold"] = float(self.threshold_config.bps_threshold)

        return effective


class AnomalyDetector:
    """
    异常源检测 - 多因子评分模型

    对每个源 IP 使用 6 个独立评分因子进行加权打分:
        综合置信度 = 0.25 * PPS相对偏离 + 0.20 * BPS相对偏离
                     + 0.15 * 包大小异常 + 0.15 * 突发模式
                     + 0.10 * 行为模式 + 0.15 * 攻击贡献度

    权重设计理由:
    - PPS 相对偏离权重最高(25%): 相对同侪的包速率偏离是最直观的异常信号
    - BPS 相对偏离(20%): 带宽占用偏离是补充维度
    - 包大小异常(15%): 识别小包攻击(SYN Flood)和大包攻击
    - 突发模式(15%): 识别脉冲式/突发式攻击
    - 行为模式(10%): 自动化工具特征（单端口/单协议/规律性）
    - 攻击贡献度(15%): 该 IP 的流量占告警阈值的比例
      即使一个 IP 相对正常同侪偏离不大，但如果它一个 IP 就贡献了
      告警阈值的 30% 以上流量，仍应被标记为可疑

    按综合得分分为 4 个等级:
        confirmed (>=80): 确认攻击源，建议立即处置
        suspicious (>=60): 可疑源，需要人工复核
        borderline (>=40): 边界源，需关注
        background (<40):  正常背景流量
    """

    def __init__(
        self,
        threshold_config: ThresholdConfig,
        traceback_config: TracebackConfig,
    ):
        self.threshold_config = threshold_config
        self.traceback_config = traceback_config

    def detect(
        self,
        features: pd.DataFrame,
        baseline_stats: Dict,
        effective_thresholds: Dict,
    ) -> pd.DataFrame:
        """
        执行异常检测，返回带分类的 features

        Args:
            features: 特征 DataFrame
            baseline_stats: 基线统计量
            effective_thresholds: 有效阈值（含自适应阈值和告警阈值）

        Returns:
            添加了 attack_confidence、traffic_class 等列的 DataFrame
        """
        if features.empty:
            return features

        features = features.copy()

        logger.info("[DETECTION] 开始异常检测 / 源IP数[%d]", len(features))

        # 因子1: PPS 相对偏离 (权重25%) — 该 IP 相对正常同侪的 PPS 偏离程度
        f1 = self._score_pps(features, baseline_stats, effective_thresholds)
        # 因子2: BPS 相对偏离 (权重20%) — 该 IP 相对正常同侪的 BPS 偏离程度
        f2 = self._score_bps(features, baseline_stats, effective_thresholds)
        # 因子3: 包大小异常 (权重15%) — 识别小包攻击(SYN Flood)和大包攻击
        f3 = self._score_packet_size(features, baseline_stats)
        # 因子4: 突发模式 (权重15%) — 识别脉冲式/突发式攻击
        f4 = self._score_burst(features)
        # 因子5: 行为模式 (权重10%) — 识别单端口/单协议等自动化工具特征
        f5 = self._score_behavior(features)
        # 因子6: 攻击贡献度 (权重15%) — 该 IP 流量占告警阈值的比例
        f6 = self._score_contribution(features, effective_thresholds)

        # 加权总分: 6 因子加权
        features["attack_confidence"] = (
            f1 * 0.25 + f2 * 0.20 + f3 * 0.15 + f4 * 0.15 + f5 * 0.10 + f6 * 0.15
        ).clip(0, 100)

        # 调试日志: 各因子得分分布
        logger.info(
            "[DETECTION] 因子得分分布 / "
            "f1_pps[mean=%.1f/max=%.1f/min=%.1f/p50=%.1f] / "
            "f2_bps[mean=%.1f/max=%.1f/min=%.1f/p50=%.1f] / "
            "f3_pkt[mean=%.1f/max=%.1f] / "
            "f4_burst[mean=%.1f/max=%.1f] / "
            "f5_behavior[mean=%.1f/max=%.1f] / "
            "f6_contrib[mean=%.1f/max=%.1f]",
            f1.mean(), f1.max(), f1.min(), f1.median(),
            f2.mean(), f2.max(), f2.min(), f2.median(),
            f3.mean(), f3.max(),
            f4.mean(), f4.max(),
            f5.mean(), f5.max(),
            f6.mean(), f6.max(),
        )

        # 分层分类: 按置信度分为 4 级
        features["traffic_class"] = pd.cut(
            features["attack_confidence"],
            bins=[-1, 40, 60, 80, 101],
            labels=["background", "borderline", "suspicious", "confirmed"],
        ).astype(str)

        # 生成置信度说明
        features["confidence_reasons"] = self._generate_reasons(
            features, f1, f2, f3, f4, f5, f6
        )

        # 统计
        class_counts = features["traffic_class"].value_counts().to_dict()
        logger.info(
            "[DETECTION] 检测完成 / confirmed[%d] / suspicious[%d] / "
            "borderline[%d] / background[%d]",
            class_counts.get("confirmed", 0),
            class_counts.get("suspicious", 0),
            class_counts.get("borderline", 0),
            class_counts.get("background", 0),
        )
        return features

    # ------------------------------------------------------------------
    # 评分因子
    # ------------------------------------------------------------------

    def _score_pps(
        self, features: pd.DataFrame, baseline: Dict, thresholds: Dict
    ) -> pd.Series:
        """
        因子1: PPS 相对偏离 (权重25%)

        双重评分机制:
        - z_score: 基于正常流量基线的 z-score × 10，衡量相对同侪的偏离程度
          一个 IP 的 PPS 比正常均值高 10 个标准差，就达到满分
        - adaptive_score: 基于自适应阈值（P95×1.5）的比例打分
          超过自适应阈值至少得 50 分，按比例上浮到 100 分
        取两者的最大值: 任一维度判为异常都给高分
        """
        pps = features["packets_per_sec"].fillna(0)
        bl = baseline.get("packets_per_sec", {})
        mean = bl.get("mean", 0)
        std = bl.get("std", 1) or 1

        # z-score: 相对正常均值的偏离程度
        z = (pps - mean) / std
        z_score = np.clip(z * 10, 0, 100)

        # 自适应阈值打分: 超过 P95×1.5 的阈值时至少得 50 分
        adaptive_threshold = thresholds.get("packets_per_sec", self.threshold_config.pps_threshold)
        adaptive_score = np.where(
            pps >= adaptive_threshold,
            np.clip((pps / adaptive_threshold) * 50, 50, 100),
            0,
        )

        return pd.Series(np.maximum(z_score, adaptive_score), index=features.index)

    def _score_bps(
        self, features: pd.DataFrame, baseline: Dict, thresholds: Dict
    ) -> pd.Series:
        """
        因子2: BPS 相对偏离 (权重20%)

        评分逻辑与 PPS 因子相同: max(z_score, adaptive_score)
        独立于 PPS 因子，某些攻击（如 DNS 放大攻击）BPS 高但 PPS 可能不高。
        """
        bps = features["bytes_per_sec"].fillna(0)
        bl = baseline.get("bytes_per_sec", {})
        mean = bl.get("mean", 0)
        std = bl.get("std", 1) or 1

        z = (bps - mean) / std
        z_score = np.clip(z * 10, 0, 100)

        adaptive_threshold = thresholds.get("bytes_per_sec", self.threshold_config.bps_threshold)
        adaptive_score = np.where(
            bps >= adaptive_threshold,
            np.clip((bps / adaptive_threshold) * 50, 50, 100),
            0,
        )

        return pd.Series(np.maximum(z_score, adaptive_score), index=features.index)

    def _score_packet_size(
        self, features: pd.DataFrame, baseline: Dict
    ) -> pd.Series:
        """
        因子3: 包大小异常 - 双侧 z-score (权重15%)

        使用绝对偏离（双侧检测），因为攻击流量的包大小可能异常小（SYN Flood ~40-60B）
        或异常大（DNS 放大攻击 ~1400+ B）。
        评分公式: score = min(|z| * 15, 100)
        缩放因子 15 使得偏离约 6.7 个标准差时达到满分。
        """
        bpp = features["bytes_per_packet"].fillna(0)
        bl = baseline.get("bytes_per_packet", {})
        mean = bl.get("mean", 0)
        std = bl.get("std", 1) or 1

        # 双侧检测：绝对偏离
        z_abs = np.abs((bpp - mean) / std)
        score = np.clip(z_abs * 15, 0, 100)

        return pd.Series(score, index=features.index)

    def _score_burst(self, features: pd.DataFrame) -> pd.Series:
        """
        因子4: 突发模式 (权重15%)

        从三个子维度评估突发行为:
        - ratio_score: burst_ratio / 5.0 * 100
            burst_ratio = max_packets / avg_packets，超过 5 倍视为高度突发
        - count_score: burst_count / 100 * 100
            100 次突发为满分基线
        - size_score: max_burst_size / 20 * 100
            连续 20 个突发流为满分基线
        加权平均: 0.4 * ratio + 0.3 * count + 0.3 * size
        """
        burst_ratio = features.get("burst_ratio", pd.Series(0, index=features.index)).fillna(0)
        burst_count = features.get("burst_count", pd.Series(0, index=features.index)).fillna(0)
        max_burst = features.get("max_burst_size", pd.Series(0, index=features.index)).fillna(0)

        # 归一化各维度到 0-100 分
        ratio_score = np.clip(burst_ratio / 5.0 * 100, 0, 100)     # burst_ratio > 5 视为突发
        count_score = np.clip(burst_count / 100.0 * 100, 0, 100)    # 100次突发为满分基线
        size_score = np.clip(max_burst / 20.0 * 100, 0, 100)        # 连续20个突发为满分基线

        # 加权平均
        return pd.Series(
            ratio_score * 0.4 + count_score * 0.3 + size_score * 0.3,
            index=features.index,
        )

    def _score_behavior(self, features: pd.DataFrame) -> pd.Series:
        """
        因子5: 行为模式 - 单端口/单协议/规律性 (权重10%)

        检测典型的自动化攻击工具行为特征:
        - single_port: 只攻击单个目的端口（如 80/443/53）
        - single_proto: 只使用单个协议（如 UDP Flood 只用 UDP）
        - regular: 发送间隔变异系数 CV < 0.5 且流数 >= 5
            高度规律的发送节奏是攻击工具的典型特征
        满足的条件越多，分数越高: score = (条件数 / 3) * 100
        """
        single_port = (features.get("dst_port_count", 1) == 1).astype(float)
        single_proto = (features.get("protocol_count", 1) == 1).astype(float)
        flow_count = features.get("flow_count", pd.Series(1, index=features.index)).fillna(0)
        cv = features.get("flow_interval_cv", pd.Series(1, index=features.index)).fillna(1.0)
        regular = ((cv < 0.5) & (flow_count >= 5)).astype(float)

        # 满足条件越多分数越高: 0个=0分, 1个=33分, 2个=67分, 3个=100分
        score = (single_port + single_proto + regular) / 3.0 * 100
        return pd.Series(score, index=features.index)

    def _score_contribution(
        self, features: pd.DataFrame, thresholds: Dict
    ) -> pd.Series:
        """
        因子6: 攻击贡献度 (权重15%)

        衡量该 IP 的流量占攻击阈值的比例。

        分母选择:
        使用 effective_thresholds 中的 alert_pps_threshold / alert_bps_threshold。
        per-type 场景下这是该攻击类型的 MySQL trigger_rate，
        旧场景下是配置文件的硬阈值。

        评分逻辑:
        - contribution = max(pps占比, bps占比)
        - < 1%: 贡献极微 → 0 分
        - 1%~5%: 有一定贡献 → 线性映射到 0-40 分
        - 5%~20%: 显著贡献 → 40-70 分
        - ≥ 20%: 核心攻击源 → 70-100 分
        """
        pps = features["packets_per_sec"].fillna(0)
        bps = features["bytes_per_sec"].fillna(0)

        alert_pps = thresholds.get("alert_pps_threshold", self.threshold_config.pps_threshold)
        alert_bps = thresholds.get("alert_bps_threshold", self.threshold_config.bps_threshold)

        # 用告警阈值作为分母计算贡献度
        pps_contrib = pps / max(alert_pps, 1) if alert_pps > 0 else np.zeros(len(features))
        bps_contrib = bps / max(alert_bps, 1) if alert_bps > 0 else np.zeros(len(features))
        contribution = np.maximum(
            np.where(pps_contrib > 0, pps_contrib, 0),
            np.where(bps_contrib > 0, bps_contrib, 0),
        )

        return pd.Series(
            self._contribution_to_score(contribution),
            index=features.index,
        )

    @staticmethod
    def _contribution_to_score(contribution: np.ndarray) -> np.ndarray:
        """
        将贡献度比例转换为分段评分

        - < 1%:  0 分（贡献极微）
        - 1%-5%: 线性映射到 0-40 分
        - 5%-20%: 映射到 40-70 分
        - ≥ 20%: 映射到 70-100 分（核心攻击源）
        """
        return np.where(
            contribution >= 0.20,
            np.clip(70 + (contribution - 0.20) / 0.80 * 30, 70, 100),
            np.where(
                contribution >= 0.05,
                40 + (contribution - 0.05) / 0.15 * 30,
                np.where(
                    contribution >= 0.01,
                    (contribution - 0.01) / 0.04 * 40,
                    0,
                ),
            ),
        )

    # ------------------------------------------------------------------
    # 置信度说明
    # ------------------------------------------------------------------

    def _generate_reasons(
        self,
        features: pd.DataFrame,
        f1: pd.Series,
        f2: pd.Series,
        f3: pd.Series,
        f4: pd.Series,
        f5: pd.Series,
        f6: pd.Series,
    ) -> pd.Series:
        """
        为每个源 IP 生成可读的置信度说明文本

        对每个因子，仅当得分超过 60 时才列入原因列表。
        这为安全分析师提供了可解释的判断依据。
        """
        reasons_list = []
        for idx in features.index:
            reasons = []
            if f1.loc[idx] > 60:
                reasons.append(f"PPS相对偏离(得分{f1.loc[idx]:.0f})")
            if f2.loc[idx] > 60:
                reasons.append(f"BPS相对偏离(得分{f2.loc[idx]:.0f})")
            if f3.loc[idx] > 60:
                reasons.append(f"包大小异常(得分{f3.loc[idx]:.0f})")
            if f4.loc[idx] > 60:
                reasons.append(f"突发模式(得分{f4.loc[idx]:.0f})")
            if f5.loc[idx] > 60:
                reasons.append(f"行为模式异常(得分{f5.loc[idx]:.0f})")
            if f6.loc[idx] > 60:
                reasons.append(f"攻击贡献度高(得分{f6.loc[idx]:.0f})")
            reasons_list.append("; ".join(reasons) if reasons else "未检出明显异常")
        return pd.Series(reasons_list, index=features.index)
