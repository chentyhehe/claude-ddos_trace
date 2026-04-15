"""
特征提取模块 - 从原始 NetFlow 数据中提取多维攻击指纹特征

本模块按源 IP (src_ip_addr) 聚合，提取以下四大类特征:

1. 基础聚合特征: 包数/字节数的 sum/mean/std/max/min、端口多样性、协议多样性等
2. 衍生特征: 平均包大小、速率指标(PPS/BPS)、突发比、字节变异性等
3. 时序特征: 流间隔均值/标准差/变异系数、突发计数/最大突发长度、活跃比
4. 分类特征: 地理位置众数、运营商众数、主导协议/端口/TCP标志

这些特征将用于后续的基线建模和异常检测评分。

核心类:
    FeatureExtractor: 执行完整的特征提取流水线
"""

import logging
from typing import Dict, List

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    按源 IP (src_ip_addr) 聚合提取多维攻击指纹特征

    提取流程:
        原始 NetFlow → 预计算 → 基础聚合 → 衍生特征 → 时序特征 → 分类特征

    所有操作均为全向量化 pandas/numpy 操作，无逐 IP 循环，
    以保证大数据量下的处理性能。
    """

    def extract(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        执行完整的特征提取流程

        Pipeline: 预计算 → 基础聚合 → 衍生特征 → 时序特征 → 分类特征

        Args:
            df: 预处理后的 NetFlow DataFrame（必须包含 src_ip_addr 列）

        Returns:
            以 src_ip_addr 为索引的特征 DataFrame，每行一个源IP
        """
        if df.empty:
            return pd.DataFrame()

        logger.info("[FEATURES] 开始特征提取 / 原始记录数[%d]", len(df))

        # 预计算辅助列（预留扩展点，当前为空操作）
        df = self._precompute(df)

        # 步骤1: 基础聚合 - 按 src_ip_addr 计算包/字节/多样性统计量
        features = self._aggregate_basic(df)

        # 步骤2: 衍生特征 - 在聚合结果上计算速率、突发比等二次指标
        features = self._compute_derived(features)

        # 步骤3: 时序特征 - 基于流时间序列计算间隔/突发/活跃度
        temporal = self._extract_temporal_features(df)
        features = features.join(temporal, how="left")

        # 步骤4: 分类特征众数 - 地理位置和协议的主导值
        features = self._aggregate_categorical(df, features)

        logger.info(
            "[FEATURES] 特征提取完成 / 唯一源IP[%d] / 特征维度[%d]",
            len(features),
            len(features.columns),
        )
        return features

    # ------------------------------------------------------------------
    # 预计算
    # ------------------------------------------------------------------

    def _precompute(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        在原始 DataFrame 上预计算辅助列

        当前为预留扩展点。未来可在此添加:
        - Herfindahl 指数（端口集中度）
        - TCP 标志位分解（SYN/ACK/FIN 等各占比）
        """
        df = df.copy()

        # 端口集中度：Herfindahl 指数 (per src_ip，后面聚合时用)
        # 这里先不做，留给聚合阶段

        return df

    # ------------------------------------------------------------------
    # 基础聚合
    # ------------------------------------------------------------------

    def _aggregate_basic(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        按源 IP 聚合基础统计特征

        使用 pandas groupby + agg 一次性计算:
        - 包统计: sum/mean/std/max/min（刻画流量量的特征）
        - 字节统计: sum/mean/std/max（刻画流量体积的特征）
        - 多样性: nunique of dst_port/src_port/protocol/interface/flow_ip（刻画扫描/泛洪行为）
        - 时间: min/max/count（用于计算流持续时间）
        """
        agg_dict: Dict[str, List] = {
            # 包统计
            "packets": ["sum", "mean", "std", "max", "min"],
            # 字节统计
            "octets": ["sum", "mean", "std", "max"],
            # 多样性
            "dst_port": ["nunique"],
            "src_port": ["nunique"],
            "protocol": ["nunique"],
            "input_if_index": ["nunique"],
            "output_if_index": ["nunique"],
            "flow_ip_addr": ["nunique"],
            # 时间
            "parser_rcv_time": ["min", "max", "count"],
        }

        grouped = df.groupby("src_ip_addr").agg(agg_dict)

        # 扁平化多级列名: ('packets', 'sum') → 'packets_sum'
        # pandas groupby + 多聚合函数会产生 MultiIndex 列名，需要拍平
        grouped.columns = [
            self._flatten_col(col)
            for col in grouped.columns
        ]

        features = grouped.rename(columns={
            "packets_sum": "total_packets",
            "packets_mean": "avg_packets",
            "packets_std": "std_packets",
            "packets_max": "max_packets",
            "packets_min": "min_packets",
            "octets_sum": "total_bytes",
            "octets_mean": "avg_bytes",
            "octets_std": "std_bytes",
            "octets_max": "max_bytes",
            "dst_port_nunique": "dst_port_count",
            "src_port_nunique": "src_port_count",
            "protocol_nunique": "protocol_count",
            "input_if_index_nunique": "input_if_count",
            "output_if_index_nunique": "output_if_count",
            "flow_ip_addr_nunique": "flow_ip_count",
            "parser_rcv_time_min": "flow_start_time",
            "parser_rcv_time_max": "flow_end_time",
            "parser_rcv_time_count": "flow_count",
        })

        # 流持续时间（秒）= (最后流时间 - 最早流时间) / 1000
        # parser_rcv_time 是毫秒级时间戳，除以 1000 转为秒
        features["flow_duration"] = (
            (features["flow_end_time"] - features["flow_start_time"]) / 1000.0
        )
        # 最少 1 秒，避免后续速率计算中出现除零错误
        features["flow_duration"] = features["flow_duration"].clip(lower=1.0)

        return features

    @staticmethod
    def _flatten_col(col: tuple) -> str:
        """将 MultiIndex 列名元组拍平为下划线连接的字符串，如 ('packets', 'sum') → 'packets_sum'"""
        if isinstance(col, tuple):
            return "_".join(str(c) for c in col if c)
        return str(col)

    # ------------------------------------------------------------------
    # 衍生特征
    # ------------------------------------------------------------------

    def _compute_derived(self, features: pd.DataFrame) -> pd.DataFrame:
        """
        计算衍生指标

        在基础聚合特征上进行二次计算:
        - bytes_per_packet = total_bytes / total_packets
            平均包大小，用于区分 SYN Flood（<100B）、正常流量（500-1200B）、大包洪泛（>1400B）
        - packets_per_sec = total_packets / flow_duration
            每秒包数（PPS），衡量包速率的核心指标
        - bytes_per_sec = total_bytes / flow_duration
            每秒字节数（BPS），衡量带宽占用
        - burst_ratio = max_packets / avg_packets
            突发比，正常流量的最大包数/平均包数通常 <3，攻击流量可能 >5
        - bytes_std_ratio = std_bytes / avg_bytes
            字节变异性（变异系数），反映包大小的一致性

        所有除法结果均将 inf 替换为 0 以保证后续计算的安全性。
        """
        features = features.copy()

        # 平均包大小
        features["bytes_per_packet"] = (
            features["total_bytes"] / features["total_packets"]
        ).replace([np.inf, -np.inf], 0)

        # 每秒包数 / 字节数
        features["packets_per_sec"] = (
            features["total_packets"] / features["flow_duration"]
        ).replace([np.inf, -np.inf], 0)

        features["bytes_per_sec"] = (
            features["total_bytes"] / features["flow_duration"]
        ).replace([np.inf, -np.inf], 0)

        # 突发比例
        features["burst_ratio"] = (
            features["max_packets"] / features["avg_packets"]
        ).replace([np.inf, -np.inf], 0)

        # 字节变异性
        features["bytes_std_ratio"] = (
            features["std_bytes"] / features["avg_bytes"]
        ).replace([np.inf, -np.inf], 0)

        return features

    # ------------------------------------------------------------------
    # 时序特征（全向量化，无逐 IP 循环）
    # ------------------------------------------------------------------

    def _extract_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        全向量化提取时序特征

        基于每个源 IP 的 parser_rcv_time 时间序列，计算:
        - flow_interval_mean / std: 相邻流记录的平均间隔和标准差（毫秒→秒）
        - flow_interval_cv: 变异系数 CV = std / mean
            CV 越小说明发送越规律，DDoS 攻击工具通常具有高度规律的发送间隔
        - burst_count: 间隔 < 1秒的"突发"次数
        - max_burst_size: 连续突发的最大长度（游程编码计算）
        - active_ratio: 活跃时间占比 = (流数-1) / 总时间跨度
            越接近 1 说明持续高速发送

        全部使用 pandas groupby 向量化操作，无逐 IP 循环。
        """
        if "parser_rcv_time" not in df.columns:
            return pd.DataFrame(index=df["src_ip_addr"].unique())

        # 按源IP + 时间排序，为计算相邻流时间间隔做准备
        sorted_df = df[["src_ip_addr", "parser_rcv_time"]].sort_values(
            ["src_ip_addr", "parser_rcv_time"]
        )

        # 计算相邻流的时间间隔（毫秒）
        # groupby().diff() 计算同一组内相邻行的差值，第一条记录的 diff 为 NaT
        sorted_df["time_diff"] = sorted_df.groupby("src_ip_addr")["parser_rcv_time"].diff()

        # 间隔统计：均值和标准差（毫秒 → 秒）
        # 这些统计量反映源的发送节奏: 间隔小且稳定 → 可能是攻击工具
        interval_stats = sorted_df.groupby("src_ip_addr")["time_diff"].agg(
            flow_interval_mean="mean",
            flow_interval_std="std",
        )
        # 转为秒（parser_rcv_time 单位为毫秒）
        interval_stats["flow_interval_mean"] = interval_stats["flow_interval_mean"] / 1000.0
        interval_stats["flow_interval_std"] = interval_stats["flow_interval_std"] / 1000.0

        # 变异系数 CV = std / mean
        # CV 接近 0 表示间隔非常稳定（典型攻击工具特征）
        # CV 较大表示间隔波动大（更像正常流量）
        interval_stats["flow_interval_cv"] = np.where(
            interval_stats["flow_interval_mean"] > 0,
            interval_stats["flow_interval_std"] / interval_stats["flow_interval_mean"],
            0.0,
        )
        interval_stats["flow_interval_cv"] = interval_stats["flow_interval_cv"].fillna(0.0)

        # 突发检测：相邻流间隔 < 1秒（1000ms）视为突发
        # DDoS 攻击的典型特征之一是在短时间内发送大量包
        sorted_df["is_burst"] = (sorted_df["time_diff"] < 1000) & (sorted_df["time_diff"].notna())

        # burst_count: 间隔 < 1s 的突发次数（反映攻击的密集程度）
        burst_stats = sorted_df.groupby("src_ip_addr")["is_burst"].agg(
            burst_count="sum",
        )
        burst_stats["burst_count"] = burst_stats["burst_count"].astype(int)

        # max_burst_size: 连续突发的最大长度（游程编码 run-length encoding）
        # 反映攻击工具一次"脉冲"中连续发送的流数量
        max_burst = (
            sorted_df.groupby("src_ip_addr")["is_burst"]
            .apply(self._max_run_length)
            .rename("max_burst_size")
        )

        # 活跃时间占比 = (流记录数 - 1) / 总时间跨度(秒)
        # 单条流时 total_span_ms = 0，此时设为 1.0（只有一条流无法判断活跃度）
        # 结果 clip 到 [0, 1.0]：每秒一条流的密度即为 100% 活跃
        duration_ms = sorted_df.groupby("src_ip_addr")["parser_rcv_time"].agg(
            first_val="min",
            last_val="max",
            count_val="count",
        )
        active_stats = pd.DataFrame(index=duration_ms.index)
        total_span_ms = duration_ms["last_val"] - duration_ms["first_val"]
        active_stats["active_ratio"] = np.clip(
            np.where(
                total_span_ms > 0,
                (duration_ms["count_val"] - 1) / (total_span_ms / 1000.0),
                1.0,
            ), None, 1.0,
        )

        # 合并所有时序特征
        temporal = interval_stats.join(burst_stats, how="left").join(
            max_burst, how="left"
        ).join(active_stats, how="left")

        # 填充缺失值
        temporal = temporal.fillna({
            "burst_count": 0,
            "max_burst_size": 0,
        })

        logger.info(
            "[FEATURES] 时序特征提取完成 / 唯一源IP[%d]",
            len(temporal),
        )
        return temporal

    @staticmethod
    def _max_run_length(series: pd.Series) -> int:
        """
        计算布尔序列中 True 的最大连续长度（游程编码）

        用于计算 max_burst_size：同一源 IP 连续发送流（间隔 < 1s）的最长序列。
        虽然是逐元素循环，但每次调用只处理单个源 IP 的序列，长度有限。
        """
        if series.empty or not series.any():
            return 0
        max_len = 0
        current = 0
        for val in series:
            if val:
                current += 1
                max_len = max(max_len, current)
            else:
                current = 0
        return max_len

    # ------------------------------------------------------------------
    # 分类特征众数
    # ------------------------------------------------------------------

    def _aggregate_categorical(
        self, df: pd.DataFrame, features: pd.DataFrame
    ) -> pd.DataFrame:
        """
        聚合地理、监测对象等分类特征的众数

        对于每个源 IP，取其所有流记录中地理位置、ISP、监测对象等
        分类字段出现频率最高的值（众数）。

        此外提取主导协议、主导目的端口、主导 TCP 标志，
        这些信息用于后续攻击类型推断。
        """
        # 分类字段 → 目标特征名的映射
        # 每个源 IP 取众数（mode），众数即为该 IP 最常出现的地理位置/运营商
        cat_cols = {
            "src_country": "country",
            "src_province": "province",
            "src_city": "city",
            "src_isp": "isp",
            "src_as": "as_number",
            "src_mo_name": "src_mo_name",
            "src_mo_code": "src_mo_code",
            "dst_mo_name": "dst_mo_name",
            "dst_mo_code": "dst_mo_code",
        }

        for src_col, dst_col in cat_cols.items():
            if src_col not in df.columns:
                features[dst_col] = None
                continue
            mode_series = df.groupby("src_ip_addr")[src_col].agg(
                lambda x: x.mode().iloc[0] if not x.mode().empty else None
            )
            features[dst_col] = mode_series

        # TCP 标志众数
        if "tcp_flags" in df.columns:
            features["dominant_tcp_flag"] = df.groupby("src_ip_addr")["tcp_flags"].agg(
                lambda x: x.mode().iloc[0] if not x.mode().empty else 0
            )

        # 主导协议（用于攻击类型推断）
        if "protocol" in df.columns:
            features["dominant_protocol"] = df.groupby("src_ip_addr")["protocol"].agg(
                lambda x: x.mode().iloc[0] if not x.mode().empty else 0
            )

        # 主导目的端口
        if "dst_port" in df.columns:
            features["dominant_dst_port"] = df.groupby("src_ip_addr")["dst_port"].agg(
                lambda x: x.mode().iloc[0] if not x.mode().empty else 0
            )

        return features
