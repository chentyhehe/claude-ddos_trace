"""
攻击路径重构模块 - 入口路由器分析、地理溯源、监测对象关联

本模块在异常检测完成后，对确认/可疑的攻击源进行路径层面的分析:

1. 入口路由器分析: 按 flow_ip_addr（采集路由器IP）+ input_if_index 聚合，
   定位攻击流量进入网络的入口节点。这些信息可用于在入口路由器上
   配置 ACL 或黑洞路由来缓解攻击。

2. 地理来源分析: 按 src_country/province/city/isp 聚合，
   揭示攻击源的地理分布，用于判断是否为跨国攻击或特定区域集中攻击。

3. 监测对象关联: 按 src_mo_code/src_mo_name 聚合，
   关联攻击源所属的运营商管理对象，便于跨部门协调处置。

4. 时间分布分析: 按小时聚合攻击流量，展示攻击的时间演变趋势。

核心类:
    AttackPathReconstructor: 执行完整的路径重构分析
"""

import logging
from typing import Dict

import pandas as pd

logger = logging.getLogger(__name__)


class AttackPathReconstructor:
    """
    攻击路径重构

    从多个维度分析攻击流量的路径特征，为攻击处置和溯源提供决策依据。
    """

    def __init__(self, top_k: int = 5):
        """
        Args:
            top_k: 入口路由器分析时保留的 Top-K 数量
        """
        self.top_k = top_k

    def reconstruct(
        self, raw_df: pd.DataFrame, features: pd.DataFrame
    ) -> Dict:
        """
        执行完整的路径重构分析

        Args:
            raw_df: 原始 NetFlow 数据（包含所有流记录）
            features: 带有 traffic_class 列的特征 DataFrame

        Returns:
            包含四个分析维度的字典:
            - entry_routers: 入口路由器 Top-K
            - geo_distribution: 地理来源 Top-10
            - mo_distribution: 监测对象关联 Top-10
            - time_distribution: 按小时的时间分布
        """
        # 仅分析异常源（confirmed + suspicious）的原始流量记录
        anomaly_ips = features.index[
            features["traffic_class"].isin(["confirmed", "suspicious"])
        ]
        anomaly_raw = raw_df[raw_df["src_ip_addr"].isin(anomaly_ips)]

        if anomaly_raw.empty:
            logger.warning("[PATH] 无异常源数据，跳过路径重构")
            return {
                "entry_routers": pd.DataFrame(),
                "geo_distribution": pd.DataFrame(),
                "mo_distribution": pd.DataFrame(),
                "time_distribution": pd.DataFrame(),
            }

        result = {}
        result["entry_routers"] = self._analyze_entry_routers(anomaly_raw)
        result["geo_distribution"] = self._analyze_geo(anomaly_raw)
        result["mo_distribution"] = self._analyze_mo(anomaly_raw, features)
        result["time_distribution"] = self._analyze_time(anomaly_raw)

        logger.info(
            "[PATH] 路径重构完成 / 入口节点[%d] / 地理来源[%d]",
            len(result["entry_routers"]),
            len(result["geo_distribution"]),
        )
        return result

    def _analyze_entry_routers(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        入口路由器分析: 按 flow_ip_addr + input_if_index 聚合

        flow_ip_addr 是采集 NetFlow 数据的路由器接口 IP，
        input_if_index 是流量进入路由器的接口索引。
        两者的组合可以精确定位攻击流量进入网络的物理入口。

        结果按流记录数降序排列，取 Top-K。
        """
        group_cols = ["flow_ip_addr", "input_if_index"]
        available = [c for c in group_cols if c in df.columns]
        if not available:
            return pd.DataFrame()

        result = (
            df.groupby(available)
            .agg(
                flow_count=("src_ip_addr", "count"),
                unique_source_ips=("src_ip_addr", "nunique"),
                total_packets=("packets", "sum"),
                total_bytes=("octets", "sum"),
            )
            .reset_index()
            .sort_values("flow_count", ascending=False)
            .head(self.top_k)
        )
        return result

    def _analyze_geo(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        地理来源分析: 按 src_country/province/city/isp 聚合

        揭示攻击源的地理分布和 ISP 归属。
        结果按总包数降序排列，取 Top-10。
        """
        group_cols = ["src_country", "src_province", "src_city", "src_isp"]
        available = [c for c in group_cols if c in df.columns]
        if not available:
            return pd.DataFrame()

        result = (
            df.groupby(available)
            .agg(
                unique_source_ips=("src_ip_addr", "nunique"),
                total_packets=("packets", "sum"),
                total_bytes=("octets", "sum"),
            )
            .reset_index()
            .sort_values("total_packets", ascending=False)
            .head(10)
        )
        return result

    def _analyze_mo(
        self, df: pd.DataFrame, features: pd.DataFrame
    ) -> pd.DataFrame:
        """
        监测对象关联分析: 按 src_mo_code/src_mo_name 聚合

        关联攻击源所属的运营商管理对象（Monitoring Object），
        便于定位责任部门和协调处置。
        结果按总包数降序排列，取 Top-10。
        """
        group_cols = ["src_mo_code", "src_mo_name"]
        available = [c for c in group_cols if c in df.columns]
        if not available:
            return pd.DataFrame()

        result = (
            df.groupby(available)
            .agg(
                attacking_source_ips=("src_ip_addr", "nunique"),
                total_packets=("packets", "sum"),
                total_bytes=("octets", "sum"),
            )
            .reset_index()
            .sort_values("total_packets", ascending=False)
            .head(10)
        )
        return result

    def _analyze_time(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        时间分布分析: 按小时聚合攻击流量

        使用 dt.floor('h') 将时间戳截断到小时级别，
        展示攻击流量的时间演变趋势（如攻击何时开始、何时达到峰值、何时结束）。
        """
        if "flow_time" not in df.columns:
            return pd.DataFrame()

        time_df = df.copy()
        # 将时间戳截断到小时级别（dt.floor('h') 向下取整）
        time_df["hour"] = time_df["flow_time"].dt.floor("h")

        result = (
            time_df.groupby("hour")
            .agg(
                flow_count=("src_ip_addr", "count"),
                unique_source_ips=("src_ip_addr", "nunique"),
                total_packets=("packets", "sum"),
                total_bytes=("octets", "sum"),
            )
            .reset_index()
            .sort_values("hour")
        )
        return result
