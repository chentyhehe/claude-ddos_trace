"""
报告生成与导出模块

本模块负责将分析结果转化为人类可读的报告和可视化图表:

1. 文字报告: 生成结构化的文本分析报告，包含:
   - 分析摘要（时间窗口、源IP总量、有效阈值）
   - 流量分类统计（confirmed/suspicious/borderline/background）
   - Top-10 确认攻击源详情
   - 背景流量特征均值（供对比参考）
   - 指纹聚类摘要

2. CSV 导出:
   - traffic_classification_report.csv: 每个源IP的分类和特征
   - cluster_fingerprint_report.csv: 每个攻击团伙的指纹特征
   - attack_blacklist.csv: 攻击源黑名单（可直接导入防火墙/SOAR）
   - attack_timeline.csv: 攻击时间线（按小时粒度的攻击流量演变）

3. 雷达图: 绘制各攻击集群的指纹雷达图（极坐标），直观展示簇间差异

核心类:
    ReportGenerator: 报告生成与导出入口
"""

import logging
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    生成分析报告、CSV 导出、可视化图表

    所有输出文件保存到 self.output_dir 目录。
    """

    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir

    def generate_text_report(
        self,
        features: pd.DataFrame,
        cluster_report: Optional[pd.DataFrame],
        path_analysis: Dict,
        effective_thresholds: Dict,
    ) -> str:
        """
        生成结构化文字分析报告

        Args:
            features: 带有 traffic_class/attack_confidence/confidence_reasons 的特征 DataFrame
            cluster_report: 聚类报告 DataFrame（可能为 None）
            path_analysis: 路径分析结果字典
            effective_thresholds: 有效阈值字典（含 packets_per_sec、bytes_per_sec）

        Returns:
            格式化的多行报告文本
        """
        lines = []

        # 1. 分析摘要
        lines.append("=" * 60)
        lines.append("DDoS 攻击溯源分析报告")
        lines.append("=" * 60)

        # 时间显示: flow_start_time/flow_end_time 仍是毫秒级 Unix 时间戳，
        # 需要通过 pd.to_datetime(unit='ms') 转换为可读格式
        start_val = features['flow_start_time'].min()
        end_val = features['flow_end_time'].max()
        try:
            start_str = pd.to_datetime(start_val, unit='ms').strftime('%Y-%m-%d %H:%M:%S')
            end_str = pd.to_datetime(end_val, unit='ms').strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            start_str = str(start_val)
            end_str = str(end_val)
        lines.append(f"\n分析时间窗口: {start_str} ~ {end_str}")
        lines.append(f"源 IP 总量: {len(features)}")
        lines.append(f"有效阈值: PPS={effective_thresholds.get('packets_per_sec', 'N/A'):.0f}, "
                     f"BPS={effective_thresholds.get('bytes_per_sec', 'N/A'):.0f}")

        # 2. 流量分类摘要
        lines.append(f"\n{'─' * 40}")
        lines.append("流量分类摘要")
        lines.append(f"{'─' * 40}")

        for cls in ["confirmed", "suspicious", "borderline", "background"]:
            mask = features["traffic_class"] == cls
            count = mask.sum()
            cls_features = features[mask]
            if count > 0:
                avg_conf = cls_features["attack_confidence"].mean()
                total_pkt = cls_features["total_packets"].sum()
                lines.append(f"  {cls:12s}: IP数={count:6d}, 总包数={total_pkt:12.0f}, 平均置信度={avg_conf:.1f}")

        # 3. Top-10 确认攻击源
        confirmed = features[features["traffic_class"] == "confirmed"].sort_values(
            "attack_confidence", ascending=False
        )
        if not confirmed.empty:
            lines.append(f"\n{'─' * 40}")
            lines.append("Top-10 确认攻击源")
            lines.append(f"{'─' * 40}")
            top10 = confirmed.head(10)
            for ip, row in top10.iterrows():
                lines.append(
                    f"  {str(ip):18s} | 置信度={row['attack_confidence']:.1f} | "
                    f"PPS={row.get('packets_per_sec', 0):.0f} | "
                    f"BPS={row.get('bytes_per_sec', 0):.0f} | "
                    f"原因: {row.get('confidence_reasons', '')}"
                )

        # 4. 背景流量特征均值
        background = features[features["traffic_class"] == "background"]
        if not background.empty:
            lines.append(f"\n{'─' * 40}")
            lines.append("背景流量特征均值")
            lines.append(f"{'─' * 40}")
            for col in ["packets_per_sec", "bytes_per_sec", "bytes_per_packet",
                        "burst_ratio", "flow_interval_cv"]:
                if col in background.columns:
                    lines.append(f"  {col:25s}: {background[col].mean():.2f}")

        # 5. 指纹聚类摘要
        if cluster_report is not None and not cluster_report.empty:
            lines.append(f"\n{'─' * 40}")
            lines.append("指纹聚类摘要")
            lines.append(f"{'─' * 40}")
            lines.append(f"  集群数: {cluster_report['cluster_id'].nunique()}")
            for _, row in cluster_report.iterrows():
                lines.append(
                    f"  集群{row['cluster_id']}: 成员数={row['member_count']}, "
                    f"攻击类型={row.get('attack_type', '未知')}"
                )

        lines.append("\n" + "=" * 60)
        report_text = "\n".join(lines)
        logger.info("[REPORT] 文字报告生成完成 / 行数[%d]", len(lines))
        return report_text

    def export_traffic_classification_csv(
        self, features: pd.DataFrame, file_tag: str = ""
    ) -> str:
        """
        导出流量分类报告 CSV

        包含每个源 IP 的攻击置信度、流量分类、关键特征值和地理信息。
        使用 utf-8-sig 编码以支持 Excel 直接打开（BOM 头）。

        Args:
            features: 带有分类标签的特征 DataFrame
            file_tag: 文件名标签，用于区分不同分析任务（如 _ATK-001 或 _1.2.3.4_20260414）
        """
        filename = f"traffic_classification_report{file_tag}.csv"
        filepath = f"{self.output_dir}/{filename}"
        export_cols = [
            "attack_confidence", "traffic_class", "confidence_reasons",
            "total_packets", "total_bytes", "packets_per_sec", "bytes_per_sec",
            "bytes_per_packet", "burst_ratio", "flow_duration",
            "dst_port_count", "protocol_count", "flow_count",
            "country", "province", "city", "isp",
        ]
        available = [c for c in export_cols if c in features.columns]
        features[available].to_csv(filepath, encoding="utf-8-sig")
        logger.info("[REPORT] CSV导出: %s", filepath)
        return filepath

    def export_cluster_report_csv(
        self,
        cluster_report: Optional[pd.DataFrame],
        file_tag: str = "",
    ) -> Optional[str]:
        """
        导出聚类报告 CSV

        每行代表一个攻击集群，包含成员数、IP列表、平均指纹特征和推断的攻击类型。

        Args:
            cluster_report: 聚类报告 DataFrame
            file_tag: 文件名标签
        """
        if cluster_report is None or cluster_report.empty:
            return None
        filename = f"cluster_fingerprint_report{file_tag}.csv"
        filepath = f"{self.output_dir}/{filename}"
        cluster_report.to_csv(filepath, index=False, encoding="utf-8-sig")
        logger.info("[REPORT] CSV导出: %s", filepath)
        return filepath

    def plot_cluster_radar_chart(
        self,
        cluster_report: Optional[pd.DataFrame],
        file_tag: str = "",
    ) -> Optional[str]:
        """
        绘制集群指纹雷达图（极坐标）

        数据处理流程:
        1. 提取 avg_ 前缀的特征列作为雷达图维度
        2. 对数归一化: log1p(|value|)，压缩大数值范围的差异
        3. Min-Max 归一化到 [0, 1]，使各维度在统一尺度上可比较
        4. 绘制极坐标多边形，每个簇一种颜色

        雷达图直观展示各攻击团伙在不同流量维度上的差异，
        便于安全分析师快速识别攻击模式。
        """
        if cluster_report is None or cluster_report.empty:
            return None

        try:
            import matplotlib
            matplotlib.use("Agg")  # 使用非交互式后端，避免在无GUI环境下报错
            import matplotlib.pyplot as plt
        except ImportError:
            logger.warning("[REPORT] matplotlib 未安装，跳过雷达图")
            return None

        # 提取 avg_ 前缀的特征列（聚类报告中的平均指纹值）
        avg_cols = [c for c in cluster_report.columns if c.startswith("avg_")]
        if not avg_cols:
            return None

        labels = [c.replace("avg_", "") for c in avg_cols]
        n_clusters = len(cluster_report)

        # 两步归一化: 先 log1p 压缩量级差异，再 Min-Max 归一到 [0,1]
        # log1p(x) = ln(1+x)，对大值有压缩效果，对小值保留细节
        data = cluster_report[avg_cols].values.copy()
        data = np.log1p(np.abs(data))
        # Min-Max 归一化: (x - min) / (max - min)，col_range=0 时设为 1 避免除零
        col_min = data.min(axis=0)
        col_max = data.max(axis=0)
        col_range = col_max - col_min
        col_range[col_range == 0] = 1
        data_norm = (data - col_min) / col_range

        # 绘制极坐标雷达图
        angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False).tolist()
        angles += angles[:1]

        fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

        colors = plt.cm.tab10(np.linspace(0, 1, max(n_clusters, 1)))
        for i in range(n_clusters):
            values = data_norm[i].tolist()
            values += values[:1]
            ax.plot(angles, values, "o-", linewidth=2, color=colors[i],
                    label=f"Cluster {cluster_report.iloc[i]['cluster_id']}")
            ax.fill(angles, values, alpha=0.15, color=colors[i])

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels, fontsize=9)
        ax.set_title("攻击集群指纹雷达图", fontsize=14, pad=20)
        ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.0))

        filepath = f"{self.output_dir}/cluster_radar_chart{file_tag}.png"
        fig.savefig(filepath, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info("[REPORT] 雷达图保存: %s", filepath)
        return filepath

    # ------------------------------------------------------------------
    # 威胁情报输出
    # ------------------------------------------------------------------

    def export_attack_blacklist_csv(
        self,
        features: pd.DataFrame,
        cluster_report: Optional[pd.DataFrame] = None,
        file_tag: str = "",
    ) -> Optional[str]:
        """
        导出攻击源黑名单 CSV

        仅包含 confirmed + suspicious 的源 IP，附带地理信息、攻击类型、
        所属团伙、首次/最后出现时间等威胁情报字段。
        可直接导入防火墙 ACL、SOAR/SIEM 平台做自动化封禁。

        Args:
            features: 带有分类标签的特征 DataFrame
            cluster_report: 聚类报告 DataFrame（用于关联攻击类型和团伙ID）
            file_tag: 文件名标签

        Returns:
            导出文件路径，无异常源时返回 None
        """
        anomaly = features[features["traffic_class"].isin(["confirmed", "suspicious"])]
        if anomaly.empty:
            logger.info("[REPORT] 无异常源，跳过黑名单导出")
            return None

        # 构建黑名单数据
        blacklist = anomaly.copy()

        # 关联聚类信息（如果有）
        if cluster_report is not None and not cluster_report.empty and "cluster_id" in blacklist.columns:
            # 构建集群ID → 攻击类型的映射
            cluster_type_map = dict(
                zip(cluster_report["cluster_id"], cluster_report.get("attack_type", "未知"))
            )
            blacklist["attack_type"] = blacklist["cluster_id"].map(cluster_type_map).fillna("未知")
        else:
            blacklist["attack_type"] = "未知"

        # 时间转换: 毫秒级 Unix 时间戳 → 可读日期时间
        for col in ["flow_start_time", "flow_end_time"]:
            if col in blacklist.columns:
                try:
                    blacklist[col] = pd.to_datetime(blacklist[col], unit="ms").dt.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                except (ValueError, TypeError):
                    pass

        # 选择黑名单输出字段
        export_cols = [
            "attack_confidence", "traffic_class", "attack_type",
            "cluster_id",
            "total_packets", "total_bytes",
            "packets_per_sec", "bytes_per_sec",
            "country", "province", "city", "isp",
            "flow_start_time", "flow_end_time",
        ]
        available = [c for c in export_cols if c in blacklist.columns]

        filename = f"attack_blacklist{file_tag}.csv"
        filepath = f"{self.output_dir}/{filename}"

        # 索引（src_ip_addr）也写入 CSV
        blacklist[available].to_csv(filepath, encoding="utf-8-sig")

        logger.info("[REPORT] 黑名单导出: %s / 异常源[%d]", filepath, len(blacklist))
        return filepath

    def export_attack_timeline_csv(
        self,
        path_analysis: Dict,
        raw_df: Optional[pd.DataFrame] = None,
        features: Optional[pd.DataFrame] = None,
        file_tag: str = "",
    ) -> Optional[str]:
        """
        导出攻击时间线 CSV

        基于已有的时间分布分析（path_analysis["time_distribution"]），
        进一步补充每个时段的 Top 攻击源和 Top 攻击团伙。
        用于识别攻击的"波次"（多波攻击的间隔、峰值、衰减规律）。

        Args:
            path_analysis: 路径分析结果字典（含 time_distribution）
            raw_df: 原始 NetFlow 数据（用于补充时段级细节）
            features: 带分类标签的特征 DataFrame（用于关联攻击源）
            file_tag: 文件名标签

        Returns:
            导出文件路径，无时间分布数据时返回 None
        """
        time_dist = path_analysis.get("time_distribution")
        if time_dist is None or (isinstance(time_dist, pd.DataFrame) and time_dist.empty):
            logger.info("[REPORT] 无时间分布数据，跳过时间线导出")
            return None

        timeline = time_dist.copy()

        # 如果有原始数据和特征，补充每个时段的 Top 攻击源
        if raw_df is not None and features is not None and "flow_time" in raw_df.columns:
            anomaly_ips = features.index[
                features["traffic_class"].isin(["confirmed", "suspicious"])
            ]
            anomaly_raw = raw_df[raw_df["src_ip_addr"].isin(anomaly_ips)].copy()

            if not anomaly_raw.empty and "flow_time" in anomaly_raw.columns:
                anomaly_raw["hour"] = anomaly_raw["flow_time"].dt.floor("h")

                # 每个时段的 Top 攻击源（按包数最大的 IP）
                top_sources = (
                    anomaly_raw.groupby(["hour", "src_ip_addr"])
                    .agg(total_pkts=("packets", "sum"))
                    .reset_index()
                    .sort_values(["hour", "total_pkts"], ascending=[True, False])
                    .groupby("hour")
                    .head(1)  # 每个时段取包数最大的 IP
                )
                top_source_map = dict(zip(top_sources["hour"], top_sources["src_ip_addr"]))
                timeline["top_source_ip"] = timeline["hour"].map(top_source_map)

                # 每个时段的总字节数
                hour_bytes = anomaly_raw.groupby("hour").agg(
                    total_bytes=("octets", "sum"),
                ).reset_index()
                bytes_map = dict(zip(hour_bytes["hour"], hour_bytes["total_bytes"]))
                timeline["total_bytes"] = timeline["hour"].map(bytes_map)

        # 确保时间列是可读格式
        if "hour" in timeline.columns:
            try:
                timeline["hour"] = timeline["hour"].dt.strftime("%Y-%m-%d %H:%M:%S")
            except (AttributeError, ValueError):
                pass

        filename = f"attack_timeline{file_tag}.csv"
        filepath = f"{self.output_dir}/{filename}"
        timeline.to_csv(filepath, index=False, encoding="utf-8-sig")

        logger.info("[REPORT] 攻击时间线导出: %s / 时段[%d]", filepath, len(timeline))
        return filepath
