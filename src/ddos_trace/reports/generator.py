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

import json
import logging
import os
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
        os.makedirs(self.output_dir, exist_ok=True)

    @staticmethod
    def _prepare_matplotlib():
        """统一 Matplotlib 配置，优先解决中文乱码和负号显示问题。"""
        import matplotlib
        matplotlib.use("Agg")
        from matplotlib import font_manager
        import matplotlib.pyplot as plt

        candidate_fonts = [
            "Microsoft YaHei",
            "SimHei",
            "Noto Sans CJK SC",
            "Source Han Sans SC",
            "WenQuanYi Zen Hei",
            "Arial Unicode MS",
        ]
        available_fonts = {f.name for f in font_manager.fontManager.ttflist}
        selected_font = None
        for font_name in candidate_fonts:
            if font_name in available_fonts:
                selected_font = font_name
                break

        if selected_font:
            matplotlib.rcParams["font.sans-serif"] = [selected_font] + candidate_fonts
        else:
            matplotlib.rcParams["font.sans-serif"] = candidate_fonts + ["DejaVu Sans"]

        matplotlib.rcParams["axes.unicode_minus"] = False
        return plt

    @staticmethod
    def _feature_label_map() -> Dict[str, str]:
        return {
            "bytes_per_packet": "平均包大小",
            "packets_per_sec": "每秒包数",
            "bytes_per_sec": "每秒字节数",
            "burst_ratio": "突发比例",
            "burst_count": "突发次数",
            "flow_interval_mean": "平均间隔",
            "flow_interval_cv": "间隔变异",
            "dst_port_count": "目的端口数",
            "protocol_count": "协议数",
        }

    @staticmethod
    def _table_to_records(table) -> List[dict]:
        """将 DataFrame / list[dict] 统一转换为记录列表。"""
        if table is None:
            return []
        if isinstance(table, pd.DataFrame):
            if table.empty:
                return []
            return table.to_dict(orient="records")
        if isinstance(table, list):
            return [row for row in table if isinstance(row, dict)]
        return []

    @staticmethod
    def _build_cluster_ip_map(
        cluster_report: Optional[pd.DataFrame],
        key_col: str = "cluster_id",
    ) -> Dict[str, str]:
        """从聚类报告中构建 ip -> cluster_id/cluster_key 映射。"""
        cluster_map: Dict[str, str] = {}
        if cluster_report is None or cluster_report.empty or "member_ips" not in cluster_report.columns:
            return cluster_map

        for _, crow in cluster_report.iterrows():
            raw_members = crow.get("member_ips", "")
            if isinstance(raw_members, str):
                members = [ip.strip() for ip in raw_members.split(",") if ip.strip()]
            elif isinstance(raw_members, list):
                members = [str(ip).strip() for ip in raw_members if str(ip).strip()]
            else:
                members = []

            cluster_value = crow.get(key_col, crow.get("cluster_id", ""))
            for ip in members:
                cluster_map[ip] = cluster_value

        return cluster_map

    @staticmethod
    def _json_default(obj):
        """为 JSON 导出提供 numpy/pandas 兼容的默认序列化。"""
        if isinstance(obj, (pd.Timestamp, )):
            return obj.isoformat()
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if pd.isna(obj):
            return None
        return str(obj)

    def generate_text_report(
        self,
        features: pd.DataFrame,
        cluster_report: Optional[pd.DataFrame],
        path_analysis: Dict,
        effective_thresholds: Dict,
        per_type_results: Optional[Dict] = None,
    ) -> str:
        """
        生成结构化文字分析报告

        Args:
            features: 带有 traffic_class/attack_confidence/confidence_reasons 的特征 DataFrame
            cluster_report: 聚类报告 DataFrame（可能为 None）
            path_analysis: 路径分析结果字典
            effective_thresholds: 有效阈值字典（含 packets_per_sec、bytes_per_sec）
            per_type_results: 分项分析结果（per-type 为主流程时非空）

        Returns:
            格式化的多行报告文本
        """
        lines = []

        # 1. 分析摘要
        lines.append("=" * 60)
        lines.append("DDoS 攻击溯源分析报告")
        lines.append("=" * 60)

        # 当 per-type 为主流程且 features 非空时，使用聚合的 features 生成总览
        # 当 features 为空但有 per_type_results 时，从分项结果聚合总览
        if features.empty and not per_type_results:
            lines.append("\n无分析结果。")
            lines.append("\n" + "=" * 60)
            return "\n".join(lines)

        # 时间窗口
        if not features.empty:
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
        elif per_type_results:
            # 从分项结果聚合时间信息
            all_start = []
            all_end = []
            total_ips = set()
            for type_result in per_type_results.values():
                tf = type_result.get("features")
                if tf is not None and not tf.empty:
                    total_ips.update(tf.index.tolist())
                    if "flow_start_time" in tf.columns:
                        all_start.append(tf["flow_start_time"].min())
                    if "flow_end_time" in tf.columns:
                        all_end.append(tf["flow_end_time"].max())
            if all_start:
                try:
                    lines.append(f"\n分析时间窗口: "
                                 f"{pd.to_datetime(min(all_start), unit='ms').strftime('%Y-%m-%d %H:%M:%S')} ~ "
                                 f"{pd.to_datetime(max(all_end), unit='ms').strftime('%Y-%m-%d %H:%M:%S')}")
                except (ValueError, TypeError):
                    pass
            lines.append(f"源 IP 总量: {len(total_ips)}")

        if not features.empty:
            pps_val = effective_thresholds.get('packets_per_sec') or effective_thresholds.get('pps_threshold', 0)
            bps_val = effective_thresholds.get('bytes_per_sec') or effective_thresholds.get('bps_threshold', 0)
            lines.append(f"有效阈值: PPS={pps_val:.0f}, BPS={bps_val:.0f}")

        # 2. 流量分类摘要（从 features 或 per_type_results 聚合）
        lines.append(f"\n{'─' * 40}")
        lines.append("流量分类摘要")
        lines.append(f"{'─' * 40}")

        if not features.empty:
            # 使用聚合的 features（统一视图）
            for cls in ["confirmed", "suspicious", "borderline", "background"]:
                mask = features["traffic_class"] == cls
                count = mask.sum()
                cls_features = features[mask]
                if count > 0:
                    avg_conf = cls_features["attack_confidence"].mean()
                    total_pkt = cls_features["total_packets"].sum()
                    lines.append(f"  {cls:12s}: IP数={count:6d}, 总包数={total_pkt:12.0f}, 平均置信度={avg_conf:.1f}")
        elif per_type_results:
            # 从分项结果聚合分类统计
            agg_counts = {"confirmed": 0, "suspicious": 0, "borderline": 0, "background": 0}
            for type_result in per_type_results.values():
                summary = type_result.get("summary", {})
                agg_counts["confirmed"] += summary.get("confirmed_count", 0)
                agg_counts["suspicious"] += summary.get("suspicious_count", 0)
                agg_counts["borderline"] += summary.get("borderline_count", 0)
                agg_counts["background"] += summary.get("background_count", 0)
            for cls, count in agg_counts.items():
                if count > 0:
                    lines.append(f"  {cls:12s}: IP数={count:6d}")

        # 3. Top-10 确认攻击源（从 features 或 per_type_results 聚合）
        if not features.empty:
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
        elif per_type_results:
            # 从各类型的 top_attackers 聚合，去重取最高分
            all_top = {}
            for at_name, type_result in per_type_results.items():
                summary = type_result.get("summary", {})
                for ip_info in summary.get("top_attackers", []):
                    ip = ip_info["ip"]
                    if ip not in all_top or ip_info["score"] > all_top[ip]["score"]:
                        all_top[ip] = {**ip_info, "attack_type": at_name}
            if all_top:
                top_sorted = sorted(all_top.values(), key=lambda x: x["score"], reverse=True)[:10]
                lines.append(f"\n{'─' * 40}")
                lines.append("Top-10 确认攻击源（跨类型聚合）")
                lines.append(f"{'─' * 40}")
                for ip_info in top_sorted:
                    geo = f"{ip_info.get('country', '')}-{ip_info.get('province', '')}-{ip_info.get('isp', '')}"
                    lines.append(
                        f"  {ip_info['ip']:18s} | score={ip_info['score']:.0f} | "
                        f"PPS={ip_info.get('pps', 0):,.0f} | "
                        f"类型={ip_info.get('attack_type', '')} | "
                        f"{geo}"
                    )

        # 4. 背景流量特征均值
        if not features.empty:
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

        # 6. 路径与来源摘要
        geo_records = self._table_to_records(path_analysis.get("geo_distribution") if path_analysis else None)
        if geo_records:
            lines.append(f"\n{'─' * 40}")
            lines.append("攻击来源地域 Top-5")
            lines.append(f"{'─' * 40}")
            for row in geo_records[:5]:
                label = "-".join([
                    str(row.get("src_country") or "未知"),
                    str(row.get("src_province") or ""),
                    str(row.get("src_isp") or ""),
                ]).strip("-")
                lines.append(
                    f"  {label or '未知'} | 源IP={int(row.get('unique_source_ips', 0))} | "
                    f"包数={float(row.get('total_packets', 0)):.0f}"
                )

        mo_records = self._table_to_records(path_analysis.get("mo_distribution") if path_analysis else None)
        if mo_records:
            lines.append(f"\n{'─' * 40}")
            lines.append("来源监测对象 Top-5")
            lines.append(f"{'─' * 40}")
            for row in mo_records[:5]:
                mo_name = row.get("src_mo_name") or row.get("src_mo_code") or "未知"
                lines.append(
                    f"  {mo_name} | 源IP={int(row.get('attacking_source_ips', 0))} | "
                    f"包数={float(row.get('total_packets', 0)):.0f}"
                )

        time_records = self._table_to_records(path_analysis.get("time_distribution") if path_analysis else None)
        if time_records:
            peak = max(time_records, key=lambda x: float(x.get("total_packets", 0)))
            lines.append(f"\n{'─' * 40}")
            lines.append("攻击时间分布摘要")
            lines.append(f"{'─' * 40}")
            lines.append(f"  活跃时段数: {len(time_records)}")
            lines.append(
                f"  峰值时段: {peak.get('hour')} | 活跃源IP={int(peak.get('unique_source_ips', 0))} | "
                f"包数={float(peak.get('total_packets', 0)):.0f}"
            )

        # 7. 攻击类型分项分析报告
        if per_type_results:
            lines.append("")
            lines.append("=" * 60)
            lines.append("  攻击类型分项分析报告")
            lines.append("=" * 60)

            for idx, (at_name, type_result) in enumerate(
                per_type_results.items(), 1
            ):
                summary = type_result.get("summary", {})
                if not summary:
                    continue

                sub = summary.get("sub_classify", "")
                sub_label = f"({sub})" if sub else ""
                lines.append("")
                lines.append(f"{'━' * 4} [{idx}] {at_name} {sub_label} {'━' * 4}")
                lines.append(f"  匹配规则: {summary.get('matching_rules', '全部流量')}")
                lines.append(
                    f"  Flow 记录: {summary['flow_count']:,} "
                    f"(占总流量 {summary.get('flow_pct', 0)}%)"
                )
                lines.append(
                    f"  流量: {summary.get('total_pps', 0):,.0f} PPS / "
                    f"{summary.get('total_bps', 0):,.0f} BPS"
                )
                lines.append(
                    f"  MySQL 阈值: PPS={summary['threshold_pps']:,} / "
                    f"BPS={summary['threshold_bps']:,}"
                )

                # 阈值超标状态
                pps_status = "超标" if summary.get("exceeds_pps_threshold") else "未超标"
                bps_status = "超标" if summary.get("exceeds_bps_threshold") else "未超标"
                lines.append(f"  阈值状态: PPS {pps_status} / BPS {bps_status}")

                # 流量分类
                lines.append("")
                lines.append("  流量分类:")
                lines.append(
                    f"    确认攻击源(confirmed): {summary['confirmed_count']} 个 IP "
                    f"(PPS 占该类型 {summary.get('confirmed_pps_ratio', 0)}%)"
                )
                lines.append(f"    可疑源(suspicious):    {summary['suspicious_count']} 个 IP")
                lines.append(f"    边界源(borderline):    {summary['borderline_count']} 个 IP")
                lines.append(f"    背景流量(background):  {summary['background_count']} 个 IP")

                # Top-5 确认攻击源
                top_ips = summary.get("top_attackers", [])
                if top_ips:
                    lines.append("")
                    lines.append("  Top-5 确认攻击源:")
                    for rank, ip_info in enumerate(top_ips[:5], 1):
                        geo = f"{ip_info['country']}-{ip_info['province']}-{ip_info['isp']}"
                        lines.append(
                            f"    {rank}. {ip_info['ip']:<16} "
                            f"score={ip_info['score']:.0f}  "
                            f"PPS={ip_info['pps']:,.0f}  "
                            f"{geo}"
                        )

                # 僵尸网络团伙
                type_clusters = type_result.get("clusters")
                if type_clusters is not None and not type_clusters.empty:
                    lines.append("")
                    lines.append("  僵尸网络团伙:")
                    for _, crow in type_clusters.iterrows():
                        lines.append(
                            f"    Cluster-{crow['cluster_id']}: "
                            f"{crow['member_count']} 个 IP, "
                            f"攻击类型={crow.get('attack_type', '未知')}"
                        )

                # 入口路由器
                type_path = type_result.get("path_analysis", {})
                entry_routers = type_path.get("entry_routers")
                if entry_routers is not None and not entry_routers.empty:
                    lines.append("")
                    lines.append("  入口路由器:")
                    for _, r in entry_routers.head(3).iterrows():
                        lines.append(
                            f"    {r.get('flow_ip_addr', '?')} "
                            f"(input_if={r.get('input_if_index', '?')}) → "
                            f"unique_sources={r.get('unique_source_ips', 0)}"
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
            "best_attack_type", "matched_attack_types", "matched_attack_type_count",
            "max_attack_confidence_across_types",
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
            plt = self._prepare_matplotlib()
        except ImportError:
            logger.warning("[REPORT] matplotlib 未安装，跳过雷达图")
            return None

        # 提取 avg_ 前缀的特征列（聚类报告中的平均指纹值）
        avg_cols = [c for c in cluster_report.columns if c.startswith("avg_")]
        if not avg_cols:
            return None

        label_map = self._feature_label_map()
        labels = [label_map.get(c.replace("avg_", ""), c.replace("avg_", "")) for c in avg_cols]
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
            cluster_id = cluster_report.iloc[i]["cluster_id"]
            attack_type = cluster_report.iloc[i].get("attack_type", "未知")
            member_count = cluster_report.iloc[i].get("member_count", 0)
            ax.plot(angles, values, "o-", linewidth=2, color=colors[i],
                    label=f"Cluster {cluster_id} | {attack_type} | {member_count} IP")
            ax.fill(angles, values, alpha=0.15, color=colors[i])

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels, fontsize=9)
        ax.set_ylim(0, 1)
        ax.set_yticks([0.25, 0.5, 0.75, 1.0])
        ax.set_yticklabels(["25%", "50%", "75%", "100%"], fontsize=8)
        ax.set_title("攻击集群指纹雷达图", fontsize=14, pad=20)
        ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.0))

        filepath = f"{self.output_dir}/cluster_radar_chart{file_tag}.png"
        fig.savefig(filepath, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info("[REPORT] 雷达图保存: %s", filepath)
        return filepath

    def plot_top_attacker_radar_chart(
        self,
        features: pd.DataFrame,
        file_tag: str = "",
        top_n: int = 5,
    ) -> Optional[str]:
        """对最高风险攻击源绘制雷达图，便于直观看不同核心攻击源的行为差异。"""
        if features is None or features.empty:
            return None

        required_cols = [
            "bytes_per_packet", "packets_per_sec", "bytes_per_sec",
            "burst_ratio", "burst_count", "flow_interval_mean",
            "flow_interval_cv", "dst_port_count", "protocol_count",
        ]
        available_cols = [c for c in required_cols if c in features.columns]
        if len(available_cols) < 3 or "attack_confidence" not in features.columns:
            return None

        top_df = features.sort_values(
            ["attack_confidence", "packets_per_sec"] if "packets_per_sec" in features.columns else ["attack_confidence"],
            ascending=False,
        ).head(top_n)
        if top_df.empty:
            return None

        try:
            plt = self._prepare_matplotlib()
        except ImportError:
            logger.warning("[REPORT] matplotlib 未安装，跳过攻击源雷达图")
            return None

        data = top_df[available_cols].fillna(0).copy()
        data = np.log1p(np.abs(data))
        col_min = data.min(axis=0)
        col_max = data.max(axis=0)
        col_range = col_max - col_min
        col_range[col_range == 0] = 1
        data_norm = (data - col_min) / col_range

        label_map = self._feature_label_map()
        labels = [label_map.get(col, col) for col in available_cols]
        angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False).tolist()
        angles += angles[:1]

        fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
        colors = plt.cm.Set2(np.linspace(0, 1, len(top_df)))

        for idx, (src_ip, row) in enumerate(data_norm.iterrows()):
            values = row.tolist()
            values += values[:1]
            score = top_df.loc[src_ip].get("attack_confidence", 0)
            ax.plot(angles, values, "o-", linewidth=2, color=colors[idx], label=f"{src_ip} | {score:.0f}分")
            ax.fill(angles, values, alpha=0.12, color=colors[idx])

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels, fontsize=9)
        ax.set_ylim(0, 1)
        ax.set_title("核心攻击源行为雷达图", fontsize=14, pad=20)
        ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.0), fontsize=8)

        filepath = f"{self.output_dir}/top_attacker_radar_chart{file_tag}.png"
        fig.savefig(filepath, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info("[REPORT] 核心攻击源雷达图保存: %s", filepath)
        return filepath

    def export_text_report(
        self,
        report_text: str,
        file_tag: str = "",
    ) -> str:
        """将文字报告落盘，便于归档与分享。"""
        filename = f"analysis_report{file_tag}.md"
        filepath = f"{self.output_dir}/{filename}"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_text)
        logger.info("[REPORT] 文字报告导出: %s", filepath)
        return filepath

    def export_path_analysis_csvs(
        self,
        path_analysis: Dict,
        file_tag: str = "",
    ) -> List[str]:
        """将路径分析的各个维度分别导出为 CSV。"""
        if not path_analysis:
            return []

        export_plan = [
            ("entry_routers", f"entry_router_report{file_tag}.csv"),
            ("geo_distribution", f"geo_distribution_report{file_tag}.csv"),
            ("mo_distribution", f"mo_distribution_report{file_tag}.csv"),
            ("time_distribution", f"time_distribution_report{file_tag}.csv"),
        ]
        exported_files: List[str] = []

        for key, filename in export_plan:
            table = path_analysis.get(key)
            if isinstance(table, pd.DataFrame) and not table.empty:
                filepath = f"{self.output_dir}/{filename}"
                table.to_csv(filepath, index=False, encoding="utf-8-sig")
                exported_files.append(filepath)
                logger.info("[REPORT] 路径分析导出: %s", filepath)

        return exported_files

    def export_summary_json(
        self,
        overview: Optional[Dict],
        effective_thresholds: Dict,
        path_analysis: Dict,
        per_type_results: Optional[Dict],
        file_tag: str = "",
    ) -> str:
        """导出适合程序消费的摘要 JSON。"""
        payload = {
            "overview": overview or {},
            "effective_thresholds": effective_thresholds or {},
            "path_summary": {
                "entry_router_count": len(self._table_to_records(path_analysis.get("entry_routers") if path_analysis else None)),
                "geo_region_count": len(self._table_to_records(path_analysis.get("geo_distribution") if path_analysis else None)),
                "mo_count": len(self._table_to_records(path_analysis.get("mo_distribution") if path_analysis else None)),
                "time_bucket_count": len(self._table_to_records(path_analysis.get("time_distribution") if path_analysis else None)),
            },
            "per_type_summary": {},
        }

        if per_type_results:
            for at_name, type_result in per_type_results.items():
                summary = type_result.get("summary", {})
                if not summary:
                    continue
                payload["per_type_summary"][at_name] = {
                    "flow_count": summary.get("flow_count", 0),
                    "total_pps": summary.get("total_pps", 0),
                    "total_bps": summary.get("total_bps", 0),
                    "confirmed_count": summary.get("confirmed_count", 0),
                    "suspicious_count": summary.get("suspicious_count", 0),
                    "threshold_pps": summary.get("threshold_pps", 0),
                    "threshold_bps": summary.get("threshold_bps", 0),
                    "matching_rules": summary.get("matching_rules", ""),
                    "top_attackers": summary.get("top_attackers", [])[:5],
                }

        filename = f"analysis_summary{file_tag}.json"
        filepath = f"{self.output_dir}/{filename}"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, default=self._json_default)
        logger.info("[REPORT] 摘要JSON导出: %s", filepath)
        return filepath

    def plot_attack_overview(
        self,
        per_type_results: Dict,
        overview: Dict,
        path_analysis: Dict,
        file_tag: str = "",
    ) -> Optional[str]:
        """
        绘制攻击总览仪表盘（2x2 子图布局）

        子图:
        - 左上: 各攻击类型的流量分类分布（堆叠条形图）
        - 右上: Top-10 攻击源 PPS（水平条形图，颜色按 traffic_class）
        - 左下: 各攻击类型 PPS/BPS 对比（分组条形图，双 Y 轴）
        - 右下: Top-10 攻击来源地域（水平条形图）

        Args:
            per_type_results: 分攻击类型结果字典
            overview: 总览统计（来自 _build_overview_from_per_type）
            path_analysis: 路径分析结果（含 geo_distribution）
            file_tag: 文件名标签

        Returns:
            图片文件路径，无数据时返回 None
        """
        if not per_type_results:
            return None

        try:
            plt = self._prepare_matplotlib()
        except ImportError:
            logger.warning("[REPORT] matplotlib 未安装，跳过攻击总览图")
            return None

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle("DDoS 攻击分析总览", fontsize=16, fontweight="bold")

        # ----------------------------------------------------------
        # 子图 1（左上）: 各攻击类型流量分类分布 — 堆叠水平条形图
        # ----------------------------------------------------------
        ax1 = axes[0, 0]
        type_names = []
        class_data = {"confirmed": [], "suspicious": [], "borderline": [], "background": []}

        for at_name, type_result in per_type_results.items():
            s = type_result.get("summary", {})
            if not s:
                continue
            type_names.append(at_name)
            class_data["confirmed"].append(s.get("confirmed_count", 0))
            class_data["suspicious"].append(s.get("suspicious_count", 0))
            class_data["borderline"].append(s.get("borderline_count", 0))
            class_data["background"].append(s.get("background_count", 0))

        if type_names:
            y_pos = np.arange(len(type_names))
            bar_height = 0.6
            class_colors = {
                "confirmed": "#e74c3c",
                "suspicious": "#f39c12",
                "borderline": "#f1c40f",
                "background": "#95a5a6",
            }
            left = np.zeros(len(type_names))
            for cls_name, color in class_colors.items():
                values = class_data[cls_name]
                ax1.barh(y_pos, values, bar_height, left=left, label=cls_name, color=color)
                left = left + np.array(values)
            ax1.set_yticks(y_pos)
            ax1.set_yticklabels(type_names, fontsize=9)
            ax1.set_xlabel("源 IP 数量")
            ax1.set_title("各攻击类型 — 流量分类分布")
            ax1.legend(fontsize=8, loc="lower right")
        else:
            ax1.text(0.5, 0.5, "无数据", ha="center", va="center", transform=ax1.transAxes)
            ax1.set_title("各攻击类型 — 流量分类分布")

        # ----------------------------------------------------------
        # 子图 2（右上）: Top-10 攻击源 PPS — 水平条形图
        # ----------------------------------------------------------
        ax2 = axes[0, 1]
        top_attackers = overview.get("top_attackers", [])

        if top_attackers:
            top10 = top_attackers[:10]
            ips = [a.get("ip", "?") for a in top10]
            pps_vals = [float(a.get("pps", 0)) for a in top10]
            scores = [float(a.get("score", 0)) for a in top10]

            # 按分数渐变色：红色（高分）-> 橙色（低分）
            cmap = plt.cm.YlOrRd
            norm_scores = [
                (s - min(scores)) / (max(scores) - min(scores)) if max(scores) != min(scores) else 1.0
                for s in scores
            ]
            colors = [cmap(ns * 0.7 + 0.3) for ns in norm_scores]

            y_pos = np.arange(len(ips))
            bars = ax2.barh(y_pos, pps_vals, color=colors, height=0.6)
            ax2.set_yticks(y_pos)
            ax2.set_yticklabels(ips, fontsize=8)
            ax2.set_xlabel("PPS (包/秒)")
            ax2.set_title("Top-10 攻击源")

            # 在条形末端标注分数和攻击类型
            for i, (bar, score, attacker) in enumerate(zip(bars, scores, top10)):
                at = attacker.get("attack_type", "")
                ax2.text(
                    bar.get_width() + max(pps_vals) * 0.01, bar.get_y() + bar.get_height() / 2,
                    f"{score:.0f}分 ({at})",
                    va="center", fontsize=7, color="#333333",
                )
            ax2.invert_yaxis()
        else:
            ax2.text(0.5, 0.5, "无数据", ha="center", va="center", transform=ax2.transAxes)
            ax2.set_title("Top-10 攻击源")

        # ----------------------------------------------------------
        # 子图 3（左下）: 各攻击类型 PPS/BPS 对比 — 分组条形图
        # ----------------------------------------------------------
        ax3 = axes[1, 0]
        type_pps = {}
        type_bps = {}
        for at_name, type_result in per_type_results.items():
            s = type_result.get("summary", {})
            if s:
                type_pps[at_name] = float(s.get("total_pps", 0))
                type_bps[at_name] = float(s.get("total_bps", 0))

        if type_pps:
            names = list(type_pps.keys())
            pps_list = [type_pps[n] for n in names]
            bps_list = [type_bps[n] for n in names]
            x = np.arange(len(names))
            width = 0.35

            bars_pps = ax3.bar(x - width / 2, pps_list, width, label="PPS", color="#3498db")
            ax3.set_ylabel("PPS (包/秒)", color="#3498db")
            ax3.tick_params(axis="y", labelcolor="#3498db")

            ax3_twin = ax3.twinx()
            bars_bps = ax3_twin.bar(x + width / 2, bps_list, width, label="BPS", color="#e67e22")
            ax3_twin.set_ylabel("BPS (字节/秒)", color="#e67e22")
            ax3_twin.tick_params(axis="y", labelcolor="#e67e22")

            ax3.set_xticks(x)
            ax3.set_xticklabels(names, fontsize=9, rotation=15, ha="right")
            ax3.set_title("各攻击类型 — PPS / BPS 对比")

            # 图例合并两个轴
            lines1, labels1 = ax3.get_legend_handles_labels()
            lines2, labels2 = ax3_twin.get_legend_handles_labels()
            ax3.legend(lines1 + lines2, labels1 + labels2, fontsize=8, loc="upper right")
        else:
            ax3.text(0.5, 0.5, "无数据", ha="center", va="center", transform=ax3.transAxes)
            ax3.set_title("各攻击类型 — PPS / BPS 对比")

        # ----------------------------------------------------------
        # 子图 4（右下）: Top-10 攻击来源地域 — 水平条形图
        # ----------------------------------------------------------
        ax4 = axes[1, 1]
        geo_records = self._table_to_records(path_analysis.get("geo_distribution") if path_analysis else None)

        if geo_records:
            top_geo = geo_records[:10]
            geo_labels = []
            geo_counts = []
            for g in top_geo:
                country = g.get("src_country", "")
                province = g.get("src_province", "")
                label = f"{country}-{province}" if province else country or "未知"
                geo_labels.append(label)
                geo_counts.append(int(g.get("unique_source_ips", 0)))

            if geo_labels:
                y_pos = np.arange(len(geo_labels))
                colors_geo = plt.cm.Blues(np.linspace(0.4, 0.9, len(geo_labels)))
                ax4.barh(y_pos, geo_counts, color=colors_geo, height=0.6)
                ax4.set_yticks(y_pos)
                ax4.set_yticklabels(geo_labels, fontsize=9)
                ax4.set_xlabel("源 IP 数量")
                ax4.set_title("Top-10 攻击来源地域")
                ax4.invert_yaxis()
            else:
                ax4.text(0.5, 0.5, "无数据", ha="center", va="center", transform=ax4.transAxes)
                ax4.set_title("Top-10 攻击来源地域")
        else:
            ax4.text(0.5, 0.5, "无数据", ha="center", va="center", transform=ax4.transAxes)
            ax4.set_title("Top-10 攻击来源地域")

        plt.tight_layout(rect=[0, 0, 1, 0.95])
        filepath = f"{self.output_dir}/attack_overview{file_tag}.png"
        fig.savefig(filepath, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info("[REPORT] 攻击总览仪表盘保存: %s", filepath)
        return filepath

    def export_attack_situation_report(
        self,
        overview: Dict,
        path_analysis: Dict,
        features: pd.DataFrame,
        file_tag: str = "",
    ) -> str:
        """输出总体攻击态势说明。"""
        total_source_ips = int(overview.get("total_source_ips", len(features) if features is not None else 0))
        anomaly_total = int(overview.get("anomaly_total", 0))
        anomaly_ratio = (anomaly_total / max(total_source_ips, 1)) * 100 if total_source_ips else 0
        attack_types = overview.get("attack_type_names", [])
        top_attackers = overview.get("top_attackers", [])
        geo_records = self._table_to_records(path_analysis.get("geo_distribution") if path_analysis else None)
        router_records = self._table_to_records(path_analysis.get("entry_routers") if path_analysis else None)
        time_records = self._table_to_records(path_analysis.get("time_distribution") if path_analysis else None)

        lines = [
            "# 总体攻击态势说明",
            "",
            f"- 源 IP 总量: {total_source_ips}",
            f"- 异常源总量: {anomaly_total}",
            f"- 异常源占比: {anomaly_ratio:.1f}%",
            f"- 涉及攻击类型数: {len(attack_types)}",
            f"- 攻击类型列表: {', '.join(attack_types) if attack_types else '未知'}",
        ]

        if top_attackers:
            top = top_attackers[0]
            lines.extend([
                "",
                "## 核心攻击源",
                f"- 最高风险源 IP: {top.get('ip', '未知')}",
                f"- 最佳匹配攻击类型: {top.get('attack_type', '未知')}",
                f"- 最高置信度: {top.get('score', 0)}",
                f"- 最高 PPS: {top.get('pps', 0)}",
            ])

        if geo_records:
            top_geo = geo_records[0]
            geo_label = "-".join([
                str(top_geo.get("src_country") or "未知"),
                str(top_geo.get("src_province") or ""),
                str(top_geo.get("src_isp") or ""),
            ]).strip("-")
            lines.extend([
                "",
                "## 主要来源地域",
                f"- Top 地域: {geo_label or '未知'}",
                f"- 源 IP 数: {int(top_geo.get('unique_source_ips', 0))}",
            ])

        if router_records:
            top_router = router_records[0]
            lines.extend([
                "",
                "## 主要入口节点",
                f"- 入口设备: {top_router.get('flow_ip_addr', '未知')}",
                f"- 接口索引: {top_router.get('input_if_index', '未知')}",
                f"- 异常源数: {int(top_router.get('unique_source_ips', 0))}",
            ])

        if time_records:
            peak = max(time_records, key=lambda x: float(x.get("total_packets", 0)))
            lines.extend([
                "",
                "## 攻击时间态势",
                f"- 峰值时段: {peak.get('hour', '未知')}",
                f"- 峰值包数: {float(peak.get('total_packets', 0)):.0f}",
                f"- 峰值活跃源 IP: {int(peak.get('unique_source_ips', 0))}",
            ])

        filename = f"overall_attack_situation{file_tag}.md"
        filepath = f"{self.output_dir}/{filename}"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        logger.info("[REPORT] 总体攻击态势说明导出: %s", filepath)
        return filepath

    def plot_attack_timeline_chart(
        self,
        path_analysis: Dict,
        file_tag: str = "",
    ) -> Optional[str]:
        """输出攻击时间线趋势图。"""
        timeline = path_analysis.get("time_distribution") if path_analysis else None
        if timeline is None or not isinstance(timeline, pd.DataFrame) or timeline.empty:
            return None

        try:
            plt = self._prepare_matplotlib()
        except ImportError:
            logger.warning("[REPORT] matplotlib 未安装，跳过时间线图")
            return None

        plot_df = timeline.copy().sort_values("hour")
        fig, ax1 = plt.subplots(figsize=(12, 5))
        ax1.plot(plot_df["hour"], plot_df["total_packets"], marker="o", color="#e74c3c", label="总包数")
        ax1.set_xlabel("时间")
        ax1.set_ylabel("总包数", color="#e74c3c")
        ax1.tick_params(axis="y", labelcolor="#e74c3c")

        ax2 = ax1.twinx()
        ax2.plot(plot_df["hour"], plot_df["unique_source_ips"], marker="s", color="#3498db", label="活跃源IP数")
        ax2.set_ylabel("活跃源IP数", color="#3498db")
        ax2.tick_params(axis="y", labelcolor="#3498db")

        ax1.set_title("攻击时间线趋势图")
        fig.autofmt_xdate(rotation=20)
        fig.tight_layout()

        filepath = f"{self.output_dir}/attack_timeline_chart{file_tag}.png"
        fig.savefig(filepath, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info("[REPORT] 攻击时间线趋势图保存: %s", filepath)
        return filepath

    def plot_source_distribution_dashboard(
        self,
        path_analysis: Dict,
        file_tag: str = "",
    ) -> Optional[str]:
        """输出来源分布仪表盘。"""
        if not path_analysis:
            return None

        geo_df = path_analysis.get("geo_distribution")
        mo_df = path_analysis.get("mo_distribution")
        router_df = path_analysis.get("entry_routers")
        has_data = any(
            isinstance(df, pd.DataFrame) and not df.empty
            for df in [geo_df, mo_df, router_df]
        )
        if not has_data:
            return None

        try:
            plt = self._prepare_matplotlib()
        except ImportError:
            logger.warning("[REPORT] matplotlib 未安装，跳过来源分布图")
            return None

        fig, axes = plt.subplots(1, 3, figsize=(18, 5))
        fig.suptitle("攻击来源分布仪表盘", fontsize=15, fontweight="bold")

        if isinstance(geo_df, pd.DataFrame) and not geo_df.empty:
            top_geo = geo_df.head(8).copy()
            labels = top_geo.apply(
                lambda r: f"{r.get('src_country', '未知')}-{r.get('src_province', '')}".strip("-"),
                axis=1,
            )
            axes[0].barh(labels, top_geo["unique_source_ips"], color="#5dade2")
            axes[0].invert_yaxis()
            axes[0].set_title("地域来源 Top-8")
            axes[0].set_xlabel("源 IP 数量")
        else:
            axes[0].text(0.5, 0.5, "无数据", ha="center", va="center", transform=axes[0].transAxes)
            axes[0].set_title("地域来源 Top-8")

        if isinstance(mo_df, pd.DataFrame) and not mo_df.empty:
            top_mo = mo_df.head(8).copy()
            labels = top_mo["src_mo_name"].fillna(top_mo["src_mo_code"]).fillna("未知")
            axes[1].barh(labels, top_mo["attacking_source_ips"], color="#58d68d")
            axes[1].invert_yaxis()
            axes[1].set_title("来源监测对象 Top-8")
            axes[1].set_xlabel("源 IP 数量")
        else:
            axes[1].text(0.5, 0.5, "无数据", ha="center", va="center", transform=axes[1].transAxes)
            axes[1].set_title("来源监测对象 Top-8")

        if isinstance(router_df, pd.DataFrame) and not router_df.empty:
            top_router = router_df.head(8).copy()
            labels = top_router.apply(
                lambda r: f"{r.get('flow_ip_addr', '?')}#{r.get('input_if_index', '?')}",
                axis=1,
            )
            axes[2].barh(labels, top_router["unique_source_ips"], color="#f5b041")
            axes[2].invert_yaxis()
            axes[2].set_title("入口节点 Top-8")
            axes[2].set_xlabel("异常源数")
        else:
            axes[2].text(0.5, 0.5, "无数据", ha="center", va="center", transform=axes[2].transAxes)
            axes[2].set_title("入口节点 Top-8")

        plt.tight_layout(rect=[0, 0, 1, 0.94])
        filepath = f"{self.output_dir}/source_distribution_dashboard{file_tag}.png"
        fig.savefig(filepath, dpi=150, bbox_inches="tight")
        plt.close(fig)
        logger.info("[REPORT] 来源分布仪表盘保存: %s", filepath)
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
            "cluster_id", "best_attack_type", "matched_attack_types",
            "matched_attack_type_count", "max_attack_confidence_across_types",
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

    # ------------------------------------------------------------------
    # 可疑攻击源导出
    # ------------------------------------------------------------------

    def export_suspicious_sources_csv(
        self,
        per_type_results: Dict,
        file_tag: str = "",
    ) -> Optional[str]:
        """
        导出可疑攻击源 CSV

        仅包含 confirmed + suspicious 的源 IP，按攻击类型分行。
        同一 IP 在不同攻击类型下各占一行，附带可疑原因说明。

        Args:
            per_type_results: {attack_type: {features, summary, clusters, ...}}
            file_tag: 文件名标签

        Returns:
            导出文件路径，无数据时返回 None
        """
        if not per_type_results:
            return None

        rows = []
        for at_name, type_result in per_type_results.items():
            features = type_result.get("features")
            summary = type_result.get("summary", {})
            if features is None or features.empty:
                continue

            # 筛选 confirmed + suspicious
            anomaly = features[features["traffic_class"].isin(["confirmed", "suspicious"])]
            if anomaly.empty:
                continue

            # 构建 cluster_map: ip -> cluster_id
            cluster_map = self._build_cluster_ip_map(type_result.get("clusters"))

            total_pps = summary.get("total_pps", 1)

            for ip, row in anomaly.iterrows():
                ip_str = ip if isinstance(ip, str) else str(ip)
                pps = float(row.get("packets_per_sec", 0))
                bps = float(row.get("bytes_per_sec", 0))

                # 时间转换
                row_data = {
                    "src_ip": ip_str,
                    "attack_type": at_name,
                    "sub_classify": summary.get("sub_classify", ""),
                    "traffic_class": row.get("traffic_class", ""),
                    "attack_confidence": round(float(row.get("attack_confidence", 0)), 1),
                    "suspicious_reasons": row.get("confidence_reasons", ""),
                    "packets_per_sec": round(pps, 0),
                    "bytes_per_sec": round(bps, 0),
                    "total_packets": round(float(row.get("total_packets", 0)), 0),
                    "total_bytes": round(float(row.get("total_bytes", 0)), 0),
                    "bytes_per_packet": round(float(row.get("bytes_per_packet", 0)), 2),
                    "burst_ratio": round(float(row.get("burst_ratio", 0)), 2),
                    "flow_count": int(row.get("flow_count", 0)),
                    "contribution_pct": round(pps / max(total_pps, 1) * 100, 2),
                    "cluster_id": cluster_map.get(ip_str, ""),
                    "country": row.get("country", ""),
                    "province": row.get("province", ""),
                    "city": row.get("city", ""),
                    "isp": row.get("isp", ""),
                }

                # 时间字段处理
                for col in ["flow_start_time", "flow_end_time"]:
                    if col in row.index:
                        val = row[col]
                        try:
                            row_data[col] = pd.to_datetime(
                                float(val), unit="ms"
                            ).strftime("%Y-%m-%d %H:%M:%S")
                        except (ValueError, TypeError, OSError):
                            row_data[col] = str(val) if pd.notna(val) else ""
                    else:
                        row_data[col] = ""

                rows.append(row_data)

        if not rows:
            logger.info("[REPORT] 无可疑攻击源，跳过导出")
            return None

        df = pd.DataFrame(rows)
        df.sort_values("attack_confidence", ascending=False, inplace=True)

        filename = f"suspicious_sources{file_tag}.csv"
        filepath = f"{self.output_dir}/{filename}"
        df.to_csv(filepath, index=False, encoding="utf-8-sig")

        logger.info(
            "[REPORT] 可疑攻击源导出: %s / 行数[%d] / 攻击类型[%d]",
            filepath, len(df), len(per_type_results),
        )
        return filepath

    # ------------------------------------------------------------------
    # 分项报告: 按攻击类型的详细分析导出
    # ------------------------------------------------------------------

    def export_per_type_csv(
        self,
        per_type_results: Dict,
        file_tag: str = "",
    ) -> Optional[str]:
        """
        导出按攻击类型分项的分析结果 CSV

        每行 = 一个源 IP 在一种攻击类型下的分析结果。

        Args:
            per_type_results: {attack_type: {features, summary, ...}}
            file_tag: 文件名标签

        Returns:
            导出文件路径，无数据时返回 None
        """
        if not per_type_results:
            return None

        rows = []
        for at_name, type_result in per_type_results.items():
            features = type_result.get("features")
            summary = type_result.get("summary", {})
            if features is None or features.empty:
                continue

            cluster_map = self._build_cluster_ip_map(type_result.get("clusters"))

            for ip, row in features.iterrows():
                ip_str = ip if isinstance(ip, str) else str(ip)
                total_pps = summary.get("total_pps", 1)
                pps = row.get("packets_per_sec", 0)
                contribution = round(pps / max(total_pps, 1) * 100, 2)

                rows.append({
                    "attack_type": at_name,
                    "sub_classify": summary.get("sub_classify", ""),
                    "matching_rules": summary.get("matching_rules", ""),
                    "src_ip": ip_str,
                    "traffic_class": row.get("traffic_class", ""),
                    "attack_confidence": round(row.get("attack_confidence", 0), 1),
                    "confidence_reasons": row.get("confidence_reasons", ""),
                    "packets_per_sec": round(pps, 0),
                    "bytes_per_sec": round(row.get("bytes_per_sec", 0), 0),
                    "total_packets": round(row.get("total_packets", 0), 0),
                    "total_bytes": round(row.get("total_bytes", 0), 0),
                    "bytes_per_packet": round(row.get("bytes_per_packet", 0), 2),
                    "burst_ratio": round(row.get("burst_ratio", 0), 2),
                    "flow_count": int(row.get("flow_count", 0)),
                    "contribution_pct": contribution,
                    "cluster_id": cluster_map.get(ip_str, ""),
                    "threshold_pps": summary.get("threshold_pps", 0),
                    "threshold_bps": summary.get("threshold_bps", 0),
                    "dominant_protocol": row.get("dominant_protocol", ""),
                    "dominant_dst_port": row.get("dominant_dst_port", ""),
                    "country": row.get("country", ""),
                    "province": row.get("province", ""),
                    "isp": row.get("isp", ""),
                })

        if not rows:
            return None

        import pandas as pd
        df = pd.DataFrame(rows)
        filename = f"attack_type_detail{file_tag}.csv"
        filepath = f"{self.output_dir}/{filename}"
        df.to_csv(filepath, index=False, encoding="utf-8-sig")

        logger.info(
            "[REPORT] 分项攻击类型详情导出: %s / 行数[%d] / 攻击类型[%d]",
            filepath, len(df), len(per_type_results),
        )
        return filepath
