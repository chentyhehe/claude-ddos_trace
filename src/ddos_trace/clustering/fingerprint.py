"""
攻击指纹聚类模块 - 三级算法降级策略

本模块对检测出的异常源 IP 进行聚类分析，识别具有相似流量指纹的攻击源团伙。
同一僵尸网络（botnet）的受控主机通常表现出高度相似的流量特征（包大小、速率、
突发模式等），聚类可以揭示这种共谋关系。

聚类算法采用三级降级策略:
    1. HDBSCAN（首选）: 基于密度的层次聚类，无需预设簇数，能自动发现任意形状的簇
    2. DBSCAN（次选）: 经典密度聚类，需要手动设置 eps 参数，使用 ball_tree 加速
    3. MiniBatchKMeans（兜底）: 基于质心的划分聚类，计算效率高但需预设簇数

降级触发条件:
    - HDBSCAN → DBSCAN: hdbscan 包未安装或 HDBSCAN 运行失败
    - DBSCAN → MiniBatchKMeans: DBSCAN 运行失败
    - 全部失败: 返回 None，跳过聚类环节

大数据保护:
    当异常源数量超过 max_samples_for_clustering（默认 10000）时，
    随机采样后训练，再通过 1-NN 将标签回传到全量样本。

核心类:
    AttackFingerprintClusterer: 聚类分析入口
"""

import logging
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from ddos_trace.config.models import TracebackConfig

logger = logging.getLogger(__name__)


class AttackFingerprintClusterer:
    """
    攻击源指纹聚类 - 识别僵尸网络团伙

    将具有相似流量特征（包大小、速率、突发模式等）的异常源 IP 聚为一簇，
    从而识别出可能的同一僵尸网络或同一攻击工具控制的多个源。
    """

    def __init__(self, config: TracebackConfig):
        self.config = config

    def cluster(
        self, features: pd.DataFrame
    ) -> Optional[pd.DataFrame]:
        """
        对异常源进行聚类分析

        Args:
            features: 仅包含 anomaly_sources（confirmed + suspicious）的特征 DataFrame

        Returns:
            聚类报告 DataFrame，每行一个集群；如果样本不足返回 None
        """
        # 异常源数量不足时无法形成有意义的簇
        if len(features) < self.config.min_cluster_size:
            logger.info(
                "[CLUSTER] 异常源数[%d] < 最小聚类数[%d]，跳过聚类",
                len(features),
                self.config.min_cluster_size,
            )
            return None

        logger.info("[CLUSTER] 开始聚类 / 异常源数[%d]", len(features))

        # 提取 9 维聚类特征（由 TracebackConfig.cluster_features 定义）
        feature_cols = self.config.cluster_features
        # 检查实际可用的特征列（防御列缺失的情况）
        available_cols = [c for c in feature_cols if c in features.columns]
        if len(available_cols) < 3:  # 至少需要 3 个维度才能进行有意义的聚类
            logger.warning("[CLUSTER] 可用特征不足，跳过聚类")
            return None

        X = features[available_cols].fillna(0).values

        # 标准化: 使用 RobustScaler（基于中位数和 IQR）而非 StandardScaler
        # 原因: 攻击流量可能包含极端异常值，RobustScaler 对异常值更鲁棒
        from sklearn.preprocessing import RobustScaler

        scaler = RobustScaler()
        X_scaled = scaler.fit_transform(X)

        # 大数据保护: 当样本数超过阈值时，随机采样后训练
        # 采样后通过 1-NN 将标签回传到全量样本，避免 OOM
        sampled = len(X_scaled) > self.config.max_samples_for_clustering
        if sampled:
            logger.info(
                "[CLUSTER] 样本数[%d] > 阈值[%d]，启用采样训练",
                len(X_scaled),
                self.config.max_samples_for_clustering,
            )
            # 使用固定随机种子(42)保证结果可复现
            rng = np.random.default_rng(42)
            sample_idx = rng.choice(
                len(X_scaled), self.config.max_samples_for_clustering, replace=False
            )
            X_train = X_scaled[sample_idx]
        else:
            X_train = X_scaled

        # 三级算法降级
        labels = self._fit_cluster(X_train, X_scaled, sampled, sample_idx if sampled else None)

        if labels is None:
            logger.warning("[CLUSTER] 所有聚类算法均失败")
            return None

        # 将标签附加到 features
        features = features.copy()
        features["cluster_id"] = labels

        # 生成聚类报告
        report = self._build_report(features, available_cols)
        logger.info(
            "[CLUSTER] 聚类完成 / 集群数[%d]",
            report["cluster_id"].nunique(),
        )
        return report

    # ------------------------------------------------------------------
    # 三级算法降级
    # ------------------------------------------------------------------

    def _fit_cluster(
        self,
        X_train: np.ndarray,
        X_full: np.ndarray,
        sampled: bool,
        sample_idx: Optional[np.ndarray],
    ) -> Optional[np.ndarray]:
        """
        三级降级聚类: HDBSCAN → DBSCAN → MiniBatchKMeans

        降级策略的合理性:
        - HDBSCAN 最适合此场景: 无需预设簇数，可发现任意形状的簇，自带噪声过滤
        - DBSCAN 是 HDBSCAN 的"简化版": 需要手动设 eps，但同样基于密度
        - MiniBatchKMeans 作为兜底: 计算最快，但需预设簇数且只能发现凸形簇
        """
        # 尝试 HDBSCAN
        labels = self._try_hdbscan(X_train, X_full, sampled, sample_idx)
        if labels is not None:
            return labels

        # 尝试 DBSCAN
        labels = self._try_dbscan(X_train, X_full, sampled, sample_idx)
        if labels is not None:
            return labels

        # 兜底 MiniBatchKMeans
        return self._fallback_kmeans(X_train, X_full, sampled, sample_idx)

    def _try_hdbscan(
        self,
        X_train: np.ndarray,
        X_full: np.ndarray,
        sampled: bool,
        sample_idx: Optional[np.ndarray],
    ) -> Optional[np.ndarray]:
        """
        首选: HDBSCAN（基于密度的层次聚类）

        优势:
        - 无需预设簇数，自动根据数据密度确定
        - 可发现任意形状的簇（攻击源的分布通常不是凸形）
        - 自动标记噪声点（标签 -1）
        """
        try:
            import hdbscan

            clusterer = hdbscan.HDBSCAN(
                min_cluster_size=self.config.min_cluster_size,
                metric="euclidean",
            )
            train_labels = clusterer.fit_predict(X_train)
            logger.info("[CLUSTER] HDBSCAN 成功 / 训练标签数[%d]", len(train_labels))
            return self._extend_labels(train_labels, X_full, sampled, sample_idx)
        except ImportError:
            logger.info("[CLUSTER] hdbscan 未安装，尝试 DBSCAN")
            return None
        except Exception as e:
            logger.warning("[CLUSTER] HDBSCAN 失败: %s", e)
            return None

    def _try_dbscan(
        self,
        X_train: np.ndarray,
        X_full: np.ndarray,
        sampled: bool,
        sample_idx: Optional[np.ndarray],
    ) -> Optional[np.ndarray]:
        """
        次选: DBSCAN（基于密量的空间聚类）

        使用 ball_tree 算法加速近邻搜索，eps=0.5（在 RobustScaler 标准化后的空间中）。
        相比 HDBSCAN 的缺点: 需要手动设置 eps 参数，对参数敏感。
        """
        try:
            from sklearn.cluster import DBSCAN

            clusterer = DBSCAN(
                eps=0.5,
                min_samples=self.config.min_cluster_size,
                algorithm="ball_tree",
            )
            train_labels = clusterer.fit_predict(X_train)
            logger.info("[CLUSTER] DBSCAN 成功 / 训练标签数[%d]", len(train_labels))
            return self._extend_labels(train_labels, X_full, sampled, sample_idx)
        except Exception as e:
            logger.warning("[CLUSTER] DBSCAN 失败: %s", e)
            return None

    def _fallback_kmeans(
        self,
        X_train: np.ndarray,
        X_full: np.ndarray,
        sampled: bool,
        sample_idx: Optional[np.ndarray],
    ) -> Optional[np.ndarray]:
        """
        兜底: MiniBatchKMeans（基于质心的增量式聚类）

        作为最后手段使用:
        - 自动计算簇数: max(2, min(10, 样本数 / min_cluster_size))
        - 使用 MiniBatchKMeans 而非 KMeans 以支持大数据量
        - batch_size 限制为 min(1000, 样本数) 以控制内存
        """
        try:
            from sklearn.cluster import MiniBatchKMeans

            # 动态计算簇数: 在 2~10 之间，按样本数/min_cluster_size 估算
            n_clusters = max(2, min(10, len(X_train) // self.config.min_cluster_size))
            clusterer = MiniBatchKMeans(
                n_clusters=n_clusters,
                random_state=42,
                batch_size=min(1000, len(X_train)),
            )
            train_labels = clusterer.fit_predict(X_train)
            logger.info("[CLUSTER] MiniBatchKMeans 成功 / K[%d]", n_clusters)
            return self._extend_labels(train_labels, X_full, sampled, sample_idx)
        except Exception as e:
            logger.error("[CLUSTER] MiniBatchKMeans 也失败: %s", e)
            return None

    def _extend_labels(
        self,
        train_labels: np.ndarray,
        X_full: np.ndarray,
        sampled: bool,
        sample_idx: Optional[np.ndarray],
    ) -> np.ndarray:
        """
        将训练集的聚类标签回传到全量样本

        当使用了采样训练时，通过 1-NN（最近邻）分类器将标签扩展到所有样本:
        1. 用训练集中有效标签（非噪声点 label >= 0）的样本作为训练数据
        2. 训练 1-NN 分类器（K=1，即每个样本继承最近邻的标签）
        3. 对全量数据进行预测

        如果没有使用采样（sampled=False），直接返回原始标签。
        """
        if not sampled:
            return train_labels

        from sklearn.neighbors import KNeighborsClassifier

        # 过滤噪声点（标签 -1），只用有效簇的样本训练 1-NN
        # 如果有效样本不足 2 个，无法训练分类器，直接返回原始标签
        valid = train_labels >= 0
        if valid.sum() < 2:
            return train_labels

        knn = KNeighborsClassifier(n_neighbors=1)
        knn.fit(
            X_full[sample_idx][valid],
            train_labels[valid],
        )
        full_labels = knn.predict(X_full)
        return full_labels

    # ------------------------------------------------------------------
    # 聚类报告
    # ------------------------------------------------------------------

    def _build_report(
        self, features: pd.DataFrame, feature_cols: List[str]
    ) -> pd.DataFrame:
        """
        生成每个集群的汇总报告

        对每个非噪声簇（cluster_id >= 0），统计:
        - 成员数量和 IP 列表
        - 各特征维度的平均值（簇指纹）
        - 推断的攻击类型

        返回的 DataFrame 每行代表一个攻击团伙。
        """
        rows = []
        for cluster_id, group in features.groupby("cluster_id"):
            # 噪声点（cluster_id = -1）跳过，不纳入报告
            if cluster_id == -1:
                continue

            row = {
                "cluster_id": cluster_id,
                "member_count": len(group),
                "member_ips": ",".join(group.index.astype(str)),
            }
            # 平均指纹特征
            for col in feature_cols:
                if col in group.columns:
                    row[f"avg_{col}"] = group[col].mean()

            # 攻击类型推断
            row["attack_type"] = self._infer_attack_type(group)

            rows.append(row)

        return pd.DataFrame(rows)

    def _infer_attack_type(self, group: pd.DataFrame) -> str:
        """
        推断集群的攻击类型

        基于两个关键指标:
        - 平均包大小 (avg_bpp):
            < 100B → 小包攻击（SYN Flood / ACK Flood 等）
            > 1400B → 大包攻击（DNS/NTP 放大攻击等）
            100-1400B → 中等包，需结合协议判断
        - 主导协议 (dominant_protocol):
            6 (TCP) → SYN Flood / TCP Flood
            17 (UDP) → UDP Flood / 反射放大攻击
            1 (ICMP) → ICMP Flood

        优先级: 小包+TCP → SYN Flood > 小包泛洪 > 大包泛洪 > UDP Flood > ICMP Flood > TCP Flood > 混合
        """
        avg_bpp = group.get("bytes_per_packet", pd.Series([0])).mean()

        # 使用主导协议（众数），而非 protocol_count
        proto = 0
        if "dominant_protocol" in group.columns:
            mode_vals = group["dominant_protocol"].dropna().mode()
            if not mode_vals.empty:
                proto = int(mode_vals.iloc[0])

        # 协议常量: 1=ICMP, 6=TCP, 17=UDP（标准 IP 协议号）
        # 攻击类型判定逻辑（按优先级从高到低）:
        if avg_bpp < 100 and proto == 6:
            return "SYN Flood"
        if avg_bpp < 100:
            return "小包洪泛"
        if avg_bpp > 1400:
            return "大包洪泛"
        if proto == 17:
            return "UDP Flood"
        if proto == 1:
            return "ICMP Flood"
        if proto == 6:
            return "TCP Flood"
        return "混合型攻击"
