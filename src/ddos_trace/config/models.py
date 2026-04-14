"""
配置模块 - 提供所有配置数据类及配置文件加载

本模块定义了 DDoS 攻击溯源分析器的全部配置项，包括：
- ClickHouseConfig: ClickHouse 数据库连接参数
- ThresholdConfig: 流量异常检测阈值（PPS/BPS 硬阈值）
- TracebackConfig: 溯源分析参数（聚类特征、置信度分级阈值、算法参数等）
- ApiConfig: FastAPI 服务监听配置
- OutputConfig: 报告输出目录配置
- AppConfig: 上述所有配置的聚合根

配置加载优先级: 环境变量 > config.yaml > 代码默认值
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml


@dataclass
class ClickHouseConfig:
    """
    ClickHouse 连接配置

    默认连接 uniflow_controller_clickhouse_trunk 数据库的
    analytics_netflow_dist（分布式NetFlow表）和 detect_attack_dist（告警表）。
    """

    host: str = "localhost"
    port: int = 9000
    username: str = "default"
    password: str = ""
    database: str = "uniflow_controller_clickhouse_trunk"
    table_name: str = "analytics_netflow_dist"
    alert_table_name: str = "detect_attack_dist"
    timeout: int = 30          # 连接与收发超时（秒）
    chunk_size: int = 100000   # 分块查询大小（预留，暂未使用）

    @property
    def connection_params(self) -> dict:
        """生成 clickhouse-driver.Client 所需的连接参数字典"""
        return {
            "host": self.host,
            "port": self.port,
            "user": self.username,
            "password": self.password,
            "database": self.database,
            "connect_timeout": self.timeout,
            "send_receive_timeout": self.timeout,
        }


@dataclass
class ThresholdConfig:
    """
    流量异常检测硬阈值配置

    pps_threshold: 每秒包数阈值，超过此值的源IP被标记为PPS超标
        默认 500,000 pps — 基于运营商骨干网经验值，正常单源IP极少达到此量级
    bps_threshold: 每秒字节数阈值，超过此值的源IP被标记为BPS超标
        默认 20,000,000 bps (~20 Mbps) — 同样基于骨干网基线
    """

    pps_threshold: int = 500_000
    bps_threshold: int = 20_000_000


@dataclass
class TracebackConfig:
    """
    溯源分析核心配置

    包含聚类算法参数、置信度分级阈值、聚类特征维度选择等关键配置。
    这些参数直接影响攻击源识别的准确率和召回率。
    """

    min_cluster_size: int = 5  # HDBSCAN/DBSCAN 的最小簇大小，低于此值的噪声点会被丢弃
    use_dynamic_baseline: bool = True  # 是否使用动态基线（取 P95 与硬阈值中的较大值）
    target_ips: List[str] = field(default_factory=list)      # 预设的攻击目标IP列表
    target_mo_codes: List[str] = field(default_factory=list)  # 预设的监测对象编码列表

    # 置信度分级阈值（百分制）:
    #   >= confirmed_threshold (80) → confirmed（确认攻击源）
    #   >= suspicious_threshold (60) → suspicious（可疑源）
    #   >= borderline_threshold (40) → borderline（边界源）
    #   < borderline_threshold → background（背景流量）
    confirmed_threshold: float = 80.0
    suspicious_threshold: float = 60.0
    borderline_threshold: float = 40.0

    # 聚类使用的 9 维特征向量
    # 这些特征从不同维度刻画攻击流量的"指纹":
    #   bytes_per_packet   — 包大小特征，用于区分 SYN Flood（小包）vs 大包洪泛
    #   packets_per_sec    — 包速率特征
    #   bytes_per_sec      — 字节速率特征
    #   burst_ratio        — 突发性特征（最大包数/平均包数）
    #   burst_count        — 突发次数
    #   flow_interval_mean — 流平均间隔
    #   flow_interval_cv   — 流间隔变异系数，反映发送规律性
    #   dst_port_count     — 目的端口多样性
    #   protocol_count     — 协议多样性
    cluster_features: List[str] = field(default_factory=lambda: [
        "bytes_per_packet",
        "packets_per_sec",
        "bytes_per_sec",
        "burst_ratio",
        "burst_count",
        "flow_interval_mean",
        "flow_interval_cv",
        "dst_port_count",
        "protocol_count",
    ])

    # IP 协议号常量，用于攻击类型推断
    PROTO_ICMP: int = 1
    PROTO_TCP: int = 6
    PROTO_UDP: int = 17
    # 聚类训练时的最大样本数限制
    # 当异常源数量超过此值时，随机采样后再训练，以控制内存和计算开销
    max_samples_for_clustering: int = 10_000


@dataclass
class ApiConfig:
    """API 服务监听配置，默认绑定所有网卡的 8000 端口"""

    host: str = "0.0.0.0"
    port: int = 8000


@dataclass
class OutputConfig:
    """输出目录配置，报告和图表将保存到此目录"""

    dir: str = "./output"


@dataclass
class AppConfig:
    """
    应用总配置 - 聚合所有子配置

    由 load_config() 函数根据 YAML 文件和环境变量构建。
    """

    clickhouse: ClickHouseConfig = field(default_factory=ClickHouseConfig)
    threshold: ThresholdConfig = field(default_factory=ThresholdConfig)
    traceback: TracebackConfig = field(default_factory=TracebackConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """
    从 YAML 文件加载配置，支持环境变量覆盖

    配置优先级：环境变量 > config.yaml > 代码默认值

    环境变量命名规则:
        DDOS_CH_*      → ClickHouse 相关
        DDOS_API_*     → API 服务相关

    Args:
        config_path: 配置文件路径，默认按以下顺序查找:
            1. 当前目录 config.yaml
            2. 当前目录 config.yml
            3. 项目根目录 config.yaml

    Returns:
        AppConfig 实例
    """
    if config_path is None:
        # 按优先级查找配置文件：当前目录 → 项目根目录
        candidates = [
            Path("config.yaml"),
            Path("config.yml"),
            Path(__file__).resolve().parents[3] / "config.yaml",  # src/ddos_trace → 上溯3级到项目根
        ]
        for p in candidates:
            if p.exists():
                config_path = str(p)
                break

    raw: dict = {}
    if config_path and Path(config_path).exists():
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}  # 空文件会返回 None，需兜底为空字典

    # 构建 ClickHouse 配置：环境变量优先于 YAML
    ch = raw.get("clickhouse", {})
    clickhouse_config = ClickHouseConfig(
        host=os.getenv("DDOS_CH_HOST", ch.get("host", "localhost")),
        port=int(os.getenv("DDOS_CH_PORT", ch.get("port", 9000))),
        username=os.getenv("DDOS_CH_USER", ch.get("username", "default")),
        password=os.getenv("DDOS_CH_PASSWORD", ch.get("password", "")),
        database=os.getenv("DDOS_CH_DATABASE", ch.get("database", "uniflow_controller_clickhouse_trunk")),
        table_name=os.getenv("DDOS_CH_TABLE", ch.get("table_name", "analytics_netflow_dist")),
        alert_table_name=os.getenv("DDOS_CH_ALERT_TABLE", ch.get("alert_table_name", "detect_attack_dist")),
        timeout=int(os.getenv("DDOS_CH_TIMEOUT", ch.get("timeout", 30))),
        chunk_size=int(os.getenv("DDOS_CH_CHUNK", ch.get("chunk_size", 100000))),
    )

    # 阈值配置（不支持环境变量覆盖，仅通过 YAML 或使用默认值）
    th = raw.get("threshold", {})
    threshold_config = ThresholdConfig(
        pps_threshold=int(th.get("pps_threshold", 500_000)),
        bps_threshold=int(th.get("bps_threshold", 20_000_000)),
    )

    # 溯源配置（部分参数可通过 YAML 覆盖）
    tb = raw.get("traceback", {})
    traceback_config = TracebackConfig(
        min_cluster_size=int(tb.get("min_cluster_size", 5)),
        use_dynamic_baseline=bool(tb.get("use_dynamic_baseline", True)),
        max_samples_for_clustering=int(tb.get("max_samples_for_clustering", 10_000)),
    )

    # API 服务配置：环境变量 DDOS_API_HOST / DDOS_API_PORT 优先
    ap = raw.get("api", {})
    api_config = ApiConfig(
        host=os.getenv("DDOS_API_HOST", ap.get("host", "0.0.0.0")),
        port=int(os.getenv("DDOS_API_PORT", ap.get("port", 8000))),
    )

    # 输出目录配置
    ou = raw.get("output", {})
    output_config = OutputConfig(
        dir=ou.get("dir", "./output"),
    )

    return AppConfig(
        clickhouse=clickhouse_config,
        threshold=threshold_config,
        traceback=traceback_config,
        api=api_config,
        output=output_config,
    )
