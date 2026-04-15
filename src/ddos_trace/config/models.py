"""
配置模块 - 提供所有配置数据类及配置文件加载

本模块定义了 DDoS 攻击溯源分析器的全部配置项，包括：
- ClickHouseConfig: ClickHouse 数据库连接参数
- MySQLConfig: MySQL 阈值配置数据库连接参数
- ThresholdConfig: 流量异常检测阈值（PPS/BPS 硬阈值，作为兜底默认值）
- TracebackConfig: 溯源分析参数（聚类特征、置信度分级阈值、算法参数等）
- ApiConfig: FastAPI 服务监听配置
- OutputConfig: 报告输出目录配置
- AppConfig: 上述所有配置的聚合根

阈值数据模型（从 MySQL 加载的多攻击类型阈值）：
- DimensionThreshold: 单维度（IPv4/IPv6）PPS/BPS 阈值
- AttackTypeThreshold: 单种攻击类型的完整阈值定义
- AttackTypeInfo: 攻击类型定义信息（协议、端口、TCP 标志等）
- MonitorThreshold: 一个监测对象的完整阈值体系

配置加载优先级: 环境变量 > config.yaml > 代码默认值
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

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
class MySQLConfig:
    """
    MySQL 阈值配置数据库连接

    用于连接业务系统的 MySQL 数据库，加载攻击类型定义、监测对象、
    阈值模板和阈值明细等配置数据。

    数据表:
    - system_base_attack_type: 攻击类型定义（47种）
    - system_base_monitor_object: 监测对象（绑定阈值模板）
    - system_base_threshold_summary: 阈值模板（1:N 关联 threshold_item）
    - system_base_threshold_item: 阈值明细（每种攻击方式的 PPS/BPS 阈值）
    """

    host: str = "localhost"
    port: int = 3306
    username: str = "root"
    password: str = ""
    database: str = "uniflow_controller_mysql"
    charset: str = "utf8mb4"
    pool_size: int = 5  # 连接池大小

    @property
    def connection_params(self) -> dict:
        """生成 pymysql 所需的连接参数字典"""
        return {
            "host": self.host,
            "port": self.port,
            "user": self.username,
            "password": self.password,
            "database": self.database,
            "charset": self.charset,
        }


@dataclass
class DimensionThreshold:
    """
    单维度（IPv4 或 IPv6）的 PPS/BPS 阈值

    对应 threshold_item 表中一个 IP 版本维度上的阈值配置。
    每个维度有 PPS 和 BPS 两类阈值，每类又分为触发率(trigger)和严重率(severity)。
    所有速率值已标准化为基本单位：PPS = packets/second, BPS = bytes/second。
    """

    pps_enable: bool = False
    pps_trigger_rate: float = 0.0    # 触发告警阈值
    pps_severity_rate: float = 0.0   # 严重告警阈值
    bps_enable: bool = False
    bps_trigger_rate: float = 0.0    # 触发告警阈值
    bps_severity_rate: float = 0.0   # 严重告警阈值


@dataclass
class AttackTypeThreshold:
    """
    单种攻击类型的完整阈值定义

    对应 threshold_item 表中的一行记录。
    protocol_type 标识攻击方式（如 SYN Flood, UDP Flood, DNS Amplification 等）。
    每种攻击类型在 IPv4 和 IPv6 两个维度上各有 PPS/BPS 阈值。
    """

    protocol_type: str = ""          # 攻击方式标识
    sub_classify_type: str = ""     # 子分类: Flood / Amplification / Traffic / Other
    both_over_bps_pps: bool = False  # 是否需要同时超过 BPS 和 PPS 才触发
    ipv4: DimensionThreshold = field(default_factory=DimensionThreshold)
    ipv6: DimensionThreshold = field(default_factory=DimensionThreshold)

    def get_effective_threshold(self, ip_version: str = "ipv4") -> Dict[str, float]:
        """
        获取有效阈值

        优先使用触发率（更低的阈值意味着更灵敏的检测）。
        如果触发率未设置，则使用严重率。

        Args:
            ip_version: "ipv4" 或 "ipv6"

        Returns:
            {"pps_threshold": float, "bps_threshold": float}
        """
        dim = self.ipv4 if ip_version == "ipv4" else self.ipv6

        def _pick(trigger: float, severity: float) -> float:
            """取触发率和严重率中较低的有效值"""
            if trigger > 0 and severity > 0:
                return min(trigger, severity)
            return max(trigger, severity)

        return {
            "pps_threshold": _pick(dim.pps_trigger_rate, dim.pps_severity_rate),
            "bps_threshold": _pick(dim.bps_trigger_rate, dim.bps_severity_rate),
        }


@dataclass
class AttackTypeInfo:
    """
    攻击类型定义信息

    对应 system_base_attack_type 表中的一行记录。
    用于将告警中的 attack_types 名称映射到 threshold_item 中的 protocol_type，
    以及提供协议/端口/TCP 标志等匹配规则。
    """

    primary_name: str = ""          # 主名称（如 syn, udp, dns_amp 等）
    second_name: str = ""           # 次名称/别名
    sub_classify_type: str = ""     # 子分类: Flood / Amplification / Traffic / Other
    protocol_name: str = ""         # 协议名称
    protocol_num: int = 0           # 协议号（6=TCP, 17=UDP, 1=ICMP）
    port_type: str = ""             # 端口类型: SRC / DST / ALL
    port_list: str = ""             # 端口列表（逗号分隔）
    tcp_flags: str = ""             # TCP 标志（逗号分隔）
    ip_version_name: str = ""       # IP 版本: All / IPv4 / IPv6
    ip_addr_type: str = ""          # IP地址类型: SRC / DST / ALL
    ip_addr_src_equal_dst: str = "" # 源和目的地址是否相同: EQUAL / IGNORE
    ip_addr_list: str = ""          # IP地址列表（CIDR或单个IP，逗号分隔）


@dataclass
class MonitorThreshold:
    """
    一个监测对象的完整阈值体系

    由 ThresholdLoader 根据 dst_mo_code 从 MySQL 加载构建。
    包含该监测对象绑定的所有攻击类型阈值，以及攻击类型定义信息。
    """

    mo_code: str = ""
    mo_name: str = ""
    threshold_enable: bool = True   # 监测对象的阈值开关
    bandwidth: float = 0.0          # 监测对象带宽
    bandwidth_unit: str = ""        # 带宽单位

    # 核心数据: 攻击类型名称 -> 该类型的阈值
    attack_thresholds: Dict[str, AttackTypeThreshold] = field(default_factory=dict)

    # 辅助映射: 攻击类型名称(primary_name/second_name) -> 攻击类型信息
    attack_type_info: Dict[str, AttackTypeInfo] = field(default_factory=dict)

    def get_threshold_by_attack_type(
        self, attack_type: str, ip_version: str = "ipv4"
    ) -> Optional[Dict[str, float]]:
        """
        根据攻击类型名称获取对应的 PPS/BPS 阈值

        支持模糊匹配: 先精确匹配 protocol_type，再匹配 primary_name/second_name。

        Args:
            attack_type: 攻击类型名称（如 syn, udp, dns_amp）
            ip_version: "ipv4" 或 "ipv6"

        Returns:
            {"pps_threshold": float, "bps_threshold": float} 或 None
        """
        # 1. 精确匹配 protocol_type
        if attack_type in self.attack_thresholds:
            return self.attack_thresholds[attack_type].get_effective_threshold(ip_version)

        # 2. 通过 attack_type_info 反查 protocol_type
        for name, info in self.attack_type_info.items():
            if name == attack_type or info.second_name == attack_type:
                if name in self.attack_thresholds:
                    return self.attack_thresholds[name].get_effective_threshold(ip_version)

        return None

    def get_all_enabled_thresholds(
        self, ip_version: str = "ipv4"
    ) -> Dict[str, Dict[str, float]]:
        """
        获取所有已启用的攻击类型阈值

        Returns:
            {attack_type_name: {"pps_threshold": float, "bps_threshold": float}}
        """
        result = {}
        for name, at in self.attack_thresholds.items():
            dim = at.ipv4 if ip_version == "ipv4" else at.ipv6
            if dim.pps_enable or dim.bps_enable:
                result[name] = at.get_effective_threshold(ip_version)
        return result

    def get_aggregate_threshold(
        self, ip_version: str = "ipv4"
    ) -> Dict[str, float]:
        """
        获取聚合阈值（所有攻击类型中 PPS/BPS 的最大触发阈值）

        用于向后兼容旧流程中需要单一阈值的场景。
        """
        all_thresholds = self.get_all_enabled_thresholds(ip_version)
        if not all_thresholds:
            return {"pps_threshold": 0.0, "bps_threshold": 0.0}

        max_pps = max(t["pps_threshold"] for t in all_thresholds.values())
        max_bps = max(t["bps_threshold"] for t in all_thresholds.values())
        return {"pps_threshold": max_pps, "bps_threshold": max_bps}


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
    mysql: MySQLConfig = field(default_factory=MySQLConfig)
    threshold: ThresholdConfig = field(default_factory=ThresholdConfig)
    traceback: TracebackConfig = field(default_factory=TracebackConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    attack_type_csv_path: str = ""  # MySQL 不可用时从此 CSV 加载攻击类型定义


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """
    从 YAML 文件加载配置，支持环境变量覆盖

    配置优先级：环境变量 > config.yaml > 代码默认值

    环境变量命名规则:
        DDOS_CH_*      → ClickHouse 相关
        DDOS_MYSQL_*   → MySQL 阈值配置数据库相关
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

    # MySQL 阈值配置数据库：环境变量优先于 YAML
    my = raw.get("mysql", {})
    mysql_config = MySQLConfig(
        host=os.getenv("DDOS_MYSQL_HOST", my.get("host", "localhost")),
        port=int(os.getenv("DDOS_MYSQL_PORT", my.get("port", 3306))),
        username=os.getenv("DDOS_MYSQL_USER", my.get("username", "root")),
        password=os.getenv("DDOS_MYSQL_PASSWORD", my.get("password", "")),
        database=os.getenv("DDOS_MYSQL_DATABASE", my.get("database", "uniflow_controller_mysql")),
        charset=my.get("charset", "utf8mb4"),
        pool_size=int(my.get("pool_size", 5)),
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
        mysql=mysql_config,
        threshold=threshold_config,
        traceback=traceback_config,
        api=api_config,
        output=output_config,
        attack_type_csv_path=raw.get("attack_type_csv_path", ""),
    )
