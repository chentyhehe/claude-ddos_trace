"""
MySQL 阈值配置加载器 - 从 MySQL 阈值配置数据库按需加载多攻击类型阈值

本模块从 MySQL 的 4 张阈值配置表中按需加载攻击阈值体系：
- system_base_attack_type: 47 种攻击类型定义（协议、端口、TCP 标志等匹配规则）
- system_base_monitor_object: 监测对象（绑定阈值模板）
- system_base_threshold_summary: 阈值模板（1:N 关联 threshold_item）
- system_base_threshold_item: 阈值明细（每种攻击方式的 IPv4/IPv6 PPS/BPS 阈值）

加载策略：
- 按 dst_mo_code 按需加载，不加载全表
- 进程内 dict 缓存，避免重复查询
- 自动检测 IP 版本，选择对应维度的阈值
- 任何 MySQL 不可用场景均回退到 ClickHouse 告警表阈值

核心类:
    ThresholdLoader: 阈值配置加载器
"""

import ipaddress
import logging
from typing import Dict, List, Optional

from ddos_trace.config.models import (
    AttackTypeInfo,
    AttackTypeThreshold,
    DimensionThreshold,
    MonitorThreshold,
    MySQLConfig,
)

logger = logging.getLogger(__name__)


def _convert_rate(value, unit: str) -> float:
    """
    将阈值速率转换为标准单位

    PPS 类: 统一转换为 packets/second
    BPS 类: 统一转换为 bytes/second

    支持的单位:
        pps, Kpps, Mpps, Gpps, Tpps
        bps, Kbps, Mbps, Gbps, Tbps
    """
    if value is None:
        return 0.0
    value = float(value)
    if value <= 0:
        return 0.0

    unit_lower = (unit or "").lower().strip()

    # PPS 类
    if "pps" in unit_lower:
        multipliers = {"tpps": 1e12, "gpps": 1e9, "mpps": 1e6, "kpps": 1e3}
        for suffix, factor in multipliers.items():
            if suffix in unit_lower:
                return value * factor
        return value

    # BPS 类
    if "bps" in unit_lower:
        multipliers = {"tbps": 1e12, "gbps": 1e9, "mbps": 1e6, "kbps": 1e3}
        for suffix, factor in multipliers.items():
            if suffix in unit_lower:
                return value * factor
        return value

    # 无法识别单位，假设已经是标准单位
    return value


class ThresholdLoader:
    """
    MySQL 阈值配置加载器

    按 dst_mo_code 按需从 MySQL 加载对应监测对象的阈值配置。
    包含进程内 dict 缓存，避免对同一监测对象的重复查询。

    降级策略:
    - MySQL 不可用 → load_threshold() 返回 None
    - 监测对象不存在 → 返回 None
    - 阈值模板存在但明细全未启用 → 返回 MonitorThreshold（attack_thresholds 为空）
    调用方收到 None 后回退到 ClickHouse 告警表的单一阈值。
    """

    def __init__(self, config: MySQLConfig, csv_path: str = ""):
        self.config = config
        self.csv_path = csv_path
        self._pool = None
        self._threshold_cache: Dict[str, MonitorThreshold] = {}

    def _get_pool(self):
        """懒加载 pymysql 连接池"""
        if self._pool is None:
            import pymysql
            self._pool = pymysql.connect(
                **self.config.connection_params,
                cursorclass=pymysql.cursors.DictCursor,
            )
            logger.info(
                "[MYSQL] 连接初始化成功 / host[%s] / port[%d] / db[%s]",
                self.config.host, self.config.port, self.config.database,
            )
        return self._pool

    def _get_connection(self):
        """获取一个新的数据库连接"""
        import pymysql
        try:
            conn = pymysql.connect(
                **self.config.connection_params,
                cursorclass=pymysql.cursors.DictCursor,
            )
            return conn
        except Exception as e:
            logger.error("[MYSQL] 连接失败 / error[%s]", e)
            raise

    # ------------------------------------------------------------------
    # 公开接口
    # ------------------------------------------------------------------

    def load_threshold(
        self, mo_code: str, ip_version: str = "ipv4"
    ) -> Optional[MonitorThreshold]:
        """
        按需加载指定监测对象的阈值配置

        加载流程（4 步查询）：
        1. 查 monitor_object → 获取 mo 基本信息 + threshold_id
        2. 查 threshold_summary → 确认模板存在
        3. 查 threshold_item → 获取所有攻击类型的阈值明细
        4. 查 attack_type → 获取攻击类型定义（用于名称映射）

        Args:
            mo_code: 监测对象编码
            ip_version: "ipv4" 或 "ipv6"

        Returns:
            MonitorThreshold 对象；未找到或 MySQL 不可用时返回 None
        """
        # 检查缓存
        cache_key = f"{mo_code}_{ip_version}"
        if cache_key in self._threshold_cache:
            logger.info("[MYSQL] 阈值缓存命中 / mo_code[%s]", mo_code)
            return self._threshold_cache[cache_key]

        logger.info(
            "[MYSQL] 开始加载阈值 / mo_code[%s] / ip_version[%s]",
            mo_code, ip_version,
        )

        try:
            conn = self._get_connection()
            try:
                # 步骤1: 查监测对象
                mo_info = self._query_monitor_object(conn, mo_code)
                if mo_info is None:
                    logger.warning("[MYSQL] 未找到监测对象 / mo_code[%s]", mo_code)
                    return None

                threshold_enable = mo_info.get("threshold_enable", "ON")
                if threshold_enable == "OFF":
                    logger.info("[MYSQL] 监测对象阈值已关闭 / mo_code[%s]", mo_code)

                # 步骤2: 查阈值模板
                threshold_id = mo_info.get("threshold_id")
                template_info = self._query_threshold_summary(
                    conn, threshold_id, mo_code
                )

                # 步骤3: 查阈值明细
                items = self._query_threshold_items(conn, template_info)

                # 步骤4: 查攻击类型定义
                attack_types = self._query_attack_types(conn)

                # 组装 MonitorThreshold
                monitor_threshold = self._build_monitor_threshold(
                    mo_info, items, attack_types
                )

                # 写入缓存
                self._threshold_cache[cache_key] = monitor_threshold

                logger.info(
                    "[MYSQL] 阈值加载完成 / mo_code[%s] / 攻击类型数[%d] / 已启用[%d]",
                    mo_code,
                    len(monitor_threshold.attack_thresholds),
                    sum(
                        1
                        for at in monitor_threshold.attack_thresholds.values()
                        if at.ipv4.pps_enable or at.ipv4.bps_enable
                    ),
                )
                return monitor_threshold

            finally:
                conn.close()
        except Exception as e:
            logger.warning(
                "[MYSQL] 阈值加载失败，尝试 CSV 降级 / mo_code[%s] / error[%s]",
                mo_code, e,
            )
            return self._fallback_from_csv(mo_code)

    def load_threshold_for_attack(
        self,
        mo_code: str,
        attack_types: List[str],
        ip_version: str = "ipv4",
    ) -> Dict[str, Dict[str, float]]:
        """
        按攻击类型列表加载对应的阈值

        适用于已知攻击类型的场景（如从告警表获取了 attack_types）。
        只返回与当前攻击相关的阈值子集。

        Args:
            mo_code: 监测对象编码
            attack_types: 攻击类型名称列表（如 ["syn", "udp", "dns_amp"]）
            ip_version: "ipv4" 或 "ipv6"

        Returns:
            {attack_type: {"pps_threshold": float, "bps_threshold": float}}
        """
        mt = self.load_threshold(mo_code, ip_version)
        if mt is None:
            return {}

        result = {}
        for at_name in attack_types:
            threshold = mt.get_threshold_by_attack_type(at_name, ip_version)
            if threshold is not None:
                result[at_name] = threshold

        # 如果没有任何匹配的攻击类型阈值，回退到聚合阈值
        if not result:
            agg = mt.get_aggregate_threshold(ip_version)
            if agg["pps_threshold"] > 0 or agg["bps_threshold"] > 0:
                result["_aggregate"] = agg

        return result

    def _fallback_from_csv(self, mo_code: str) -> Optional[MonitorThreshold]:
        """
        MySQL 不可用时从 CSV 加载攻击类型定义（降级方案）

        只加载攻击类型定义（匹配规则），不加载阈值明细。
        阈值降级到配置文件默认值。
        """
        if not self.csv_path:
            logger.info("[MYSQL] 无 CSV 路径配置，降级跳过")
            return None

        # 检查缓存（CSV 降级结果也可缓存）
        cache_key = f"{mo_code}_csv"
        if cache_key in self._threshold_cache:
            return self._threshold_cache[cache_key]

        attack_type_info = load_attack_types_from_csv(self.csv_path)
        if not attack_type_info:
            return None

        mt = MonitorThreshold(
            mo_code=mo_code,
            mo_name="",
            threshold_enable=True,
        )
        mt.attack_type_info = attack_type_info
        # attack_thresholds 为空 — 阈值降级到配置文件默认值

        self._threshold_cache[cache_key] = mt
        logger.info(
            "[MYSQL] CSV 降级加载完成 / mo_code[%s] / 攻击类型数[%d]",
            mo_code, len(attack_type_info),
        )
        return mt

    @staticmethod
    def detect_ip_version(target_ips: List[str]) -> str:
        """
        根据目标 IP 地址自动判断 IP 版本

        如果列表中包含至少一个 IPv6 地址且无 IPv4 地址，返回 "ipv6"；
        否则默认返回 "ipv4"（包含混合地址的场景也使用 ipv4，
        因为当前 NetFlow 数据以 IPv4 为主）。

        Args:
            target_ips: 目标 IP 地址列表

        Returns:
            "ipv4" 或 "ipv6"
        """
        if not target_ips:
            return "ipv4"

        has_ipv6 = False
        has_ipv4 = False
        for ip_str in target_ips:
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.version == 6:
                    has_ipv6 = True
                else:
                    has_ipv4 = True
            except (ValueError, TypeError):
                continue

        # 仅当全部为 IPv6 时才使用 ipv6 维度
        if has_ipv6 and not has_ipv4:
            return "ipv6"
        return "ipv4"

    # ------------------------------------------------------------------
    # 内部查询方法
    # ------------------------------------------------------------------

    def _query_monitor_object(self, conn, mo_code: str) -> Optional[dict]:
        """
        查 system_base_monitor_object 表

        查询策略:
        1. 先按 code 查询（mo_code 可能是对象编码）
        2. code 未找到时按 id 查询（custcode 关联的是 monitor_object.id）
        """
        with conn.cursor() as cursor:
            # 先按 code 查
            cursor.execute(
                "SELECT id, code, name, threshold_enable, threshold_id, "
                "bandwidth, bandwidth_unit "
                "FROM system_base_monitor_object WHERE code = %s",
                (mo_code,),
            )
            result = cursor.fetchone()
            if result:
                return result

            # 再按 id 查（custcode → monitor_object.id）
            cursor.execute(
                "SELECT id, code, name, threshold_enable, threshold_id, "
                "bandwidth, bandwidth_unit "
                "FROM system_base_monitor_object WHERE id = %s",
                (mo_code,),
            )
            return cursor.fetchone()

    def _query_threshold_summary(
        self, conn, threshold_id, mo_code: str
    ) -> Optional[dict]:
        """
        查 system_base_threshold_summary 表

        优先级：
        1. 通过 monitor_object.threshold_id 关联 summary.id（模板类型）
        2. 通过 mo_code 直接关联（DEFINED 类型）
        """
        with conn.cursor() as cursor:
            # 先按 threshold_id 查模板
            if threshold_id:
                cursor.execute(
                    "SELECT id, name, type, ipv4_enable, ipv6_enable "
                    "FROM system_base_threshold_summary WHERE id = %s",
                    (threshold_id,),
                )
                result = cursor.fetchone()
                if result:
                    return result

            # 再按 mo_code 查自定义阈值
            cursor.execute(
                "SELECT id, name, type, ipv4_enable, ipv6_enable "
                "FROM system_base_threshold_summary "
                "WHERE name = %s AND type = 'DEFINED'",
                (mo_code,),
            )
            return cursor.fetchone()

    def _query_threshold_items(
        self, conn, summary_info: Optional[dict]
    ) -> List[dict]:
        """查 system_base_threshold_item 表"""
        if summary_info is None:
            return []

        summary_id = summary_info["id"]
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT protocol_type, both_over_bps_pps, "
                "ipv4_pps_enable, ipv4_pps_trigger_rate, ipv4_pps_trigger_unit, "
                "ipv4_pps_severity_rate, ipv4_pps_severity_unit, "
                "ipv4_bps_enable, ipv4_bps_trigger_rate, ipv4_bps_trigger_unit, "
                "ipv4_bps_severity_rate, ipv4_bps_severity_unit, "
                "ipv6_pps_enable, ipv6_pps_trigger_rate, ipv6_pps_trigger_unit, "
                "ipv6_pps_severity_rate, ipv6_pps_severity_unit, "
                "ipv6_bps_enable, ipv6_bps_trigger_rate, ipv6_bps_trigger_unit, "
                "ipv6_bps_severity_rate, ipv6_bps_severity_unit "
                "FROM system_base_threshold_item WHERE threshold_id = %s",
                (summary_id,),
            )
            return cursor.fetchall()

    def _query_attack_types(self, conn) -> Dict[str, dict]:
        """
        查 system_base_attack_type 表，返回攻击类型定义

        返回双重映射:
        - key 为 primary_name
        - 同时包含 second_name 到 primary_name 的映射关系

        关联关系:
        - threshold_item.protocol_type 对应 attack_type.second_name
        - detect_attack_dist.attack_types 中的值也是 second_name
        """
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT primary_name, second_name, sub_classify_type, "
                "protocol_name, protocol_num, port_type, port_list, "
                "tcp_flags, ip_version_name, "
                "ip_addr_type, ip_addr_src_equal_dst, ip_addr_list "
                "FROM system_base_attack_type"
            )
            rows = cursor.fetchall()
            return {row["primary_name"]: row for row in rows}

    # ------------------------------------------------------------------
    # 组装方法
    # ------------------------------------------------------------------

    def _build_monitor_threshold(
        self,
        mo_info: dict,
        items: List[dict],
        attack_types: Dict[str, dict],
    ) -> MonitorThreshold:
        """
        将原始查询结果组装为 MonitorThreshold 对象

        关键处理：
        - 单位转换：threshold_item 中的速率值可能带有独立单位
        - 子分类映射：从 attack_type 表获取 sub_classify_type 补充到 AttackTypeThreshold
        - protocol_type 关联：threshold_item.protocol_type 对应 attack_type.second_name

        关联链:
        threshold_item.protocol_type (= second_name)
            → attack_type 表中 second_name 匹配的行 → primary_name, sub_classify_type 等
        """
        mt = MonitorThreshold(
            mo_code=mo_info.get("code", "") or str(mo_info.get("id", "")),
            mo_name=mo_info.get("name", ""),
            threshold_enable=(mo_info.get("threshold_enable", "ON") == "ON"),
            bandwidth=float(mo_info.get("bandwidth", 0) or 0),
            bandwidth_unit=mo_info.get("bandwidth_unit", ""),
        )

        # 构建 second_name → primary_name 的反向映射
        # threshold_item.protocol_type 和 detect_attack_dist.attack_types 都使用 second_name
        second_to_primary = {}
        for name, raw_info in attack_types.items():
            sn = raw_info.get("second_name", "")
            if sn:
                second_to_primary[sn] = name

        # 构建攻击类型信息映射（以 primary_name 为 key）
        for name, raw_info in attack_types.items():
            mt.attack_type_info[name] = AttackTypeInfo(
                primary_name=raw_info.get("primary_name", ""),
                second_name=raw_info.get("second_name", ""),
                sub_classify_type=raw_info.get("sub_classify_type", ""),
                protocol_name=raw_info.get("protocol_name", ""),
                protocol_num=int(raw_info.get("protocol_num", 0) or 0),
                port_type=raw_info.get("port_type", ""),
                port_list=raw_info.get("port_list", ""),
                tcp_flags=raw_info.get("tcp_flags", ""),
                ip_version_name=raw_info.get("ip_version_name", ""),
                ip_addr_type=raw_info.get("ip_addr_type", ""),
                ip_addr_src_equal_dst=raw_info.get("ip_addr_src_equal_dst", ""),
                ip_addr_list=raw_info.get("ip_addr_list", ""),
            )

        # 同时以 second_name 建立映射（告警表中的 attack_types 使用 second_name）
        for name, raw_info in attack_types.items():
            second_name = raw_info.get("second_name", "")
            if second_name and second_name not in mt.attack_type_info:
                mt.attack_type_info[second_name] = AttackTypeInfo(
                    primary_name=raw_info.get("primary_name", ""),
                    second_name=second_name,
                    sub_classify_type=raw_info.get("sub_classify_type", ""),
                    protocol_name=raw_info.get("protocol_name", ""),
                    protocol_num=int(raw_info.get("protocol_num", 0) or 0),
                    port_type=raw_info.get("port_type", ""),
                    port_list=raw_info.get("port_list", ""),
                    tcp_flags=raw_info.get("tcp_flags", ""),
                    ip_version_name=raw_info.get("ip_version_name", ""),
                    ip_addr_type=raw_info.get("ip_addr_type", ""),
                    ip_addr_src_equal_dst=raw_info.get("ip_addr_src_equal_dst", ""),
                    ip_addr_list=raw_info.get("ip_addr_list", ""),
                )

        # 构建攻击类型阈值映射
        # protocol_type 对应 attack_type.second_name，需通过反向映射找到 primary_name
        for item in items:
            protocol_type = item.get("protocol_type", "")
            if not protocol_type:
                continue

            # protocol_type 是 second_name，反查 primary_name
            primary_name = second_to_primary.get(protocol_type, protocol_type)

            # 查找子分类（通过 second_name 在原始数据中查找）
            sub_classify = ""
            at_row = attack_types.get(primary_name)
            if at_row:
                sub_classify = at_row.get("sub_classify_type", "")

            at = AttackTypeThreshold(
                protocol_type=protocol_type,
                sub_classify_type=sub_classify,
                both_over_bps_pps=(
                    item.get("both_over_bps_pps", "OFF") == "ON"
                ),
                ipv4=DimensionThreshold(
                    pps_enable=(
                        item.get("ipv4_pps_enable", "OFF") == "ON"
                    ),
                    pps_trigger_rate=_convert_rate(
                        item.get("ipv4_pps_trigger_rate", 0),
                        item.get("ipv4_pps_trigger_unit", "pps"),
                    ),
                    pps_severity_rate=_convert_rate(
                        item.get("ipv4_pps_severity_rate", 0),
                        item.get("ipv4_pps_severity_unit", "pps"),
                    ),
                    bps_enable=(
                        item.get("ipv4_bps_enable", "OFF") == "ON"
                    ),
                    bps_trigger_rate=_convert_rate(
                        item.get("ipv4_bps_trigger_rate", 0),
                        item.get("ipv4_bps_trigger_unit", "bps"),
                    ),
                    bps_severity_rate=_convert_rate(
                        item.get("ipv4_bps_severity_rate", 0),
                        item.get("ipv4_bps_severity_unit", "bps"),
                    ),
                ),
                ipv6=DimensionThreshold(
                    pps_enable=(
                        item.get("ipv6_pps_enable", "OFF") == "ON"
                    ),
                    pps_trigger_rate=_convert_rate(
                        item.get("ipv6_pps_trigger_rate", 0),
                        item.get("ipv6_pps_trigger_unit", "pps"),
                    ),
                    pps_severity_rate=_convert_rate(
                        item.get("ipv6_pps_severity_rate", 0),
                        item.get("ipv6_pps_severity_unit", "pps"),
                    ),
                    bps_enable=(
                        item.get("ipv6_bps_enable", "OFF") == "ON"
                    ),
                    bps_trigger_rate=_convert_rate(
                        item.get("ipv6_bps_trigger_rate", 0),
                        item.get("ipv6_bps_trigger_unit", "bps"),
                    ),
                    bps_severity_rate=_convert_rate(
                        item.get("ipv6_bps_severity_rate", 0),
                        item.get("ipv6_bps_severity_unit", "bps"),
                    ),
                ),
            )
            # 以 primary_name 为 key 存储（输出使用 primary_name）
            mt.attack_thresholds[primary_name] = at
            # 同时以 second_name（protocol_type）为备选 key
            if protocol_type != primary_name:
                mt.attack_thresholds[protocol_type] = at

        return mt


# ------------------------------------------------------------------
# Flow 过滤：根据攻击类型匹配规则过滤 NetFlow 数据
# ------------------------------------------------------------------

# TCP flags 名称到位掩码的映射
_TCP_FLAG_BITS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}


def _parse_tcp_flags(flags_str: str) -> int:
    """
    将 TCP 标志字符串（逗号分隔）转换为位掩码

    例如 "SYN,ACK" → 0x12 (SYN=0x02 | ACK=0x10)
    """
    bitmask = 0
    for flag in flags_str.split(","):
        flag = flag.strip().upper()
        if flag in _TCP_FLAG_BITS:
            bitmask |= _TCP_FLAG_BITS[flag]
    return bitmask


def filter_flows_by_attack_type(
    raw_df: "pd.DataFrame",
    attack_type_info: AttackTypeInfo,
) -> "pd.DataFrame":
    """
    根据攻击类型的匹配规则过滤 NetFlow DataFrame

    对 DataFrame 应用攻击类型定义中的所有匹配条件（AND 关系）：
    1. protocol_num ≠ 0 → protocol == protocol_num
    2. port_type=SRC/DST + port_list → 对应端口匹配
    3. tcp_flags 非空 → TCP 标志位运算匹配
    4. ip_addr_src_equal_dst=EQUAL → 源 IP == 目的 IP

    所有条件为 AND 关系，空值条件视为"不限制"（跳过）。

    Args:
        raw_df: 预处理后的 NetFlow DataFrame
        attack_type_info: 攻击类型定义信息（含匹配规则字段）

    Returns:
        过滤后的 DataFrame（原始 DataFrame 的子集）
    """
    import pandas as pd

    if raw_df.empty:
        return raw_df

    mask = pd.Series(True, index=raw_df.index)

    # 1. 协议号匹配
    proto = attack_type_info.protocol_num
    if proto and proto > 0:
        if "protocol" in raw_df.columns:
            mask &= raw_df["protocol"] == proto

    # 2. 端口匹配
    port_type = attack_type_info.port_type
    port_list_str = attack_type_info.port_list
    if port_type and port_type in ("SRC", "DST") and port_list_str:
        try:
            ports = [int(p.strip()) for p in port_list_str.split(",") if p.strip()]
            if ports:
                port_col = "src_port" if port_type == "SRC" else "dst_port"
                if port_col in raw_df.columns:
                    mask &= raw_df[port_col].isin(ports)
        except (ValueError, TypeError):
            pass

    # 3. TCP flags 位运算匹配
    tcp_flags_str = attack_type_info.tcp_flags
    if tcp_flags_str:
        required_bits = _parse_tcp_flags(tcp_flags_str)
        if required_bits and "tcp_flags" in raw_df.columns:
            mask &= (raw_df["tcp_flags"].astype(int) & required_bits) == required_bits

    # 4. 源 IP == 目的 IP（Land 攻击）
    if attack_type_info.ip_addr_src_equal_dst == "EQUAL":
        if "src_ip_addr" in raw_df.columns and "dst_ip_addr" in raw_df.columns:
            mask &= raw_df["src_ip_addr"] == raw_df["dst_ip_addr"]

    return raw_df.loc[mask]


def get_attack_type_matching_rules(attack_type_info: AttackTypeInfo) -> str:
    """
    生成攻击类型匹配规则的可读摘要

    Returns:
        规则摘要字符串，如 "protocol=TCP, tcp_flags=SYN"
    """
    parts = []

    if attack_type_info.protocol_num and attack_type_info.protocol_num > 0:
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", 2: "IGMP", 0: "HOPOPT"}
        proto_name = proto_map.get(
            attack_type_info.protocol_num, str(attack_type_info.protocol_num)
        )
        parts.append(f"protocol={proto_name}")

    if attack_type_info.port_type and attack_type_info.port_type in ("SRC", "DST"):
        port_dir = "src" if attack_type_info.port_type == "SRC" else "dst"
        if attack_type_info.port_list:
            parts.append(f"{port_dir}_port={attack_type_info.port_list}")

    if attack_type_info.tcp_flags:
        parts.append(f"tcp_flags={attack_type_info.tcp_flags}")

    if attack_type_info.ip_addr_src_equal_dst == "EQUAL":
        parts.append("src_ip==dst_ip")

    return ", ".join(parts) if parts else "全部流量"


def load_attack_types_from_csv(csv_path: str) -> Dict[str, "AttackTypeInfo"]:
    """
    从 CSV 文件加载攻击类型定义（MySQL 不可用时的降级方案）

    CSV 文件格式与 system_base_attack_type 表一致，包含:
    primary_name, second_name, sub_classify_type, protocol_num, port_type,
    port_list, tcp_flags, ip_addr_type, ip_addr_src_equal_dst, ip_addr_list 等

    Args:
        csv_path: CSV 文件路径

    Returns:
        {primary_name/second_name: AttackTypeInfo} 映射
    """
    import pandas as pd

    if not csv_path:
        return {}

    try:
        df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    except FileNotFoundError:
        logger.error("[CSV] 攻击类型定义文件不存在 / path[%s]", csv_path)
        return {}
    except Exception as e:
        logger.error("[CSV] 攻击类型定义加载失败 / error[%s]", e)
        return {}

    info_map: Dict[str, AttackTypeInfo] = {}

    for _, row in df.iterrows():
        ati = AttackTypeInfo(
            primary_name=str(row.get("primary_name", "")).strip(),
            second_name=str(row.get("second_name", "")).strip(),
            sub_classify_type=str(row.get("sub_classify_type", "")).strip(),
            protocol_name=str(row.get("protocol_name", "")).strip(),
            protocol_num=int(row.get("protocol_num", 0) or 0),
            port_type=str(row.get("port_type", "")).strip(),
            port_list=str(row.get("port_list", "")).strip(),
            tcp_flags=str(row.get("tcp_flags", "")).strip(),
            ip_version_name=str(row.get("ip_version_name", "")).strip(),
            ip_addr_type=str(row.get("ip_addr_type", "")).strip(),
            ip_addr_src_equal_dst=str(row.get("ip_addr_src_equal_dst", "")).strip(),
            ip_addr_list=str(row.get("ip_addr_list", "")).strip(),
        )

        # 以 primary_name 为 key
        if ati.primary_name:
            info_map[ati.primary_name] = ati
        # 同时以 second_name 为 key（告警表可能使用别名）
        if ati.second_name and ati.second_name not in info_map:
            info_map[ati.second_name] = ati

    logger.info("[CSV] 攻击类型定义加载完成 / 数量[%d] / path[%s]", len(info_map), csv_path)
    return info_map
