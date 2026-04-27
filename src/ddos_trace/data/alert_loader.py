"""
告警数据加载器 - 从 detect_attack_dist 表读取告警记录并构建攻击上下文

本模块从 ClickHouse 告警表中加载已有的攻击检测记录，自动提取:
- 攻击目标（IP 或监测对象编码）
- 时间窗口（start_time ~ end_time）
- 检测阈值（PPS/BPS，支持多种单位的自动转换）
- 攻击类型信息

这些信息被封装为 AttackContext 对象，作为后续溯源分析的输入参数，
替代了原来需要用户手动传入的目标IP、时间范围和阈值。

核心类:
    - AttackContext: 攻击上下文数据类，封装告警表中的关键信息
    - AlertLoader: 从告警表查询并构建 AttackContext
"""

import logging
from datetime import datetime
from typing import List, Optional

import pandas as pd

from ddos_trace._compat import dataclass, field
from ddos_trace.config.models import ClickHouseConfig

logger = logging.getLogger(__name__)


@dataclass
class AttackContext:
    """
    攻击上下文 — 由告警记录自动填充

    封装了从告警表获取的所有关键信息，
    替代原来需要用户手动传入的 target_ips / 时间范围 / 阈值。

    一个 attack_id 可能对应多条告警记录（如多目标聚合攻击），
    _build_context() 会将它们合并为统一的上下文。
    """

    # 来源标识
    attack_id: Optional[str] = None           # 告警系统生成的攻击唯一标识
    alert_ids: List[int] = field(default_factory=list)  # 对应的告警记录ID列表

    # 攻击目标
    attack_target: str = ""                   # 主目标标识（IP 或 MO 编码）
    attack_target_type: str = ""              # 目标类型: ipv4 / mo / customer 等
    target_ips: List[str] = field(default_factory=list)      # 解析出的目标IP列表
    target_mo_codes: List[str] = field(default_factory=list)  # 解析出的监测对象编码列表

    # 时间窗口
    start_time: Optional[datetime] = None     # 攻击开始时间（取所有告警的最早时间）
    end_time: Optional[datetime] = None       # 攻击结束时间（取所有告警的最晚时间）

    # 阈值（从告警记录获取，支持 pps/kpps/mpps/bps/Kbps/Mbps/Gbps 等多种单位）
    threshold_pps: Optional[float] = None     # PPS 阈值（标准化为 packets/second）
    threshold_bps: Optional[float] = None     # BPS 阈值（标准化为 bytes/second）
    threshold_raw: Optional[int] = None       # 原始阈值数值（未转换单位）
    threshold_unit: Optional[str] = None      # 原始阈值单位

    # 攻击类型信息
    attack_types: List[str] = field(default_factory=list)  # 具体攻击类型列表
    attack_maintype: Optional[str] = None     # 攻击主分类
    direction: str = "in"                     # 攻击方向（in=入站）
    level: str = ""                           # 告警级别

    # 告警中的峰值（用于参考和阈值估算）
    max_pps: Optional[float] = None           # 告警期间最大PPS
    max_bps: Optional[float] = None           # 告警期间最大BPS
    mean_pps: Optional[float] = None          # 告警期间平均PPS
    mean_bps: Optional[float] = None          # 告警期间平均BPS

    # MySQL 多类型阈值（由 analyzer 注入，不在 _build_context 中设置）
    # 存储 ThresholdLoader 从 MySQL 加载的监测对象阈值体系
    monitor_threshold: Optional[object] = None  # MonitorThreshold 类型，避免循环导入用 object

    def get_pps_threshold(self, fallback: float = 500_000) -> float:
        """
        获取 PPS 阈值，若无则使用兜底值

        Args:
            fallback: 兜底阈值，默认 500,000 pps（与 ThresholdConfig 默认值一致）
        """
        return self.threshold_pps if self.threshold_pps is not None else fallback

    def get_bps_threshold(self, fallback: float = 20_000_000) -> float:
        """
        获取 BPS 阈值，若无则使用兜底值

        Args:
            fallback: 兜底阈值，默认 20,000,000 bps（与 ThresholdConfig 默认值一致）
        """
        return self.threshold_bps if self.threshold_bps is not None else fallback


class AlertLoader:
    """
    从 detect_attack_dist 表加载告警记录

    提供两种查询方式:
    - load_by_attack_id: 通过告警系统生成的 attack_id 精确查询
    - load_by_target: 通过攻击目标（IP/监测对象编码）+ 时间范围模糊查询
    """

    ALERT_COLUMNS = [
        "id", "attack_id", "attack_target", "attack_target_type",  # 标识
        "level", "status", "attack_types", "attack_maintype",       # 攻击分类
        "threshold_unit", "threshold", "direction",                  # 阈值与方向
        "start_time", "end_time",                                    # 时间窗口
        "max_pps", "max_bps", "mean_packet_ps", "mean_bytes_ps",    # 峰值/均值统计
        "duration", "daytime",                                       # 持续时间、时段
        "custcode", "isp_code",                                      # 客户/运营商编码
    ]
    def __init__(self, config: ClickHouseConfig):
        self.config = config
        self._client = None

    def _get_client(self):
        if self._client is None:
            from clickhouse_driver import Client

            self._client = Client(**self.config.connection_params)
        return self._client

    def load_by_attack_id(self, attack_id: str) -> Optional[AttackContext]:
        """
        通过 attack_id 加载告警记录，构建攻击上下文

        一个 attack_id 可能对应多条告警记录（多条聚合），
        将它们合并为一个 AttackContext。

        Args:
            attack_id: 告警系统生成的攻击唯一标识（如 "ATK-20260401-001"）

        Returns:
            合并后的 AttackContext；若无匹配返回 None
        """
        table = f"{self.config.database}.{self.config.alert_table_name}"
        cols = ", ".join(self.ALERT_COLUMNS)
        query = f"SELECT {cols} FROM {table} WHERE attack_id = %(attack_id)s"
        params = {"attack_id": attack_id}

        logger.info("[ALERT_LOADER] 查询告警 / attack_id[%s]", attack_id)
        client = self._get_client()

        try:
            df = client.query_dataframe(query, params)
        except Exception as e:
            logger.error("[ALERT_LOADER] 查询失败 / %s", e)
            raise

        if df.empty:
            logger.warning("[ALERT_LOADER] 未找到告警记录 / attack_id[%s]", attack_id)
            return None

        return self._build_context(df)

    def load_by_target(
        self,
        attack_target: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Optional[AttackContext]:
        """
        通过攻击目标 + 时间范围加载告警记录

        按攻击目标和可选的时间范围查询，返回最近 10 条告警记录
        合并的 AttackContext。用于"目标驱动"分析模式。

        Args:
            attack_target: 攻击目标（IP 地址或监测对象编码）
            start_time: 可选的开始时间过滤
            end_time: 可选的结束时间过滤

        Returns:
            合并后的 AttackContext；若无匹配返回 None
        """
        table = f"{self.config.database}.{self.config.alert_table_name}"
        cols = ", ".join(self.ALERT_COLUMNS)

        conditions = ["attack_target = %(attack_target)s"]
        params = {"attack_target": attack_target}

        if start_time:
            conditions.append("start_time >= %(start_time)s")
            params["start_time"] = start_time
        if end_time:
            conditions.append("end_time <= %(end_time)s")
            params["end_time"] = end_time

        where = " AND ".join(conditions)
        query = f"SELECT {cols} FROM {table} WHERE {where} ORDER BY start_time DESC LIMIT 10"

        logger.info(
            "[ALERT_LOADER] 查询告警 / target[%s] / time[%s ~ %s]",
            attack_target, start_time, end_time,
        )
        client = self._get_client()

        try:
            df = client.query_dataframe(query, params)
        except Exception as e:
            logger.error("[ALERT_LOADER] 查询失败 / %s", e)
            raise

        if df.empty:
            logger.warning("[ALERT_LOADER] 未找到告警记录 / target[%s]", attack_target)
            return None

        return self._build_context(df)

    def load_by_target_multi(
        self,
        attack_target: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[AttackContext]:
        """
        通过攻击目标 + 时间范围加载告警记录，每条记录返回独立的 AttackContext

        当 detect_attack_dist 中存在多条告警记录时（如不同时间段的攻击），
        分别构建上下文，用于逐条独立分析。

        Args:
            attack_target: 攻击目标（IP 地址或监测对象编码）
            start_time: 可选的开始时间过滤
            end_time: 可选的结束时间过滤

        Returns:
            AttackContext 列表（每条告警记录一个）；若无匹配返回空列表
        """
        table = f"{self.config.database}.{self.config.alert_table_name}"
        cols = ", ".join(self.ALERT_COLUMNS)

        conditions = ["attack_target = %(attack_target)s"]
        params = {"attack_target": attack_target}

        if start_time:
            conditions.append("start_time >= %(start_time)s")
            params["start_time"] = start_time
        if end_time:
            conditions.append("end_time <= %(end_time)s")
            params["end_time"] = end_time

        where = " AND ".join(conditions)
        query = f"SELECT {cols} FROM {table} WHERE {where} ORDER BY start_time DESC LIMIT 50"

        logger.info(
            "[ALERT_LOADER] 查询多条告警 / target[%s] / time[%s ~ %s]",
            attack_target, start_time, end_time,
        )
        client = self._get_client()

        try:
            df = client.query_dataframe(query, params)
        except Exception as e:
            logger.error("[ALERT_LOADER] 查询失败 / %s", e)
            raise

        if df.empty:
            logger.warning("[ALERT_LOADER] 未找到告警记录 / target[%s]", attack_target)
            return []

        # 按 attack_id 分组，每个 attack_id 构建一个独立的 AttackContext
        contexts = []
        if "attack_id" in df.columns:
            for aid, group in df.groupby("attack_id"):
                ctx = self._build_context(group)
                if ctx:
                    contexts.append(ctx)
        else:
            ctx = self._build_context(df)
            if ctx:
                contexts.append(ctx)

        logger.info(
            "[ALERT_LOADER] 查询到 %d 条独立告警 / target[%s]",
            len(contexts), attack_target,
        )
        return contexts

    def _build_context(self, df: pd.DataFrame) -> AttackContext:
        """
        将告警 DataFrame 合并为单个 AttackContext

        合并策略:
        - 主信息取第一条记录
        - target_ips/target_mo_codes: 根据 attack_target_type 决定如何提取
        - 时间窗口: 取最早 start_time 和最晚 end_time（尽量扩大分析范围）
        - 阈值: 取最大 threshold 值，并自动转换单位；若无法解析则从峰值反推
        - 攻击类型: 合并所有记录的 attack_types 为去重列表
        """
        # 取第一条作为主要信息来源
        first = df.iloc[0]

        # 根据目标类型确定过滤方式:
        # - ipv4: 将所有记录的 attack_target 作为目标IP列表
        # - mo: 将所有记录的 attack_target 作为监测对象编码列表
        # - 其他: 尝试将主目标作为单个IP使用
        target_type = _val(first, "attack_target_type", "")
        main_target = _val(first, "attack_target", "")

        target_ips = []
        target_mo_codes = []

        if target_type == "ipv4":
            # 可能有多条记录对应不同的目标IP
            target_ips = df["attack_target"].dropna().unique().tolist()
        elif target_type == "mo":
            target_mo_codes = df["attack_target"].dropna().unique().tolist()
        else:
            # 尝试同时使用
            target_ips = [main_target] if main_target else []

        # custcode 关联监测对象表的 id
        # 无论 target_type 是什么，只要 custcode 存在就作为 target_mo_codes
        if "custcode" in df.columns:
            custcodes = df["custcode"].dropna().unique().tolist()
            if custcodes:
                target_mo_codes = [str(c) for c in custcodes]

        # 时间窗口合并：取所有告警的最早开始时间和最晚结束时间
        # 这样可以覆盖攻击的完整持续时间
        start_times = pd.to_datetime(df["start_time"], errors="coerce")
        end_times = pd.to_datetime(df["end_time"], errors="coerce")
        ctx_start = start_times.min()
        ctx_end = end_times.max()

        # 若 end_time 缺失但 duration 存在，用 start_time + duration 推算
        if pd.isna(ctx_end) and "duration" in df.columns:
            max_dur_ms = df["duration"].max()
            if pd.notna(max_dur_ms):
                ctx_end = ctx_start + pd.Timedelta(milliseconds=max_dur_ms)

        # 阈值处理：取所有记录中的最大 threshold 作为检测阈值
        threshold_raw = None
        if "threshold" in df.columns:
            valid_thresholds = df["threshold"].dropna()
            if not valid_thresholds.empty:
                threshold_raw = float(valid_thresholds.max())
        threshold_unit = _val(first, "threshold_unit", "")

        threshold_pps = None
        threshold_bps = None
        if threshold_raw is not None and threshold_unit:
            # 根据 threshold_unit 中的关键字进行单位自动转换
            # 支持: pps/kpps/mpps、bps/Kbps/Mbps/Gbps 等多种格式
            unit_lower = threshold_unit.lower()
            if "pps" in unit_lower or "packet" in unit_lower:
                # PPS 类单位转换: mpps → ×10^6, kpps → ×10^3, pps → 原值
                if "mpps" in unit_lower or "mpps" in unit_lower:
                    threshold_pps = float(threshold_raw) * 1_000_000
                elif "kpps" in unit_lower:
                    threshold_pps = float(threshold_raw) * 1_000
                else:
                    threshold_pps = float(threshold_raw)
            elif "bps" in unit_lower or "byte" in unit_lower or "mb" in unit_lower:
                # BPS 类单位转换: Gbps → ×10^9, Mbps → ×10^6, Kbps → ×10^3
                if "gbps" in unit_lower or "g" in unit_lower:
                    threshold_bps = float(threshold_raw) * 1_000_000_000
                elif "mbps" in unit_lower or "mb" in unit_lower or "m" in unit_lower:
                    threshold_bps = float(threshold_raw) * 1_000_000
                elif "kbps" in unit_lower or "kb" in unit_lower or "k" in unit_lower:
                    threshold_bps = float(threshold_raw) * 1_000
                else:
                    threshold_bps = float(threshold_raw)

        # 如果单位解析未能得到阈值，使用告警峰值反推:
        # 取最大峰值 × 50% 作为保守阈值
        # 理由: 告警峰值说明至少超过了这个值，50% 是一个安全下界
        if threshold_pps is None and "max_pps" in df.columns:
            max_pps_val = df["max_pps"].max()
            if pd.notna(max_pps_val) and max_pps_val > 0:
                # 告警峰值说明至少超过了这个值，取50%作为保守阈值
                threshold_pps = max_pps_val * 0.5
        if threshold_bps is None and "max_bps" in df.columns:
            max_bps_val = df["max_bps"].max()
            if pd.notna(max_bps_val) and max_bps_val > 0:
                threshold_bps = max_bps_val * 0.5  # 同样取50%作为保守阈值

        # 合并攻击类型：将所有告警记录的 attack_types 字段拆分后去重
        all_types = set()
        for types_str in df["attack_types"].dropna().unique():
            for t in str(types_str).split(","):
                t = t.strip()
                if t:
                    all_types.add(t)

        ctx = AttackContext(
            attack_id=_val(first, "attack_id"),
            alert_ids=df["id"].dropna().astype(int).tolist(),
            attack_target=main_target,
            attack_target_type=target_type,
            target_ips=target_ips,
            target_mo_codes=target_mo_codes,
            start_time=ctx_start.to_pydatetime() if pd.notna(ctx_start) else None,
            end_time=ctx_end.to_pydatetime() if pd.notna(ctx_end) else None,
            threshold_pps=threshold_pps,
            threshold_bps=threshold_bps,
            threshold_raw=int(threshold_raw) if threshold_raw is not None else None,            threshold_unit=threshold_unit,
            attack_types=sorted(all_types),
            attack_maintype=_val(first, "attack_maintype"),
            direction=_val(first, "direction", "in"),
            level=_val(first, "level", ""),
            max_pps=_float(df["max_pps"].max()) if "max_pps" in df.columns else None,
            max_bps=_float(df["max_bps"].max()) if "max_bps" in df.columns else None,
            mean_pps=_float(df["mean_packet_ps"].mean()) if "mean_packet_ps" in df.columns else None,
            mean_bps=_float(df["mean_bytes_ps"].mean()) if "mean_bytes_ps" in df.columns else None,
        )

        logger.info(
            "[ALERT_LOADER] 告警上下文构建完成 / target[%s] / type[%s] / "
            "time[%s ~ %s] / threshold_pps[%s] / threshold_bps[%s] / "
            "attack_types%s / alerts[%d]",
            ctx.attack_target,
            ctx.attack_target_type,
            ctx.start_time,
            ctx.end_time,
            ctx.threshold_pps,
            ctx.threshold_bps,
            ctx.attack_types,
            len(ctx.alert_ids),
        )
        return ctx


def _val(row_or_series, key: str, default: str = None):
    """
    安全取值辅助函数

    处理 pandas Series 和普通字典两种数据源，
    自动过滤 None 和 NaN 值，返回字符串或默认值。
    """
    if isinstance(row_or_series, pd.Series):
        v = row_or_series.get(key)
    else:
        v = row_or_series.get(key, default) if hasattr(row_or_series, "get") else default
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return default
    return str(v)


def _float(v) -> Optional[float]:
    """安全转换为浮点数，None 和 NaN 返回 None"""
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    return float(v)
