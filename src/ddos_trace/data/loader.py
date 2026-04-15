"""
ClickHouse 数据加载与预处理模块

本模块负责从 ClickHouse 的 NetFlow 分布式表中查询原始流量数据，
并进行时间解析、类型转换等预处理操作。

核心类:
    - ClickHouseLoader: 从 ClickHouse 加载 NetFlow 数据，支持按目标IP/监测对象/时间范围过滤
    - DataPreprocessor: 原始数据预处理，包括时间戳转换、数值类型修正
"""

import logging
from datetime import datetime
from typing import List, Optional

import pandas as pd

from ddos_trace.config.models import ClickHouseConfig

logger = logging.getLogger(__name__)

# ClickHouse 查询需要的字段列表
# 这些字段覆盖了流量溯源所需的全部维度:
#   - 流量标识: flow_ip_addr（采集路由器IP）
#   - 五元组: src_ip_addr, dst_ip_addr, src_port, dst_port, protocol
#   - 流量指标: octets（字节数）, packets（包数）, tcp_flags
#   - 接口索引: input_if_index, output_if_index（用于入口路由器定位）
#   - 时间戳: first_time, last_time, parser_rcv_time（毫秒级Unix时间戳）
#   - 地理归属: src/dst 的 country/province/city/isp
#   - 监测对象: src/dst 的 mo_name, mo_code（运营商管理对象）
QUERY_COLUMNS = [
    "flow_ip_addr",
    "src_ip_addr",
    "dst_ip_addr",
    "octets",
    "packets",
    "src_port",
    "dst_port",
    "tcp_flags",
    "protocol",
    "input_if_index",
    "output_if_index",
    "first_time",
    "last_time",
    "parser_rcv_time",
    "src_mo_name",
    "src_mo_code",
    "dst_mo_name",
    "dst_mo_code",
    "src_country",
    "src_province",
    "src_city",
    "src_isp",
    "src_as",
    "dst_country",
    "dst_province",
    "dst_city",
    "dst_isp",
]


class ClickHouseLoader:
    """
    从 ClickHouse 加载 NetFlow 数据

    使用 clickhouse-driver 的 query_dataframe 方法直接返回 DataFrame，
    避免手动转换。采用懒加载模式初始化客户端连接，首次查询时才建立连接。
    """

    def __init__(self, config: ClickHouseConfig):
        self.config = config
        self._client = None  # 懒加载：首次调用 _get_client() 时才创建连接

    def _get_client(self):
        """
        懒加载 ClickHouse 客户端

        延迟到首次查询时才建立连接，避免 import 时就要求 ClickHouse 可达。
        创建后执行 SELECT 1 验证连接可用性。
        """
        if self._client is None:
            try:
                from clickhouse_driver import Client

                self._client = Client(**self.config.connection_params)
                # 验证连接：执行简单查询确认 ClickHouse 可达
                self._client.execute("SELECT 1")
                logger.info(
                    "[CLICKHOUSE] 连接成功 / host[%s] / port[%s] / database[%s]",
                    self.config.host,
                    self.config.port,
                    self.config.database,
                )
            except ImportError:
                raise ImportError(
                    "需要安装 clickhouse-driver: pip install clickhouse-driver"
                )
            except Exception as e:
                raise ConnectionError(
                    f"ClickHouse 连接失败: {e}"
                ) from e
        return self._client

    def load_data(
        self,
        target_ips: Optional[List[str]] = None,
        target_mo_codes: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> pd.DataFrame:
        """
        从 ClickHouse 查询 NetFlow 数据

        Args:
            target_ips: 目的IP列表，为空则不过滤
            target_mo_codes: 目的监测对象编码列表，为空则不过滤
            start_time: 开始时间
            end_time: 结束时间

        Returns:
            包含原始 NetFlow 数据的 DataFrame
        """
        query, params = self._build_query(target_ips, target_mo_codes, start_time, end_time)
        logger.info("[DATA_LOADER] 构建查询 [%s] / 查询参数[%s] / 执行查询-预计返回字段[%d]", query, params, len(QUERY_COLUMNS))

        client = self._get_client()

        try:
            result = client.query_dataframe(query, params)
        except Exception as e:
            logger.error("[DATA_LOADER] 查询失败 / 异常[%s]", e)
            raise

        if result.empty:
            logger.warning("[DATA_LOADER] 查询结果为空")
            return result

        logger.info(
            "[DATA_LOADER] 查询完成 / 记录数[%d] / 列数[%d]",
            len(result),
            len(result.columns),
        )
        return result

    def _build_query(
        self,
        target_ips: Optional[List[str]],
        target_mo_codes: Optional[List[str]],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> tuple:
        """
        构建 SQL 查询语句

        动态拼接 WHERE 条件:
        - target_ips → dst_ip_addr IN (...)  按目的IP过滤
        - target_mo_codes → dst_mo_code IN (...)  按监测对象过滤
        - start_time / end_time → app_rcv_time 范围过滤（使用分区键优化查询性能）

        clickhouse-driver 要求 IN 子句的参数使用 tuple 类型。
        """
        cols = ", ".join(QUERY_COLUMNS)
        table = f"{self.config.database}.{self.config.table_name}"

        conditions = []
        params = {}

        # 目的IP过滤（clickhouse-driver 要求 IN 参数用 tuple）
        if target_ips:
            conditions.append("dst_ip_addr IN %(target_ips)s")
            params["target_ips"] = tuple(target_ips)

        # 监测对象过滤
        if target_mo_codes:
            conditions.append("dst_mo_code IN %(target_mo_codes)s")
            params["target_mo_codes"] = tuple(target_mo_codes)

        # 时间范围过滤（使用 app_rcv_time 作为分区键优化查询）
        if start_time:
            conditions.append("parser_rcv_time >= (toUnixTimestamp(%(start_time)s)*1000)")
            params["start_time"] = start_time
        if end_time:
            conditions.append("parser_rcv_time <= (toUnixTimestamp(%(end_time)s)*1000)")
            params["end_time"] = end_time

        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        query = f"SELECT {cols} FROM {table} {where_clause} ORDER BY parser_rcv_time"
        return query, params


class DataPreprocessor:
    """数据预处理 - 时间解析、类型转换、过滤"""

    def process(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        对原始数据进行预处理

        Args:
            df: 原始 ClickHouse 查询结果

        Returns:
            预处理后的 DataFrame
        """
        if df.empty:
            return df

        df = df.copy()

        # 时间字段转换：parser_rcv_time（毫秒）→ datetime
        if "parser_rcv_time" in df.columns:
            df["flow_time"] = pd.to_datetime(df["parser_rcv_time"], unit="ms")

        # first_time / last_time 也转换为 datetime
        if "first_time" in df.columns:
            df["first_time_dt"] = pd.to_datetime(df["first_time"], unit="ms", errors="coerce")
        if "last_time" in df.columns:
            df["last_time_dt"] = pd.to_datetime(df["last_time"], unit="ms", errors="coerce")

        # 确保数值类型正确
        numeric_cols = ["octets", "packets", "src_port", "dst_port",
                        "tcp_flags", "protocol", "input_if_index", "output_if_index"]
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        logger.info(
            "[PREPROCESSOR] 预处理完成 / 记录数[%d] / 时间范围[%s ~ %s]",
            len(df),
            df["flow_time"].min() if "flow_time" in df.columns else "N/A",
            df["flow_time"].max() if "flow_time" in df.columns else "N/A",
        )
        return df
