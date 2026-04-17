# ClickHouse 大数据量查询优化方案

## 1. 问题分析

### 当前查询模式

当前系统通过 `clickhouse-driver` 的 `query_dataframe` 一次性加载全量数据到内存:

```python
# loader.py 现状
result = client.query_dataframe(query, params)
# SELECT 29列 FROM analytics_netflow_dist WHERE ... ORDER BY parser_rcv_time
```

### 瓶颈场景

| 场景 | 数据量级 | 典型问题 |
|------|----------|----------|
| 持续时间长的攻击 (≥24h) | 数千万~数亿行 | 查询超时 (>30s)、内存溢出 |
| 大流量 DDoS (反射放大) | 数千万行 | DataFrame 内存 10~50 GB |
| 多目标批量分析 | 并发查询 | 连接池耗尽、ClickHouse 过载 |
| 宽时间窗口查询 | 全表扫描 | 未命中分区/索引 |

---

## 2. 优化策略总览

```
┌─────────────────────────────────────────────────────────┐
│              ClickHouse 查询优化 策略栈                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Layer 1: SQL 层优化 (无需改代码)                        │
│  ├─ 分区裁剪 / 主键索引                                  │
│  ├─ PREWHERE 优化                                       │
│  └─ 物化视图预聚合                                       │
│                                                         │
│  Layer 2: 查询层优化 (改 loader.py)                      │
│  ├─ 分页游标查询 (替代一次性加载)                          │
│  ├─ 服务端聚合下推 (减少传输量)                           │
│  └─ 超时控制 + 重试                                      │
│                                                         │
│  Layer 3: 架构层优化 (改数据流)                           │
│  ├─ 采样分析模式 (大数据降采样)                           │
│  ├─ 异步队列 + 增量分析                                   │
│  └─ 缓存层 (重复查询优化)                                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Layer 1: SQL 层优化

### 3.1 确认/创建分区和索引

```sql
-- 检查当前表结构
SHOW CREATE TABLE analytics_netflow_dist;

-- 如果 parser_rcv_time 不是分区键, 建议按日分区
-- (需 DBA 配合, 在 ClickHouse 服务端修改)
ALTER TABLE analytics_netflow_dist
  PARTITION BY toYYYYMMDD(toDateTime(parser_rcv_time / 1000));

-- 如果 parser_rcv_time 不在 ORDER BY 中, 添加二级索引
ALTER TABLE analytics_netflow_dist
  ADD INDEX idx_parser_rcv_time parser_rcv_time TYPE minmax GRANULARITY 4;
```

### 3.2 使用 PREWHERE 优化过滤

```sql
-- 优化前: WHERE 过滤在数据读取之后
SELECT ... FROM table WHERE dst_ip_addr IN (...) AND parser_rcv_time >= ...

-- 优化后: PREWHERE 先过滤高选择性列, 减少IO
SELECT ... FROM table
PREWHERE dst_ip_addr IN (...)       -- 高选择性列优先过滤
WHERE parser_rcv_time >= ...        -- 再过滤时间
```

### 3.3 物化视图预聚合 (针对高频分析场景)

```sql
-- 为特征提取阶段创建按 src_ip 预聚合的物化视图
CREATE MATERIALIZED VIEW mv_src_ip_agg
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMMDD(hour)
ORDER BY (dst_ip_addr, src_ip_addr, hour)
AS SELECT
    dst_ip_addr,
    src_ip_addr,
    toStartOfMinute(toDateTime(parser_rcv_time / 1000)) AS hour,
    -- 基础聚合
    sum(packets)           AS total_packets,
    sum(octets)            AS total_bytes,
    count()                AS flow_count,
    min(parser_rcv_time)   AS flow_start_time,
    max(parser_rcv_time)   AS flow_end_time,
    -- 多样性
    uniq(dst_port)         AS dst_port_count,
    uniq(protocol)         AS protocol_count,
    -- 分类众数
    any(src_country)       AS country,
    any(src_province)      AS province,
    any(src_isp)           AS isp
FROM analytics_netflow_dist
GROUP BY dst_ip_addr, src_ip_addr, hour;
```

> 优势: 特征提取阶段可直接从物化视图查询，数据量减少 10~100 倍。

---

## 4. Layer 2: 查询层优化

### 4.1 分页游标查询 (分批加载)

改造 `ClickHouseLoader`，支持大数据量分批加载:

```python
class ClickHouseLoader:
    # 新增配置项
    DEFAULT_PAGE_SIZE = 500_000   # 每批 50 万行
    MAX_TOTAL_ROWS    = 10_000_000  # 最大加载 1000 万行
    QUERY_TIMEOUT     = 60          # 单批查询超时 60 秒

    def load_data(self, target_ips=None, target_mo_codes=None,
                  start_time=None, end_time=None) -> pd.DataFrame:
        """分批游标加载，避免单次查询过大"""
        query, params = self._build_query(target_ips, target_mo_codes,
                                          start_time, end_time)

        # Step 1: 先查询总行数，判断是否需要采样
        count = self._count_rows(query, params)
        if count > self.MAX_TOTAL_ROWS:
            logger.warning("[DATA] 数据量[%d]超过上限[%d]，启用采样模式",
                           count, self.MAX_TOTAL_ROWS)
            return self._load_sampled(query, params, count)

        # Step 2: 分批加载
        frames = []
        offset = 0
        while True:
            batch_query = f"{query} LIMIT {self.DEFAULT_PAGE_SIZE} OFFSET {offset}"
            batch = self._execute_with_timeout(batch_query, params)
            if batch.empty:
                break
            frames.append(batch)
            offset += self.DEFAULT_PAGE_SIZE
            logger.info("[DATA] 分批加载 / offset[%d] / batch[%d]",
                        offset, len(batch))
            if len(batch) < self.DEFAULT_PAGE_SIZE:
                break

        return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()

    def _count_rows(self, query, params) -> int:
        """快速计数（用 EXPLAIN 估算或直接 COUNT）"""
        count_query = query.replace("SELECT ...", "SELECT count()", 1)
        # 使用轻量计数: system.parts 估算
        result = self._client.execute(count_query, params)
        return result[0][0] if result else 0
```

### 4.2 超时与重试

```python
def _execute_with_timeout(self, query, params, retries=2):
    """带超时和重试的查询执行"""
    import time
    for attempt in range(retries + 1):
        try:
            settings = {
                'max_execution_time': self.QUERY_TIMEOUT,
                'send_timeout': 30,
                'receive_timeout': 120,
            }
            return self._client.query_dataframe(query, params,
                                                 settings=settings)
        except Exception as e:
            if attempt < retries:
                wait = 2 ** attempt  # 指数退避: 1s, 2s
                logger.warning("[DATA] 查询失败, %ds后重试 / error[%s]",
                               wait, e)
                time.sleep(wait)
            else:
                raise
```

### 4.3 服务端聚合下推

对于路径分析中的聚合查询（入口路由器、地理分布等），直接在 ClickHouse 端完成:

```python
def load_preaggregated(self, target_ips, start_time, end_time,
                       group_cols: list, agg_cols: dict) -> pd.DataFrame:
    """
    服务端聚合查询 — 减少网络传输

    示例: 入口路由器分析
    group_cols = ['flow_ip_addr', 'input_if_index']
    agg_cols   = {'src_ip_addr': ['count', 'nunique'],
                  'packets': ['sum'], 'octets': ['sum']}
    """
    # 构建聚合 SQL
    group_clause = ", ".join(group_cols)
    agg_clauses = []
    for col, funcs in agg_cols.items():
        for func in funcs:
            agg_clauses.append(f"{func}({col}) AS {col}_{func}")

    query = f"""
        SELECT {group_clause}, {', '.join(agg_clauses)}
        FROM {self.config.database}.{self.config.table_name}
        WHERE dst_ip_addr IN %(target_ips)s
          AND parser_rcv_time >= %(start_ts)s
          AND parser_rcv_time <= %(end_ts)s
        GROUP BY {group_clause}
        ORDER BY flow_count DESC
    """
    return self._client.query_dataframe(query, params)
```

---

## 5. Layer 3: 架构层优化

### 5.1 采样分析模式

当数据量超过阈值时，自动切换到采样模式:

```
数据量判断:
├─ < 500 万行   → 全量分析 (当前模式)
├─ 500~2000 万  → 采样分析 (随机采样 500 万)
└─ > 2000 万    → 两阶段分析:
                   ├─ 阶段A: 采样快速分析 (1分钟内出初步结果)
                   └─ 阶段B: 后台全量异步分析 (结果更新)
```

```python
def _load_sampled(self, query, params, total_count) -> pd.DataFrame:
    """采样加载: ClickHouse 原生 SAMPLE 或随机采样"""
    sample_ratio = min(self.MAX_TOTAL_ROWS / total_count, 1.0)

    # 方案1: ClickHouse SAMPLE 子句 (需表引擎支持)
    sampled_query = query.replace(
        "FROM",
        f"FROM {self.config.database}.{self.config.table_name} SAMPLE {sample_ratio:.4f}",
        1
    )

    # 方案2: 基于伪列的随机采样 (通用方案)
    # WHERE rand() % 1000 < {sample_rate_permille}
    sample_permille = int(sample_ratio * 1000)
    sampled_query = query + f" AND rand(42) %% 1000 < {sample_permille}"

    return self._client.query_dataframe(sampled_query, params)
```

### 5.2 异步分析 + 增量计算

```
┌──────────────────────────────────────────────────────┐
│                异步分析架构                            │
├──────────────────────────────────────────────────────┤
│                                                      │
│  API 请求 ──▶ 任务队列 (Redis/RabbitMQ)              │
│                 │                                    │
│                 ├─▶ Worker 1: 分批加载 + 增量特征提取  │
│                 ├─▶ Worker 2: 分批加载 + 增量特征提取  │
│                 └─▶ Worker N: ...                    │
│                      │                               │
│                      ▼                               │
│              增量合并 (流式特征聚合)                    │
│              ├─ 每 100 万行合并一次 features           │
│              └─ 最终合并 → 全量分析                    │
│                      │                               │
│                      ▼                               │
│              结果写入 output/ + 通知 API               │
│                                                      │
└──────────────────────────────────────────────────────┘
```

### 5.3 查询缓存层

```python
import hashlib
import pickle
from pathlib import Path

class QueryCache:
    """本地文件缓存 ClickHouse 查询结果"""

    def __init__(self, cache_dir: str = ".cache/queries", ttl: int = 3600):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl  # 缓存有效期(秒)

    def _cache_key(self, query: str, params: dict) -> str:
        raw = f"{query}:{sorted(params.items())}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def get(self, query: str, params: dict) -> Optional[pd.DataFrame]:
        key = self._cache_key(query, params)
        path = self.cache_dir / f"{key}.parquet"
        if path.exists():
            age = time.time() - path.stat().st_mtime
            if age < self.ttl:
                logger.info("[CACHE] 命中 / key[%s] / age[%ds]", key, int(age))
                return pd.read_parquet(path)
        return None

    def put(self, query: str, params: dict, df: pd.DataFrame):
        key = self._cache_key(query, params)
        path = self.cache_dir / f"{key}.parquet"
        df.to_parquet(path, index=False)
        logger.info("[CACHE] 写入 / key[%s] / rows[%d]", key, len(df))
```

---

## 6. 推荐的 ClickHouse 服务端配置

### 6.1 查询配额

```xml
<!-- users.xml -->
<profiles>
    <ddos_trace>
        <max_execution_time>120</max_execution_time>          <!-- 最大执行120秒 -->
        <max_memory_usage>10000000000</max_memory_usage>      <!-- 单查询最大10GB -->
        <max_rows_to_read>1000000000</max_rows_to_read>       <!-- 最多读10亿行 -->
        <read_overflow_mode>throw</read_overflow_mode>         <!-- 超限抛异常 -->
        <use_query_cache>1</use_query_cache>                   <!-- 启用查询缓存 -->
    </ddos_trace>
</profiles>

<quotas>
    <ddos_trace_quota>
        <interval>
            <duration>3600</duration>
            <queries>1000</queries>
            <errors>100</errors>
        </interval>
    </ddos_trace_quota>
</quotas>
```

### 6.2 表引擎优化建议

```sql
-- 当前使用 Distributed + ReplicatedMergeTree
-- 建议添加 TTL 自动清理历史数据
ALTER TABLE analytics_netflow_dist_local
  MODIFY TTL toDateTime(parser_rcv_time / 1000) + INTERVAL 90 DAY;

-- 添加跳数索引 (加速 WHERE 过滤)
ALTER TABLE analytics_netflow_dist_local
  ADD INDEX idx_dst_ip dst_ip_addr TYPE bloom_filter(0.01) GRANULARITY 4;

ALTER TABLE analytics_netflow_dist_local
  ADD INDEX idx_dst_mo dst_mo_code TYPE bloom_filter(0.01) GRANULARITY 4;

ALTER TABLE analytics_netflow_dist_local
  ADD INDEX idx_time parser_rcv_time TYPE minmax GRANULARITY 4;
```

---

## 7. 实施优先级

| 优先级 | 改动 | 工作量 | 效果 |
|--------|------|--------|------|
| **P0** | loader.py 加超时+重试 | 0.5 天 | 防止查询卡死 |
| **P0** | 分批游标加载 (分页) | 1 天 | 解决大数据 OOM |
| **P1** | 数据量预估 + 采样模式 | 1 天 | 应对亿级数据 |
| **P1** | ClickHouse 索引/分区优化 | 0.5 天 (需 DBA) | 查询提速 5~10x |
| **P2** | 服务端聚合下推 (路径分析) | 2 天 | 路径分析提速 10~50x |
| **P2** | 查询缓存层 | 1 天 | 重复查询秒出 |
| **P3** | 物化视图预聚合 | 2 天 (需 DBA) | 特征提取提速 10x |
| **P3** | 异步分析架构 | 5 天 | 彻底解耦查询与分析 |
