# 威胁情报库总体设计 Threat Intelligence Overall Design

## 1. 设计目标

本系统的威胁情报库不是为了做一个“大而全”的 TI 平台，而是为了服务运营商 DDoS 监测、研判、处置和协同。

核心目标只有四个：

1. 对攻击源给出历史可信度与风险沉淀。
2. 对重复出现的攻击源、团伙、地域、入口路径做跨事件关联。
3. 给当前溯源分析结果补充“历史命中 + 外部情报 + 人工反馈”的上下文。
4. 为运营商输出更可执行的结论，例如是否封堵、是否牵引、是否需要上游协同。

## 2. 从运营商痛点出发的建设原则

运营商最关心的不是“情报字段多不多”，而是：

1. 这个源是不是老对手，历史上打过几次。
2. 这次攻击是不是延续性的团伙行为。
3. 哪些来源 AS、地域、运营商、监测对象反复出现。
4. 是否值得立即处置，还是先观察。
5. 是否能给客户、网维、骨干、上游协同方一套统一口径。

因此设计原则是：

1. 以 IP、网段、ASN、团伙、事件为主线。
2. 以“可回流、可查询、可衰减、可人工修正”为核心机制。
3. 外部情报只作为增强信号，不作为唯一依据。
4. 优先支持 DDoS 场景，不追求一步到位覆盖所有安全场景。

## 3. 业务能力范围

### 3.1 P0 必须支持

- IP 风险画像
- 历史事件回溯
- 分析结果自动回流
- 人工确认与误报修正
- 情报查询接口

### 3.2 P1 应该支持

- 聚类团伙沉淀
- 网段 / ASN / 国家 / 省份维度的汇总画像
- 外部情报接入与缓存
- 告警前置加权

### 3.3 P2 可扩展

- STIX 2.1 导出
- TAXII 订阅与共享
- 多租户权限隔离
- 处置策略联动

## 4. 总体架构

```text
NetFlow / 告警 / 分析结果
        |
        v
  溯源分析器 Analyzer
        |
        +---- 实时查询威胁情报库 -----> 情报查询服务 TI Query API
        |
        +---- 分析结果回流 -----------> 情报回流服务 TI Ingest API
                                          |
                                          v
                               PostgreSQL + Redis
                                          |
                      +-------------------+-------------------+
                      |                                       |
                      v                                       v
                外部情报采集器                         人工运营台 / 审核台
             AbuseIPDB / OTX / VT / 黑名单               确认 / 白名单 / 备注
```

## 5. 功能分层

### 5.1 采集层

负责从三类来源获取情报：

1. 本地分析回流
2. 外部威胁情报源
3. 人工审核反馈

### 5.2 存储层

建议拆成两类库，不要混放：

- `ClickHouse`
  - 承载分析结果沉淀
  - 包括事件总览、源画像回流、聚类、路径热点、时间分布、日汇总
- `MySQL`
  - 承载基础信息和策略信息
  - 包括黑名单、白名单、人工标签、处置策略、情报源配置
- `Redis`
  - 存热点查询缓存、短 TTL 的外部情报结果

原因：

1. ClickHouse 适合高吞吐写入和按事件、按时间、按来源的大范围查询分析。
2. MySQL 更适合存管理类主数据、白黑名单、审核配置、策略规则和人工维护信息。
3. 运营侧经常需要人工维护白名单/黑名单，这类数据放 MySQL 更稳妥。

#### ClickHouse 表设计

建议采用“两层表”：

1. 本地表
   - 命名为 `xxx_local`
   - 使用 `ReplacingMergeTree` 或 `MergeTree`
2. 分布式表
   - 命名为 `xxx_local_dist`
   - 使用 `Distributed`

#### MySQL 表设计

建议用于：

1. 黑名单
2. 白名单
3. 人工反馈
4. 情报源配置
5. 处置策略和例外规则

### 5.3 服务层

提供三类接口：

1. 单 IP / 批量 IP 查询
2. 事件回流
3. 人工修正与白名单

### 5.4 应用层

直接服务当前 DDoS 分析系统：

1. 分析前查询历史风险
2. 分析后写入事件与源画像
3. 页面展示历史命中和关联结果

## 6. 核心数据模型

### 6.1 核心实体

#### `ti_source`

情报源定义表，记录本地回流、AbuseIPDB、OTX、VirusTotal 等。

#### `ti_indicator`

统一 IOC 主表，适配 IP、CIDR、Domain、URL、Hash、ASN 等类型。

#### `ti_ip_profile`

面向 IP 的核心画像表，是 DDoS 场景最重要的表。

关键内容：

- 当前风险分
- 首次出现 / 最近出现
- 命中事件次数
- 最近攻击类型
- 地域、ASN、运营商
- 白名单标记
- 人工确认状态

#### `ti_attack_event`

沉淀一次攻击事件的总体信息。

#### `ti_event_source_ip`

事件与源 IP 的关系表，记录该源在该事件中的角色、分值、流量强度、聚类结果。

#### `ti_cluster_profile`

跨事件沉淀的团伙/指纹画像表，用于表达“疑似同一团伙”。

#### `ti_feedback`

人工反馈与审核表，包括确认、误报、忽略、白名单等。

#### `ti_ip_daily_stat`

按天汇总的命中统计，用于趋势、衰减、热点查询。

#### `ti_blacklist` / `ti_whitelist`

建议放在 MySQL，作为基础策略数据维护表。  
这两张表不应该和大体量分析结果混在 ClickHouse 中。

## 7. 关键字段设计

### 7.1 IP 风险分

建议 `risk_score` 取值 `0~100`。

组成建议：

- 本地历史命中：40%
- 本次行为强度：25%
- 外部情报命中：20%
- 团伙关联：10%
- 人工反馈：5%

### 7.2 状态字段

- `trust_level`
  - `unknown`
  - `watch`
  - `suspicious`
  - `confirmed`
  - `whitelisted`

- `disposition`
  - `observe`
  - `rate_limit`
  - `blackhole`
  - `scrubbing`
  - `upstream_coordination`

### 7.3 生命周期字段

- `first_seen`
- `last_seen`
- `expire_at`
- `last_feedback_at`

## 8. 风险评分与衰减策略

### 8.1 基础规则

1. 每次被 `confirmed` 事件命中，分值增加。
2. 被人工标注为误报，分值大幅下降。
3. 被加入白名单，强制降为低风险并排除处置建议。
4. 长时间不再命中，按衰减规则递减。

### 8.2 建议公式

```text
score_today =
  min(
    100,
    base_score_from_history
    + behavior_score
    + external_score
    + cluster_score
    + analyst_adjustment
  )
```

衰减：

```text
decayed_score = max(10, current_score * e^(-0.02 * days_since_last_seen))
```

说明：

- 保留最低分 10，是为了不丢历史痕迹。
- 白名单对象不适用该公式，单独按白名单逻辑处理。

## 9. 与现有溯源系统的集成方式

### 9.1 分析前

对待分析源做批量查询：

- 历史命中次数
- 最近一次出现时间
- 历史攻击类型
- 历史风险分
- 是否已知团伙成员
- 是否白名单

其中：

1. 历史命中、历史风险、团伙关联优先查 ClickHouse。
2. 白名单、黑名单、人工例外规则优先查 MySQL。

### 9.2 分析中

把查询结果融合到当前特征中：

- `ti_risk_score`
- `ti_hit_count`
- `ti_tags`
- `ti_last_seen`
- `ti_cluster_id`

用于增强排序和报告解释，但不直接替代行为分析。

### 9.3 分析后

把本次分析回流：

1. 写入事件表
2. 写入事件源 IP 关系表
3. 更新 IP 风险画像
4. 更新团伙画像
5. 更新日汇总统计

### 9.4 与当前分析结果字段的契合关系

当前项目里稳定可回流的结果主要分为三类：

#### 源画像特征

- `attack_confidence`
- `traffic_class`
- `confidence_reasons`
- `best_attack_type`
- `matched_attack_types`
- `matched_attack_type_count`
- `max_attack_confidence_across_types`
- `total_packets`
- `total_bytes`
- `packets_per_sec`
- `bytes_per_sec`
- `bytes_per_packet`
- `burst_ratio`
- `burst_count`
- `flow_duration`
- `protocol_count`
- `dst_port_count`
- `country/province/city/isp`
- `cluster_id`

这些字段应直接回流到：

- ClickHouse `ti_event_source_ip_local`
- ClickHouse `ti_ip_profile_local`

#### 事件总览

- `overview.total_source_ips`
- `overview.confirmed`
- `overview.suspicious`
- `overview.borderline`
- `overview.background`
- `overview.anomaly_total`
- `overview.attack_type_names`
- `overview.attack_type_count`
- `overview.top_attackers`

这些字段应直接回流到：

- ClickHouse `ti_attack_event_local`

#### 路径与热点分析

- `entry_routers`
- `geo_distribution`
- `mo_distribution`
- `time_distribution`

这些字段不适合只放在 JSON 中，建议分别沉淀到：

- ClickHouse `ti_event_entry_router_local`
- ClickHouse `ti_event_geo_distribution_local`
- ClickHouse `ti_event_mo_distribution_local`
- ClickHouse `ti_event_time_distribution_local`

这样后续才能支持：

1. 跨事件统计入口热点。
2. 统计某地区、某运营商、某监测对象的重复命中情况。
3. 对同类攻击做时间趋势对比。

## 10. 外部情报接入策略

### 10.1 接入优先级

#### P0

- AbuseIPDB
- AlienVault OTX

#### P1

- VirusTotal
- Blocklist.de
- Spamhaus

#### P2

- STIX/TAXII 订阅源
- 行业共享情报平台

### 10.2 接入原则

1. 外部情报只做增强，不单独定性。
2. 必须保留 `source_name`、`confidence`、`first_seen`、`last_seen`、`raw_payload`。
3. 每个情报源要有独立可信度权重。
4. 对查询频率高的热点 IP 要走缓存。

## 11. API 设计建议

### 11.1 批量查询

`POST /api/v1/threat-intel/ip/batch-query`

请求：

```json
{
  "ips": ["1.1.1.1", "2.2.2.2"]
}
```

返回：

```json
{
  "1.1.1.1": {
    "risk_score": 82,
    "trust_level": "confirmed",
    "hit_count": 7,
    "last_seen": "2026-04-16T10:00:00+08:00",
    "cluster_id": "CL-202604-0007",
    "tags": ["udp_flood", "reflector", "repeat_offender"]
  }
}
```

### 11.2 事件回流

`POST /api/v1/threat-intel/event/ingest`

写入一次完整分析结果，供情报库沉淀。

### 11.3 人工反馈

`POST /api/v1/threat-intel/feedback`

支持：

- `confirm`
- `false_positive`
- `ignore`
- `whitelist`

## 12. 页面与输出建议

威胁情报库接入后，页面和报告至少补充以下内容：

1. 历史命中次数
2. 最近命中时间
3. 是否重复攻击源
4. 是否疑似同团伙
5. 是否命中外部情报
6. 建议处置动作

## 13. 实施路线

### Phase 1

- 建表
- 批量查询 API
- 分析结果回流
- 人工反馈接口

### Phase 2

- 外部情报接入
- 风险评分与衰减任务
- 报告中展示历史命中

### Phase 3

- 团伙画像
- 跨事件关联
- 页面联动展示

### Phase 4

- 共享接口
- 处置联动
- 质量度量与运营台

## 14. 结论

一个对运营商有价值的威胁情报库，不是简单地堆 IP 黑名单。  
它应该把“历史命中、当前行为、跨事件关联、人工反馈、处置建议”串成闭环。  
对当前项目来说，最实际的落地方向是：以 ClickHouse 为主库，先把 IP 画像、事件回流、人工反馈和批量查询做扎实，再逐步叠加外部情报和团伙关联。
