-- 说明:
-- 1. 本脚本仅用于 ClickHouse 侧分析结果沉淀。
-- 2. 黑名单、白名单、人工维护基础信息建议放在 MySQL，不放在 ClickHouse。
-- 3. 每张表都提供本地表 `xxx_local` 与分布式表 `xxx_local_dist`。
-- 4. `'{cluster}'` 需要替换为实际集群名。
-- 5. 由于攻击源、目标、入口节点可能同时存在 IPv4 / IPv6，本脚本中的 IP 字段统一使用 String。

drop database threaten_intelligence
CREATE DATABASE IF NOT EXISTS threaten_intelligence on cluster cluster_zyuc;

-- 情报源定义表
create table threaten_intelligence.ti_source_local on cluster cluster_zyuc
(
    source_name String COMMENT '情报源名称，如 local_analyzer、abuseipdb',
    source_type String COMMENT '情报源类型，如 internal/api/stix/csv',
    reliability_weight Float32 DEFAULT 50 COMMENT '情报源可信度权重，0~100',
    enabled UInt8 DEFAULT 1 COMMENT '是否启用，1启用，0停用',
    config_json String DEFAULT '{}' COMMENT '情报源配置，JSON字符串',
    last_sync_time Nullable(DateTime) COMMENT '最近一次同步时间',
    create_time DateTime DEFAULT now() COMMENT '记录创建时间',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
)
    engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_source_local', '{replica}')
    PARTITION BY toYYYYMM(updated_time)
    ORDER BY updated_time
    TTL updated_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

   create table threaten_intelligence.ti_source_local_dist on cluster cluster_zyuc
(
    source_name String COMMENT '情报源名称，如 local_analyzer、abuseipdb',
    source_type String COMMENT '情报源类型，如 internal/api/stix/csv',
    reliability_weight Float32 DEFAULT 50 COMMENT '情报源可信度权重，0~100',
    enabled UInt8 DEFAULT 1 COMMENT '是否启用，1启用，0停用',
    config_json String DEFAULT '{}' COMMENT '情报源配置，JSON字符串',
    last_sync_time Nullable(DateTime) COMMENT '最近一次同步时间',
    create_time DateTime DEFAULT now() COMMENT '记录创建时间',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_source_local', rand());


-- 通用 IOC 指标表
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_indicator_local on cluster cluster_zyuc
(
    indicator_type String COMMENT '指标类型，如 ip/domain/hash/asn/cidr',
    indicator_value String COMMENT '原始指标值',
    normalized_value String COMMENT '标准化后的指标值，用于去重与查询',
    confidence UInt8 DEFAULT 50 COMMENT '指标置信度，0~100',
    severity String DEFAULT 'medium' COMMENT '风险等级，low/medium/high/critical',
    tlp String DEFAULT 'TLP:WHITE' COMMENT '共享级别',
    source_name String COMMENT '来源情报源名称',
    tags Array(String) DEFAULT [] COMMENT '标签数组，如 botnet/reflector/udp_flood',
    raw_payload String DEFAULT '{}' COMMENT '原始情报内容，JSON字符串',
    first_seen_time Nullable(DateTime) COMMENT '首次出现时间',
    last_seen_time Nullable(DateTime) COMMENT '最近出现时间',
    expire_time Nullable(DateTime) COMMENT '过期时间',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
)
    engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_indicator_local', '{replica}')
    PARTITION BY toYYYYMM(updated_time)
    ORDER BY updated_time
    TTL updated_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_indicator_local_dist on cluster cluster_zyuc
(
    indicator_type String COMMENT '指标类型，如 ip/domain/hash/asn/cidr',
    indicator_value String COMMENT '原始指标值',
    normalized_value String COMMENT '标准化后的指标值，用于去重与查询',
    confidence UInt8 DEFAULT 50 COMMENT '指标置信度，0~100',
    severity String DEFAULT 'medium' COMMENT '风险等级，low/medium/high/critical',
    tlp String DEFAULT 'TLP:WHITE' COMMENT '共享级别',
    source_name String COMMENT '来源情报源名称',
    tags Array(String) DEFAULT [] COMMENT '标签数组，如 botnet/reflector/udp_flood',
    raw_payload String DEFAULT '{}' COMMENT '原始情报内容，JSON字符串',
    first_seen_time Nullable(DateTime) COMMENT '首次出现时间',
    last_seen_time Nullable(DateTime) COMMENT '最近出现时间',
    expire_time Nullable(DateTime) COMMENT '过期时间',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
)    engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_indicator_local', rand());


-- 团伙/聚类画像表
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_cluster_profile_local on cluster cluster_zyuc
(
    cluster_id String COMMENT '聚类ID，对应当前分析中的 cluster_id',
    cluster_name String COMMENT '聚类名称，可用于人工命名',
    cluster_type String DEFAULT 'fingerprint' COMMENT '聚类类型，默认 fingerprint',
    cluster_score UInt8 DEFAULT 0 COMMENT '聚类整体风险分，0~100',
    attack_types Array(String) DEFAULT [] COMMENT '聚类涉及的攻击类型列表',
    countries Array(String) DEFAULT [] COMMENT '聚类常见来源国家/地区',
    asns Array(UInt32) DEFAULT [] COMMENT '聚类常见来源ASN列表',
    feature_profile String DEFAULT '{}' COMMENT '聚类特征画像，JSON字符串',
    status String DEFAULT 'active' COMMENT '状态，如 active/inactive/merged',
    first_seen_time Nullable(DateTime) COMMENT '首次出现时间',
    last_seen_time Nullable(DateTime) COMMENT '最近出现时间',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
)
    engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_cluster_profile_local', '{replica}')
    PARTITION BY toYYYYMM(updated_time)
    ORDER BY updated_time
    TTL updated_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_cluster_profile_local_dist on cluster cluster_zyuc
(
    cluster_id String COMMENT '聚类ID，对应当前分析中的 cluster_id',
    cluster_name String COMMENT '聚类名称，可用于人工命名',
    cluster_type String DEFAULT 'fingerprint' COMMENT '聚类类型，默认 fingerprint',
    cluster_score UInt8 DEFAULT 0 COMMENT '聚类整体风险分，0~100',
    attack_types Array(String) DEFAULT [] COMMENT '聚类涉及的攻击类型列表',
    countries Array(String) DEFAULT [] COMMENT '聚类常见来源国家/地区',
    asns Array(UInt32) DEFAULT [] COMMENT '聚类常见来源ASN列表',
    feature_profile String DEFAULT '{}' COMMENT '聚类特征画像，JSON字符串',
    status String DEFAULT 'active' COMMENT '状态，如 active/inactive/merged',
    first_seen_time Nullable(DateTime) COMMENT '首次出现时间',
    last_seen_time Nullable(DateTime) COMMENT '最近出现时间',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_cluster_profile_local', rand());


-- IP 画像主表
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_ip_profile_local on cluster cluster_zyuc
(
    ip String COMMENT '源IP地址，兼容IPv4/IPv6，当前分析主键',
    risk_score UInt8 DEFAULT 0 COMMENT '综合风险分，0~100',
    trust_level String DEFAULT 'unknown' COMMENT '可信等级，unknown/watch/suspicious/confirmed/whitelisted',
    disposition String DEFAULT 'observe' COMMENT '建议处置动作，observe/rate_limit/blackhole/scrubbing/upstream_coordination',
    hit_count UInt32 DEFAULT 0 COMMENT '历史命中总次数',
    confirmed_count UInt32 DEFAULT 0 COMMENT '命中 confirmed 的次数',
    false_positive_count UInt32 DEFAULT 0 COMMENT '被人工标记为误报的次数',
    last_attack_type String DEFAULT '' COMMENT '最近一次主攻击类型，对齐 best_attack_type/source_attack_type',
    matched_attack_types Array(String) DEFAULT [] COMMENT '历史或最近一次命中的攻击类型集合',
    matched_attack_type_count UInt16 DEFAULT 0 COMMENT '命中的攻击类型数量',
    max_attack_confidence_across_types Float32 DEFAULT 0 COMMENT '跨攻击类型的最高置信度',
    last_attack_confidence Float32 DEFAULT 0 COMMENT '最近一次分析中的攻击置信度',
    last_traffic_class String DEFAULT 'background' COMMENT '最近一次分析中的流量分类',
    last_confidence_reasons String DEFAULT '' COMMENT '最近一次分析中的置信度原因',
    cluster_id String DEFAULT '' COMMENT '最近命中的聚类ID',
    asn UInt32 DEFAULT 0 COMMENT '来源ASN',
    country String DEFAULT '' COMMENT '来源国家',
    province String DEFAULT '' COMMENT '来源省份',
    city String DEFAULT '' COMMENT '来源城市',
    isp String DEFAULT '' COMMENT '来源运营商/ISP',
    tags Array(String) DEFAULT [] COMMENT '情报标签',
    source_weights String DEFAULT '{}' COMMENT '各情报源贡献分，JSON字符串',
    whitelist_flag UInt8 DEFAULT 0 COMMENT '是否白名单，1是0否',
    note String DEFAULT '' COMMENT '人工备注',
    first_seen_time Nullable(DateTime) COMMENT '首次出现时间',
    last_seen_time Nullable(DateTime) COMMENT '最近出现时间',
    last_feedback_time Nullable(DateTime) COMMENT '最近人工反馈时间',
    expire_time Nullable(DateTime) COMMENT '过期时间',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
)
engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_ip_profile_local', '{replica}')
    PARTITION BY toYYYYMM(updated_time)
    ORDER BY updated_time
    TTL updated_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_ip_profile_local_dist on cluster cluster_zyuc
(
    ip String COMMENT '源IP地址，兼容IPv4/IPv6，当前分析主键',
    risk_score UInt8 DEFAULT 0 COMMENT '综合风险分，0~100',
    trust_level String DEFAULT 'unknown' COMMENT '可信等级，unknown/watch/suspicious/confirmed/whitelisted',
    disposition String DEFAULT 'observe' COMMENT '建议处置动作，observe/rate_limit/blackhole/scrubbing/upstream_coordination',
    hit_count UInt32 DEFAULT 0 COMMENT '历史命中总次数',
    confirmed_count UInt32 DEFAULT 0 COMMENT '命中 confirmed 的次数',
    false_positive_count UInt32 DEFAULT 0 COMMENT '被人工标记为误报的次数',
    last_attack_type String DEFAULT '' COMMENT '最近一次主攻击类型，对齐 best_attack_type/source_attack_type',
    matched_attack_types Array(String) DEFAULT [] COMMENT '历史或最近一次命中的攻击类型集合',
    matched_attack_type_count UInt16 DEFAULT 0 COMMENT '命中的攻击类型数量',
    max_attack_confidence_across_types Float32 DEFAULT 0 COMMENT '跨攻击类型的最高置信度',
    last_attack_confidence Float32 DEFAULT 0 COMMENT '最近一次分析中的攻击置信度',
    last_traffic_class String DEFAULT 'background' COMMENT '最近一次分析中的流量分类',
    last_confidence_reasons String DEFAULT '' COMMENT '最近一次分析中的置信度原因',
    cluster_id String DEFAULT '' COMMENT '最近命中的聚类ID',
    asn UInt32 DEFAULT 0 COMMENT '来源ASN',
    country String DEFAULT '' COMMENT '来源国家',
    province String DEFAULT '' COMMENT '来源省份',
    city String DEFAULT '' COMMENT '来源城市',
    isp String DEFAULT '' COMMENT '来源运营商/ISP',
    tags Array(String) DEFAULT [] COMMENT '情报标签',
    source_weights String DEFAULT '{}' COMMENT '各情报源贡献分，JSON字符串',
    whitelist_flag UInt8 DEFAULT 0 COMMENT '是否白名单，1是0否',
    note String DEFAULT '' COMMENT '人工备注',
    first_seen_time Nullable(DateTime) COMMENT '首次出现时间',
    last_seen_time Nullable(DateTime) COMMENT '最近出现时间',
    last_feedback_time Nullable(DateTime) COMMENT '最近人工反馈时间',
    expire_time Nullable(DateTime) COMMENT '过期时间',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_ip_profile_local', rand());


-- 事件总表
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_attack_event_local on cluster cluster_zyuc
(
    event_id String COMMENT '内部事件ID，建议使用 attack_id 或 run_id',
    attack_id String COMMENT '告警攻击ID，无 attack_id 模式可为空',
    event_name String COMMENT '事件名称，建议用 目标IP_时间窗',
    target_ip String COMMENT '受攻击目标IP，兼容IPv4/IPv6',
    target_mo_name String COMMENT '目标监测对象名称',
    target_mo_code String COMMENT '目标监测对象编码',
    start_time DateTime COMMENT '分析开始时间',
    end_time Nullable(DateTime) COMMENT '分析结束时间',
    attack_types Array(String) DEFAULT [] COMMENT '本次事件涉及的攻击类型',
    severity String DEFAULT 'medium' COMMENT '事件风险等级',
    event_status String DEFAULT 'auto' COMMENT '事件状态，如 auto/confirmed/false_positive/closed',
    total_source_ips UInt32 DEFAULT 0 COMMENT '源IP总量，对齐 overview.total_source_ips',
    confirmed_sources UInt32 DEFAULT 0 COMMENT 'confirmed 源数量',
    suspicious_sources UInt32 DEFAULT 0 COMMENT 'suspicious 源数量',
    borderline_sources UInt32 DEFAULT 0 COMMENT 'borderline 源数量',
    background_sources UInt32 DEFAULT 0 COMMENT 'background 源数量',
    anomaly_total UInt32 DEFAULT 0 COMMENT '异常源总量，对齐 overview.anomaly_total',
    peak_pps UInt64 DEFAULT 0 COMMENT '峰值PPS',
    peak_bps UInt64 DEFAULT 0 COMMENT '峰值BPS',
    attack_type_count UInt16 DEFAULT 0 COMMENT '攻击类型数量',
    overview_json String DEFAULT '{}' COMMENT '总览摘要，JSON字符串',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
)
engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_attack_event_local', '{replica}')
    PARTITION BY toYYYYMM(updated_time)
    ORDER BY updated_time
    TTL updated_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_attack_event_local_dist on cluster cluster_zyuc
(
    event_id String COMMENT '内部事件ID，建议使用 attack_id 或 run_id',
    attack_id String COMMENT '告警攻击ID，无 attack_id 模式可为空',
    event_name String COMMENT '事件名称，建议用 目标IP_时间窗',
    target_ip String COMMENT '受攻击目标IP，兼容IPv4/IPv6',
    target_mo_name String COMMENT '目标监测对象名称',
    target_mo_code String COMMENT '目标监测对象编码',
    start_time DateTime COMMENT '分析开始时间',
    end_time Nullable(DateTime) COMMENT '分析结束时间',
    attack_types Array(String) DEFAULT [] COMMENT '本次事件涉及的攻击类型',
    severity String DEFAULT 'medium' COMMENT '事件风险等级',
    event_status String DEFAULT 'auto' COMMENT '事件状态，如 auto/confirmed/false_positive/closed',
    total_source_ips UInt32 DEFAULT 0 COMMENT '源IP总量，对齐 overview.total_source_ips',
    confirmed_sources UInt32 DEFAULT 0 COMMENT 'confirmed 源数量',
    suspicious_sources UInt32 DEFAULT 0 COMMENT 'suspicious 源数量',
    borderline_sources UInt32 DEFAULT 0 COMMENT 'borderline 源数量',
    background_sources UInt32 DEFAULT 0 COMMENT 'background 源数量',
    anomaly_total UInt32 DEFAULT 0 COMMENT '异常源总量，对齐 overview.anomaly_total',
    peak_pps UInt64 DEFAULT 0 COMMENT '峰值PPS',
    peak_bps UInt64 DEFAULT 0 COMMENT '峰值BPS',
    attack_type_count UInt16 DEFAULT 0 COMMENT '攻击类型数量',
    overview_json String DEFAULT '{}' COMMENT '总览摘要，JSON字符串',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_attack_event_local', rand());


-- 事件-源IP 明细表，直接承接当前 features 输出
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_source_ip_local on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    src_ip String COMMENT '源IP地址，兼容IPv4/IPv6',
    traffic_class String DEFAULT 'background' COMMENT '流量分类，对齐 traffic_class',
    attack_confidence Float32 DEFAULT 0 COMMENT '攻击置信度，对齐 attack_confidence',
    confidence_reasons String DEFAULT '' COMMENT '置信度原因，对齐 confidence_reasons',
    attack_type String DEFAULT '' COMMENT '当前主攻击类型，可对齐 source_attack_type',
    best_attack_type String DEFAULT '' COMMENT '统一主视图攻击类型，对齐 best_attack_type',
    matched_attack_types Array(String) DEFAULT [] COMMENT '命中的攻击类型列表，对齐 matched_attack_types',
    matched_attack_type_count UInt16 DEFAULT 0 COMMENT '命中的攻击类型数量',
    max_attack_confidence_across_types Float32 DEFAULT 0 COMMENT '跨类型最高置信度',
    cluster_id String DEFAULT '' COMMENT '聚类ID，对齐 cluster_id',
    total_packets UInt64 DEFAULT 0 COMMENT '总包数，对齐 total_packets',
    total_bytes UInt64 DEFAULT 0 COMMENT '总字节数，对齐 total_bytes',
    packets_per_sec UInt64 DEFAULT 0 COMMENT '包速率，对齐 packets_per_sec',
    bytes_per_sec UInt64 DEFAULT 0 COMMENT '字节速率，对齐 bytes_per_sec',
    bytes_per_packet Float32 DEFAULT 0 COMMENT '平均包长，对齐 bytes_per_packet',
    burst_ratio Float32 DEFAULT 0 COMMENT '突发比，对齐 burst_ratio',
    burst_count UInt32 DEFAULT 0 COMMENT '突发次数，对齐 burst_count',
    flow_duration Float32 DEFAULT 0 COMMENT '持续时长，对齐 flow_duration',
    protocol_count UInt16 DEFAULT 0 COMMENT '协议数，对齐 protocol_count',
    dst_port_count UInt16 DEFAULT 0 COMMENT '目的端口数，对齐 dst_port_count',
    asn UInt32 DEFAULT 0 COMMENT '来源ASN',
    country String DEFAULT '' COMMENT '来源国家，对齐 country',
    province String DEFAULT '' COMMENT '来源省份，对齐 province',
    city String DEFAULT '' COMMENT '来源城市，对齐 city',
    isp String DEFAULT '' COMMENT '来源运营商，对齐 isp',
    feature_json String DEFAULT '{}' COMMENT '完整源特征，JSON字符串',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
)
engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_event_source_ip_local', '{replica}')
    PARTITION BY toYYYYMM(created_time)
    ORDER BY created_time
    TTL created_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_source_ip_local_dist on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    src_ip String COMMENT '源IP地址，兼容IPv4/IPv6',
    traffic_class String DEFAULT 'background' COMMENT '流量分类，对齐 traffic_class',
    attack_confidence Float32 DEFAULT 0 COMMENT '攻击置信度，对齐 attack_confidence',
    confidence_reasons String DEFAULT '' COMMENT '置信度原因，对齐 confidence_reasons',
    attack_type String DEFAULT '' COMMENT '当前主攻击类型，可对齐 source_attack_type',
    best_attack_type String DEFAULT '' COMMENT '统一主视图攻击类型，对齐 best_attack_type',
    matched_attack_types Array(String) DEFAULT [] COMMENT '命中的攻击类型列表，对齐 matched_attack_types',
    matched_attack_type_count UInt16 DEFAULT 0 COMMENT '命中的攻击类型数量',
    max_attack_confidence_across_types Float32 DEFAULT 0 COMMENT '跨类型最高置信度',
    cluster_id String DEFAULT '' COMMENT '聚类ID，对齐 cluster_id',
    total_packets UInt64 DEFAULT 0 COMMENT '总包数，对齐 total_packets',
    total_bytes UInt64 DEFAULT 0 COMMENT '总字节数，对齐 total_bytes',
    packets_per_sec UInt64 DEFAULT 0 COMMENT '包速率，对齐 packets_per_sec',
    bytes_per_sec UInt64 DEFAULT 0 COMMENT '字节速率，对齐 bytes_per_sec',
    bytes_per_packet Float32 DEFAULT 0 COMMENT '平均包长，对齐 bytes_per_packet',
    burst_ratio Float32 DEFAULT 0 COMMENT '突发比，对齐 burst_ratio',
    burst_count UInt32 DEFAULT 0 COMMENT '突发次数，对齐 burst_count',
    flow_duration Float32 DEFAULT 0 COMMENT '持续时长，对齐 flow_duration',
    protocol_count UInt16 DEFAULT 0 COMMENT '协议数，对齐 protocol_count',
    dst_port_count UInt16 DEFAULT 0 COMMENT '目的端口数，对齐 dst_port_count',
    asn UInt32 DEFAULT 0 COMMENT '来源ASN',
    country String DEFAULT '' COMMENT '来源国家，对齐 country',
    province String DEFAULT '' COMMENT '来源省份，对齐 province',
    city String DEFAULT '' COMMENT '来源城市，对齐 city',
    isp String DEFAULT '' COMMENT '来源运营商，对齐 isp',
    feature_json String DEFAULT '{}' COMMENT '完整源特征，JSON字符串',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_event_source_ip_local', rand());


-- 事件入口节点热点表，对齐 entry_routers 输出
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_entry_router_local on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    flow_ip_addr String COMMENT '入口设备或采集节点IP，兼容IPv4/IPv6',
    input_if_index UInt32 DEFAULT 0 COMMENT '入口接口索引',
    unique_source_ips UInt32 DEFAULT 0 COMMENT '该入口承载的唯一源IP数量',
    total_packets UInt64 DEFAULT 0 COMMENT '该入口总包数',
    total_bytes UInt64 DEFAULT 0 COMMENT '该入口总字节数',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
)
engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_event_entry_router_local', '{replica}')
    PARTITION BY toYYYYMM(created_time)
    ORDER BY created_time
    TTL created_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_entry_router_local_dist on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    flow_ip_addr String COMMENT '入口设备或采集节点IP，兼容IPv4/IPv6',
    input_if_index UInt32 DEFAULT 0 COMMENT '入口接口索引',
    unique_source_ips UInt32 DEFAULT 0 COMMENT '该入口承载的唯一源IP数量',
    total_packets UInt64 DEFAULT 0 COMMENT '该入口总包数',
    total_bytes UInt64 DEFAULT 0 COMMENT '该入口总字节数',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_event_entry_router_local', rand());


-- 事件来源地域热点表，对齐 geo_distribution 输出
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_geo_distribution_local on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    src_country String DEFAULT '' COMMENT '来源国家',
    src_province String DEFAULT '' COMMENT '来源省份',
    src_city String DEFAULT '' COMMENT '来源城市',
    src_isp String DEFAULT '' COMMENT '来源运营商',
    unique_source_ips UInt32 DEFAULT 0 COMMENT '该地域唯一源IP数量',
    total_packets UInt64 DEFAULT 0 COMMENT '该地域总包数',
    total_bytes UInt64 DEFAULT 0 COMMENT '该地域总字节数',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
)
engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_event_geo_distribution_local', '{replica}')
    PARTITION BY toYYYYMM(created_time)
    ORDER BY created_time
    TTL created_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_geo_distribution_local_dist on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    src_country String DEFAULT '' COMMENT '来源国家',
    src_province String DEFAULT '' COMMENT '来源省份',
    src_city String DEFAULT '' COMMENT '来源城市',
    src_isp String DEFAULT '' COMMENT '来源运营商',
    unique_source_ips UInt32 DEFAULT 0 COMMENT '该地域唯一源IP数量',
    total_packets UInt64 DEFAULT 0 COMMENT '该地域总包数',
    total_bytes UInt64 DEFAULT 0 COMMENT '该地域总字节数',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_event_geo_distribution_local', rand());


-- 事件来源监测对象热点表，对齐 mo_distribution 输出
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_mo_distribution_local on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    src_mo_name String COMMENT '来源监测对象名称',
    src_mo_code String COMMENT '来源监测对象编码',
    attacking_source_ips UInt32 DEFAULT 0 COMMENT '攻击源IP数量',
    total_packets UInt64 DEFAULT 0 COMMENT '总包数',
    total_bytes UInt64 DEFAULT 0 COMMENT '总字节数',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
)
engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_event_mo_distribution_local', '{replica}')
    PARTITION BY toYYYYMM(created_time)
    ORDER BY created_time
    TTL created_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_mo_distribution_local_dist on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    src_mo_name String COMMENT '来源监测对象名称',
    src_mo_code String COMMENT '来源监测对象编码',
    attacking_source_ips UInt32 DEFAULT 0 COMMENT '攻击源IP数量',
    total_packets UInt64 DEFAULT 0 COMMENT '总包数',
    total_bytes UInt64 DEFAULT 0 COMMENT '总字节数',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_event_mo_distribution_local', rand());

-- 事件时间分布表，对齐 time_distribution 输出
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_time_distribution_local on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    bucket_time DateTime COMMENT '时间桶起始时间，对齐 hour',
    unique_source_ips UInt32 DEFAULT 0 COMMENT '该时间桶唯一源IP数',
    total_packets UInt64 DEFAULT 0 COMMENT '该时间桶总包数',
    total_bytes UInt64 DEFAULT 0 COMMENT '该时间桶总字节数',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
)
engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_event_time_distribution_local', '{replica}')
    PARTITION BY toYYYYMM(created_time)
    ORDER BY created_time
    TTL created_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_time_distribution_local_dist on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    bucket_time DateTime COMMENT '时间桶起始时间，对齐 hour',
    unique_source_ips UInt32 DEFAULT 0 COMMENT '该时间桶唯一源IP数',
    total_packets UInt64 DEFAULT 0 COMMENT '该时间桶总包数',
    total_bytes UInt64 DEFAULT 0 COMMENT '该时间桶总字节数',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_event_time_distribution_local', rand());


-- 事件附件元数据表。详情页图表应优先从数据库分析明细实时绘制，本地文件仅作为可选下载附件。
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_artifact_local on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    artifact_name String COMMENT '附件文件名',
    artifact_title String DEFAULT '' COMMENT '附件展示标题',
    artifact_kind String DEFAULT 'report' COMMENT '附件类型：image/report/table/other',
    file_ext String DEFAULT '' COMMENT '文件扩展名',
    file_size UInt64 DEFAULT 0 COMMENT '文件大小',
    mime_type String DEFAULT '' COMMENT 'MIME 类型',
    storage_uri String DEFAULT '' COMMENT '持久化存储位置，可为本地路径、对象存储 URI 或其他地址',
    download_url String DEFAULT '' COMMENT '下载 URL，本地 output 文件可映射到 /artifacts/',
    checksum String DEFAULT '' COMMENT '文件校验值，暂可为空',
    priority UInt16 DEFAULT 999 COMMENT '附件展示排序',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
)
engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_event_artifact_local', '{replica}')
    PARTITION BY toYYYYMM(created_time)
    ORDER BY (event_id, priority, artifact_name)
    TTL created_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_event_artifact_local_dist on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    artifact_name String COMMENT '附件文件名',
    artifact_title String DEFAULT '' COMMENT '附件展示标题',
    artifact_kind String DEFAULT 'report' COMMENT '附件类型：image/report/table/other',
    file_ext String DEFAULT '' COMMENT '文件扩展名',
    file_size UInt64 DEFAULT 0 COMMENT '文件大小',
    mime_type String DEFAULT '' COMMENT 'MIME 类型',
    storage_uri String DEFAULT '' COMMENT '持久化存储位置，可为本地路径、对象存储 URI 或其他地址',
    download_url String DEFAULT '' COMMENT '下载 URL，本地 output 文件可映射到 /artifacts/',
    checksum String DEFAULT '' COMMENT '文件校验值，暂可为空',
    priority UInt16 DEFAULT 999 COMMENT '附件展示排序',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_event_artifact_local', rand());


-- 人工反馈表
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_feedback_local on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    ip String COMMENT '被反馈的IP，兼容IPv4/IPv6',
    action String COMMENT '反馈动作，confirm/false_positive/ignore/whitelist',
    analyst String DEFAULT '' COMMENT '操作分析员',
    reason String DEFAULT '' COMMENT '反馈原因',
    feedback_json String DEFAULT '{}' COMMENT '附加反馈信息，JSON字符串',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
)
engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_feedback_local', '{replica}')
    PARTITION BY toYYYYMM(created_time)
    ORDER BY created_time
    TTL created_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_feedback_local_dist on cluster cluster_zyuc
(
    event_id String COMMENT '事件ID',
    ip String COMMENT '被反馈的IP，兼容IPv4/IPv6',
    action String COMMENT '反馈动作，confirm/false_positive/ignore/whitelist',
    analyst String DEFAULT '' COMMENT '操作分析员',
    reason String DEFAULT '' COMMENT '反馈原因',
    feedback_json String DEFAULT '{}' COMMENT '附加反馈信息，JSON字符串',
    created_time DateTime DEFAULT now() COMMENT '记录创建时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_feedback_local', rand());


-- IP 按天汇总统计表
CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_ip_daily_stat_local on cluster cluster_zyuc
(
    stat_date Date COMMENT '统计日期',
    ip String COMMENT '源IP，兼容IPv4/IPv6',
    hit_events UInt32 DEFAULT 0 COMMENT '当天命中事件数',
    confirmed_events UInt32 DEFAULT 0 COMMENT '当天命中 confirmed 事件数',
    suspicious_events UInt32 DEFAULT 0 COMMENT '当天命中 suspicious 事件数',
    max_pps UInt64 DEFAULT 0 COMMENT '当天最大PPS',
    max_bps UInt64 DEFAULT 0 COMMENT '当天最大BPS',
    attack_types Array(String) DEFAULT [] COMMENT '当天出现的攻击类型集合',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
)
engine = ReplicatedMergeTree(
                                    '/clickhouse/threaten_intelligence/tables/{shard}/ti_ip_daily_stat_local', '{replica}')
    PARTITION BY toYYYYMM(updated_time)
    ORDER BY updated_time
    TTL updated_time + toIntervalMonth(36)
    SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS threaten_intelligence.ti_ip_daily_stat_local_dist on cluster cluster_zyuc
(
    stat_date Date COMMENT '统计日期',
    ip String COMMENT '源IP，兼容IPv4/IPv6',
    hit_events UInt32 DEFAULT 0 COMMENT '当天命中事件数',
    confirmed_events UInt32 DEFAULT 0 COMMENT '当天命中 confirmed 事件数',
    suspicious_events UInt32 DEFAULT 0 COMMENT '当天命中 suspicious 事件数',
    max_pps UInt64 DEFAULT 0 COMMENT '当天最大PPS',
    max_bps UInt64 DEFAULT 0 COMMENT '当天最大BPS',
    attack_types Array(String) DEFAULT [] COMMENT '当天出现的攻击类型集合',
    updated_time DateTime DEFAULT now() COMMENT '记录更新时间'
) engine = Distributed('cluster_zyuc', 'threaten_intelligence', 'ti_ip_daily_stat_local', rand());


-- 初始化情报源
INSERT INTO threaten_intelligence.ti_source_local
    (source_name, source_type, reliability_weight, enabled, config_json)
VALUES
    ('local_analyzer', 'internal', 90, 1, '{"description":"local analysis result ingest"}'),
    ('abuseipdb', 'api', 70, 0, '{"vendor":"AbuseIPDB"}'),
    ('alienvault_otx', 'api', 65, 0, '{"vendor":"AlienVault OTX"}');

-- 2026-04-28 threat_type enhancement
ALTER TABLE threaten_intelligence.ti_ip_profile_local on cluster cluster_zyuc
    ADD COLUMN IF NOT EXISTS threat_types Array(String) DEFAULT [] COMMENT '威胁类型列表';

ALTER TABLE threaten_intelligence.ti_ip_profile_local_dist on cluster cluster_zyuc
    ADD COLUMN IF NOT EXISTS threat_types Array(String) DEFAULT [] COMMENT '威胁类型列表';
