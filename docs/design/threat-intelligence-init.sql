-- 说明:
-- 1. 本文件为 MySQL 初始化脚本。
-- 2. 该脚本用于基础信息和策略信息，不用于承载大体量分析结果。
-- 3. 分析结果沉淀请使用 ClickHouse 版本:
--    docs/design/threat-intelligence-init-clickhouse.sql
-- 4. 为兼容 IPv4 / IPv6，IP 字段统一使用 VARCHAR(64)。

CREATE DATABASE IF NOT EXISTS threaten_intelligence
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE threaten_intelligence;

CREATE TABLE IF NOT EXISTS ti_source (
    source_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
    source_name VARCHAR(64) NOT NULL COMMENT '情报源名称，如 local_analyzer、abuseipdb',
    source_type VARCHAR(32) NOT NULL COMMENT '情报源类型，如 internal/api/stix/csv',
    reliability_weight DECIMAL(5,2) NOT NULL DEFAULT 50.00 COMMENT '情报源可信度权重，0~100',
    enabled TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否启用，1启用，0停用',
    config_json JSON NOT NULL COMMENT '情报源配置，JSON格式',
    last_sync_at DATETIME NULL COMMENT '最近一次同步时间',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '记录更新时间',
    PRIMARY KEY (source_id),
    UNIQUE KEY uk_ti_source_name (source_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='情报源配置表';

CREATE TABLE IF NOT EXISTS ti_blacklist (
    blacklist_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
    indicator_type VARCHAR(32) NOT NULL COMMENT '对象类型，如 ip/cidr/domain/asn',
    indicator_value VARCHAR(255) NOT NULL COMMENT '对象值，兼容IPv4/IPv6/CIDR/域名',
    normalized_value VARCHAR(255) NOT NULL COMMENT '标准化后的对象值',
    severity VARCHAR(16) NOT NULL DEFAULT 'high' COMMENT '严重级别，low/medium/high/critical',
    confidence_score DECIMAL(5,2) NOT NULL DEFAULT 80.00 COMMENT '加入黑名单的置信分',
    source_name VARCHAR(64) NOT NULL COMMENT '黑名单来源，如 local/manual/external',
    reason VARCHAR(512) NOT NULL DEFAULT '' COMMENT '加入黑名单原因',
    tags JSON NULL COMMENT '标签列表，JSON数组',
    effective_from DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '生效时间',
    effective_to DATETIME NULL COMMENT '失效时间，为空表示长期有效',
    status VARCHAR(16) NOT NULL DEFAULT 'active' COMMENT '状态，active/inactive/expired',
    created_by VARCHAR(128) NOT NULL DEFAULT 'system' COMMENT '创建人或系统标识',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '记录更新时间',
    PRIMARY KEY (blacklist_id),
    KEY idx_ti_blacklist_lookup (indicator_type, normalized_value, status),
    KEY idx_ti_blacklist_effective (effective_from, effective_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='基础黑名单表';

CREATE TABLE IF NOT EXISTS ti_whitelist (
    whitelist_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
    indicator_type VARCHAR(32) NOT NULL COMMENT '对象类型，如 ip/cidr/domain/asn',
    indicator_value VARCHAR(255) NOT NULL COMMENT '对象值，兼容IPv4/IPv6/CIDR/域名',
    normalized_value VARCHAR(255) NOT NULL COMMENT '标准化后的对象值',
    scope_type VARCHAR(32) NOT NULL DEFAULT 'global' COMMENT '作用范围，global/mo/target/customer',
    scope_value VARCHAR(255) NOT NULL DEFAULT '' COMMENT '作用范围值，如监测对象编码、目标IP、客户编码',
    reason VARCHAR(512) NOT NULL DEFAULT '' COMMENT '加入白名单原因',
    source_name VARCHAR(64) NOT NULL DEFAULT 'manual' COMMENT '白名单来源',
    effective_from DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '生效时间',
    effective_to DATETIME NULL COMMENT '失效时间，为空表示长期有效',
    status VARCHAR(16) NOT NULL DEFAULT 'active' COMMENT '状态，active/inactive/expired',
    created_by VARCHAR(128) NOT NULL DEFAULT 'system' COMMENT '创建人或系统标识',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '记录更新时间',
    PRIMARY KEY (whitelist_id),
    KEY idx_ti_whitelist_lookup (indicator_type, normalized_value, scope_type, scope_value, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='基础白名单表';

CREATE TABLE IF NOT EXISTS ti_manual_tag (
    tag_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
    indicator_type VARCHAR(32) NOT NULL COMMENT '对象类型，如 ip/cidr/domain/asn',
    indicator_value VARCHAR(255) NOT NULL COMMENT '对象值，兼容IPv4/IPv6/CIDR/域名',
    normalized_value VARCHAR(255) NOT NULL COMMENT '标准化后的对象值',
    tag_name VARCHAR(64) NOT NULL COMMENT '人工标签名称，如 repeat_offender、reflector、trusted_scanner',
    tag_value VARCHAR(255) NOT NULL DEFAULT '' COMMENT '标签取值，可为空',
    confidence_score DECIMAL(5,2) NOT NULL DEFAULT 80.00 COMMENT '标签可信度',
    reason VARCHAR(512) NOT NULL DEFAULT '' COMMENT '标签说明',
    analyst VARCHAR(128) NOT NULL DEFAULT 'system' COMMENT '操作人',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '记录更新时间',
    PRIMARY KEY (tag_id),
    KEY idx_ti_manual_tag_lookup (indicator_type, normalized_value, tag_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='人工标签表';

CREATE TABLE IF NOT EXISTS ti_disposition_rule (
    rule_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
    rule_name VARCHAR(128) NOT NULL COMMENT '规则名称',
    rule_scope VARCHAR(32) NOT NULL DEFAULT 'global' COMMENT '规则作用范围，global/mo/customer',
    rule_target VARCHAR(255) NOT NULL DEFAULT '' COMMENT '规则作用对象，如监测对象编码、客户编码',
    match_type VARCHAR(32) NOT NULL COMMENT '匹配类型，如 risk_score/indicator/tag/attack_type',
    match_expr VARCHAR(1024) NOT NULL COMMENT '匹配表达式，建议JSON格式',
    action VARCHAR(32) NOT NULL COMMENT '处置动作，如 observe/rate_limit/blackhole/scrubbing/upstream_coordination',
    priority INT NOT NULL DEFAULT 100 COMMENT '优先级，数字越小优先级越高',
    enabled TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否启用',
    remark VARCHAR(512) NOT NULL DEFAULT '' COMMENT '备注',
    created_by VARCHAR(128) NOT NULL DEFAULT 'system' COMMENT '创建人',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '记录更新时间',
    PRIMARY KEY (rule_id),
    KEY idx_ti_disposition_rule_scope (rule_scope, rule_target, enabled, priority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='处置策略规则表';

CREATE TABLE IF NOT EXISTS ti_feedback (
    feedback_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键ID',
    event_id VARCHAR(128) NOT NULL COMMENT '事件ID，对应分析结果事件标识',
    indicator_type VARCHAR(32) NOT NULL DEFAULT 'ip' COMMENT '对象类型，默认ip',
    indicator_value VARCHAR(255) NOT NULL COMMENT '对象值，兼容IPv4/IPv6',
    action VARCHAR(32) NOT NULL COMMENT '反馈动作，confirm/false_positive/ignore/whitelist/blacklist',
    analyst VARCHAR(128) NOT NULL DEFAULT 'system' COMMENT '操作分析员',
    reason VARCHAR(512) NOT NULL DEFAULT '' COMMENT '反馈原因',
    feedback_json JSON NULL COMMENT '附加反馈信息，JSON格式',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
    PRIMARY KEY (feedback_id),
    KEY idx_ti_feedback_lookup (event_id, indicator_type, indicator_value),
    KEY idx_ti_feedback_analyst (analyst, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='人工反馈与审核表';

INSERT INTO ti_source (source_name, source_type, reliability_weight, enabled, config_json)
VALUES
    ('local_analyzer', 'internal', 90.00, 1, JSON_OBJECT('description', '本地溯源分析结果回流')),
    ('abuseipdb', 'api', 70.00, 0, JSON_OBJECT('vendor', 'AbuseIPDB')),
    ('alienvault_otx', 'api', 65.00, 0, JSON_OBJECT('vendor', 'AlienVault OTX'))
ON DUPLICATE KEY UPDATE
    reliability_weight = VALUES(reliability_weight),
    enabled = VALUES(enabled),
    config_json = VALUES(config_json),
    updated_at = CURRENT_TIMESTAMP;
