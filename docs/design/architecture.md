# DDoS 攻击溯源分析器 — 处理架构设计

## 系统总览流水线

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DDoS 攻击溯源分析器 总体架构                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐      │
│  │ Phase 0 │──▶│ Phase 1 │──▶│Phase 1.5│──▶│ Phase 2 │──▶│ Phase 3 │      │
│  │数据加载  │   │特征提取  │   │基线建模  │   │异常检测  │   │指纹聚类  │      │
│  └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘      │
│       │                                                    │               │
│       │              ┌─────────┐   ┌─────────┐            │               │
│       └─────────────▶│ Phase 4 │──▶│ Phase 5 │◀───────────┘               │
│                      │路径重构  │   │报告生成  │                            │
│                      └─────────┘   └─────────┘                            │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 0: 数据加载与预处理

### 数据来源

| 来源 | 用途 | 存储位置 |
|------|------|----------|
| ClickHouse `analytics_netflow_dist` | NetFlow 原始流量数据（五元组、字节数、包数、地理等） | ClickHouse 分布式表 |
| ClickHouse `detect_attack_dist` | 告警记录（attack_id、攻击类型、阈值、时间窗口） | ClickHouse 分布式表 |
| MySQL `system_base_attack_type` | 47 种攻击类型定义（协议、端口、TCP 标志匹配规则） | MySQL 配置库 |
| MySQL `system_base_threshold_*` | 阈值模板和明细（按监测对象 × 攻击类型 × IPv4/IPv6） | MySQL 配置库 |
| CSV `system_base_attack_type.csv` | 攻击类型降级数据源（MySQL 不可用时使用） | 本地文件 |

### 数据流

```
                    ┌──────────────────────────┐
                    │    3 种分析入口模式       │
                    ├──────────────────────────┤
                    │ 1. attack_id (推荐)       │──▶ ClickHouse 告警表获取上下文
                    │ 2. attack_target (目标IP) │──▶ ClickHouse 告警表匹配
                    │ 3. 手动传参 (兼容)        │──▶ 直接使用配置默认值
                    └──────────┬───────────────┘
                               │
                    ┌──────────▼───────────────┐
                    │   AlertContext 构建       │
                    │ - target_ips / mo_codes  │
                    │ - start_time / end_time  │
                    │ - attack_types[]          │
                    │ - threshold_pps / bps     │
                    │ - attack_maintype / level │
                    └──────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
    ┌─────────▼─────────┐ ┌───▼────────────┐ ┌─▼──────────────┐
    │ ClickHouse Loader │ │ ThresholdLoader│ │ 攻击类型定义    │
    │ NetFlow 查询      │ │ MySQL 阈值加载 │ │ MySQL→CSV降级   │
    │ 29 个字段         │ │ 进程缓存       │ │ 47 种类型       │
    └─────────┬─────────┘ └───┬────────────┘ └─┬──────────────┘
              │               │                │
              └───────────────┼────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │ DataPreprocessor   │
                    │ - ms→datetime 转换 │
                    │ - 数值类型修正     │
                    │ - flow_time 生成   │
                    └─────────┬──────────┘
                              │
                    raw_df (预处理后 DataFrame)
```

### 查询字段 (29列)

```
流量标识:  flow_ip_addr (采集路由器IP)
五元组:    src_ip_addr, dst_ip_addr, src_port, dst_port, protocol
流量指标:  octets (字节数), packets (包数), tcp_flags
接口索引:  input_if_index, output_if_index
时间戳:    first_time, last_time, parser_rcv_time (毫秒)
地理归属:  src/dst 的 country/province/city/isp
监测对象:  src/dst 的 mo_name/mo_code
AS编号:    src_as
```

---

## Phase 1: 特征工程 (FeatureExtractor)

### 处理逻辑

按 `src_ip_addr` 聚合，提取 30+ 维攻击指纹特征，全部使用向量化操作。

### 四大类特征

```
raw_df (NetFlow 记录)
  │
  ├─▶ [1] 基础聚合特征 (_aggregate_basic)
  │     groupby('src_ip_addr').agg(...)
  │     ├─ 包统计:  total_packets, avg_packets, std_packets, max_packets, min_packets
  │     ├─ 字节统计: total_bytes, avg_bytes, std_bytes, max_bytes
  │     ├─ 多样性:  dst_port_count, src_port_count, protocol_count,
  │     │           input_if_count, output_if_count, flow_ip_count
  │     └─ 时间:    flow_start_time, flow_end_time, flow_count, flow_duration
  │
  ├─▶ [2] 衍生特征 (_compute_derived)
  │     在聚合结果上二次计算
  │     ├─ bytes_per_packet  = total_bytes / total_packets    平均包大小
  │     ├─ packets_per_sec   = total_packets / flow_duration  包速率 PPS
  │     ├─ bytes_per_sec     = total_bytes / flow_duration    字节速率 BPS
  │     ├─ burst_ratio       = max_packets / avg_packets      突发比
  │     └─ bytes_std_ratio   = std_bytes / avg_bytes          字节变异性
  │
  ├─▶ [3] 时序特征 (_extract_temporal_features)
  │     基于 parser_rcv_time 时间序列
  │     ├─ flow_interval_mean  相邻流平均间隔 (ms→s)
  │     ├─ flow_interval_std   间隔标准差
  │     ├─ flow_interval_cv    变异系数 CV = std/mean
  │     ├─ burst_count         间隔<1s的突发次数
  │     ├─ max_burst_size      最大连续突发长度 (游程编码)
  │     └─ active_ratio        活跃比 = (流数-1) / 时间跨度
  │
  └─▶ [4] 分类特征众数 (_aggregate_categorical)
        取每个源IP的众数
        ├─ 地理位置: country, province, city, isp, as_number
        ├─ 监测对象: src_mo_name, src_mo_code, dst_mo_name, dst_mo_code
        ├─ dominant_protocol     主导协议
        ├─ dominant_dst_port     主导目的端口
        └─ dominant_tcp_flag     主导TCP标志
```

### 关键特征的业务含义

| 特征 | 含义 | 攻击信号 |
|------|------|----------|
| packets_per_sec | 每秒发包速率 | DDoS 源通常 PPS 极高 |
| bytes_per_packet | 平均包大小 | SYN Flood <100B, 放大攻击 >1400B |
| burst_ratio | 突发强度 | 正常 <3, 攻击 >5 |
| flow_interval_cv | 发送节奏稳定性 | 攻击工具 CV 接近 0 (高度规律) |
| dst_port_count | 目的端口多样性 | 单端口攻击 = 1, 扫描 >100 |
| protocol_count | 协议多样性 | 单协议攻击 = 1 |

---

## Phase 1.5: 基线建模 (TrafficBaseline)

### 分析方法

从所有源 IP 的特征中分离"疑似正常 IP"，计算正常流量统计基线。

### 攻击 IP 排除策略 (三级降级)

```
features (所有源IP)
  │
  ├─▶ [auto 模式] 逐级降级
  │     ├─ 1. 均值+σ过滤:  PPS/BPS > mean + 3σ → 排除
  │     │   └─ 排除0个IP时降级 ↓
  │     ├─ 2. 中位数+MAD:  PPS/BPS > median + σ×MAD → 排除
  │     │   └─ 仍排除0个时降级 ↓
  │     └─ 3. 百分位兜底:  排除 PPS/BPS Top 20% IP
  │
  └─▶ normal_df (疑似正常IP子集, ≥10个)
        │
        └─▶ 计算 6 个核心指标统计量:
            packets_per_sec, bytes_per_sec, bytes_per_packet,
            burst_ratio, flow_interval_mean, flow_interval_cv
            │
            └─▶ 各指标的: mean, median, std, p75, p90, p95, p99, max, min
```

### 阈值输出

```
effective_thresholds
  ├─ packets_per_sec     自适应单源阈值 = 正常P95 × 1.5
  ├─ bytes_per_sec       自适应单源阈值 = 正常P95 × 1.5
  ├─ alert_pps_threshold 告警聚合阈值 (来自 MySQL 或配置)
  └─ alert_bps_threshold 告警聚合阈值 (来自 MySQL 或配置)
```

---

## Phase 2: 异常检测 (AnomalyDetector) — 六因子评分模型

### 评分模型

```
每个源 IP 的综合置信度 = Σ (因子得分 × 权重)

┌──────────────────────────────────────────────────────────────┐
│                    六因子加权评分模型                         │
├──────────┬────────┬──────────────────────────────────────────┤
│  因子     │ 权重   │  计算方法                                │
├──────────┼────────┼──────────────────────────────────────────┤
│ f1 PPS   │  25%   │ max(z-score×10, 自适应阈值比例×50)       │
│ 偏离     │        │ z = (PPS - 正常均值) / 正常标准差        │
├──────────┼────────┼──────────────────────────────────────────┤
│ f2 BPS   │  20%   │ 同 f1, 独立维度                          │
│ 偏离     │        │ 某些攻击BPS高但PPS不高(DNS放大)           │
├──────────┼────────┼──────────────────────────────────────────┤
│ f3 包大小│  15%   │ 双侧 |z-score| × 15                      │
│ 异常     │        │ <100B=小包攻击, >1400B=大包攻击           │
├──────────┼────────┼──────────────────────────────────────────┤
│ f4 突发  │  15%   │ 0.4×突发比 + 0.3×突发次数 + 0.3×突发长度 │
│ 模式     │        │ burst_ratio>5 视为突发                    │
├──────────┼────────┼──────────────────────────────────────────┤
│ f5 行为  │  10%   │ (单端口? + 单协议? + 规律性?) / 3 × 100  │
│ 模式     │        │ CV<0.5 且 流数≥5 → 规律性                │
├──────────┼────────┼──────────────────────────────────────────┤
│ f6 攻击  │  15%   │ max(PPS占比, BPS占比) 分段映射            │
│ 贡献度   │        │ <1%=0分, 1-5%=0-40, 5-20%=40-70, ≥20%=70+│
└──────────┴────────┴──────────────────────────────────────────┘

                        │
                        ▼
              attack_confidence = 0.25×f1 + 0.20×f2 + 0.15×f3
                                + 0.15×f4 + 0.10×f5 + 0.15×f6
              (clip to [0, 100])
                        │
                        ▼
              ┌────────────────────┐
              │ 四级分类           │
              ├────────────────────┤
              │ ≥80  → confirmed   │  确认攻击源，建议立即处置
              │ ≥60  → suspicious  │  可疑源，需人工复核
              │ ≥40  → borderline  │  边界源，需关注
              │ <40  → background  │  正常背景流量
              └────────────────────┘
```

### 研判逻辑说明

- **f1/f2 (PPS/BPS偏离)**: 双重评分，取 max(z-score, 自适应阈值得分)。任一维度判为异常即给高分，避免单一维度漏判。
- **f3 (包大小)**: 双侧检测，因为攻击可能是极小包(SYN Flood ~40B)或极大包(DNS放大 ~1500B)。
- **f4 (突发模式)**: 三个子维度加权。burst_ratio 衡量"脉冲强度"，burst_count 衡量"脉冲频率"，max_burst_size 衡量"脉冲持续"。
- **f5 (行为模式)**: 自动化工具的三个典型特征。单一目的端口+单一协议+高度规律的发送节奏，满足越多越可疑。
- **f6 (攻击贡献度)**: 即使一个 IP 相对同侪偏离不大，但如果它独占告警阈值 20% 以上的流量，仍应标记为可疑。

---

## Phase 3: 攻击指纹聚类 (AttackFingerprintClusterer)

### 分析方法

对 confirmed + suspicious 的源 IP 进行聚类，识别同一僵尸网络团伙。

```
anomaly_sources (confirmed + suspicious)
  │
  ├─▶ 提取 9 维聚类特征 (TracebackConfig.cluster_features)
  │     packets_per_sec, bytes_per_sec, bytes_per_packet,
  │     burst_ratio, burst_count, flow_interval_mean,
  │     flow_interval_cv, dst_port_count, protocol_count
  │
  ├─▶ RobustScaler 标准化 (基于中位数+IQR, 对异常值鲁棒)
  │
  ├─▶ 大数据保护: 样本>10000时随机采样训练, 1-NN回传全量标签
  │
  └─▶ 三级算法降级:
        ├─ HDBSCAN (首选) — 基于密度的层次聚类，自动发现簇数
        │   └─ 失败 ↓
        ├─ DBSCAN (次选) — eps=0.5, ball_tree加速
        │   └─ 失败 ↓
        └─ MiniBatchKMeans (兜底) — K=动态计算(2~10)
            │
            ▼
      cluster_report (每个团伙的指纹摘要)
        ├─ cluster_id / member_count / member_ips
        ├─ avg_ 特征值 (团伙指纹)
        └─ attack_type 推断 (基于包大小+协议)
```

### 攻击类型推断规则

```
avg_bpp < 100B + protocol=TCP(6)  →  SYN Flood
avg_bpp < 100B                     →  小包洪泛
avg_bpp > 1400B                    →  大包洪泛
protocol = UDP(17)                 →  UDP Flood
protocol = ICMP(1)                 →  ICMP Flood
protocol = TCP(6)                  →  TCP Flood
其他                                →  混合型攻击
```

---

## Phase 4: 攻击路径重构 (AttackPathReconstructor)

### 四维度分析

```
raw_df + features (仅 confirmed/suspicious 源的原始流)
  │
  ├─▶ [1] 入口路由器分析 (_analyze_entry_routers)
  │     groupby(flow_ip_addr, input_if_index)
  │     └─ flow_count, unique_source_ips, total_packets, total_bytes
  │     └─ 按 flow_count DESC 取 Top-K
  │     用途: 定位攻击流量进入网络的物理入口，配置ACL/黑洞
  │
  ├─▶ [2] 地理来源分析 (_analyze_geo)
  │     groupby(src_country, src_province, src_city, src_isp)
  │     └─ unique_source_ips, total_packets, total_bytes
  │     └─ 按 total_packets DESC 取 Top-10
  │     用途: 揭示地理分布，判断跨国/区域集中攻击
  │
  ├─▶ [3] 监测对象关联 (_analyze_mo)
  │     groupby(src_mo_code, src_mo_name)
  │     └─ attacking_source_ips, total_packets, total_bytes
  │     └─ 按 total_packets DESC 取 Top-10
  │     用途: 关联运营商管理对象，跨部门协调处置
  │
  └─▶ [4] 时间分布分析 (_analyze_time) — 自适应粒度
        根据攻击持续时间自动选择聚合粒度:
        ├─ < 10 min  → floor('30s')   30秒粒度
        ├─ < 30 min  → floor('1min')  1分钟粒度
        ├─ < 2 hour  → floor('5min')  5分钟粒度
        ├─ < 12 hour → floor('15min') 15分钟粒度
        └─ ≥ 12 hour → floor('1h')    1小时粒度

        groupby(时间桶)
        └─ flow_count, unique_source_ips, total_packets, total_bytes
        用途: 展示攻击时间演变(开始/峰值/结束)，识别多波攻击
```

---

## Phase 5: 报告生成与导出 (ReportGenerator)

### 输出产物

```
┌──────────────────────────────────────────────────┐
│           output/{attack_id}_{target}/            │
├──────────────────────────────────────────────────┤
│                                                  │
│  文字报告:                                        │
│  ├─ analysis_report.md            结构化文本报告  │
│  ├─ overall_attack_situation.md   攻击态势说明    │
│                                                  │
│  数据导出:                                        │
│  ├─ traffic_classification_report.csv  源IP分类   │
│  ├─ cluster_fingerprint_report.csv     聚类指纹   │
│  ├─ attack_blacklist.csv               黑名单     │
│  ├─ attack_timeline.csv                时间线     │
│  ├─ suspicious_sources.csv             可疑源     │
│  ├─ attack_type_detail.csv             分项详情   │
│  ├─ entry_router_report.csv            入口路由   │
│  ├─ geo_distribution_report.csv        地理分布   │
│  ├─ mo_distribution_report.csv         监测对象   │
│  ├─ time_distribution_report.csv       时间分布   │
│  ├─ analysis_summary.json              摘要JSON   │
│                                                  │
│  可视化图表:                                      │
│  ├─ attack_overview.png             攻击总览 2×2  │
│  ├─ attack_timeline_chart.png       时序趋势      │
│  ├─ source_risk_dashboard.png       风险看板 2×2  │
│  ├─ attack_source_operator_dashboard.png  运营看板│
│  ├─ source_distribution_dashboard.png 来源分布   │
│  ├─ cluster_radar_chart.png         集群雷达图    │
│  ├─ top_attacker_radar_chart.png    攻击源雷达图  │
│  ├─ overall_profile_radar_chart.png 总体画像      │
│  ├─ suspect_source_radar_panels.png 疑似源多雷达  │
│  └─ attack_type_profile_*.png       分类型画像    │
│                                                  │
└──────────────────────────────────────────────────┘
```

---

## 按攻击类型分项分析模式 (per-type)

当通过告警 ID 入口分析时，系统按攻击类型分项运行完整流水线:

```
attack_context (含 attack_types[] 和 MySQL 阈值)
  │
  ├─▶ 攻击类型定义加载 (MySQL 优先, CSV 降级)
  │     ├─ 47 种攻击类型的匹配规则 (协议/端口/TCP标志)
  │     └─ 每种攻击类型 × IPv4/IPv6 的 PPS/BPS 阈值
  │
  └─▶ 对每种攻击类型并行执行:
        ├─ filter_flows_by_attack_type(raw_df, type_info)  按规则过滤flow子集
        ├─ Phase 1~4 完整流水线 (特征→基线→检测→聚类→路径)
        │   使用该类型的专用阈值
        └─ _build_per_type_summary()  统计摘要

              │
              ▼
        结果聚合 (_aggregate_per_type_results):
        ├─ features:   去重合并 (同一IP取最高风险视图)
        ├─ clusters:   直接拼接
        ├─ path:       各维度聚合 (geo/router/mo/time)
        └─ thresholds: 取各类型最大值
```

---

## API 服务层

```
FastAPI 服务 (api.py)
  │
  ├─ GET  /health                    健康检查
  ├─ GET  /reports                   报告列表页 (HTML)
  ├─ GET  /reports/{run_name}        报告详情页 (HTML, 内联展示)
  ├─ GET  /artifacts/{path}          静态文件 (图片/CSV)
  │
  ├─ POST /api/v1/analyze/alert      告警ID分析 (推荐)
  │     req: { attack_id }
  │     resp: AnalysisResponse
  │
  ├─ POST /api/v1/analyze/target     目标分析
  │     req: { attack_target, start_time?, end_time? }
  │     resp: AnalysisResponse
  │
  └─ POST /api/v1/analyze            手动传参 (兼容)
        req: { target_ips, target_mo_codes, start_time, end_time }
        resp: AnalysisResponse
```
