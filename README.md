# DDoS 攻击溯源分析器

基于 NetFlow 数据的 DDoS 攻击溯源分析工具。从 ClickHouse 读取 NetFlow 原始数据，自动完成攻击源识别、行为特征分析、指纹聚类、路径溯源，生成结构化报告。

## 功能概述

1. **告警驱动分析** — 传入告警 ID，自动获取目标 IP、阈值、时间窗口，一键溯源
2. **异常源检测** — 5 因子加权评分（PPS/BPS/包大小/突发/行为），四级分类
3. **指纹聚类** — 识别僵尸网络团伙，三层算法降级（HDBSCAN → DBSCAN → KMeans）
4. **路径溯源** — 入口路由器、地理来源、监测对象、时间分布分析
5. **报告输出** — 文字报告 + CSV + 雷达图

## 目录结构

```
ddos_trace/
├── config.yaml                          # 配置文件（ClickHouse 连接、阈值等）
├── pyproject.toml                       # 项目元数据和依赖
├── docs/
│   ├── deploy.md                        # 部署与使用指南
│   ├── 需求.md                          # 需求规格说明书
│   ├── 攻击告警表结构.txt                # detect_attack_dist 表 DDL
│   └── Neflow原始数据结构.txt            # analytics_netflow_dist 表 DDL
├── dist/                                # 构建产物（wheel/tar.gz）
└── src/ddos_trace/
    ├── __init__.py                      # 包入口
    ├── __main__.py                      # CLI 入口（serve / alert / target / analyze）
    ├── analyzer.py                      # 主分析器 — 编排全流程
    ├── api.py                           # FastAPI 服务 — REST API 接口
    ├── config/
    │   └── models.py                    # 配置数据类 + YAML 加载
    ├── data/
    │   ├── loader.py                    # ClickHouse 数据加载 + 预处理
    │   └── alert_loader.py             # 告警记录加载 + AttackContext 构建
    ├── features/
    │   └── extraction.py               # 特征工程 — 聚合/衍生/时序/分类特征
    ├── detection/
    │   └── anomaly.py                  # 流量基线建模 + 异常源检测
    ├── clustering/
    │   └── fingerprint.py              # 攻击指纹聚类 — 三层算法降级
    ├── traceback/
    │   └── path.py                     # 攻击路径重构 — 路由/地理/监测对象/时间
    └── reports/
        └── generator.py                # 报告生成 — 文字报告/CSV/雷达图
```

## 各模块业务说明

### config/models.py — 配置管理

定义所有配置数据类，从 `config.yaml` 加载配置，支持环境变量覆盖。

| 配置类 | 职责 |
|-------|------|
| `ClickHouseConfig` | ClickHouse 连接参数（host/port/user/password/database） |
| `ThresholdConfig` | 检测阈值（PPS/BPS），作为找不到告警记录时的兜底值 |
| `TracebackConfig` | 溯源参数（聚类最小样本数、是否动态基线、分类阈值） |
| `AppConfig` | 总配置，聚合以上所有子配置 |

### data/loader.py — 数据加载

从 ClickHouse 的 `analytics_netflow_dist` 表查询 NetFlow 原始数据。

- `ClickHouseLoader`：构建 SQL 查询，按目标 IP + 监测对象 + 时间范围过滤
- `DataPreprocessor`：时间字段解析（毫秒 → datetime）、数值类型转换

### data/alert_loader.py — 告警加载

从 ClickHouse 的 `detect_attack_dist` 表读取告警记录，构建攻击上下文。

- `AlertLoader`：按 `attack_id` 或 `attack_target` 查询告警
- `AttackContext`：封装告警信息（目标 IP、时间窗口、阈值、攻击类型）
- 多条告警记录自动合并：取最早开始时间、最晚结束时间、最大阈值
- 阈值单位自动转换（Kbps/Mbps/Gbps/Kpps/Mpps → 统一为 bps/pps）

### features/extraction.py — 特征工程

按源 IP 聚合，提取多维特征供后续分析使用。

| 特征类别 | 包含字段 | 说明 |
|---------|---------|------|
| 包统计 | total/avg/std/max/min_packets | 基础流量统计 |
| 字节统计 | total/avg/std/max_bytes | 基础流量统计 |
| 流量速率 | packets_per_sec, bytes_per_sec | 每秒包数/字节数 |
| 包大小 | bytes_per_packet | 平均包大小（区分 SYN Flood 和带宽攻击） |
| 突发特征 | burst_ratio, burst_count, max_burst_size | 流量突发程度 |
| 时序特征 | flow_interval_mean/std/cv, active_ratio | 流量规律性 |
| 多样性 | dst_port_count, protocol_count, src_port_count | 攻击特征多样性 |
| 地理/ISP | country, province, city, isp | 来源地理信息 |
| 路径 | flow_ip_count, input_if_count | 入口路由器分布 |

### detection/anomaly.py — 异常检测

分两步：先建基线，再做异常检测。

**基线建模（TrafficBaseline）**：
1. 初步排除疑似攻击 IP（PPS/BPS 超过阈值）
2. 用剩余 IP 计算 6 个核心指标的统计量（mean/median/std/P95 等）
3. 有效阈值 = max(配置阈值, P95)

**异常检测（AnomalyDetector）** — 5 因子加权评分：

| 因子 | 权重 | 检测内容 |
|------|------|---------|
| PPS 超标 | 30% | z-score + 硬阈值判断 |
| BPS 超标 | 25% | z-score + 硬阈值判断 |
| 包大小异常 | 15% | 双侧 z-score（过小或过大） |
| 突发模式 | 15% | burst_ratio + burst_count + max_burst_size |
| 行为模式 | 15% | 单端口 + 单协议 + 规律性流量 |

**四级分类**：
- confirmed（≥80）：确认攻击源
- suspicious（60-80）：高度可疑
- borderline（40-60）：边缘案例
- background（<40）：背景流量

### clustering/fingerprint.py — 指纹聚类

将异常源按 9 维行为指纹分组，识别僵尸网络团伙。

- 特征维度：bytes_per_packet, packets_per_sec, bytes_per_sec, burst_ratio, burst_count, flow_interval_mean, flow_interval_cv, dst_port_count, protocol_count
- 标准化：RobustScaler（抗异常值）
- 三层算法降级：HDBSCAN → DBSCAN → MiniBatchKMeans
- 大数据保护：超过 10000 条自动采样训练 + 1-NN 回传
- 自动推断攻击类型：SYN Flood / UDP Flood / ICMP Flood / 大包洪泛 / 混合型

### traceback/path.py — 路径重构

分析攻击流量的路径特征。

| 分析维度 | 聚合键 | 输出 |
|---------|--------|------|
| 入口路由器 | flow_ip_addr + input_if_index | Top-5 入口节点 |
| 地理来源 | country/province/city/isp | Top-10 来源地 |
| 监测对象 | src_mo_code + src_mo_name | Top-10 来源 MO |
| 时间分布 | 按小时聚合 | 攻击时间线 |

### reports/generator.py — 报告生成

生成三种输出：

| 输出 | 文件 | 内容 |
|------|------|------|
| 文字报告 | 控制台输出 | 分析摘要 + Top-10 攻击源 + 聚类摘要 |
| CSV | traffic_classification_report.csv | 所有源 IP 的完整分类明细 |
| CSV | cluster_fingerprint_report.csv | 每个集群的指纹特征 |
| 图表 | cluster_radar_chart.png | 攻击集群多维行为雷达图 |

### analyzer.py — 主分析器

编排完整分析流程，提供三种入口：

| 入口 | 方法 | 阈值来源 |
|------|------|---------|
| 告警 ID | `run_analysis_by_alert(attack_id)` | 告警表自动获取 |
| 攻击目标 | `run_analysis_by_target(attack_target)` | 告警表，未找到用配置默认值 |
| 手动传参 | `run_full_analysis(target_ips, ...)` | 配置文件固定值 |

### api.py — REST API 服务

FastAPI 服务，暴露三个 POST 接口：

| 端点 | 说明 |
|------|------|
| `POST /api/v1/analyze/alert` | 传 attack_id，自动溯源 |
| `POST /api/v1/analyze/target` | 传 IP 或 MO 编码 |
| `POST /api/v1/analyze` | 手动传参（兼容旧接口） |

### __main__.py — 命令行入口

```bash
ddos-trace serve                    # 启动 API 服务
ddos-trace alert <attack_id>        # 基于告警 ID 分析
ddos-trace target <attack_target>   # 基于攻击目标分析
ddos-trace analyze --target-ips ... # 手动传参分析
```

## 技术栈

- **数据处理**：Pandas + NumPy（全向量化计算，无逐行 Python 循环）
- **机器学习**：scikit-learn（DBSCAN/MiniBatchKMeans/RobustScaler）
- **数据源**：ClickHouse（clickhouse-driver 原生协议）
- **API 框架**：FastAPI + uvicorn
- **可视化**：Matplotlib

## 快速开始

详见 [docs/deploy.md](docs/deploy.md)

```bash
# 安装
pip install -e .

# 编辑配置
vi config.yaml

# 启动 API
python -m ddos_trace serve

# 命令行分析
python -m ddos_trace alert ATK-20260401-001
```
