---
title: 研究发现
description: 用于记录研究和发现的详细信息
created: 2026-04-14
---

## 总体开发计划

### 开发阶段概览

**项目名称**：DDoS 攻击溯源分析器  
**开发周期**：预计 8-10 周  
**团队规模**：1-2 名开发人员 + 1 名安全专家  

### 详细开发计划

#### 📋 **Phase 1: 基础框架搭建**（2周）
**目标**：建立开发环境和基础架构

**Week 1-1：环境准备**
- [ ] 搭建 Python 开发环境
  - 安装 Python 3.8+
  - 安装 IDE（VS Code/PyCharm）
  - 配置 Git 仓库
- [ ] 安装核心依赖库
  ```bash
  pip install pandas numpy matplotlib scikit-learn
  pip install clickhouse-driver sqlalchemy
  pip install jupyterlab  # 用于数据探索
  ```
- [ ] 配置 ClickHouse 开发环境
  - 申请测试环境权限
  - 配置连接参数
  - 准备测试数据

**Week 1-2：基础架构设计**
- [ ] 设计项目目录结构
  ```
  ddos_trace/
  ├── src/
  │   ├── __init__.py
  │   ├── config/
  │   │   ├── __init__.py
  │   │   ├── clickhouse.py
  │   │   └── thresholds.py
  │   ├── data/
  │   │   ├── __init__.py
  │   │   ├── loader.py
  │   │   └── processor.py
  │   ├── features/
  │   │   ├── __init__.py
  │   │   ├── extraction.py
  │   │   └── temporal.py
  │   ├── detection/
  │   │   ├── __init__.py
  │   │   ├── baseline.py
  │   │   └── anomaly.py
  │   ├── clustering/
  │   │   ├── __init__.py
  │   │   ├── algorithms.py
  │   │   └── fingerprint.py
  │   ├── traceback/
  │   │   ├── __init__.py
  │   │   ├── router.py
  │   │   └── geography.py
  │   ├── reports/
  │   │   ├── __init__.py
  │   │   ├── generator.py
  │   │   └── visualization.py
  │   └── utils/
  │       ├── __init__.py
  │       ├── logger.py
  │       └── validator.py
  ├── tests/
  ├── data/
  ├── docs/
  └── examples/
  ```
- [ ] 编写配置文件
  - ClickHouse 连接配置
  - 阈值参数配置
  - 日志配置
- [ ] 实现基础工具类
  - 日志记录器
  - 数据验证器
  - 错误处理器

#### 📋 **Phase 2: 数据加载模块**（1.5周）
**目标**：实现从 ClickHouse 加载数据的功能

**Week 2-1：数据连接实现**
- [ ] 实现 ClickHouse 连接池
  ```python
  # config/clickhouse.py
  class ClickHouseConfig:
      def __init__(self):
          self.host = "localhost"
          self.port = 9000
          self.database = "analytics"
          self.username = "default"
          self.password = ""
          self.timeout = 30
  ```
- [ ] 实现数据查询接口
  ```python
  # data/loader.py
  class ClickHouseLoader:
      def query_netflow_data(self, target_ips, target_mo_codes, start_time, end_time):
          """实现核心查询逻辑"""
  ```
- [ ] 实现分批查询机制
  - 大数据量分页处理
  - 内存使用优化

**Week 2-2：数据预处理**
- [ ] 实现数据清洗
  - 缺失值处理
  - 异常值检测
  - 数据类型转换
- [ ] 实现时间解析
  - parser_rcv_time 转换
  - 时间范围验证
- [ ] 实现数据过滤
  - dst_ip + dst_mo_code 过滤
  - 入向流量筛选

#### 📋 **Phase 3: 特征工程模块**（2周）
**目标**：实现多维特征提取

**Week 3-1：基础特征**
- [ ] 实现包统计特征
  - total_packets, avg_packets, std_packets
  - max_packets, min_packets
- [ ] 实现字节统计特征
  - total_bytes, avg_bytes, std_bytes
  - max_bytes, min_bytes
- [ ] 实现多样性特征
  - dst_port_count, src_port_count
  - protocol_count

**Week 3-2：高级特征**
- [ ] 实现地理特征聚合
  - country, province, city, isp
  - AS 编码聚合
- [ ] 实现监测对象特征
  - src_mo_code/dst_mo_code 统计
- [ ] 实现衍生特征
  - bytes_per_packet
  - packets_per_sec, bytes_per_sec
  - burst_ratio, bytes_std_ratio
- [ ] 实现路径特征
  - flow_ip_count, input_if_count
  - output_if_count

**Week 3-3：时序特征**
- [ ] 实现时序特征提取
  - flow_interval_mean, std, cv
  - burst_count, max_burst_size
  - active_ratio
- [ ] 实现向量化计算
  - 无逐行循环的高效实现

#### 📋 **Phase 4: 基线建模与异常检测**（1.5周）
**目标**：建立正常流量基线，识别异常

**Week 4-1：基线建模**
- [ ] 实现动态基线计算
  - 正常 IP 初步筛选
  - 6 个核心指标统计量
  - P95 动态阈值
- [ ] 实现基线缓存机制
  - 避免重复计算
  - 定期更新机制

**Week 4-2：异常检测**
- [ ] 实现多因子评分模型
  - PPS/BPS 包大小异常
  - 突发模式检测
  - 行为模式分析
- [ ] 实现加权总分计算
  - 100 分制评分
  - 置信度生成
- [ ] 实现分层分类
  - confirmed/suspicious/borderline/background

#### 📋 **Phase 5: 聚类分析**（1.5周）
**目标**：识别僵尸网络团伙

**Week 5-1：聚类准备**
- [ ] 实现 9 维特征提取
  - bytes_per_packet, packets_per_sec
  - burst_ratio, flow_interval_cv 等
- [ ] 实现 RobustScaler 标准化
- [ ] 实现数据降采样策略

**Week 5-2：聚类算法**
- [ ] 实现三级算法降级
  - HDBSCAN（首选）
  - DBSCAN（次选）
  - MiniBatchKMeans（兜底）
- [ ] 实现攻击类型推断
  - SYN Flood, UDP Flood 等
  - 规则引擎实现

#### 📋 **Phase 6: 路径重构**（1周）
**目标**：追踪攻击路径

**Week 6-1：入口分析**
- [ ] 实现路由器分析
  - flow_ip_addr + input_if_index 聚合
  - Top-K 入口节点
- [ ] 实现地理溯源
  - 国家/省份/城市分布
  - ISP 分析

**Week 6-2：高级分析**
- [ ] 实现监测对象关联
  - src_mo_code 关联分析
  - 业务系统分布
- [ ] 实现时间分布
  - 攻击高峰识别
  - 持续时间分析

#### 📋 **Phase 7: 报告生成**（1周）
**目标**：生成可视化报告

**Week 7-1：报告导出**
- [ ] 实现文字报告
  - 分析摘要
  - 攻击源详情
  - 背景流量特征
- [ ] 实现 CSV 导出
  - traffic_classification_report.csv
  - cluster_fingerprint_report.csv

**Week 7-2：可视化**
- [ ] 实现雷达图
  - 集群指纹可视化
  - 对数归一化处理
- [ ] 实现其他图表
  - 地理分布图
  - 时间分布图

#### 📋 **Phase 8: 测试与优化**（1周）
**目标**：确保系统稳定可靠

**Week 8-1：单元测试**
- [ ] 数据加载测试
- [ ] 特征提取测试
- [ ] 异常检测测试
- [ ] 聚类算法测试

**Week 8-2：性能测试**
- [ ] 大数据处理性能
- [ ] ClickHouse 查询优化
- [ ] 内存使用优化
- [ ] 算法准确性验证

## 技术调研（更新）

### ClickHouse 最佳实践

1. **连接管理**
   - 使用连接池避免频繁创建连接
   - 设置合理的超时时间
   - 实现重试机制

2. **查询优化**
   - 使用合适的分区键
   - 限制查询数据量
   - 使用合适的索引

3. **数据类型映射**
   ```python
   # ClickHouse to Python 类型映射
   ClickHouse UInt64 -> Python int
   ClickHouse String -> Python str
   ClickHouse DateTime -> Python datetime
   ClickHouse UInt8 -> Python int
   ```

### 向量化计算优化

1. **Pandas 优化技巧**
   - 使用 groupby 替代循环
   - 使用 vectorized 操作
   - 避免 apply 使用

2. **内存管理**
   - 分块处理大数据
   - 及时删除临时变量
   - 使用合适的数据类型

### 机器学习调优

1. **聚类算法选择**
   - HDBSCAN：适合密度聚类
   - DBSCAN：适合噪声数据
   - MiniBatchKMeans：适合大数据

2. **特征标准化**
   - RobustScaler：抗异常值
   - StandardScaler：标准正态分布

### 性能基准

| 模块 | 预期处理时间 | 内存使用 | 数据量 |
|------|-------------|---------|-------|
| 数据加载 | < 1分钟 | 1GB | 1M 记录 |
| 特征提取 | < 2分钟 | 2GB | 1M 记录 |
| 异常检测 | < 1分钟 | 500MB | 100K IP |
| 聚类分析 | < 3分钟 | 1GB | 10K IP |
| 路径重构 | < 30秒 | 200MB | 100K IP |
| 报告生成 | < 1分钟 | 100MB | - |