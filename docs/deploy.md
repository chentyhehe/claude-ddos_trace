# DDoS 攻击溯源分析器 — 部署与使用指南

---

## 一、Windows 开发环境调试

### 1. 环境准备

**前置要求**：Python 3.8+（推荐 3.11），pip 最新版。

项目使用 `pyproject.toml` 管理依赖和构建，不使用 `setup.py`。

```powershell
# 进入项目目录
cd f:\PyProjects\claude-ddos_trace

# （推荐）创建虚拟环境，隔离依赖，避免污染全局 Python
python -m venv venv
.\venv\Scripts\Activate.ps1

# 以开发模式安装项目（-e 表示 editable，代码改动立即生效，无需重新安装）
pip install -e .
```

`pip install -e .` 做了什么：
- 读取 `pyproject.toml` 中声明的依赖（pandas, numpy, fastapi, clickhouse-driver, pymysql 等）
- 安装所有依赖到当前虚拟环境
- 以符号链接方式安装项目本身，代码修改后无需重新安装

**可选依赖**（HDBSCAN 高级聚类算法）：

```powershell
pip install -e ".[hdbscan]"
```

**验证安装**：

```powershell
python -c "from ddos_trace.analyzer import DDoSTracebackAnalyzer; print('模块导入正常')"
```

### 2. 统一 __pycache__ 目录

Python 默认在每个源码目录下生成 `__pycache__/` 存放编译后的 `.pyc` 文件。
通过设置环境变量 `PYTHONPYCACHEPREFIX`，可以将所有编译缓存集中到项目根目录下的 `.pyccache/`。

**PowerShell（临时生效）**：

```powershell
$env:PYTHONPYCACHEPREFIX = "f:\PyProjects\claude-ddos_trace\.pyccache"
python -m ddos_trace serve  # 此时会话内所有 .pyc 都写入 .pyccache/
```

**CMD（临时生效）**：

```cmd
set PYTHONPYCACHEPREFIX=f:\PyProjects\claude-ddos_trace\.pyccache
python -m ddos_trace serve
```

**永久生效**（系统环境变量）：

```
设置 → 系统 → 高级系统设置 → 环境变量 → 用户变量 → 新建
  变量名：PYTHONPYCACHEPREFIX
  变量值：f:\PyProjects\claude-ddos_trace\.pyccache
```

`.pyccache/` 已在 `.gitignore` 中，不会被提交到版本库。

### 3. 配置文件

项目根目录 `config.yaml` 是唯一的配置文件。

```yaml
# ClickHouse — NetFlow 原始数据 + 告警数据
# 注意端口：clickhouse-driver 使用原生协议(9000)，不是 HTTP(8123)
clickhouse:
  host: "192.168.131.212"
  port: 9000
  username: "default"
  password: "your_password"
  database: "uniflow_controller_clickhouse_develop"
  table_name: "analytics_netflow_dist"       # NetFlow 流量表
  alert_table_name: "detect_attack_dist"     # 告警表

# MySQL — 攻击类型定义 + 多类型阈值配置
# 包含 4 张表：attack_type(47种攻击类型)、monitor_object(监测对象)、
#             threshold_summary(阈值模板)、threshold_item(阈值明细)
mysql:
  host: "192.168.130.4"
  port: 3306
  username: "root"
  password: "your_password"
  database: "uniflow_controller_mysql_cmcc"

# 攻击类型定义 CSV 降级文件
# MySQL 不可用时自动从该文件加载 47 种攻击类型的匹配规则
attack_type_csv_path: "docs/source/system_base_attack_type.csv"

# 硬阈值（兜底默认值，MySQL 阈值优先）
threshold:
  pps_threshold: 500000       # 每秒包数
  bps_threshold: 20000000     # 每秒字节数（约 20MB/s）

# 溯源分析参数
traceback:
  min_cluster_size: 5         # 聚类最小样本数
  use_dynamic_baseline: true  # 使用动态基线（P95 × 1.5）

# API 服务
api:
  host: "0.0.0.0"
  port: 8000

# 报告输出目录
output:
  dir: "./output"
```

**环境变量覆盖**（优先级高于 config.yaml）：

| 环境变量 | 说明 | 示例 |
|---------|------|------|
| `DDOS_CH_HOST` | ClickHouse 地址 | `10.0.0.100` |
| `DDOS_CH_PORT` | ClickHouse 端口 | `9000` |
| `DDOS_CH_USER` | ClickHouse 用户名 | `default` |
| `DDOS_CH_PASSWORD` | ClickHouse 密码 | `mypassword` |
| `DDOS_CH_DATABASE` | ClickHouse 数据库名 | `my_db` |
| `DDOS_CH_TABLE` | NetFlow 表名 | `analytics_netflow_dist` |
| `DDOS_CH_ALERT_TABLE` | 告警表名 | `detect_attack_dist` |
| `DDOS_CH_TIMEOUT` | 连接超时（秒） | `30` |
| `DDOS_MYSQL_HOST` | MySQL 地址 | `10.0.0.200` |
| `DDOS_MYSQL_PORT` | MySQL 端口 | `3306` |
| `DDOS_MYSQL_USER` | MySQL 用户名 | `root` |
| `DDOS_MYSQL_PASSWORD` | MySQL 密码 | `mypassword` |
| `DDOS_MYSQL_DATABASE` | MySQL 数据库名 | `my_db` |
| `DDOS_API_HOST` | API 监听地址 | `0.0.0.0` |
| `DDOS_API_PORT` | API 监听端口 | `8000` |

**验证配置加载**：

```powershell
python -c "from ddos_trace.config.models import load_config; c = load_config(); print(f'CH: {c.clickhouse.host}:{c.clickhouse.port}/{c.clickhouse.database}'); print(f'MySQL: {c.mysql.host}:{c.mysql.port}/{c.mysql.database}')"
```

### 4. 启动 API 服务

```powershell
cd f:\PyProjects\claude-ddos_trace

# 方式一：通过 python -m（推荐，无需 PATH 配置）
python -m ddos_trace serve

# 方式二：指定端口
python -m ddos_trace serve --port 8000

# 方式三：指定配置文件路径
python -m ddos_trace serve --config f:\PyProjects\claude-ddos_trace\config.yaml --port 8000

# 方式四：如果已 pip install -e .，可直接使用命令行工具
ddos-trace serve
```

启动成功后会输出：

```
启动 DDoS 攻击溯源分析器 API 服务: http://0.0.0.0:8000
API 文档: http://0.0.0.0:8000/docs
ClickHouse: 192.168.131.212:9000/uniflow_controller_clickhouse_develop
MySQL: 192.168.130.4:3306/uniflow_controller_mysql_cmcc
```

此时可以访问：
- **Swagger 交互式文档**：`http://localhost:8000/docs` — 可直接在浏览器中测试 API
- **健康检查**：`http://localhost:8000/health`

### 5. 命令行单次分析

不启动服务，直接在命令行触发一次分析，报告打印到终端，CSV 文件写入 `./output/` 目录。

```powershell
# 基于告警 ID（推荐 — 自动获取目标、阈值、时间窗口、攻击类型）
python -m ddos_trace alert ATK-20260401-001

# 基于攻击目标（自动从告警表匹配，可选指定时间）
python -m ddos_trace target 192.168.1.100 --start-time "2026-04-01 00:00:00" --end-time "2026-04-01 23:59:59"

# 手动传参（需完整指定所有参数，使用配置文件默认阈值）
python -m ddos_trace analyze --target-ips 192.168.1.100 --target-mo-codes MO001 --start-time "2026-04-01 00:00:00" --end-time "2026-04-01 23:59:59"

# 指定输出目录
python -m ddos_trace alert ATK-20260401-001 --output-dir ./my_output
```

### 6. Python 交互式调试

在 Python REPL 或 Jupyter Notebook 中直接调用，适合调试和探索性分析。

```python
from ddos_trace.config.models import load_config
from ddos_trace.analyzer import DDoSTracebackAnalyzer
from datetime import datetime

# 加载配置
config = load_config("config.yaml")

# 创建分析器
analyzer = DDoSTracebackAnalyzer(
    threshold_config=config.threshold,
    traceback_config=config.traceback,
    clickhouse_config=config.clickhouse,
    mysql_config=config.mysql,
    output_dir="./output",
    csv_path=config.attack_type_csv_path,
)

# ---- 基于告警 ID 分析 ----
result = analyzer.run_analysis_by_alert("ATK-20260401-001")

# 查看攻击上下文（告警表自动填充）
print(result["attack_context"].attack_types)  # 如 ['syn', 'udp']
print(result["attack_context"].target_ips)    # 如 ['192.168.1.100']

# 查看分项分析结果
for at_name, type_result in result["per_type_results"].items():
    summary = type_result["summary"]
    print(f"{at_name}: confirmed={summary['confirmed_count']}, pps={summary['total_pps']}")

# 查看聚合总览
print(result["overview"])

# 打印完整报告
print(result["report"])

# ---- 基于攻击目标分析 ----
result = analyzer.run_analysis_by_target(
    attack_target="192.168.1.100",
    start_time=datetime(2026, 4, 1, 0, 0, 0),
    end_time=datetime(2026, 4, 1, 23, 59, 59),
)
```

### 7. 构建 Wheel 包

```powershell
pip install build
python -m build
```

产物在 `dist/` 目录：
- `dist/ddos_trace-1.0.0-py3-none-any.whl` — 可直接 pip install 的 Wheel 包
- `dist/ddos_trace-1.0.0.tar.gz` — 源码分发包

---

## 二、Linux 生产环境部署

### 1. 在开发机上构建

```powershell
cd f:\PyProjects\claude-ddos_trace
python -m build
```

构建完成后 `dist/` 目录包含 Wheel 包。

### 2. 传输到服务器

将 Wheel 包和配置文件上传到服务器：

```bash
# 在本地执行
scp dist/ddos_trace-1.0.0-py3-none-any.whl user@server:/opt/ddos-trace/
scp config.yaml user@server:/opt/ddos-trace/
scp docs/source/system_base_attack_type.csv user@server:/opt/ddos-trace/docs/source/
```

`config.yaml` 和 CSV 文件需要单独传输，它们不包含在 Wheel 包内。

### 3. 服务器端安装

```bash
ssh user@server
cd /opt/ddos-trace

# 创建虚拟环境（隔离依赖，避免与系统 Python 冲突）
python3 -m venv venv
source venv/bin/activate

# 安装 Wheel 包（自动安装所有依赖）
pip install ddos_trace-1.0.0-py3-none-any.whl

# 验证安装
python -c "from ddos_trace.analyzer import DDoSTracebackAnalyzer; print('OK')"
ddos-trace --help
```

### 4. 修改生产配置

```bash
vi /opt/ddos-trace/config.yaml
```

将 ClickHouse 和 MySQL 地址改为生产环境地址。

也可以通过环境变量覆盖（不改文件），适合容器化部署：

```bash
# 在 ~/.bashrc 或 systemd Service 中设置
export DDOS_CH_HOST="10.0.0.100"
export DDOS_CH_PASSWORD="prod_password"
export DDOS_MYSQL_HOST="10.0.0.200"
export DDOS_MYSQL_PASSWORD="prod_mysql_password"
```

### 5. 手动启动验证

```bash
cd /opt/ddos-trace
source venv/bin/activate

# 设置统一 pycache 目录（可选，保持源码目录整洁）
export PYTHONPYCACHEPREFIX=/opt/ddos-trace/.pyccache

# 前台启动（观察日志输出）
ddos-trace serve --config config.yaml --host 0.0.0.0 --port 8000
```

另开终端验证：

```bash
# 健康检查
curl http://localhost:8000/health
# 返回: {"status":"ok","service":"ddos-trace"}

# 测试告警分析接口
curl -X POST http://localhost:8000/api/v1/analyze/alert \
  -H "Content-Type: application/json" \
  -d '{"attack_id": "ATK-20260401-001"}'
```

### 6. 注册为 systemd 服务（开机自启）

systemd 是 Linux 标准的服务管理器，负责自动启动、崩溃重启、日志管理。

```bash
sudo vi /etc/systemd/system/ddos-trace.service
```

写入以下内容：

```ini
[Unit]
Description=DDoS Trace API Service
After=network.target

[Service]
Type=simple
User=ddos
WorkingDirectory=/opt/ddos-trace
ExecStart=/opt/ddos-trace/venv/bin/ddos-trace serve --config /opt/ddos-trace/config.yaml --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5

# 统一 pycache 目录
Environment=PYTHONPYCACHEPREFIX=/opt/ddos-trace/.pyccache

# 可选：通过环境变量覆盖配置（优先于 config.yaml）
# Environment=DDOS_CH_HOST=10.0.0.100
# Environment=DDOS_CH_PASSWORD=prod_password

[Install]
WantedBy=multi-user.target
```

各字段说明：
- `After=network.target` — 等网络就绪后再启动
- `Type=simple` — 前台进程模式（uvicorn 不 fork）
- `Restart=on-failure` — 进程异常退出时自动重启
- `RestartSec=5` — 重启间隔 5 秒

启动和管理：

```bash
# 重新加载 systemd 配置（修改 .service 文件后必须执行）
sudo systemctl daemon-reload

# 设置开机自启
sudo systemctl enable ddos-trace

# 启动服务
sudo systemctl start ddos-trace

# 查看运行状态
sudo systemctl status ddos-trace

# 查看实时日志
sudo journalctl -u ddos-trace -f

# 停止服务
sudo systemctl stop ddos-trace

# 重启服务
sudo systemctl restart ddos-trace
```

### 7. Nginx 反向代理（生产推荐）

直接暴露 uvicorn 到外网不推荐。用 Nginx 做反向代理，可以提供：
- HTTPS 加密（TLS 证书）
- 请求限速（防止单个客户端滥用）
- 访问日志
- 静态文件服务

```bash
sudo apt install nginx
sudo vi /etc/nginx/sites-available/ddos-trace
```

写入：

```nginx
server {
    listen 80;
    server_name ddos-trace.example.com;

    # 反向代理到 uvicorn
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # 分析可能耗时较长，设置超时为 5 分钟
        proxy_read_timeout 300s;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/ddos-trace /etc/nginx/sites-enabled/
sudo nginx -t          # 检查配置语法
sudo systemctl reload nginx
```

配置完成后，外部通过 `http://ddos-trace.example.com` 访问。

### 8. Docker 部署（可选）

**Dockerfile**：

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# 安装 Wheel 包
COPY dist/ddos_trace-1.0.0-py3-none-any.whl .
RUN pip install --no-cache-dir ddos_trace-1.0.0-py3-none-any.whl

# 复制配置文件和 CSV 降级数据
COPY config.yaml .
COPY docs/source/system_base_attack_type.csv docs/source/

# 创建输出目录
RUN mkdir -p /app/output

EXPOSE 8000

CMD ["ddos-trace", "serve", "--config", "/app/config.yaml", "--host", "0.0.0.0", "--port", "8000"]
```

**构建和运行**：

```bash
# 构建镜像
docker build -t ddos-trace:1.0.0 .

# 运行容器
docker run -d \
  --name ddos-trace \
  -p 8000:8000 \
  -v /opt/ddos-trace/config.yaml:/app/config.yaml \
  -v /opt/ddos-trace/output:/app/output \
  ddos-trace:1.0.0

# 查看日志
docker logs -f ddos-trace

# 停止
docker stop ddos-trace
```

参数说明：
- `-d` — 后台运行
- `-p 8000:8000` — 将容器 8000 端口映射到宿主机 8000 端口
- `-v .../config.yaml:/app/config.yaml` — 挂载配置文件（可在线修改，无需重建镜像）
- `-v .../output:/app/output` — 挂载输出目录（分析报告持久化到宿主机）

---

## 三、外部 HTTP API 调用

### 接口总览

| 方法 | 路径 | 必传参数 | 阈值来源 | 适用场景 |
|------|------|---------|---------|---------|
| POST | `/api/v1/analyze/alert` | `attack_id` | MySQL 按攻击类型加载，CSV 降级 | **告警触发后自动溯源（推荐）** |
| POST | `/api/v1/analyze/target` | `attack_target` | MySQL 加载，未找到用配置默认值 | 按 IP 或监测对象分析 |
| POST | `/api/v1/analyze` | `target_ips` + `target_mo_codes` + 时间 | 配置文件固定值 | 灵活自定义分析 |
| GET  | `/health` | 无 | — | 服务存活检查 |

### 接口 1：基于告警 ID（推荐）

只需传一个 `attack_id`，系统自动从 ClickHouse 告警表获取目标 IP、时间窗口、攻击类型，然后：
1. 从 MySQL 加载该监测对象的攻击类型定义和每种攻击类型的 PPS/BPS 阈值
2. MySQL 不可用时自动从 CSV 文件降级加载攻击类型定义
3. 对每种攻击类型分别运行：Flow 分类 → 特征提取 → 基线建模 → 异常检测 → 聚类 → 路径重构
4. 聚合所有类型的分析结果，生成总览报告

**请求**：

```json
POST /api/v1/analyze/alert
Content-Type: application/json

{
  "attack_id": "ATK-20260401-001"
}
```

`attack_id` 是告警系统生成的唯一标识，存在于 ClickHouse 的 `detect_attack_dist` 表中。

### 接口 2：基于攻击目标

传入攻击目标（IP 地址或监测对象编码），系统自动从告警表匹配对应的告警记录。
如果匹配到告警，则使用告警中的时间窗口和阈值；否则使用配置文件默认值。

**请求**：

```json
POST /api/v1/analyze/target
Content-Type: application/json

{
  "attack_target": "192.168.1.100"
}
```

可选指定时间范围（不传则使用告警记录中的时间窗口）：

```json
{
  "attack_target": "192.168.1.100",
  "start_time": "2026-04-01 00:00:00",
  "end_time": "2026-04-01 23:59:59"
}
```

### 接口 3：手动传参

需要完整指定目标 IP 列表、监测对象编码列表和时间范围。
使用配置文件中的固定阈值，不查询告警表和 MySQL。

```json
POST /api/v1/analyze
Content-Type: application/json

{
  "target_ips": ["192.168.1.100", "10.0.0.50"],
  "target_mo_codes": ["MO001", "MO002"],
  "start_time": "2026-04-01 00:00:00",
  "end_time": "2026-04-01 23:59:59"
}
```

### 响应格式

所有接口返回统一的 `AnalysisResponse` 结构：

```json
{
  "task_id": "a1b2c3d4e5f6",
  "status": "completed",
  "alert_context": {
    "attack_id": "ATK-20260401-001",
    "attack_target": "192.168.1.100",
    "attack_target_type": "ipv4",
    "target_ips": ["192.168.1.100"],
    "target_mo_codes": ["MO001"],
    "start_time": "2026-04-01T10:00:00",
    "end_time": "2026-04-01T12:00:00",
    "attack_types": ["syn", "udp"],
    "level": "HIGH",
    "max_pps": 5000000.0,
    "max_bps": 200000000.0,
    "threshold_pps": 500000.0,
    "threshold_bps": 20000000.0
  },
  "summary": {
    "total_source_ips": 1523,
    "confirmed": 45,
    "suspicious": 128,
    "borderline": 350,
    "background": 1000,
    "anomaly_total": 173
  },
  "anomaly_sources": [
    {
      "src_ip": "203.0.113.1",
      "attack_confidence": 92.5,
      "traffic_class": "confirmed",
      "confidence_reasons": "PPS相对偏离(得分85); 攻击贡献度高(得分78)",
      "packets_per_sec": 850000.0,
      "bytes_per_sec": 45000000.0,
      "country": "US",
      "province": "California",
      "isp": "Example ISP"
    }
  ],
  "clusters": [
    {
      "cluster_id": 0,
      "member_count": 32,
      "member_ips": "203.0.113.1,198.51.100.5,...",
      "attack_type": "SYN Flood"
    }
  ],
  "geo_distribution": [
    {
      "src_country": "US",
      "src_province": "California",
      "src_isp": "Example ISP",
      "unique_source_ips": 15,
      "total_packets": 5000000,
      "total_bytes": 200000000
    }
  ],
  "entry_routers": [
    {
      "flow_ip_addr": "10.0.0.1",
      "input_if_index": 3,
      "flow_count": 15000,
      "unique_source_ips": 200,
      "total_packets": 8000000,
      "total_bytes": 400000000
    }
  ],
  "per_type_summary": {
    "syn": {
      "flow_count": 50000,
      "flow_pct": 45.2,
      "total_pps": 1500000,
      "total_bps": 75000000,
      "confirmed_count": 25,
      "suspicious_count": 60,
      "threshold_pps": 50000,
      "threshold_bps": 5000000,
      "exceeds_pps_threshold": true,
      "exceeds_bps_threshold": true,
      "top_attackers": [
        {"ip": "203.0.113.1", "pps": 500000, "score": 92.5}
      ]
    }
  },
  "report": "=== DDoS 攻击溯源分析报告 === ..."
}
```

**字段说明**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `task_id` | string | 本次分析的唯一标识（12位随机hex） |
| `status` | string | `completed` 或 `failed` |
| `alert_context` | object | 告警上下文（接口 1/2 有值，接口 3 为 null） |
| `summary` | object | 分类统计：各等级的源 IP 数量 |
| `anomaly_sources` | array | 置信度 >= 60 的异常源 IP 列表 |
| `clusters` | array | 攻击指纹聚类结果（异常源不足时为空数组） |
| `geo_distribution` | array | 攻击源地理分布统计 |
| `entry_routers` | array | 入口路由器统计 |
| `per_type_summary` | object | 各攻击类型的分析摘要（per-type 模式下有值） |
| `report` | string | 完整的文字分析报告 |

### 调用示例

**curl**（Linux / Windows Git Bash）：

```bash
# 健康检查
curl http://localhost:8000/health

# 基于告警 ID 分析
curl -X POST http://localhost:8000/api/v1/analyze/alert \
  -H "Content-Type: application/json" \
  -d '{"attack_id": "ATK-20260401-001"}'

# 基于攻击目标分析
curl -X POST http://localhost:8000/api/v1/analyze/target \
  -H "Content-Type: application/json" \
  -d '{"attack_target": "192.168.1.100"}'

# 基于攻击目标 + 指定时间
curl -X POST http://localhost:8000/api/v1/analyze/target \
  -H "Content-Type: application/json" \
  -d '{"attack_target": "192.168.1.100", "start_time": "2026-04-01 00:00:00", "end_time": "2026-04-01 23:59:59"}'

# 手动传参分析
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "target_ips": ["192.168.1.100"],
    "target_mo_codes": ["MO001"],
    "start_time": "2026-04-01 00:00:00",
    "end_time": "2026-04-01 23:59:59"
  }'
```

**PowerShell**：

```powershell
# 健康检查
Invoke-RestMethod -Uri "http://localhost:8000/health"

# 基于告警 ID 分析
$body = '{"attack_id": "ATK-20260401-001"}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/analyze/alert" -Method Post -ContentType "application/json" -Body $body

# 基于攻击目标分析
$body = '{"attack_target": "192.168.1.100"}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/analyze/target" -Method Post -ContentType "application/json" -Body $body
```

**Python requests**：

```python
import requests

BASE = "http://localhost:8000"

# 健康检查
r = requests.get(f"{BASE}/health")
print(r.json())

# 基于告警 ID 分析
r = requests.post(f"{BASE}/api/v1/analyze/alert", json={"attack_id": "ATK-20260401-001"})
result = r.json()
print(f"状态: {result['status']}")
print(f"确认攻击源: {result['summary']['confirmed']}")
print(f"攻击类型: {result['alert_context']['attack_types']}")

# 基于攻击目标分析
r = requests.post(f"{BASE}/api/v1/analyze/target", json={
    "attack_target": "192.168.1.100",
    "start_time": "2026-04-01 00:00:00",
    "end_time": "2026-04-01 23:59:59",
})
print(r.json()["summary"])
```

---

## 四、输出文件

每次分析完成后，在 `output` 目录（配置文件中 `output.dir` 指定）生成以下文件：

| 文件 | 说明 |
|------|------|
| `traffic_classification_report{tag}.csv` | 所有源 IP 的分类明细（置信度、分类、PPS/BPS、地理信息） |
| `cluster_fingerprint_report{tag}.csv` | 聚类报告（集群 ID、成员数、成员 IP、攻击类型、指纹特征） |
| `cluster_radar_chart{tag}.png` | 攻击集群多维行为雷达图 |
| `attack_blacklist{tag}.csv` | 攻击源黑名单（confirmed + suspicious，可导入防火墙/SOAR） |
| `attack_timeline{tag}.csv` | 攻击时间线（按小时粒度的攻击流量演变） |
| `attack_type_detail{tag}.csv` | 按攻击类型分项的详细分析结果 |

`{tag}` 是分析任务标识：基于告警 ID 时为 `_ATK-xxx`，基于目标时为 `_IP_时间戳`。

---

## 五、常见问题

**Q: ClickHouse 连接失败**

确认 `config.yaml` 中 `port` 为 **9000**（原生协议），不是 8123（HTTP 端口）。`clickhouse-driver` 使用原生 TCP 协议，和 HTTP 接口不兼容。

**Q: 告警表找不到记录**

确认 `alert_table_name` 配置正确（默认 `detect_attack_dist`），`attack_id` 存在于该表中。可用以下 SQL 验证：

```sql
SELECT attack_id, attack_target, attack_types, start_time, end_time
FROM detect_attack_dist
WHERE attack_id = 'ATK-20260401-001'
```

**Q: MySQL 阈值加载失败**

MySQL 不可用时系统会自动从 CSV 降级文件（`attack_type_csv_path` 配置）加载攻击类型定义。降级模式下无阈值数据，使用配置文件中的 `pps_threshold` / `bps_threshold` 作为兜底值。

**Q: 查询结果为空**

确认时间范围和目标 IP / 监测对象编码在 NetFlow 表中有数据。NetFlow 表按 `app_rcv_time` 分区，时间范围越精确查询越快。

**Q: Windows 终端中文乱码**

CLI 帮助信息和报告中的中文在 Windows CMD 中可能乱码。解决方法：
- 使用 Windows Terminal（推荐）
- 或在 CMD 中执行 `chcp 65001` 切换到 UTF-8 编码
- API 返回的 JSON 不受终端编码影响

**Q: __pycache__ 目录散落各处**

设置环境变量 `PYTHONPYCACHEPREFIX` 指向一个统一目录，Python 会把所有 `.pyc` 编译缓存集中存放，不再在源码目录生成 `__pycache__/`。
