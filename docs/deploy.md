# DDoS 攻击溯源分析器 - 部署与使用指南

---

## 一、Windows 开发环境调试

### 1. 安装（开发模式）

```bash
cd f:\PyProjects\ddos_trace
pip install -e .
```

验证安装：

```bash
python -c "import ddos_trace; print(ddos_trace.__version__)"
# 输出: 1.0.0
```

> 如果 `ddos-trace` 命令不在 PATH 中，可用 `python -m ddos_trace` 代替。

### 2. 配置 ClickHouse 连接

编辑项目根目录 `config.yaml`，修改以下字段：

```yaml
clickhouse:
  host: "192.168.131.212"                          # ClickHouse 地址
  port: 9000                                       # 原生协议端口（不是 8123）
  username: "default"
  password: "your_password"
  database: "uniflow_controller_clickhouse_develop"
  table_name: "analytics_netflow_dist"             # NetFlow 数据表
  alert_table_name: "detect_attack_dist"           # 攻击告警表
```

验证配置加载：

```bash
python -c "from ddos_trace.config.models import load_config; c = load_config(); print(c.clickhouse.host, c.clickhouse.port, c.clickhouse.database)"
# 输出: 192.168.131.212 9000 uniflow_controller_clickhouse_develop
```

### 3. 验证模块导入

```bash
python -c "from ddos_trace.analyzer import DDoSTracebackAnalyzer; print('ok')"
python -c "from ddos_trace.data.alert_loader import AlertLoader, AttackContext; print('ok')"
python -c "from ddos_trace.api import create_app; app = create_app(); print([r.path for r in app.routes])"
# 输出: ['/openapi.json', '/docs', ..., '/health', '/api/v1/analyze/alert', '/api/v1/analyze/target', '/api/v1/analyze']
```

### 4. 启动 API 服务

```bash
cd f:\PyProjects\ddos_trace

# 方式一：通过命令行工具
ddos-trace serve

# 方式二：通过 python -m（推荐，无需 PATH）
python -m ddos_trace serve --port 8000

# 指定配置文件
python -m ddos_trace serve --config f:\PyProjects\ddos_trace\config.yaml --port 8000
```

启动后：
- API 地址：`http://localhost:8000`
- Swagger 文档：`http://localhost:8000/docs`
- 健康检查：`http://localhost:8000/health`

### 5. 调试调用

在 PowerShell 中用 `Invoke-WebRequest` 调用（或使用浏览器打开 Swagger 文档 `http://localhost:8000/docs` 直接测试）：

```powershell
# 健康检查
Invoke-RestMethod -Uri "http://localhost:8000/health"

# 基于告警 ID 分析
$body = '{"attack_id": "ATK-20260401-001"}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/analyze/alert" -Method Post -ContentType "application/json" -Body $body

# 基于攻击目标分析
$body = '{"attack_target": "192.168.1.100", "start_time": "2026-04-01 00:00:00", "end_time": "2026-04-01 23:59:59"}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/analyze/target" -Method Post -ContentType "application/json" -Body $body

# 手动传参分析
$body = '{"target_ips": ["192.168.1.100"], "target_mo_codes": ["MO001"], "start_time": "2026-04-01 00:00:00", "end_time": "2026-04-01 23:59:59"}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/analyze" -Method Post -ContentType "application/json" -Body $body
```

### 6. 命令行单次分析

```bash
# 基于告警 ID
python -m ddos_trace alert ATK-20260401-001

# 基于攻击目标（可选指定时间）
python -m ddos_trace target 192.168.1.100 --start-time "2026-04-01 00:00:00" --end-time "2026-04-01 23:59:59"

# 手动传参
python -m ddos_trace analyze --target-ips 192.168.1.100 --target-mo-codes MO001 --start-time "2026-04-01 00:00:00" --end-time "2026-04-01 23:59:59"
```

### 7. Python 交互式调试

```python
from ddos_trace.config.models import load_config
from ddos_trace.analyzer import DDoSTracebackAnalyzer

config = load_config("config.yaml")
analyzer = DDoSTracebackAnalyzer(
    threshold_config=config.threshold,
    traceback_config=config.traceback,
    clickhouse_config=config.clickhouse,
    output_dir="./output",
)

# 基于告警 ID
result = analyzer.run_analysis_by_alert("ATK-20260401-001")
print(result["report"])
print(result["attack_context"].attack_types)

# 基于攻击目标
from datetime import datetime
result = analyzer.run_analysis_by_target(
    attack_target="192.168.1.100",
    start_time=datetime(2026, 4, 1, 0, 0, 0),
    end_time=datetime(2026, 4, 1, 23, 59, 59),
)
print(result["features"].columns.tolist())
```

### 8. 构建 Wheel 包

```bash
pip install build
cd f:\PyProjects\ddos_trace
python -m build
```

产物在 `dist/` 目录：
- `dist/ddos_trace-1.0.0-py3-none-any.whl`（32KB）
- `dist/ddos_trace-1.0.0.tar.gz`（25KB）

---

## 二、Linux 生产环境部署

### 1. 构建

在 Windows 开发机上执行：

```bash
cd f:\PyProjects\ddos_trace
python -m build
```

### 2. 传输到服务器

```bash
scp dist/ddos_trace-1.0.0-py3-none-any.whl user@server:/opt/ddos-trace/
scp config.yaml user@server:/opt/ddos-trace/
```

### 3. 服务器安装

```bash
ssh user@server
cd /opt/ddos-trace

# 创建虚拟环境（推荐）
python3 -m venv venv
source venv/bin/activate

# 安装
pip install ddos_trace-1.0.0-py3-none-any.whl

# 验证
python -c "import ddos_trace; print(ddos_trace.__version__)"
ddos-trace --help
```

### 4. 修改配置

```bash
vi /opt/ddos-trace/config.yaml
```

修改 ClickHouse 连接信息，指向生产环境地址。也可用环境变量覆盖：

```bash
export DDOS_CH_HOST="10.0.0.100"
export DDOS_CH_PASSWORD="prod_password"
```

| 环境变量 | 说明 |
|---------|------|
| `DDOS_CH_HOST` | ClickHouse 地址 |
| `DDOS_CH_PORT` | ClickHouse 端口 |
| `DDOS_CH_USER` | 用户名 |
| `DDOS_CH_PASSWORD` | 密码 |
| `DDOS_CH_DATABASE` | 数据库名 |
| `DDOS_CH_TABLE` | NetFlow 表名 |
| `DDOS_CH_ALERT_TABLE` | 告警表名 |

### 5. 手动启动验证

```bash
cd /opt/ddos-trace
source venv/bin/activate

# 前台启动，观察日志
ddos-trace serve --config config.yaml --host 0.0.0.0 --port 8000
```

另开终端验证：

```bash
curl http://localhost:8000/health
# 返回: {"status":"ok","service":"ddos-trace"}

# 测试告警接口
curl -X POST http://localhost:8000/api/v1/analyze/alert \
  -H "Content-Type: application/json" \
  -d '{"attack_id": "ATK-20260401-001"}'
```

### 6. 注册为 systemd 服务

```bash
sudo vi /etc/systemd/system/ddos-trace.service
```

写入：

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

[Install]
WantedBy=multi-user.target
```

启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable ddos-trace
sudo systemctl start ddos-trace

# 查看状态
sudo systemctl status ddos-trace

# 查看日志
sudo journalctl -u ddos-trace -f
```

### 7. Docker 部署（可选）

将 `Dockerfile` 和 `config.yaml` 放在同一目录：

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY ddos_trace-1.0.0-py3-none-any.whl .
RUN pip install --no-cache-dir ddos_trace-1.0.0-py3-none-any.whl
COPY config.yaml .
RUN mkdir -p /app/output

EXPOSE 8000
CMD ["ddos-trace", "serve", "--config", "/app/config.yaml", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t ddos-trace:1.0.0 .

docker run -d \
  --name ddos-trace \
  -p 8000:8000 \
  -v /opt/ddos-trace/config.yaml:/app/config.yaml \
  -v /opt/ddos-trace/output:/app/output \
  ddos-trace:1.0.0
```

---

## 三、API 接口说明

### 接口总览

| 方法 | 路径 | 必传参数 | 阈值来源 | 适用场景 |
|------|------|---------|---------|---------|
| POST | `/api/v1/analyze/alert` | `attack_id` | 告警表自动获取 | 告警触发后自动溯源 |
| POST | `/api/v1/analyze/target` | `attack_target` | 告警表，未找到用配置默认值 | 按 IP/监测对象分析 |
| POST | `/api/v1/analyze` | `target_ips` + `target_mo_codes` + 时间 | 配置文件固定值 | 灵活自定义分析 |

### 请求示例

**接口 1：基于告警 ID**（推荐，阈值和时间窗口全部自动获取）

```json
POST /api/v1/analyze/alert
{"attack_id": "ATK-20260401-001"}
```

**接口 2：基于攻击目标**（可选指定时间，不传则从告警记录获取）

```json
POST /api/v1/analyze/target
{"attack_target": "192.168.1.100"}
```

```json
POST /api/v1/analyze/target
{"attack_target": "192.168.1.100", "start_time": "2026-04-01 00:00:00", "end_time": "2026-04-01 23:59:59"}
```

**接口 3：手动传参**

```json
POST /api/v1/analyze
{
  "target_ips": ["192.168.1.100", "10.0.0.50"],
  "target_mo_codes": ["MO001", "MO002"],
  "start_time": "2026-04-01 00:00:00",
  "end_time": "2026-04-01 23:59:59"
}
```

### 响应格式

```json
{
  "task_id": "a1b2c3d4e5f6",
  "status": "completed",
  "alert_context": {
    "attack_id": "ATK-20260401-001",
    "attack_target": "192.168.1.100",
    "attack_target_type": "ipv4",
    "target_ips": ["192.168.1.100"],
    "attack_types": ["syn", "udp"],
    "level": "HIGH",
    "threshold_pps": 500000.0,
    "threshold_bps": 200000000.0
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
      "confidence_reasons": "PPS超标(得分85); BPS超标(得分78)",
      "packets_per_sec": 850000.0,
      "bytes_per_sec": 45000000.0
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
  "report": "=== DDoS 攻击溯源分析报告 === ..."
}
```

- `alert_context`：接口 1/2 填充告警上下文，接口 3 为 `null`
- `anomaly_sources`：置信度 >= 60 的源 IP 列表
- `clusters`：攻击指纹聚类结果（异常源不足时为空数组）

---

## 四、输出文件

每次分析完成后，在输出目录（默认 `./output`）生成：

| 文件 | 说明 |
|------|------|
| `traffic_classification_report.csv` | 所有源 IP 的分类明细 |
| `cluster_fingerprint_report.csv` | 聚类报告（集群 ID、成员 IP、攻击类型、指纹特征） |
| `cluster_radar_chart.png` | 攻击集群多维行为雷达图 |

---

## 五、常见问题

**ClickHouse 连接失败**
确认 `config.yaml` 中 `port` 为 **9000**（原生协议），不是 8123（HTTP）。`clickhouse-driver` 使用原生协议。

**告警表找不到记录**
确认 `alert_table_name` 配置正确，`attack_id` 存在于 `detect_attack_dist` 表中。

**查询结果为空**
确认时间范围、目标 IP / 监测对象编码在 NetFlow 表中有数据。NetFlow 表按 `app_rcv_time` 分区，时间范围越精确查询越快。

**Windows 终端中文乱码**
CLI 帮助信息中文乱码是 Windows 终端编码问题，不影响功能。API 返回的 JSON 不受影响。
