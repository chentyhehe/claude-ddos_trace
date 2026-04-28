# Linux 打包部署

更新时间：2026-04-27

## 1. Linux 环境打包部署（不创建 venv，Python 3.6.8）

当前项目已为 Python 3.6.8 补充兼容性依赖约束，并新增 `setup.py`，可兼容老版本 `pip` 直接从源码安装。

### 1.1 在打包机上生成发布包

```bash
cd /path/to/claude-ddos_trace
python3 -m pip install --upgrade build
python3 -m build
```

打包完成后，产物在 `dist/` 目录下，通常会有：

- `ddos_trace-1.0.0.tar.gz`
- `ddos_trace-1.0.0-py3-none-any.whl`

### 1.2 上传部署文件到 Linux 服务器

```bash
scp dist/ddos_trace-1.0.0.tar.gz user@server:/opt/ddos-trace/
scp config.yaml user@server:/opt/ddos-trace/
scp docs/source/system_base_attack_type.csv user@server:/opt/ddos-trace/docs/source/
```

### 1.3 在 Linux 服务器上部署（不创建 venv）

```bash
cd /opt/ddos-trace
tar -xzf ddos_trace-1.0.0.tar.gz
cd ddos_trace-1.0.0

python3.6 -m pip install --no-cache-dir --upgrade "setuptools<60" wheel
python3.6 -m pip install --no-cache-dir .
python3.6 -m ddos_trace serve --config /opt/ddos-trace/config.yaml --host 0.0.0.0 --port 8000
```

如果机器上的 `pip` 太旧，或你希望先显式装运行依赖，也可以先执行：

```bash
python3.6 -m pip install --no-cache-dir \
  "dataclasses>=0.8" \
  "pandas>=1.1.5,<1.2" \
  "numpy>=1.19.5,<1.20" \
  "matplotlib>=3.3.4,<3.4" \
  "scikit-learn>=0.24.2,<1.0" \
  "clickhouse-driver>=0.2.5,<0.2.6" \
  "pymysql>=0.9.3,<1.1" \
  "fastapi>=0.63.0,<0.79" \
  "uvicorn>=0.16.0,<0.17" \
  "pyyaml>=5.4.1,<6.0.1"
```

如果你们机器上已经提前装好了依赖，也可以直接走源码启动：

```bash
cd /opt/ddos-trace/ddos_trace-1.0.0
PYTHONPATH=src python3.6 -m ddos_trace serve --config /opt/ddos-trace/config.yaml --host 0.0.0.0 --port 8000
```

### 1.4 后台启动方式

推荐直接用 `nohup` 后台启动，并把日志落到文件：

```bash
cd /opt/ddos-trace/ddos_trace-1.0.0
mkdir -p /opt/ddos-trace/logs

nohup env PYTHONPATH=src python3.6 -m ddos_trace serve \
  --config /home/ddos_trace/config.yaml \
  --host 0.0.0.0 \
  --port 8000 \
  > /home/ddos_trace/logs/ddos-trace.out 2>&1 &
```

启动后可用下面命令检查：

```bash
ps -ef | grep ddos_trace | grep -v grep
tail -f /opt/ddos-trace/logs/ddos-trace.out
```

如需停止进程，可先查 PID 再结束：

```bash
ps -ef | grep ddos_trace | grep -v grep
kill <PID>
```

## 2. 传入攻击 ID 调用分析接口的 curl 示例

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyze/alert" \
  -H "Content-Type: application/json" \
  -d '{"attack_id":"ATK-20260401-001"}'
```

安装包离线下载：
wget -P /opt/ddos-trace/ https://www.python.org/ftp/python/3.6.8/Python-3.6.8.tgz

python3.6 -m pip download \
  -d /home/offline_wheels \
  "dataclasses>=0.8" \
  "pandas>=1.1.5,<1.2" \
  "numpy>=1.19.5,<1.20" \
  "matplotlib>=3.3.4,<3.4" \
  "scikit-learn>=0.24.2,<1.0" \
  "clickhouse-driver>=0.2.5,<0.2.6" \
  "pymysql>=0.9.3,<1.1" \
  "fastapi>=0.63.0,<0.79" \
  "uvicorn>=0.16.0,<0.17" \
  "pyyaml>=5.4.1,<6.0.1"
