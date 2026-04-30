# Linux 部署指南

更新时间：2026-04-29

环境要求：Linux x86_64、Python 3.6.8+。

---

## 一、联网安装

### 步骤 1：在 Windows 上打包

```powershell
cd F:\PyProjects\claude-ddos_trace
python -m pip install --upgrade build
python -m build
```

打包完成后产物在 `dist/` 目录下：
- `ddos_trace-1.0.0-py3-none-any.whl`（用这个）
- `ddos_trace-1.0.0.tar.gz`

### 步骤 2：上传到目标服务器

```powershell
scp dist/ddos_trace-1.0.0-py3-none-any.whl user@server:/opt/ddos-trace/
scp config.yaml user@server:/opt/ddos-trace/
scp docs/source/system_base_attack_type.csv user@server:/opt/ddos-trace/docs/source/
```

### 步骤 3：安装并启动

```bash
# 安装
cd /opt/ddos-trace
python3 -m pip install --no-cache-dir ddos_trace-1.0.0-py3-none-any.whl

# 前台（调试用）
python3 -m ddos_trace serve --config /opt/ddos-trace/config.yaml --host 0.0.0.0 --port 8000

# 后台
mkdir -p /opt/ddos-trace/logs
nohup python3 -m ddos_trace serve \
  --config /opt/ddos-trace/config.yaml \
  --host 0.0.0.0 \
  --port 8000 \
  > /opt/ddos-trace/logs/ddos-trace.out 2>&1 &
```

---

## 二、离线安装（目标机无外网）

### 步骤 1：在有网络的 Linux 机器上下载依赖

> **前提**：下载机器上必须有 `python3.6` 命令可用。
> 因为 pandas 1.1.5、numpy 1.19.5 等老版本没有 Python 3.7+ 的预编译 wheel，
> 必须用 python3.6 下载才能得到目标机兼容的包。

```bash
cd /path/to/claude-ddos_trace/docs/deploy
bash download_wheels.sh /home/offline_wheels
```

下载完成后校验输出，确保关键包都存在（dataclasses、pandas、numpy、matplotlib、scikit-learn）。

### 步骤 2：在 Windows 上打包项目

```powershell
cd F:\PyProjects\claude-ddos_trace
python -m build
# 产物: dist/ddos_trace-1.0.0-py3-none-any.whl
```

### 步骤 3：上传到目标服务器

将 whl 包、依赖 wheel、配置文件一起上传：

```powershell
scp dist/ddos_trace-1.0.0-py3-none-any.whl user@server:/data/ddos-trace/offline_wheels/
scp config.yaml user@server:/data/ddos-trace/
scp docs/source/system_base_attack_type.csv user@server:/data/ddos-trace/docs/source/
```

依赖 wheel 从下载机器传输到目标机：
```bash
scp -r /home/offline_wheels user@server:/data/ddos-trace/offline_wheels/
```

### 步骤 4：离线安装

方式 A：whl 安装（推荐，ddos_trace 注册到 site-packages，直接 `python3 -m ddos_trace` 启动）

```bash
cd /data/ddos-trace/offline_wheels

# 离线安装所有依赖
python3 -m pip install --no-index \
  --find-links=/data/ddos-trace/offline_wheels \
  -r requirements.txt

# 离线安装项目 whl
python3 -m pip install --no-index \
  --find-links=/data/ddos-trace/offline_wheels \
  ddos_trace-1.0.0-py3-none-any.whl
```

方式 B：tar.gz 源码安装（用 sdist 包，需 PYTHONPATH 启动）

```bash
cd /data/ddos-trace/offline_wheels

# 离线安装依赖
python3 -m pip install --no-index \
  --find-links=/data/ddos-trace/offline_wheels \
  -r requirements.txt

# 解压并安装项目
tar -xzf ddos_trace-1.0.0.tar.gz
cd ddos_trace-1.0.0
python3 -m pip install --no-index \
  --find-links=/data/ddos-trace/offline_wheels \
  .
```

### 步骤 5：启动

whl 方式安装后直接启动：

```bash
mkdir -p /data/ddos-trace/logs
nohup python3 -m ddos_trace serve \
  --config /data/ddos-trace/config.yaml \
  --host 0.0.0.0 \
  --port 8000 \
  > /data/ddos-trace/logs/ddos-trace.out 2>&1 &
```

如果 pip 安装失败，用 PYTHONPATH 源码启动：

```bash
cd /data/ddos-trace/offline_wheels/ddos_trace-1.0.0
nohup env PYTHONPATH=src python3 -m ddos_trace serve \
  --config /data/ddos-trace/config.yaml \
  --host 0.0.0.0 \
  --port 8000 \
  > /data/ddos-trace/logs/ddos-trace.out 2>&1 &
```

---

## 三、运维命令

```bash
# 查看进程
ps -ef | grep ddos_trace | grep -v grep

# 查看日志
tail -f /data/ddos-trace/logs/ddos-trace.out

# 停止服务
kill $(ps -ef | grep 'ddos_trace serve' | grep -v grep | awk '{print $2}')
```

## 四、版本更新（业务修改后换包）

> 只需重新打包 whl 并替换，依赖不变时不需要重新下载。

### 4.1 修改版本号

改代码前先升版本号，在 `setup.py` 和 `pyproject.toml` 中修改：

```python
# setup.py
version="1.0.1"  # 原来是 1.0.0
```

```toml
# pyproject.toml
version = "1.0.1"
```

### 4.2 重新打包并上传

```powershell
cd F:\PyProjects\claude-ddos_trace
python -m build
scp dist/ddos_trace-1.0.1-py3-none-any.whl user@server:/data/ddos-trace/
```

### 4.3 在目标服务器上替换安装

```bash
# 1. 停服务
kill $(ps -ef | grep 'ddos_trace serve' | grep -v grep | awk '{print $2}')

# 2. 升级 whl（--upgrade 自动替换旧版本）
python3 -m pip install --no-cache-dir --upgrade \
  /data/ddos-trace/ddos_trace-1.0.1-py3-none-any.whl

# 3. 重启
nohup python3 -m ddos_trace serve \
  --config /data/ddos-trace/config.yaml \
  --host 0.0.0.0 \
  --port 8000 \
  > /data/ddos-trace/logs/ddos-trace.out 2>&1 &
```

如果新增了依赖，需重新执行下载脚本并离线安装依赖后再升级 whl。

## 五、调用示例

```bash
curl -X POST "http://10.187.179.6:8000/api/v1/analyze/alert" \
  -H "Content-Type: application/json" \
  -d '{"attack_id":"2026042718085100480002"}'

##  现网源码启动
nohup env  PYTHONPATH=src python3 -m ddos_trace serve \
  --config /data/ddos_trace/ddos_trace-1.0.0/config.yaml \
  --host 0.0.0.0 \
  --port 8000 \
  > /data/ddos_trace/ddos_trace-1.0.0/logs/ddos-trace.out 2>&1 &
```

