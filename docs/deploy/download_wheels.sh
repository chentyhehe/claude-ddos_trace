#!/bin/bash
# 离线依赖下载脚本 —— 在有网络的 Linux 机器上运行
#
# 前提：机器上已安装 Python 3.6（python3.6 命令可用，pip 可用）
#       因为 pandas 1.1.5、numpy 1.19.5 等老版本没有 Python 3.7+ 的 wheel，
#       必须用 python3.6 下载才能得到目标机兼容的包。
#
# 用法：
#   bash download_wheels.sh [输出目录]
#
# 默认输出到脚本所在目录

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR}"

mkdir -p "$OUTPUT_DIR"

# 必须使用 python3.6，老版本包没有 3.7+ 的 wheel
PYTHON=python3.6
if ! command -v python3.6 &>/dev/null; then
    echo "错误: 未找到 python3.6"
    echo "本脚本必须使用 Python 3.6 下载依赖，因为目标机是 Python 3.6.8。"
    echo "请在下载机器上安装 Python 3.6 后重试。"
    exit 1
fi

echo "==> 使用 $(python3.6 --version) ..."
echo "==> 下载依赖到 $OUTPUT_DIR ..."

python3.6 -m pip download \
  -d "$OUTPUT_DIR" \
  "setuptools>=39,<60" \
  "wheel" \
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

echo ""
echo "==> 下载完成！共 $(ls "$OUTPUT_DIR"/*.whl "$OUTPUT_DIR"/*.tar.gz 2>/dev/null | wc -l) 个文件"
echo ""
echo "==> 校验关键包："
for pkg in dataclasses pandas numpy matplotlib scikit_learn; do
  if ls "$OUTPUT_DIR"/${pkg}* &>/dev/null; then
    echo "  ✓ $pkg"
  else
    echo "  ✗ $pkg 缺失！"
  fi
done
