"""
DDoS 攻击溯源分析器 - 命令行入口

支持通过 `python -m ddos_trace` 调用，提供四个子命令:

1. serve   — 启动 FastAPI HTTP API 服务
2. alert   — 基于告警ID执行溯源分析（推荐）
3. target  — 基于攻击目标执行溯源分析
4. analyze — 手动传参执行溯源分析（兼容旧接口）

用法示例:
    python -m ddos_trace serve --port 8000
    python -m ddos_trace alert ATK-20260401-001
    python -m ddos_trace target 192.168.1.100 --start-time "2026-04-01 00:00:00"
    python -m ddos_trace analyze --target-ips 1.2.3.4 --start-time "2026-04-01 00:00:00" --end-time "2026-04-01 23:59:59"
"""

import argparse
import sys
from datetime import datetime

from ddos_trace.config.models import load_config


def main():
    """
    CLI 主入口函数

    使用 argparse 定义四个子命令，各自有独立的参数集。
    未指定子命令时打印帮助信息。
    """
    parser = argparse.ArgumentParser(description="DDoS 攻击溯源分析器")
    sub = parser.add_subparsers(dest="command")

    # serve 子命令 - 启动 API 服务
    serve_parser = sub.add_parser("serve", help="启动 API 服务")
    serve_parser.add_argument("--host", type=str, default=None, help="监听地址")
    serve_parser.add_argument("--port", type=int, default=None, help="监听端口")
    serve_parser.add_argument("--config", type=str, default=None, help="配置文件路径")

    # alert 子命令 - 基于告警ID分析（推荐）
    alert_parser = sub.add_parser("alert", help="基于告警ID执行溯源分析")
    alert_parser.add_argument("attack_id", type=str, help="告警系统生成的攻击ID")
    alert_parser.add_argument("--config", type=str, default=None, help="配置文件路径")
    alert_parser.add_argument("--output-dir", type=str, default=None, help="输出目录")

    # target 子命令 - 基于攻击目标分析
    target_parser = sub.add_parser("target", help="基于攻击目标执行溯源分析")
    target_parser.add_argument("attack_target", type=str, help="攻击目标（IP / 监测对象编码）")
    target_parser.add_argument("--start-time", type=str, default=None, help="开始时间")
    target_parser.add_argument("--end-time", type=str, default=None, help="结束时间")
    target_parser.add_argument("--config", type=str, default=None, help="配置文件路径")
    target_parser.add_argument("--output-dir", type=str, default=None, help="输出目录")

    # analyze 子命令 - 手动传参分析（兼容旧接口）
    analyze_parser = sub.add_parser("analyze", help="手动传参执行分析（兼容旧接口）")
    analyze_parser.add_argument("--target-ips", nargs="+", required=True, help="目的IP列表")
    analyze_parser.add_argument("--target-mo-codes", nargs="+", required=True, help="监测对象编码")
    analyze_parser.add_argument("--start-time", type=str, required=True, help="开始时间")
    analyze_parser.add_argument("--end-time", type=str, required=True, help="结束时间")
    analyze_parser.add_argument("--config", type=str, default=None, help="配置文件路径")
    analyze_parser.add_argument("--output-dir", type=str, default=None, help="输出目录")

    args = parser.parse_args()

    if args.command == "serve":
        _run_serve(args)
    elif args.command == "alert":
        _run_alert(args)
    elif args.command == "target":
        _run_target(args)
    elif args.command == "analyze":
        _run_analyze(args)
    else:
        parser.print_help()


def _run_serve(args):
    """
    启动 API 服务

    使用 uvicorn 作为 ASGI 服务器运行 FastAPI 应用。
    支持通过命令行参数覆盖配置文件中的 host/port。
    """
    import uvicorn
    from ddos_trace.api import create_app

    config = load_config(args.config)
    app = create_app(args.config)

    host = args.host or config.api.host
    port = args.port or config.api.port

    print(f"启动 DDoS 攻击溯源分析器 API 服务: http://{host}:{port}")
    print(f"API 文档: http://{host}:{port}/docs")
    print(f"ClickHouse: {config.clickhouse.host}:{config.clickhouse.port}/{config.clickhouse.database}")
    print(f"MySQL: {config.mysql.host}:{config.mysql.port}/{config.mysql.database}")

    uvicorn.run(app, host=host, port=port, log_level="info")


def _run_alert(args):
    """
    基于告警ID执行分析

    加载配置 → 创建分析器 → 调用 run_analysis_by_alert → 打印报告
    """
    from ddos_trace.analyzer import DDoSTracebackAnalyzer

    config = load_config(args.config)
    output_dir = args.output_dir or config.output.dir

    analyzer = DDoSTracebackAnalyzer(
        threshold_config=config.threshold,
        traceback_config=config.traceback,
        clickhouse_config=config.clickhouse,
        mysql_config=config.mysql,
        threat_intel_config=config.threat_intel,
        output_dir=output_dir,
        csv_path=config.attack_type_csv_path,
    )

    result = analyzer.run_analysis_by_alert(attack_id=args.attack_id)

    if "error" in result:
        print(f"\n分析失败: {result['error']}", file=sys.stderr)
        sys.exit(1)

    print("\n" + result["report"])


def _run_target(args):
    """
    基于攻击目标执行分析

    解析时间参数 → 加载配置 → 创建分析器 → 调用 run_analysis_by_target → 打印报告
    """
    from ddos_trace.analyzer import DDoSTracebackAnalyzer

    config = load_config(args.config)
    output_dir = args.output_dir or config.output.dir

    start_time = None
    end_time = None
    if args.start_time:
        start_time = datetime.strptime(args.start_time, "%Y-%m-%d %H:%M:%S")
    if args.end_time:
        end_time = datetime.strptime(args.end_time, "%Y-%m-%d %H:%M:%S")

    analyzer = DDoSTracebackAnalyzer(
        threshold_config=config.threshold,
        traceback_config=config.traceback,
        clickhouse_config=config.clickhouse,
        mysql_config=config.mysql,
        threat_intel_config=config.threat_intel,
        output_dir=output_dir,
        csv_path=config.attack_type_csv_path,
    )

    result = analyzer.run_analysis_by_target(
        attack_target=args.attack_target,
        start_time=start_time,
        end_time=end_time,
    )

    if "error" in result:
        print(f"\n分析失败: {result['error']}", file=sys.stderr)
        sys.exit(1)

    print("\n" + result["report"])


def _run_analyze(args):
    """
    手动传参执行分析（兼容旧接口）

    需要完整指定 --target-ips、--target-mo-codes、--start-time、--end-time。
    """
    from ddos_trace.analyzer import DDoSTracebackAnalyzer

    config = load_config(args.config)

    start_time = datetime.strptime(args.start_time, "%Y-%m-%d %H:%M:%S")
    end_time = datetime.strptime(args.end_time, "%Y-%m-%d %H:%M:%S")
    output_dir = args.output_dir or config.output.dir

    analyzer = DDoSTracebackAnalyzer(
        threshold_config=config.threshold,
        traceback_config=config.traceback,
        clickhouse_config=config.clickhouse,
        mysql_config=config.mysql,
        threat_intel_config=config.threat_intel,
        output_dir=output_dir,
        csv_path=config.attack_type_csv_path,
    )

    result = analyzer.run_full_analysis(
        target_ips=args.target_ips,
        target_mo_codes=args.target_mo_codes,
        start_time=start_time,
        end_time=end_time,
    )

    if "error" in result:
        print(f"\n分析失败: {result['error']}", file=sys.stderr)
        sys.exit(1)

    print("\n" + result["report"])


if __name__ == "__main__":
    main()
