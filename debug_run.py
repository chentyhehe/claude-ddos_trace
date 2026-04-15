"""
本地 DEBUG 入口脚本

在 VS Code 中按 F5 启动，或命令行直接运行:
    python debug_run.py alert ATK-20260401-001
    python debug_run.py target 192.168.1.100
    python debug_run.py target 192.168.1.100 --start-time "2026-04-01 00:00:00" --end-time "2026-04-01 23:59:59"
"""

import argparse
import sys
from datetime import datetime

from ddos_trace.config.models import load_config
from ddos_trace.analyzer import DDoSTracebackAnalyzer


def main():
    parser = argparse.ArgumentParser(description="DDoS 溯源分析 DEBUG 入口")
    sub = parser.add_subparsers(dest="command")

    # alert 子命令
    alert_p = sub.add_parser("alert", help="基于告警ID分析")
    alert_p.add_argument("attack_id", help="告警ID，如 ATK-20260401-001")

    # target 子命令
    target_p = sub.add_parser("target", help="基于攻击目标分析")
    target_p.add_argument("attack_target", help="攻击目标 IP 或监测对象编码")
    target_p.add_argument("--start-time", default=None, help="开始时间 YYYY-MM-DD HH:MM:SS")
    target_p.add_argument("--end-time", default=None, help="结束时间 YYYY-MM-DD HH:MM:SS")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # 加载配置
    config = load_config()
    print(f"[CONFIG] ClickHouse: {config.clickhouse.host}:{config.clickhouse.port}/{config.clickhouse.database}")
    print(f"[CONFIG] MySQL:      {config.mysql.host}:{config.mysql.port}/{config.mysql.database}")
    print(f"[CONFIG] CSV降级:    {config.attack_type_csv_path or '(未配置)'}")

    # 创建分析器
    analyzer = DDoSTracebackAnalyzer(
        threshold_config=config.threshold,
        traceback_config=config.traceback,
        clickhouse_config=config.clickhouse,
        mysql_config=config.mysql,
        output_dir=config.output.dir,
        csv_path=config.attack_type_csv_path,
    )

    if args.command == "alert":
        print(f"\n>>> 运行告警分析: attack_id={args.attack_id}\n")
        result = analyzer.run_analysis_by_alert(attack_id=args.attack_id)

    elif args.command == "target":
        start = None
        end = None
        if args.start_time:
            start = datetime.strptime(args.start_time, "%Y-%m-%d %H:%M:%S")
        if args.end_time:
            end = datetime.strptime(args.end_time, "%Y-%m-%d %H:%M:%S")

        print(f"\n>>> 运行目标分析: target={args.attack_target}, time={start} ~ {end}\n")
        result = analyzer.run_analysis_by_target(
            attack_target=args.attack_target,
            start_time=start,
            end_time=end,
        )

    # 输出结果
    if "error" in result:
        print(f"\n分析失败: {result['error']}", file=sys.stderr)
        sys.exit(1)

    # 打印报告
    print("\n" + "=" * 60)
    print(result.get("report", ""))

    # 打印分项摘要
    overview = result.get("overview", {})
    if overview:
        print("\n=== 总览 ===")
        print(f"  攻击类型数: {overview.get('attack_type_count', 0)}")
        print(f"  类型列表:   {overview.get('attack_type_names', [])}")
        print(f"  总源IP:     {overview.get('total_source_ips', 0)}")
        print(f"  confirmed:  {overview.get('confirmed', 0)}")
        print(f"  suspicious: {overview.get('suspicious', 0)}")

    per_type = result.get("per_type_results", {})
    if per_type:
        print(f"\n=== 分项结果 ({len(per_type)} 种攻击类型) ===")
        for at_name, tr in per_type.items():
            s = tr.get("summary", {})
            print(f"  {at_name}: flow={s.get('flow_count', 0)}, "
                  f"confirmed={s.get('confirmed_count', 0)}, "
                  f"suspicious={s.get('suspicious_count', 0)}, "
                  f"PPS阈值={s.get('threshold_pps', 0)}, "
                  f"BPS阈值={s.get('threshold_bps', 0)}")


if __name__ == "__main__":
    main()
