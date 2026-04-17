import csv
import html
import json
import re
from pathlib import Path
from typing import Dict, List, Optional


def _escape(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _parse_run_dir_name(name: str) -> Dict[str, str]:
    attack_id = name
    target = ""
    if "_" in name:
        attack_id, target = name.split("_", 1)
    return {
        "name": name,
        "attack_id": attack_id,
        "target": target,
    }


def list_report_runs(output_dir: str) -> List[Dict[str, str]]:
    root = Path(output_dir)
    if not root.exists():
        return []

    runs: List[Dict[str, str]] = []
    for item in root.rglob("*"):
        if not item.is_dir():
            continue
        if not any(child.is_file() for child in item.iterdir()):
            continue
        parsed = _parse_run_dir_name(item.name)
        parsed["mtime"] = str(item.stat().st_mtime)
        parsed["updated_at"] = item.stat().st_mtime_ns
        parsed["path"] = str(item)
        parsed["relative_path"] = str(item.relative_to(root)).replace("\\", "/")
        runs.append(parsed)

    runs.sort(key=lambda row: row["updated_at"], reverse=True)
    return runs


def get_report_run(output_dir: str, run_name: str) -> Optional[Dict[str, object]]:
    root = Path(output_dir)
    run_dir = root / run_name
    if not run_dir.exists() or not run_dir.is_dir():
        return None

    parsed = _parse_run_dir_name(run_name)
    files = sorted([p for p in run_dir.iterdir() if p.is_file()], key=lambda p: p.name.lower())

    images = [f.name for f in files if f.suffix.lower() in {".png", ".jpg", ".jpeg", ".svg"}]
    markdown_files = [f for f in files if f.suffix.lower() in {".md", ".txt"}]
    data_files = [f.name for f in files if f.suffix.lower() in {".csv", ".json"}]

    summary = {}
    summary_file = next(
        (
            f for f in files
            if f.suffix.lower() == ".json" and ("summary" in f.stem.lower() or "摘要" in f.stem)
        ),
        None,
    )
    if summary_file is not None:
        try:
            summary = json.loads(summary_file.read_text(encoding="utf-8-sig"))
        except Exception:
            summary = {}

    markdown_preview = ""
    if markdown_files:
        try:
            markdown_preview = markdown_files[0].read_text(encoding="utf-8-sig")
        except Exception:
            markdown_preview = ""

    # 读取各数据文件的内容用于内联展示
    csv_tables: Dict[str, List[List[str]]] = {}
    for fname in data_files:
        fpath = run_dir / fname
        if fname.lower().endswith(".csv"):
            try:
                with open(fpath, newline="", encoding="utf-8-sig") as f:
                    reader = csv.reader(f)
                    csv_tables[fname] = [row for row in reader]
            except Exception:
                csv_tables[fname] = []

    json_data: Dict[str, object] = {}
    for fname in data_files:
        fpath = run_dir / fname
        if fname.lower().endswith(".json"):
            try:
                json_data[fname] = json.loads(fpath.read_text(encoding="utf-8-sig"))
            except Exception:
                json_data[fname] = None

    return {
        **parsed,
        "relative_path": str(run_dir.relative_to(root)).replace("\\", "/"),
        "images": images,
        "data_files": data_files,
        "markdown_files": [f.name for f in markdown_files],
        "markdown_preview": markdown_preview,
        "summary": summary,
        "csv_tables": csv_tables,
        "json_data": json_data,
    }


def build_report_index_html(output_dir: str) -> str:
    runs = list_report_runs(output_dir)
    cards = []
    for run in runs:
        attack_id = _escape(run["attack_id"])
        target = _escape(run["target"] or "unknown_target")
        name = _escape(run["relative_path"])
        cards.append(
            f"""
            <a class="card" href="/reports/{name}">
              <div class="eyebrow">攻击ID</div>
              <div class="headline">{attack_id}</div>
              <div class="eyebrow">目标</div>
              <div class="subhead">{target}</div>
            </a>
            """
        )

    empty = "<p class='empty'>output 目录下还没有分析结果文件夹。</p>" if not cards else ""
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DDoS 分析结果</title>
  <style>
    :root {{
      --bg: #f4efe7;
      --panel: #fffdf8;
      --ink: #1b2a34;
      --muted: #6d7b86;
      --accent: #bc5a45;
      --line: #d9cdbd;
    }}
    body {{ margin: 0; font-family: "Segoe UI", "Microsoft YaHei", sans-serif; background: linear-gradient(180deg, #f1e7d8 0%, var(--bg) 45%, #efe8de 100%); color: var(--ink); }}
    .wrap {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px 48px; }}
    h1 {{ font-size: 32px; margin: 0 0 8px; }}
    p.lead {{ margin: 0 0 28px; color: var(--muted); }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px; }}
    .card {{ display: block; text-decoration: none; color: inherit; background: rgba(255,255,255,0.82); border: 1px solid var(--line); border-radius: 18px; padding: 18px; box-shadow: 0 12px 30px rgba(57, 43, 28, 0.08); }}
    .card:hover {{ transform: translateY(-2px); transition: 150ms ease; border-color: #c48b6a; }}
    .eyebrow {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 6px; }}
    .headline {{ font-size: 24px; font-weight: 700; margin-bottom: 14px; word-break: break-word; }}
    .subhead {{ font-size: 16px; line-height: 1.45; word-break: break-word; }}
    .empty {{ background: var(--panel); border: 1px dashed var(--line); padding: 24px; border-radius: 16px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>DDoS 分析结果浏览</h1>
    <p class="lead">读取 output 目录下的分析结果，按攻击ID与目标IP聚合展示。</p>
    {empty}
    <div class="grid">
      {''.join(cards)}
    </div>
  </div>
</body>
</html>"""


def _render_markdown_simple(text: str) -> str:
    """将报告 Markdown 做基础 HTML 渲染（标题、分割线、列表、粗体等）。"""
    lines = text.split("\n")
    out: List[str] = []
    in_list = False
    for line in lines:
        stripped = line.strip()
        # 标题
        if stripped.startswith("====") or stripped.startswith("────") or stripped.startswith("━━━━"):
            if out and out[-1].startswith("<h"):
                pass  # already added heading
            else:
                out.append('<hr class="divider">')
            continue
        if stripped.startswith("# "):
            out.append(f"<h2>{_escape(stripped[2:])}</h2>")
            continue
        if stripped.startswith("## "):
            out.append(f"<h3>{_escape(stripped[3:])}</h3>")
            continue
        # 列表项
        if stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                out.append('<ul class="report-list">')
                in_list = True
            content = _escape(stripped[2:])
            content = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", content)
            out.append(f"<li>{content}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        # 空行
        if not stripped:
            out.append("")
            continue
        # 普通段落
        content = _escape(stripped)
        content = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", content)
        out.append(f"<p>{content}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def _render_csv_table(rows: List[List[str]], max_rows: int = 50) -> str:
    """将 CSV 行数据渲染为 HTML 表格。"""
    if not rows:
        return '<p class="empty-msg">空文件</p>'
    header = rows[0]
    body = rows[1:max_rows + 1]
    truncated = len(rows) - 1 > max_rows

    th_cells = "".join(f"<th>{_escape(c)}</th>" for c in header)
    body_rows = []
    for row in body:
        cells = "".join(f"<td>{_escape(c)}</td>" for c in row)
        body_rows.append(f"<tr>{cells}</tr>")
    suffix = f'<p class="truncated-msg">…共 {len(rows) - 1} 行，仅显示前 {max_rows} 行</p>' if truncated else ""
    return f'<div class="table-wrap"><table><thead><tr>{th_cells}</tr></thead><tbody>{"".join(body_rows)}</tbody></table></div>{suffix}'


def build_report_detail_html(output_dir: str, run_name: str) -> Optional[str]:
    run = get_report_run(output_dir, run_name)
    if run is None:
        return None

    overview = (run.get("summary") or {}).get("overview", {}) if isinstance(run.get("summary"), dict) else {}
    cards = []
    for key, label in [
        ("total_source_ips", "源IP总量"),
        ("anomaly_total", "异常源总量"),
        ("confirmed", "Confirmed"),
        ("suspicious", "Suspicious"),
        ("borderline", "Borderline"),
        ("background", "Background"),
    ]:
        if key in overview:
            cards.append(
                f'<div class="metric"><div class="metric-label">{_escape(label)}</div><div class="metric-value">{_escape(overview.get(key))}</div></div>'
            )

    image_blocks = []
    for image_name in run["images"]:
        safe_name = _escape(image_name)
        image_blocks.append(
            f"""
            <figure class="panel">
              <figcaption>{safe_name}</figcaption>
              <img src="/artifacts/{_escape(run_name)}/{safe_name}" alt="{safe_name}">
            </figure>
            """
        )

    # CSV 内联表格
    csv_sections = []
    csv_tables = run.get("csv_tables", {})
    for fname, rows in csv_tables.items():
        if not rows:
            continue
        table_html = _render_csv_table(rows)
        csv_sections.append(
            f"""
            <details class="data-section" open>
              <summary class="data-section-title">{_escape(fname)}</summary>
              {table_html}
            </details>
            """
        )

    # JSON 内联展示
    json_sections = []
    json_data = run.get("json_data", {})
    for fname, data in json_data.items():
        if data is None:
            continue
        formatted = json.dumps(data, ensure_ascii=False, indent=2)
        # 限制显示行数
        formatted_lines = formatted.split("\n")
        if len(formatted_lines) > 200:
            formatted = "\n".join(formatted_lines[:200]) + "\n… (truncated)"
        json_sections.append(
            f"""
            <details class="data-section" open>
              <summary class="data-section-title">{_escape(fname)}</summary>
              <div class="panel"><pre class="json-block"><code>{_escape(formatted)}</code></pre></div>
            </details>
            """
        )

    # Markdown 报告渲染
    markdown_preview = run.get("markdown_preview", "")
    rendered_report = _render_markdown_simple(markdown_preview) if markdown_preview else '<p class="empty-msg">未找到 Markdown 报告。</p>'

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_escape(run["attack_id"])} - 详情</title>
  <style>
    :root {{
      --bg: #f7f4ee;
      --panel: #fffdfa;
      --ink: #20303a;
      --muted: #687883;
      --line: #dbcdbc;
      --accent: #b6543e;
    }}
    body {{ margin: 0; font-family: "Segoe UI", "Microsoft YaHei", sans-serif; background: var(--bg); color: var(--ink); }}
    .wrap {{ max-width: 1280px; margin: 0 auto; padding: 24px 20px 48px; }}
    .topbar {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 20px; }}
    .back {{ color: var(--accent); text-decoration: none; font-weight: 600; }}
    h1 {{ margin: 8px 0 6px; font-size: 30px; }}
    h2 {{ margin: 24px 0 8px; font-size: 22px; }}
    h3 {{ margin: 18px 0 6px; font-size: 18px; }}
    .sub {{ color: var(--muted); }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px; margin: 22px 0; }}
    .metric, .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 18px; padding: 16px; box-shadow: 0 10px 24px rgba(74, 55, 35, 0.06); }}
    .metric-label {{ color: var(--muted); font-size: 13px; margin-bottom: 8px; }}
    .metric-value {{ font-size: 28px; font-weight: 700; }}
    .section-title {{ margin: 28px 0 12px; font-size: 20px; font-weight: 700; border-left: 4px solid var(--accent); padding-left: 12px; }}
    .images {{ display: grid; grid-template-columns: 1fr; gap: 16px; }}
    img {{ width: 100%; height: auto; border-radius: 12px; background: white; }}
    figcaption {{ margin-bottom: 10px; font-weight: 600; }}
    /* 报告文本渲染 */
    .report-body {{ background: var(--panel); border: 1px solid var(--line); border-radius: 18px; padding: 20px 24px; box-shadow: 0 10px 24px rgba(74, 55, 35, 0.06); line-height: 1.7; }}
    .report-body p {{ margin: 4px 0; }}
    .report-body ul {{ margin: 4px 0; padding-left: 20px; }}
    .report-body li {{ margin: 2px 0; }}
    .divider {{ border: none; border-top: 1px solid var(--line); margin: 12px 0; }}
    /* CSV 表格 */
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin: 0; }}
    th {{ background: #f0ebe2; font-weight: 600; text-align: left; padding: 8px 10px; border-bottom: 2px solid var(--line); white-space: nowrap; }}
    td {{ padding: 6px 10px; border-bottom: 1px solid #ece6da; white-space: nowrap; }}
    tr:hover {{ background: #faf5ec; }}
    /* JSON / 代码块 */
    .json-block {{ white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere; line-height: 1.5; font-size: 12px; margin: 0; }}
    /* 折叠区块 */
    details.data-section {{ margin: 8px 0; }}
    details.data-section > .data-section-title {{
      font-weight: 600; font-size: 15px; cursor: pointer;
      padding: 10px 14px; background: #f0ebe2; border-radius: 10px;
      display: block; margin-bottom: 4px;
    }}
    details.data-section > .data-section-title:hover {{ background: #e8e0d2; }}
    .empty-msg {{ color: var(--muted); font-style: italic; }}
    .truncated-msg {{ color: var(--muted); font-size: 12px; margin-top: 6px; }}
    @media (min-width: 1100px) {{ .images {{ grid-template-columns: 1fr 1fr; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div>
        <a class="back" href="/reports">返回结果列表</a>
        <h1>{_escape(run["attack_id"])}</h1>
        <div class="sub">目标: {_escape(run["target"] or "unknown_target")} | 目录: {_escape(run["relative_path"])}</div>
      </div>
    </div>

    <div class="metrics">{''.join(cards) or '<div class="panel">未找到 summary 概览数据。</div>'}</div>

    <div class="section-title">分析报告</div>
    <div class="report-body">{rendered_report}</div>

    <div class="section-title">图表</div>
    <div class="images">{''.join(image_blocks) or '<div class="panel">未找到图表文件。</div>'}</div>

    {''.join(csv_sections) and f'<div class="section-title">数据表</div>' + ''.join(csv_sections)}
    {''.join(json_sections) and f'<div class="section-title">JSON 数据</div>' + ''.join(json_sections)}
  </div>
</body>
</html>"""
