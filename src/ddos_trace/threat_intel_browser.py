def build_intel_dashboard_html() -> str:
    return """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Threat Intelligence Dashboard</title>
  <style>
    :root {
      --bg: #f4efe7;
      --ink: #101820;
      --muted: #55636f;
      --panel: rgba(255, 250, 244, 0.82);
      --line: rgba(16, 24, 32, 0.12);
      --accent: #c44c35;
      --accent-2: #0f766e;
      --warn: #b45309;
      --danger: #b42318;
      --shadow: 0 24px 60px rgba(16, 24, 32, 0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI Variable Display", "Bahnschrift", "Trebuchet MS", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(196, 76, 53, 0.16), transparent 28%),
        radial-gradient(circle at top right, rgba(15, 118, 110, 0.14), transparent 30%),
        linear-gradient(180deg, #fbf6ef 0%, var(--bg) 100%);
      min-height: 100vh;
    }
    .shell { max-width: 1440px; margin: 0 auto; padding: 28px; }
    .hero {
      display: grid;
      grid-template-columns: 1.5fr 1fr;
      gap: 18px;
      align-items: stretch;
      margin-bottom: 18px;
    }
    .hero-card, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
    }
    .hero-card { padding: 28px; position: relative; overflow: hidden; }
    .hero-card h1 { margin: 0 0 10px; font-size: 42px; line-height: 1; }
    .hero-card p { margin: 0; color: var(--muted); font-size: 15px; max-width: 640px; }
    .nav-line { margin-top: 16px; font-size: 13px; color: var(--muted); }
    .nav-line a { color: var(--ink); text-decoration: none; font-weight: 700; margin-right: 14px; }
    .status-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }
    .stat-tile {
      padding: 18px;
      border-radius: 20px;
      background: rgba(255,255,255,0.55);
      border: 1px solid var(--line);
    }
    .stat-tile .k { font-size: 28px; font-weight: 800; margin-top: 8px; }
    .stat-tile .l { color: var(--muted); font-size: 13px; }
    .grid {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 18px;
    }
    .stack { display: grid; gap: 18px; }
    .panel { padding: 20px; }
    .panel h2 { margin: 0 0 6px; font-size: 20px; }
    .sub { color: var(--muted); font-size: 13px; margin-bottom: 16px; }
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 12px;
    }
    .metric {
      background: rgba(255,255,255,0.7);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 16px;
    }
    .metric .v { font-size: 24px; font-weight: 800; margin-bottom: 4px; }
    .metric .t { color: var(--muted); font-size: 13px; }
    .bars, .chips { display: grid; gap: 10px; }
    .bar-row { display: grid; gap: 6px; }
    .bar-head { display: flex; justify-content: space-between; gap: 12px; font-size: 13px; }
    .bar-track { height: 12px; border-radius: 999px; background: rgba(16, 24, 32, 0.08); overflow: hidden; }
    .bar-fill { height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--accent), #ef8b57); }
    .bar-fill.alt { background: linear-gradient(90deg, var(--accent-2), #14b8a6); }
    .chip-wrap { display: flex; flex-wrap: wrap; gap: 10px; }
    .chip {
      padding: 10px 14px;
      border-radius: 999px;
      background: rgba(255,255,255,0.7);
      border: 1px solid var(--line);
      font-size: 13px;
      font-weight: 700;
    }
    .chart {
      width: 100%;
      height: 260px;
      background: linear-gradient(180deg, rgba(255,255,255,0.75), rgba(255,255,255,0.4));
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 10px;
    }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px 10px; text-align: left; border-bottom: 1px solid var(--line); font-size: 13px; }
    th { color: var(--muted); font-weight: 700; }
    tr.clickable { cursor: pointer; }
    tr.clickable:hover { background: rgba(16, 24, 32, 0.04); }
    .sev { display: inline-block; padding: 6px 10px; border-radius: 999px; font-size: 12px; font-weight: 800; }
    .sev.high, .sev.critical { background: rgba(180, 35, 24, 0.12); color: var(--danger); }
    .sev.medium { background: rgba(180, 83, 9, 0.12); color: var(--warn); }
    .sev.low { background: rgba(15, 118, 110, 0.12); color: var(--accent-2); }
    .empty { color: var(--muted); padding: 28px 0; text-align: center; }
    @media (max-width: 1100px) {
      .hero, .grid { grid-template-columns: 1fr; }
      .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 640px) {
      .shell { padding: 16px; }
      .metric-grid, .status-grid { grid-template-columns: 1fr; }
      .hero-card h1 { font-size: 34px; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div class="hero-card">
        <h1>威胁情报总览 Dashboard</h1>
        <p>围绕运营商最关心的受影响目标、风险源规模、近30天趋势、运营商/地域热点和处置支撑信息，统一展示威胁情报库沉淀结果。</p>
        <div class="nav-line">
          <a href="/reports">输出文件</a>
          <a href="/docs">API 文档</a>
        </div>
      </div>
      <div class="hero-card">
        <div class="status-grid" id="mysqlSummary"></div>
      </div>
    </section>

    <section class="panel">
      <h2>核心指标 Overview</h2>
      <div class="sub">最近 30 天的事件规模、源规模、峰值和目标分布</div>
      <div class="metric-grid" id="overviewCards"></div>
    </section>

    <section class="grid" style="margin-top:18px;">
      <div class="stack">
        <section class="panel">
          <h2>事件趋势 Trend</h2>
          <div class="sub">按日观察告警事件数、高风险源规模和峰值带宽变化</div>
          <svg class="chart" id="trendChart" viewBox="0 0 760 260" preserveAspectRatio="none"></svg>
        </section>
        <section class="panel">
          <h2>最新事件明细 Recent Events</h2>
          <div class="sub">点击进入事件总览、来源画像、趋势和各类图表详情</div>
          <div style="overflow:auto;">
            <table>
              <thead>
                <tr>
                  <th>事件ID</th>
                  <th>目标IP</th>
                  <th>监测对象</th>
                  <th>严重级别</th>
                  <th>高风险源</th>
                  <th>峰值BPS</th>
                  <th>开始时间</th>
                </tr>
              </thead>
              <tbody id="eventRows"></tbody>
            </table>
          </div>
        </section>
      </div>

      <div class="stack">
        <section class="panel">
          <h2>攻击类型热度 Attack Types</h2>
          <div class="sub">最常出现的攻击类型及事件占比</div>
          <div class="bars" id="attackTypes"></div>
        </section>
        <section class="panel">
          <h2>目标热点 Target Hotspots</h2>
          <div class="sub">哪些目标持续承压、需要重点运营关注</div>
          <div class="bars" id="targetHotspots"></div>
        </section>
        <section class="panel">
          <h2>来源运营商 / 风险分层</h2>
          <div class="sub">辅助运营判断跨网协同、清洗优先级和处置面</div>
          <div class="bars" id="ispBars"></div>
          <div style="height:12px;"></div>
          <div class="chip-wrap" id="classChips"></div>
        </section>
        <section class="panel">
          <h2>基础情报资产 MySQL</h2>
          <div class="sub">黑白名单、人工标签和运营反馈沉淀情况</div>
          <div class="chip-wrap" id="tagChips"></div>
        </section>
      </div>
    </section>
  </div>
  <script>
    const fmt = (value) => {
      if (value === null || value === undefined || value === '') return '-';
      const num = Number(value);
      if (!Number.isNaN(num) && Number.isFinite(num)) {
        if (Math.abs(num) >= 1000000000) return (num / 1000000000).toFixed(2) + 'G';
        if (Math.abs(num) >= 1000000) return (num / 1000000).toFixed(2) + 'M';
        if (Math.abs(num) >= 1000) return (num / 1000).toFixed(1) + 'K';
      }
      return String(value);
    };

    const renderBars = (el, items, labelKey, valueKey, alt = false, suffix = '') => {
      if (!items || !items.length) {
        el.innerHTML = '<div class="empty">暂无数据</div>';
        return;
      }
      const max = Math.max(...items.map(item => Number(item[valueKey] || 0)), 1);
      el.innerHTML = items.map(item => {
        const value = Number(item[valueKey] || 0);
        const width = Math.max(6, Math.round(value / max * 100));
        const label = item[labelKey] || '未标注';
        return `<div class="bar-row">
          <div class="bar-head"><span>${label}</span><strong>${fmt(value)}${suffix}</strong></div>
          <div class="bar-track"><div class="bar-fill ${alt ? 'alt' : ''}" style="width:${width}%"></div></div>
        </div>`;
      }).join('');
    };

    const renderTrend = (el, points) => {
      if (!points || !points.length) {
        el.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#55636f">暂无趋势数据</text>';
        return;
      }
      const w = 760, h = 260, pad = 24;
      const maxEvent = Math.max(...points.map(p => Number(p.event_count || 0)), 1);
      const maxRisk = Math.max(...points.map(p => Number((p.confirmed_sources || 0) + (p.suspicious_sources || 0))), 1);
      const step = points.length === 1 ? 0 : (w - pad * 2) / (points.length - 1);
      const path = (getter, maxVal) => points.map((p, idx) => {
        const x = pad + step * idx;
        const y = h - pad - ((Number(getter(p)) || 0) / maxVal) * (h - pad * 2);
        return `${idx === 0 ? 'M' : 'L'} ${x} ${y}`;
      }).join(' ');
      const eventPath = path(p => p.event_count, maxEvent);
      const riskPath = path(p => (Number(p.confirmed_sources || 0) + Number(p.suspicious_sources || 0)), maxRisk);
      const labels = points.map((p, idx) => {
        const x = pad + step * idx;
        return `<text x="${x}" y="${h - 6}" font-size="10" text-anchor="middle" fill="#55636f">${String(p.day).slice(5)}</text>`;
      }).join('');
      el.innerHTML = `
        <rect x="0" y="0" width="${w}" height="${h}" rx="18" fill="transparent"></rect>
        <path d="${eventPath}" fill="none" stroke="#c44c35" stroke-width="4" stroke-linecap="round"></path>
        <path d="${riskPath}" fill="none" stroke="#0f766e" stroke-width="4" stroke-linecap="round"></path>
        <text x="${pad}" y="${pad}" font-size="12" fill="#c44c35">事件数</text>
        <text x="${pad + 60}" y="${pad}" font-size="12" fill="#0f766e">高风险源</text>
        ${labels}
      `;
    };

    fetch('/api/v1/intel/dashboard')
      .then(res => {
        if (!res.ok) throw new Error('dashboard fetch failed');
        return res.json();
      })
      .then(data => {
        const ov = data.overview || {};
        document.getElementById('overviewCards').innerHTML = [
          ['近30天事件', fmt(ov.event_count_30d)],
          ['目标IP数', fmt(ov.target_ip_count_30d)],
          ['Confirmed源', fmt(ov.confirmed_sources_30d)],
          ['Suspicious源', fmt(ov.suspicious_sources_30d)],
          ['源IP总量', fmt(ov.source_ip_total_30d)],
          ['峰值PPS', fmt(ov.peak_pps_30d)],
          ['峰值BPS', fmt(ov.peak_bps_30d)],
        ].map(([t, v]) => `<div class="metric"><div class="v">${v}</div><div class="t">${t}</div></div>`).join('');

        const ms = data.mysql_summary || {};
        document.getElementById('mysqlSummary').innerHTML = [
          ['黑名单', ms.blacklist_active],
          ['白名单', ms.whitelist_active],
          ['人工标签', ms.manual_tag_total],
          ['反馈记录', ms.feedback_total],
        ].map(([t, v]) => `<div class="stat-tile"><div class="l">${t}</div><div class="k">${fmt(v)}</div></div>`).join('');

        renderTrend(document.getElementById('trendChart'), data.daily_trend || []);
        renderBars(document.getElementById('attackTypes'), data.attack_type_distribution || [], 'attack_type', 'event_count');
        renderBars(document.getElementById('targetHotspots'), data.target_hotspots || [], 'target_ip', 'risky_source_count');
        renderBars(document.getElementById('ispBars'), data.top_isps || [], 'isp_name', 'ip_count', true);

        const classes = data.source_class_distribution || [];
        document.getElementById('classChips').innerHTML = classes.length
          ? classes.map(item => `<span class="chip">${item.traffic_class || 'unknown'} · ${fmt(item.ip_count)}</span>`).join('')
          : '<div class="empty">暂无风险分层数据</div>';

        const tags = data.manual_tags || [];
        document.getElementById('tagChips').innerHTML = tags.length
          ? tags.map(item => `<span class="chip">${item.tag_name || '未命名标签'} · ${fmt(item.tag_count)}</span>`).join('')
          : '<div class="empty">暂无人工标签数据</div>';

        const rows = data.recent_events || [];
        document.getElementById('eventRows').innerHTML = rows.length ? rows.map(item => `
          <tr class="clickable" onclick="location.href='/intel/events/${encodeURIComponent(item.event_id)}'">
            <td>${item.event_id || '-'}</td>
            <td>${item.target_ip || '-'}</td>
            <td>${item.target_mo_name || '-'}</td>
            <td><span class="sev ${(item.severity || 'medium').toLowerCase()}">${item.severity || 'medium'}</span></td>
            <td>${fmt((Number(item.confirmed_sources || 0) + Number(item.suspicious_sources || 0)))}</td>
            <td>${fmt(item.peak_bps)}</td>
            <td>${item.start_time || '-'}</td>
          </tr>`).join('') : '<tr><td colspan="7" class="empty">暂无事件数据</td></tr>';
      })
      .catch(() => {
        document.body.insertAdjacentHTML('beforeend', '<div style="position:fixed;right:20px;bottom:20px;background:#101820;color:#fff;padding:12px 16px;border-radius:14px;">威胁情报看板加载失败，请检查数据库连接或表数据。</div>');
      });
  </script>
</body>
</html>"""


def _intel_nav(active: str) -> str:
    items = [
        ("总览", "/intel", "overview"),
        ("事件", "/intel/events", "events"),
        ("攻击源", "/intel/sources", "sources"),
        ("资产", "/intel/assets/blacklist", "assets"),
    ]
    html = []
    for label, href, key in items:
        cls = "nav-link active" if active == key else "nav-link"
        html.append(f'<a class="{cls}" href="{href}">{label}</a>')
    return "".join(html)


def _intel_page(title: str, active: str, hero_title: str, hero_subtitle: str, body: str, script: str = "") -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{
      --bg: #07111f;
      --bg-2: #0d1b30;
      --panel: rgba(8, 19, 35, 0.78);
      --panel-2: rgba(14, 32, 58, 0.72);
      --panel-3: rgba(10, 24, 44, 0.92);
      --ink: #edf6ff;
      --muted: #95a9c6;
      --line: rgba(125, 173, 255, 0.18);
      --accent: #42e8e0;
      --accent-2: #5b8cff;
      --accent-3: #ff8a5b;
      --good: #59f0b1;
      --warn: #ffb457;
      --danger: #ff6f91;
      --shadow-outer: 0 28px 70px rgba(0, 0, 0, 0.36);
      --shadow-inner: inset 0 1px 0 rgba(255,255,255,0.06);
      --glow: 0 0 0 1px rgba(125, 173, 255, 0.12), 0 0 40px rgba(66, 232, 224, 0.08);
      --radius-xl: 30px;
      --radius-lg: 24px;
      --radius-md: 18px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      background:
        radial-gradient(circle at 0% 0%, rgba(91, 140, 255, 0.26), transparent 28%),
        radial-gradient(circle at 100% 0%, rgba(66, 232, 224, 0.18), transparent 24%),
        radial-gradient(circle at 50% 100%, rgba(255, 138, 91, 0.15), transparent 28%),
        linear-gradient(180deg, #07111f 0%, var(--bg-2) 48%, var(--bg) 100%);
      font-family: "Bahnschrift", "Segoe UI Variable Text", "Microsoft YaHei UI", sans-serif;
      overflow-x: hidden;
    }}
    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background:
        linear-gradient(rgba(125, 173, 255, 0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(125, 173, 255, 0.05) 1px, transparent 1px);
      background-size: 72px 72px;
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.55), transparent 92%);
    }}
    .shell {{
      position: relative;
      max-width: 1480px;
      margin: 0 auto;
      padding: 24px;
    }}
    .shell::before,
    .shell::after {{
      content: "";
      position: absolute;
      border-radius: 999px;
      pointer-events: none;
      filter: blur(24px);
      opacity: 0.7;
    }}
    .shell::before {{
      width: 220px;
      height: 220px;
      top: 40px;
      right: 32px;
      background: radial-gradient(circle, rgba(66, 232, 224, 0.28), transparent 70%);
    }}
    .shell::after {{
      width: 180px;
      height: 180px;
      top: 320px;
      left: -24px;
      background: radial-gradient(circle, rgba(91, 140, 255, 0.22), transparent 72%);
    }}
    .topbar {{
      position: sticky;
      top: 18px;
      z-index: 5;
      display: flex; align-items: center; justify-content: space-between; gap: 16px;
      padding: 18px 22px; margin-bottom: 20px; border-radius: var(--radius-xl);
      background: linear-gradient(135deg, rgba(9, 20, 38, 0.9), rgba(14, 32, 58, 0.82));
      border: 1px solid var(--line);
      backdrop-filter: blur(20px);
      box-shadow: var(--shadow-outer), var(--shadow-inner);
    }}
    .brand {{
      position: relative;
      padding-left: 18px;
      font-size: 20px;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}
    .brand::before {{
      content: "";
      position: absolute;
      left: 0;
      top: 4px;
      bottom: 4px;
      width: 4px;
      border-radius: 999px;
      background: linear-gradient(180deg, var(--accent), var(--accent-2));
      box-shadow: 0 0 18px rgba(66, 232, 224, 0.45);
    }}
    .brand small {{
      display:block;
      font-size: 11px;
      color: var(--muted);
      letter-spacing: 0.16em;
      margin-top: 6px;
    }}
    .nav {{ display: flex; flex-wrap: wrap; gap: 12px; }}
    .nav-link {{
      position: relative;
      padding: 12px 18px; border-radius: 999px; color: var(--muted); text-decoration: none;
      font-size: 14px; font-weight: 700; letter-spacing: 0.03em;
      background: rgba(10, 24, 44, 0.84);
      border: 1px solid rgba(125, 173, 255, 0.12);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
      transition: transform 160ms ease, border-color 160ms ease, color 160ms ease, box-shadow 160ms ease;
    }}
    .nav-link:hover {{
      transform: translateY(-1px);
      color: var(--ink);
      border-color: rgba(66, 232, 224, 0.34);
      box-shadow: 0 0 24px rgba(66, 232, 224, 0.12);
    }}
    .nav-link.active {{
      color: #06101d;
      background: linear-gradient(135deg, var(--accent), #8de7ff 52%, var(--accent-2));
      border-color: transparent;
      box-shadow: 0 14px 30px rgba(66, 232, 224, 0.2);
    }}
    .hero {{
      position: relative;
      overflow: hidden;
      padding: 32px; margin-bottom: 20px; border-radius: var(--radius-xl);
      background:
        linear-gradient(135deg, rgba(8, 21, 39, 0.94), rgba(10, 31, 56, 0.86)),
        linear-gradient(135deg, rgba(66, 232, 224, 0.08), rgba(91, 140, 255, 0.08));
      border: 1px solid var(--line);
      box-shadow: var(--shadow-outer), var(--shadow-inner), var(--glow);
    }}
    .hero::before {{
      content: "";
      position: absolute;
      inset: auto -80px -90px auto;
      width: 320px;
      height: 320px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(91, 140, 255, 0.26), transparent 70%);
      filter: blur(6px);
    }}
    .hero::after {{
      content: "";
      position: absolute;
      inset: 18px;
      border-radius: 24px;
      border: 1px solid rgba(125, 173, 255, 0.08);
      pointer-events: none;
    }}
    .hero h1 {{
      position: relative;
      margin: 0 0 12px;
      max-width: 760px;
      font-size: 42px;
      line-height: 1.05;
      letter-spacing: 0.04em;
      text-shadow: 0 0 26px rgba(66, 232, 224, 0.16);
    }}
    .hero p {{
      position: relative;
      margin: 0;
      max-width: 860px;
      color: var(--muted);
      font-size: 15px;
      line-height: 1.8;
    }}
    .grid {{ display: grid; gap: 18px; }}
    .grid.two {{ grid-template-columns: 1.2fr 0.8fr; }}
    .grid.three {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    .two-col {{ display: grid; grid-template-columns: 1.05fr 0.95fr; gap: 18px; }}
    .panel {{
      position: relative;
      overflow: hidden;
      padding: 22px;
      border-radius: var(--radius-lg);
      background: linear-gradient(180deg, rgba(9, 20, 38, 0.92), rgba(8, 18, 34, 0.82));
      border: 1px solid var(--line);
      box-shadow: var(--shadow-outer), var(--shadow-inner);
    }}
    .panel::before {{
      content: "";
      position: absolute;
      inset: 0 0 auto 0;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(66, 232, 224, 0.4), transparent);
    }}
    .panel h2 {{
      margin: 0 0 8px;
      font-size: 22px;
      letter-spacing: 0.04em;
    }}
    .subtle {{ color: var(--muted); font-size: 13px; line-height: 1.75; margin-bottom: 14px; }}
    .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }}
    .metric {{
      position: relative;
      padding: 18px;
      border-radius: var(--radius-md);
      background: linear-gradient(135deg, rgba(15, 34, 61, 0.92), rgba(9, 23, 43, 0.82));
      border: 1px solid rgba(125, 173, 255, 0.12);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.04), 0 16px 32px rgba(0, 0, 0, 0.18);
    }}
    .metric::after {{
      content: "";
      position: absolute;
      top: 0;
      right: 0;
      width: 92px;
      height: 92px;
      background: radial-gradient(circle, rgba(66, 232, 224, 0.14), transparent 70%);
      pointer-events: none;
    }}
    .metric .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
    .metric .value {{ margin-top: 10px; font-size: 30px; font-weight: 800; letter-spacing: 0.02em; }}
    .metric .hint {{ margin-top: 8px; color: var(--muted); font-size: 12px; }}
    .status-badge {{
      display: inline-flex; align-items: center; padding: 6px 12px; border-radius: 999px;
      font-size: 12px; font-weight: 800; background: rgba(14, 32, 58, 0.86); color: var(--ink);
      border: 1px solid rgba(125, 173, 255, 0.14);
    }}
    .status-badge.high {{ background: rgba(255, 111, 145, 0.14); color: var(--danger); border-color: rgba(255, 111, 145, 0.24); }}
    .status-badge.medium {{ background: rgba(255, 180, 87, 0.14); color: var(--warn); border-color: rgba(255, 180, 87, 0.24); }}
    .status-badge.low {{ background: rgba(89, 240, 177, 0.12); color: var(--good); border-color: rgba(89, 240, 177, 0.2); }}
    .chart-card {{
      height: 280px;
      padding: 18px;
      border-radius: var(--radius-md);
      background:
        linear-gradient(180deg, rgba(10, 25, 46, 0.95), rgba(7, 18, 34, 0.92)),
        linear-gradient(90deg, rgba(66, 232, 224, 0.06), rgba(91, 140, 255, 0.04));
      border: 1px solid rgba(125, 173, 255, 0.12);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
    }}
    .chart-card svg {{ width: 100%; height: 100%; display: block; }}
    .bar-list {{ display: grid; gap: 12px; }}
    .bar-item {{ display: grid; gap: 6px; }}
    .bar-head {{ display: flex; justify-content: space-between; gap: 12px; font-size: 13px; color: var(--muted); }}
    .bar-head strong {{ color: var(--ink); }}
    .bar-track {{
      height: 12px;
      border-radius: 999px;
      overflow: hidden;
      background: rgba(125, 173, 255, 0.08);
      border: 1px solid rgba(125, 173, 255, 0.08);
    }}
    .bar-fill {{
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, var(--accent), #8de7ff 48%, var(--accent-2));
      box-shadow: 0 0 18px rgba(66, 232, 224, 0.22);
    }}
    .bar-fill.good {{ background: linear-gradient(90deg, #59f0b1, #42e8e0); }}
    .bar-fill.soft {{ background: linear-gradient(90deg, var(--accent-3), #ffd46a); }}
    .chip-row {{ display: flex; flex-wrap: wrap; gap: 10px; }}
    .chip {{
      padding: 10px 14px;
      border-radius: 999px;
      background: rgba(14, 32, 58, 0.84);
      border: 1px solid rgba(125, 173, 255, 0.14);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
      font-size: 13px;
      color: var(--ink);
    }}
    .priority-list {{ display: grid; gap: 14px; }}
    .priority-item {{
      position: relative;
      padding: 18px;
      border-radius: var(--radius-md);
      background: linear-gradient(135deg, rgba(13, 31, 57, 0.96), rgba(9, 22, 40, 0.88));
      border: 1px solid rgba(125, 173, 255, 0.12);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
    }}
    .priority-top {{ display:flex; justify-content:space-between; gap:14px; align-items:center; margin-bottom:10px; }}
    .priority-title {{ font-size: 16px; font-weight: 800; }}
    .priority-meta {{ color: var(--muted); font-size: 12px; line-height: 1.7; }}
    .priority-action {{ margin-top: 10px; color: #cbdbff; font-size: 13px; font-weight: 700; }}
    .event-table {{ width: 100%; border-collapse: collapse; }}
    .event-table th, .event-table td {{
      padding: 12px 10px;
      text-align: left;
      border-bottom: 1px solid rgba(125, 173, 255, 0.12);
      font-size: 13px;
      vertical-align: top;
    }}
    .event-table th {{ color: var(--muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; font-size: 12px; }}
    .event-table tr.clickable {{ cursor: pointer; }}
    .event-table tr.clickable:hover {{ background: rgba(66, 232, 224, 0.06); }}
    .link-button {{
      display:inline-flex; align-items:center; justify-content:center; min-height:42px; padding:0 16px;
      border-radius:999px;
      border: 0;
      background: linear-gradient(135deg, var(--accent), #8de7ff 48%, var(--accent-2));
      color:#06101d;
      text-decoration:none;
      font-weight:800;
      box-shadow: 0 14px 30px rgba(66, 232, 224, 0.2);
    }}
    .ghost-button {{
      background: rgba(14, 32, 58, 0.84);
      color: var(--ink);
      border: 1px solid rgba(125, 173, 255, 0.14);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
    }}
    .toolbar {{ display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin-bottom:14px; }}
    .toolbar input, .toolbar select {{
      min-height:42px;
      padding:0 14px;
      border: 1px solid rgba(125, 173, 255, 0.14);
      border-radius:999px;
      color: var(--ink);
      background: rgba(10, 24, 44, 0.84);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
      font-size:13px;
    }}
    .toolbar input::placeholder {{ color: #7690b0; }}
    .empty {{ color: var(--muted); text-align:center; padding:26px 0; font-size:13px; }}
    .key-points {{ display:grid; gap:10px; padding-left:18px; color: var(--ink); }}
    .key-points li {{ line-height: 1.7; }}
    @media (max-width: 1100px) {{ .grid.two, .two-col, .grid.three {{ grid-template-columns: 1fr; }} }}
    @media (max-width: 760px) {{
      .shell {{ padding:16px; }}
      .topbar {{ flex-direction:column; align-items:flex-start; }}
      .hero {{ padding: 24px; }}
      .hero h1 {{ font-size:30px; }}
      .event-table {{ min-width:780px; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">威胁情报中心<small>面向运营研判与处置联动的统一视图</small></div>
      <nav class="nav">{_intel_nav(active)}</nav>
    </header>
    <section class="hero">
      <h1>{hero_title}</h1>
      <p>{hero_subtitle}</p>
    </section>
    {body}
  </div>
  <script>
    const toNumber = (value) => {{
      const num = Number(value);
      return Number.isFinite(num) ? num : 0;
    }};
    const fmt = (value) => {{
      if (value === null || value === undefined || value === '') return '-';
      const num = Number(value);
      if (!Number.isFinite(num)) return String(value);
      if (Math.abs(num) >= 1000000000) return (num / 1000000000).toFixed(2) + 'G';
      if (Math.abs(num) >= 1000000) return (num / 1000000).toFixed(2) + 'M';
      if (Math.abs(num) >= 1000) return (num / 1000).toFixed(1) + 'K';
      return String(Math.round(num * 100) / 100);
    }};
    const fmtBps = (value) => {{
      const num = toNumber(value);
      if (num >= 1e9) return (num / 1e9).toFixed(2) + ' Gbps';
      if (num >= 1e6) return (num / 1e6).toFixed(2) + ' Mbps';
      if (num >= 1e3) return (num / 1e3).toFixed(1) + ' Kbps';
      return num + ' bps';
    }};
    const safeText = (value, fallback = '-') => {{
      if (value === null || value === undefined || value === '') return fallback;
      return String(value);
    }};
    const severityClass = (value) => {{
      const text = String(value || '').toLowerCase();
      if (text === 'critical' || text === 'high') return 'high';
      if (text === 'medium') return 'medium';
      return 'low';
    }};
    const renderBarList = (target, items, labelKey, valueKey, fillClass = '') => {{
      const el = document.getElementById(target);
      if (!el) return;
      if (!items || !items.length) {{
        el.innerHTML = '<div class="empty">暂无数据</div>';
        return;
      }}
      const maxValue = Math.max(...items.map(item => toNumber(item[valueKey])), 1);
      el.innerHTML = items.map(item => {{
        const value = toNumber(item[valueKey]);
        const width = Math.max(8, Math.round((value / maxValue) * 100));
        const label = safeText(item[labelKey], '未标注');
        return `<div class="bar-item"><div class="bar-head"><span>${{label}}</span><strong>${{fmt(value)}}</strong></div><div class="bar-track"><div class="bar-fill ${{fillClass}}" style="width:${{width}}%"></div></div></div>`;
      }}).join('');
    }};
    const renderLineChart = (target, points, series) => {{
      const el = document.getElementById(target);
      if (!el) return;
      if (!points || !points.length) {{
        el.innerHTML = '<div class="empty">暂无趋势数据</div>';
        return;
      }}
      const width = 780, height = 240, padL = 50, padR = 24, padT = 28, padB = 28;
      const chartW = width - padL - padR, chartH = height - padT - padB;
      const step = points.length === 1 ? 0 : chartW / (points.length - 1);
      const globalMax = Math.max(...series.map(s => Math.max(...points.map(p => toNumber(p[s.key])), 1)));
      const yTicks = 4;
      const yLabels = Array.from({{length: yTicks + 1}}, (_, i) => {{
        const val = Math.round(globalMax * (1 - i / yTicks));
        const y = padT + (i / yTicks) * chartH;
        return `<text x="${{padL - 6}}" y="${{y + 4}}" font-size="9" text-anchor="end" fill="#7690b0">${{fmt(val)}}</text><line x1="${{padL}}" y1="${{y}}" x2="${{width - padR}}" y2="${{y}}" stroke="rgba(125,173,255,0.06)" stroke-width="1"/>`;
      }}).join('');
      const lines = series.map(item => {{
        const maxValue = Math.max(...points.map(point => toNumber(point[item.key])), 1);
        const path = points.map((point, index) => {{
          const x = padL + step * index;
          const y = padT + chartH - (toNumber(point[item.key]) / maxValue) * chartH;
          return `${{index === 0 ? 'M' : 'L'}} ${{x}} ${{y}}`;
        }}).join(' ');
        return `<path d="${{path}}" fill="none" stroke="${{item.color}}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></path>`;
      }}).join('');
      const dots = series.map(item => {{
        const maxValue = Math.max(...points.map(point => toNumber(point[item.key])), 1);
        return points.map((point, index) => {{
          const x = padL + step * index;
          const y = padT + chartH - (toNumber(point[item.key]) / maxValue) * chartH;
          return `<circle cx="${{x}}" cy="${{y}}" r="3" fill="${{item.color}}" opacity="0.7"><title>${{safeText(item.label)}}: ${{fmt(toNumber(point[item.key]))}}</title></circle>`;
        }}).join('');
      }}).join('');
      const labels = points.map((point, index) => {{
        const x = padL + step * index;
        const raw = point.day || point.bucket_time || point.month || '';
        const text = String(raw).slice(5, 10) || String(raw);
        return `<text x="${{x}}" y="${{height - 6}}" font-size="10" text-anchor="middle" fill="#7690b0">${{text}}</text>`;
      }}).join('');
      const legend = series.map((item, index) => `<circle cx="${{padL + index * 100 + 6}}" cy="12" r="4" fill="${{item.color}}"/><text x="${{padL + index * 100 + 14}}" y="16" font-size="11" fill="${{item.color}}">${{item.label}}</text>`).join('');
      el.innerHTML = `<svg viewBox="0 0 ${{width}} ${{height}}" preserveAspectRatio="xMidYMid meet">${{legend}}${{yLabels}}${{lines}}${{dots}}${{labels}}</svg>`;
    }};
    {script}
  </script>
</body>
</html>"""


def build_intel_dashboard_html() -> str:
    body = """
    <section class="grid">
      <div class="panel">
        <h2>全局态势</h2>
        <div class="subtle">先看现在有没有需要立刻联动处置的事件，再看风险规模和受影响对象。</div>
        <div class="metric-grid" id="overviewCards"></div>
      </div>
      <div class="panel">
        <h2>情报资产概况</h2>
        <div class="subtle">黑白名单、人工标签和反馈记录决定了研判是否有先验证据。</div>
        <div class="metric-grid" id="assetCards"></div>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>近 14 天趋势</h2>
        <div class="subtle">同时观察事件数、高风险源和峰值带宽，判断压力是在扩散还是回落。</div>
        <div class="chart-card" id="trendChart"></div>
      </div>
      <div class="panel">
        <h2>高优先级事件</h2>
        <div class="subtle">这里优先展示最值得运营侧立刻看的一批事件，而不是把全部事件平铺开。</div>
        <div class="priority-list" id="priorityEvents"></div>
      </div>
    </section>
    <section class="grid three" style="margin-top:18px;">
      <div class="panel">
        <h2>攻击类型热度</h2>
        <div class="subtle">判断当前主要承压形态，便于对应清洗和防护策略。</div>
        <div class="bar-list" id="attackTypeList"></div>
      </div>
      <div class="panel">
        <h2>热点目标</h2>
        <div class="subtle">运营侧最关心哪些目标反复承压，是否已经形成连续性风险。</div>
        <div class="bar-list" id="targetHotspots"></div>
      </div>
      <div class="panel">
        <h2>热点监测对象</h2>
        <div class="subtle">把目标 IP 汇总到监测对象层，帮助判断客户侧和产品侧影响面。</div>
        <div class="bar-list" id="monitorHotspots"></div>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>来源运营商与风险分层</h2>
        <div class="subtle">辅助判断跨网协同方向，并快速理解高风险源整体分布。</div>
        <div class="bar-list" id="ispRank"></div>
        <div style="height:14px"></div>
        <div class="chip-row" id="riskChips"></div>
      </div>
      <div class="panel">
        <h2>最新事件简表</h2>
        <div class="subtle">提供最近事件的快速入口，完整筛选在事件列表页完成。</div>
        <div style="overflow:auto;">
          <table class="event-table">
            <thead>
              <tr>
                <th>事件编号</th>
                <th>目标 IP</th>
                <th>监测对象</th>
                <th>严重级别</th>
                <th>高风险源</th>
                <th>峰值 BPS</th>
              </tr>
            </thead>
            <tbody id="recentEvents"></tbody>
          </table>
        </div>
      </div>
    </section>
    """
    script = """
    fetch('/api/v1/intel/dashboard')
      .then(res => { if (!res.ok) throw new Error('dashboard fetch failed'); return res.json(); })
      .then(data => {
        const overview = data.overview || {};
        document.getElementById('overviewCards').innerHTML = [
          ['24 小时事件数', fmt(overview.event_count_24h), '最近一天新增事件总量'],
          ['24 小时高危事件', fmt(overview.high_severity_event_count_24h), '严重级别为高或紧急的事件'],
          ['24 小时高风险源', fmt(overview.risky_source_count_24h), '确认与可疑攻击源总和'],
          ['24 小时活跃目标', fmt(overview.target_ip_count_24h), '正在承压的目标 IP 数量'],
          ['24 小时监测对象', fmt(overview.monitor_object_count_24h), '受影响监测对象数量'],
          ['24 小时峰值带宽', fmt(overview.peak_bps_24h), '单事件观测到的最高带宽'],
          ['30 天事件数', fmt(overview.event_count_30d), '用于看整体压力规模'],
          ['30 天源总量', fmt(overview.source_ip_total_30d), '近一月累计观测来源数'],
        ].map(item => `<div class="metric"><div class="label">${item[0]}</div><div class="value">${item[1]}</div><div class="hint">${item[2]}</div></div>`).join('');

        const mysqlSummary = data.mysql_summary || {};
        document.getElementById('assetCards').innerHTML = [
          ['生效黑名单', fmt(mysqlSummary.blacklist_active), '可直接提供先验风险证据'],
          ['生效白名单', fmt(mysqlSummary.whitelist_active), '用于避免误伤正常源'],
          ['人工标签', fmt(mysqlSummary.manual_tag_total), '长期研判知识沉淀'],
          ['反馈记录', fmt(mysqlSummary.feedback_total), '运营与分析闭环情况'],
        ].map(item => `<div class="metric"><div class="label">${item[0]}</div><div class="value">${item[1]}</div><div class="hint">${item[2]}</div></div>`).join('');

        renderLineChart('trendChart', data.daily_trend || [], [
          { key: 'event_count', color: '#d26d4b', label: '事件数' },
          { key: 'confirmed_sources', color: '#6f8b63', label: '确认攻击源' },
          { key: 'peak_bps', color: '#b57c42', label: '峰值带宽' },
        ]);

        const priority = data.priority_events || [];
        document.getElementById('priorityEvents').innerHTML = priority.length ? priority.map(item => `
          <div class="priority-item">
            <div class="priority-top">
              <div>
                <div class="priority-title">${safeText(item.event_name, item.event_id)}</div>
                <div class="priority-meta">${safeText(item.target_ip)} / ${safeText(item.target_mo_name, '未识别监测对象')}</div>
              </div>
              <span class="status-badge ${severityClass(item.severity)}">${safeText(item.severity, '未知级别')}</span>
            </div>
            <div class="priority-meta">高风险源 ${fmt(toNumber(item.confirmed_sources) + toNumber(item.suspicious_sources))} / 峰值带宽 ${fmt(item.peak_bps)} / 开始时间 ${safeText(item.start_time)}</div>
            <div class="priority-action">${safeText(item.action_hint, '建议进一步研判')}</div>
            <div style="margin-top:12px;"><a class="link-button" href="/intel/events/${encodeURIComponent(item.event_id)}">查看详情</a></div>
          </div>
        `).join('') : '<div class="empty">暂无高优先级事件</div>';

        renderBarList('attackTypeList', data.attack_type_distribution || [], 'attack_type', 'event_count');
        renderBarList('targetHotspots', data.target_hotspots || [], 'target_ip', 'risky_source_count', 'soft');
        renderBarList('monitorHotspots', data.monitor_hotspots || [], 'target_mo_name', 'risky_source_count', 'good');
        renderBarList('ispRank', data.top_isps || [], 'isp_name', 'ip_count', 'good');

        const risk = data.source_class_distribution || [];
        document.getElementById('riskChips').innerHTML = risk.length
          ? risk.map(item => `<span class="chip">${safeText(item.traffic_class, '未分类')}：${fmt(item.ip_count)}</span>`).join('')
          : '<div class="empty">暂无风险分层数据</div>';

        const events = data.recent_events || [];
        document.getElementById('recentEvents').innerHTML = events.length ? events.map(item => `
          <tr class="clickable" onclick="location.href='/intel/events/${encodeURIComponent(item.event_id)}'">
            <td>${safeText(item.event_id)}</td>
            <td>${safeText(item.target_ip)}</td>
            <td>${safeText(item.target_mo_name, '未识别')}</td>
            <td><span class="status-badge ${severityClass(item.severity)}">${safeText(item.severity)}</span></td>
            <td>${fmt(toNumber(item.confirmed_sources) + toNumber(item.suspicious_sources))}</td>
            <td>${fmt(item.peak_bps)}</td>
          </tr>
        `).join('') : '<tr><td colspan="6" class="empty">暂无事件数据</td></tr>';
      })
      .catch(() => {
        document.body.insertAdjacentHTML('beforeend', '<div style="position:fixed;right:20px;bottom:20px;padding:14px 18px;border-radius:18px;background:#f6eee4;box-shadow:22px 22px 44px rgba(180,157,130,0.28);">总览页面加载失败，请检查威胁情报库连接。</div>');
      });
    """
    return _intel_page(
        title="威胁情报总览",
        active="overview",
        hero_title="威胁情报总览",
        hero_subtitle="这里先回答运营侧最关心的四个问题：现在严不严重、谁在受影响、该先处置什么、这些来源大概是什么性质。",
        body=body,
        script=script,
    )


def build_intel_event_list_html() -> str:
    body = """
    <section class="panel">
      <h2>事件检索</h2>
      <div class="subtle">支持按严重级别、攻击类型、目标 IP、监测对象和时间范围筛选，避免在总览页堆信息。</div>
      <div class="toolbar">
        <select id="severity">
          <option value="">全部严重级别</option>
          <option value="critical">紧急</option>
          <option value="high">高</option>
          <option value="medium">中</option>
          <option value="low">低</option>
        </select>
        <input id="attackType" type="text" placeholder="攻击类型，例如 UDP Flood">
        <input id="targetIp" type="text" placeholder="目标 IP">
        <input id="targetMo" type="text" placeholder="监测对象名称">
        <select id="timeRange">
          <option value="24h">最近 24 小时</option>
          <option value="7d">最近 7 天</option>
          <option value="30d" selected>最近 30 天</option>
        </select>
        <select id="sortBy">
          <option value="time">按时间</option>
          <option value="bps">按峰值带宽</option>
          <option value="sources">按高风险源数量</option>
        </select>
        <button class="link-button ghost-button" id="searchBtn">查询</button>
      </div>
      <div class="chip-row" id="eventSummary"></div>
    </section>
    <section class="panel" style="margin-top:18px;">
      <h2>事件列表</h2>
      <div class="subtle">事件列表负责完整浏览，详情页负责研判结论和证据展示，两者职责分开。</div>
      <div style="overflow:auto;">
        <table class="event-table">
          <thead>
            <tr>
              <th>事件编号</th>
              <th>目标 IP</th>
              <th>监测对象</th>
              <th>攻击类型</th>
              <th>严重级别</th>
              <th>高风险源</th>
              <th>峰值 BPS</th>
              <th>建议动作</th>
            </tr>
          </thead>
          <tbody id="eventListRows"></tbody>
        </table>
      </div>
    </section>
    """
    script = """
    const loadEvents = () => {
      const params = new URLSearchParams({
        severity: document.getElementById('severity').value,
        attack_type: document.getElementById('attackType').value,
        target_ip: document.getElementById('targetIp').value,
        target_mo: document.getElementById('targetMo').value,
        time_range: document.getElementById('timeRange').value,
        sort_by: document.getElementById('sortBy').value,
        page: '1',
        page_size: '20'
      });
      fetch(`/api/v1/intel/events_filtered?${params.toString()}`)
        .then(res => { if (!res.ok) throw new Error('event list fetch failed'); return res.json(); })
        .then(data => {
          const summary = data.severity_summary || {};
          document.getElementById('eventSummary').innerHTML = [
            `总事件数：${fmt(data.total)}`,
            `紧急：${fmt(summary.critical)}`,
            `高：${fmt(summary.high)}`,
            `中：${fmt(summary.medium)}`,
            `低：${fmt(summary.low)}`
          ].map(text => `<span class="chip">${text}</span>`).join('');

          const items = data.items || [];
          document.getElementById('eventListRows').innerHTML = items.length ? items.map(item => `
            <tr class="clickable" onclick="location.href='/intel/events/${encodeURIComponent(item.event_id)}'">
              <td>${safeText(item.event_id)}</td>
              <td>${safeText(item.target_ip)}</td>
              <td>${safeText(item.target_mo_name, '未识别')}</td>
              <td>${(item.attack_types || []).join('、') || '未识别'}</td>
              <td><span class="status-badge ${severityClass(item.severity)}">${safeText(item.severity)}</span></td>
              <td>${fmt(toNumber(item.confirmed_sources) + toNumber(item.suspicious_sources))}</td>
              <td>${fmt(item.peak_bps)}</td>
              <td>${safeText(item.action_hint, '建议进一步研判')}</td>
            </tr>
          `).join('') : '<tr><td colspan="8" class="empty">没有匹配的事件</td></tr>';
        })
        .catch(() => {
          document.getElementById('eventListRows').innerHTML = '<tr><td colspan="8" class="empty">事件列表加载失败</td></tr>';
        });
    };
    document.getElementById('searchBtn').addEventListener('click', loadEvents);
    loadEvents();
    """
    return _intel_page(
        title="威胁情报事件列表",
        active="events",
        hero_title="事件列表",
        hero_subtitle="事件列表用于完整检索历史事件；真正的研判重点会在事件详情页进一步收敛，不把所有字段放在一个表里硬塞给使用者。",
        body=body,
        script=script,
    )


def build_intel_event_detail_html(event_id: str) -> str:
    body = """
    <section class="grid">
      <div class="panel">
        <h2>研判结论</h2>
        <div class="subtle">这里优先给结论和处置建议，再给支撑证据，避免研判时陷入大列表。</div>
        <div class="metric-grid" id="detailMetrics"></div>
        <div style="height:14px"></div>
        <div class="metric">
          <div class="value" style="font-size:22px" id="recommendationText">正在加载建议...</div>
          <div class="hint" id="impactSummary"></div>
        </div>
      </div>
      <div class="panel">
        <h2>关键证据</h2>
        <div class="subtle">仅保留支撑结论的高价值证据，其他明细下沉到后面。</div>
        <ul class="key-points" id="judgementFindings"></ul>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>时序趋势</h2>
        <div class="subtle">看攻击强度和来源规模是否持续升高，辅助判断是否需要升级处置。</div>
        <div class="chart-card" id="eventTrend"></div>
      </div>
      <div class="panel">
        <h2>来源结构</h2>
        <div class="subtle">按流量分类、攻击类型和聚类三种方式看结构，而不是把所有源一股脑列出来。</div>
        <div class="bar-list" id="sourceClassBars"></div>
        <div style="height:14px"></div>
        <div class="bar-list" id="attackTypeBars"></div>
        <div style="height:14px"></div>
        <div class="bar-list" id="clusterBars"></div>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>来源地域与入口节点</h2>
        <div class="subtle">这部分更偏溯源支撑，帮助运营侧判断跨区域特征和入口承压位置。</div>
        <div class="bar-list" id="geoBars"></div>
        <div style="height:14px"></div>
        <div class="bar-list" id="entryBars"></div>
      </div>
      <div class="panel">
        <h2>高价值源对象</h2>
        <div class="subtle">只展示最值得人工复核的一小批源对象，并直接标出情报命中情况。</div>
        <div style="overflow:auto;">
          <table class="event-table">
            <thead>
              <tr>
                <th>源 IP</th>
                <th>分类</th>
                <th>置信度</th>
                <th>攻击类型</th>
                <th>地域与运营商</th>
                <th>情报命中</th>
              </tr>
            </thead>
            <tbody id="topSourceRows"></tbody>
          </table>
        </div>
      </div>
    </section>
    """
    script = f"""
    fetch('/api/v1/intel/events/{event_id}')
      .then(res => {{ if (!res.ok) throw new Error('detail fetch failed'); return res.json(); }})
      .then(data => {{
        const event = data.event || {{}};
        const judgement = data.judgement || {{}};
        const evidence = judgement.evidence_summary || {{}};
        document.querySelector('.hero h1').textContent = safeText(event.event_name, '事件详情');
        document.querySelector('.hero p').textContent = `${{safeText(event.target_ip)}} / ${{safeText(event.target_mo_name, '未识别监测对象')}} / 开始时间 ${{safeText(event.start_time)}}`;

        document.getElementById('detailMetrics').innerHTML = [
          ['严重级别', safeText(event.severity)],
          ['高风险源', fmt(toNumber(event.confirmed_sources) + toNumber(event.suspicious_sources))],
          ['确认攻击源', fmt(event.confirmed_sources)],
          ['峰值带宽', fmt(event.peak_bps)],
          ['黑名单命中', fmt(evidence.blacklist_hits)],
          ['人工标签命中', fmt(evidence.manual_tag_hits)]
        ].map(item => `<div class="metric"><div class="label">${{item[0]}}</div><div class="value">${{item[1]}}</div></div>`).join('');

        document.getElementById('recommendationText').textContent = safeText(judgement.recommendation, '建议继续观察');
        const impact = judgement.impact_summary || {{}};
        document.getElementById('impactSummary').textContent = `受影响目标：${{safeText(impact.target_ip)}}，监测对象：${{safeText(impact.target_mo_name, '未识别')}}，高风险源：${{fmt(impact.risky_source_count)}}，峰值带宽：${{fmt(impact.peak_bps)}}。`;

        const findings = judgement.findings || [];
        document.getElementById('judgementFindings').innerHTML = findings.length ? findings.map(item => `<li>${{item}}</li>`).join('') : '<li>暂无研判摘要</li>';

        renderLineChart('eventTrend', data.time_distribution || [], [
          {{ key: 'unique_source_ips', color: '#d26d4b', label: '来源规模' }},
          {{ key: 'total_bytes', color: '#6f8b63', label: '总字节' }}
        ]);

        renderBarList('sourceClassBars', data.source_classes || [], 'traffic_class', 'ip_count');
        renderBarList('attackTypeBars', data.attack_type_mix || [], 'attack_type', 'ip_count', 'soft');
        renderBarList('clusterBars', data.cluster_mix || [], 'cluster_id', 'ip_count', 'good');
        renderBarList('geoBars', (data.geo_distribution || []).map(item => ({{...item, display: [item.src_country, item.src_province, item.src_isp].filter(Boolean).join(' / ') || '未标注'}})), 'display', 'unique_source_ips');
        renderBarList('entryBars', (data.entry_routers || []).map(item => ({{...item, display: [item.flow_ip_addr, item.input_if_index !== null && item.input_if_index !== undefined ? '接口 ' + item.input_if_index : ''].filter(Boolean).join(' / ')}})), 'display', 'unique_source_ips', 'good');

        const topSources = data.top_sources || [];
        document.getElementById('topSourceRows').innerHTML = topSources.length ? topSources.map(item => {{
          const intel = item.intel || {{}};
          const badges = [];
          if (toNumber(intel.blacklist_hit) > 0) badges.push('黑名单');
          if (toNumber(intel.whitelist_hit) > 0) badges.push('白名单');
          if (toNumber(intel.manual_tag_count) > 0) badges.push('人工标签');
          const geo = [item.country, item.province, item.city, item.isp].filter(Boolean).join(' / ') || '未标注';
          return `<tr><td>${{safeText(item.src_ip)}}</td><td>${{safeText(item.traffic_class)}}</td><td>${{fmt(item.attack_confidence)}}</td><td>${{safeText(item.best_attack_type, '未识别')}}</td><td>${{geo}}</td><td>${{badges.join('、') || '无明显命中'}}</td></tr>`;
        }}).join('') : '<tr><td colspan="6" class="empty">暂无高价值源对象</td></tr>';
      }})
      .catch(() => {{
        document.querySelector('.hero h1').textContent = '事件详情加载失败';
        document.querySelector('.hero p').textContent = '请检查事件编号和威胁情报库连接状态。';
      }});
    """
    return _intel_page(
        title="威胁情报事件详情",
        active="events",
        hero_title="事件详情",
        hero_subtitle="事件详情页不再平权展示所有字段，而是先给结论、再给证据、最后给必要的明细支撑。",
        body=body,
        script=script,
    )


def build_intel_source_rank_html() -> str:
    body = """
    <section class="grid three">
      <div class="panel">
        <h2>高关注攻击源</h2>
        <div class="subtle">只看疑似和确认来源，按置信度、攻击规模、峰值流量和事件覆盖度排序。</div>
        <div class="metric-grid" id="sourceStats"></div>
      </div>
      <div class="panel">
        <h2>活跃聚类</h2>
        <div class="subtle">多个源持续落在同一聚类，可能属于同一团伙或同类攻击基础设施。</div>
        <div class="bar-list" id="clusterRank"></div>
      </div>
      <div class="panel">
        <h2>来源地域排行</h2>
        <div class="subtle">帮助判断跨区域特征和潜在联动方向。数字含关联事件数和峰值流速。</div>
        <div class="bar-list" id="geoRank"></div>
      </div>
    </section>
    <section class="panel" style="margin-top:18px;">
      <h2>僵尸网段识别</h2>
      <div class="subtle">按 /24 网段聚合攻击源。同一网段内出现多个攻击源时，僵尸主机概率更高，值得重点封堵。</div>
      <div style="overflow:auto;">
        <table class="event-table">
          <thead>
            <tr>
              <th>网段 (/24)</th>
              <th>源 IP 数</th>
              <th>攻击类型</th>
              <th>关联事件</th>
              <th>峰值流速</th>
              <th>归属地 / 运营商</th>
              <th>成员 IP</th>
            </tr>
          </thead>
          <tbody id="prefixClusterRows"></tbody>
        </table>
      </div>
    </section>
    <section class="panel" style="margin-top:18px;">
      <h2>重点攻击源</h2>
      <div class="subtle">集中展示有效攻击源的事件贡献、攻击特征、归属地和情报命中；背景流量不进入主列表。</div>
      <div style="overflow:auto;">
        <table class="event-table">
          <thead>
            <tr>
              <th>源 IP</th>
              <th>风险分层</th>
              <th>出现事件数</th>
              <th>最高置信度</th>
              <th>攻击类型</th>
              <th>攻击特征</th>
              <th>地域 / 运营商</th>
              <th>情报命中</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody id="topSourcesRows"></tbody>
        </table>
      </div>
    </section>
    <style>
      .row-suspicious { background: rgba(255, 180, 87, 0.10) !important; border-left: 3px solid var(--warn) !important; }
      .row-confirmed { background: rgba(255, 111, 145, 0.08) !important; border-left: 3px solid var(--danger) !important; }
      .row-borderline { background: rgba(89, 240, 177, 0.06) !important; border-left: 3px solid var(--good) !important; }
      .btn-blacklist {
        display:inline-flex;align-items:center;justify-content:center;padding:6px 12px;border-radius:999px;
        border:1px solid rgba(255,111,145,0.24);background:rgba(255,111,145,0.10);color:var(--danger);
        font-size:12px;font-weight:700;cursor:pointer;transition:background 160ms ease;
      }
      .btn-blacklist:hover { background:rgba(255,111,145,0.22); }
      .btn-events {
        display:inline-flex;align-items:center;justify-content:center;padding:4px 10px;border-radius:999px;
        border:1px solid rgba(66,232,224,0.24);background:rgba(66,232,224,0.08);color:var(--accent);
        font-size:12px;font-weight:700;cursor:pointer;transition:background 160ms ease;
      }
      .btn-events:hover { background:rgba(66,232,224,0.18); }
      .popup-overlay {
        position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:100;display:flex;align-items:center;justify-content:center;
        backdrop-filter:blur(6px);
      }
      .popup-card {
        background:var(--panel);border:1px solid var(--line);border-radius:24px;padding:24px;max-width:520px;width:90%;
        box-shadow:var(--shadow-outer);max-height:80vh;overflow:auto;
      }
      .popup-card h3 { margin:0 0 12px;font-size:18px; }
      .popup-close {
        float:right;background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;
      }
    </style>
    """
    script = """
    const showEventPopup = (ip, eventIds) => {
      const overlay = document.createElement('div');
      overlay.className = 'popup-overlay';
      const listHtml = eventIds.length ? eventIds.map(id =>
        `<li style="margin-bottom:8px;"><a href="/intel/events/${encodeURIComponent(id)}" style="color:var(--accent);text-decoration:none;">${safeText(id)}</a></li>`
      ).join('') : '<li>无关联事件</li>';
      overlay.innerHTML = `<div class="popup-card">
        <button class="popup-close" onclick="this.closest('.popup-overlay').remove()">&times;</button>
        <h3>${safeText(ip)} 关联事件</h3>
        <div class="subtle">该攻击源参与的攻击事件列表（近 30 天）</div>
        <ul style="list-style:none;padding:0;">${listHtml}</ul>
      </div>`;
      overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
      document.body.appendChild(overlay);
    };

    const addToBlacklist = async (ip, confidence, attackTypes) => {
      const types = Array.isArray(attackTypes) ? attackTypes.join('、') : (attackTypes || '未识别');
      if (!confirm(`确认将 ${ip} 加入黑名单吗？\\n\\n置信度：${fmt(confidence)}\\n攻击类型：${types}`)) return;
      try {
        const res = await fetch('/api/v1/intel/assets/blacklist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            indicator_type: 'ip',
            indicator_value: ip,
            severity: confidence >= 80 ? 'high' : 'medium',
            confidence_score: confidence,
            source_name: 'manual',
            reason: `从攻击源排行加入，攻击类型：${types}，置信度：${confidence}`
          })
        });
        if (!res.ok) {
          const errText = await res.text();
          throw new Error(errText);
        }
        alert(`${ip} 已成功加入黑名单`);
        location.reload();
      } catch (err) {
        alert(`加入黑名单失败：${err.message}`);
      }
    };

    fetch('/api/v1/intel/top_sources?limit=30&min_events=1')
      .then(res => { if (!res.ok) throw new Error('top source fetch failed'); return res.json(); })
      .then(data => {
        document.getElementById('sourceStats').innerHTML = [
          ['高关注攻击源', fmt(data.total_repeat_sources), '近 30 天疑似及确认来源'],
          ['最高关联事件', fmt(data.max_repeat_count), '单一来源关联事件数'],
          ['跨事件来源', fmt(data.cross_target_sources), '同一来源命中多个事件']
        ].map(item => `<div class="metric"><div class="label">${item[0]}</div><div class="value">${item[1]}</div><div class="hint">${item[2]}</div></div>`).join('');

        const items = data.items || [];
        document.getElementById('topSourcesRows').innerHTML = items.length ? items.map(item => {
          const intel = item.intel || {};
          const tags = [];
          if (toNumber(intel.blacklist_hit) > 0) tags.push('黑名单');
          if (toNumber(intel.whitelist_hit) > 0) tags.push('白名单');
          if (Array.isArray(intel.manual_tags)) intel.manual_tags.forEach(tag => tags.push(tag));
          const geo = [item.country, item.province, item.city, item.isp].filter(Boolean).join(' / ') || '未标注';
          const attackTypes = Array.isArray(item.attack_type_list) ? item.attack_type_list.filter(Boolean) : [];
          const eventIds = Array.isArray(item.event_ids) ? item.event_ids : [];
          /* 修复风险分层逻辑：优先用 traffic_class，仅当为空时才用置信度推断 */
          const rawClass = safeText(item.traffic_class, '');
          const trafficClass = (rawClass === 'confirmed' || rawClass === 'suspicious' || rawClass === 'borderline')
            ? rawClass
            : (toNumber(item.max_confidence) >= 80 ? 'confirmed' : 'suspicious');
          const rowClass = trafficClass === 'confirmed' ? 'row-confirmed' : trafficClass === 'suspicious' ? 'row-suspicious' : trafficClass === 'borderline' ? 'row-borderline' : '';
          const badgeClass = trafficClass === 'confirmed' ? 'high' : trafficClass === 'suspicious' ? 'medium' : 'low';
          const classLabel = trafficClass === 'confirmed' ? '确认' : trafficClass === 'suspicious' ? '疑似' : trafficClass === 'borderline' ? '边界' : trafficClass;
          const features = [];
          if (toNumber(item.max_pps) > 0) features.push(`PPS ${fmt(item.max_pps)}`);
          if (toNumber(item.max_bps) > 0) features.push(`峰值流速 ${fmtBps(item.max_bps)}`);
          if (toNumber(item.max_burst_ratio) > 0) features.push(`burst ${fmt(item.max_burst_ratio)}`);
          if (toNumber(item.cluster_id)) features.push(`聚类 ${item.cluster_id}`);
          const contribution = [
            eventIds.length ? `event ${eventIds.slice(0, 2).join(' / ')}` : '',
            item.last_seen ? `last ${safeText(item.last_seen)}` : ''
          ].filter(Boolean).join('<br>');
          const alreadyBlacklisted = toNumber(intel.blacklist_hit) > 0;
          const eventDataAttr = encodeURIComponent(JSON.stringify(eventIds)).replace(/'/g, '&#39;');
          return `<tr class="${rowClass}">
            <td><a href="/intel/sources/${encodeURIComponent(item.src_ip)}" style="color:var(--accent);text-decoration:none;">${safeText(item.src_ip)}</a></td>
            <td><span class="status-badge ${badgeClass}">${classLabel}</span></td>
            <td><button class="btn-events" data-ip="${safeText(item.src_ip)}" data-events='${eventDataAttr}'>${fmt(item.event_count)} 个事件</button><div style="margin-top:6px;font-size:11px;color:var(--muted);">${contribution || '-'}</div></td>
            <td>${fmt(item.max_confidence)}</td>
            <td>${attackTypes.join('、') || '未识别'}</td>
            <td style="font-size:12px;color:var(--muted);">${features.join('；') || '-'}</td>
            <td>${geo}</td>
            <td>${tags.length ? tags.map(tag => `<span class="chip" style="font-size:11px;">${safeText(tag)}</span>`).join('') : '-'}</td>
            <td>${alreadyBlacklisted ? '<span style="color:var(--muted);font-size:12px;">已在黑名单</span>' : `<button class="btn-blacklist" data-blacklist-ip="${safeText(item.src_ip)}" data-blacklist-confidence="${toNumber(item.max_confidence)}" data-blacklist-types='${encodeURIComponent(JSON.stringify(attackTypes))}'>加入黑名单</button>`}</td>
          </tr>`;
        }).join('') : '<tr><td colspan="9" class="empty">暂无重复攻击源</td></tr>';

        /* 事件弹窗按钮绑定 */
        document.querySelectorAll('.btn-events').forEach(btn => {
          btn.addEventListener('click', () => {
            const ip = btn.dataset.ip;
            const eventIds = JSON.parse(decodeURIComponent(btn.dataset.events));
            showEventPopup(ip, eventIds);
          });
        });

        /* 黑名单按钮绑定 */
        document.querySelectorAll('[data-blacklist-ip]').forEach(btn => {
          btn.addEventListener('click', () => {
            const ip = btn.dataset.blacklistIp;
            const confidence = toNumber(btn.dataset.blacklistConfidence);
            const types = JSON.parse(decodeURIComponent(btn.dataset.blacklistTypes));
            addToBlacklist(ip, confidence, types);
          });
        });
      })
      .catch(() => { document.getElementById('topSourcesRows').innerHTML = '<tr><td colspan="9" class="empty">攻击源排行加载失败</td></tr>'; });
    fetch('/api/v1/intel/clusters?limit=10').then(res => res.ok ? res.json() : { items: [] }).then(data => {
      const clusterItems = (data.items || []).map(item => {
        const types = Array.isArray(item.attack_type_list) ? item.attack_type_list.filter(Boolean).join('、') : '';
        return { ...item, display: `${safeText(item.cluster_id)}${types ? ' (' + types + ')' : ''}` };
      });
      renderBarList('clusterRank', clusterItems, 'display', 'member_count', 'good');
    });
    fetch('/api/v1/intel/geo_rank?limit=10').then(res => res.ok ? res.json() : { items: [] }).then(data => {
      const geoItems = (data.items || []).map(item => ({
        ...item,
        display: [item.country, item.province, item.isp_name].filter(Boolean).join(' / '),
        geo_detail: `${fmt(item.ip_count)} IP / ${fmt(item.event_count)} 事件 / 峰值 ${fmtBps(item.peak_bps)}`
      }));
      const maxGeo = Math.max(...geoItems.map(i => toNumber(i.ip_count)), 1);
      document.getElementById('geoRank').innerHTML = geoItems.length ? geoItems.map(item => {
        const value = toNumber(item.ip_count);
        const width = Math.max(8, Math.round((value / maxGeo) * 100));
        return `<div class="bar-item"><div class="bar-head"><span>${safeText(item.display, '未标注')}</span><strong>${safeText(item.geo_detail)}</strong></div><div class="bar-track"><div class="bar-fill soft" style="width:${width}%"></div></div></div>`;
      }).join('') : '<div class="empty">暂无地域数据</div>';
    });
    fetch('/api/v1/intel/prefix_clusters?limit=20').then(res => res.ok ? res.json() : { items: [] }).then(data => {
      const items = data.items || [];
      document.getElementById('prefixClusterRows').innerHTML = items.length ? items.map(item => {
        const types = Array.isArray(item.attack_type_list) ? item.attack_type_list.filter(Boolean).join('、') : '未识别';
        const members = Array.isArray(item.member_ips) ? item.member_ips : [];
        const showMembers = members.slice(0, 5).join('、');
        const more = members.length > 5 ? `等 ${members.length} 个` : '';
        const geo = [item.country, item.province, item.isp].filter(Boolean).join(' / ') || '未知';
        const riskStyle = toNumber(item.ip_count) >= 5 ? 'color:var(--danger);font-weight:800;' : toNumber(item.ip_count) >= 3 ? 'color:var(--warn);font-weight:700;' : '';
        return `<tr>
          <td><span style="${{riskStyle}}">${safeText(item.ip_prefix)}.0/24</span></td>
          <td>${fmt(item.ip_count)}</td>
          <td>${safeText(types)}</td>
          <td>${fmt(item.event_count)}</td>
          <td>${fmtBps(item.max_bps)}</td>
          <td>${safeText(geo)}</td>
          <td style="font-size:12px;color:var(--muted);">${safeText(showMembers)}${safeText(more)}</td>
        </tr>`;
      }).join('') : '<tr><td colspan="7" class="empty">暂无网段聚类数据（需要同一网段内有 2 个以上攻击源）</td></tr>';
    });
    """
    return _intel_page(
        title="威胁情报攻击源排行",
        active="sources",
        hero_title="高关注攻击源",
        hero_subtitle="聚焦疑似与确认来源：谁在贡献攻击、具备哪些攻击特征、是否应该进入处置资产。",
        body=body,
        script=script,
    )


def build_intel_source_profile_html(ip: str) -> str:
    body = """
    <section class="grid">
      <div class="panel">
        <h2>源画像总览</h2>
        <div class="subtle">这里集中展示这个源对象的长期风险等级、地理信息、历史活跃度和情报命中。</div>
        <div class="metric-grid" id="profileMetrics"></div>
      </div>
      <div class="panel">
        <h2>情报与反馈</h2>
        <div class="subtle">运营知识沉淀会直接影响后续是否需要人工复核或避免误伤。</div>
        <ul class="key-points" id="profileIntel"></ul>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>月度趋势</h2>
        <div class="subtle">看这个源对象是偶发出现，还是已经形成持续性活动。</div>
        <div class="chart-card" id="profileTrend"></div>
      </div>
      <div class="panel">
        <h2>近期关联事件</h2>
        <div class="subtle">帮助快速回看它最近打过哪些目标。</div>
        <div style="overflow:auto;">
          <table class="event-table">
            <thead>
              <tr>
                <th>事件编号</th>
                <th>目标 IP</th>
                <th>严重级别</th>
                <th>攻击类型</th>
                <th>峰值带宽</th>
              </tr>
            </thead>
            <tbody id="profileEvents"></tbody>
          </table>
        </div>
      </div>
    </section>
    """
    script = f"""
    fetch('/api/v1/intel/source_profile/{ip}')
      .then(res => {{ if (!res.ok) throw new Error('source profile fetch failed'); return res.json(); }})
      .then(data => {{
        document.querySelector('.hero h1').textContent = `攻击源画像：${{safeText(data.ip)}}`;
        const geo = data.geo || {{}};
        document.querySelector('.hero p').textContent = `${{[geo.country, geo.province, geo.city, geo.isp].filter(Boolean).join(' / ') || '未标注地域'}}`;
        document.getElementById('profileMetrics').innerHTML = [
          ['风险等级', safeText(data.risk_level, '未知')],
          ['历史事件数', fmt(data.total_events)],
          ['最高置信度', fmt(data.max_confidence)],
          ['最近出现', safeText(data.last_seen)],
          ['首次出现', safeText(data.first_seen)],
          ['关联聚类', (data.cluster_ids || []).join('、') || '无']
        ].map(item => `<div class="metric"><div class="label">${{item[0]}}</div><div class="value">${{item[1]}}</div></div>`).join('');

        const intel = data.intel || {{}};
        const intelLines = [
          `黑名单命中条目：${{fmt((intel.blacklist || []).length)}}`,
          `白名单命中条目：${{fmt((intel.whitelist || []).length)}}`,
          `人工标签：${{(intel.manual_tags || []).map(item => item.tag_name).join('、') || '无'}}`,
          `反馈记录：${{fmt((data.feedback || []).length)}}`
        ];
        document.getElementById('profileIntel').innerHTML = intelLines.map(item => `<li>${{item}}</li>`).join('');

        renderLineChart('profileTrend', data.monthly_trend || [], [
          {{ key: 'event_count', color: '#d26d4b', label: '事件次数' }},
          {{ key: 'max_bps', color: '#6f8b63', label: '峰值带宽' }}
        ]);

        const events = data.recent_events || [];
        document.getElementById('profileEvents').innerHTML = events.length ? events.map(item => `
          <tr class="clickable" onclick="location.href='/intel/events/${encodeURIComponent(item.event_id)}'">
            <td>${safeText(item.event_id)}</td>
            <td>${safeText(item.target_ip)}</td>
            <td><span class="status-badge ${severityClass(item.severity)}">${safeText(item.severity)}</span></td>
            <td>${safeText(item.best_attack_type, '未识别')}</td>
            <td>${fmt(item.bytes_per_sec)}</td>
          </tr>
        `).join('') : '<tr><td colspan="5" class="empty">暂无关联事件</td></tr>';
      }})
      .catch(() => {{
        document.querySelector('.hero h1').textContent = '攻击源画像加载失败';
        document.querySelector('.hero p').textContent = '请检查源 IP 是否存在。';
      }});
    """
    return _intel_page(
        title="威胁情报攻击源画像",
        active="sources",
        hero_title="攻击源画像",
        hero_subtitle="源画像页聚焦一个对象的长期行为与情报命中，不再把所有明细当成同等重要的内容。",
        body=body,
        script=script,
    )


def _asset_page(title: str, endpoint: str, hero_title: str, hero_subtitle: str, columns: str, row_template: str, query: str = "") -> str:
    body = f"""
    <section class="panel">
      <h2>{hero_title}</h2>
      <div class="subtle">{hero_subtitle}</div>
      <div style="overflow:auto;">
        <table class="event-table">
          <thead><tr>{columns}</tr></thead>
          <tbody id="assetRows"></tbody>
        </table>
      </div>
    </section>
    """
    script = f"""
    fetch('{endpoint}{query}')
      .then(res => {{ if (!res.ok) throw new Error('asset fetch failed'); return res.json(); }})
      .then(data => {{
        const items = data.items || [];
        document.getElementById('assetRows').innerHTML = items.length ? items.map(item => `{row_template}`).join('') : '<tr><td colspan="6" class="empty">暂无数据</td></tr>';
      }})
      .catch(() => {{
        document.getElementById('assetRows').innerHTML = '<tr><td colspan="6" class="empty">数据加载失败</td></tr>';
      }});
    """
    return _intel_page(title, "assets", hero_title, hero_subtitle, body, script)


def build_intel_asset_blacklist_html() -> str:
    body = """
    <section class="panel">
      <h2>黑名单资产</h2>
      <div class="subtle">黑名单页服务于先验风险识别，重点看是否仍然生效、来源是否可靠、理由是否清楚。</div>
      <div style="overflow:auto;">
        <table class="event-table">
          <thead>
            <tr>
              <th>对象值</th>
              <th>严重级别</th>
              <th>置信分</th>
              <th>来源</th>
              <th>状态</th>
              <th>生效时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody id="assetRows"></tbody>
        </table>
      </div>
    </section>
    <style>
      .btn-release {
        display:inline-flex;align-items:center;justify-content:center;padding:6px 12px;border-radius:999px;
        border:1px solid rgba(66,232,224,0.24);background:rgba(66,232,224,0.08);color:var(--accent);
        font-size:12px;font-weight:700;cursor:pointer;
      }
      .btn-release:hover { background:rgba(66,232,224,0.18); }
    </style>
    """
    script = """
    const releaseBlacklist = async (item) => {
      const value = safeText(item.indicator_value);
      if (!confirm(`确认解除 ${value} 的黑名单状态吗？`)) return;
      try {
        const res = await fetch('/api/v1/intel/assets/blacklist/deactivate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            blacklist_id: item.blacklist_id,
            indicator_type: item.indicator_type || 'ip',
            indicator_value: value
          })
        });
        if (!res.ok) throw new Error(await res.text());
        location.reload();
      } catch (err) {
        alert(`解除失败：${err.message}`);
      }
    };

    fetch('/api/v1/intel/assets/blacklist?status=active&page=1&page_size=20')
      .then(res => { if (!res.ok) throw new Error('asset fetch failed'); return res.json(); })
      .then(data => {
        const items = data.items || [];
        document.getElementById('assetRows').innerHTML = items.length ? items.map((item, index) => `
          <tr>
            <td>${safeText(item.indicator_value)}</td>
            <td>${safeText(item.severity)}</td>
            <td>${fmt(item.confidence_score)}</td>
            <td>${safeText(item.source_name)}</td>
            <td>${safeText(item.status)}</td>
            <td>${safeText(item.effective_from || item.created_time)}</td>
            <td><button class="btn-release" data-release-index="${index}">解除</button></td>
          </tr>
        `).join('') : '<tr><td colspan="7" class="empty">暂无数据</td></tr>';
        document.querySelectorAll('[data-release-index]').forEach(btn => {
          btn.addEventListener('click', () => releaseBlacklist(items[toNumber(btn.dataset.releaseIndex)] || {}));
        });
      })
      .catch(() => {
        document.getElementById('assetRows').innerHTML = '<tr><td colspan="7" class="empty">数据加载失败</td></tr>';
      });
    """
    return _intel_page("威胁情报黑名单资产", "assets", "黑名单资产", "管理当前生效的黑名单对象，支持人工解除。", body, script)


def build_intel_asset_whitelist_html() -> str:
    return _asset_page(
        title="威胁情报白名单资产",
        endpoint="/api/v1/intel/assets/whitelist",
        hero_title="白名单资产",
        hero_subtitle="白名单用于控制误伤，是运营侧很关键的保障项之一。",
        columns="<th>对象值</th><th>作用范围</th><th>原因</th><th>来源</th><th>状态</th><th>生效时间</th>",
        row_template="<tr><td>${safeText(item.indicator_value)}</td><td>${safeText(item.scope_type)} / ${safeText(item.scope_value, '全局')}</td><td>${safeText(item.reason, '未填写')}</td><td>${safeText(item.source_name)}</td><td>${safeText(item.status)}</td><td>${safeText(item.effective_from)}</td></tr>",
        query="?status=active&page=1&page_size=20",
    )


def build_intel_asset_tags_html() -> str:
    return _asset_page(
        title="威胁情报人工标签",
        endpoint="/api/v1/intel/assets/tags",
        hero_title="人工标签资产",
        hero_subtitle="人工标签是研判经验沉淀，重点是数量、活跃度和最近是否还在被使用。",
        columns="<th>标签名称</th><th>关联对象数</th><th>最近使用时间</th>",
        row_template="<tr><td>${safeText(item.tag_name)}</td><td>${fmt(item.ip_count)}</td><td>${safeText(item.last_used)}</td></tr>",
        query="?page=1&page_size=20",
    )


def build_intel_asset_feedback_html() -> str:
    return _asset_page(
        title="威胁情报反馈记录",
        endpoint="/api/v1/intel/assets/feedback",
        hero_title="反馈记录",
        hero_subtitle="反馈记录体现运营与研判是否形成闭环，重点看动作、对象和值班人员留下的结论。",
        columns="<th>时间</th><th>事件编号</th><th>对象值</th><th>动作</th><th>分析人员</th><th>原因</th>",
        row_template="<tr><td>${safeText(item.created_time)}</td><td>${safeText(item.event_id)}</td><td>${safeText(item.indicator_value)}</td><td>${safeText(item.action)}</td><td>${safeText(item.analyst)}</td><td>${safeText(item.reason, '未填写')}</td></tr>",
        query="?page=1&page_size=20",
    )


def build_intel_event_detail_html(event_id: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Threat Event Detail</title>
  <style>
    :root {{
      --bg: #0f1720;
      --ink: #eff4f8;
      --muted: #9fb0be;
      --panel: rgba(16, 24, 32, 0.72);
      --line: rgba(255,255,255,0.08);
      --accent: #f97316;
      --accent-2: #22c55e;
      --accent-3: #38bdf8;
      --danger: #fb7185;
      --shadow: 0 24px 70px rgba(0,0,0,0.28);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI Variable Display", "Bahnschrift", "Trebuchet MS", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top right, rgba(249, 115, 22, 0.22), transparent 25%),
        radial-gradient(circle at bottom left, rgba(56, 189, 248, 0.18), transparent 30%),
        linear-gradient(180deg, #121c28 0%, var(--bg) 100%);
      min-height: 100vh;
    }}
    .shell {{ max-width: 1500px; margin: 0 auto; padding: 28px; }}
    .top, .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      backdrop-filter: blur(12px);
      box-shadow: var(--shadow);
    }}
    .top {{ padding: 26px; margin-bottom: 18px; }}
    .back {{ color: var(--ink); text-decoration: none; font-weight: 800; font-size: 13px; }}
    h1 {{ margin: 10px 0 6px; font-size: 40px; }}
    .sub {{ color: var(--muted); font-size: 14px; }}
    .hero-grid {{
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 12px;
      margin-top: 18px;
    }}
    .hero-stat {{
      padding: 16px;
      border-radius: 18px;
      background: rgba(255,255,255,0.04);
      border: 1px solid var(--line);
    }}
    .hero-stat .v {{ font-size: 24px; font-weight: 800; }}
    .hero-stat .t {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
    .grid {{
      display: grid;
      grid-template-columns: 1.1fr 0.9fr;
      gap: 18px;
    }}
    .stack {{ display: grid; gap: 18px; }}
    .panel {{ padding: 20px; }}
    .panel h2 {{ margin: 0 0 6px; font-size: 20px; }}
    .hint {{ color: var(--muted); font-size: 13px; margin-bottom: 14px; }}
    .chart {{ width: 100%; height: 260px; border-radius: 18px; border: 1px solid var(--line); background: rgba(255,255,255,0.03); }}
    .bars {{ display: grid; gap: 10px; }}
    .bar-row {{ display: grid; gap: 6px; }}
    .bar-head {{ display:flex; justify-content:space-between; gap:12px; font-size:13px; }}
    .bar-track {{ height: 12px; border-radius: 999px; background: rgba(255,255,255,0.08); overflow: hidden; }}
    .bar-fill {{ height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--accent), #fdba74); }}
    .bar-fill.alt {{ background: linear-gradient(90deg, var(--accent-2), #86efac); }}
    .bar-fill.blue {{ background: linear-gradient(90deg, var(--accent-3), #93c5fd); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px 10px; text-align: left; border-bottom: 1px solid var(--line); font-size: 13px; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 700; }}
    .badge {{
      display:inline-block;
      padding:5px 9px;
      border-radius:999px;
      font-size:11px;
      font-weight:800;
      margin-right:6px;
      margin-bottom:6px;
      background: rgba(255,255,255,0.08);
    }}
    .danger {{ background: rgba(251, 113, 133, 0.16); color: #fecdd3; }}
    .good {{ background: rgba(34, 197, 94, 0.16); color: #bbf7d0; }}
    .warn {{ background: rgba(249, 115, 22, 0.16); color: #fed7aa; }}
    .empty {{ color: var(--muted); text-align:center; padding:24px 0; }}
    @media (max-width: 1200px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .hero-grid {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    }}
    @media (max-width: 720px) {{
      .shell {{ padding: 16px; }}
      .hero-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      h1 {{ font-size: 30px; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <section class="top">
      <a class="back" href="/intel">返回 Dashboard</a>
      <h1 id="eventTitle">事件详情加载中...</h1>
      <div class="sub" id="eventSub">正在读取事件总览、趋势、来源画像和情报命中信息</div>
      <div class="hero-grid" id="heroStats"></div>
    </section>

    <section class="grid">
      <div class="stack">
        <section class="panel">
          <h2>时序趋势 Timeline</h2>
          <div class="hint">观察该事件在时间维度上的源规模和流量压力变化</div>
          <svg class="chart" id="timeChart" viewBox="0 0 760 260" preserveAspectRatio="none"></svg>
        </section>
        <section class="panel">
          <h2>高风险源明细 Top Sources</h2>
          <div class="hint">结合威胁情报命中、攻击置信度、聚类和地域做优先处置</div>
          <div style="overflow:auto;">
            <table>
              <thead>
                <tr>
                  <th>源IP</th>
                  <th>分类</th>
                  <th>置信度</th>
                  <th>攻击类型</th>
                  <th>速率</th>
                  <th>地域/运营商</th>
                  <th>情报命中</th>
                </tr>
              </thead>
              <tbody id="sourceRows"></tbody>
            </table>
          </div>
        </section>
      </div>

      <div class="stack">
        <section class="panel">
          <h2>分层画像</h2>
          <div class="hint">按流量分类、攻击类型、聚类群组查看风险结构</div>
          <div class="bars" id="classBars"></div>
          <div style="height:12px;"></div>
          <div class="bars" id="typeBars"></div>
          <div style="height:12px;"></div>
          <div class="bars" id="clusterBars"></div>
        </section>
        <section class="panel">
          <h2>地理与来源对象</h2>
          <div class="hint">判断跨区域扩散、骨干入口承压和监测对象受影响范围</div>
          <div class="bars" id="geoBars"></div>
          <div style="height:12px;"></div>
          <div class="bars" id="moBars"></div>
        </section>
        <section class="panel">
          <h2>入口节点 Entry Routers</h2>
          <div class="hint">用于定位最先承压的入口节点和接口</div>
          <div class="bars" id="entryBars"></div>
        </section>
      </div>
    </section>
  </div>
  <script>
    const eventId = {event_id!r};
    const fmt = (value) => {{
      if (value === null || value === undefined || value === '') return '-';
      const num = Number(value);
      if (!Number.isNaN(num) && Number.isFinite(num)) {{
        if (Math.abs(num) >= 1000000000) return (num / 1000000000).toFixed(2) + 'G';
        if (Math.abs(num) >= 1000000) return (num / 1000000).toFixed(2) + 'M';
        if (Math.abs(num) >= 1000) return (num / 1000).toFixed(1) + 'K';
      }}
      return String(value);
    }};
    const barList = (el, items, labelKey, valueKey, cls = '') => {{
      if (!items || !items.length) {{
        el.innerHTML = '<div class="empty">暂无数据</div>';
        return;
      }}
      const max = Math.max(...items.map(item => Number(item[valueKey] || 0)), 1);
      el.innerHTML = items.map(item => {{
        const value = Number(item[valueKey] || 0);
        const width = Math.max(6, Math.round(value / max * 100));
        const label = item[labelKey] || '未标注';
        return `<div class="bar-row">
          <div class="bar-head"><span>${{label}}</span><strong>${{fmt(value)}}</strong></div>
          <div class="bar-track"><div class="bar-fill ${{cls}}" style="width:${{width}}%"></div></div>
        </div>`;
      }}).join('');
    }};
    const renderTimeline = (el, points) => {{
      if (!points || !points.length) {{
        el.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#9fb0be">暂无时序数据</text>';
        return;
      }}
      const w = 760, h = 260, pad = 24;
      const maxBytes = Math.max(...points.map(p => Number(p.total_bytes || 0)), 1);
      const maxIps = Math.max(...points.map(p => Number(p.unique_source_ips || 0)), 1);
      const step = points.length === 1 ? 0 : (w - pad * 2) / (points.length - 1);
      const mk = (getter, maxVal) => points.map((p, idx) => {{
        const x = pad + step * idx;
        const y = h - pad - ((Number(getter(p)) || 0) / maxVal) * (h - pad * 2);
        return `${{idx === 0 ? 'M' : 'L'}} ${{x}} ${{y}}`;
      }}).join(' ');
      const bytesPath = mk(p => p.total_bytes, maxBytes);
      const ipPath = mk(p => p.unique_source_ips, maxIps);
      const labels = points.map((p, idx) => {{
        const x = pad + step * idx;
        const label = String(p.bucket_time || '').slice(11, 16) || String(p.bucket_time || '').slice(5, 16);
        return `<text x="${{x}}" y="${{h - 6}}" font-size="10" text-anchor="middle" fill="#9fb0be">${{label}}</text>`;
      }}).join('');
      el.innerHTML = `
        <path d="${{bytesPath}}" fill="none" stroke="#38bdf8" stroke-width="4" stroke-linecap="round"></path>
        <path d="${{ipPath}}" fill="none" stroke="#22c55e" stroke-width="4" stroke-linecap="round"></path>
        <text x="${{pad}}" y="${{pad}}" font-size="12" fill="#38bdf8">总字节</text>
        <text x="${{pad + 60}}" y="${{pad}}" font-size="12" fill="#22c55e">唯一源IP</text>
        ${{labels}}
      `;
    }};
    fetch(`/api/v1/intel/events/${{encodeURIComponent(eventId)}}`)
      .then(res => {{
        if (!res.ok) throw new Error('detail fetch failed');
        return res.json();
      }})
      .then(data => {{
        const event = data.event || {{}};
        document.getElementById('eventTitle').textContent = event.event_name || event.event_id || '未命名事件';
        document.getElementById('eventSub').textContent = `${{event.target_ip || '-'}} · ${{event.target_mo_name || '未识别监测对象'}} · ${{event.start_time || '-'}} ~ ${{event.end_time || '进行中'}}`;
        document.getElementById('heroStats').innerHTML = [
          ['严重级别', event.severity || 'medium'],
          ['源IP总量', fmt(event.total_source_ips)],
          ['Confirmed', fmt(event.confirmed_sources)],
          ['Suspicious', fmt(event.suspicious_sources)],
          ['峰值PPS', fmt(event.peak_pps)],
          ['峰值BPS', fmt(event.peak_bps)],
        ].map(([t, v]) => `<div class="hero-stat"><div class="v">${{v}}</div><div class="t">${{t}}</div></div>`).join('');

        renderTimeline(document.getElementById('timeChart'), data.time_distribution || []);
        barList(document.getElementById('classBars'), data.source_classes || [], 'traffic_class', 'ip_count');
        barList(document.getElementById('typeBars'), data.attack_type_mix || [], 'attack_type', 'ip_count', 'alt');
        barList(document.getElementById('clusterBars'), data.cluster_mix || [], 'cluster_id', 'ip_count', 'blue');
        barList(document.getElementById('geoBars'), (data.geo_distribution || []).map(item => ({{...item, label: [item.src_country, item.src_province, item.src_isp].filter(Boolean).join(' / ') || '未标注'}})), 'label', 'unique_source_ips');
        barList(document.getElementById('moBars'), (data.mo_distribution || []).map(item => ({{...item, label: item.src_mo_name || item.src_mo_code || '未标注'}})), 'label', 'attacking_source_ips', 'alt');
        barList(document.getElementById('entryBars'), (data.entry_routers || []).map(item => ({{...item, label: [item.flow_ip_addr, item.input_if_index !== null && item.input_if_index !== undefined ? 'if=' + item.input_if_index : ''].filter(Boolean).join(' / ')}})), 'label', 'unique_source_ips', 'blue');

        const rows = data.top_sources || [];
        document.getElementById('sourceRows').innerHTML = rows.length ? rows.map(item => {{
          const intel = item.intel || {{}};
          const badges = [];
          if ((intel.blacklist_hit || 0) > 0) badges.push(`<span class="badge danger">黑名单 ${{intel.blacklist_hit}}</span>`);
          if ((intel.whitelist_hit || 0) > 0) badges.push(`<span class="badge good">白名单 ${{intel.whitelist_hit}}</span>`);
          if ((intel.manual_tag_count || 0) > 0) badges.push(`<span class="badge warn">标签 ${{intel.manual_tag_count}}</span>`);
          (intel.manual_tags || []).slice(0, 3).forEach(tag => badges.push(`<span class="badge">${{tag}}</span>`));
          const geo = [item.country, item.province, item.city, item.isp].filter(Boolean).join(' / ') || '-';
          const rate = `PPS ${{fmt(item.packets_per_sec)}}<br>BPS ${{fmt(item.bytes_per_sec)}}`;
          return `<tr>
            <td>${{item.src_ip || '-'}}</td>
            <td>${{item.traffic_class || '-'}}</td>
            <td>${{fmt(item.attack_confidence)}}</td>
            <td>${{item.best_attack_type || '-'}}</td>
            <td>${{rate}}</td>
            <td>${{geo}}</td>
            <td>${{badges.join('') || '-'}}</td>
          </tr>`;
        }}).join('') : '<tr><td colspan="7" class="empty">暂无源明细数据</td></tr>';
      }})
      .catch(() => {{
        document.getElementById('eventTitle').textContent = '事件详情加载失败';
        document.getElementById('eventSub').textContent = '请检查 ClickHouse / MySQL 威胁情报库连接和事件ID是否存在';
      }});
  </script>
</body>
</html>"""


def build_intel_dashboard_html() -> str:
    body = """
    <section class="panel">
      <h2>运营关注总览</h2>
      <div class="subtle">先回答客户最关心的几个问题：近期事件规模、受影响目标、需要优先处置的对象，以及基础情报是否命中。</div>
      <div class="metric-grid" id="overviewCards"></div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>趋势变化</h2>
        <div class="subtle">按天看事件数量和高风险源数量，帮助判断压力是在抬升还是在回落。</div>
        <div class="chart-card" id="dashboardTrend"></div>
      </div>
      <div class="panel">
        <h2>情报资产概况</h2>
        <div class="subtle">黑名单、白名单、人工标签和反馈记录，是影响研判和处置的重要基础信息。</div>
        <div class="chip-row" id="mysqlSummary"></div>
        <div style="height:12px"></div>
        <div class="chip-row" id="manualTags"></div>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>优先关注事件</h2>
        <div class="subtle">优先级综合严重级别、确认攻击源数量、峰值带宽和风险规模计算，不再只看单一字段。</div>
        <div style="overflow:auto;">
          <table class="event-table">
            <thead>
              <tr>
                <th>事件编号</th>
                <th>目标 IP</th>
                <th>监测对象</th>
                <th>严重级别</th>
                <th>高风险源</th>
                <th>处置建议</th>
              </tr>
            </thead>
            <tbody id="priorityEventRows"></tbody>
          </table>
        </div>
      </div>
      <div class="panel">
        <h2>热点目标与来源结构</h2>
        <div class="subtle">用于快速判断哪些目标持续承压，以及来源风险分层和运营商热点大致落在哪里。</div>
        <div class="bar-list" id="targetHotspots"></div>
        <div style="height:14px"></div>
        <div class="bar-list" id="attackTypeBars"></div>
        <div style="height:14px"></div>
        <div class="chip-row" id="sourceClassChips"></div>
      </div>
    </section>
    """
    script = """
    fetch('/api/v1/intel/dashboard')
      .then(res => { if (!res.ok) throw new Error('dashboard fetch failed'); return res.json(); })
      .then(data => {
        const overview = data.overview || {};
        document.getElementById('overviewCards').innerHTML = [
          ['近 30 天事件数', fmt(overview.event_count_30d)],
          ['近 30 天目标 IP 数', fmt(overview.target_ip_count_30d)],
          ['近 30 天确认攻击源', fmt(overview.confirmed_sources_30d)],
          ['近 30 天疑似攻击源', fmt(overview.suspicious_sources_30d)],
          ['近 24 小时高严重事件', fmt(overview.high_severity_event_count_24h)],
          ['近 24 小时峰值带宽', fmt(overview.peak_bps_24h)],
        ].map(item => `<div class="metric"><div class="label">${item[0]}</div><div class="value">${item[1]}</div></div>`).join('');

        document.getElementById('mysqlSummary').innerHTML = [
          `黑名单：${fmt((data.mysql_summary || {}).blacklist_active)}`,
          `白名单：${fmt((data.mysql_summary || {}).whitelist_active)}`,
          `人工标签：${fmt((data.mysql_summary || {}).manual_tag_total)}`,
          `反馈记录：${fmt((data.mysql_summary || {}).feedback_total)}`
        ].map(text => `<span class="chip">${text}</span>`).join('');

        const tags = data.manual_tags || [];
        document.getElementById('manualTags').innerHTML = tags.length
          ? tags.map(item => `<span class="chip">${safeText(item.tag_name)} / ${fmt(item.tag_count)}</span>`).join('')
          : '<span class="chip">暂无人工标签统计</span>';

        renderLineChart('dashboardTrend', data.daily_trend || [], [
          { key: 'event_count', color: '#d26d4b', label: '事件数量' },
          { key: 'confirmed_sources', color: '#6f8b63', label: '确认攻击源' },
          { key: 'suspicious_sources', color: '#6c7dd8', label: '疑似攻击源' }
        ]);

        renderBarList('targetHotspots', data.target_hotspots || [], 'target_ip', 'risky_source_count');
        renderBarList('attackTypeBars', data.attack_type_distribution || [], 'attack_type', 'event_count', 'soft');

        const sourceClasses = data.source_class_distribution || [];
        document.getElementById('sourceClassChips').innerHTML = sourceClasses.length
          ? sourceClasses.map(item => `<span class="chip">${safeText(item.traffic_class, '未标注')} / ${fmt(item.ip_count)}</span>`).join('')
          : '<span class="chip">暂无来源分层数据</span>';

        const items = data.priority_events || [];
        document.getElementById('priorityEventRows').innerHTML = items.length ? items.map(item => `
          <tr class="clickable" onclick="location.href='/intel/events/${encodeURIComponent(item.event_id)}'">
            <td>${safeText(item.display_event_id)}</td>
            <td>${safeText(item.target_ip)}</td>
            <td>${safeText(item.target_mo_name, '未识别监测对象')}</td>
            <td><span class="status-badge ${severityClass(item.severity)}">${safeText(item.severity, 'medium')}</span></td>
            <td>${fmt(toNumber(item.confirmed_sources) + toNumber(item.suspicious_sources))}</td>
            <td>${safeText(item.action_hint, '建议继续观察')}</td>
          </tr>
        `).join('') : '<tr><td colspan="6" class="empty">暂无事件数据</td></tr>';
      })
      .catch(() => {
        document.querySelector('.hero h1').textContent = '威胁情报总览加载失败';
        document.querySelector('.hero p').textContent = '请检查 ClickHouse 与 MySQL 威胁情报库连接。';
      });
    """
    return _intel_page(
        title="威胁情报总览",
        active="overview",
        hero_title="威胁情报总览",
        hero_subtitle="这个页面优先呈现客户需要先知道的内容：现在严不严重、哪些目标在承压、哪些事件该先处置，以及现有情报是否已经命中。",
        body=body,
        script=script,
    )


def build_intel_event_list_html() -> str:
    body = """
    <section class="panel">
      <h2>事件检索</h2>
      <div class="subtle">事件列表负责完整浏览，详情页负责研判结论与图形化证据，两者职责分开，避免把所有字段都堆在一张表里。</div>
      <div class="toolbar">
        <select id="severity">
          <option value="">全部严重级别</option>
          <option value="critical">紧急</option>
          <option value="high">高</option>
          <option value="medium">中</option>
          <option value="low">低</option>
        </select>
        <input id="attackType" type="text" placeholder="攻击类型，例如 UDP Flood">
        <input id="targetIp" type="text" placeholder="目标 IP">
        <input id="targetMo" type="text" placeholder="监测对象">
        <select id="timeRange">
          <option value="24h">最近 24 小时</option>
          <option value="7d">最近 7 天</option>
          <option value="30d" selected>最近 30 天</option>
        </select>
        <select id="sortBy">
          <option value="time">按时间</option>
          <option value="bps">按峰值带宽</option>
          <option value="sources">按高风险源数</option>
        </select>
        <button class="link-button ghost-button" id="searchBtn">查询</button>
      </div>
      <div class="chip-row" id="eventSummary"></div>
    </section>
    <section class="panel" style="margin-top:18px;">
      <h2>事件列表</h2>
      <div style="overflow:auto;">
        <table class="event-table">
          <thead>
            <tr>
              <th>事件编号</th>
              <th>编号类型</th>
              <th>目标 IP</th>
              <th>监测对象</th>
              <th>攻击类型</th>
              <th>严重级别</th>
              <th>高风险源</th>
              <th>处置建议</th>
            </tr>
          </thead>
          <tbody id="eventListRows"></tbody>
        </table>
      </div>
    </section>
    """
    script = """
    const loadEvents = () => {
      const params = new URLSearchParams({
        severity: document.getElementById('severity').value,
        attack_type: document.getElementById('attackType').value,
        target_ip: document.getElementById('targetIp').value,
        target_mo: document.getElementById('targetMo').value,
        time_range: document.getElementById('timeRange').value,
        sort_by: document.getElementById('sortBy').value,
        page: '1',
        page_size: '20'
      });
      fetch(`/api/v1/intel/events_filtered?${params.toString()}`)
        .then(res => { if (!res.ok) throw new Error('event list fetch failed'); return res.json(); })
        .then(data => {
          const summary = data.severity_summary || {};
          document.getElementById('eventSummary').innerHTML = [
            `总事件数：${fmt(data.total)}`,
            `紧急：${fmt(summary.critical)}`,
            `高：${fmt(summary.high)}`,
            `中：${fmt(summary.medium)}`,
            `低：${fmt(summary.low)}`
          ].map(text => `<span class="chip">${text}</span>`).join('');

          const items = data.items || [];
          document.getElementById('eventListRows').innerHTML = items.length ? items.map(item => `
            <tr class="clickable" onclick="location.href='/intel/events/${encodeURIComponent(item.event_id)}'">
              <td>${safeText(item.display_event_id)}</td>
              <td>${safeText(item.display_event_type)}</td>
              <td>${safeText(item.target_ip)}</td>
              <td>${safeText(item.target_mo_name, '未识别监测对象')}</td>
              <td>${(item.attack_types || []).join('、') || '未识别'}</td>
              <td><span class="status-badge ${severityClass(item.severity)}">${safeText(item.severity, 'medium')}</span></td>
              <td>${fmt(toNumber(item.confirmed_sources) + toNumber(item.suspicious_sources))}</td>
              <td>${safeText(item.action_hint, '建议进一步研判')}</td>
            </tr>
          `).join('') : '<tr><td colspan="8" class="empty">没有匹配的事件</td></tr>';
        })
        .catch(() => {
          document.getElementById('eventListRows').innerHTML = '<tr><td colspan="8" class="empty">事件列表加载失败</td></tr>';
        });
    };
    document.getElementById('searchBtn').addEventListener('click', loadEvents);
    loadEvents();
    """
    return _intel_page(
        title="威胁情报事件列表",
        active="events",
        hero_title="事件列表",
        hero_subtitle="这里兼容攻击事件编号和分析事件编号两种模式，非 attack_id 的场景不再硬要求展示攻击编号。",
        body=body,
        script=script,
    )


def build_intel_event_detail_html(event_id: str) -> str:
    body = """
    <section class="grid">
      <div class="panel">
        <h2>研判结论</h2>
        <div class="subtle">先给结论和建议，再给支撑证据，避免让人先陷进大表格。</div>
        <div class="metric-grid" id="detailMetrics"></div>
        <div style="height:14px"></div>
        <div class="metric">
          <div class="label">建议动作</div>
          <div class="value" style="font-size:22px" id="recommendationText">正在加载...</div>
          <div class="hint" id="impactSummary"></div>
        </div>
      </div>
      <div class="panel">
        <h2>关键证据</h2>
        <div class="subtle">只展示真正支撑判断的少量证据，包括命中情报、热点来源和主要攻击表现。</div>
        <ul class="key-points" id="judgementFindings"></ul>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>结构与趋势</h2>
        <div class="subtle">时间趋势、来源分层、攻击类型和聚类结构是研判主干证据。</div>
        <div class="chart-card" id="eventTrend"></div>
        <div style="height:14px"></div>
        <div class="bar-list" id="sourceClassBars"></div>
        <div style="height:14px"></div>
        <div class="bar-list" id="attackTypeBars"></div>
        <div style="height:14px"></div>
        <div class="bar-list" id="clusterBars"></div>
      </div>
      <div class="panel">
        <h2>来源位置与入口压力</h2>
        <div class="subtle">帮助判断跨区域扩散、入口承压点和来源对象分布。</div>
        <div class="bar-list" id="geoBars"></div>
        <div style="height:14px"></div>
        <div class="bar-list" id="moBars"></div>
        <div style="height:14px"></div>
        <div class="bar-list" id="entryBars"></div>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>图形与报告</h2>
        <div class="subtle">这里直接集成分析输出目录中的图表和报告，不再让已有成果游离在页面之外。</div>
        <div id="artifactImages" class="gallery-grid"></div>
        <div style="height:14px"></div>
        <div id="artifactLinks" class="chip-row"></div>
      </div>
      <div class="panel">
        <h2>高价值源对象</h2>
        <div class="subtle">仅保留最值得复核的少量对象，并突出黑名单、白名单和人工标签命中情况。</div>
        <div style="overflow:auto;">
          <table class="event-table">
            <thead>
              <tr>
                <th>源 IP</th>
                <th>分类</th>
                <th>置信度</th>
                <th>攻击类型</th>
                <th>地域与运营商</th>
                <th>情报命中</th>
              </tr>
            </thead>
            <tbody id="topSourceRows"></tbody>
          </table>
        </div>
      </div>
    </section>
    """
    script = f"""
    fetch('/api/v1/intel/events/{event_id}')
      .then(res => {{ if (!res.ok) throw new Error('detail fetch failed'); return res.json(); }})
      .then(data => {{
        const event = data.event || {{}};
        const judgement = data.judgement || {{}};
        const impact = judgement.impact_summary || {{}};
        const evidence = judgement.evidence_summary || {{}};

        document.querySelector('.hero h1').textContent = safeText(event.event_label, '事件详情');
        document.querySelector('.hero p').textContent =
          `${{safeText(event.display_event_type, '事件编号')}}：${{safeText(event.display_event_id)}} / 目标 IP：${{safeText(event.target_ip)}} / 监测对象：${{safeText(event.target_mo_name, '未识别监测对象')}}`;

        document.getElementById('detailMetrics').innerHTML = [
          ['事件编号', safeText(event.display_event_id)],
          ['峰值带宽', fmt(event.peak_bps)],
          ['峰值包速率', fmt(event.peak_pps)],
          ['高风险源', fmt(toNumber(event.confirmed_sources) + toNumber(event.suspicious_sources))],
          ['黑名单命中', fmt(evidence.blacklist_hits)],
          ['人工标签命中', fmt(evidence.manual_tag_hits)]
        ].map(item => `<div class="metric"><div class="label">${{item[0]}}</div><div class="value">${{item[1]}}</div></div>`).join('');

        document.getElementById('recommendationText').textContent = safeText(judgement.recommendation, '建议继续观察');
        document.getElementById('impactSummary').textContent =
          `受影响目标：${{safeText(impact.target_ip)}}；监测对象：${{safeText(impact.target_mo_name, '未识别监测对象')}}；高风险源：${{fmt(impact.risky_source_count)}}；峰值带宽：${{fmt(impact.peak_bps)}}。`;

        const findings = judgement.findings || [];
        document.getElementById('judgementFindings').innerHTML = findings.length
          ? findings.map(item => `<li>${{item}}</li>`).join('')
          : '<li>暂无研判摘要</li>';

        renderLineChart('eventTrend', data.time_distribution || [], [
          {{ key: 'unique_source_ips', color: '#d26d4b', label: '来源规模' }},
          {{ key: 'total_bytes', color: '#6f8b63', label: '总字节数' }}
        ]);
        renderBarList('sourceClassBars', data.source_classes || [], 'traffic_class', 'ip_count');
        renderBarList('attackTypeBars', data.attack_type_mix || [], 'attack_type', 'ip_count', 'soft');
        renderBarList('clusterBars', data.cluster_mix || [], 'cluster_id', 'ip_count', 'good');
        renderBarList('geoBars', (data.geo_distribution || []).map(item => ({{ ...item, display: [item.src_country, item.src_province, item.src_isp].filter(Boolean).join(' / ') || '未标注' }})), 'display', 'unique_source_ips');
        renderBarList('moBars', (data.mo_distribution || []).map(item => ({{ ...item, display: item.src_mo_name || item.src_mo_code || '未标注' }})), 'display', 'attacking_source_ips', 'soft');
        renderBarList('entryBars', (data.entry_routers || []).map(item => ({{ ...item, display: [item.flow_ip_addr, item.input_if_index !== null && item.input_if_index !== undefined ? '接口 ' + item.input_if_index : ''].filter(Boolean).join(' / ') }})), 'display', 'unique_source_ips', 'good');

        const imageItems = data.artifact_images || [];
        document.getElementById('artifactImages').innerHTML = imageItems.length
          ? imageItems.map(item => `
              <a class="gallery-card" href="${{item.url}}" target="_blank" rel="noreferrer">
                <img src="${{item.url}}" alt="${{safeText(item.title)}}" style="width:100%; border-radius:18px; display:block;">
                <div class="hint" style="margin-top:10px;">${{safeText(item.title)}}</div>
              </a>
            `).join('')
          : '<div class="empty">暂无图形化产物</div>';

        const reportItems = [...(data.artifact_reports || []), ...(data.artifact_tables || [])];
        document.getElementById('artifactLinks').innerHTML = reportItems.length
          ? reportItems.map(item => `<a class="chip" href="${{item.url}}" target="_blank" rel="noreferrer">${{safeText(item.title)}}</a>`).join('')
          : '<span class="chip">暂无报告与表格</span>';

        const topSources = data.top_sources || [];
        document.getElementById('topSourceRows').innerHTML = topSources.length ? topSources.map(item => {{
          const intel = item.intel || {{}};
          const badges = [];
          if (toNumber(intel.blacklist_hit) > 0) badges.push('黑名单');
          if (toNumber(intel.whitelist_hit) > 0) badges.push('白名单');
          if (toNumber(intel.manual_tag_count) > 0) badges.push('人工标签');
          const geo = [item.country, item.province, item.city, item.isp].filter(Boolean).join(' / ') || '未标注';
          return `<tr>
            <td>${{safeText(item.src_ip)}}</td>
            <td>${{safeText(item.traffic_class, '未标注')}}</td>
            <td>${{fmt(item.attack_confidence)}}</td>
            <td>${{safeText(item.best_attack_type, '未识别')}}</td>
            <td>${{geo}}</td>
            <td>${{badges.join('、') || '暂无命中'}}</td>
          </tr>`;
        }}).join('') : '<tr><td colspan="6" class="empty">暂无高价值源对象</td></tr>';
      }})
      .catch(() => {{
        document.querySelector('.hero h1').textContent = '事件详情加载失败';
        document.querySelector('.hero p').textContent = '请检查事件编号、ClickHouse 数据回流和 output 目录产物。';
      }});
    """
    return _intel_page(
        title="威胁情报事件详情",
        active="events",
        hero_title="事件详情",
        hero_subtitle="详情页按“结论优先、证据支撑、图形辅助、明细下沉”的顺序组织，不再把所有信息平权展示。",
        body=body,
        script=script,
    )
