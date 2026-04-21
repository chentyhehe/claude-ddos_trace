from ddos_trace.threat_intel_browser import _intel_page


def build_intel_dashboard_html() -> str:
    body = """
    <section class="panel">
      <h2>威胁态势总览</h2>
      <div class="subtle">当前整体安全压力、需要优先关注的目标和事件、已有情报线索的命中情况。</div>
      <div class="metric-grid" id="overviewCards"></div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>近 14 天态势变化</h2>
        <div class="subtle">按日查看事件量、确认源数和峰值流速，判断压力趋势。数据不足时以卡片形式呈现。</div>
        <div id="trendGrid"></div>
      </div>
      <div class="panel">
        <h2>情报资产概况</h2>
        <div class="subtle">黑名单、白名单、人工标签和反馈记录会直接影响研判和处置。</div>
        <div class="metric-grid" id="assetCards"></div>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>重点事件</h2>
        <div class="subtle">需要优先查看的事件，可移除测试数据，系统会同步清理数据库和输出目录。</div>
        <div style="overflow:auto;">
          <table class="event-table">
            <thead>
              <tr>
                <th>事件编号</th>
                <th>目标 IP</th>
                <th>监测对象</th>
                <th>严重级别</th>
                <th>高风险源</th>
                <th>建议动作</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody id="priorityEventRows"></tbody>
          </table>
        </div>
      </div>
      <div class="panel">
        <h2>高疑似来源画像</h2>
        <div class="subtle">按源 IP 展示归属地、运营商、风险标签、情报命中和关联事件数，方便快速判断来源处置优先级。</div>
        <div style="overflow:auto;">
          <table class="event-table">
            <thead>
              <tr>
                <th>源 IP</th>
                <th>风险分层</th>
                <th>最高置信度</th>
                <th>归属地/运营商</th>
                <th>攻击类型</th>
                <th>情报标签</th>
                <th>关联事件</th>
              </tr>
            </thead>
            <tbody id="highRiskSourceRows"></tbody>
          </table>
        </div>
      </div>
    </section>
    <section class="grid three" style="margin-top:18px;">
      <div class="panel">
        <h2>攻击类型分布</h2>
        <div class="subtle" style="color:var(--accent);font-size:11px;">按近 30 天事件计数</div>
        <div class="bar-list" id="attackTypeBars"></div>
      </div>
      <div class="panel">
        <h2>目标承压排行</h2>
        <div class="subtle" style="color:var(--accent);font-size:11px;">按高风险源计数</div>
        <div class="bar-list" id="targetHotspots"></div>
      </div>
      <div class="panel">
        <h2>来源风险分层</h2>
        <div class="subtle">仅展示确认、疑似和边界流量。勾选可显示背景流量。</div>
        <label style="display:flex;align-items:center;gap:6px;margin-bottom:10px;font-size:12px;color:var(--muted);cursor:pointer;">
          <input type="checkbox" id="showBackground" style="accent-color:var(--accent);"> 显示背景流量
        </label>
        <div class="bar-list" id="sourceClassBars"></div>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>来源运营商分布</h2>
        <div class="subtle" style="color:var(--accent);font-size:11px;">按 IP 计数（仅确认、疑似、边界源）</div>
        <div class="bar-list" id="sourceIspBars"></div>
      </div>
      <div class="panel">
        <h2>来源地域分布</h2>
        <div class="subtle" style="color:var(--accent);font-size:11px;">按 IP 计数（仅确认、疑似、边界源）</div>
        <div class="bar-list" id="sourceGeoBars"></div>
      </div>
    </section>
    """
    script = """
    const removeEvent = async (eventId, label) => {
      if (!confirm(`确认移除事件 ${label || eventId} 吗？这会清空该事件的数据库结果和输出目录。`)) return;
      const res = await fetch(`/api/v1/intel/events/${encodeURIComponent(eventId)}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    };

    fetch('/api/v1/intel/dashboard')
      .then(res => { if (!res.ok) throw new Error('dashboard fetch failed'); return res.json(); })
      .then(data => {
        const overview = data.overview || {};
        document.getElementById('overviewCards').innerHTML = [
          ['24h 事件数', fmt(overview.event_count_24h)],
          ['24h 高危事件', fmt(overview.high_severity_event_count_24h)],
          ['24h 活跃目标', fmt(overview.target_ip_count_24h)],
          ['30d 事件数', fmt(overview.event_count_30d)],
          ['30d 确认源', fmt(overview.confirmed_sources_30d)],
          ['24h 峰值流速', fmtBps(overview.peak_bps_24h)]
        ].map(item => `<div class="metric"><div class="label">${item[0]}</div><div class="value">${item[1]}</div></div>`).join('');

        /* 趋势卡片替代折线图 */
        const trend = (data.daily_trend || []).slice(-14);
        const trendGrid = document.getElementById('trendGrid');
        if (trend.length === 0) {
          trendGrid.innerHTML = '<div class="empty">暂无趋势数据</div>';
        } else if (trend.length <= 5) {
          trendGrid.innerHTML = '<div class="grid" style="gap:12px;">' + trend.map(item => {
            const day = String(item.day || item.bucket_time || '').slice(5);
            return `<div class="metric"><div class="label">${safeText(day, '日期')}</div><div class="value" style="font-size:20px;">${fmt(item.event_count)} 事件</div><div class="hint">确认源 ${fmt(item.confirmed_sources)} / 峰值 ${fmtBps(item.peak_bps)}</div></div>`;
          }).join('') + '</div>';
        } else {
          trendGrid.innerHTML = '<div style="overflow:auto;"><table class="event-table"><thead><tr><th>日期</th><th>事件数</th><th>确认源</th><th>疑似源</th><th>峰值流速</th></tr></thead><tbody>' +
            trend.map(item => {
              const day = String(item.day || item.bucket_time || '').slice(5);
              return `<tr><td>${safeText(day)}</td><td>${fmt(item.event_count)}</td><td>${fmt(item.confirmed_sources)}</td><td>${fmt(item.suspicious_sources)}</td><td>${fmtBps(item.peak_bps)}</td></tr>`;
            }).join('') + '</tbody></table></div>';
        }

        /* 情报资产 */
        const mysqlSummary = data.mysql_summary || {};
        document.getElementById('assetCards').innerHTML = [
          ['生效黑名单', fmt(mysqlSummary.blacklist_active), '可直接提供先验风险证据'],
          ['生效白名单', fmt(mysqlSummary.whitelist_active), '用于避免误伤正常源'],
          ['人工标签', fmt(mysqlSummary.manual_tag_total), '长期研判知识沉淀'],
          ['反馈记录', fmt(mysqlSummary.feedback_total), '运营与分析闭环']
        ].map(item => `<div class="metric"><div class="label">${item[0]}</div><div class="value">${item[1]}</div><div class="hint">${item[2]}</div></div>`).join('');

        /* 攻击类型 */
        renderBarList('attackTypeBars', data.attack_type_distribution || [], 'attack_type', 'event_count', 'soft');
        /* 目标承压 */
        renderBarList('targetHotspots', data.target_hotspots || [], 'target_ip', 'risky_source_count', 'soft');

        /* 风险分层 - 默认隐藏 background */
        const sourceClasses = data.source_class_distribution || [];
        const renderSourceClass = (showBg) => {
          const filtered = showBg ? sourceClasses : sourceClasses.filter(item => item.traffic_class !== 'background');
          renderBarList('sourceClassBars', filtered.map(item => {
            const label = safeText(item.traffic_class, '未标注');
            const displayLabel = label === 'confirmed' ? '确认' : label === 'suspicious' ? '疑似' : label === 'borderline' ? '边界' : label === 'background' ? '背景' : label;
            return { ...item, display_class: displayLabel };
          }), 'display_class', 'ip_count');
        };
        renderSourceClass(false);
        document.getElementById('showBackground').addEventListener('change', (e) => renderSourceClass(e.target.checked));

        /* 运营商 */
        renderBarList('sourceIspBars', data.top_isps || [], 'isp_name', 'ip_count', 'good');
        /* 地域 */
        renderBarList('sourceGeoBars', (data.source_geo_distribution || []).map(item => ({
          ...item,
          display: [item.country, item.province].filter(Boolean).join(' / ') || '未知地域'
        })), 'display', 'ip_count', 'good');

        /* 高疑似来源画像 */
        const highRiskSources = data.high_risk_sources || [];
        document.getElementById('highRiskSourceRows').innerHTML = highRiskSources.length ? highRiskSources.map(item => {
          const intel = item.intel || {};
          const tags = [];
          if (toNumber(intel.blacklist_hit) > 0) tags.push('黑名单');
          if (toNumber(intel.whitelist_hit) > 0) tags.push('白名单');
          if (Array.isArray(intel.manual_tags)) intel.manual_tags.forEach(tag => tags.push(tag));
          const geo = [item.country, item.province, item.city, item.isp].filter(Boolean).join(' / ') || '未知归属';
          const attackTypes = Array.isArray(item.attack_type_list) ? item.attack_type_list.filter(Boolean).join('、') : safeText(item.attack_type_list);
          const displayTypes = attackTypes || '未识别';
          const rawClass = safeText(item.traffic_class, '');
          const classLabel = rawClass === 'confirmed' ? '确认' : rawClass === 'suspicious' ? '疑似' : rawClass;
          const classColor = rawClass === 'confirmed' ? '--danger' : rawClass === 'suspicious' ? '--warn' : '--muted';
          return `<tr>
            <td><a href="/intel/sources/${encodeURIComponent(item.src_ip)}" style="color:var(--accent)">${safeText(item.src_ip)}</a></td>
            <td><span style="color:var(${classColor});font-weight:700;">${safeText(classLabel, '未知')}</span></td>
            <td>${fmt(item.max_confidence)}</td>
            <td>${safeText(geo)}</td>
            <td>${safeText(displayTypes)}</td>
            <td>${tags.length ? tags.map(tag => `<span class="chip">${safeText(tag)}</span>`).join('') : '暂无命中'}</td>
            <td>${fmt(item.event_count)}</td>
          </tr>`;
        }).join('') : '<tr><td colspan="7" class="empty">暂无高疑似来源</td></tr>';

        /* 重点事件 */
        const items = data.priority_events || [];
        document.getElementById('priorityEventRows').innerHTML = items.length ? items.map(item => `
          <tr>
            <td><a href="/intel/events/${encodeURIComponent(item.event_id)}" style="color:var(--accent)">${safeText(item.display_event_id)}</a></td>
            <td>${safeText(item.target_ip)}</td>
            <td>${safeText(item.target_mo_name, '未识别监测对象')}</td>
            <td><span class="status-badge ${severityClass(item.severity)}">${safeText(item.severity, 'medium')}</span></td>
            <td>${fmt(toNumber(item.confirmed_sources) + toNumber(item.suspicious_sources))}</td>
            <td>${safeText(item.action_hint, '建议继续观察')}</td>
            <td><button class="chip" data-remove-event="${safeText(item.event_id)}" data-remove-label="${safeText(item.display_event_id)}">移除</button></td>
          </tr>
        `).join('') : '<tr><td colspan="7" class="empty">暂无事件数据</td></tr>';

        document.querySelectorAll('[data-remove-event]').forEach(button => {
          button.addEventListener('click', async (event) => {
            event.preventDefault();
            event.stopPropagation();
            try {
              await removeEvent(button.dataset.removeEvent, button.dataset.removeLabel);
              location.reload();
            } catch (error) {
              alert(`移除失败：${error.message}`);
            }
          });
        });
      })
      .catch((err) => {
        console.error('[THREAT_INTEL] dashboard load error:', err);
        document.querySelector('.hero h1').textContent = '威胁情报总览加载失败';
        document.querySelector('.hero p').textContent = '请检查 ClickHouse 与 MySQL 威胁情报库连接。';
      });
    """
    return _intel_page(
        title="威胁情报总览",
        active="overview",
        hero_title="威胁情报总览",
        hero_subtitle="当前压力是否在上升、哪些目标在承压、哪些事件要先处理、现有情报是否已有明确命中。",
        body=body,
        script=script,
    )


def build_intel_event_list_html() -> str:
    body = """
    <section class="panel">
      <h2>事件检索</h2>
      <div class="subtle">这里用于检索、筛选和比对事件。查询条件会实际生效，并保留在地址栏中，方便回看和分享。</div>
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
      <h2>检索结果</h2>
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
              <th>建议动作</th>
            </tr>
          </thead>
          <tbody id="eventListRows"></tbody>
        </table>
      </div>
    </section>
    """
    script = """
    const readQueryToForm = () => {
      const query = new URLSearchParams(location.search);
      document.getElementById('severity').value = query.get('severity') || '';
      document.getElementById('attackType').value = query.get('attack_type') || '';
      document.getElementById('targetIp').value = query.get('target_ip') || '';
      document.getElementById('targetMo').value = query.get('target_mo') || '';
      document.getElementById('timeRange').value = query.get('time_range') || '30d';
      document.getElementById('sortBy').value = query.get('sort_by') || 'time';
    };

    const loadEvents = () => {
      const params = new URLSearchParams({
        severity: document.getElementById('severity').value,
        attack_type: document.getElementById('attackType').value,
        target_ip: document.getElementById('targetIp').value,
        target_mo: document.getElementById('targetMo').value,
        time_range: document.getElementById('timeRange').value,
        sort_by: document.getElementById('sortBy').value,
        sort_order: 'desc',
        page: '1',
        page_size: '20'
      });
      history.replaceState(null, '', `/intel/events?${params.toString()}`);
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
              <td>${Array.isArray(item.attack_types) ? item.attack_types.join('、') : safeText(item.attack_types) || '未识别'}</td>
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

    readQueryToForm();
    document.getElementById('searchBtn').addEventListener('click', loadEvents);
    document.querySelectorAll('#severity, #timeRange, #sortBy').forEach(el => el.addEventListener('change', loadEvents));
    document.querySelectorAll('#attackType, #targetIp, #targetMo').forEach(el => {
      el.addEventListener('keydown', event => {
        if (event.key === 'Enter') loadEvents();
      });
    });
    loadEvents();
    """
    return _intel_page(
        title="威胁情报事件检索",
        active="events",
        hero_title="事件检索",
        hero_subtitle="这里兼容攻击事件编号和分析事件编号两种模式，非 attack_id 的场景也能完整展示和筛选。",
        body=body,
        script=script,
    )


def build_intel_event_detail_html(event_id: str) -> str:
    body = """
    <section class="grid">
      <div class="panel">
        <h2>研判结论</h2>
        <div class="subtle">先给结论和建议，再给支撑证据，避免把人拉进低价值的大列表里。</div>
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
        <div class="subtle">支撑判断的核心证据：主要攻击表现、热点来源、已命中的情报线索。</div>
        <ul class="key-points" id="judgementFindings"></ul>
      </div>
    </section>
    <section class="grid two" style="margin-top:18px;">
      <div class="panel">
        <h2>攻击时间线</h2>
        <div class="subtle">来源规模和流量的时序变化，判断攻击持续性和强度趋势。</div>
        <div class="chart-card" id="eventTrend"></div>
        <div style="height:14px"></div>
        <h3 style="font-size:15px;margin-bottom:8px;">来源结构</h3>
        <div class="subtle" style="color:var(--accent);font-size:11px;">按流量分类的源 IP 分布</div>
        <div class="bar-list" id="sourceClassBars"></div>
        <div style="height:14px"></div>
        <div class="subtle" style="color:var(--accent);font-size:11px;">按攻击类型分类</div>
        <div class="bar-list" id="attackTypeBars"></div>
        <div style="height:14px"></div>
        <div class="subtle" style="color:var(--accent);font-size:11px;">按聚类分组</div>
        <div class="bar-list" id="clusterBars"></div>
      </div>
      <div class="panel">
        <h2>来源位置与入口压力</h2>
        <div class="subtle">帮助定位主要来源区域、来源对象和入口承压点。</div>
        <div class="subtle" style="color:var(--accent);font-size:11px;">地域与运营商分布</div>
        <div class="bar-list" id="geoBars"></div>
        <div style="height:14px"></div>
        <div class="subtle" style="color:var(--accent);font-size:11px;">监测对象分布</div>
        <div class="bar-list" id="moBars"></div>
        <div style="height:14px"></div>
        <div class="subtle" style="color:var(--accent);font-size:11px;">入口路由 / 接口分布</div>
        <div class="bar-list" id="entryBars"></div>
      </div>
    </section>
    <section class="panel" style="margin-top:18px;">
      <h2>攻击态势</h2>
      <div class="subtle">综合态势评估：攻击源识别、聚类分布、疑似度分布、攻击持续时间。</div>
      <div class="grid two" style="margin-top:14px;">
        <div>
          <div class="metric-grid" id="postureMetrics" style="margin-bottom:14px;"></div>
          <div style="height:14px"></div>
          <div class="metric-grid" id="postureExtra" style="margin-bottom:14px;"></div>
          <div class="subtle" style="color:var(--accent);font-size:11px;margin-top:10px;">来源流量分类</div>
          <div class="bar-list" id="postureSourceClassBars"></div>
          <div style="height:14px"></div>
          <div class="subtle" style="color:var(--accent);font-size:11px;">攻击类型分布</div>
          <div class="bar-list" id="postureAttackTypeBars"></div>
        </div>
        <div>
          <div id="postureRadar" class="chart-card"></div>
          <div style="height:14px"></div>
          <div class="subtle" style="color:var(--accent);font-size:11px;">疑似度分布</div>
          <div class="bar-list" id="postureConfidenceBars"></div>
        </div>
      </div>
      <div style="margin-top:18px;overflow:auto;">
        <table class="event-table">
          <thead>
            <tr>
              <th>攻击源</th>
              <th>疑似等级</th>
              <th>攻击类型</th>
              <th>流量峰值</th>
              <th>归属地</th>
              <th>情报命中</th>
            </tr>
          </thead>
          <tbody id="postureSourceRows"></tbody>
        </table>
      </div>
      <div style="margin-top:18px;text-align:center;">
        <a class="link-button" id="attachmentsLink" href="#" target="_blank">查看事件附件</a>
      </div>
    </section>
    <section class="panel" style="margin-top:18px;">
      <h2>高价值源对象</h2>
      <div class="subtle">仅保留最值得复核的一小批对象，并突出黑名单、白名单和人工标签命中。</div>
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
          ['峰值流速', fmtBps(event.peak_bps)],
          ['峰值包速率', fmt(event.peak_pps)],
          ['高风险源', fmt(toNumber(event.confirmed_sources) + toNumber(event.suspicious_sources))],
          ['黑名单命中', fmt(evidence.blacklist_hits)],
          ['人工标签命中', fmt(evidence.manual_tag_hits)]
        ].map(item => `<div class="metric"><div class="label">${{item[0]}}</div><div class="value">${{item[1]}}</div></div>`).join('');

        document.getElementById('recommendationText').textContent = safeText(judgement.recommendation, '建议继续观察');
        document.getElementById('impactSummary').textContent =
          `目标 IP：${{safeText(impact.target_ip)}}；监测对象：${{safeText(impact.target_mo_name, '未识别监测对象')}}；高风险源：${{fmt(impact.risky_source_count)}}；峰值流速：${{fmtBps(impact.peak_bps)}}。`;

        const findings = judgement.findings || [];
        document.getElementById('judgementFindings').innerHTML = findings.length
          ? findings.map(item => `<li>${{item}}</li>`).join('')
          : '<li>暂无研判摘要</li>';

        /* 攻击时间线曲线 */
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

        /* ---- 攻击态势 ---- */
        const srcClasses = data.source_classes || [];
        const atkMix = data.attack_type_mix || [];
        const topSrc = data.top_sources || [];
        const confirmed = toNumber(event.confirmed_sources);
        const suspicious = toNumber(event.suspicious_sources);
        const borderline = toNumber(event.borderline_sources);
        const totalSources = confirmed + suspicious + borderline;
        const peakPps = toNumber(event.peak_pps);
        const peakBps = toNumber(event.peak_bps);
        const atkTypes = atkMix.length;

        document.getElementById('postureMetrics').innerHTML = [
          ['确认源', fmt(confirmed), 'danger', totalSources > 0 ? Math.round(confirmed / totalSources * 100) + '%' : ''],
          ['疑似源', fmt(suspicious), 'warn', totalSources > 0 ? Math.round(suspicious / totalSources * 100) + '%' : ''],
          ['边界源', fmt(borderline), 'muted', totalSources > 0 ? Math.round(borderline / totalSources * 100) + '%' : ''],
          ['攻击类型数', fmt(atkTypes), '', '']
        ].map(item => `<div class="metric"><div class="label">${{item[0]}}</div><div class="value" ${{item[2] && item[2] !== 'muted' ? 'style="color:var(--' + item[2] + ')"' : ''}}>${{item[1]}}</div>${{item[3] ? '<div class="hint">' + item[3] + '</div>' : ''}}</div>`).join('');

        /* 攻击持续时间 */
        let durationText = '-';
        if (event.start_time && event.end_time) {{
          try {{
            const s = new Date(event.start_time);
            const e = new Date(event.end_time);
            const diffMs = e - s;
            if (diffMs > 0) {{
              const hours = Math.floor(diffMs / 3600000);
              const mins = Math.floor((diffMs % 3600000) / 60000);
              durationText = hours > 0 ? `${{hours}} 小时 ${{mins}} 分钟` : `${{mins}} 分钟`;
            }}
          }} catch(ex) {{}}
        }}

        /* 主要聚类识别 */
        const clusterMix = data.cluster_mix || [];
        let mainCluster = '-';
        if (clusterMix.length > 0) {{
          const biggest = clusterMix.reduce((a, b) => toNumber(a.ip_count) > toNumber(b.ip_count) ? a : b);
          mainCluster = `${{safeText(biggest.cluster_id)}} (${{fmt(biggest.ip_count)}} 源)`;
        }}

        document.getElementById('postureExtra').innerHTML = [
          ['峰值流速', fmtBps(peakBps), ''],
          ['峰值包速率', fmt(peakPps) + ' pps', ''],
          ['攻击持续时间', durationText, ''],
          ['主要聚类', mainCluster, '']
        ].map(item => `<div class="metric"><div class="label">${{item[0]}}</div><div class="value" style="font-size:18px;">${{item[1]}}</div></div>`).join('');

        /* 来源分类条形图：主视图只突出疑似及以上，其余流量靠边展示 */
        const focusSrcClasses = srcClasses.filter(item => ['confirmed', 'suspicious'].includes(safeText(item.traffic_class, '')));
        const srcClassBars = focusSrcClasses.map(item => {{
          const cls = safeText(item.traffic_class, '');
          const displayLabel = cls === 'confirmed' ? '确认' : cls === 'suspicious' ? '疑似' : cls === 'borderline' ? '边界' : cls === 'background' ? '背景' : cls;
          return {{ ...item, display_class: displayLabel, fill_class: cls === 'confirmed' ? 'soft' : cls === 'suspicious' ? '' : cls === 'borderline' ? 'good' : 'good' }};
        }});
        renderBarList('postureSourceClassBars', srcClassBars, 'display_class', 'ip_count');
        renderBarList('postureAttackTypeBars', atkMix, 'attack_type', 'ip_count', 'soft');

        /* 雷达图 */
        const radarMetrics = [
          ['确认源', confirmed],
          ['疑似源', suspicious],
          ['边界源', borderline],
          ['峰值PPS', peakPps],
          ['峰值BPS', peakBps],
          ['攻击类型', atkTypes]
        ];
        const maxRadar = Math.max(...radarMetrics.map(item => item[1]), 1);
        const radarPoints = radarMetrics.map((item, idx) => {{
          const angle = Math.PI * 2 * idx / radarMetrics.length - Math.PI / 2;
          const radius = 28 + (item[1] / maxRadar) * 72;
          return [100 + Math.cos(angle) * radius, 100 + Math.sin(angle) * radius];
        }});
        const radarLabels = radarMetrics.map((item, idx) => {{
          const angle = Math.PI * 2 * idx / radarMetrics.length - Math.PI / 2;
          const x = 100 + Math.cos(angle) * 92;
          const y = 100 + Math.sin(angle) * 92;
          return `<text x="${{x}}" y="${{y}}" text-anchor="middle" fill="currentColor" font-size="10">${{safeText(item[0])}}</text>`;
        }}).join('');
        document.getElementById('postureRadar').innerHTML = `
          <svg viewBox="0 0 200 200" style="width:100%;height:100%;">
            <polygon points="${{radarPoints.map(p => p.join(',')).join(' ')}}" fill="rgba(210,109,75,0.28)" stroke="#d26d4b" stroke-width="3"></polygon>
            <circle cx="100" cy="100" r="72" fill="none" stroke="rgba(255,255,255,0.18)"></circle>
            <circle cx="100" cy="100" r="44" fill="none" stroke="rgba(255,255,255,0.12)"></circle>
            ${{radarLabels}}
          </svg>
        `;

        /* 疑似度分布 - 分颜色 */
        const confidenceBuckets = [
          {{ label: '高置信 (>=80)', count: 0, fill: 'soft' }},
          {{ label: '中置信 (60-80)', count: 0, fill: '' }},
          {{ label: '低置信 (<60)', count: 0, fill: 'good' }}
        ];
        topSrc.forEach(s => {{
          const c = toNumber(s.attack_confidence);
          if (c >= 80) confidenceBuckets[0].count++;
          else if (c >= 60) confidenceBuckets[1].count++;
          else confidenceBuckets[2].count++;
        }});
        renderBarList('postureConfidenceBars', confidenceBuckets, 'label', 'count', 'good');

        const focusSources = topSrc.filter(item => ['confirmed', 'suspicious'].includes(safeText(item.traffic_class, '')));
        document.getElementById('postureSourceRows').innerHTML = focusSources.length ? focusSources.map(item => {{
          const intel = item.intel || {{}};
          const cls = safeText(item.traffic_class, '');
          const label = cls === 'confirmed' ? '确认' : cls === 'suspicious' ? '疑似' : cls || '未标注';
          const color = cls === 'confirmed' ? 'var(--danger)' : 'var(--warn)';
          const geo = [item.country, item.province, item.city, item.isp].filter(Boolean).join(' / ') || '未标注';
          const hits = [];
          if (toNumber(intel.blacklist_hit) > 0) hits.push('黑名单');
          if (toNumber(intel.whitelist_hit) > 0) hits.push('白名单');
          if (toNumber(intel.manual_tag_count) > 0) hits.push('人工标签');
          return `<tr style="background:${{cls === 'suspicious' ? 'rgba(255,180,87,0.12)' : 'rgba(255,111,145,0.10)'}}">
            <td>${{safeText(item.src_ip)}}</td>
            <td><span style="color:${{color}};font-weight:800;">${{label}} / ${{fmt(item.attack_confidence)}}%</span></td>
            <td>${{safeText(item.best_attack_type, '未识别')}}</td>
            <td>${{fmtBps(item.bytes_per_sec || item.max_bps || 0)}} / ${{fmt(item.packets_per_sec || item.max_pps || 0)}} pps</td>
            <td>${{safeText(geo)}}</td>
            <td>${{hits.length ? hits.join('、') : '-'}}</td>
          </tr>`;
        }}).join('') : '<tr><td colspan="6" class="empty">暂无疑似及以上攻击源</td></tr>';

        /* 附件链接 */
        const attachmentsLink = document.getElementById('attachmentsLink');
        attachmentsLink.href = `/intel/events/${{encodeURIComponent('{event_id}')}}/attachments`;

        /* 高价值源对象表格 */
        document.getElementById('topSourceRows').innerHTML = topSrc.length ? topSrc.map(item => {{
          const intel = item.intel || {{}};
          const badges = [];
          if (toNumber(intel.blacklist_hit) > 0) badges.push('黑名单');
          if (toNumber(intel.whitelist_hit) > 0) badges.push('白名单');
          if (toNumber(intel.manual_tag_count) > 0) badges.push('人工标签');
          const geo = [item.country, item.province, item.city, item.isp].filter(Boolean).join(' / ') || '未标注';
          const rawClass = safeText(item.traffic_class, '');
          const classLabel = rawClass === 'confirmed' ? '确认' : rawClass === 'suspicious' ? '疑似' : rawClass === 'borderline' ? '边界' : rawClass;
          const classColor = rawClass === 'confirmed' ? 'var(--danger)' : rawClass === 'suspicious' ? 'var(--warn)' : 'var(--muted)';
          return `<tr>
            <td>${{safeText(item.src_ip)}}</td>
            <td><span style="color:${{classColor}};font-weight:700;">${{safeText(classLabel, '未标注')}}</span></td>
            <td>${{fmt(item.attack_confidence)}}</td>
            <td>${{safeText(item.best_attack_type, '未识别')}}</td>
            <td>${{geo}}</td>
            <td>${{badges.join('、') || '暂无命中'}}</td>
          </tr>`;
        }}).join('') : '<tr><td colspan="6" class="empty">暂无高价值源对象</td></tr>';
      }})
      .catch((err) => {{
        console.error('[THREAT_INTEL] event detail load error:', err);
        document.querySelector('.hero h1').textContent = '事件详情加载失败';
        document.querySelector('.hero p').textContent = '请检查事件编号、ClickHouse 数据回流和 output 目录产物。';
      }});
    """
    return _intel_page(
        title="威胁情报事件详情",
        active="events",
        hero_title="事件详情",
        hero_subtitle="先给研判结论，再给支撑证据，图形和明细下沉到后面。让运营侧第一时间掌握态势。",
        body=body,
        script=script,
    )


def build_intel_event_attachments_html(event_id: str) -> str:
    body = f"""
    <section class="panel">
      <h2>事件附件</h2>
      <div class="subtle">展示从分析输出文件中读取到的信息，支持在线预览和下载。</div>
      <div style="margin-bottom:14px;">
        <a class="link-button" href="/intel/events/{event_id}" style="font-size:13px;">返回事件详情</a>
      </div>
      <div class="chip-row" id="attachmentSummary"></div>
    </section>
    <section class="panel" style="margin-top:18px;">
      <h2>图片预览</h2>
      <div class="subtle">分析过程中生成的可视化图片，点击可查看大图。</div>
      <div class="grid two" id="imageGallery" style="margin-top:14px;"></div>
    </section>
    <section class="panel" style="margin-top:18px;">
      <h2>报告与数据文件</h2>
      <div class="subtle">分析报告、汇总表格和 JSON 数据文件，可按需下载查看。</div>
      <div style="overflow:auto;margin-top:14px;">
        <table class="event-table">
          <thead>
            <tr>
              <th>文件名</th>
              <th>类型</th>
              <th>大小</th>
              <th>创建时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody id="fileListRows"></tbody>
        </table>
      </div>
    </section>
    """
    script = f"""
    fetch('/api/v1/intel/events/{event_id}')
      .then(res => {{ if (!res.ok) throw new Error('detail fetch failed'); return res.json(); }})
      .then(data => {{
        const event = data.event || {{}};
        document.querySelector('.hero h1').textContent = safeText(event.event_label, '事件附件');
        document.querySelector('.hero p').textContent =
          `附件列表 / ${{safeText(event.display_event_id)}} / 目标 IP：${{safeText(event.target_ip)}}`;

        const attachments = data.attachments || data.artifacts || [];
        const images = attachments.filter(item => item.kind === 'image');
        const files = attachments.filter(item => item.kind !== 'image');

        document.getElementById('attachmentSummary').innerHTML = [
          `附件总数：${{fmt(attachments.length)}}`,
          `图片：${{fmt(images.length)}}`,
          `报告/表格：${{fmt(files.length)}}`
        ].map(text => `<span class="chip">${{text}}</span>`).join('');

        document.getElementById('imageGallery').innerHTML = images.length ? images.map(item => `
          <div class="panel" style="padding:14px;">
            <div style="font-size:13px;font-weight:700;margin-bottom:8px;">${{safeText(item.title || item.name)}}</div>
            <div style="border-radius:12px;overflow:hidden;background:rgba(0,0,0,0.2);">
              <img src="${{safeText(item.url)}}" alt="${{safeText(item.name)}}" style="width:100%;height:auto;display:block;cursor:pointer;" onclick="window.open('${{safeText(item.url)}}', '_blank')" />
            </div>
            <div style="margin-top:8px;display:flex;justify-content:space-between;align-items:center;">
              <span class="hint">${{safeText(item.kind)}} / ${{fmt(item.file_size)}} bytes</span>
              <a href="${{safeText(item.url)}}" download="${{safeText(item.name)}}" class="chip" style="text-decoration:none;">下载</a>
            </div>
          </div>
        `).join('') : '<div class="empty">暂无图片附件</div>';

        document.getElementById('fileListRows').innerHTML = files.length ? files.map(item => `
          <tr>
            <td>${{safeText(item.title || item.name)}}</td>
            <td><span class="chip">${{safeText(item.kind, '未知')}}</span></td>
            <td>${{fmt(item.file_size)}} bytes</td>
            <td>${{safeText(item.created_time)}}</td>
            <td><a href="${{safeText(item.url || item.storage_uri)}}" download="${{safeText(item.name)}}" class="chip" style="text-decoration:none;cursor:pointer;">下载</a></td>
          </tr>
        `).join('') : '<tr><td colspan="5" class="empty">暂无报告或表格文件</td></tr>';
      }})
      .catch(() => {{
        document.querySelector('.hero h1').textContent = '附件加载失败';
        document.querySelector('.hero p').textContent = '请检查事件编号和 ClickHouse 数据回流。';
      }});
    """
    return _intel_page(
        title="事件附件",
        active="events",
        hero_title="事件附件",
        hero_subtitle="展示分析输出文件，支持在线预览和下载。",
        body=body,
        script=script,
    )
