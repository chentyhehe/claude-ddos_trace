# 生产环境问题排查记录

更新时间：2026-04-29

本文基于现网日志 `ddos-trace.out` 梳理问题。结论先说：

- 主分析链路是成功的，`/api/v1/analyze/alert` 返回了 `200 OK`，报告和附件也在正常生成。
- 现网暴露出来的问题主要分两类：
  - 环境差异导致的告警或能力降级。
  - 威胁情报看板查询在现网 ClickHouse 版本/解析行为下触发的兼容性问题。
- 本次代码修改只触碰 `src/ddos_trace/data/threat_intel_dashboard.py` 的两条看板 SQL，不影响已有正常分析、报告生成、情报回流等主功能。

## 1. 问题清单

### 1.1 Python 缺少 `lzma` 扩展

- 日志特征：
  - `Could not import the lzma module. Your installed Python is incomplete.`
- 是否环境问题：是。
- 影响范围：
  - 当前项目主流程不依赖 `.xz` 压缩读写，分析任务可以继续执行。
  - 只有 pandas 处理 `xz/lzma` 压缩文件时才会真正报错。
- 根因判断：
  - 现网 Python 3.6 是手工编译或精简安装，缺少 `liblzma/xz-devel` 相关编译依赖，导致 `_lzma` 扩展没有编进解释器。
- 修复建议：
  - 重编 Python 前先安装系统依赖，例如 `xz-devel`。
  - 重新编译后执行 `python3 -c "import lzma"` 验证。
- 是否必须立刻修：否，属于告警级问题。

### 1.2 `hdbscan` 未安装，聚类自动降级到 DBSCAN

- 日志特征：
  - `[CLUSTER] hdbscan 未安装，尝试 DBSCAN`
- 是否环境问题：是。
- 影响范围：
  - 不会阻断分析。
  - 会影响聚类质量和聚类稳定性，尤其是复杂攻击指纹场景。
- 根因判断：
  - `hdbscan` 在项目中本来就是可选依赖；现网只安装了基础依赖，没有安装 `hdbscan` extra。
- 修复建议：
  - 如果现网需要更稳定的聚类结果，补装 `hdbscan`。
  - 如果现网以“先跑通”为目标，可以保持现状，因为代码已有 DBSCAN 兜底。
- 是否必须立刻修：否，属于能力增强项。

### 1.3 Matplotlib 缺少中文字体，生成 PNG 时大量 glyph warning

- 日志特征：
  - `RuntimeWarning: Glyph xxxx missing from current font.`
- 是否环境问题：是。
- 影响范围：
  - 不影响分析完成。
  - 会影响 PNG 图表中的中文显示，可能出现方块字、缺字或告警刷屏。
- 根因判断：
  - 代码已在 `ReportGenerator._prepare_matplotlib()` 中尝试查找 `Microsoft YaHei`、`SimHei`、`Noto Sans CJK SC`、`Source Han Sans SC`、`WenQuanYi Zen Hei` 等字体。
  - 现网机器没有这些字体，所以 matplotlib 退回到不支持中文的字体。
- 修复建议：
  - 安装任一支持中文的字体，例如 `Noto Sans CJK SC` 或 `WenQuanYi Zen Hei`。
  - 安装后清理 matplotlib 字体缓存，重启服务。
  - 验证方式：重新生成报告，确认日志不再刷 glyph warning，PNG 中文可读。
- 是否必须立刻修：否，但建议尽快修，能明显改善报告可读性和日志噪音。

### 1.4 威胁情报首页日趋势 SQL 使用了错误列引用

- 日志特征：
  - `Missing columns: 's.event_id'`
  - 出错 SQL 指向 `ti_attack_event_local_dist`
- 是否环境问题：不是纯环境问题，是代码兼容性问题，被现网环境放大。
- 影响范围：
  - 只影响 `/api/v1/intel/dashboard` 中的日趋势子查询。
  - 主分析、报告、情报写回不受影响。
- 根因判断：
  - 查询直接读的是事件表 `ti_attack_event_local[_dist]`，SQL 却写成了 `uniqExact(s.event_id)`。
  - 这个查询没有表别名 `s`，本地/测试可能没有覆盖到这条路径或没注意 warning，但现网明确报错。
- 修复方式：
  - 改为 `uniqExact(event_id)`。
- 本次已处理：是。

### 1.5 威胁情报首页高风险源 SQL 在现网 ClickHouse 上触发别名解析冲突

- 日志特征：
  - `Aggregate function any(traffic_class) is found in WHERE`
- 是否环境问题：属于“代码在不同 ClickHouse 版本/解析行为上的兼容性问题”。
- 影响范围：
  - 只影响 `/api/v1/intel/dashboard` 的高风险攻击源子查询。
  - API 因 `safe_ch()` 容错仍返回 `200`，但该卡片会丢数据。
- 根因判断：
  - SQL 里同时存在：
    - `any(traffic_class) AS traffic_class`
    - `WHERE ... traffic_class IN ('confirmed', 'suspicious')`
  - 在部分 ClickHouse 版本里，别名会提前参与解析，导致 `WHERE traffic_class` 被误解成聚合后的别名，从而触发“聚合函数不能出现在 WHERE”的报错。
- 修复方式：
  - 不再用 `any(traffic_class)`。
  - 改用优先级明确的聚合表达式：
    - `confirmed > suspicious > background`
  - 并将聚合结果先命名为 `source_traffic_class`，查询返回后再映射回 `traffic_class`，彻底避开同名别名冲突。
- 本次已处理：是。

## 2. 为什么本地和测试没出现

可能同时存在下面几种差异：

- ClickHouse 版本不同：
  - 旧版本或不同配置下，对 SELECT 别名和 WHERE 的解析更敏感。
- 测试库数据量和访问路径不同：
  - 看板接口未被频繁点击，warning 不容易暴露。
- 测试环境依赖更完整：
  - 本地 Windows 常自带中文字体。
  - 测试 Python 可能带有 `_lzma`。
  - 测试机器可能装过 `hdbscan`。
- 现网更接近真实使用方式：
  - 用户会同时看 `/intel`、`/intel/sources`、附件和图表，能把“查询兼容性问题”和“字体依赖问题”一起打出来。

## 3. 本次代码改动说明

文件：`src/ddos_trace/data/threat_intel_dashboard.py`

### 改动 1

- 位置：`get_dashboard() -> daily_trend`
- 修改前：
  - `uniqExact(s.event_id) AS event_count`
- 修改后：
  - `uniqExact(event_id) AS event_count`
- 风险评估：
  - 只是修正错误列引用，不改变业务语义。

### 改动 2

- 位置：`get_dashboard() -> high_risk_sources`
- 修改前：
  - `any(traffic_class) AS traffic_class`
- 修改后：
  - 用 `multiIf(sum(if(...)))` 按优先级聚合成 `source_traffic_class`
  - 查询返回后再映射成 `traffic_class`
- 风险评估：
  - 只影响看板展示层。
  - 相比 `any()`，新写法语义更稳定，也更符合项目里已有的 `confirmed > suspicious > borderline > background` 规则。

## 4. 建议的生产环境修复顺序

1. 先升级当前代码包，带上本次两条 SQL 修复。
2. 复测以下页面：
   - `/intel`
   - `/api/v1/intel/dashboard`
   - `/intel/sources`
3. 补中文字体，消除图表乱码和大批 warning。
4. 如果生产研判依赖聚类质量，再补装 `hdbscan`。
5. 如果后续需要处理压缩数据文件，再重装带 `_lzma` 的 Python。

## 5. 上线后验证项

- `POST /api/v1/analyze/alert` 仍返回 `200`。
- `output/` 下 Markdown、CSV、JSON、PNG 正常生成。
- `/api/v1/intel/dashboard` 不再出现以下 warning：
  - `Missing columns: 's.event_id'`
  - `Aggregate function any(traffic_class) is found in WHERE`
- `/intel` 首页“趋势”和“高风险攻击源”卡片恢复数据。
- 图表 PNG 中文显示正常，日志中 glyph warning 明显减少或消失。

## 6. 不建议的改法

- 不建议修改主分析链路来规避看板问题。
  - 当前问题发生在威胁情报展示层，不在 `analyzer` 主流程。
- 不建议直接关闭 matplotlib warning 或删除中文标题。
  - 这会掩盖真实的字体缺失问题，且降低报告可读性。
- 不建议把 `hdbscan` 改成强依赖。
  - 现有“可选安装 + 自动降级”策略更适合生产环境逐步补齐依赖。
