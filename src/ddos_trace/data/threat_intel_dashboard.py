import json
import logging
import os
import shutil
from datetime import date, datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence
from urllib.parse import quote

from ddos_trace.config.models import ClickHouseConfig, MySQLConfig, ThreatIntelConfig
from ddos_trace.data.threat_intel_lookup import ThreatIntelLookup

logger = logging.getLogger(__name__)


DEFAULT_THREAT_TYPE = "其他"
THREAT_TYPE_MAX_ITEMS = 100
THREAT_TYPE_ITEM_MAX_LENGTH = 32
THREAT_TYPE_ENUM = (
    "僵尸主机",
    "扫描探测",
    "漏洞利用",
    "Web攻击",
    "反射放大器",
    "代理僵尸",
    "Botnet控制器",
    "钓鱼欺诈",
    "恶意下载源",
    "其他",
)


class ThreatIntelDashboardRepository:
    """威胁情报页面的数据访问层。"""

    def __init__(
        self,
        clickhouse_config: ClickHouseConfig,
        mysql_config: MySQLConfig,
        threat_intel_config: Optional[ThreatIntelConfig] = None,
    ):
        self.clickhouse_config = clickhouse_config
        self.mysql_config = mysql_config
        self.config = threat_intel_config or ThreatIntelConfig()
        self._lookup = ThreatIntelLookup(mysql_config, self.config)
        self._ch_client = None
        self._table_cache: Dict[str, str] = {}
        self._output_root = Path(self.config.output_root or "./output").resolve()

    def _build_clickhouse_params(self) -> Dict[str, object]:
        return {
            "host": self.config.clickhouse_host or self.clickhouse_config.host,
            "port": int(self.config.clickhouse_port or self.clickhouse_config.port),
            "user": self.config.clickhouse_username or self.clickhouse_config.username,
            "password": self.config.clickhouse_password or self.clickhouse_config.password,
            "database": self.config.clickhouse_database,
            "connect_timeout": int(self.config.clickhouse_timeout or self.clickhouse_config.timeout),
            "send_receive_timeout": int(self.config.clickhouse_timeout or self.clickhouse_config.timeout),
        }

    def _build_mysql_params(self) -> Dict[str, object]:
        return {
            "host": self.config.mysql_host or self.mysql_config.host,
            "port": int(self.config.mysql_port or self.mysql_config.port),
            "user": self.config.mysql_username or self.mysql_config.username,
            "password": self.config.mysql_password or self.mysql_config.password,
            "database": self.config.mysql_database,
            "charset": self.config.mysql_charset or self.mysql_config.charset,
        }

    def _get_clickhouse_client(self):
        if self._ch_client is None:
            from clickhouse_driver import Client

            params = self._build_clickhouse_params()
            self._ch_client = Client(**params)
            self._ch_client.execute("SELECT 1")
        return self._ch_client

    def _get_mysql_connection(self):
        import pymysql

        params = self._build_mysql_params()
        params["cursorclass"] = pymysql.cursors.DictCursor
        return pymysql.connect(**params)

    def _get_table_name(self, base_name: str) -> str:
        cached = self._table_cache.get(base_name)
        if cached:
            return cached

        client = self._get_clickhouse_client()
        candidates = [f"{base_name}_dist", base_name]
        for candidate in candidates:
            rows = client.execute(
                """
                SELECT name
                FROM system.tables
                WHERE database = %(database)s AND name = %(table)s
                LIMIT 1
                """,
                {"database": self.config.clickhouse_database, "table": candidate},
            )
            if rows:
                self._table_cache[base_name] = candidate
                return candidate

        logger.warning("[THREAT_INTEL] ClickHouse 表 %s 及其 _dist 版本均不存在", base_name)
        self._table_cache[base_name] = base_name
        return base_name

    @staticmethod
    def _serialize_value(value):
        if isinstance(value, datetime):
            return value.isoformat(sep=" ", timespec="seconds")
        if isinstance(value, date):
            return value.isoformat()
        return value

    def _select_clickhouse(self, sql: str, params: Optional[Dict[str, object]] = None) -> List[Dict]:
        client = self._get_clickhouse_client()
        rows, meta = client.execute(sql, params or {}, with_column_types=True)
        columns = [col for col, _ in meta]
        return [
            {columns[idx]: self._serialize_value(value) for idx, value in enumerate(row)}
            for row in rows
        ]

    def _execute_clickhouse(self, sql: str, params: Optional[Dict[str, object]] = None):
        client = self._get_clickhouse_client()
        return client.execute(sql, params or {})

    def _select_mysql(self, sql: str, params: Optional[Sequence[object]] = None) -> List[Dict]:
        conn = self._get_mysql_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(sql, params or ())
                rows = cursor.fetchall()
                return [
                    {key: self._serialize_value(value) for key, value in row.items()}
                    for row in rows
                ]
        finally:
            conn.close()

    def _safe_mysql_count(self, sql: str) -> int:
        try:
            rows = self._select_mysql(sql)
        except Exception as exc:
            logger.warning("[THREAT_INTEL] MySQL 统计查询失败 / error[%s]", exc)
            return 0
        if not rows:
            return 0
        row = rows[0]
        first_value = next(iter(row.values()), 0)
        return int(first_value or 0)

    @staticmethod
    def _safe_float(value, default: float = 0.0) -> float:
        try:
            if value is None:
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_int(value, default: int = 0) -> int:
        try:
            if value is None:
                return default
            return int(float(value))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _parse_json_object(value) -> Dict[str, object]:
        if isinstance(value, dict):
            return value
        if not value:
            return {}
        try:
            parsed = json.loads(str(value))
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _quote_literal(value: object) -> str:
        text = str(value or "")
        return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"

    @staticmethod
    def normalize_threat_types(threat_types: Optional[Sequence[object]]) -> List[str]:
        normalized: List[str] = []
        for raw in threat_types or ():
            value = str(raw or "").strip()
            if not value:
                continue
            if len(value) > THREAT_TYPE_ITEM_MAX_LENGTH:
                raise ValueError(
                    "threat_type item length must be <= %s" % THREAT_TYPE_ITEM_MAX_LENGTH
                )
            if value not in normalized:
                normalized.append(value)

        if not normalized:
            raise ValueError("threat_type must contain at least one non-empty item")
        if len(normalized) > THREAT_TYPE_MAX_ITEMS:
            raise ValueError("threat_type item count must be <= %s" % THREAT_TYPE_MAX_ITEMS)
        return normalized

    @staticmethod
    def infer_threat_types(
        attack_types: Optional[Sequence[object]] = None,
        reason: str = "",
    ) -> List[str]:
        text_parts = [str(reason or "")]
        for item in attack_types or ():
            value = str(item or "").strip()
            if value:
                text_parts.append(value)
        haystack = " ".join(text_parts).lower()

        inferred: List[str] = []
        if any(token in haystack for token in ("cc", "http", "web", "xss", "sql", "注入")):
            inferred.append("Web攻击")
        if any(
            token in haystack
            for token in ("反射", "放大", "dns", "ntp", "ssdp", "cldap", "memcached")
        ):
            inferred.append("反射放大器")
        if any(token in haystack for token in ("扫描", "探测", "scan", "probe")):
            inferred.append("扫描探测")
        if any(token in haystack for token in ("漏洞", "利用", "exploit", "rce")):
            inferred.append("漏洞利用")
        if any(token in haystack for token in ("botnet", "c2", "僵尸", "肉鸡", "ddos")):
            inferred.append("僵尸主机")

        return inferred or [DEFAULT_THREAT_TYPE]

    @staticmethod
    def _json_to_list(value) -> List[str]:
        if isinstance(value, list):
            items = value
        elif isinstance(value, tuple):
            items = list(value)
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                return []
            try:
                decoded = json.loads(text)
            except (TypeError, ValueError, json.JSONDecodeError):
                return [text]
            if isinstance(decoded, list):
                items = decoded
            elif decoded:
                items = [decoded]
            else:
                return []
        else:
            return []

        result: List[str] = []
        for item in items:
            text = str(item or "").strip()
            if text and text not in result:
                result.append(text)
        return result

    def _guess_output_dir(self, event: Dict[str, object], overview: Optional[Dict[str, object]] = None) -> str:
        overview = overview or {}
        output_dir = str(overview.get("output_dir") or event.get("output_dir") or "").strip()
        if output_dir and Path(output_dir).exists():
            return str(Path(output_dir).resolve())
        if not self._output_root.exists():
            return output_dir

        candidates = [
            str(event.get("event_name", "") or "").strip(),
            str(event.get("event_id", "") or "").strip(),
            str(event.get("attack_id", "") or "").strip(),
        ]
        for candidate in candidates:
            if not candidate:
                continue
            direct_path = self._output_root / candidate
            if direct_path.is_dir():
                return str(direct_path.resolve())
            for matched in self._output_root.rglob(candidate):
                if matched.is_dir():
                    return str(matched.resolve())

        attack_id = str(event.get("attack_id", "") or "").strip()
        target_ip = str(event.get("target_ip", "") or "").strip()
        if attack_id:
            for matched in self._output_root.rglob(f"{attack_id}_*"):
                if matched.is_dir() and (not target_ip or target_ip in matched.name):
                    return str(matched.resolve())
        return output_dir

    def _build_artifact_gallery(self, output_dir: str) -> Dict[str, List[Dict[str, str]]]:
        if not output_dir:
            return {"all": [], "images": [], "reports": [], "tables": []}

        output_path = Path(output_dir).resolve()
        if not output_path.exists() or not output_path.is_dir():
            return {"all": [], "images": [], "reports": [], "tables": []}

        priority_map = {
            "attack_overview": 10,
            "source_risk_dashboard": 20,
            "operator_dashboard": 30,
            "overall_profile_radar": 40,
            "suspect_source_radar": 50,
            "attack_timeline": 60,
            "type_profile_radar": 70,
            "overall_attack_situation": 80,
            "overview_report": 90,
            "summary": 100,
        }
        items: List[Dict[str, str]] = []
        for file_path in sorted(output_path.iterdir()):
            if not file_path.is_file():
                continue
            suffix = file_path.suffix.lower()
            if suffix not in {".png", ".md", ".json", ".csv"}:
                continue
            try:
                rel_path = file_path.resolve().relative_to(self._output_root).as_posix()
            except ValueError:
                continue
            kind = "image" if suffix == ".png" else "report" if suffix in {".md", ".json"} else "table"
            priority = 999
            for key, value in priority_map.items():
                if key in file_path.name:
                    priority = value
                    break
            items.append(
                {
                    "name": file_path.name,
                    "title": file_path.stem.replace("_", " "),
                    "kind": kind,
                    "priority": str(priority),
                    "url": f"/artifacts/{quote(rel_path, safe='/')}",
                }
            )

        items.sort(key=lambda item: (int(item["priority"]), item["name"]))
        return {
            "all": items,
            "images": [item for item in items if item["kind"] == "image"],
            "reports": [item for item in items if item["kind"] == "report"],
            "tables": [item for item in items if item["kind"] == "table"],
        }

    def _build_artifact_url(self, path_value: str) -> str:
        path_text = str(path_value or "").strip()
        if not path_text:
            return ""
        try:
            rel_path = Path(path_text).resolve().relative_to(self._output_root).as_posix()
        except (ValueError, OSError):
            return ""
        return f"/artifacts/{quote(rel_path, safe='/')}"

    def _query_event_attachments(self, event_id: str, output_dir: str) -> Dict[str, List[Dict[str, str]]]:
        """Return persisted attachment metadata; local files are only a compatibility fallback."""
        db = self.config.clickhouse_database
        try:
            artifact_table = self._get_table_name("ti_event_artifact_local")
            rows = self._select_clickhouse(
                f"""
                SELECT
                    event_id,
                    artifact_name AS name,
                    artifact_title AS title,
                    artifact_kind AS kind,
                    file_ext,
                    file_size,
                    mime_type,
                    storage_uri,
                    download_url AS url,
                    checksum,
                    priority,
                    created_time
                FROM {db}.{artifact_table}
                WHERE event_id = %(event_id)s
                ORDER BY priority ASC, name ASC
                """,
                {"event_id": event_id},
            )
        except Exception as exc:
            logger.warning("[THREAT_INTEL] 附件元数据查询失败，降级读取本地目录 / event_id[%s] / error[%s]", event_id, exc)
            return self._build_artifact_gallery(output_dir)

        items = []
        for row in rows:
            item = dict(row)
            item["url"] = str(item.get("url") or "").strip() or self._build_artifact_url(item.get("storage_uri"))
            item["optional"] = True
            items.append(item)
        if not items:
            return self._build_artifact_gallery(output_dir)
        return {
            "all": items,
            "images": [item for item in items if item.get("kind") == "image"],
            "reports": [item for item in items if item.get("kind") == "report"],
            "tables": [item for item in items if item.get("kind") == "table"],
        }

    def _remove_output_dir(self, output_dir: str) -> bool:
        if not output_dir:
            return False
        try:
            output_path = Path(output_dir).resolve()
        except OSError:
            return False
        try:
            output_path.relative_to(self._output_root)
        except ValueError:
            logger.warning("[THREAT_INTEL] 输出目录不在 output 根目录下，跳过删除 / path[%s]", output_dir)
            return False
        if not output_path.exists() or not output_path.is_dir():
            return False
        shutil.rmtree(output_path)
        return True

    def _decorate_event(self, event: Dict[str, object]) -> Dict[str, object]:
        item = dict(event)
        overview = self._parse_json_object(item.get("overview_json"))
        display_event_id = (
            str(item.get("attack_id", "") or "").strip()
            or str(item.get("event_id", "") or "").strip()
            or str(item.get("event_name", "") or "").strip()
        )
        item["display_event_id"] = display_event_id
        item["display_event_type"] = "攻击事件编号" if str(item.get("attack_id", "") or "").strip() else "分析事件编号"
        item["event_label"] = str(item.get("event_name", "") or display_event_id or "未命名事件")
        item["overview"] = overview
        item["output_dir"] = self._guess_output_dir(item, overview)
        return item

    def delete_event_result(self, event_id: str) -> Dict[str, object]:
        event = self.get_event_detail(event_id)
        if event is None:
            return {"deleted": False, "event_id": event_id, "message": "event not found"}

        event_meta = event["event"]
        db = self.config.clickhouse_database
        event_tables = [
            "ti_attack_event_local",
            "ti_event_source_ip_local",
            "ti_event_entry_router_local",
            "ti_event_geo_distribution_local",
            "ti_event_mo_distribution_local",
            "ti_event_time_distribution_local",
            "ti_event_artifact_local",
        ]
        for table_name in event_tables:
            try:
                self._execute_clickhouse(
                    f"ALTER TABLE {db}.{table_name} DELETE WHERE event_id = %(event_id)s SETTINGS mutations_sync = 1",
                    {"event_id": event_id},
                )
            except Exception:
                if table_name != "ti_event_artifact_local":
                    raise
                logger.warning("[THREAT_INTEL] 附件表不存在或删除失败，跳过旧附件清理 / event_id[%s]", event_id)

        source_ips = [str(item.get("src_ip", "")).strip() for item in event.get("top_sources", []) if str(item.get("src_ip", "")).strip()]
        cluster_ids = [str(item.get("cluster_id", "")).strip() for item in event.get("top_sources", []) if str(item.get("cluster_id", "")).strip()]
        if source_ips:
            quoted_ips = ", ".join(self._quote_literal(ip) for ip in source_ips)
            self._execute_clickhouse(
                f"ALTER TABLE {db}.ti_ip_profile_local DELETE WHERE ip IN ({quoted_ips}) SETTINGS mutations_sync = 1"
            )
            start_time = event_meta.get("start_time")
            if start_time:
                self._execute_clickhouse(
                    f"""
                    ALTER TABLE {db}.ti_ip_daily_stat_local
                    DELETE WHERE stat_date = toDate(%(start_time)s) AND ip IN ({quoted_ips})
                    SETTINGS mutations_sync = 1
                    """,
                    {"start_time": start_time},
                )
        if cluster_ids:
            quoted_clusters = ", ".join(self._quote_literal(cluster_id) for cluster_id in cluster_ids)
            self._execute_clickhouse(
                f"ALTER TABLE {db}.ti_cluster_profile_local DELETE WHERE cluster_id IN ({quoted_clusters}) SETTINGS mutations_sync = 1"
            )

        output_deleted = self._remove_output_dir(str(event_meta.get("output_dir", "") or ""))
        return {
            "deleted": True,
            "event_id": event_id,
            "display_event_id": event_meta.get("display_event_id"),
            "output_deleted": output_deleted,
        }

    @staticmethod
    def _severity_rank(severity: str) -> int:
        ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return ranks.get(str(severity or "").lower(), 0)

    def _event_priority_score(self, event: Dict) -> float:
        severity = self._severity_rank(str(event.get("severity", "")))
        confirmed = self._safe_float(event.get("confirmed_sources"))
        suspicious = self._safe_float(event.get("suspicious_sources"))
        peak_bps = self._safe_float(event.get("peak_bps"))
        total_sources = self._safe_float(event.get("total_source_ips"))
        return severity * 30 + confirmed * 5 + suspicious * 2 + peak_bps / 1_000_000 + total_sources * 0.2

    def _build_action_hint(self, event: Dict) -> str:
        confirmed = self._safe_float(event.get("confirmed_sources"))
        suspicious = self._safe_float(event.get("suspicious_sources"))
        severity = str(event.get("severity", "medium")).lower()
        peak_bps = self._safe_float(event.get("peak_bps"))
        if severity in {"critical", "high"} or confirmed >= 20 or peak_bps >= 1_000_000_000:
            return "优先联动清洗与骨干侧排查"
        if confirmed >= 5 or suspicious >= 20:
            return "建议限速并持续追踪来源聚类"
        return "建议保持观察并结合情报标签复核"

    def get_dashboard(self, recent_limit: int = 12) -> Dict[str, object]:
        event_table = self._get_table_name("ti_attack_event_local")
        source_table = self._get_table_name("ti_event_source_ip_local")
        db = self.config.clickhouse_database

        def safe_ch(sql, params=None):
            try:
                return self._select_clickhouse(sql, params)
            except Exception as exc:
                logger.warning("[THREAT_INTEL] 看板 ClickHouse 查询失败 / error[%s]", exc)
                return []

        overview_rows = safe_ch(
            f"""
            SELECT
                countIf(start_time >= now() - INTERVAL 1 DAY) AS event_count_24h,
                uniqExactIf(target_ip, start_time >= now() - INTERVAL 1 DAY) AS target_ip_count_24h,
                uniqExactIf(target_mo_name, start_time >= now() - INTERVAL 1 DAY AND target_mo_name != '') AS monitor_object_count_24h,
                sumIf(confirmed_sources + suspicious_sources, start_time >= now() - INTERVAL 1 DAY) AS risky_source_count_24h,
                maxIf(peak_bps, start_time >= now() - INTERVAL 1 DAY) AS peak_bps_24h,
                countIf(start_time >= now() - INTERVAL 1 DAY AND severity IN ('critical', 'high')) AS high_severity_event_count_24h,
                count() AS event_count_30d,
                uniqExact(target_ip) AS target_ip_count_30d,
                sum(confirmed_sources) AS confirmed_sources_30d,
                sum(suspicious_sources) AS suspicious_sources_30d,
                sum(total_source_ips) AS source_ip_total_30d,
                max(peak_pps) AS peak_pps_30d,
                max(peak_bps) AS peak_bps_30d
            FROM {db}.{event_table}
            WHERE start_time >= now() - INTERVAL 30 DAY
            """
        )
        overview = overview_rows[0] if overview_rows else {}

        daily_trend = safe_ch(
            f"""
            SELECT
                toDate(start_time) AS day,
                uniqExact(s.event_id) AS event_count,
                sum(confirmed_sources) AS confirmed_sources,
                sum(suspicious_sources) AS suspicious_sources,
                max(peak_bps) AS peak_bps
            FROM {db}.{event_table}
            WHERE start_time >= today() - 13
            GROUP BY day
            ORDER BY day ASC
            """
        )

        attack_type_distribution = safe_ch(
            f"""
            SELECT attack_type, count() AS event_count
            FROM
            (
                SELECT arrayJoin(attack_types) AS attack_type
                FROM {db}.{event_table}
                WHERE start_time >= now() - INTERVAL 30 DAY
            )
            WHERE attack_type != ''
            GROUP BY attack_type
            ORDER BY event_count DESC
            LIMIT 10
            """
        )

        target_hotspots = safe_ch(
            f"""
            SELECT
                target_ip,
                any(target_mo_name) AS target_mo_name,
                count() AS event_count,
                sum(confirmed_sources + suspicious_sources) AS risky_source_count,
                max(peak_bps) AS peak_bps
            FROM {db}.{event_table}
            WHERE start_time >= now() - INTERVAL 30 DAY
            GROUP BY target_ip
            ORDER BY risky_source_count DESC, event_count DESC
            LIMIT 8
            """
        )

        monitor_hotspots = safe_ch(
            f"""
            SELECT
                if(target_mo_name = '', '未识别监测对象', target_mo_name) AS target_mo_name,
                count() AS event_count,
                sum(confirmed_sources + suspicious_sources) AS risky_source_count,
                max(peak_bps) AS peak_bps
            FROM {db}.{event_table}
            WHERE start_time >= now() - INTERVAL 30 DAY
            GROUP BY target_mo_name
            ORDER BY risky_source_count DESC, event_count DESC
            LIMIT 8
            """
        )

        source_class_distribution = safe_ch(
            f"""
            SELECT traffic_class, count() AS ip_count
            FROM {db}.{source_table}
            WHERE created_time >= now() - INTERVAL 30 DAY
            GROUP BY traffic_class
            ORDER BY ip_count DESC
            """
        )

        top_isps = safe_ch(
            f"""
            SELECT
                if(isp = '', '未知运营商', isp) AS isp_name,
                count() AS ip_count,
                max(bytes_per_sec) AS peak_bps
            FROM {db}.{source_table}
            WHERE created_time >= now() - INTERVAL 30 DAY
              AND traffic_class IN ('confirmed', 'suspicious', 'borderline')
            GROUP BY isp_name
            ORDER BY ip_count DESC, peak_bps DESC
            LIMIT 10
            """
        )

        source_geo_distribution = safe_ch(
            f"""
            SELECT
                if(country = '', '未知国家', country) AS country,
                if(province = '', '未知省份', province) AS province,
                if(isp = '', '未知运营商', isp) AS isp_name,
                traffic_class,
                count() AS ip_count,
                uniqExact(event_id) AS event_count,
                max(attack_confidence) AS max_confidence,
                max(bytes_per_sec) AS peak_bps
            FROM {db}.{source_table}
            WHERE created_time >= now() - INTERVAL 30 DAY
              AND traffic_class IN ('confirmed', 'suspicious', 'borderline')
            GROUP BY country, province, isp_name, traffic_class
            ORDER BY ip_count DESC, max_confidence DESC
            LIMIT 12
            """
        )

        high_risk_sources = safe_ch(
            f"""
            SELECT
                src_ip,
                any(country) AS country,
                any(province) AS province,
                any(city) AS city,
                any(isp) AS isp,
                any(traffic_class) AS traffic_class,
                max(attack_confidence) AS max_confidence,
                groupArray(DISTINCT best_attack_type) AS attack_type_list,
                uniqExact(event_id) AS event_count,
                max(bytes_per_sec) AS peak_bps
            FROM {db}.{source_table}
            WHERE created_time >= now() - INTERVAL 30 DAY
              AND traffic_class IN ('confirmed', 'suspicious')
            GROUP BY src_ip
            ORDER BY max_confidence DESC, event_count DESC, peak_bps DESC
            LIMIT 10
            """
        )
        high_risk_sources = self._build_source_intel_safe(high_risk_sources)

        recent_events = safe_ch(
            f"""
            SELECT
                event_id,
                attack_id,
                event_name,
                target_ip,
                target_mo_name,
                start_time,
                end_time,
                severity,
                total_source_ips,
                confirmed_sources,
                suspicious_sources,
                peak_pps,
                peak_bps
            FROM {db}.{event_table}
            ORDER BY start_time DESC
            LIMIT %(limit)s
            """,
            {"limit": int(recent_limit)},
        )
        for item in recent_events:
            item.update(self._decorate_event(item))
            item["priority_score"] = round(self._event_priority_score(item), 2)
            item["action_hint"] = self._build_action_hint(item)
        priority_events = sorted(recent_events, key=self._event_priority_score, reverse=True)[:6]

        mysql_summary = {
            "blacklist_active": self._safe_mysql_count(
                "SELECT COUNT(*) AS cnt FROM ti_blacklist WHERE status = 'active' AND (effective_to IS NULL OR effective_to >= NOW())"
            ),
            "whitelist_active": self._safe_mysql_count(
                "SELECT COUNT(*) AS cnt FROM ti_whitelist WHERE status = 'active' AND (effective_to IS NULL OR effective_to >= NOW())"
            ),
            "manual_tag_total": self._safe_mysql_count(
                "SELECT COUNT(*) AS cnt FROM ti_manual_tag"
            ),
            "feedback_total": self._safe_mysql_count(
                "SELECT COUNT(*) AS cnt FROM ti_feedback"
            ),
        }

        manual_tags = []
        try:
            manual_tags = self._select_mysql(
                """
                SELECT tag_name, COUNT(*) AS tag_count
                FROM ti_manual_tag
                GROUP BY tag_name
                ORDER BY tag_count DESC
                LIMIT 10
                """
            )
        except Exception as exc:
            logger.warning("[THREAT_INTEL] MySQL 标签聚合失败 / error[%s]", exc)

        return {
            "generated_at": self._serialize_value(datetime.now()),
            "overview": overview,
            "priority_events": priority_events,
            "daily_trend": daily_trend,
            "attack_type_distribution": attack_type_distribution,
            "target_hotspots": target_hotspots,
            "monitor_hotspots": monitor_hotspots,
            "source_class_distribution": source_class_distribution,
            "top_isps": top_isps,
            "source_geo_distribution": source_geo_distribution,
            "high_risk_sources": high_risk_sources,
            "recent_events": recent_events,
            "mysql_summary": mysql_summary,
            "manual_tags": manual_tags,
        }

    def list_events(self, limit: int = 50) -> List[Dict]:
        event_table = self._get_table_name("ti_attack_event_local")
        rows = self._select_clickhouse(
            f"""
            SELECT
                event_id,
                attack_id,
                event_name,
                target_ip,
                target_mo_name,
                start_time,
                end_time,
                severity,
                total_source_ips,
                confirmed_sources,
                suspicious_sources,
                borderline_sources,
                background_sources,
                peak_pps,
                peak_bps
            FROM {self.config.clickhouse_database}.{event_table}
            ORDER BY start_time DESC
            LIMIT %(limit)s
            """,
            {"limit": int(limit)},
        )
        return [self._decorate_event(row) for row in rows]

    def get_event_detail(self, event_id: str) -> Optional[Dict[str, object]]:
        event_table = self._get_table_name("ti_attack_event_local")
        source_table = self._get_table_name("ti_event_source_ip_local")
        geo_table = self._get_table_name("ti_event_geo_distribution_local")
        mo_table = self._get_table_name("ti_event_mo_distribution_local")
        time_table = self._get_table_name("ti_event_time_distribution_local")
        entry_table = self._get_table_name("ti_event_entry_router_local")

        event_rows = self._select_clickhouse(
            f"""
            SELECT *
            FROM {self.config.clickhouse_database}.{event_table}
            WHERE event_id = %(event_id)s
            ORDER BY updated_time DESC
            LIMIT 1
            """,
            {"event_id": event_id},
        )
        if not event_rows:
            return None

        event = self._decorate_event(event_rows[0])
        top_sources = self._select_clickhouse(
            f"""
            SELECT
                src_ip,
                traffic_class,
                attack_confidence,
                best_attack_type,
                matched_attack_types,
                packets_per_sec,
                bytes_per_sec,
                country,
                province,
                city,
                isp,
                cluster_id,
                confidence_reasons
            FROM {self.config.clickhouse_database}.{source_table}
            WHERE event_id = %(event_id)s
            ORDER BY attack_confidence DESC, bytes_per_sec DESC
            LIMIT 50
            """,
            {"event_id": event_id},
        )

        source_classes = self._select_clickhouse(
            f"""
            SELECT
                traffic_class,
                count() AS ip_count,
                round(avg(attack_confidence), 2) AS avg_confidence,
                max(attack_confidence) AS max_confidence
            FROM {self.config.clickhouse_database}.{source_table}
            WHERE event_id = %(event_id)s
            GROUP BY traffic_class
            ORDER BY ip_count DESC
            """,
            {"event_id": event_id},
        )

        attack_type_mix = self._select_clickhouse(
            f"""
            SELECT
                if(best_attack_type = '', '未识别', best_attack_type) AS attack_type,
                count() AS ip_count,
                max(bytes_per_sec) AS peak_bps
            FROM {self.config.clickhouse_database}.{source_table}
            WHERE event_id = %(event_id)s
            GROUP BY attack_type
            ORDER BY ip_count DESC, peak_bps DESC
            LIMIT 10
            """,
            {"event_id": event_id},
        )

        cluster_mix = self._select_clickhouse(
            f"""
            SELECT
                cluster_id,
                count() AS ip_count,
                max(attack_confidence) AS max_confidence
            FROM {self.config.clickhouse_database}.{source_table}
            WHERE event_id = %(event_id)s
              AND cluster_id != ''
            GROUP BY cluster_id
            ORDER BY ip_count DESC, max_confidence DESC
            LIMIT 10
            """,
            {"event_id": event_id},
        )

        geo_distribution = self._select_clickhouse(
            f"""
            SELECT *
            FROM {self.config.clickhouse_database}.{geo_table}
            WHERE event_id = %(event_id)s
            ORDER BY unique_source_ips DESC, total_bytes DESC
            LIMIT 12
            """,
            {"event_id": event_id},
        )

        mo_distribution = self._select_clickhouse(
            f"""
            SELECT *
            FROM {self.config.clickhouse_database}.{mo_table}
            WHERE event_id = %(event_id)s
            ORDER BY attacking_source_ips DESC, total_bytes DESC
            LIMIT 12
            """,
            {"event_id": event_id},
        )

        time_distribution = self._select_clickhouse(
            f"""
            SELECT *
            FROM {self.config.clickhouse_database}.{time_table}
            WHERE event_id = %(event_id)s
            ORDER BY bucket_time ASC
            """,
            {"event_id": event_id},
        )

        entry_routers = self._select_clickhouse(
            f"""
            SELECT *
            FROM {self.config.clickhouse_database}.{entry_table}
            WHERE event_id = %(event_id)s
            ORDER BY unique_source_ips DESC, total_bytes DESC
            LIMIT 10
            """,
            {"event_id": event_id},
        )

        intel_hits = self._build_source_intel(top_sources)
        judgement = self._build_event_judgement(event, intel_hits, source_classes, attack_type_mix, geo_distribution)
        attachment_gallery = self._query_event_attachments(event_id, str(event.get("output_dir", "") or ""))

        return {
            "event": event,
            "judgement": judgement,
            "source_classes": source_classes,
            "attack_type_mix": attack_type_mix,
            "cluster_mix": cluster_mix,
            "geo_distribution": geo_distribution,
            "mo_distribution": mo_distribution,
            "time_distribution": time_distribution,
            "entry_routers": entry_routers,
            "top_sources": intel_hits[:10],
            "attachments": attachment_gallery["all"],
            "artifacts": attachment_gallery["all"],
            "artifact_images": attachment_gallery["images"],
            "artifact_reports": attachment_gallery["reports"],
            "artifact_tables": attachment_gallery["tables"],
        }

    def _build_event_judgement(
        self,
        event: Dict,
        top_sources: List[Dict],
        source_classes: List[Dict],
        attack_type_mix: List[Dict],
        geo_distribution: List[Dict],
    ) -> Dict[str, object]:
        blacklist_hits = sum(int(item.get("intel", {}).get("blacklist_hit", 0) or 0) > 0 for item in top_sources)
        whitelist_hits = sum(int(item.get("intel", {}).get("whitelist_hit", 0) or 0) > 0 for item in top_sources)
        manual_tag_hits = sum(int(item.get("intel", {}).get("manual_tag_count", 0) or 0) > 0 for item in top_sources)
        top_attack = attack_type_mix[0]["attack_type"] if attack_type_mix else "未识别"
        top_geo = ""
        if geo_distribution:
            geo = geo_distribution[0]
            top_geo = " / ".join(
                str(geo.get(key, "")).strip()
                for key in ("src_country", "src_province", "src_isp")
                if str(geo.get(key, "")).strip()
            )
        confirmed = int(self._safe_float(event.get("confirmed_sources")))
        suspicious = int(self._safe_float(event.get("suspicious_sources")))
        risky_total = confirmed + suspicious
        severity = str(event.get("severity", "medium")).lower()

        if severity in {"critical", "high"} or confirmed >= 20:
            recommendation = "优先进入清洗联动，核查骨干入口与热点来源运营商。"
        elif risky_total >= 20:
            recommendation = "建议对重点来源聚类做限速或封堵预案，并持续观察趋势。"
        else:
            recommendation = "建议作为重点观察事件，结合情报标签和客户白名单持续复核。"

        findings = [
            f"本次事件高风险源共 {risky_total} 个，其中确认攻击源 {confirmed} 个。",
            f"主要攻击类型表现为 {top_attack}。",
            f"来源热点主要集中在 {top_geo or '地域信息不足'}。",
        ]
        if blacklist_hits:
            findings.append(f"高风险源中有 {blacklist_hits} 个命中黑名单，具备较强先验证据。")
        if manual_tag_hits:
            findings.append(f"高风险源中有 {manual_tag_hits} 个命中人工标签，可优先纳入研判。")
        if whitelist_hits:
            findings.append(f"同时存在 {whitelist_hits} 个白名单命中源，处置时应避免误伤。")

        return {
            "recommendation": recommendation,
            "impact_summary": {
                "target_ip": event.get("target_ip", ""),
                "target_mo_name": event.get("target_mo_name", ""),
                "risky_source_count": risky_total,
                "peak_bps": event.get("peak_bps", 0),
            },
            "evidence_summary": {
                "blacklist_hits": blacklist_hits,
                "whitelist_hits": whitelist_hits,
                "manual_tag_hits": manual_tag_hits,
                "top_attack_type": top_attack,
                "top_source_region": top_geo,
            },
            "findings": findings[:5],
        }

    # ------------------------------------------------------------------
    # 事件列表（带筛选、分页、排序）
    # ------------------------------------------------------------------

    def list_events_filtered(
        self,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
        target_ip: Optional[str] = None,
        target_mo: Optional[str] = None,
        time_range: str = "30d",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        sort_by: str = "time",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, object]:
        event_table = self._get_table_name("ti_attack_event_local")
        db = self.config.clickhouse_database

        where_clauses = ["1=1"]
        params: Dict[str, object] = {}

        # 时间范围
        if start_time and end_time:
            where_clauses.append("start_time >= %(start_time)s")
            where_clauses.append("start_time <= %(end_time)s")
            params["start_time"] = start_time
            params["end_time"] = end_time
        elif time_range == "24h":
            where_clauses.append("start_time >= now() - INTERVAL 1 DAY")
        elif time_range == "7d":
            where_clauses.append("start_time >= now() - INTERVAL 7 DAY")
        else:
            where_clauses.append("start_time >= now() - INTERVAL 30 DAY")

        # 严重级别
        if severity:
            sev_list = [s.strip() for s in severity.split(",") if s.strip()]
            if sev_list:
                placeholders = ", ".join([f"%(sev_{i})s" for i in range(len(sev_list))])
                where_clauses.append(f"severity IN ({placeholders})")
                for i, s in enumerate(sev_list):
                    params[f"sev_{i}"] = s

        # 攻击类型
        if attack_type:
            where_clauses.append(
                "arrayExists(x -> positionCaseInsensitiveUTF8(x, %(attack_type)s) > 0, attack_types)"
            )
            params["attack_type"] = attack_type

        # 目标IP
        if target_ip:
            where_clauses.append("target_ip LIKE %(target_ip_like)s")
            params["target_ip_like"] = f"%{target_ip}%"

        # 监测对象
        if target_mo:
            where_clauses.append("target_mo_name LIKE %(target_mo_like)s")
            params["target_mo_like"] = f"%{target_mo}%"

        where_sql = " AND ".join(where_clauses)

        # 排序
        sort_map = {
            "time": "start_time",
            "severity": "multiIf(severity = 'critical', 4, severity = 'high', 3, severity = 'medium', 2, severity = 'low', 1, 0)",
            "bps": "peak_bps",
            "sources": "confirmed_sources + suspicious_sources",
        }
        order_col = sort_map.get(sort_by, "start_time")
        order_dir = "DESC" if sort_order == "desc" else "ASC"

        offset = (page - 1) * page_size
        params["limit"] = int(page_size)
        params["offset"] = int(offset)

        # 总数
        count_sql = f"SELECT count() AS total FROM {db}.{event_table} WHERE {where_sql}"
        count_rows = self._select_clickhouse(count_sql, params)
        total = int(count_rows[0]["total"]) if count_rows else 0

        # 严重级别汇总
        summary_sql = f"""
            SELECT
                countIf(severity = 'critical') AS critical,
                countIf(severity = 'high') AS high,
                countIf(severity = 'medium') AS medium,
                countIf(severity = 'low') AS low
            FROM {db}.{event_table}
            WHERE {where_sql}
        """
        summary_rows = self._select_clickhouse(summary_sql, params)
        severity_summary = summary_rows[0] if summary_rows else {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # 数据
        data_sql = f"""
            SELECT
                event_id, attack_id, event_name, target_ip, target_mo_name,
                start_time, end_time, severity, attack_types,
                total_source_ips, confirmed_sources, suspicious_sources,
                borderline_sources, background_sources, peak_pps, peak_bps
            FROM {db}.{event_table}
            WHERE {where_sql}
            ORDER BY {order_col} {order_dir}
            LIMIT %(limit)s OFFSET %(offset)s
        """
        items = [self._decorate_event(row) for row in self._select_clickhouse(data_sql, params)]

        # 补充 action_hint
        for item in items:
            item["action_hint"] = self._build_action_hint(item)

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "severity_summary": severity_summary,
            "items": items,
        }

    # ------------------------------------------------------------------
    # 攻击源排行
    # ------------------------------------------------------------------

    def get_top_repeat_sources(self, limit: int = 50, min_events: int = 2) -> Dict[str, object]:
        source_table = self._get_table_name("ti_event_source_ip_local")
        event_table = self._get_table_name("ti_attack_event_local")
        db = self.config.clickhouse_database

        # 重复攻击源统计
        items = self._select_clickhouse(
            f"""
            SELECT
                s.src_ip AS src_ip,
                count() AS event_count,
                groupArray(DISTINCT s.best_attack_type) AS attack_type_list,
                max(s.created_time) AS last_seen,
                max(s.attack_confidence) AS max_confidence,
                max(s.bytes_per_sec) AS max_bps,
                any(s.country) AS country,
                any(s.province) AS province,
                any(s.city) AS city,
                any(s.isp) AS isp,
                any(s.cluster_id) AS cluster_id,
                multiIf(
                  sum(if(s.traffic_class = 'confirmed', 1, 0)) > 0, 'confirmed',
                  sum(if(s.traffic_class = 'suspicious', 1, 0)) > 0, 'suspicious',
                  sum(if(s.traffic_class = 'borderline', 1, 0)) > 0, 'borderline',
                  'background'
                ) AS traffic_class,
                groupArray(DISTINCT s.event_id) AS event_ids,
                max(s.packets_per_sec) AS max_pps,
                max(s.burst_ratio) AS max_burst_ratio,
                max(s.burst_count) AS max_burst_count
            FROM {db}.{source_table} AS s
            WHERE s.created_time >= now() - INTERVAL 30 DAY
              AND s.traffic_class IN ('confirmed', 'suspicious')
            GROUP BY s.src_ip
            HAVING event_count >= %(min_events)s
            ORDER BY max_confidence DESC, event_count DESC, max_bps DESC
            LIMIT %(limit)s
            """,
            {"limit": int(limit), "min_events": int(min_events)},
        )

        # 补充情报命中
        enriched = self._build_source_intel_safe(items)

        # 统计
        total_repeat = self._select_clickhouse(
            f"""
            SELECT count() AS total FROM (
                SELECT src_ip
                FROM {db}.{source_table}
                WHERE created_time >= now() - INTERVAL 30 DAY
                  AND traffic_class IN ('confirmed', 'suspicious')
                GROUP BY src_ip
            )
            """
        )
        max_repeat = enriched[0]["event_count"] if enriched else 0

        # 跨目标攻击源
        cross_target = self._select_clickhouse(
            f"""
            SELECT count() AS total FROM (
                SELECT src_ip
                FROM {db}.{source_table}
                WHERE created_time >= now() - INTERVAL 30 DAY
                  AND traffic_class IN ('confirmed', 'suspicious')
                GROUP BY src_ip
                HAVING uniqExact(event_id) >= 2
            )
            """
        )
        cross_target_count = int(cross_target[0]["total"]) if cross_target else 0

        return {
            "total_repeat_sources": int(total_repeat[0]["total"]) if total_repeat else 0,
            "max_repeat_count": int(max_repeat),
            "cross_target_sources": cross_target_count,
            "items": enriched,
        }

    def get_active_clusters(self, limit: int = 20) -> List[Dict]:
        source_table = self._get_table_name("ti_event_source_ip_local")
        cluster_table = self._get_table_name("ti_cluster_profile_local")
        db = self.config.clickhouse_database

        return self._select_clickhouse(
            f"""
            SELECT
                if(cluster_id = '', '未聚类', cluster_id) AS cluster_id,
                count() AS member_count,
                uniqExact(event_id) AS event_count,
                groupArray(DISTINCT best_attack_type) AS attack_type_list,
                max(attack_confidence) AS max_confidence,
                max(bytes_per_sec) AS max_bps,
                groupArray(DISTINCT country) AS country_list
            FROM {db}.{source_table}
            WHERE created_time >= now() - INTERVAL 30 DAY
              AND cluster_id != ''
            GROUP BY cluster_id
            ORDER BY member_count DESC, max_confidence DESC
            LIMIT %(limit)s
            """,
            {"limit": int(limit)},
        )

    def get_geo_rank(self, limit: int = 20) -> List[Dict]:
        source_table = self._get_table_name("ti_event_source_ip_local")
        db = self.config.clickhouse_database

        return self._select_clickhouse(
            f"""
            SELECT
                if(country = '', '未知', country) AS country,
                if(province = '', '未知', province) AS province,
                if(isp = '', '未知运营商', isp) AS isp_name,
                count() AS ip_count,
                uniqExact(event_id) AS event_count,
                max(bytes_per_sec) AS peak_bps
            FROM {db}.{source_table}
            WHERE created_time >= now() - INTERVAL 30 DAY
              AND traffic_class IN ('confirmed', 'suspicious', 'borderline')
            GROUP BY country, province, isp
            ORDER BY ip_count DESC, peak_bps DESC
            LIMIT %(limit)s
            """,
            {"limit": int(limit)},
        )

    def get_prefix_clusters(self, limit: int = 20) -> List[Dict]:
        """按 /24 网段聚合攻击源，识别僵尸主机高概率网段。"""
        source_table = self._get_table_name("ti_event_source_ip_local")
        db = self.config.clickhouse_database

        return self._select_clickhouse(
            f"""
            SELECT
                arrayStringConcat(arraySlice(splitByChar('.', src_ip), 1, 3), '.') AS ip_prefix,
                count() AS ip_count,
                groupArray(DISTINCT src_ip) AS member_ips,
                uniqExact(event_id) AS event_count,
                groupArray(DISTINCT best_attack_type) AS attack_type_list,
                max(attack_confidence) AS max_confidence,
                max(bytes_per_sec) AS max_bps,
                any(country) AS country,
                any(province) AS province,
                any(isp) AS isp
            FROM {db}.{source_table}
            WHERE created_time >= now() - INTERVAL 30 DAY
              AND traffic_class IN ('confirmed', 'suspicious', 'borderline')
            GROUP BY ip_prefix
            HAVING ip_count >= 2
            ORDER BY ip_count DESC, max_confidence DESC
            LIMIT %(limit)s
            """,
            {"limit": int(limit)},
        )

    # ------------------------------------------------------------------
    # 源 IP 画像
    # ------------------------------------------------------------------

    def get_source_profile(self, ip: str) -> Optional[Dict[str, object]]:
        source_table = self._get_table_name("ti_event_source_ip_local")
        profile_table = self._get_table_name("ti_ip_profile_local")
        event_table = self._get_table_name("ti_attack_event_local")
        db = self.config.clickhouse_database

        # 基本画像
        profile_rows = self._select_clickhouse(
            f"""
            SELECT *
            FROM {db}.{profile_table}
            WHERE ip = %(ip)s
            ORDER BY updated_time DESC
            LIMIT 1
            """,
            {"ip": ip},
        )

        # 如果 profile 表没有，从 source_ip 表聚合
        if not profile_rows:
            profile_rows = self._select_clickhouse(
                f"""
                SELECT
                    src_ip AS ip,
                    max(attack_confidence) AS risk_score,
                    count() AS hit_count,
                    min(created_time) AS first_seen_time,
                    max(created_time) AS last_seen_time,
                    any(country) AS country,
                    any(province) AS province,
                    any(city) AS city,
                    any(isp) AS isp,
                    groupArray(DISTINCT best_attack_type) AS attack_type_list,
                    groupArray(DISTINCT cluster_id) AS cluster_ids
                FROM {db}.{source_table}
                WHERE src_ip = %(ip)s
                GROUP BY src_ip
                LIMIT 1
                """,
                {"ip": ip},
            )

        if not profile_rows:
            return None

        profile = profile_rows[0]

        # 历史事件列表
        recent_events = self._select_clickhouse(
            f"""
            SELECT
                e.event_id,
                e.target_ip,
                e.target_mo_name,
                e.start_time,
                e.severity,
                s.attack_confidence,
                s.best_attack_type,
                s.bytes_per_sec,
                s.traffic_class
            FROM {db}.{source_table} s
            INNER JOIN {db}.{event_table} e ON s.event_id = e.event_id
            WHERE s.src_ip = %(ip)s
            ORDER BY e.start_time DESC
            LIMIT 30
            """,
            {"ip": ip},
        )

        # 月度趋势
        monthly_trend = self._select_clickhouse(
            f"""
            SELECT
                toYYYYMM(created_time) AS month,
                count() AS event_count,
                max(attack_confidence) AS max_confidence,
                max(bytes_per_sec) AS max_bps
            FROM {db}.{source_table}
            WHERE src_ip = %(ip)s
            GROUP BY month
            ORDER BY month ASC
            """,
            {"ip": ip},
        )

        # 情报命中
        intel = {}
        try:
            intel_map = self._lookup.load_ip_intel([ip])
            intel = intel_map.get(ip, {})
        except Exception as exc:
            logger.warning("[THREAT_INTEL] 源IP画像情报查询失败 / ip[%s] / error[%s]", ip, exc)

        # 反馈记录
        feedback = []
        try:
            feedback = self._select_mysql(
                "SELECT * FROM ti_feedback WHERE indicator_type = 'ip' AND indicator_value = %s ORDER BY created_time DESC LIMIT 20",
                [ip],
            )
        except Exception as exc:
            logger.warning("[THREAT_INTEL] 源IP反馈查询失败 / error[%s]", exc)

        return {
            "ip": ip,
            "profile": profile,
            "geo": {
                "country": profile.get("country", ""),
                "province": profile.get("province", ""),
                "city": profile.get("city", ""),
                "isp": profile.get("isp", ""),
            },
            "first_seen": profile.get("first_seen_time") or profile.get("created_time"),
            "last_seen": profile.get("last_seen_time") or profile.get("updated_time"),
            "risk_level": profile.get("trust_level", "unknown"),
            "total_events": int(profile.get("hit_count", 0) or 0),
            "max_confidence": self._safe_float(profile.get("risk_score") or profile.get("max_confidence")),
            "max_bps": self._safe_float(profile.get("max_bps")),
            "attack_types": profile.get("attack_type_list", []),
            "cluster_ids": profile.get("cluster_ids", []),
            "intel": {
                "blacklist": [
                    dict(item, threat_type=self._json_to_list(item.get("threat_type")))
                    for item in intel.get("blacklist", [])
                ],
                "whitelist": intel.get("whitelist", []),
                "manual_tags": [
                    {
                        "tag_name": str(tag.get("tag_name", "")),
                        "confidence_score": tag.get("confidence_score"),
                        "threat_type": self._json_to_list(tag.get("threat_type")),
                    }
                    for tag in intel.get("manual_tags", [])
                    if str(tag.get("tag_name", "")).strip()
                ],
                "threat_types": self._merge_intel_threat_types(intel),
            },
            "monthly_trend": monthly_trend,
            "recent_events": recent_events,
            "feedback": feedback,
        }

    # ------------------------------------------------------------------
    # 情报资产
    # ------------------------------------------------------------------

    def add_to_blacklist(
        self,
        indicator_type: str,
        indicator_value: str,
        severity: str = "high",
        confidence_score: float = 80.0,
        source_name: str = "manual",
        reason: str = "",
        created_by: str = "operator",
        threat_types: Optional[Sequence[object]] = None,
    ) -> Dict[str, object]:
        import pymysql

        normalized = indicator_value.strip().lower()
        normalized_threat_types = self.normalize_threat_types(
            threat_types or self.infer_threat_types(reason=reason)
        )
        conn = self._get_mysql_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT blacklist_id FROM ti_blacklist
                    WHERE indicator_type = %s AND normalized_value = %s AND status = 'active'
                    LIMIT 1
                    """,
                    [indicator_type, normalized],
                )
                existing = cursor.fetchone()
                if existing:
                    return {"status": "already_exists", "blacklist_id": existing["blacklist_id"]}

                cursor.execute(
                    """
                    INSERT INTO ti_blacklist
                    (indicator_type, indicator_value, normalized_value, severity,
                     confidence_score, source_name, reason, threat_type, status, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active', %s)
                    """,
                    [indicator_type, indicator_value.strip(), normalized, severity,
                     confidence_score, source_name, reason,
                     json.dumps(normalized_threat_types, ensure_ascii=False), created_by],
                )
            conn.commit()
            return {
                "status": "added",
                "indicator_value": indicator_value.strip(),
                "threat_type": normalized_threat_types,
            }
        except Exception as exc:
            logger.error("[THREAT_INTEL] 黑名单添加失败 / error[%s]", exc)
            return {"status": "error", "message": str(exc)}
        finally:
            conn.close()

    def deactivate_blacklist(
        self,
        indicator_type: str = "ip",
        indicator_value: str = "",
        blacklist_id: Optional[int] = None,
    ) -> Dict[str, object]:
        conn = self._get_mysql_connection()
        normalized = indicator_value.strip().lower()
        try:
            with conn.cursor() as cursor:
                if blacklist_id:
                    affected = cursor.execute(
                        """
                        UPDATE ti_blacklist
                        SET status = 'inactive', updated_at = NOW()
                        WHERE blacklist_id = %s AND status = 'active'
                        """,
                        [blacklist_id],
                    )
                else:
                    affected = cursor.execute(
                        """
                        UPDATE ti_blacklist
                        SET status = 'inactive', updated_at = NOW()
                        WHERE indicator_type = %s AND normalized_value = %s AND status = 'active'
                        """,
                        [indicator_type, normalized],
                    )
            conn.commit()
            return {"status": "deactivated" if affected else "not_found", "affected": int(affected)}
        except Exception as exc:
            logger.error("[THREAT_INTEL] 黑名单解除失败 / error[%s]", exc)
            return {"status": "error", "message": str(exc)}
        finally:
            conn.close()

    def update_blacklist_metadata(
        self,
        blacklist_id: int,
        threat_types: Sequence[object],
        source_name: str,
    ) -> Dict[str, object]:
        normalized_threat_types = self.normalize_threat_types(threat_types)
        normalized_source_name = str(source_name or "").strip() or "manual"
        conn = self._get_mysql_connection()
        try:
            with conn.cursor() as cursor:
                affected = cursor.execute(
                    """
                    UPDATE ti_blacklist
                    SET threat_type = %s,
                        source_name = %s,
                        updated_at = NOW()
                    WHERE blacklist_id = %s AND status = 'active'
                    """,
                    [
                        json.dumps(normalized_threat_types, ensure_ascii=False),
                        normalized_source_name,
                        int(blacklist_id),
                    ],
                )
            conn.commit()
            if not affected:
                return {"status": "not_found", "affected": 0}
            return {
                "status": "updated",
                "affected": int(affected),
                "blacklist_id": int(blacklist_id),
                "threat_type": normalized_threat_types,
                "source_name": normalized_source_name,
            }
        except Exception as exc:
            logger.error("[THREAT_INTEL] blacklist metadata update failed / error[%s]", exc)
            return {"status": "error", "message": str(exc)}
        finally:
            conn.close()

    def get_blacklist_assets(self, status: str = "active", page: int = 1, page_size: int = 20) -> Dict[str, object]:
        try:
            total_rows = self._select_mysql(
                "SELECT COUNT(*) AS cnt FROM ti_blacklist WHERE indicator_type = 'ip' AND status = %s",
                [status],
            )
            total = int(total_rows[0]["cnt"]) if total_rows else 0

            offset = (page - 1) * page_size
            items = self._select_mysql(
                "SELECT *, created_at AS created_time FROM ti_blacklist WHERE indicator_type = 'ip' AND status = %s ORDER BY created_at DESC LIMIT %s OFFSET %s",
                [status, page_size, offset],
            )
        except Exception as exc:
            logger.warning("[THREAT_INTEL] 黑名单查询失败 / error[%s]", exc)
            return {"total": 0, "page": page, "page_size": page_size, "items": []}

        for item in items:
            item["threat_type"] = self._json_to_list(item.get("threat_type"))
        return {"total": total, "page": page, "page_size": page_size, "items": items}

    def get_whitelist_assets(self, status: str = "active", page: int = 1, page_size: int = 20) -> Dict[str, object]:
        try:
            total_rows = self._select_mysql(
                "SELECT COUNT(*) AS cnt FROM ti_whitelist WHERE indicator_type = 'ip' AND status = %s",
                [status],
            )
            total = int(total_rows[0]["cnt"]) if total_rows else 0

            offset = (page - 1) * page_size
            items = self._select_mysql(
                "SELECT * FROM ti_whitelist WHERE indicator_type = 'ip' AND status = %s ORDER BY created_time DESC LIMIT %s OFFSET %s",
                [status, page_size, offset],
            )
        except Exception as exc:
            logger.warning("[THREAT_INTEL] 白名单查询失败 / error[%s]", exc)
            return {"total": 0, "page": page, "page_size": page_size, "items": []}

        return {"total": total, "page": page, "page_size": page_size, "items": items}

    def get_tags_assets(self, page: int = 1, page_size: int = 20) -> Dict[str, object]:
        try:
            total_rows = self._select_mysql("SELECT COUNT(DISTINCT tag_name) AS cnt FROM ti_manual_tag")
            total = int(total_rows[0]["cnt"]) if total_rows else 0

            offset = (page - 1) * page_size
            items = self._select_mysql(
                """
                SELECT
                    tag_name,
                    COUNT(*) AS ip_count,
                    MAX(created_time) AS last_used,
                    GROUP_CONCAT(DISTINCT jt.threat_type_json ORDER BY jt.threat_type_json SEPARATOR '||') AS threat_type_group
                FROM ti_manual_tag
                LEFT JOIN JSON_TABLE(
                    COALESCE(threat_type, JSON_ARRAY()),
                    '$[*]' COLUMNS (threat_type_json VARCHAR(64) PATH '$')
                ) jt ON TRUE
                WHERE indicator_type = 'ip'
                GROUP BY tag_name
                ORDER BY ip_count DESC
                LIMIT %s OFFSET %s
                """,
                [page_size, offset],
            )
        except Exception as exc:
            logger.warning("[THREAT_INTEL] 标签查询失败 / error[%s]", exc)
            return {"total": 0, "page": page, "page_size": page_size, "items": []}

        for item in items:
            raw_group = str(item.get("threat_type_group", "") or "")
            threat_types: List[str] = []
            for chunk in raw_group.split("||"):
                value = chunk.strip()
                if value and value not in threat_types:
                    threat_types.append(value)
            item["threat_type"] = threat_types
        return {"total": total, "page": page, "page_size": page_size, "items": items}

    def get_feedback_assets(self, page: int = 1, page_size: int = 20) -> Dict[str, object]:
        try:
            total_rows = self._select_mysql("SELECT COUNT(*) AS cnt FROM ti_feedback")
            total = int(total_rows[0]["cnt"]) if total_rows else 0

            offset = (page - 1) * page_size
            items = self._select_mysql(
                "SELECT * FROM ti_feedback ORDER BY created_time DESC LIMIT %s OFFSET %s",
                [page_size, offset],
            )
        except Exception as exc:
            logger.warning("[THREAT_INTEL] 反馈查询失败 / error[%s]", exc)
            return {"total": 0, "page": page, "page_size": page_size, "items": []}

        return {"total": total, "page": page, "page_size": page_size, "items": items}

    def _merge_intel_threat_types(self, intel: Dict) -> List[str]:
        result: List[str] = []
        for item in intel.get("blacklist", []):
            for threat_type in self._json_to_list(item.get("threat_type")):
                if threat_type not in result:
                    result.append(threat_type)
        for item in intel.get("manual_tags", []):
            for threat_type in self._json_to_list(item.get("threat_type")):
                if threat_type not in result:
                    result.append(threat_type)
        return result

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------

    def _build_source_intel(self, sources: Iterable[Dict]) -> List[Dict]:
        sources = list(sources)
        ip_list = [str(item.get("src_ip", "")).strip() for item in sources if str(item.get("src_ip", "")).strip()]
        intel_map = self._lookup.load_ip_intel(ip_list)
        enriched = []
        for item in sources:
            ip = str(item.get("src_ip", "")).strip()
            intel = intel_map.get(ip, {})
            item = dict(item)
            item["intel"] = {
                "blacklist_hit": len(intel.get("blacklist", [])),
                "whitelist_hit": len(intel.get("whitelist", [])),
                "manual_tag_count": len(intel.get("manual_tags", [])),
                "blacklist_items": [
                    {
                        "blacklist_id": entry.get("blacklist_id"),
                        "source_name": str(entry.get("source_name", "")).strip(),
                        "threat_type": self._json_to_list(entry.get("threat_type")),
                    }
                    for entry in intel.get("blacklist", [])
                ],
                "manual_tags": [
                    str(tag.get("tag_name", "")).strip()
                    for tag in intel.get("manual_tags", [])
                    if str(tag.get("tag_name", "")).strip()
                ],
                "threat_types": self._merge_intel_threat_types(intel),
            }
            enriched.append(item)
        return enriched

    def _build_source_intel_safe(self, sources: Iterable[Dict]) -> List[Dict]:
        sources = list(sources)
        try:
            return self._build_source_intel(sources)
        except Exception as exc:
            logger.warning("[THREAT_INTEL] source intel enrichment failed / error[%s]", exc)
            enriched = []
            for item in sources:
                row = dict(item)
                row["intel"] = {
                    "blacklist_hit": 0,
                    "whitelist_hit": 0,
                    "manual_tag_count": 0,
                    "blacklist_items": [],
                    "manual_tags": [],
                    "threat_types": [],
                }
                enriched.append(row)
            return enriched
