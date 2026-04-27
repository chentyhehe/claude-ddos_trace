import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence
from urllib.parse import quote

import pandas as pd

from ddos_trace.config.models import ClickHouseConfig, MySQLConfig, ThreatIntelConfig

logger = logging.getLogger(__name__)


class ThreatIntelWriter:
    """将分析结果批量回流到威胁情报业务表。"""

    def __init__(
        self,
        clickhouse_config: ClickHouseConfig,
        mysql_config: MySQLConfig,
        threat_intel_config: Optional[ThreatIntelConfig] = None,
    ):
        self.clickhouse_config = clickhouse_config
        self.mysql_config = mysql_config
        self.config = threat_intel_config or ThreatIntelConfig()
        self._ch_client = None
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

    def _get_clickhouse_client(self):
        if self._ch_client is None:
            from clickhouse_driver import Client

            connection_params = self._build_clickhouse_params()
            logger.info(
                "[THREAT_INTEL] 使用 ClickHouse 回流连接 host=%s port=%s database=%s",
                connection_params["host"],
                connection_params["port"],
                connection_params["database"],
            )
            self._ch_client = Client(**connection_params)
            self._ch_client.execute("SELECT 1")
            db_exists = self._ch_client.execute(
                "SELECT count() FROM system.databases WHERE name = %(db)s",
                {"db": self.config.clickhouse_database},
            )
            if not db_exists or db_exists[0][0] == 0:
                raise RuntimeError(
                    f"Threat intel ClickHouse database does not exist: {self.config.clickhouse_database}"
                )
        return self._ch_client

    @staticmethod
    def _to_native(value):
        if isinstance(value, pd.Timestamp):
            return value.to_pydatetime().replace(tzinfo=None)
        if isinstance(value, datetime):
            return value.replace(tzinfo=None) if value.tzinfo else value
        if pd.isna(value):
            return None
        return value

    @staticmethod
    def _to_str_list(value) -> List[str]:
        if value is None or (isinstance(value, float) and pd.isna(value)):
            return []
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        return [str(value).strip()]

    @staticmethod
    def _json_dumps(value: Dict) -> str:
        return json.dumps(value, ensure_ascii=False, default=str)

    def _batch_insert(
        self,
        table_name: str,
        columns: Sequence[str],
        rows: Iterable[Sequence],
    ) -> None:
        rows = list(rows)
        if not rows:
            return

        client = self._get_clickhouse_client()
        db = self.config.clickhouse_database
        sql = f"INSERT INTO {db}.{table_name} ({', '.join(columns)}) VALUES"
        batch_size = max(int(self.config.batch_size), 1)

        for offset in range(0, len(rows), batch_size):
            batch = rows[offset: offset + batch_size]
            client.execute(sql, batch)

    def _execute(self, sql: str, params: Optional[Dict[str, object]] = None) -> None:
        client = self._get_clickhouse_client()
        client.execute(sql, params or {})

    def _table_exists(self, table_name: str) -> bool:
        client = self._get_clickhouse_client()
        db = self.config.clickhouse_database
        rows = client.execute(
            "SELECT name FROM system.tables WHERE database = %(db)s AND name = %(table)s LIMIT 1",
            {"db": db, "table": table_name},
        )
        return bool(rows)

    @staticmethod
    def _quote_literal(value: object) -> str:
        text = str(value or "")
        return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"

    def _build_in_clause(self, values: Iterable[object]) -> str:
        items = [self._quote_literal(value) for value in values if str(value or "").strip()]
        if not items:
            return ""
        return ", ".join(items)

    def _delete_existing_rows(
        self,
        event_meta: Dict[str, object],
        features: Optional[pd.DataFrame],
        cluster_report: Optional[pd.DataFrame],
    ) -> None:
        event_id = str(event_meta.get("event_id", "") or "").strip()
        if not event_id:
            return

        db = self.config.clickhouse_database
        event_tables = [
            "ti_attack_event_local",
            "ti_event_source_ip_local",
            "ti_event_entry_router_local",
            "ti_event_geo_distribution_local",
            "ti_event_mo_distribution_local",
            "ti_event_time_distribution_local",
        ]
        for table_name in event_tables:
            self._execute(
                f"ALTER TABLE {db}.{table_name} DELETE WHERE event_id = %(event_id)s SETTINGS mutations_sync = 1",
                {"event_id": event_id},
            )

        try:
            if self._table_exists("ti_event_artifact_local"):
                self._execute(
                    f"ALTER TABLE {db}.ti_event_artifact_local DELETE WHERE event_id = %(event_id)s SETTINGS mutations_sync = 1",
                    {"event_id": event_id},
                )
        except Exception as exc:
            logger.warning("[THREAT_INTEL] 附件元数据清理失败，继续回流主数据 / event_id[%s] / error[%s]", event_id, exc)

        if features is not None and not features.empty:
            ip_clause = self._build_in_clause(features.index.map(str).tolist())
            if ip_clause:
                self._execute(
                    f"ALTER TABLE {db}.ti_ip_profile_local DELETE WHERE ip IN ({ip_clause}) SETTINGS mutations_sync = 1"
                )
                stat_date = self._to_native(event_meta.get('start_time') or datetime.now())
                if isinstance(stat_date, datetime):
                    stat_date = stat_date.date().isoformat()
                else:
                    stat_date = str(stat_date)
                self._execute(
                    f"""
                    ALTER TABLE {db}.ti_ip_daily_stat_local
                    DELETE WHERE stat_date = toDate(%(stat_date)s) AND ip IN ({ip_clause})
                    SETTINGS mutations_sync = 1
                    """,
                    {"stat_date": stat_date},
                )

        if cluster_report is not None and not cluster_report.empty and "cluster_id" in cluster_report.columns:
            cluster_clause = self._build_in_clause(cluster_report["cluster_id"].astype(str).tolist())
            if cluster_clause:
                self._execute(
                    f"""
                    ALTER TABLE {db}.ti_cluster_profile_local
                    DELETE WHERE cluster_id IN ({cluster_clause})
                    SETTINGS mutations_sync = 1
                    """
                )

    def sync_analysis_result(
        self,
        event_meta: Dict[str, object],
        overview: Optional[Dict],
        features: Optional[pd.DataFrame],
        cluster_report: Optional[pd.DataFrame],
        path_analysis: Optional[Dict],
        per_type_results: Optional[Dict],
    ) -> None:
        if not self.config.enabled:
            return

        try:
            self._delete_existing_rows(event_meta, features, cluster_report)
            self._insert_attack_event(event_meta, overview, features)
            self._insert_event_source_ips(event_meta, features, cluster_report)
            self._insert_ip_profiles(features, cluster_report)
            self._insert_cluster_profiles(cluster_report, features)
            self._insert_path_analysis(event_meta, path_analysis)
            self._insert_event_artifacts(event_meta)
            self._insert_daily_stats(event_meta, features)
        except Exception as exc:
            logger.exception("[THREAT_INTEL] 回流业务表失败 / error[%s]", exc)

    def _insert_attack_event(
        self,
        event_meta: Dict[str, object],
        overview: Optional[Dict],
        features: Optional[pd.DataFrame],
    ) -> None:
        overview = dict(overview or {})
        peak_pps = 0
        peak_bps = 0
        if features is not None and not features.empty:
            if "packets_per_sec" in features.columns:
                peak_pps = int(pd.to_numeric(features["packets_per_sec"], errors="coerce").fillna(0).max())
            if "bytes_per_sec" in features.columns:
                peak_bps = int(pd.to_numeric(features["bytes_per_sec"], errors="coerce").fillna(0).max())
        overview.setdefault("event_id", str(event_meta.get("event_id", "") or ""))
        overview.setdefault("attack_id", str(event_meta.get("attack_id", "") or ""))
        overview.setdefault("target_ip", str(event_meta.get("target_ip", "") or ""))
        overview.setdefault("target_mo_name", str(event_meta.get("target_mo_name", "") or ""))
        overview["output_dir"] = str(event_meta.get("output_dir", "") or overview.get("output_dir", ""))
        columns = [
            "event_id", "attack_id", "event_name", "target_ip", "target_mo_name", "target_mo_code",
            "start_time", "end_time", "attack_types", "severity", "event_status",
            "total_source_ips", "confirmed_sources", "suspicious_sources", "borderline_sources",
            "background_sources", "anomaly_total", "peak_pps", "peak_bps",
            "attack_type_count", "overview_json", "created_time", "updated_time",
        ]
        row = [
            str(event_meta.get("event_id", "")),
            str(event_meta.get("attack_id", "")),
            str(event_meta.get("event_name", "")),
            str(event_meta.get("target_ip", "")),
            str(event_meta.get("target_mo_name", "")),
            str(event_meta.get("target_mo_code", "")),
            self._to_native(event_meta.get("start_time")),
            self._to_native(event_meta.get("end_time")),
            self._to_str_list(overview.get("attack_type_names", [])),
            str(event_meta.get("severity", "medium")),
            str(event_meta.get("event_status", "auto")),
            int(overview.get("total_source_ips", 0) or 0),
            int(overview.get("confirmed", 0) or 0),
            int(overview.get("suspicious", 0) or 0),
            int(overview.get("borderline", 0) or 0),
            int(overview.get("background", 0) or 0),
            int(overview.get("anomaly_total", 0) or 0),
            peak_pps,
            peak_bps,
            int(overview.get("attack_type_count", 0) or 0),
            self._json_dumps(overview),
            self._to_native(event_meta.get("created_at") or datetime.now()),
            self._to_native(event_meta.get("updated_at") or datetime.now()),
        ]
        self._batch_insert("ti_attack_event_local", columns, [row])

    def _build_cluster_ip_map(self, cluster_report: Optional[pd.DataFrame]) -> Dict[str, str]:
        cluster_ip_map: Dict[str, str] = {}
        if cluster_report is None or cluster_report.empty:
            return cluster_ip_map
        for _, row in cluster_report.iterrows():
            cluster_id = str(row.get("cluster_id", "") or "")
            for member_ip in self._to_str_list(row.get("member_ips", [])):
                cluster_ip_map[member_ip] = cluster_id
        return cluster_ip_map

    def _insert_event_source_ips(
        self,
        event_meta: Dict[str, object],
        features: Optional[pd.DataFrame],
        cluster_report: Optional[pd.DataFrame],
    ) -> None:
        if features is None or features.empty:
            return

        export_df = features.copy()
        export_df.index = export_df.index.map(str)
        cluster_ip_map = self._build_cluster_ip_map(cluster_report)
        columns = [
            "event_id", "src_ip", "traffic_class", "attack_confidence", "confidence_reasons",
            "attack_type", "best_attack_type", "matched_attack_types", "matched_attack_type_count",
            "max_attack_confidence_across_types", "cluster_id", "total_packets", "total_bytes",
            "packets_per_sec", "bytes_per_sec", "bytes_per_packet", "burst_ratio", "burst_count",
            "flow_duration", "protocol_count", "dst_port_count", "asn", "country", "province",
            "city", "isp", "feature_json", "created_time",
        ]
        rows = []
        for src_ip, row in export_df.iterrows():
            record = row.to_dict()
            rows.append([
                str(event_meta.get("event_id", "")),
                str(src_ip),
                str(record.get("traffic_class", "background") or "background"),
                float(record.get("attack_confidence", 0) or 0),
                str(record.get("confidence_reasons", "") or ""),
                str(record.get("source_attack_type", "") or ""),
                str(record.get("best_attack_type", "") or ""),
                self._to_str_list(record.get("matched_attack_types", [])),
                int(record.get("matched_attack_type_count", 0) or 0),
                float(record.get("max_attack_confidence_across_types", 0) or 0),
                str(record.get("cluster_id", "") or cluster_ip_map.get(str(src_ip), "")),
                int(record.get("total_packets", 0) or 0),
                int(record.get("total_bytes", 0) or 0),
                int(float(record.get("packets_per_sec", 0) or 0)),
                int(float(record.get("bytes_per_sec", 0) or 0)),
                float(record.get("bytes_per_packet", 0) or 0),
                float(record.get("burst_ratio", 0) or 0),
                int(record.get("burst_count", 0) or 0),
                float(record.get("flow_duration", 0) or 0),
                int(record.get("protocol_count", 0) or 0),
                int(record.get("dst_port_count", 0) or 0),
                int(record.get("asn", 0) or 0),
                str(record.get("country", "") or ""),
                str(record.get("province", "") or ""),
                str(record.get("city", "") or ""),
                str(record.get("isp", "") or ""),
                self._json_dumps(record),
                self._to_native(event_meta.get("updated_at") or datetime.now()),
            ])
        self._batch_insert("ti_event_source_ip_local", columns, rows)

    def _insert_ip_profiles(
        self,
        features: Optional[pd.DataFrame],
        cluster_report: Optional[pd.DataFrame],
    ) -> None:
        if features is None or features.empty:
            return

        cluster_ip_map = self._build_cluster_ip_map(cluster_report)
        columns = [
            "ip", "risk_score", "trust_level", "disposition", "hit_count", "confirmed_count",
            "false_positive_count", "last_attack_type", "matched_attack_types",
            "matched_attack_type_count", "max_attack_confidence_across_types",
            "last_attack_confidence", "last_traffic_class", "last_confidence_reasons",
            "cluster_id", "asn", "country", "province", "city", "isp", "tags",
            "source_weights", "whitelist_flag", "note", "first_seen_time", "last_seen_time",
            "last_feedback_time", "expire_time", "created_time", "updated_time",
        ]
        now = datetime.now()
        rows = []
        for src_ip, row in features.iterrows():
            trust_level = str(row.get("traffic_class", "background") or "background")
            if trust_level == "background":
                trust_level = "unknown"
            disposition = "observe"
            if str(row.get("traffic_class", "")) == "confirmed":
                disposition = "scrubbing"
            elif str(row.get("traffic_class", "")) == "suspicious":
                disposition = "rate_limit"

            rows.append([
                str(src_ip),
                max(0, min(100, int(float(row.get("attack_confidence", 0) or 0)))),
                trust_level,
                disposition,
                1,
                1 if str(row.get("traffic_class", "")) == "confirmed" else 0,
                0,
                str(row.get("best_attack_type", row.get("source_attack_type", "")) or ""),
                self._to_str_list(row.get("matched_attack_types", [])),
                int(row.get("matched_attack_type_count", 0) or 0),
                float(row.get("max_attack_confidence_across_types", 0) or 0),
                float(row.get("attack_confidence", 0) or 0),
                str(row.get("traffic_class", "background") or "background"),
                str(row.get("confidence_reasons", "") or ""),
                str(row.get("cluster_id", "") or cluster_ip_map.get(str(src_ip), "")),
                int(row.get("asn", 0) or 0),
                str(row.get("country", "") or ""),
                str(row.get("province", "") or ""),
                str(row.get("city", "") or ""),
                str(row.get("isp", "") or ""),
                [],
                "{}",
                0,
                "",
                now,
                now,
                None,
                None,
                now,
                now,
            ])
        self._batch_insert("ti_ip_profile_local", columns, rows)

    def _insert_cluster_profiles(self, cluster_report: Optional[pd.DataFrame], features: Optional[pd.DataFrame]) -> None:
        if cluster_report is None or cluster_report.empty:
            return

        feature_map = {}
        if features is not None and not features.empty:
            feature_map = features.copy()
            feature_map.index = feature_map.index.map(str)

        columns = [
            "cluster_id", "cluster_name", "cluster_type", "cluster_score", "attack_types",
            "countries", "asns", "feature_profile", "status", "first_seen_time", "last_seen_time",
            "created_time", "updated_time",
        ]
        now = datetime.now()
        rows = []
        for _, row in cluster_report.iterrows():
            member_ips = self._to_str_list(row.get("member_ips", []))
            countries = []
            asns = []
            if isinstance(feature_map, pd.DataFrame) and not feature_map.empty:
                subset = feature_map.loc[feature_map.index.intersection(member_ips)]
                if not subset.empty:
                    countries = [str(v) for v in subset.get("country", pd.Series(dtype=str)).dropna().unique().tolist() if str(v)]
                    asns = [int(v) for v in subset.get("asn", pd.Series(dtype=int)).dropna().tolist() if str(v).strip()]
            rows.append([
                str(row.get("cluster_id", "")),
                f"cluster_{row.get('cluster_id', '')}",
                "fingerprint",
                0,
                self._to_str_list(row.get("attack_type", "")),
                countries,
                asns,
                self._json_dumps(row.to_dict()),
                "active",
                now,
                now,
                now,
                now,
            ])
        self._batch_insert("ti_cluster_profile_local", columns, rows)

    def _insert_path_analysis(self, event_meta: Dict[str, object], path_analysis: Optional[Dict]) -> None:
        if not path_analysis:
            return

        event_id = str(event_meta.get("event_id", ""))
        now = self._to_native(event_meta.get("updated_at") or datetime.now())

        self._insert_dataframe(
            "ti_event_entry_router_local",
            path_analysis.get("entry_routers"),
            [
                "event_id", "flow_ip_addr", "input_if_index", "unique_source_ips",
                "total_packets", "total_bytes", "created_time",
            ],
            lambda row: [
                event_id,
                str(row.get("flow_ip_addr", "") or ""),
                int(row.get("input_if_index", 0) or 0),
                int(row.get("unique_source_ips", 0) or 0),
                int(row.get("total_packets", 0) or 0),
                int(row.get("total_bytes", 0) or 0),
                now,
            ],
        )
        self._insert_dataframe(
            "ti_event_geo_distribution_local",
            path_analysis.get("geo_distribution"),
            [
                "event_id", "src_country", "src_province", "src_city", "src_isp",
                "unique_source_ips", "total_packets", "total_bytes", "created_time",
            ],
            lambda row: [
                event_id,
                str(row.get("src_country", "") or ""),
                str(row.get("src_province", "") or ""),
                str(row.get("src_city", "") or ""),
                str(row.get("src_isp", "") or ""),
                int(row.get("unique_source_ips", 0) or 0),
                int(row.get("total_packets", 0) or 0),
                int(row.get("total_bytes", 0) or 0),
                now,
            ],
        )
        self._insert_dataframe(
            "ti_event_mo_distribution_local",
            path_analysis.get("mo_distribution"),
            [
                "event_id", "src_mo_name", "src_mo_code", "attacking_source_ips",
                "total_packets", "total_bytes", "created_time",
            ],
            lambda row: [
                event_id,
                str(row.get("src_mo_name", "") or ""),
                str(row.get("src_mo_code", "") or ""),
                int(row.get("attacking_source_ips", 0) or 0),
                int(row.get("total_packets", 0) or 0),
                int(row.get("total_bytes", 0) or 0),
                now,
            ],
        )
        self._insert_dataframe(
            "ti_event_time_distribution_local",
            path_analysis.get("time_distribution"),
            [
                "event_id", "bucket_time", "unique_source_ips",
                "total_packets", "total_bytes", "created_time",
            ],
            lambda row: [
                event_id,
                self._to_native(row.get("hour")),
                int(row.get("unique_source_ips", 0) or 0),
                int(row.get("total_packets", 0) or 0),
                int(row.get("total_bytes", 0) or 0),
                now,
            ],
        )

    def _insert_dataframe(self, table_name: str, df: Optional[pd.DataFrame], columns: Sequence[str], row_builder) -> None:
        if df is None or not isinstance(df, pd.DataFrame) or df.empty:
            return
        rows = [row_builder(row) for _, row in df.iterrows()]
        self._batch_insert(table_name, columns, rows)

    def _insert_event_artifacts(self, event_meta: Dict[str, object]) -> None:
        """Persist optional output files as attachment metadata, not as primary evidence."""
        event_id = str(event_meta.get("event_id", "") or "").strip()
        output_dir = str(event_meta.get("output_dir", "") or "").strip()
        if not event_id or not output_dir:
            return

        output_path = Path(output_dir)
        if not output_path.exists() or not output_path.is_dir():
            return

        priority_map = {
            "attack_overview": 10,
            "source_risk_dashboard": 20,
            "operator_dashboard": 30,
            "overall_profile_radar": 40,
            "suspect_source_radar": 50,
            "attack_timeline": 60,
            "type_profile_radar": 70,
            "overview_report": 80,
            "summary": 90,
        }
        mime_map = {
            ".png": "image/png",
            ".md": "text/markdown",
            ".json": "application/json",
            ".csv": "text/csv",
        }
        columns = [
            "event_id", "artifact_name", "artifact_title", "artifact_kind", "file_ext",
            "file_size", "mime_type", "storage_uri", "download_url", "checksum",
            "priority", "created_time",
        ]
        rows = []
        for file_path in sorted(output_path.iterdir()):
            if not file_path.is_file():
                continue
            suffix = file_path.suffix.lower()
            if suffix not in mime_map:
                continue
            kind = "image" if suffix == ".png" else "report" if suffix in {".md", ".json"} else "table"
            priority = 999
            for key, value in priority_map.items():
                if key in file_path.name:
                    priority = value
                    break
            storage_uri = str(file_path.resolve())
            try:
                rel_path = file_path.resolve().relative_to(self._output_root).as_posix()
                download_url = f"/artifacts/{quote(rel_path, safe='/')}"
            except ValueError:
                download_url = ""
            rows.append([
                event_id,
                file_path.name,
                file_path.stem.replace("_", " "),
                kind,
                suffix.lstrip("."),
                int(file_path.stat().st_size),
                mime_map[suffix],
                storage_uri,
                download_url,
                "",
                int(priority),
                self._to_native(event_meta.get("updated_at") or datetime.now()),
            ])

        if not rows:
            return
        if not self._table_exists("ti_event_artifact_local"):
            return
        try:
            self._batch_insert("ti_event_artifact_local", columns, rows)
        except Exception as exc:
            logger.warning("[THREAT_INTEL] 附件元数据回流失败，不影响分析主数据 / event_id[%s] / error[%s]", event_id, exc)

    def _insert_daily_stats(self, event_meta: Dict[str, object], features: Optional[pd.DataFrame]) -> None:
        if features is None or features.empty:
            return

        stat_date = self._to_native(event_meta.get("start_time") or datetime.now())
        if isinstance(stat_date, datetime):
            stat_date = stat_date.date()
        rows = []
        columns = [
            "stat_date", "ip", "hit_events", "confirmed_events", "suspicious_events",
            "max_pps", "max_bps", "attack_types", "updated_time",
        ]
        now = datetime.now()
        for src_ip, row in features.iterrows():
            rows.append([
                stat_date,
                str(src_ip),
                1,
                1 if str(row.get("traffic_class", "")) == "confirmed" else 0,
                1 if str(row.get("traffic_class", "")) == "suspicious" else 0,
                int(float(row.get("packets_per_sec", 0) or 0)),
                int(float(row.get("bytes_per_sec", 0) or 0)),
                self._to_str_list(row.get("matched_attack_types") or row.get("best_attack_type", "")),
                now,
            ])
        self._batch_insert("ti_ip_daily_stat_local", columns, rows)
