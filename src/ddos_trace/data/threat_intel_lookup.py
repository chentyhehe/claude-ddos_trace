import logging
import json
import logging
from typing import Dict, List, Optional

import pandas as pd

from ddos_trace.config.models import MySQLConfig, ThreatIntelConfig

logger = logging.getLogger(__name__)


class ThreatIntelLookup:
    """分析前查询 MySQL 黑白名单与人工标签，并对特征做权重增强。"""

    QUERY_BATCH_SIZE = 1000

    def __init__(
        self,
        mysql_config: MySQLConfig,
        threat_intel_config: Optional[ThreatIntelConfig] = None,
    ):
        self.mysql_config = mysql_config
        self.config = threat_intel_config or ThreatIntelConfig()

    def _build_mysql_params(self) -> Dict[str, object]:
        return {
            "host": self.config.mysql_host or self.mysql_config.host,
            "port": int(self.config.mysql_port or self.mysql_config.port),
            "user": self.config.mysql_username or self.mysql_config.username,
            "password": self.config.mysql_password or self.mysql_config.password,
            "database": self.config.mysql_database,
            "charset": self.config.mysql_charset or self.mysql_config.charset,
        }

    def _get_connection(self):
        import pymysql

        params = self._build_mysql_params()
        params["cursorclass"] = pymysql.cursors.DictCursor
        logger.info(
            "[THREAT_INTEL] 使用 MySQL 情报查询连接 host=%s port=%s database=%s",
            params["host"],
            params["port"],
            params["database"],
        )
        return pymysql.connect(**params)

    @staticmethod
    def _normalize_ip_list(index_values) -> List[str]:
        ips = []
        for value in index_values:
            ip = str(value).strip()
            if ip:
                ips.append(ip)
        return ips

    @staticmethod
    def _extract_threat_types(entries: List[Dict]) -> List[str]:
        result: List[str] = []
        for item in entries or []:
            raw_value = item.get("threat_type")
            if isinstance(raw_value, list):
                values = raw_value
            else:
                try:
                    values = json.loads(str(raw_value or "[]"))
                except (TypeError, ValueError, json.JSONDecodeError):
                    values = []
            for value in values:
                text = str(value or "").strip()
                if text and text not in result:
                    result.append(text)
        return result

    def _query_table(self, conn, sql: str, ips: List[str]) -> List[Dict]:
        all_rows: List[Dict] = []
        with conn.cursor() as cursor:
            for offset in range(0, len(ips), self.QUERY_BATCH_SIZE):
                batch = ips[offset: offset + self.QUERY_BATCH_SIZE]
                placeholders = ",".join(["%s"] * len(batch))
                cursor.execute(sql.format(placeholders=placeholders), batch)
                all_rows.extend(cursor.fetchall())
        return all_rows

    def load_ip_intel(self, ips: List[str]) -> Dict[str, Dict]:
        if not ips:
            return {}

        intel_map: Dict[str, Dict] = {
            ip: {
                "blacklist": [],
                "whitelist": [],
                "manual_tags": [],
            }
            for ip in ips
        }

        try:
            conn = self._get_connection()
        except Exception as exc:
            logger.error("[THREAT_INTEL] MySQL 情报查询连接失败 / error[%s]", exc)
            return intel_map

        try:
            blacklist_sql = """
                SELECT blacklist_id, normalized_value, severity, confidence_score, source_name, reason, threat_type
                FROM ti_blacklist
                WHERE indicator_type = 'ip'
                  AND status = 'active'
                  AND normalized_value IN ({placeholders})
                  AND (effective_to IS NULL OR effective_to >= NOW())
            """
            whitelist_sql = """
                SELECT normalized_value, scope_type, scope_value, source_name, reason
                FROM ti_whitelist
                WHERE indicator_type = 'ip'
                  AND status = 'active'
                  AND normalized_value IN ({placeholders})
                  AND (effective_to IS NULL OR effective_to >= NOW())
            """
            tag_sql = """
                SELECT normalized_value, tag_name, tag_value, confidence_score, reason, threat_type
                FROM ti_manual_tag
                WHERE indicator_type = 'ip'
                  AND normalized_value IN ({placeholders})
            """

            for row in self._query_table(conn, blacklist_sql, ips):
                intel_map.setdefault(row["normalized_value"], {}).setdefault("blacklist", []).append(row)
            for row in self._query_table(conn, whitelist_sql, ips):
                intel_map.setdefault(row["normalized_value"], {}).setdefault("whitelist", []).append(row)
            for row in self._query_table(conn, tag_sql, ips):
                intel_map.setdefault(row["normalized_value"], {}).setdefault("manual_tags", []).append(row)
        except Exception as exc:
            logger.error("[THREAT_INTEL] MySQL 情报查询失败 / error[%s]", exc)
        finally:
            conn.close()

        return intel_map

    def enrich_features(self, features: pd.DataFrame) -> pd.DataFrame:
        if features is None or features.empty:
            return features

        result = features.copy()
        ips = self._normalize_ip_list(result.index)
        intel_map = self.load_ip_intel(ips)

        result["ti_blacklist_hit"] = 0
        result["ti_whitelist_hit"] = 0
        result["ti_manual_tag_count"] = 0
        result["ti_weight_adjustment"] = 0.0
        result["ti_tags"] = ""
        result["ti_threat_types"] = ""

        for src_ip, row in result.iterrows():
            ip = str(src_ip).strip()
            intel = intel_map.get(ip, {})
            blacklists = intel.get("blacklist", [])
            whitelists = intel.get("whitelist", [])
            manual_tags = intel.get("manual_tags", [])
            threat_types = self._extract_threat_types(blacklists) + self._extract_threat_types(manual_tags)

            base_score = float(row.get("attack_confidence", 0) or 0)
            score = base_score
            reasons = str(row.get("confidence_reasons", "") or "")
            tags: List[str] = []

            if whitelists:
                result.at[src_ip, "ti_whitelist_hit"] = 1
                score = min(score, 5.0)
                result.at[src_ip, "traffic_class"] = "background"
                reasons = f"{reasons};TI白名单命中" if reasons else "TI白名单命中"
                tags.extend(["whitelist"])

            if blacklists and not whitelists:
                result.at[src_ip, "ti_blacklist_hit"] = 1
                max_conf = max(float(item.get("confidence_score", 80) or 80) for item in blacklists)
                boost = min(40.0, max_conf * 0.4)
                score = min(100.0, max(score, 55.0) + boost)
                if score >= 85:
                    result.at[src_ip, "traffic_class"] = "confirmed"
                elif score >= 60 and str(result.at[src_ip, "traffic_class"]) == "background":
                    result.at[src_ip, "traffic_class"] = "suspicious"
                reasons = f"{reasons};TI黑名单命中" if reasons else "TI黑名单命中"
                tags.extend(["blacklist"])

            if manual_tags and not whitelists:
                result.at[src_ip, "ti_manual_tag_count"] = len(manual_tags)
                tag_boost = sum(min(15.0, float(item.get("confidence_score", 80) or 80) * 0.15) for item in manual_tags)
                score = min(100.0, score + tag_boost)
                if score >= 60 and str(result.at[src_ip, "traffic_class"]) == "background":
                    result.at[src_ip, "traffic_class"] = "suspicious"
                tag_names = [str(item.get("tag_name", "")).strip() for item in manual_tags if str(item.get("tag_name", "")).strip()]
                if tag_names:
                    tags.extend(tag_names)
                    reasons = f"{reasons};TI人工标签:{','.join(tag_names)}" if reasons else f"TI人工标签:{','.join(tag_names)}"

            result.at[src_ip, "attack_confidence"] = round(score, 2)
            result.at[src_ip, "confidence_reasons"] = reasons
            result.at[src_ip, "ti_weight_adjustment"] = round(score - base_score, 2)
            result.at[src_ip, "ti_tags"] = ",".join(sorted(set(tags)))
            result.at[src_ip, "ti_threat_types"] = ",".join(sorted(set(threat_types)))

        return result
