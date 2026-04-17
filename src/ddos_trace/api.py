"""
FastAPI 服务 - 对外暴露 DDoS 溯源分析 RESTful API

本模块基于 FastAPI 框架提供 HTTP API 服务，支持三种分析入口:

1. POST /api/v1/analyze/alert  — 基于告警ID分析（推荐）
2. POST /api/v1/analyze/target — 基于攻击目标分析
3. POST /api/v1/analyze        — 手动传参分析（兼容旧接口）

此外提供健康检查端点:
- GET /health — 服务存活检查

所有响应使用统一的 AnalysisResponse 模型，包含:
- 分类统计摘要
- 异常源列表（含置信度和原因）
- 聚类摘要
- 地理分布和入口路由器信息
- 完整的文字分析报告

核心函数:
    create_app: 创建并配置 FastAPI 应用实例
    _build_response: 将分析结果字典转换为标准响应模型
"""

import logging
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ddos_trace.analyzer import DDoSTracebackAnalyzer
from ddos_trace.config.models import load_config
from ddos_trace.data.alert_loader import AttackContext
from ddos_trace.data.threat_intel_dashboard import ThreatIntelDashboardRepository
from ddos_trace.report_browser import build_report_detail_html, build_report_index_html
from ddos_trace.threat_intel_browser import (
    build_intel_dashboard_html,
    build_intel_event_detail_html,
    build_intel_event_list_html,
    build_intel_source_rank_html,
    build_intel_source_profile_html,
    build_intel_asset_blacklist_html,
    build_intel_asset_whitelist_html,
    build_intel_asset_tags_html,
    build_intel_asset_feedback_html,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# 请求模型 (Pydantic BaseModel)
# 自动执行类型校验和 JSON 序列化/反序列化
# ------------------------------------------------------------------

class AlertAnalysisRequest(BaseModel):
    """
    基于告警 ID 的分析请求（推荐方式）

    仅需提供告警系统生成的 attack_id，系统自动获取所有必要参数。
    """

    attack_id: str = Field(
        ..., description="告警系统生成的攻击ID",
        examples=["ATK-20260401-001"],
    )


class TargetAnalysisRequest(BaseModel):
    """
    基于攻击目标的分析请求

    提供攻击目标（IP 或监测对象编码），系统自动从告警表匹配阈值。
    时间范围为可选参数，不传则使用告警记录中的时间窗口。
    """

    attack_target: str = Field(
        ..., description="攻击目标（IP / 监测对象编码）",
        examples=["192.168.1.100"],
    )
    start_time: Optional[str] = Field(
        None, description="开始时间 (YYYY-MM-DD HH:MM:SS)，不传则使用告警时间窗口",
        examples=["2026-04-01 00:00:00"],
    )
    end_time: Optional[str] = Field(
        None, description="结束时间 (YYYY-MM-DD HH:MM:SS)，不传则使用告警时间窗口",
        examples=["2026-04-01 23:59:59"],
    )


class AnalysisRequest(BaseModel):
    """
    手动传参分析请求（兼容旧接口）

    需要完整指定目标IP列表、监测对象编码列表和时间范围。
    使用配置文件中的默认阈值进行检测。
    """

    target_ips: List[str] = Field(
        ..., description="目的IP列表",
        examples=[["192.168.1.100", "10.0.0.50"]],
    )
    target_mo_codes: List[str] = Field(
        ..., description="目的监测对象编码列表",
        examples=[["MO001", "MO002"]],
    )
    start_time: str = Field(
        ..., description="开始时间 (YYYY-MM-DD HH:MM:SS)",
        examples=["2026-04-01 00:00:00"],
    )
    end_time: str = Field(
        ..., description="结束时间 (YYYY-MM-DD HH:MM:SS)",
        examples=["2026-04-01 23:59:59"],
    )


# ------------------------------------------------------------------
# 响应模型 — 统一的 API 返回结构
# ------------------------------------------------------------------

class AlertContextInfo(BaseModel):
    """告警上下文摘要信息 — 告警驱动的分析中附带的告警元数据"""

    attack_id: Optional[str] = None
    attack_target: str = ""
    attack_target_type: str = ""
    target_ips: List[str] = []
    target_mo_codes: List[str] = []
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    attack_types: List[str] = []
    attack_maintype: Optional[str] = None
    direction: str = "in"
    level: str = ""
    max_pps: Optional[float] = None
    max_bps: Optional[float] = None
    threshold_pps: Optional[float] = None
    threshold_bps: Optional[float] = None


class SourceSummary(BaseModel):
    """单个源 IP 的分类摘要 — 包含攻击置信度、流量分类、关键速率指标和地理信息"""

    src_ip: str
    attack_confidence: float
    traffic_class: str
    confidence_reasons: str
    packets_per_sec: float
    bytes_per_sec: float
    country: Optional[str] = None
    province: Optional[str] = None
    isp: Optional[str] = None


class ClusterSummary(BaseModel):
    """集群摘要 — 攻击团伙的聚类ID、成员数、IP列表和推断的攻击类型"""

    cluster_id: int
    member_count: int
    member_ips: str
    attack_type: str


class GeoEntry(BaseModel):
    """地理分布条目 — 攻击源在国家/省/市/ISP 维度的聚合统计"""

    src_country: Optional[str] = None
    src_province: Optional[str] = None
    src_city: Optional[str] = None
    src_isp: Optional[str] = None
    unique_source_ips: int
    total_packets: float
    total_bytes: float


class RouterEntry(BaseModel):
    """入口路由器条目 — 攻击流量进入网络的入口节点信息"""

    flow_ip_addr: Optional[str] = None
    input_if_index: Optional[int] = None
    flow_count: int
    unique_source_ips: int
    total_packets: float
    total_bytes: float


class AnalysisResponse(BaseModel):
    """
    统一分析响应模型

    所有分析 API 返回此结构:
    - task_id: 本次分析的唯一标识（12位随机hex）
    - status: 分析状态（completed / failed）
    - alert_context: 告警上下文（仅告警驱动模式有值）
    - summary: 分类统计摘要
    - anomaly_sources: 异常源列表
    - clusters: 聚类摘要列表
    - geo_distribution: 地理分布
    - entry_routers: 入口路由器
    - report: 完整的文字分析报告
    """

    task_id: str
    status: str
    alert_context: Optional[AlertContextInfo] = None
    summary: dict
    anomaly_sources: List[SourceSummary]
    clusters: List[ClusterSummary] = []
    geo_distribution: List[GeoEntry] = []
    entry_routers: List[RouterEntry] = []
    per_type_summary: Optional[Dict[str, Dict]] = None
    report: str = ""


# ------------------------------------------------------------------
# FastAPI 应用
# ------------------------------------------------------------------

def create_app(config_path: Optional[str] = None) -> FastAPI:
    """
    创建 FastAPI 应用实例

    使用工厂函数模式创建应用，便于测试和配置注入。
    内部初始化分析器实例并将其绑定到路由闭包中。

    Args:
        config_path: 配置文件路径，None 时使用默认查找策略

    Returns:
        配置好的 FastAPI 应用实例
    """

    app = FastAPI(
        title="DDoS 攻击溯源分析器 API",
        version="2.0.0",
        description="基于 NetFlow 数据的 DDoS 攻击溯源分析服务",
    )

    # 加载配置并初始化分析器（应用生命周期内复用同一实例）
    config = load_config(config_path)

    # 确保输出目录存在（避免报告导出时因目录不存在而失败）
    os.makedirs(config.output.dir, exist_ok=True)

    analyzer = DDoSTracebackAnalyzer(
        threshold_config=config.threshold,
        traceback_config=config.traceback,
        clickhouse_config=config.clickhouse,
        mysql_config=config.mysql,
        threat_intel_config=config.threat_intel,
        output_dir=config.output.dir,
        csv_path=config.attack_type_csv_path,
    )
    threat_intel_repo = ThreatIntelDashboardRepository(
        clickhouse_config=config.clickhouse,
        mysql_config=config.mysql,
        threat_intel_config=config.threat_intel,
    )
    app.mount("/artifacts", StaticFiles(directory=config.output.dir), name="artifacts")

    @app.get("/health")
    async def health_check():
        """健康检查端点，用于负载均衡和服务监控"""
        return {"status": "ok", "service": "ddos-trace"}

    @app.get("/reports", response_class=HTMLResponse)
    async def reports_index():
        return HTMLResponse(build_report_index_html(config.output.dir))

    @app.get("/reports/{run_name:path}", response_class=HTMLResponse)
    async def reports_detail(run_name: str):
        page = build_report_detail_html(config.output.dir, run_name)
        if page is None:
            raise HTTPException(status_code=404, detail="report not found")
        return HTMLResponse(page)

    @app.get("/intel", response_class=HTMLResponse)
    async def intel_dashboard():
        return HTMLResponse(build_intel_dashboard_html())

    @app.get("/intel/events", response_class=HTMLResponse)
    async def intel_event_list_page():
        return HTMLResponse(build_intel_event_list_html())

    @app.get("/intel/events/{event_id}", response_class=HTMLResponse)
    async def intel_event_detail(event_id: str):
        return HTMLResponse(build_intel_event_detail_html(event_id))

    @app.get("/intel/sources", response_class=HTMLResponse)
    async def intel_source_rank_page():
        return HTMLResponse(build_intel_source_rank_html())

    @app.get("/intel/sources/{ip}", response_class=HTMLResponse)
    async def intel_source_profile_page(ip: str):
        return HTMLResponse(build_intel_source_profile_html(ip))

    @app.get("/intel/assets/blacklist", response_class=HTMLResponse)
    async def intel_asset_blacklist_page():
        return HTMLResponse(build_intel_asset_blacklist_html())

    @app.get("/intel/assets/whitelist", response_class=HTMLResponse)
    async def intel_asset_whitelist_page():
        return HTMLResponse(build_intel_asset_whitelist_html())

    @app.get("/intel/assets/tags", response_class=HTMLResponse)
    async def intel_asset_tags_page():
        return HTMLResponse(build_intel_asset_tags_html())

    @app.get("/intel/assets/feedback", response_class=HTMLResponse)
    async def intel_asset_feedback_page():
        return HTMLResponse(build_intel_asset_feedback_html())

    @app.get("/api/v1/intel/dashboard")
    async def intel_dashboard_api():
        try:
            return threat_intel_repo.get_dashboard()
        except Exception as exc:
            logger.error("[API] 威胁情报看板查询失败 / error[%s]", exc)
            raise HTTPException(status_code=500, detail=f"威胁情报看板查询失败: {exc}")

    @app.get("/api/v1/intel/events")
    async def intel_events_api(limit: int = Query(50, ge=1, le=200)):
        try:
            return {"items": threat_intel_repo.list_events(limit=limit)}
        except Exception as exc:
            logger.error("[API] 威胁情报事件列表查询失败 / error[%s]", exc)
            raise HTTPException(status_code=500, detail=f"威胁情报事件列表查询失败: {exc}")

    @app.get("/api/v1/intel/events/{event_id}")
    async def intel_event_detail_api(event_id: str):
        try:
            detail = threat_intel_repo.get_event_detail(event_id=event_id)
        except Exception as exc:
            logger.error("[API] 威胁情报事件详情查询失败 / event_id[%s] / error[%s]", event_id, exc)
            raise HTTPException(status_code=500, detail=f"威胁情报事件详情查询失败: {exc}")
        if detail is None:
            raise HTTPException(status_code=404, detail="event not found")
        return detail

    # ------------------------------------------------------------------
    # 威胁情报 — 事件列表（带筛选分页）
    # ------------------------------------------------------------------

    @app.get("/api/v1/intel/events_filtered")
    async def intel_events_filtered_api(
        severity: Optional[str] = Query(None),
        attack_type: Optional[str] = Query(None),
        target_ip: Optional[str] = Query(None),
        target_mo: Optional[str] = Query(None),
        time_range: str = Query("30d"),
        start_time: Optional[str] = Query(None),
        end_time: Optional[str] = Query(None),
        sort_by: str = Query("time"),
        sort_order: str = Query("desc"),
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=100),
    ):
        try:
            return threat_intel_repo.list_events_filtered(
                severity=severity,
                attack_type=attack_type,
                target_ip=target_ip,
                target_mo=target_mo,
                time_range=time_range,
                start_time=start_time,
                end_time=end_time,
                sort_by=sort_by,
                sort_order=sort_order,
                page=page,
                page_size=page_size,
            )
        except Exception as exc:
            logger.error("[API] 威胁情报事件筛选查询失败 / error[%s]", exc)
            raise HTTPException(status_code=500, detail=f"查询失败: {exc}")

    # ------------------------------------------------------------------
    # 威胁情报 — 攻击源排行
    # ------------------------------------------------------------------

    @app.get("/api/v1/intel/top_sources")
    async def intel_top_sources_api(
        limit: int = Query(50, ge=1, le=200),
        min_events: int = Query(2, ge=1),
    ):
        try:
            return threat_intel_repo.get_top_repeat_sources(limit=limit, min_events=min_events)
        except Exception as exc:
            logger.error("[API] 攻击源排行查询失败 / error[%s]", exc)
            raise HTTPException(status_code=500, detail=f"查询失败: {exc}")

    @app.get("/api/v1/intel/clusters")
    async def intel_clusters_api(limit: int = Query(20, ge=1, le=100)):
        try:
            return {"items": threat_intel_repo.get_active_clusters(limit=limit)}
        except Exception as exc:
            logger.error("[API] 团伙聚类查询失败 / error[%s]", exc)
            raise HTTPException(status_code=500, detail=f"查询失败: {exc}")

    @app.get("/api/v1/intel/geo_rank")
    async def intel_geo_rank_api(limit: int = Query(20, ge=1, le=100)):
        try:
            return {"items": threat_intel_repo.get_geo_rank(limit=limit)}
        except Exception as exc:
            logger.error("[API] 地域排行查询失败 / error[%s]", exc)
            raise HTTPException(status_code=500, detail=f"查询失败: {exc}")

    # ------------------------------------------------------------------
    # 威胁情报 — 源 IP 画像
    # ------------------------------------------------------------------

    @app.get("/api/v1/intel/source_profile/{ip}")
    async def intel_source_profile_api(ip: str):
        try:
            profile = threat_intel_repo.get_source_profile(ip=ip)
        except Exception as exc:
            logger.error("[API] 源IP画像查询失败 / ip[%s] / error[%s]", ip, exc)
            raise HTTPException(status_code=500, detail=f"查询失败: {exc}")
        if profile is None:
            raise HTTPException(status_code=404, detail="source IP not found")
        return profile

    # ------------------------------------------------------------------
    # 威胁情报 — 情报资产管理
    # ------------------------------------------------------------------

    @app.get("/api/v1/intel/assets/blacklist")
    async def intel_asset_blacklist_api(
        status: str = Query("active"),
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=100),
    ):
        try:
            return threat_intel_repo.get_blacklist_assets(status=status, page=page, page_size=page_size)
        except Exception as exc:
            logger.error("[API] 黑名单查询失败 / error[%s]", exc)
            raise HTTPException(status_code=500, detail=f"查询失败: {exc}")

    @app.get("/api/v1/intel/assets/whitelist")
    async def intel_asset_whitelist_api(
        status: str = Query("active"),
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=100),
    ):
        try:
            return threat_intel_repo.get_whitelist_assets(status=status, page=page, page_size=page_size)
        except Exception as exc:
            logger.error("[API] 白名单查询失败 / error[%s]", exc)
            raise HTTPException(status_code=500, detail=f"查询失败: {exc}")

    @app.get("/api/v1/intel/assets/tags")
    async def intel_asset_tags_api(
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=100),
    ):
        try:
            return threat_intel_repo.get_tags_assets(page=page, page_size=page_size)
        except Exception as exc:
            logger.error("[API] 标签查询失败 / error[%s]", exc)
            raise HTTPException(status_code=500, detail=f"查询失败: {exc}")

    @app.get("/api/v1/intel/assets/feedback")
    async def intel_asset_feedback_api(
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=100),
    ):
        try:
            return threat_intel_repo.get_feedback_assets(page=page, page_size=page_size)
        except Exception as exc:
            logger.error("[API] 反馈查询失败 / error[%s]", exc)
            raise HTTPException(status_code=500, detail=f"查询失败: {exc}")

    # ------------------------------------------------------------------
    # POST /api/v1/analyze/alert  — 基于告警ID（推荐）
    # ------------------------------------------------------------------

    @app.post("/api/v1/analyze/alert", response_model=AnalysisResponse)
    async def analyze_by_alert(req: AlertAnalysisRequest):
        """
        基于告警 ID 执行溯源分析（推荐方式）

        自动从告警表获取目标IP、阈值、时间窗口、攻击类型等信息。
        只需传入 attack_id 即可触发完整的溯源分析流水线。
        """
        # 生成12位随机hex作为本次分析任务的唯一标识（用于日志追踪）
        task_id = uuid.uuid4().hex[:12]

        try:
            result = analyzer.run_analysis_by_alert(attack_id=req.attack_id)
        except Exception as e:
            logger.error("[API] 分析失败 / task_id[%s] / error[%s]", task_id, e)
            raise HTTPException(status_code=500, detail=f"分析失败: {e}")

        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])

        return _build_response(task_id, result)

    # ------------------------------------------------------------------
    # POST /api/v1/analyze/target  — 基于攻击目标
    # ------------------------------------------------------------------

    @app.post("/api/v1/analyze/target", response_model=AnalysisResponse)
    async def analyze_by_target(req: TargetAnalysisRequest):
        """
        基于攻击目标执行溯源分析

        自动从告警表获取阈值和攻击类型；若未找到告警则使用配置文件默认阈值。
        """
        task_id = uuid.uuid4().hex[:12]
        logger.info(
            "[API] 收到目标分析请求 / task_id[%s] / target[%s] / time[%s ~ %s]",
            task_id, req.attack_target, req.start_time, req.end_time,
        )

        start = _parse_optional_time(req.start_time)
        end = _parse_optional_time(req.end_time)

        try:
            result = analyzer.run_analysis_by_target(
                attack_target=req.attack_target,
                start_time=start,
                end_time=end,
            )
        except Exception as e:
            logger.error("[API] 分析失败 / task_id[%s] / error[%s]", task_id, e)
            raise HTTPException(status_code=500, detail=f"分析失败: {e}")

        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])

        return _build_response(task_id, result)

    # ------------------------------------------------------------------
    # POST /api/v1/analyze  — 手动传参（兼容旧接口）
    # ------------------------------------------------------------------

    @app.post("/api/v1/analyze", response_model=AnalysisResponse)
    async def analyze(req: AnalysisRequest):
        """
        手动传参执行溯源分析（使用配置文件中的默认阈值）

        传入目的IP、监测对象编码和时间范围，返回完整的分析结果。
        """
        task_id = uuid.uuid4().hex[:12]
        logger.info(
            "[API] 收到分析请求 / task_id[%s] / target_ips%s / target_mo%s / time[%s ~ %s]",
            task_id, req.target_ips, req.target_mo_codes, req.start_time, req.end_time,
        )

        try:
            start = datetime.strptime(req.start_time, "%Y-%m-%d %H:%M:%S")
            end = datetime.strptime(req.end_time, "%Y-%m-%d %H:%M:%S")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"时间格式错误: {e}")

        try:
            result = analyzer.run_full_analysis(
                target_ips=req.target_ips,
                target_mo_codes=req.target_mo_codes,
                start_time=start,
                end_time=end,
            )
        except Exception as e:
            logger.error("[API] 分析失败 / task_id[%s] / error[%s]", task_id, e)
            raise HTTPException(status_code=500, detail=f"分析失败: {e}")

        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])

        return _build_response(task_id, result)

    return app


# ------------------------------------------------------------------
# 响应构建
# ------------------------------------------------------------------

def _build_response(task_id: str, result: dict) -> AnalysisResponse:
    """
    从分析结果字典构建统一的 API 响应

    将 analyzer 返回的原始字典（含 DataFrame 等非序列化对象）
    转换为 Pydantic 响应模型，便于 FastAPI 自动序列化为 JSON。

    支持两种结果结构:
    - per-type 模式: features 可能为空 DataFrame，从 overview 聚合 summary
    - legacy 模式: features 包含统一分析结果

    Args:
        task_id: 本次分析任务ID
        result: analyzer.run_*() 返回的结果字典

    Returns:
        AnalysisResponse 实例
    """
    features = result.get("features", pd.DataFrame())
    overview = result.get("overview", {})

    # 分类统计: 优先从 features 计算，features 为空时从 overview 取
    if not features.empty:
        class_counts = features["traffic_class"].value_counts().to_dict()
        summary = {
            "total_source_ips": len(features),
            "confirmed": class_counts.get("confirmed", 0),
            "suspicious": class_counts.get("suspicious", 0),
            "borderline": class_counts.get("borderline", 0),
            "background": class_counts.get("background", 0),
            "anomaly_total": class_counts.get("confirmed", 0) + class_counts.get("suspicious", 0),
        }
    elif overview:
        summary = {
            "total_source_ips": overview.get("total_source_ips", 0),
            "confirmed": overview.get("confirmed", 0),
            "suspicious": overview.get("suspicious", 0),
            "borderline": overview.get("borderline", 0),
            "background": overview.get("background", 0),
            "anomaly_total": overview.get("anomaly_total", 0),
        }
    else:
        summary = {
            "total_source_ips": 0,
            "confirmed": 0,
            "suspicious": 0,
            "borderline": 0,
            "background": 0,
            "anomaly_total": 0,
        }

    # 异常源列表
    anomaly_df = result.get("anomaly_sources", pd.DataFrame())
    anomaly_list = []
    if not anomaly_df.empty:
        for ip, row in anomaly_df.iterrows():
            anomaly_list.append(SourceSummary(
                src_ip=str(ip),
                attack_confidence=round(float(row.get("attack_confidence", 0)), 2),
                traffic_class=str(row.get("traffic_class", "")),
                confidence_reasons=str(row.get("confidence_reasons", "")),
                packets_per_sec=round(float(row.get("packets_per_sec", 0)), 2),
                bytes_per_sec=round(float(row.get("bytes_per_sec", 0)), 2),
                country=_safe_str(row.get("country")),
                province=_safe_str(row.get("province")),
                isp=_safe_str(row.get("isp")),
            ))

    # 集群
    cluster_list = []
    cluster_report = result.get("clusters")
    if cluster_report is not None and not cluster_report.empty:
        for _, row in cluster_report.iterrows():
            cluster_list.append(ClusterSummary(
                cluster_id=int(row["cluster_id"]),
                member_count=int(row["member_count"]),
                member_ips=str(row.get("member_ips", "")),
                attack_type=str(row.get("attack_type", "未知")),
            ))

    # 地理分布
    geo_list = []
    geo_df = result.get("path_analysis", {}).get("geo_distribution", pd.DataFrame())
    if not geo_df.empty:
        for _, row in geo_df.iterrows():
            geo_list.append(GeoEntry(
                src_country=_safe_str(row.get("src_country")),
                src_province=_safe_str(row.get("src_province")),
                src_city=_safe_str(row.get("src_city")),
                src_isp=_safe_str(row.get("src_isp")),
                unique_source_ips=int(row.get("unique_source_ips", 0)),
                total_packets=float(row.get("total_packets", 0)),
                total_bytes=float(row.get("total_bytes", 0)),
            ))

    # 入口路由器
    router_list = []
    router_df = result.get("path_analysis", {}).get("entry_routers", pd.DataFrame())
    if not router_df.empty:
        for _, row in router_df.iterrows():
            router_list.append(RouterEntry(
                flow_ip_addr=_safe_str(row.get("flow_ip_addr")),
                input_if_index=_safe_int(row.get("input_if_index")),
                flow_count=int(row.get("flow_count", 0)),
                unique_source_ips=int(row.get("unique_source_ips", 0)),
                total_packets=float(row.get("total_packets", 0)),
                total_bytes=float(row.get("total_bytes", 0)),
            ))

    # 告警上下文
    alert_ctx = _build_alert_context(result.get("attack_context"))

    # 攻击类型分项摘要
    per_type_summary = None
    per_type_results = result.get("per_type_results", {})
    if per_type_results:
        per_type_summary = {}
        for at_name, type_result in per_type_results.items():
            s = type_result.get("summary", {})
            if s:
                per_type_summary[at_name] = {
                    "flow_count": s.get("flow_count", 0),
                    "flow_pct": s.get("flow_pct", 0),
                    "total_pps": s.get("total_pps", 0),
                    "total_bps": s.get("total_bps", 0),
                    "confirmed_count": s.get("confirmed_count", 0),
                    "suspicious_count": s.get("suspicious_count", 0),
                    "threshold_pps": s.get("threshold_pps", 0),
                    "threshold_bps": s.get("threshold_bps", 0),
                    "exceeds_pps_threshold": s.get("exceeds_pps_threshold", False),
                    "exceeds_bps_threshold": s.get("exceeds_bps_threshold", False),
                    "top_attackers": [
                        {"ip": t.get("ip", ""), "pps": t.get("pps", 0), "score": t.get("score", 0)}
                        for t in s.get("top_attackers", [])[:5]
                    ],
                }

    response = AnalysisResponse(
        task_id=task_id,
        status="completed",
        alert_context=alert_ctx,
        summary=summary,
        anomaly_sources=anomaly_list,
        clusters=cluster_list,
        geo_distribution=geo_list,
        entry_routers=router_list,
        per_type_summary=per_type_summary,
        report=result.get("report", ""),
    )

    logger.info(
        "[API] 分析完成 / task_id[%s] / confirmed[%d] / suspicious[%d]",
        task_id, summary["confirmed"], summary["suspicious"],
    )
    return response


def _build_alert_context(ctx: Optional[AttackContext]) -> Optional[AlertContextInfo]:
    """
    将 AttackContext 转换为 API 响应模型

    将 datetime 对象转换为 ISO 格式字符串，便于 JSON 序列化。
    """
    if ctx is None:
        return None
    return AlertContextInfo(
        attack_id=ctx.attack_id,
        attack_target=ctx.attack_target,
        attack_target_type=ctx.attack_target_type,
        target_ips=ctx.target_ips,
        target_mo_codes=ctx.target_mo_codes,
        start_time=ctx.start_time.isoformat() if ctx.start_time else None,
        end_time=ctx.end_time.isoformat() if ctx.end_time else None,
        attack_types=ctx.attack_types,
        attack_maintype=ctx.attack_maintype,
        direction=ctx.direction,
        level=ctx.level,
        max_pps=ctx.max_pps,
        max_bps=ctx.max_bps,
        threshold_pps=ctx.threshold_pps,
        threshold_bps=ctx.threshold_bps,
    )


def _parse_optional_time(time_str: Optional[str]) -> Optional[datetime]:
    """
    解析可选的时间字符串

    格式: "YYYY-MM-DD HH:MM:SS"
    解析失败返回 None（不抛异常，让后续逻辑使用默认值）
    """
    if time_str is None:
        return None
    try:
        return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _safe_str(val) -> Optional[str]:
    """安全转换为字符串，None 和 NaN 返回 None"""
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return None
    return str(val)


def _safe_int(val) -> Optional[int]:
    """安全转换为整数，None 和 NaN 返回 None"""
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return None
    return int(val)
