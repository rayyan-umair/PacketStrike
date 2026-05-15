"""
PacketStrike - API Layer
api.py - FastAPI server, WebSocket streaming, REST endpoints

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : The external interface of PacketStrike. Exposes a FastAPI
          server with REST endpoints for querying flows, strikes, and
          entities, plus a WebSocket endpoint that streams strike events
          to connected dashboard clients in real time.
          All business logic lives in the engine layers - the API only
          reads, formats, and streams. No analysis happens here.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/PacketStrike

"Silence the noise, strike the signal."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

# ── Third Party ───────────────────────────────────────────────────────────────
from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from database import Database
from entity import EntityEngine
from models import (
    EntitySummary,
    HealthResponse,
    StrikeSummary,
    StrikeType,
)

logger = logging.getLogger(__name__)


# ── WebSocket Connection Manager ──────────────────────────────────────────────

class ConnectionManager:
    """
    Manages all active WebSocket connections.
    Broadcasts strike events to every connected client.
    Dead connections are removed silently.
    """

    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        logger.info(
            f"WebSocket client connected. "
            f"Total: {len(self._connections)}"
        )

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        logger.info(
            f"WebSocket client disconnected. "
            f"Total: {len(self._connections)}"
        )

    async def broadcast(self, payload: dict) -> None:
        """
        Send a JSON payload to all connected clients.
        Dead connections are collected and removed after the broadcast.
        """
        if not self._connections:
            return

        message = json.dumps(payload, default=str)
        dead: Set[WebSocket] = set()

        async with self._lock:
            connections = set(self._connections)

        for ws in connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)

        if dead:
            async with self._lock:
                self._connections -= dead
            logger.debug(f"Removed {len(dead)} dead WebSocket connections.")

    @property
    def connection_count(self) -> int:
        return len(self._connections)


# ── App Factory ───────────────────────────────────────────────────────────────

def create_app(
    settings        : Settings,
    db              : Database,
    entity_engine   : EntityEngine,
    capture_stats_fn: callable,
    inspector_stats_fn: callable,
    detection_stats_fn: callable,
    started_at      : datetime,
) -> tuple[FastAPI, ConnectionManager]:
    """
    Build and return the FastAPI application and WebSocket manager.
    Called once from main.py at startup.

    All engine references are injected - the API layer owns nothing.
    """

    app = FastAPI(
        title       = "PacketStrike",
        description = "Local-first DPI network intelligence engine.",
        version     = settings.app_version,
        docs_url    = "/docs",
        redoc_url   = "/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins     = ["*"],
        allow_credentials = True,
        allow_methods     = ["*"],
        allow_headers     = ["*"],
    )

    manager = ConnectionManager()

    # ── Health ────────────────────────────────────────────────────────────────

    @app.get(
        "/health",
        response_model = HealthResponse,
        tags           = ["System"],
        summary        = "Health check and system status",
    )
    async def health() -> HealthResponse:
        uptime = (datetime.now(timezone.utc) - started_at).total_seconds()
        return HealthResponse(
            status       = "ok",
            app_name     = settings.app_name,
            version      = settings.app_version,
            capture_mode = settings.capture_mode,
            interface    = settings.capture_interface,
            ai_enabled   = settings.ai_enabled,
            uptime_seconds = uptime,
        )

    @app.get(
        "/stats",
        tags    = ["System"],
        summary = "Full engine statistics",
    )
    async def stats() -> dict:
        """
        Returns combined statistics from all engine layers:
        capture, DPI, detection, entity, database, and WebSocket.
        """
        db_stats = db.get_stats()
        return {
            "capture"    : capture_stats_fn(),
            "inspector"  : inspector_stats_fn(),
            "detections" : detection_stats_fn(),
            "entities"   : entity_engine.stats,
            "database"   : db_stats,
            "websocket"  : {
                "active_connections": manager.connection_count,
            },
        }

    # ── Strikes ───────────────────────────────────────────────────────────────

    @app.get(
        "/strikes",
        tags    = ["Strikes"],
        summary = "List recent strikes",
    )
    async def get_strikes(
        limit       : int           = Query(default=100, le=1000),
        src_ip      : Optional[str] = Query(default=None),
        strike_type : Optional[str] = Query(default=None),
        since_hours : int           = Query(default=24),
    ) -> List[dict]:
        """
        Return recent strike events with optional filters.
        Results are ordered newest first.
        """
        since = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        if since_hours:
            from datetime import timedelta
            since = datetime.now(timezone.utc) - timedelta(hours=since_hours)

        st = None
        if strike_type:
            try:
                st = StrikeType(strike_type)
            except ValueError:
                raise HTTPException(
                    status_code = status.HTTP_400_BAD_REQUEST,
                    detail      = f"Invalid strike_type: {strike_type}. "
                                  f"Valid values: {[s.value for s in StrikeType]}",
                )

        return db.get_strikes(
            since       = since,
            src_ip      = src_ip,
            strike_type = st,
            limit       = limit,
        )

    @app.get(
        "/strikes/summary",
        tags    = ["Strikes"],
        summary = "Strike count by type",
    )
    async def get_strike_summary() -> dict:
        """Return a count of all strikes grouped by strike type."""
        return db.get_strike_count_by_type()

    @app.get(
        "/strikes/{strike_id}",
        tags    = ["Strikes"],
        summary = "Get a single strike by ID",
    )
    async def get_strike(strike_id: str) -> dict:
        rows = db.get_strikes(limit=1)
        # Direct strike lookup via SQL
        results = db.query_flows_sql(
            f"SELECT * FROM strikes WHERE strike_id = '{strike_id}' LIMIT 1"
        )
        if not results:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail      = f"Strike {strike_id} not found.",
            )
        return results[0]

    # ── Flows ─────────────────────────────────────────────────────────────────

    @app.get(
        "/flows",
        tags    = ["Flows"],
        summary = "List recent flows",
    )
    async def get_flows(
        limit: int = Query(default=100, le=2000),
    ) -> List[dict]:
        """Return the most recent flow records across all IPs."""
        return db.get_recent_flows(limit=limit)

    @app.get(
        "/flows/ip/{ip}",
        tags    = ["Flows"],
        summary = "Get flows for a specific IP",
    )
    async def get_flows_by_ip(
        ip          : str,
        limit       : int = Query(default=200, le=2000),
        since_hours : int = Query(default=24),
    ) -> List[dict]:
        """Return all flows involving a specific source or destination IP."""
        from datetime import timedelta
        since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        return db.get_flows_by_ip(ip=ip, since=since, limit=limit)

    @app.post(
        "/flows/query",
        tags    = ["Flows"],
        summary = "Run a raw SQL SELECT against the flows table",
    )
    async def query_flows(body: dict) -> List[dict]:
        """
        Execute a SQL SELECT query against the live flows table.
        For analyst investigation - e.g.:
            { "sql": "SELECT * FROM flows WHERE dst_port = 4444 LIMIT 50" }
        Only SELECT statements are permitted.
        """
        sql = body.get("sql", "").strip()
        if not sql:
            raise HTTPException(
                status_code = status.HTTP_400_BAD_REQUEST,
                detail      = "Request body must contain a 'sql' field.",
            )
        try:
            return db.query_flows_sql(sql)
        except ValueError as e:
            raise HTTPException(
                status_code = status.HTTP_400_BAD_REQUEST,
                detail      = str(e),
            )
        except Exception as e:
            raise HTTPException(
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail      = f"Query failed: {e}",
            )

    # ── Entities ──────────────────────────────────────────────────────────────

    @app.get(
        "/entities",
        tags    = ["Entities"],
        summary = "List all tracked entities",
    )
    async def get_entities(
        min_risk    : float = Query(default=0.0),
        limit       : int   = Query(default=200, le=2000),
    ) -> List[dict]:
        """
        Return all tracked IP entities.
        Filter by minimum risk score with min_risk parameter.
        """
        entities = entity_engine.get_all_entities()
        if min_risk > 0:
            entities = [e for e in entities if e.risk_score >= min_risk]
        entities.sort(key=lambda e: e.risk_score, reverse=True)
        return [e.model_dump(mode="json") for e in entities[:limit]]

    @app.get(
        "/entities/high-risk",
        tags    = ["Entities"],
        summary = "List high-risk entities",
    )
    async def get_high_risk_entities(
        min_risk: float = Query(default=7.0),
    ) -> List[dict]:
        """Return entities with risk score at or above the threshold."""
        entities = entity_engine.get_high_risk_entities(min_risk=min_risk)
        return [e.model_dump(mode="json") for e in entities]

    @app.get(
        "/entities/{ip}",
        tags    = ["Entities"],
        summary = "Get entity profile for a specific IP",
    )
    async def get_entity(ip: str) -> dict:
        """
        Return the full entity profile for an IP address,
        including timeline, flags, risk score, and traffic stats.
        """
        entity = entity_engine.get_entity(ip)
        if not entity:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail      = f"Entity {ip} has not been observed.",
            )
        return entity.model_dump(mode="json")

    @app.get(
        "/entities/{ip}/timeline",
        tags    = ["Entities"],
        summary = "Get behavior timeline for a specific IP",
    )
    async def get_entity_timeline(
        ip   : str,
        limit: int = Query(default=100, le=1000),
    ) -> List[dict]:
        """
        Return the chronological behavior timeline for an IP entity.
        Most recent events first.
        """
        entity = entity_engine.get_entity(ip)
        if not entity:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail      = f"Entity {ip} has not been observed.",
            )
        timeline = sorted(
            entity.timeline,
            key     = lambda e: e.timestamp,
            reverse = True,
        )
        return [t.model_dump(mode="json") for t in timeline[:limit]]

    # ── Threat Intel ──────────────────────────────────────────────────────────

    @app.post(
        "/intel/reload",
        tags    = ["Intel"],
        summary = "Reload threat intelligence feed from disk",
    )
    async def reload_intel() -> dict:
        """
        Force an immediate reload of the threat intel feed.
        Useful after updating the known_bad.txt file.
        """
        try:
            detection_stats_fn()    # Verify engine is alive
            # Access intel store via entity engine's detection engine
            entity_engine._detections.intel.load()
            intel_stats = entity_engine._detections.intel.stats
            return {
                "status"  : "reloaded",
                "intel"   : intel_stats,
            }
        except Exception as e:
            raise HTTPException(
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail      = f"Intel reload failed: {e}",
            )

    @app.get(
        "/intel/stats",
        tags    = ["Intel"],
        summary = "Threat intelligence feed statistics",
    )
    async def intel_stats() -> dict:
        """Return current threat intel feed statistics."""
        return entity_engine._detections.intel.stats

    # ── WebSocket ─────────────────────────────────────────────────────────────

    @app.websocket("/ws/strikes")
    async def ws_strikes(ws: WebSocket) -> None:
        """
        Real-time WebSocket stream of strike events.

        Connect to receive JSON-encoded StrikeEvent objects as they fire.
        Heartbeat pings are sent every ws_heartbeat_interval seconds
        to keep the connection alive.

        Message format:
            { "type": "strike", "data": { ...StrikeEvent fields... } }
            { "type": "heartbeat", "timestamp": "UTC ISO8601" }
        """
        await manager.connect(ws)
        try:
            while True:
                # Heartbeat - keeps connection alive through proxies/firewalls
                await asyncio.sleep(settings.ws_heartbeat_interval)
                await ws.send_text(json.dumps({
                    "type"      : "heartbeat",
                    "timestamp" : datetime.now(timezone.utc).isoformat(),
                }))
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.debug(f"WebSocket error: {e}")
        finally:
            await manager.disconnect(ws)

    @app.websocket("/ws/flows")
    async def ws_flows(ws: WebSocket) -> None:
        """
        Real-time WebSocket stream of all flow records.
        High-volume - connect only for live traffic monitoring dashboards.

        Message format:
            { "type": "flow", "data": { ...FlowRecord fields... } }
        """
        await manager.connect(ws)
        try:
            while True:
                await asyncio.sleep(settings.ws_heartbeat_interval)
                await ws.send_text(json.dumps({
                    "type"      : "heartbeat",
                    "timestamp" : datetime.now(timezone.utc).isoformat(),
                }))
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.debug(f"WebSocket error: {e}")
        finally:
            await manager.disconnect(ws)

    return app, manager