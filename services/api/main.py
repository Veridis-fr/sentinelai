import json
import os
import asyncio
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Optional

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

PG_HOST = os.getenv("PG_HOST", "postgres")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB = os.getenv("PG_DB", "sentinel")
PG_USER = os.getenv("PG_USER", "sentinel")
PG_PASSWORD = os.getenv("PG_PASSWORD", "sentinel")
PG_POOL_MIN = int(os.getenv("PG_POOL_MIN", "2"))
PG_POOL_MAX = int(os.getenv("PG_POOL_MAX", "10"))

# CORS : liste séparée par virgules, ex: "http://localhost:80,https://sentinel.local"
CORS_ORIGINS_RAW = os.getenv("CORS_ORIGINS", "")
CORS_ORIGINS = [o.strip() for o in CORS_ORIGINS_RAW.split(",") if o.strip()] or ["*"]

WS_PUSH_INTERVAL_SECONDS = int(os.getenv("WS_PUSH_INTERVAL_SECONDS", "5"))

API_TITLE = "SentinelAI API"
API_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Connection pool — créé une seule fois au démarrage
# ---------------------------------------------------------------------------
_pool: ThreadedConnectionPool | None = None


def get_pool() -> ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = ThreadedConnectionPool(
            minconn=PG_POOL_MIN,
            maxconn=PG_POOL_MAX,
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_DB,
            user=PG_USER,
            password=PG_PASSWORD,
        )
    return _pool


@contextmanager
def get_conn():
    pool = get_pool()
    conn = pool.getconn()
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    try:
        yield conn
        conn.reset()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        pool.putconn(conn)


# ---------------------------------------------------------------------------
# WebSocket — gestionnaire de connexions actives
# ---------------------------------------------------------------------------
class AlertBroadcaster:
    def __init__(self) -> None:
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients = [c for c in self._clients if c is not ws]

    async def broadcast(self, payload: dict) -> None:
        dead: list[WebSocket] = []
        for client in self._clients:
            try:
                await client.send_json(payload)
            except Exception:
                dead.append(client)
        for ws in dead:
            self.disconnect(ws)

    @property
    def count(self) -> int:
        return len(self._clients)


broadcaster = AlertBroadcaster()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    return value


def fetch_latest_alerts(limit: int = 25) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    alert_id, dedupe_key, rule_key, title, status,
                    severity, source, first_seen, last_seen, metadata, created_at
                FROM alerts
                ORDER BY last_seen DESC, created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            return [jsonable(dict(row)) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Background task : push WebSocket toutes les N secondes
# ---------------------------------------------------------------------------
async def ws_push_loop() -> None:
    while True:
        await asyncio.sleep(WS_PUSH_INTERVAL_SECONDS)
        if broadcaster.count == 0:
            continue
        try:
            alerts = fetch_latest_alerts(25)
            await broadcaster.broadcast({"type": "alerts_update", "data": alerts})
        except Exception as exc:
            print(f"[ws-push] error: {exc}", flush=True)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description="API de consultation des événements et alertes SentinelAI.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup() -> None:
    get_pool()
    print(
        f"[api] pool initialized min={PG_POOL_MIN} max={PG_POOL_MAX}",
        flush=True,
    )
    asyncio.create_task(ws_push_loop())
    print(
        f"[api] ws push loop started interval={WS_PUSH_INTERVAL_SECONDS}s",
        flush=True,
    )


@app.on_event("shutdown")
async def shutdown() -> None:
    if _pool:
        _pool.closeall()
        print("[api] pool closed", flush=True)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
def root() -> dict[str, Any]:
    return {
        "name": API_TITLE,
        "version": API_VERSION,
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "events": "/events",
            "alerts": "/alerts",
            "stats": "/stats",
            "ws_alerts": "/ws/alerts",
        },
    }


@app.get("/health")
def health() -> dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT NOW() AS db_time")
            row = cur.fetchone()
            cur.execute("SELECT COUNT(*) AS count FROM events")
            events_count = cur.fetchone()["count"]
            cur.execute("SELECT COUNT(*) AS count FROM alerts")
            alerts_count = cur.fetchone()["count"]
    return {
        "status": "ok",
        "service": "sentinel-api",
        "db_time": jsonable(row["db_time"]),
        "ws_clients": broadcaster.count,
        "counts": {
            "events": events_count,
            "alerts": alerts_count,
        },
    }


@app.get("/stats")
def stats() -> dict[str, Any]:
    """
    Compteurs agrégés pour les KPI du dashboard.
    Tous les calculs sont faits en base, pas côté frontend.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:

            # Alertes par statut
            cur.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM alerts
                GROUP BY status
                """
            )
            alerts_by_status = {row["status"]: row["count"] for row in cur.fetchall()}

            # Alertes par rule_key (top 10)
            cur.execute(
                """
                SELECT rule_key, COUNT(*) AS count
                FROM alerts
                GROUP BY rule_key
                ORDER BY count DESC
                LIMIT 10
                """
            )
            alerts_by_rule = [dict(row) for row in cur.fetchall()]

            # Alertes par sévérité
            cur.execute(
                """
                SELECT severity, COUNT(*) AS count
                FROM alerts
                GROUP BY severity
                ORDER BY severity DESC
                """
            )
            alerts_by_severity = {str(row["severity"]): row["count"] for row in cur.fetchall()}

            # Events par source
            cur.execute(
                """
                SELECT source, COUNT(*) AS count
                FROM events
                GROUP BY source
                """
            )
            events_by_source = {row["source"]: row["count"] for row in cur.fetchall()}

            # Events par heure sur les dernières 24h
            cur.execute(
                """
                SELECT
                    date_trunc('hour', event_ts) AS hour,
                    source,
                    COUNT(*) AS count
                FROM events
                WHERE event_ts >= NOW() - INTERVAL '24 hours'
                GROUP BY date_trunc('hour', event_ts), source
                ORDER BY hour ASC
                """
            )
            events_timeline = [
                {
                    "hour": jsonable(row["hour"]),
                    "source": row["source"],
                    "count": row["count"],
                }
                for row in cur.fetchall()
            ]

            # Top 10 IP attaquantes (alertes ouvertes)
            cur.execute(
                """
                SELECT
                    metadata->>'attacker_ip' AS ip,
                    COUNT(*) AS alert_count,
                    MAX(last_seen) AS last_seen
                FROM alerts
                WHERE status = 'open'
                  AND metadata->>'attacker_ip' IS NOT NULL
                GROUP BY metadata->>'attacker_ip'
                ORDER BY alert_count DESC
                LIMIT 10
                """
            )
            top_attacker_ips = [
                {
                    "ip": row["ip"],
                    "alert_count": row["alert_count"],
                    "last_seen": jsonable(row["last_seen"]),
                }
                for row in cur.fetchall()
            ]

    return {
        "alerts": {
            "by_status": alerts_by_status,
            "by_rule": alerts_by_rule,
            "by_severity": alerts_by_severity,
        },
        "events": {
            "by_source": events_by_source,
            "timeline_24h": events_timeline,
        },
        "top_attacker_ips": top_attacker_ips,
    }


@app.get("/events")
def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    search: Optional[str] = None,
) -> dict[str, Any]:
    where_clauses: list[str] = []
    params: list[Any] = []

    if source:
        where_clauses.append("source = %s")
        params.append(source)
    if event_type:
        where_clauses.append("event_type = %s")
        params.append(event_type)
    if src_ip:
        where_clauses.append("src_ip::text = %s")
        params.append(src_ip)
    if search:
        where_clauses.append(
            """
            (
                COALESCE(alert_signature, '') ILIKE %s
                OR COALESCE(alert_category, '') ILIKE %s
                OR COALESCE(raw::text, '') ILIKE %s
            )
            """
        )
        like = f"%{search}%"
        params.extend([like, like, like])

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    query = f"""
        SELECT
            event_id, source_event_id, event_ts, source, event_type,
            src_ip, dest_ip, src_port, dest_port, proto, app_proto,
            flow_id, alert_signature, alert_category, alert_severity,
            tags, raw, created_at
        FROM events
        {where_sql}
        ORDER BY event_ts DESC
        LIMIT %s OFFSET %s
    """

    count_query = f"SELECT COUNT(*) AS total FROM events {where_sql}"

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(count_query, params)
            total = cur.fetchone()["total"]
            cur.execute(query, params + [limit, offset])
            rows = cur.fetchall()

    return {
        "items": [jsonable(dict(row)) for row in rows],
        "pagination": {"limit": limit, "offset": offset, "total": total},
        "filters": {"source": source, "event_type": event_type, "src_ip": src_ip, "search": search},
    }


@app.get("/alerts")
def list_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = None,
    rule_key: Optional[str] = None,
    source: Optional[str] = None,
) -> dict[str, Any]:
    where_clauses: list[str] = []
    params: list[Any] = []

    if status:
        where_clauses.append("status = %s")
        params.append(status)
    if rule_key:
        where_clauses.append("rule_key = %s")
        params.append(rule_key)
    if source:
        where_clauses.append("source = %s")
        params.append(source)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    query = f"""
        SELECT
            alert_id, dedupe_key, rule_key, title, status, severity,
            source, first_seen, last_seen, metadata, created_at
        FROM alerts
        {where_sql}
        ORDER BY last_seen DESC, created_at DESC
        LIMIT %s OFFSET %s
    """

    count_query = f"SELECT COUNT(*) AS total FROM alerts {where_sql}"

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(count_query, params)
            total = cur.fetchone()["total"]
            cur.execute(query, params + [limit, offset])
            rows = cur.fetchall()

    return {
        "items": [jsonable(dict(row)) for row in rows],
        "pagination": {"limit": limit, "offset": offset, "total": total},
        "filters": {"status": status, "rule_key": rule_key, "source": source},
    }


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    alert_id, dedupe_key, rule_key, title, status, severity,
                    source, first_seen, last_seen, metadata, created_at
                FROM alerts
                WHERE alert_id = %s
                """,
                (alert_id,),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return jsonable(dict(row))


@app.get("/alerts/{alert_id}/events")
def get_alert_events(
    alert_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT alert_id, title, rule_key, status, severity, source, first_seen, last_seen
                FROM alerts WHERE alert_id = %s
                """,
                (alert_id,),
            )
            alert = cur.fetchone()
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")

            cur.execute(
                "SELECT COUNT(*) AS total FROM alert_events ae WHERE ae.alert_id = %s",
                (alert_id,),
            )
            total = cur.fetchone()["total"]

            cur.execute(
                """
                SELECT
                    e.event_id, e.source_event_id, e.event_ts, e.source, e.event_type,
                    e.src_ip, e.dest_ip, e.src_port, e.dest_port, e.proto, e.app_proto,
                    e.flow_id, e.alert_signature, e.alert_category, e.alert_severity,
                    e.tags, e.raw, e.created_at
                FROM alert_events ae
                JOIN events e ON e.event_id = ae.event_id AND e.event_ts = ae.event_ts
                WHERE ae.alert_id = %s
                ORDER BY e.event_ts DESC
                LIMIT %s OFFSET %s
                """,
                (alert_id, limit, offset),
            )
            rows = cur.fetchall()

    return {
        "alert": jsonable(dict(alert)),
        "items": [jsonable(dict(row)) for row in rows],
        "pagination": {"limit": limit, "offset": offset, "total": total},
    }


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------
@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket) -> None:
    await broadcaster.connect(ws)
    print(f"[ws] client connected total={broadcaster.count}", flush=True)
    try:
        # Push immédiat à la connexion
        alerts = fetch_latest_alerts(25)
        await ws.send_json({"type": "alerts_update", "data": alerts})

        # Maintenir la connexion ouverte (ping/pong géré par uvicorn)
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        broadcaster.disconnect(ws)
        print(f"[ws] client disconnected total={broadcaster.count}", flush=True)
