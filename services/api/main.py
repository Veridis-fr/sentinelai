import json
import os
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Optional

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

PG_HOST = os.getenv("PG_HOST", "postgres")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB = os.getenv("PG_DB", "sentinel")
PG_USER = os.getenv("PG_USER", "sentinel")
PG_PASSWORD = os.getenv("PG_PASSWORD", "sentinel")

API_TITLE = "SentinelAI API"
API_VERSION = "0.1.0"


def jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    return value


@contextmanager
def get_conn():
    conn = psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    try:
        yield conn
    finally:
        conn.close()


app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description="API de consultation des événements et alertes SentinelAI.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
        "counts": {
            "events": events_count,
            "alerts": alerts_count,
        },
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

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    query = f"""
        SELECT
            event_id,
            source_event_id,
            event_ts,
            source,
            event_type,
            src_ip,
            dest_ip,
            src_port,
            dest_port,
            proto,
            app_proto,
            flow_id,
            alert_signature,
            alert_category,
            alert_severity,
            tags,
            raw,
            created_at
        FROM events
        {where_sql}
        ORDER BY event_ts DESC
        LIMIT %s
        OFFSET %s
    """

    count_query = f"""
        SELECT COUNT(*) AS total
        FROM events
        {where_sql}
    """

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(count_query, params)
            total = cur.fetchone()["total"]

            cur.execute(query, params + [limit, offset])
            rows = cur.fetchall()

    return {
        "items": [jsonable(dict(row)) for row in rows],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
        },
        "filters": {
            "source": source,
            "event_type": event_type,
            "src_ip": src_ip,
            "search": search,
        },
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

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    query = f"""
        SELECT
            alert_id,
            dedupe_key,
            rule_key,
            title,
            status,
            severity,
            source,
            first_seen,
            last_seen,
            metadata,
            created_at
        FROM alerts
        {where_sql}
        ORDER BY last_seen DESC, created_at DESC
        LIMIT %s
        OFFSET %s
    """

    count_query = f"""
        SELECT COUNT(*) AS total
        FROM alerts
        {where_sql}
    """

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(count_query, params)
            total = cur.fetchone()["total"]

            cur.execute(query, params + [limit, offset])
            rows = cur.fetchall()

    return {
        "items": [jsonable(dict(row)) for row in rows],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
        },
        "filters": {
            "status": status,
            "rule_key": rule_key,
            "source": source,
        },
    }


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    alert_id,
                    dedupe_key,
                    rule_key,
                    title,
                    status,
                    severity,
                    source,
                    first_seen,
                    last_seen,
                    metadata,
                    created_at
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
                SELECT
                    alert_id,
                    title,
                    rule_key,
                    status,
                    severity,
                    source,
                    first_seen,
                    last_seen
                FROM alerts
                WHERE alert_id = %s
                """,
                (alert_id,),
            )
            alert = cur.fetchone()

            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")

            cur.execute(
                """
                SELECT COUNT(*) AS total
                FROM alert_events ae
                WHERE ae.alert_id = %s
                """,
                (alert_id,),
            )
            total = cur.fetchone()["total"]

            cur.execute(
                """
                SELECT
                    e.event_id,
                    e.source_event_id,
                    e.event_ts,
                    e.source,
                    e.event_type,
                    e.src_ip,
                    e.dest_ip,
                    e.src_port,
                    e.dest_port,
                    e.proto,
                    e.app_proto,
                    e.flow_id,
                    e.alert_signature,
                    e.alert_category,
                    e.alert_severity,
                    e.tags,
                    e.raw,
                    e.created_at
                FROM alert_events ae
                JOIN events e
                  ON e.event_id = ae.event_id
                 AND e.event_ts = ae.event_ts
                WHERE ae.alert_id = %s
                ORDER BY e.event_ts DESC
                LIMIT %s
                OFFSET %s
                """,
                (alert_id, limit, offset),
            )
            rows = cur.fetchall()

    return {
        "alert": jsonable(dict(alert)),
        "items": [jsonable(dict(row)) for row in rows],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
        },
    }
