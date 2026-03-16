import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg2
import redis
from psycopg2.extensions import connection as PGConnection
from psycopg2.extensions import cursor as PGCursor

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
STREAM_KEY = os.getenv("REDIS_STREAM_KEY", "stream:suricata")
GROUP_NAME = os.getenv("REDIS_GROUP_NAME", "suricata-workers")
CONSUMER_NAME = os.getenv("REDIS_CONSUMER_NAME", "suricata-worker-1")
READ_COUNT = int(os.getenv("REDIS_READ_COUNT", "100"))
BLOCK_MS = int(os.getenv("REDIS_BLOCK_MS", "5000"))

PG_HOST = os.getenv("PG_HOST", "postgres")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB = os.getenv("PG_DB", "sentinel")
PG_USER = os.getenv("PG_USER", "sentinel")
PG_PASSWORD = os.getenv("PG_PASSWORD", "sentinel")


def connect_pg() -> PGConnection:
    while True:
        try:
            conn = psycopg2.connect(
                host=PG_HOST,
                port=PG_PORT,
                dbname=PG_DB,
                user=PG_USER,
                password=PG_PASSWORD,
            )
            conn.autocommit = False
            print("[worker] connected to postgres", flush=True)
            return conn
        except Exception as exc:
            print(f"[worker] postgres not ready: {exc}", flush=True)
            time.sleep(2)


def connect_redis() -> redis.Redis:
    while True:
        try:
            client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=True,
            )
            client.ping()
            print("[worker] connected to redis", flush=True)
            return client
        except Exception as exc:
            print(f"[worker] redis not ready: {exc}", flush=True)
            time.sleep(2)


def ensure_consumer_group(client: redis.Redis) -> None:
    try:
        client.xgroup_create(
            name=STREAM_KEY,
            groupname=GROUP_NAME,
            id="0",
            mkstream=True,
        )
        print(f"[worker] consumer group created: {GROUP_NAME}", flush=True)
    except redis.exceptions.ResponseError as exc:
        if "BUSYGROUP" in str(exc):
            print(f"[worker] consumer group already exists: {GROUP_NAME}", flush=True)
        else:
            raise


def parse_timestamp(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)

    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except Exception:
        return datetime.now(timezone.utc)


def normalize_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def safe_event_load(raw: str) -> dict:
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    return {}


def build_tags(event: dict) -> list[str]:
    tags: list[str] = []

    event_type = event.get("event_type")
    if event_type:
        tags.append(str(event_type))

    alert = event.get("alert")
    if isinstance(alert, dict):
        category = alert.get("category")
        signature = alert.get("signature")
        if category:
            tags.append(str(category))
        if signature:
            tags.append(str(signature))

    # Uniques en conservant l'ordre
    return list(dict.fromkeys(tags))


def insert_event(cur: PGCursor, message_id: str, raw: str) -> tuple[datetime, str]:
    event = safe_event_load(raw)

    event_ts = parse_timestamp(event.get("timestamp"))
    event_type = event.get("event_type")
    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    src_port = normalize_int(event.get("src_port"))
    dest_port = normalize_int(event.get("dest_port"))
    proto = event.get("proto")
    app_proto = event.get("app_proto")
    flow_id = normalize_int(event.get("flow_id"))

    alert_signature = None
    alert_category = None
    alert_severity = None

    if isinstance(event.get("alert"), dict):
        alert_signature = event["alert"].get("signature")
        alert_category = event["alert"].get("category")
        alert_severity = normalize_int(event["alert"].get("severity"))

    tags = build_tags(event)

    cur.execute(
        """
        INSERT INTO events (
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
            raw
        )
        VALUES (
            %s,
            %s,
            'suricata',
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s::jsonb
        )
        ON CONFLICT (event_ts, source, source_event_id) DO NOTHING
        """,
        (
            message_id,
            event_ts,
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
        ),
    )

    return event_ts, event_type or ""


def read_batch(
    client: redis.Redis,
    stream_id: str,
) -> list[tuple[str, dict[str, str]]]:
    response = client.xreadgroup(
        groupname=GROUP_NAME,
        consumername=CONSUMER_NAME,
        streams={STREAM_KEY: stream_id},
        count=READ_COUNT,
        block=BLOCK_MS,
    )

    if not response:
        return []

    messages: list[tuple[str, dict[str, str]]] = []
    for _, batch in response:
        for message_id, fields in batch:
            messages.append((message_id, fields))
    return messages


MAX_RETRY_BEFORE_SKIP = 3
_fail_counts: dict[str, int] = {}


def sanitize_raw(raw: str) -> str:
    # Supprime les null bytes que PostgreSQL refuse dans le JSONB
    return raw.replace("\\u0000", "").replace("\x00", "")


def process_messages(client: redis.Redis, conn: PGConnection, messages: list[tuple[str, dict[str, str]]]) -> int:
    processed = 0

    with conn.cursor() as cur:
        for message_id, fields in messages:
            raw = sanitize_raw(fields.get("raw", "{}"))

            try:
                event_ts, event_type = insert_event(cur, message_id, raw)
                conn.commit()
                client.xack(STREAM_KEY, GROUP_NAME, message_id)
                _fail_counts.pop(message_id, None)
                processed += 1
                print(
                    f"[worker] acked id={message_id} event_ts={event_ts.isoformat()} "
                    f"event_type={event_type}",
                    flush=True,
                )
            except Exception as exc:
                conn.rollback()
                _fail_counts[message_id] = _fail_counts.get(message_id, 0) + 1
                if _fail_counts[message_id] >= MAX_RETRY_BEFORE_SKIP:
                    # Message irrécupérable — on ack pour débloquer la queue
                    client.xack(STREAM_KEY, GROUP_NAME, message_id)
                    _fail_counts.pop(message_id, None)
                    print(f"[worker] skipped id={message_id} after {MAX_RETRY_BEFORE_SKIP} failures: {exc}", flush=True)
                else:
                    print(f"[worker] failed id={message_id} attempt={_fail_counts[message_id]}: {exc}", flush=True)

    return processed


def main() -> None:
    client = connect_redis()
    conn = connect_pg()
    ensure_consumer_group(client)

    print(
        f"[worker] stream={STREAM_KEY} group={GROUP_NAME} consumer={CONSUMER_NAME}",
        flush=True,
    )

    while True:
        try:
            pending_messages = read_batch(client, "0")
            if pending_messages:
                process_messages(client, conn, pending_messages)
                continue

            new_messages = read_batch(client, ">")
            if not new_messages:
                continue

            process_messages(client, conn, new_messages)

        except (psycopg2.OperationalError, psycopg2.InterfaceError) as exc:
            print(f"[worker] postgres connection lost: {exc}", flush=True)
            time.sleep(2)
            conn = connect_pg()

        except (
            redis.exceptions.ConnectionError,
            redis.exceptions.TimeoutError,
        ) as exc:
            print(f"[worker] redis connection lost: {exc}", flush=True)
            time.sleep(2)
            client = connect_redis()
            ensure_consumer_group(client)

        except Exception as exc:
            print(f"[worker] unexpected error: {exc}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
