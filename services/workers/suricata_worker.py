import json
import os
import time

import psycopg2
import redis

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
PG_HOST = os.getenv("PG_HOST", "postgres")
PG_DB = os.getenv("PG_DB", "sentinel")
PG_USER = os.getenv("PG_USER", "sentinel")
PG_PASSWORD = os.getenv("PG_PASSWORD", "sentinel")

STREAM_KEY = "stream:suricata"
LAST_ID = "0-0"

def connect_pg():
    while True:
        try:
            conn = psycopg2.connect(
                host=PG_HOST,
                dbname=PG_DB,
                user=PG_USER,
                password=PG_PASSWORD,
            )
            conn.autocommit = True
            print("[worker] connected to postgres", flush=True)
            return conn
        except Exception as e:
            print(f"[worker] postgres not ready: {e}", flush=True)
            time.sleep(2)

def connect_redis():
    while True:
        try:
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            r.ping()
            print("[worker] connected to redis", flush=True)
            return r
        except Exception as e:
            print(f"[worker] redis not ready: {e}", flush=True)
            time.sleep(2)

def main():
    global LAST_ID

    r = connect_redis()
    conn = connect_pg()
    cur = conn.cursor()

    while True:
        data = r.xread({STREAM_KEY: LAST_ID}, block=5000, count=100)

        if not data:
            continue

        for _, messages in data:
            for message_id, fields in messages:
                raw = fields.get("raw", "{}")

                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    event = {}

                event_ts = event.get("timestamp")
                event_type = event.get("event_type")
                src_ip = event.get("src_ip")
                dest_ip = event.get("dest_ip")
                proto = event.get("proto")

                alert_signature = None
                alert_category = None
                alert_severity = None

                if isinstance(event.get("alert"), dict):
                    alert_signature = event["alert"].get("signature")
                    alert_category = event["alert"].get("category")
                    alert_severity = event["alert"].get("severity")

                cur.execute(
                    """
                    INSERT INTO events (
                        event_ts,
                        source,
                        event_type,
                        src_ip,
                        dest_ip,
                        proto,
                        alert_signature,
                        alert_category,
                        alert_severity,
                        raw
                    )
                    VALUES (
                        COALESCE(%s::timestamptz, NOW()),
                        'suricata',
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s::jsonb
                    )
                    """,
                    (
                        event_ts,
                        event_type,
                        src_ip,
                        dest_ip,
                        proto,
                        alert_signature,
                        alert_category,
                        alert_severity,
                        raw,
                    ),
                )

                LAST_ID = message_id
                print(f"[worker] inserted {message_id} event_type={event_type}", flush=True)

if __name__ == "__main__":
    main()
