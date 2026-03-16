import json
import os
import time
from pathlib import Path
from typing import Optional, TextIO

import redis

LOG_FILE = Path(os.getenv("SURICATA_EVE_FILE", "/logs/eve.json"))
STREAM_KEY = os.getenv("REDIS_STREAM_KEY", "stream:suricata")
STREAM_MAXLEN = int(os.getenv("REDIS_STREAM_MAXLEN", "100000"))
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
POLL_INTERVAL = float(os.getenv("INGEST_POLL_INTERVAL", "0.5"))


def connect_redis() -> redis.Redis:
    while True:
        try:
            client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=True,
            )
            client.ping()
            print("[ingester] connected to redis", flush=True)
            return client
        except Exception as exc:
            print(f"[ingester] redis not ready: {exc}", flush=True)
            time.sleep(2)


def wait_for_logfile() -> None:
    while not LOG_FILE.exists():
        print(f"[ingester] waiting for {LOG_FILE} ...", flush=True)
        time.sleep(2)


def open_logfile() -> tuple[TextIO, int]:
    file_obj = LOG_FILE.open("r", encoding="utf-8", errors="replace")
    file_obj.seek(0, os.SEEK_END)
    inode = os.fstat(file_obj.fileno()).st_ino
    print(f"[ingester] following {LOG_FILE} (inode={inode})", flush=True)
    return file_obj, inode


def detect_rotation(current_inode: int) -> bool:
    if not LOG_FILE.exists():
        return False

    try:
        latest_inode = LOG_FILE.stat().st_ino
    except FileNotFoundError:
        return False

    return latest_inode != current_inode


def safe_json_load(line: str) -> Optional[dict]:
    try:
        parsed = json.loads(line)
        if isinstance(parsed, dict):
            return parsed
        return None
    except json.JSONDecodeError:
        return None


def build_payload(event: dict) -> dict:
    return {
        "source": "suricata",
        "event_type": event.get("event_type", ""),
        "timestamp": event.get("timestamp", ""),
        "src_ip": event.get("src_ip", ""),
        "dest_ip": event.get("dest_ip", ""),
        "proto": event.get("proto", ""),
        "raw": json.dumps(event, ensure_ascii=False),
    }


def push_event(client: redis.Redis, payload: dict) -> str:
    return client.xadd(
        STREAM_KEY,
        payload,
        maxlen=STREAM_MAXLEN,
        approximate=True,
    )


def main() -> None:
    client = connect_redis()
    wait_for_logfile()

    file_obj, inode = open_logfile()
    pushed = 0
    skipped = 0

    while True:
        line = file_obj.readline()

        if not line:
            if detect_rotation(inode):
                print("[ingester] log rotation detected, reopening file", flush=True)
                file_obj.close()
                time.sleep(0.2)
                file_obj, inode = open_logfile()

            time.sleep(POLL_INTERVAL)
            continue

        line = line.strip()
        if not line:
            continue

        event = safe_json_load(line)
        if event is None:
            skipped += 1
            print(f"[ingester] invalid json skipped (total_skipped={skipped})", flush=True)
            continue

        payload = build_payload(event)

        while True:
            try:
                message_id = push_event(client, payload)
                pushed += 1
                print(
                    f"[ingester] pushed id={message_id} event_type={payload['event_type']} "
                    f"total_pushed={pushed}",
                    flush=True,
                )
                break
            except Exception as exc:
                print(f"[ingester] redis push failed: {exc}", flush=True)
                time.sleep(2)
                client = connect_redis()


if __name__ == "__main__":
    main()
