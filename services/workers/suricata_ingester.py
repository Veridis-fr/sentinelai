import json
import os
import time
from pathlib import Path

import redis

LOG_FILE = Path("/logs/eve.json")
STREAM_KEY = "stream:suricata"
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def wait_for_file():
    while not LOG_FILE.exists():
        print(f"[ingester] waiting for {LOG_FILE} ...", flush=True)
        time.sleep(2)

def follow(file_obj):
    file_obj.seek(0, os.SEEK_END)
    while True:
        line = file_obj.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

def main():
    wait_for_file()
    print(f"[ingester] following {LOG_FILE}", flush=True)

    with LOG_FILE.open("r", encoding="utf-8", errors="replace") as f:
        for line in follow(f):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print("[ingester] invalid json line skipped", flush=True)
                continue

            payload = {
                "source": "suricata",
                "event_type": event.get("event_type", ""),
                "timestamp": event.get("timestamp", ""),
                "raw": json.dumps(event, ensure_ascii=False),
            }

            r.xadd(STREAM_KEY, payload, maxlen=100000, approximate=True)
            print(f"[ingester] pushed event_type={payload['event_type']}", flush=True)

if __name__ == "__main__":
    main()
