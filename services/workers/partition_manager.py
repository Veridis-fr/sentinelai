import os
import time
from datetime import datetime, timezone

import psycopg2

PG_HOST = os.getenv("PG_HOST", "postgres")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB = os.getenv("PG_DB", "sentinel")
PG_USER = os.getenv("PG_USER", "sentinel")
PG_PASSWORD = os.getenv("PG_PASSWORD", "sentinel")

LOOKAHEAD_MONTHS = int(os.getenv("PARTITION_LOOKAHEAD_MONTHS", "2"))
CHECK_INTERVAL_SECONDS = int(os.getenv("PARTITION_CHECK_INTERVAL_SECONDS", "3600"))


def connect_pg():
    while True:
        try:
            conn = psycopg2.connect(
                host=PG_HOST,
                port=PG_PORT,
                dbname=PG_DB,
                user=PG_USER,
                password=PG_PASSWORD,
            )
            conn.autocommit = True
            print("[partition-manager] connected to postgres", flush=True)
            return conn
        except Exception as exc:
            print(f"[partition-manager] postgres not ready: {exc}", flush=True)
            time.sleep(2)


def month_start(dt: datetime) -> datetime:
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def add_months(dt: datetime, months: int) -> datetime:
    year = dt.year + ((dt.month - 1 + months) // 12)
    month = ((dt.month - 1 + months) % 12) + 1
    return dt.replace(year=year, month=month, day=1)


def ensure_partitions(conn) -> None:
    now = datetime.now(timezone.utc)
    base = month_start(now)

    with conn.cursor() as cur:
        for offset in range(LOOKAHEAD_MONTHS + 1):
            target = add_months(base, offset)
            cur.execute("SELECT ensure_month_partition('events', %s)", (target,))
            cur.execute("SELECT ensure_month_partition('alert_events', %s)", (target,))
            print(
                f"[partition-manager] ensured partitions for {target.strftime('%Y-%m')}",
                flush=True,
            )


def main() -> None:
    conn = connect_pg()

    while True:
        try:
            ensure_partitions(conn)
            time.sleep(CHECK_INTERVAL_SECONDS)
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as exc:
            print(f"[partition-manager] postgres connection lost: {exc}", flush=True)
            time.sleep(2)
            conn = connect_pg()
        except Exception as exc:
            print(f"[partition-manager] unexpected error: {exc}", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
