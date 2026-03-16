import hashlib
import json
import os
import time

import psycopg2
from psycopg2.extensions import connection as PGConnection
from psycopg2.extensions import cursor as PGCursor

PG_HOST     = os.getenv("PG_HOST", "postgres")
PG_PORT     = int(os.getenv("PG_PORT", "5432"))
PG_DB       = os.getenv("PG_DB", "sentinel")
PG_USER     = os.getenv("PG_USER", "sentinel")
PG_PASSWORD = os.getenv("PG_PASSWORD", "sentinel")

ALERT_POLL_INTERVAL_SECONDS  = int(os.getenv("ALERT_POLL_INTERVAL_SECONDS", "15"))
ALERT_LOOKBACK_MINUTES       = int(os.getenv("ALERT_LOOKBACK_MINUTES", "15"))
SSH_BRUTEFORCE_WINDOW_MINUTES = int(os.getenv("SSH_BRUTEFORCE_WINDOW_MINUTES", "5"))
SSH_BRUTEFORCE_THRESHOLD     = int(os.getenv("SSH_BRUTEFORCE_THRESHOLD", "5"))
SURICATA_HIGH_SEVERITY_MIN   = int(os.getenv("SURICATA_HIGH_SEVERITY_MIN", "3"))
PORT_SCAN_WINDOW_MINUTES     = int(os.getenv("PORT_SCAN_WINDOW_MINUTES", "2"))
PORT_SCAN_THRESHOLD          = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))
STALE_ALERT_HOURS            = int(os.getenv("STALE_ALERT_HOURS", "24"))


def connect_pg() -> PGConnection:
    while True:
        try:
            conn = psycopg2.connect(
                host=PG_HOST, port=PG_PORT,
                dbname=PG_DB, user=PG_USER, password=PG_PASSWORD,
            )
            conn.autocommit = False
            print("[alert-worker] connected to postgres", flush=True)
            return conn
        except Exception as exc:
            print(f"[alert-worker] postgres not ready: {exc}", flush=True)
            time.sleep(2)


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def build_dedupe_key(rule_key: str, raw_key: str) -> str:
    return f"{rule_key}:{stable_hash(raw_key)}"


def upsert_alert(
    cur: PGCursor,
    *,
    dedupe_key: str,
    rule_key: str,
    title: str,
    severity: int,
    source: str,
    first_seen,
    last_seen,
    metadata: dict,
) -> str:
    cur.execute(
        """
        INSERT INTO alerts (
            dedupe_key, rule_key, title, status, severity,
            source, first_seen, last_seen, metadata
        )
        VALUES (%s, %s, %s, 'open', %s, %s, %s, %s, %s::jsonb)
        ON CONFLICT (dedupe_key)
        DO UPDATE SET
            title     = EXCLUDED.title,
            status    = 'open',
            severity  = GREATEST(alerts.severity, EXCLUDED.severity),
            source    = EXCLUDED.source,
            last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen),
            metadata  = EXCLUDED.metadata
        RETURNING alert_id
        """,
        (
            dedupe_key, rule_key, title, severity, source,
            first_seen, last_seen,
            json.dumps(metadata, ensure_ascii=False),
        ),
    )
    row = cur.fetchone()
    if not row:
        raise RuntimeError("failed to upsert alert")
    return str(row[0])


def link_event(cur: PGCursor, alert_id: str, event_id: str, event_ts) -> None:
    cur.execute(
        """
        INSERT INTO alert_events (alert_id, event_id, event_ts)
        VALUES (%s, %s, %s)
        ON CONFLICT DO NOTHING
        """,
        (alert_id, event_id, event_ts),
    )


# ---------------------------------------------------------------------------
# Règle 1 — SSH bruteforce (syslog)
# ---------------------------------------------------------------------------
def process_ssh_bruteforce(cur: PGCursor) -> int:
    cur.execute(
        """
        WITH candidates AS (
            SELECT
                COALESCE(src_ip::text, raw->>'source_ip') AS attacker_ip,
                MIN(event_ts)          AS first_seen,
                MAX(event_ts)          AS last_seen,
                COUNT(*)               AS hit_count,
                MAX(raw->>'hostname')  AS hostname
            FROM events
            WHERE source = 'syslog'
              AND event_ts >= NOW() - (%s || ' minutes')::interval
              AND COALESCE(raw->>'appname', raw->>'program', '') = 'sshd'
              AND COALESCE(raw->>'message', '') ILIKE 'Failed password%%'
              AND (src_ip IS NOT NULL OR raw->>'source_ip' IS NOT NULL)
            GROUP BY COALESCE(src_ip::text, raw->>'source_ip')
            HAVING COUNT(*) >= %s
        )
        SELECT attacker_ip, first_seen, last_seen, hit_count, hostname
        FROM candidates
        ORDER BY last_seen DESC
        """,
        (str(SSH_BRUTEFORCE_WINDOW_MINUTES), SSH_BRUTEFORCE_THRESHOLD),
    )

    candidates = cur.fetchall()
    created_or_updated = 0

    for attacker_ip, first_seen, last_seen, hit_count, hostname in candidates:
        dedupe_key = build_dedupe_key(
            "ssh_bruteforce_syslog",
            f"{attacker_ip}:{hostname or 'unknown'}",
        )
        alert_id = upsert_alert(
            cur,
            dedupe_key=dedupe_key,
            rule_key="ssh_bruteforce_syslog",
            title=f"SSH brute force suspect depuis {attacker_ip}",
            severity=3,
            source="syslog",
            first_seen=first_seen,
            last_seen=last_seen,
            metadata={
                "rule_key":       "ssh_bruteforce_syslog",
                "attacker_ip":    attacker_ip,
                "hostname":       hostname,
                "window_minutes": SSH_BRUTEFORCE_WINDOW_MINUTES,
                "threshold":      SSH_BRUTEFORCE_THRESHOLD,
                "hit_count":      int(hit_count),
            },
        )
        cur.execute(
            """
            SELECT event_id, event_ts FROM events
            WHERE source = 'syslog'
              AND event_ts >= NOW() - (%s || ' minutes')::interval
              AND COALESCE(src_ip::text, raw->>'source_ip') = %s
              AND COALESCE(raw->>'appname', raw->>'program', '') = 'sshd'
              AND COALESCE(raw->>'message', '') ILIKE 'Failed password%%'
            ORDER BY event_ts ASC
            """,
            (str(SSH_BRUTEFORCE_WINDOW_MINUTES), attacker_ip),
        )
        for event_id, event_ts in cur.fetchall():
            link_event(cur, alert_id, str(event_id), event_ts)

        created_or_updated += 1
        print(
            f"[alert-worker] rule=ssh_bruteforce_syslog alert_id={alert_id} "
            f"attacker_ip={attacker_ip} hits={hit_count}",
            flush=True,
        )

    return created_or_updated


# ---------------------------------------------------------------------------
# Règle 2 — Suricata haute sévérité
# ---------------------------------------------------------------------------
def process_suricata_high_severity(cur: PGCursor) -> int:
    cur.execute(
        """
        WITH candidates AS (
            SELECT
                COALESCE(alert_signature, 'unknown-signature') AS signature,
                COALESCE(src_ip::text,  'unknown-src')         AS src_ip,
                COALESCE(dest_ip::text, 'unknown-dest')        AS dest_ip,
                MIN(event_ts)       AS first_seen,
                MAX(event_ts)       AS last_seen,
                MAX(alert_severity) AS max_severity,
                COUNT(*)            AS hit_count,
                MAX(alert_category) AS category
            FROM events
            WHERE source = 'suricata'
              AND event_ts >= NOW() - (%s || ' minutes')::interval
              AND COALESCE(alert_severity, 0) >= %s
            GROUP BY
                COALESCE(alert_signature, 'unknown-signature'),
                COALESCE(src_ip::text,  'unknown-src'),
                COALESCE(dest_ip::text, 'unknown-dest')
        )
        SELECT signature, src_ip, dest_ip, first_seen, last_seen,
               max_severity, hit_count, category
        FROM candidates
        ORDER BY last_seen DESC
        """,
        (str(ALERT_LOOKBACK_MINUTES), SURICATA_HIGH_SEVERITY_MIN),
    )

    candidates = cur.fetchall()
    created_or_updated = 0

    for signature, src_ip, dest_ip, first_seen, last_seen, max_severity, hit_count, category in candidates:
        dedupe_key = build_dedupe_key(
            "suricata_high_severity",
            f"{signature}:{src_ip}:{dest_ip}",
        )
        severity = int(max_severity) if max_severity is not None else SURICATA_HIGH_SEVERITY_MIN
        alert_id = upsert_alert(
            cur,
            dedupe_key=dedupe_key,
            rule_key="suricata_high_severity",
            title=f"Suricata haute sévérité : {signature}",
            severity=severity,
            source="suricata",
            first_seen=first_seen,
            last_seen=last_seen,
            metadata={
                "rule_key":           "suricata_high_severity",
                "signature":          signature,
                "src_ip":             src_ip,
                "dest_ip":            dest_ip,
                "category":           category,
                "hit_count":          int(hit_count),
                "severity_threshold": SURICATA_HIGH_SEVERITY_MIN,
            },
        )
        cur.execute(
            """
            SELECT event_id, event_ts FROM events
            WHERE source = 'suricata'
              AND event_ts >= NOW() - (%s || ' minutes')::interval
              AND COALESCE(alert_severity, 0) >= %s
              AND COALESCE(alert_signature, 'unknown-signature') = %s
              AND COALESCE(src_ip::text,  'unknown-src')  = %s
              AND COALESCE(dest_ip::text, 'unknown-dest') = %s
            ORDER BY event_ts ASC
            """,
            (str(ALERT_LOOKBACK_MINUTES), SURICATA_HIGH_SEVERITY_MIN,
             signature, src_ip, dest_ip),
        )
        for event_id, event_ts in cur.fetchall():
            link_event(cur, alert_id, str(event_id), event_ts)

        created_or_updated += 1
        print(
            f"[alert-worker] rule=suricata_high_severity alert_id={alert_id} "
            f"signature={signature} src={src_ip} dest={dest_ip} hits={hit_count}",
            flush=True,
        )

    return created_or_updated


# ---------------------------------------------------------------------------
# Règle 3 — Port scan (Suricata)
# Sévérité adaptative : <50 ports=2, 50-99=3, 100+=4
# ---------------------------------------------------------------------------
def process_port_scan(cur: PGCursor) -> int:
    cur.execute(
        """
        WITH candidates AS (
            SELECT
                src_ip::text                        AS scanner_ip,
                COALESCE(dest_ip::text, 'unknown')  AS target_ip,
                COUNT(DISTINCT dest_port)            AS distinct_ports,
                MIN(event_ts)                        AS first_seen,
                MAX(event_ts)                        AS last_seen,
                COUNT(*)                             AS hit_count
            FROM events
            WHERE source = 'suricata'
              AND event_ts >= NOW() - (%s || ' minutes')::interval
              AND src_ip IS NOT NULL
              AND dest_port IS NOT NULL
            GROUP BY src_ip::text, COALESCE(dest_ip::text, 'unknown')
            HAVING COUNT(DISTINCT dest_port) >= %s
        )
        SELECT scanner_ip, target_ip, distinct_ports, first_seen, last_seen, hit_count
        FROM candidates
        ORDER BY distinct_ports DESC
        """,
        (str(PORT_SCAN_WINDOW_MINUTES), PORT_SCAN_THRESHOLD),
    )

    candidates = cur.fetchall()
    created_or_updated = 0

    for scanner_ip, target_ip, distinct_ports, first_seen, last_seen, hit_count in candidates:
        dedupe_key = build_dedupe_key("port_scan", f"{scanner_ip}:{target_ip}")

        if distinct_ports >= 100:
            severity = 4
        elif distinct_ports >= 50:
            severity = 3
        else:
            severity = 2

        alert_id = upsert_alert(
            cur,
            dedupe_key=dedupe_key,
            rule_key="port_scan",
            title=f"Scan de ports depuis {scanner_ip} vers {target_ip}",
            severity=severity,
            source="suricata",
            first_seen=first_seen,
            last_seen=last_seen,
            metadata={
                "rule_key":       "port_scan",
                "scanner_ip":     scanner_ip,
                "target_ip":      target_ip,
                "distinct_ports": int(distinct_ports),
                "hit_count":      int(hit_count),
                "window_minutes": PORT_SCAN_WINDOW_MINUTES,
                "threshold":      PORT_SCAN_THRESHOLD,
            },
        )
        cur.execute(
            """
            SELECT event_id, event_ts FROM events
            WHERE source = 'suricata'
              AND event_ts >= NOW() - (%s || ' minutes')::interval
              AND src_ip::text = %s
              AND COALESCE(dest_ip::text, 'unknown') = %s
              AND dest_port IS NOT NULL
            ORDER BY event_ts ASC
            LIMIT 500
            """,
            (str(PORT_SCAN_WINDOW_MINUTES), scanner_ip, target_ip),
        )
        for event_id, event_ts in cur.fetchall():
            link_event(cur, alert_id, str(event_id), event_ts)

        created_or_updated += 1
        print(
            f"[alert-worker] rule=port_scan alert_id={alert_id} "
            f"scanner={scanner_ip} target={target_ip} ports={distinct_ports}",
            flush=True,
        )

    return created_or_updated


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------
def close_stale_alerts(cur: PGCursor) -> int:
    cur.execute(
        """
        UPDATE alerts SET status = 'closed'
        WHERE status = 'open'
          AND last_seen < NOW() - (%s || ' hours')::interval
        """,
        (str(STALE_ALERT_HOURS),),
    )
    closed = cur.rowcount or 0
    if closed:
        print(f"[alert-worker] closed_stale_alerts={closed} threshold={STALE_ALERT_HOURS}h", flush=True)
    return closed


def run_cycle(cur: PGCursor) -> tuple[int, int]:
    rule_hits  = process_ssh_bruteforce(cur)
    rule_hits += process_suricata_high_severity(cur)
    rule_hits += process_port_scan(cur)
    stale_closed = close_stale_alerts(cur)
    return rule_hits, stale_closed


def main() -> None:
    conn = connect_pg()

    while True:
        try:
            with conn.cursor() as cur:
                rule_hits, stale_closed = run_cycle(cur)
                conn.commit()
                print(
                    f"[alert-worker] cycle_done rule_hits={rule_hits} stale_closed={stale_closed}",
                    flush=True,
                )
            time.sleep(ALERT_POLL_INTERVAL_SECONDS)

        except (psycopg2.OperationalError, psycopg2.InterfaceError) as exc:
            print(f"[alert-worker] postgres connection lost: {exc}", flush=True)
            try:
                conn.close()
            except Exception:
                pass
            time.sleep(2)
            conn = connect_pg()

        except Exception as exc:
            conn.rollback()
            print(f"[alert-worker] unexpected error: {exc}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
