"""
ml_worker.py — IsolationForest training + continuous anomaly detection

Two modes:
  - train  : builds a new baseline model from recent events
  - detect : scores new events in a loop, creates alerts on anomalies

The worker runs in detect mode by default.
Training is triggered automatically when no active baseline exists,
or manually via ML_FORCE_TRAIN=true.
"""

import hashlib
import json
import os
import pickle
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import numpy as np
import psycopg2
import psycopg2.extras
from psycopg2.extensions import connection as PGConnection
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PG_HOST     = os.getenv("PG_HOST", "postgres")
PG_PORT     = int(os.getenv("PG_PORT", "5432"))
PG_DB       = os.getenv("PG_DB", "sentinel")
PG_USER     = os.getenv("PG_USER", "sentinel")
PG_PASSWORD = os.getenv("PG_PASSWORD", "sentinel")

# Training
ML_TRAIN_LOOKBACK_HOURS    = int(os.getenv("ML_TRAIN_LOOKBACK_HOURS", "336"))    # 14 days
ML_TRAIN_MIN_EVENTS        = int(os.getenv("ML_TRAIN_MIN_EVENTS", "10000"))
ML_N_ESTIMATORS            = int(os.getenv("ML_N_ESTIMATORS", "200"))
ML_CONTAMINATION           = float(os.getenv("ML_CONTAMINATION", "0.01"))        # 1% expected anomalies
ML_FORCE_TRAIN             = os.getenv("ML_FORCE_TRAIN", "false").lower() == "true"

# Detection
ML_DETECT_POLL_SECONDS     = int(os.getenv("ML_DETECT_POLL_SECONDS", "30"))
ML_DETECT_LOOKBACK_MINUTES = int(os.getenv("ML_DETECT_LOOKBACK_MINUTES", "5"))
ML_ANOMALY_THRESHOLD       = float(os.getenv("ML_ANOMALY_THRESHOLD", "-0.05"))   # score below = anomaly
ML_ALERT_MIN_SCORE         = float(os.getenv("ML_ALERT_MIN_SCORE", "-0.10"))     # only alert on strong anomalies
ML_ALERT_COOLDOWN_MINUTES  = int(os.getenv("ML_ALERT_COOLDOWN_MINUTES", "15"))   # avoid alert storm per IP


# ---------------------------------------------------------------------------
# Feature engineering
# Features used for IsolationForest:
#   - hour_of_day        (0-23) — time pattern
#   - is_night           (0/1) — night = 0h-6h
#   - is_weekend         (0/1)
#   - dest_port_norm     normalized destination port
#   - src_entropy        IP source entropy (how unusual is this IP)
#   - is_suricata_alert  (0/1) — has an alert signature
#   - alert_severity     (0-10, 0 if none)
#   - proto_tcp          (0/1)
#   - proto_udp          (0/1)
# ---------------------------------------------------------------------------
FEATURE_NAMES = [
    "hour_of_day",
    "is_night",
    "is_weekend",
    "dest_port_norm",
    "is_suricata_alert",
    "alert_severity",
    "proto_tcp",
    "proto_udp",
]


def extract_features(row: dict) -> list[float]:
    event_ts = row.get("event_ts")
    if isinstance(event_ts, str):
        event_ts = datetime.fromisoformat(event_ts.replace("Z", "+00:00"))

    hour = event_ts.hour if event_ts else 12
    is_night = 1.0 if hour < 6 else 0.0
    is_weekend = 1.0 if event_ts and event_ts.weekday() >= 5 else 0.0

    dest_port = row.get("dest_port") or 0
    dest_port_norm = min(dest_port / 65535.0, 1.0)

    alert_severity = row.get("alert_severity") or 0
    is_alert = 1.0 if row.get("alert_signature") else 0.0

    proto = (row.get("proto") or "").lower()
    proto_tcp = 1.0 if proto == "tcp" else 0.0
    proto_udp = 1.0 if proto == "udp" else 0.0

    return [
        float(hour),
        is_night,
        is_weekend,
        dest_port_norm,
        is_alert,
        float(alert_severity),
        proto_tcp,
        proto_udp,
    ]


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def connect_pg() -> PGConnection:
    while True:
        try:
            conn = psycopg2.connect(
                host=PG_HOST, port=PG_PORT,
                dbname=PG_DB, user=PG_USER, password=PG_PASSWORD,
            )
            conn.autocommit = False
            print("[ml-worker] connected to postgres", flush=True)
            return conn
        except Exception as exc:
            print(f"[ml-worker] postgres not ready: {exc}", flush=True)
            time.sleep(3)


def get_active_baseline(conn: PGConnection) -> Optional[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT baseline_id, baseline_name, baseline_version,
                   config, metrics, created_at
            FROM baselines
            WHERE status = 'active'
              AND baseline_type = 'isolation_forest'
            ORDER BY created_at DESC
            LIMIT 1
            """
        )
        row = cur.fetchone()
        return dict(row) if row else None


def save_baseline(
    conn: PGConnection,
    model: IsolationForest,
    scaler: StandardScaler,
    metrics: dict,
    config: dict,
) -> str:
    # Désactiver les anciennes baselines
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE baselines SET status = 'retired'
            WHERE status = 'active' AND baseline_type = 'isolation_forest'
            """
        )

    # Sérialiser le modèle + scaler
    model_blob = pickle.dumps({"model": model, "scaler": scaler})
    model_b64 = __import__("base64").b64encode(model_blob).decode()

    config["model_b64"] = model_b64
    config["feature_names"] = FEATURE_NAMES

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO baselines (
                baseline_name, baseline_version, baseline_type,
                status, config, metrics
            )
            SELECT
                'isolation_forest',
                COALESCE((
                    SELECT MAX(baseline_version) + 1
                    FROM baselines
                    WHERE baseline_name = 'isolation_forest'
                ), 1),
                'isolation_forest',
                'active',
                %s::jsonb,
                %s::jsonb
            RETURNING baseline_id
            """,
            (
                json.dumps(config, ensure_ascii=False),
                json.dumps(metrics, ensure_ascii=False),
            ),
        )
        row = cur.fetchone()
        baseline_id = str(row[0])

    conn.commit()
    print(f"[ml-worker] baseline saved id={baseline_id}", flush=True)
    return baseline_id


def load_baseline(baseline: dict) -> tuple[IsolationForest, StandardScaler]:
    import base64
    config = baseline["config"]
    if isinstance(config, str):
        config = json.loads(config)
    model_blob = base64.b64decode(config["model_b64"])
    obj = pickle.loads(model_blob)
    return obj["model"], obj["scaler"]


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def fetch_training_events(conn: PGConnection) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ML_TRAIN_LOOKBACK_HOURS)
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT event_ts, source, event_type, src_ip, dest_ip,
                   dest_port, proto, alert_signature, alert_severity
            FROM events
            WHERE event_ts >= %s
            ORDER BY event_ts ASC
            """,
            (cutoff,),
        )
        return [dict(r) for r in cur.fetchall()]


def train(conn: PGConnection) -> Optional[str]:
    print(f"[ml-worker] fetching training events (lookback={ML_TRAIN_LOOKBACK_HOURS}h)...", flush=True)
    events = fetch_training_events(conn)

    if len(events) < ML_TRAIN_MIN_EVENTS:
        print(
            f"[ml-worker] not enough events to train: {len(events)} < {ML_TRAIN_MIN_EVENTS}",
            flush=True,
        )
        return None

    print(f"[ml-worker] training on {len(events)} events...", flush=True)

    X_raw = [extract_features(e) for e in events]
    X = np.array(X_raw, dtype=np.float32)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=ML_N_ESTIMATORS,
        contamination=ML_CONTAMINATION,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    scores = model.score_samples(X_scaled)
    anomaly_count = int((scores < ML_ANOMALY_THRESHOLD).sum())

    metrics = {
        "training_events":  len(events),
        "score_mean":       float(np.mean(scores)),
        "score_std":        float(np.std(scores)),
        "score_min":        float(np.min(scores)),
        "score_max":        float(np.max(scores)),
        "anomaly_count":    anomaly_count,
        "anomaly_rate":     round(anomaly_count / len(events), 4),
        "trained_at":       datetime.now(timezone.utc).isoformat(),
        "lookback_hours":   ML_TRAIN_LOOKBACK_HOURS,
    }

    config = {
        "n_estimators":    ML_N_ESTIMATORS,
        "contamination":   ML_CONTAMINATION,
        "threshold":       ML_ANOMALY_THRESHOLD,
        "lookback_hours":  ML_TRAIN_LOOKBACK_HOURS,
        "min_events":      ML_TRAIN_MIN_EVENTS,
    }

    print(
        f"[ml-worker] training done — score_mean={metrics['score_mean']:.4f} "
        f"anomaly_rate={metrics['anomaly_rate']:.4f}",
        flush=True,
    )

    return save_baseline(conn, model, scaler, metrics, config)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
_alert_cooldown: dict[str, datetime] = {}


def is_on_cooldown(key: str) -> bool:
    last = _alert_cooldown.get(key)
    if not last:
        return False
    return datetime.now(timezone.utc) - last < timedelta(minutes=ML_ALERT_COOLDOWN_MINUTES)


def set_cooldown(key: str) -> None:
    _alert_cooldown[key] = datetime.now(timezone.utc)


def fetch_recent_events(conn: PGConnection, since: datetime) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT event_id, event_ts, source, event_type,
                   src_ip, dest_ip, dest_port, proto,
                   alert_signature, alert_severity
            FROM events
            WHERE event_ts >= %s
            ORDER BY event_ts ASC
            """,
            (since,),
        )
        return [dict(r) for r in cur.fetchall()]


def already_scored(conn: PGConnection, event_ids: list[str]) -> set[str]:
    if not event_ids:
        return set()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT event_id::text FROM ml_scores WHERE event_id::text = ANY(%s)",
            (event_ids,),
        )
        return {str(r[0]) for r in cur.fetchall()}


def save_scores(
    conn: PGConnection,
    events: list[dict],
    scores: np.ndarray,
    predictions: np.ndarray,
    baseline_id: str,
    threshold: float,
    features_list: list[list[float]],
) -> None:
    with conn.cursor() as cur:
        for event, score, pred, feats in zip(events, scores, predictions, features_list):
            cur.execute(
                """
                INSERT INTO ml_scores (
                    scored_at, event_id, event_ts, baseline_id,
                    anomaly_score, is_anomaly, threshold, features
                )
                VALUES (NOW(), %s, %s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT DO NOTHING
                """,
                (
                    str(event["event_id"]),
                    event["event_ts"],
                    baseline_id,
                    float(score),
                    bool(pred == -1),
                    threshold,
                    json.dumps(dict(zip(FEATURE_NAMES, feats))),
                ),
            )
    conn.commit()


def create_ml_alert(conn: PGConnection, event: dict, score: float, baseline_id: str) -> None:
    src_ip = str(event.get("src_ip") or "unknown").replace("/32", "")
    dest_ip = str(event.get("dest_ip") or "unknown").replace("/32", "")
    event_type = event.get("event_type") or "unknown"

    cooldown_key = f"{src_ip}:{event_type}"
    if is_on_cooldown(cooldown_key):
        return

    # Sévérité basée sur le score
    if score < -0.20:
        severity = 4
    elif score < -0.15:
        severity = 3
    else:
        severity = 2

    dedupe_key = f"ml_anomaly:{src_ip}:{event_type}:{datetime.now(timezone.utc).strftime('%Y%m%d%H')}"
    title = f"Anomalie ML détectée — {event_type} depuis {src_ip}"

    metadata = {
        "rule_key":     "ml_isolation_forest",
        "src_ip":       src_ip,
        "dest_ip":      dest_ip,
        "event_type":   event_type,
        "anomaly_score": round(score, 4),
        "baseline_id":  str(baseline_id),
        "dest_port":    event.get("dest_port"),
        "proto":        event.get("proto"),
    }

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (
                dedupe_key, rule_key, title, status, severity,
                source, first_seen, last_seen, metadata
            )
            VALUES (%s, 'ml_isolation_forest', %s, 'open', %s, %s, %s, %s, %s::jsonb)
            ON CONFLICT (dedupe_key) DO UPDATE SET
                last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen),
                severity  = GREATEST(alerts.severity, EXCLUDED.severity),
                metadata  = EXCLUDED.metadata
            """,
            (
                dedupe_key,
                title,
                severity,
                event.get("source", "suricata"),
                event["event_ts"],
                event["event_ts"],
                json.dumps(metadata),
            ),
        )

    conn.commit()
    set_cooldown(cooldown_key)
    print(
        f"[ml-worker] anomaly alert — score={score:.4f} src={src_ip} "
        f"type={event_type} severity={severity}",
        flush=True,
    )


def detect_cycle(
    conn: PGConnection,
    model: IsolationForest,
    scaler: StandardScaler,
    baseline: dict,
    threshold: float,
) -> int:
    since = datetime.now(timezone.utc) - timedelta(minutes=ML_DETECT_LOOKBACK_MINUTES)
    events = fetch_recent_events(conn, since)

    if not events:
        return 0

   # Filtrer les events déjà scorés
    event_ids = [str(e["event_id"]) for e in events]
    scored_ids = already_scored(conn, event_ids)
    events = [e for e in events if str(e["event_id"]) not in scored_ids]

    if not events:
        return 0

    features_list = [extract_features(e) for e in events]
    X = np.array(features_list, dtype=np.float32)
    X_scaled = scaler.transform(X)

    scores = model.score_samples(X_scaled)
    predictions = model.predict(X_scaled)

    baseline_id = str(baseline["baseline_id"])
    config = baseline["config"]
    if isinstance(config, str):
        config = json.loads(config)

    save_scores(conn, events, scores, predictions, baseline_id, threshold, features_list)

    anomalies = [
        (e, s) for e, s, p in zip(events, scores, predictions)
        if p == -1 and s < ML_ALERT_MIN_SCORE
    ]

    for event, score in anomalies:
        create_ml_alert(conn, event, score, baseline_id)

    if anomalies:
        print(
            f"[ml-worker] cycle — scored={len(events)} anomalies={len(anomalies)}",
            flush=True,
        )

    return len(anomalies)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    conn = connect_pg()

    # Vérifier si on doit entraîner
    baseline = get_active_baseline(conn)

    if baseline is None or ML_FORCE_TRAIN:
        reason = "forced" if ML_FORCE_TRAIN else "no active baseline"
        print(f"[ml-worker] training triggered ({reason})", flush=True)
        baseline_id = train(conn)
        if baseline_id is None:
            print("[ml-worker] training failed — not enough data, retrying in 1h", flush=True)
            time.sleep(3600)
            return main()
        baseline = get_active_baseline(conn)

    print(
        f"[ml-worker] loaded baseline id={baseline['baseline_id']} "
        f"version={baseline['baseline_version']}",
        flush=True,
    )

    model, scaler = load_baseline(baseline)
    config = baseline["config"]
    if isinstance(config, str):
        config = json.loads(config)
    threshold = float(config.get("threshold", ML_ANOMALY_THRESHOLD))

    print(f"[ml-worker] detection loop started (poll={ML_DETECT_POLL_SECONDS}s)", flush=True)

    while True:
        try:
            detect_cycle(conn, model, scaler, baseline, threshold)
            time.sleep(ML_DETECT_POLL_SECONDS)

        except (psycopg2.OperationalError, psycopg2.InterfaceError) as exc:
            print(f"[ml-worker] postgres lost: {exc}", flush=True)
            time.sleep(3)
            conn = connect_pg()
            baseline = get_active_baseline(conn)
            if baseline:
                model, scaler = load_baseline(baseline)

        except Exception as exc:
            print(f"[ml-worker] unexpected error: {exc}", flush=True)
            try:
                conn.rollback()
            except Exception:
                pass
            time.sleep(5)


if __name__ == "__main__":
    main()

