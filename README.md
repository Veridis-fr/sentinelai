# SentinelAI

Autonomous cybersecurity appliance for SMEs — a modern streaming-based detection pipeline.

SentinelAI ingests network telemetry (Suricata IDS + Syslog), processes it through Redis Streams, stores normalized events in PostgreSQL, correlates alerts using both deterministic rules and machine learning, and exposes everything on a real-time SOC dashboard.

---

## Architecture

```
Suricata IDS ──┐
               ├──> Redis Streams ──> Python Workers ──> PostgreSQL (monthly partitioned)
Syslog UDP/TCP─┘
                                            │
                                    Alert Worker (rules engine)
                                    ML Worker (IsolationForest)
                                            │
                                       FastAPI + WebSocket
                                            │
                                    React SOC Dashboard (Live)
```

---

## Features

### Ingestion
- Suricata IDS — real-time `eve.json` tail with log rotation detection
- Syslog — UDP and TCP reception on port 5514
- Redis Streams as single event bus with consumer groups
- Null byte and invalid character sanitization

### Storage
- `events` table partitioned by month (native PostgreSQL)
- `alerts` table with `dedupe_key` deduplication
- `alert_events` join table for alert ↔ event linking
- `ml_scores` table for IsolationForest anomaly scores
- `baselines` table for versioned ML models
- `feedback` table for operator ground truth (TP/FP)
- Automatic monthly partition creation via `partition_manager`

### Detection — Deterministic rules (3 active)
- **SSH Bruteforce** — N failed SSH attempts from the same IP within a configurable time window (syslog)
- **Suricata high severity** — Suricata alerts above a configurable severity threshold
- **Port scan** — source IP contacting N distinct ports within X minutes (adaptive severity)

### Detection — Machine Learning (IsolationForest)
- Trained on 2+ weeks of real network traffic baseline
- Continuous anomaly scoring every 30 seconds on new events
- Adaptive severity based on anomaly score
- Alert cooldown per IP/event_type to prevent alert storms
- Operator feedback loop (TP/FP) for model retraining
- Per-network learning — each deployment learns its own normal traffic profile

### API
- FastAPI with PostgreSQL connection pool
- WebSocket `/ws/alerts` — real-time alert push
- Endpoints: `/health`, `/events`, `/alerts`, `/alerts/{id}/events`, `/stats`
- Configurable CORS

### Dashboard
- Live WebSocket badge (green / amber / red)
- Real-time KPIs from `/stats` (true totals, not estimates)
- Top attacker IPs
- Stats tab — alerts by rule, by severity, 24h timeline
- Source / status / search filters
- Alert detail panel with correlated events and metadata

---

## Tech Stack

| Component | Technology |
|---|---|
| Ingestion | Python 3.11 |
| Transport | Redis 7 Streams |
| Storage | PostgreSQL 16 (partitioned) |
| IDS | Suricata |
| ML Detection | scikit-learn IsolationForest |
| API | FastAPI + uvicorn |
| Real-time | WebSocket (uvicorn native) |
| Frontend | React 18 + TypeScript + Vite |
| Reverse proxy | nginx |
| Orchestration | Docker Compose |

---

## Project Structure

```
sentinelai/
├── docker-compose.yml
├── .env.example
├── services/
│   ├── postgres/
│   │   └── migrations/
│   │       ├── 001_init_schema.sql      # events, alerts, alert_events, baselines, feedback
│   │       ├── 002_alerting.sql         # dedupe_key, composite indexes
│   │       ├── 002_create_initial_partitions.sql
│   │       └── 003_ml.sql              # ml_scores table
│   ├── workers/
│   │   ├── suricata_ingester.py         # eve.json tail → Redis Streams
│   │   ├── suricata_worker.py           # Redis → PostgreSQL (Suricata)
│   │   ├── syslog_ingester.py           # UDP/TCP → Redis Streams
│   │   ├── syslog_worker.py             # Redis → PostgreSQL (Syslog)
│   │   ├── alert_worker.py              # deterministic rules engine
│   │   ├── ml_worker.py                 # IsolationForest training + detection
│   │   └── partition_manager.py        # automatic monthly partition creation
│   ├── api/
│   │   └── main.py                     # FastAPI + WebSocket + connection pool
│   └── frontend/
│       └── src/
│           └── App.tsx                 # Real-time React dashboard
```

---

## Installation

```bash
git clone https://github.com/Veridis-fr/sentinelai
cd sentinelai
cp .env.example .env
# Edit .env to match your environment (network interface, credentials, etc.)
docker compose up -d --build
```

### Access

| Service | URL |
|---|---|
| Dashboard | `http://SERVER_IP` |
| API | `http://SERVER_IP:8000` |
| API docs | `http://SERVER_IP:8000/docs` |

---

## Configuration

Key variables in `.env`:

```bash
SURICATA_INTERFACE=eth0          # Network interface to monitor

# Detection rules
SSH_BRUTEFORCE_THRESHOLD=5
SSH_BRUTEFORCE_WINDOW_MINUTES=5
PORT_SCAN_THRESHOLD=20
PORT_SCAN_WINDOW_MINUTES=2

# ML Worker
ML_TRAIN_LOOKBACK_HOURS=336      # 14 days baseline
ML_TRAIN_MIN_EVENTS=10000
ML_CONTAMINATION=0.01            # Expected anomaly rate
ML_ANOMALY_THRESHOLD=-0.05       # Score below = anomaly
ML_ALERT_MIN_SCORE=-0.10         # Only alert on strong anomalies
ML_FORCE_TRAIN=false             # Set true to force retraining

# API
PG_POOL_MIN=2
PG_POOL_MAX=10
WS_PUSH_INTERVAL_SECONDS=5
```

---

## Data Model

```sql
events        -- normalized raw events, partitioned by event_ts
alerts        -- correlated alerts with deduplication
alert_events  -- N-N join between alerts and events, partitioned
ml_scores     -- IsolationForest anomaly scores per event
baselines     -- versioned ML models (pickle + scaler stored as base64)
feedback      -- operator ground truth (TP/FP) for model retraining
```

---

## ML Onboarding — How it works

SentinelAI learns what "normal" looks like for each specific network:

1. **Week 1-2** — collect baseline traffic (deterministic rules active, ML inactive)
2. **Auto-training** — IsolationForest trains automatically when `ML_TRAIN_MIN_EVENTS` is reached
3. **Detection** — model scores new events every 30s, alerts on anomalies
4. **Feedback loop** — operator marks FP/TP, model retrains periodically to improve

Each client deployment learns its own normal profile — a PME with an ERP has different normal traffic than a law firm or a medical practice.

---

## Project Status

| Phase | Description | Status |
|---|---|---|
| Phase 0 | Docker infra + partitioned PostgreSQL | ✅ |
| Phase 1 | Suricata → Redis → PostgreSQL pipeline | ✅ |
| Phase 2 | Syslog ingestion | ✅ |
| Phase 3 | Deterministic rules + Dashboard V1 | ✅ |
| Phase 3.5 | WebSocket live + stats API + UI polish | ✅ |
| Phase 4 | IsolationForest ML detection | ✅ Active — baseline accumulating |
| Phase 5 | LLM co-pilot (local Ollama) | ⏳ Next |
| Phase 6 | Hardening + packaging + install script | ⏳ |

---

## Roadmap

### Phase 5 — LLM co-pilot
- Local Ollama integration (quantized Mistral 7B)
- `AI_EXPLAINER_ENABLED` flag — optional, logs never leave the appliance
- Natural language incident explanation for non-expert SME operators
- Structured context sent to LLM: alert type, triggered rules, IP, 24h history
- French language output by default

### Phase 6 — Hardening & packaging
- PostgreSQL and Redis bound to `127.0.0.1` only
- Dashboard authentication
- Restrictive CORS
- One-liner install script
- Automatic ML onboarding mode (2-week baseline → auto-train → detection)
- User documentation

---

## Author

**Valentin Delamare**
GitHub — [Veridis-fr](https://github.com/Veridis-fr)

SentinelAI is an open-source cybersecurity appliance designed to bring threat detection to SMEs without a dedicated SOC infrastructure.

---

## License

MIT
