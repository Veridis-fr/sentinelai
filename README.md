# SentinelAI

Appliance de cyberdéfense autonome pour PME — pipeline de détection moderne basé sur une architecture streaming.

SentinelAI ingère la télémétrie réseau (Suricata IDS + Syslog), la traite via Redis Streams, stocke les événements normalisés dans PostgreSQL, corrèle les alertes et les expose sur un dashboard SOC temps réel.

---

## Architecture

```
Suricata IDS ──┐
               ├──> Redis Streams ──> Workers Python ──> PostgreSQL (partitionné par mois)
Syslog UDP/TCP─┘
                                            │
                                    Alert Worker (règles)
                                            │
                                       FastAPI + WebSocket
                                            │
                                      Dashboard React (Live)
```

---

## Fonctionnalités

### Ingestion
- Suricata IDS — lecture temps réel du fichier `eve.json` avec détection de rotation
- Syslog — réception UDP et TCP sur port 5514
- Redis Streams comme bus d'événements unique avec consumer groups
- Gestion automatique des null bytes et caractères invalides

### Stockage
- Table `events` partitionnée par mois (PostgreSQL natif)
- Table `alerts` avec déduplication par `dedupe_key`
- Table `alert_events` pour la liaison événements ↔ alertes
- Table `baselines` pour le versionnage des modèles ML (Phase 4)
- Table `feedback` pour la vérité terrain opérateur
- Création automatique des partitions mensuelles via `partition_manager`

### Détection (3 règles actives)
- **SSH Bruteforce** — N échecs SSH depuis la même IP sur une fenêtre configurable (syslog)
- **Suricata haute sévérité** — alertes Suricata au-dessus d'un seuil de sévérité configurable
- **Port scan** — IP source contactant N ports distincts en moins de X minutes (sévérité adaptative)

### API
- FastAPI avec connection pool PostgreSQL
- WebSocket `/ws/alerts` — push temps réel des alertes
- Endpoints : `/health`, `/events`, `/alerts`, `/alerts/{id}/events`, `/stats`
- CORS configurable

### Dashboard
- Badge Live WebSocket (vert/orange/rouge)
- KPI temps réel depuis `/stats` (vrais totaux, pas estimations)
- Top IPs attaquantes
- Onglet Stats — alertes par règle, par sévérité, timeline 24h
- Filtres source / statut / recherche
- Détail alerte avec événements corrélés et métadonnées

---

## Stack technique

| Composant | Technologie |
|---|---|
| Ingestion | Python 3.11 |
| Transport | Redis 7 Streams |
| Stockage | PostgreSQL 16 (partitionné) |
| IDS | Suricata |
| API | FastAPI + uvicorn |
| Temps réel | WebSocket (uvicorn native) |
| Frontend | React 18 + TypeScript + Vite |
| Reverse proxy | nginx |
| Orchestration | Docker Compose |

---

## Structure du projet

```
sentinelai/
├── docker-compose.yml
├── .env.example
├── services/
│   ├── postgres/
│   │   └── migrations/
│   │       ├── 001_init_schema.sql      # events, alerts, alert_events, baselines, feedback
│   │       ├── 002_alerting.sql         # dedupe_key, index composites
│   │       └── 002_create_initial_partitions.sql
│   ├── workers/
│   │   ├── suricata_ingester.py         # lecture eve.json → Redis Streams
│   │   ├── suricata_worker.py           # Redis → PostgreSQL (Suricata)
│   │   ├── syslog_ingester.py           # UDP/TCP → Redis Streams
│   │   ├── syslog_worker.py             # Redis → PostgreSQL (Syslog)
│   │   ├── alert_worker.py              # moteur de règles + corrélation
│   │   └── partition_manager.py        # création automatique des partitions
│   ├── api/
│   │   └── main.py                     # FastAPI + WebSocket + connection pool
│   └── frontend/
│       └── src/
│           └── App.tsx                 # Dashboard React temps réel
```

---

## Installation

```bash
git clone https://github.com/Veridis-fr/sentinelai
cd sentinelai
cp .env.example .env
# Éditer .env selon votre environnement (interface réseau, credentials, etc.)
docker compose up -d --build
```

### Accès

| Service | URL |
|---|---|
| Dashboard | `http://SERVER_IP` |
| API | `http://SERVER_IP:8000` |
| Documentation API | `http://SERVER_IP:8000/docs` |

---

## Configuration

Variables clés dans `.env` :

```bash
SURICATA_INTERFACE=eth0          # Interface réseau à surveiller

# Règles de détection
SSH_BRUTEFORCE_THRESHOLD=5       # Nombre d'échecs SSH pour déclencher une alerte
SSH_BRUTEFORCE_WINDOW_MINUTES=5  # Fenêtre de temps
PORT_SCAN_THRESHOLD=20           # Ports distincts pour déclencher port scan
PORT_SCAN_WINDOW_MINUTES=2

# Pool de connexions API
PG_POOL_MIN=2
PG_POOL_MAX=10

# WebSocket
WS_PUSH_INTERVAL_SECONDS=5
```

---

## Modèle de données

```sql
events        -- événements bruts normalisés, partitionné par event_ts
alerts        -- alertes corrélées avec déduplication
alert_events  -- liaison N-N alertes ↔ événements, partitionné
baselines     -- modèles ML versionnés (Phase 4)
feedback      -- vérité terrain opérateur (TP/FP)
```

---

## Statut du projet

| Phase | Description | Statut |
|---|---|---|
| Phase 0 | Socle infra Docker + PostgreSQL partitionné | ✅ |
| Phase 1 | Pipeline Suricata → Redis → PostgreSQL | ✅ |
| Phase 2 | Ingestion Syslog + Filebeat | ✅ |
| Phase 3 | Règles déterministes + Dashboard V1 | ✅ |
| Phase 3.5 | WebSocket temps réel + API stats + polish UI | ✅ |
| Phase 4 | IsolationForest + corrélation incidents | 🔄 Baseline en cours |
| Phase 5 | LLM co-pilote (Ollama local) | ⏳ |
| Phase 6 | Hardening + packaging + script install | ⏳ |

---

## Roadmap Phase 4

- Entraînement IsolationForest sur baseline 2 semaines minimum
- Table `feedback` pour réentraînement supervisé
- Corrélation temporelle simple (même IP, même type, fenêtre 5 min = 1 incident)
- Scoring de risque

## Roadmap Phase 5

- Ollama local (Mistral 7B quantisé)
- Flag `AI_EXPLAINER_ENABLED` — optionnel, les logs ne quittent pas l'appliance
- Explication incidents en langage naturel pour opérateur PME

## Roadmap Phase 6

- PostgreSQL et Redis sur `127.0.0.1` uniquement
- Authentification dashboard
- CORS restrictif
- Script d'installation one-liner
- Documentation utilisateur

---

## Auteur

**Valentin Delamare**
GitHub — [Veridis-fr](https://github.com/Veridis-fr)

SentinelAI est une appliance de cyberdéfense open-source conçue pour rendre la détection de menaces accessible aux PME sans infrastructure SOC dédiée.

---

## Licence

MIT	
