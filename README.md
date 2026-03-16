# SentinelAI

SentinelAI is a modular detection and threat analysis platform built step by step with an infrastructure-first approach.

## Current status

### Phase 1.1 in progress
This repository currently provides:

- PostgreSQL persistence with monthly partitioned event storage
- Redis Streams transport layer
- Suricata log ingestion from `eve.json`
- Python workers for ingestion, stream consumption, and partition management
- Docker Compose stack for local end-to-end validation

## Current data flow

Suricata -> Python Ingester -> Redis Streams -> Python Worker -> PostgreSQL

## Project structure

```text
.
├── docker-compose.yml
├── .env.example
├── README.md
└── services
    ├── postgres
    │   ├── data/
    │   └── migrations/
    ├── suricata
    │   └── logs/
    └── workers
        ├── Dockerfile
        ├── requirements.txt
        ├── suricata_ingester.py
        ├── suricata_worker.py
        └── partition_manager.py
