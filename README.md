# SentinelAI

SentinelAI is a modular detection and threat analysis platform built step by step from a clean infrastructure-first approach.

## Current status
Phase 1 completed:
- Docker Compose base stack
- Suricata ingestion
- Redis-based event transport
- Python workers
- PostgreSQL persistence layer

## Architecture
Suricata → Python Ingester → Redis / Worker pipeline → PostgreSQL

## Project structure
- `services/suricata/` : Suricata configuration and rules
- `services/workers/` : ingestion and processing workers
- `services/postgres/` : database init and migrations
- `services/redis/` : Redis service
- `configs/` : shared configuration files
- `scripts/` : helper scripts

## Goal
Build a scalable SOC-oriented detection platform before adding higher-level detection logic, API, or frontend.
