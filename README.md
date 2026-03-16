# SentinelAI

Lightweight SIEM and detection pipeline built around a modern streaming architecture.

SentinelAI ingests security telemetry (IDS and Syslog), processes it through Redis Streams, stores normalized events in PostgreSQL, and performs correlation to generate actionable alerts.

The project is designed as a **modular detection pipeline** that can later integrate machine learning detection and behavioral analysis.

---

# Architecture

SentinelAI follows a streaming security pipeline:

Suricata
      │
      │
      ├──> Redis Streams ──> Workers ──> PostgreSQL (partitioned)
      │
Syslog ┘

            ↓

      Alert Correlation Engine

            ↓

        FastAPI API

            ↓

       SOC Dashboard

---

# Features

Current capabilities (Phase 4)

### Event Ingestion
- Suricata IDS alert ingestion
- Syslog ingestion (UDP and TCP)
- Redis Streams event transport

### Event Storage
- Unified `events` table
- PostgreSQL partitioned by time
- JSONB raw event storage

### Detection
- Rule-based correlation engine
- Example detection: SSH brute force

### API
- FastAPI service
- Query events and alerts
- Health monitoring endpoint

### Dashboard
- React SOC dashboard
- Alert inspection
- Event timeline
- Basic filtering

---

# Technology Stack

Backend

Python  
FastAPI  
Redis Streams  
PostgreSQL  
Suricata IDS  
Docker Compose  

Frontend

React  
Vite  
SOC-style dashboard  

---

# Project Structure

sentinelai

docker-compose.yml

migrations  
SQL schema

services  

suricata-ingester  
ingests Suricata alerts  

suricata-worker  
normalizes and stores Suricata events  

syslog-ingester  
receives Syslog events  

syslog-worker  
normalizes Syslog logs  

workers  
alert correlation engine  

api  
FastAPI detection API  

frontend  
SOC dashboard  

---

# Data Model

Unified event model

event_ts — timestamp  
source — suricata or syslog  
event_type — normalized event type  
src_ip — source IP  
dest_ip — destination IP  
alert_signature — IDS signature  
tags — event tags  
raw — full JSON payload  

This design enables

- unified correlation
- flexible parsing
- ML integration later

---

# Example Detection

Current implemented rule

SSH Brute Force

Triggered when multiple syslog entries contain

Failed password for invalid user

within a short time window.

Example alert

SSH brute force suspect depuis 172.20.0.1

---

# Running SentinelAI

Start the full stack

docker compose up -d --build

Services started

API — 8000  
PostgreSQL — 5432  
Redis — 6379  
Dashboard — 5173  

---

# API Endpoints

Health

/health

Events

/events

Alerts

/alerts

Alert details

/alerts/{alert_id}/events

Interactive documentation

http://SERVER_IP:8000/docs

---

# Dashboard

Access the SOC dashboard

http://SERVER_IP:5173

Features

- Alerts list
- Alert investigation panel
- Event feed
- Filtering by source

---

# Project Goals

SentinelAI aims to explore modern detection pipelines built on

- streaming architectures
- unified event storage
- scalable correlation
- machine learning assisted detection

Future work will include

- behavioral baselines
- anomaly detection
- clustering of events
- detection automation

---

# Development Status

Version

v1.0 — Phase 4 complete

Completed phases

Phase 1 — Infrastructure stack  
Phase 2 — Suricata ingestion pipeline  
Phase 3 — Syslog ingestion pipeline  
Phase 4 — Detection engine + API + dashboard  

---

# Future Roadmap

Phase 5

- Dockerized dashboard
- reverse proxy
- real time metrics

Phase 6

- ML detection models
- anomaly detection
- event clustering

---

# License

MIT

---

# Author

Valentin Delamare

GitHub

https://github.com/Veridis-fr

SentinelAI is an experimental detection platform created to explore SIEM architecture and cybersecurity telemetry processing.
