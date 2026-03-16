FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir redis psycopg2-binary

COPY suricata_ingester.py /app/suricata_ingester.py
COPY suricata_worker.py /app/suricata_worker.py
