FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY suricata_ingester.py /app/suricata_ingester.py
COPY suricata_worker.py /app/suricata_worker.py
COPY syslog_ingester.py /app/syslog_ingester.py
COPY syslog_worker.py /app/syslog_worker.py
COPY partition_manager.py /app/partition_manager.py
