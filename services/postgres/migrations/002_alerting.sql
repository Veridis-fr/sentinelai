ALTER TABLE alerts
ADD COLUMN IF NOT EXISTS dedupe_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_dedupe_key
ON alerts (dedupe_key)
WHERE dedupe_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_alerts_rule_key_status_last_seen
ON alerts (rule_key, status, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_events_source_event_ts
ON events (source, event_ts DESC);

CREATE INDEX IF NOT EXISTS idx_events_alert_severity
ON events (alert_severity);

CREATE INDEX IF NOT EXISTS idx_events_raw_gin
ON events
USING GIN (raw);
