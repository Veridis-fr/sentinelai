CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE events (
    id UUID DEFAULT gen_random_uuid(),
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT,
    raw JSONB NOT NULL,
    tags TEXT[],
    event_ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, event_ts)
) PARTITION BY RANGE (event_ts);

CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_name TEXT NOT NULL,
    severity TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    source TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE alert_events (
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    event_ts TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (alert_id, event_id, event_ts)
) PARTITION BY RANGE (event_ts);

CREATE TABLE baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    baseline_name TEXT NOT NULL,
    version TEXT NOT NULL,
    model_type TEXT NOT NULL,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE events_2026_03
PARTITION OF events
FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE alert_events_2026_03
PARTITION OF alert_events
FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE INDEX idx_events_event_ts ON events(event_ts);
CREATE INDEX idx_events_source ON events(source);
CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_raw_gin ON events USING GIN(raw);

CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);

CREATE INDEX idx_alert_events_event_ts ON alert_events(event_ts);
