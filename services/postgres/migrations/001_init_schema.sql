CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS events (
    event_id UUID NOT NULL DEFAULT gen_random_uuid(),
    source_event_id TEXT NOT NULL,
    event_ts TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT,
    src_ip INET,
    dest_ip INET,
    src_port INTEGER,
    dest_port INTEGER,
    proto TEXT,
    app_proto TEXT,
    flow_id BIGINT,
    alert_signature TEXT,
    alert_category TEXT,
    alert_severity INTEGER,
    tags TEXT[] NOT NULL DEFAULT '{}',
    raw JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (event_ts, event_id)
) PARTITION BY RANGE (event_ts);

CREATE UNIQUE INDEX IF NOT EXISTS uq_events_source_message
    ON events (event_ts, source, source_event_id);

CREATE INDEX IF NOT EXISTS idx_events_event_ts
    ON events (event_ts DESC);

CREATE INDEX IF NOT EXISTS idx_events_event_type
    ON events (event_type);

CREATE INDEX IF NOT EXISTS idx_events_src_ip
    ON events (src_ip);

CREATE INDEX IF NOT EXISTS idx_events_dest_ip
    ON events (dest_ip);

CREATE INDEX IF NOT EXISTS idx_events_source
    ON events (source);

CREATE INDEX IF NOT EXISTS idx_events_alert_signature
    ON events (alert_signature);

CREATE INDEX IF NOT EXISTS idx_events_tags
    ON events USING GIN (tags);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_key TEXT,
    title TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    severity INTEGER,
    source TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alerts (status);

CREATE INDEX IF NOT EXISTS idx_alerts_last_seen
    ON alerts (last_seen DESC);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id UUID NOT NULL,
    event_id UUID NOT NULL,
    event_ts TIMESTAMPTZ NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (alert_id, event_ts, event_id)
) PARTITION BY RANGE (event_ts);

CREATE INDEX IF NOT EXISTS idx_alert_events_alert_id
    ON alert_events (alert_id, event_ts DESC);

CREATE INDEX IF NOT EXISTS idx_alert_events_event_id
    ON alert_events (event_id, event_ts DESC);

CREATE TABLE IF NOT EXISTS baselines (
    baseline_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    baseline_name TEXT NOT NULL,
    baseline_version INTEGER NOT NULL DEFAULT 1,
    baseline_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_baselines_name_version
    ON baselines (baseline_name, baseline_version);

CREATE OR REPLACE FUNCTION ensure_month_partition(
    p_parent_table TEXT,
    p_month_start TIMESTAMPTZ
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_month_start TIMESTAMPTZ := date_trunc('month', p_month_start);
    v_month_end   TIMESTAMPTZ := v_month_start + INTERVAL '1 month';
    v_suffix      TEXT := to_char(v_month_start AT TIME ZONE 'UTC', 'YYYYMM');
    v_partition   TEXT := format('%s_%s', p_parent_table, v_suffix);
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
        v_partition,
        p_parent_table,
        v_month_start,
        v_month_end
    );
END;
$$;
