CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    event_ts TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT,
    src_ip INET,
    dest_ip INET,
    proto TEXT,
    alert_signature TEXT,
    alert_category TEXT,
    alert_severity INTEGER,
    raw JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_event_ts ON events (event_ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dest_ip ON events (dest_ip);
