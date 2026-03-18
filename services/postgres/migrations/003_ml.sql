-- Migration 003 : tables pour le ML worker

-- Scores d'anomalie par event (résultats IsolationForest)
CREATE TABLE IF NOT EXISTS ml_scores (
    score_id     UUID        NOT NULL DEFAULT gen_random_uuid(),
    scored_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_id     UUID        NOT NULL,
    event_ts     TIMESTAMPTZ NOT NULL,
    baseline_id  UUID        NOT NULL,
    anomaly_score NUMERIC(8, 6) NOT NULL,  -- score brut IsolationForest (-1 à 0, plus négatif = plus anormal)
    is_anomaly   BOOLEAN     NOT NULL DEFAULT FALSE,
    threshold    NUMERIC(8, 6) NOT NULL,
    features     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY  (score_id, scored_at)
) PARTITION BY RANGE (scored_at);

CREATE INDEX IF NOT EXISTS idx_ml_scores_scored_at
    ON ml_scores (scored_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_scores_event_id
    ON ml_scores (event_id);
CREATE INDEX IF NOT EXISTS idx_ml_scores_is_anomaly
    ON ml_scores (is_anomaly, scored_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_scores_baseline_id
    ON ml_scores (baseline_id);

-- Partitions initiales
SELECT ensure_month_partition('ml_scores', NOW());
SELECT ensure_month_partition('ml_scores', NOW() + INTERVAL '1 month');
