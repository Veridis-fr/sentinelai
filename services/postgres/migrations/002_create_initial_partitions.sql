SELECT ensure_month_partition('events', now());
SELECT ensure_month_partition('events', now() + INTERVAL '1 month');
SELECT ensure_month_partition('alert_events', now());
SELECT ensure_month_partition('alert_events', now() + INTERVAL '1 month');
