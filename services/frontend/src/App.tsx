import { useEffect, useMemo, useState } from "react";
import "./App.css";

const API_BASE = "/api";

type HealthResponse = {
  status: string;
  service: string;
  db_time: string;
  counts: {
    events: number;
    alerts: number;
  };
};

type AlertItem = {
  alert_id: string;
  dedupe_key?: string;
  rule_key: string;
  title: string;
  status: string;
  severity: number;
  source: string;
  first_seen: string;
  last_seen: string;
  metadata?: Record<string, unknown> | null;
  created_at?: string;
};

type EventItem = {
  event_id: string;
  source_event_id?: string;
  event_ts: string;
  source: string;
  event_type: string;
  src_ip: string | null;
  dest_ip: string | null;
  src_port: number | null;
  dest_port: number | null;
  proto: string | null;
  app_proto: string | null;
  flow_id: string | null;
  alert_signature: string | null;
  alert_category: string | null;
  alert_severity: number | null;
  tags: string[] | null;
  raw: Record<string, unknown> | null;
  created_at?: string;
};

type ListResponse<T> = {
  items: T[];
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
};

type AlertEventsResponse = {
  alert: AlertItem;
  items: EventItem[];
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
};

function formatDate(value?: string | null) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function severityClass(severity?: number | null) {
  if (severity == null) return "badge";
  if (severity >= 4) return "badge badge-red";
  if (severity >= 3) return "badge badge-amber";
  if (severity >= 2) return "badge badge-blue";
  return "badge badge-green";
}

function sourceClass(source?: string | null) {
  if (source === "suricata") return "badge badge-purple";
  if (source === "syslog") return "badge badge-cyan";
  return "badge";
}

async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`API error ${response.status}`);
  }
  return response.json();
}

function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [selectedAlertEvents, setSelectedAlertEvents] = useState<EventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [error, setError] = useState<string>("");

  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [tab, setTab] = useState<"alerts" | "events">("alerts");

  const loadDashboard = async () => {
    try {
      setLoading(true);
      setError("");

      const [healthData, alertsData, eventsData] = await Promise.all([
        apiGet<HealthResponse>("/health"),
        apiGet<ListResponse<AlertItem>>("/alerts?limit=25"),
        apiGet<ListResponse<EventItem>>("/events?limit=30"),
      ]);

      setHealth(healthData);
      setAlerts(alertsData.items);
      setEvents(eventsData.items);

      if (!selectedAlert && alertsData.items.length > 0) {
        await loadAlertDetails(alertsData.items[0]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  const loadAlertDetails = async (alert: AlertItem) => {
    try {
      setDetailsLoading(true);
      setSelectedAlert(alert);
      const data = await apiGet<AlertEventsResponse>(
        `/alerts/${alert.alert_id}/events?limit=100`
      );
      setSelectedAlertEvents(data.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load alert details");
    } finally {
      setDetailsLoading(false);
    }
  };

  useEffect(() => {
    void loadDashboard();
  }, []);

  const filteredAlerts = useMemo(() => {
    const q = search.trim().toLowerCase();

    return alerts.filter((alert) => {
      const matchesSource = sourceFilter === "all" || alert.source === sourceFilter;
      const matchesStatus = statusFilter === "all" || alert.status === statusFilter;
      const matchesSearch =
        !q ||
        alert.title.toLowerCase().includes(q) ||
        alert.rule_key.toLowerCase().includes(q) ||
        alert.alert_id.toLowerCase().includes(q);

      return matchesSource && matchesStatus && matchesSearch;
    });
  }, [alerts, search, sourceFilter, statusFilter]);

  const filteredEvents = useMemo(() => {
    const q = search.trim().toLowerCase();

    return events.filter((event) => {
      const rawMessage =
        event.raw && typeof event.raw["message"] === "string"
          ? String(event.raw["message"])
          : "";

      const matchesSource = sourceFilter === "all" || event.source === sourceFilter;
      const matchesSearch =
        !q ||
        event.source.toLowerCase().includes(q) ||
        event.event_type.toLowerCase().includes(q) ||
        rawMessage.toLowerCase().includes(q) ||
        (event.alert_signature || "").toLowerCase().includes(q);

      return matchesSource && matchesSearch;
    });
  }, [events, search, sourceFilter]);

  const openAlerts = alerts.filter((a) => a.status === "open").length;
  const highSeverity = alerts.filter((a) => a.severity >= 3).length;
  const syslogEvents = events.filter((e) => e.source === "syslog").length;
  const suricataEvents = events.filter((e) => e.source === "suricata").length;

  return (
    <div className="app-shell">
      <div className="app-container">
        <header className="hero">
          <div>
            <div className="hero-chip">SentinelAI · SOC Dashboard</div>
            <h1>Detection & visibility in one place</h1>
            <p>
              Vue unifiée des alertes, des événements Suricata et des logs
              Syslog, branchée directement sur ton API SentinelAI.
            </p>
          </div>

          <div className="hero-actions">
            <button className="btn btn-primary" onClick={() => void loadDashboard()}>
              Refresh
            </button>
            <div className="api-box">
              <div className="api-label">API</div>
              <div className="api-value">{API_BASE}</div>
            </div>
          </div>
        </header>

        <section className="kpi-grid">
          <div className="card kpi-card">
            <div className="kpi-label">Open alerts</div>
            <div className="kpi-value red">{openAlerts}</div>
            <div className="kpi-sub">{highSeverity} severity ≥ 3</div>
          </div>

          <div className="card kpi-card">
            <div className="kpi-label">Indexed events</div>
            <div className="kpi-value cyan">{health?.counts.events ?? 0}</div>
            <div className="kpi-sub">
              {syslogEvents} syslog / {suricataEvents} suricata
            </div>
          </div>

          <div className="card kpi-card">
            <div className="kpi-label">Known alerts</div>
            <div className="kpi-value amber">{health?.counts.alerts ?? 0}</div>
            <div className="kpi-sub">Correlated in PostgreSQL</div>
          </div>

          <div className="card kpi-card">
            <div className="kpi-label">Service state</div>
            <div className="kpi-value green">
              {health?.status === "ok" ? "ONLINE" : "CHECK"}
            </div>
            <div className="kpi-sub">
              {health ? `DB ${formatDate(health.db_time)}` : "Waiting for API"}
            </div>
          </div>
        </section>

        <section className="card filters-card">
          <div className="filters-grid">
            <input
              className="input"
              placeholder="Search alerts, rules, messages, signatures..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />

            <select
              className="select"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
            >
              <option value="all">All sources</option>
              <option value="syslog">Syslog</option>
              <option value="suricata">Suricata</option>
            </select>

            <select
              className="select"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="all">All statuses</option>
              <option value="open">Open</option>
              <option value="closed">Closed</option>
            </select>
          </div>
        </section>

        {error && <div className="error-box">{error}</div>}

        <section className="tabs-row">
          <button
            className={`tab-btn ${tab === "alerts" ? "active" : ""}`}
            onClick={() => setTab("alerts")}
          >
            Alerts
          </button>
          <button
            className={`tab-btn ${tab === "events" ? "active" : ""}`}
            onClick={() => setTab("events")}
          >
            Events
          </button>
        </section>

        {tab === "alerts" && (
          <section className="alerts-layout">
            <div className="card panel">
              <div className="panel-header">
                <h2>Active detections</h2>
                <p>Click an alert to inspect its correlated events.</p>
              </div>

              <div className="list-scroll">
                {loading ? (
                  <div className="empty-box">Loading alerts...</div>
                ) : filteredAlerts.length === 0 ? (
                  <div className="empty-box">No alerts found for the current filters.</div>
                ) : (
                  filteredAlerts.map((alert) => (
                    <button
                      key={alert.alert_id}
                      className={`alert-row ${
                        selectedAlert?.alert_id === alert.alert_id ? "selected" : ""
                      }`}
                      onClick={() => void loadAlertDetails(alert)}
                    >
                      <div className="row-top">
                        <div className="row-badges">
                          <span className={severityClass(alert.severity)}>
                            Severity {alert.severity}
                          </span>
                          <span className={sourceClass(alert.source)}>{alert.source}</span>
                          <span className="badge">{alert.status}</span>
                        </div>
                        <div className="row-time">{formatDate(alert.last_seen)}</div>
                      </div>

                      <div className="row-title">{alert.title}</div>
                      <div className="row-subtitle">{alert.rule_key}</div>
                      <div className="row-id">{alert.alert_id}</div>
                    </button>
                  ))
                )}
              </div>
            </div>

            <div className="card panel">
              <div className="panel-header">
                <h2>Alert details</h2>
                <p>Evidence, timeline and correlated events.</p>
              </div>

              {!selectedAlert ? (
                <div className="empty-box">Select an alert to inspect it.</div>
              ) : (
                <>
                  <div className="details-box">
                    <div className="row-badges">
                      <span className={severityClass(selectedAlert.severity)}>
                        Severity {selectedAlert.severity}
                      </span>
                      <span className={sourceClass(selectedAlert.source)}>
                        {selectedAlert.source}
                      </span>
                      <span className="badge">{selectedAlert.status}</span>
                    </div>

                    <div className="details-title">{selectedAlert.title}</div>
                    <div className="details-subtitle">
                      Rule: {selectedAlert.rule_key}
                    </div>

                    <div className="details-meta-grid">
                      <div className="mini-box">
                        <div className="mini-label">First seen</div>
                        <div className="mini-value">
                          {formatDate(selectedAlert.first_seen)}
                        </div>
                      </div>
                      <div className="mini-box">
                        <div className="mini-label">Last seen</div>
                        <div className="mini-value">
                          {formatDate(selectedAlert.last_seen)}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="subpanel-title">Correlated events</div>

                  <div className="list-scroll details-scroll">
                    {detailsLoading ? (
                      <div className="empty-box">Loading correlated events...</div>
                    ) : selectedAlertEvents.length === 0 ? (
                      <div className="empty-box">No correlated events found.</div>
                    ) : (
                      selectedAlertEvents.map((event) => {
                        const message =
                          event.raw && typeof event.raw["message"] === "string"
                            ? String(event.raw["message"])
                            : "No message";

                        return (
                          <div key={event.event_id} className="event-row">
                            <div className="row-top">
                              <div className="row-badges">
                                <span className={sourceClass(event.source)}>
                                  {event.source}
                                </span>
                                <span className="badge">{event.event_type}</span>
                              </div>
                              <div className="row-time">{formatDate(event.event_ts)}</div>
                            </div>

                            <div className="event-message">{message}</div>
                            <div className="event-meta">src_ip: {event.src_ip || "—"}</div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </>
              )}
            </div>
          </section>
        )}

        {tab === "events" && (
          <section className="card panel">
            <div className="panel-header">
              <h2>Recent events</h2>
              <p>Unified event feed across Suricata and Syslog.</p>
            </div>

            <div className="list-scroll events-scroll">
              {loading ? (
                <div className="empty-box">Loading events...</div>
              ) : filteredEvents.length === 0 ? (
                <div className="empty-box">No events found for the current filters.</div>
              ) : (
                filteredEvents.map((event) => {
                  const message =
                    event.raw && typeof event.raw["message"] === "string"
                      ? String(event.raw["message"])
                      : event.alert_signature || "Event captured";

                  const hostname =
                    event.raw && typeof event.raw["hostname"] === "string"
                      ? String(event.raw["hostname"])
                      : null;

                  return (
                    <div key={event.event_id} className="event-row">
                      <div className="row-top">
                        <div className="row-badges">
                          <span className={sourceClass(event.source)}>{event.source}</span>
                          <span className={severityClass(event.alert_severity)}>
                            {event.alert_severity != null
                              ? `Severity ${event.alert_severity}`
                              : event.event_type}
                          </span>
                          {hostname && <span className="badge">{hostname}</span>}
                        </div>
                        <div className="row-time">{formatDate(event.event_ts)}</div>
                      </div>

                      <div className="event-message">{message}</div>
                      <div className="event-meta">
                        src: {event.src_ip || "—"} · dest: {event.dest_ip || "—"} ·
                        proto: {event.proto || "—"} · type: {event.event_type}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

export default App;
