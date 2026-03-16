import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Activity, AlertTriangle, Radio, RefreshCw, Server, Shield, WifiOff } from "lucide-react";
import "./App.css";

const API_BASE = "/api";
const WS_URL = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/ws/alerts`;
const WS_RECONNECT_DELAY_MS = 4000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type HealthResponse = {
  status: string;
  service: string;
  db_time: string;
  ws_clients: number;
  counts: { events: number; alerts: number };
};

type StatsResponse = {
  alerts: {
    by_status: Record<string, number>;
    by_rule: { rule_key: string; count: number }[];
    by_severity: Record<string, number>;
  };
  events: {
    by_source: Record<string, number>;
    timeline_24h: { hour: string; source: string; count: number }[];
  };
  top_attacker_ips: { ip: string; alert_count: number; last_seen: string }[];
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
  event_ts: string;
  source: string;
  event_type: string;
  src_ip: string | null;
  dest_ip: string | null;
  src_port: number | null;
  dest_port: number | null;
  proto: string | null;
  alert_signature: string | null;
  alert_severity: number | null;
  tags: string[] | null;
  raw: Record<string, unknown> | null;
};

type ListResponse<T> = {
  items: T[];
  pagination: { limit: number; offset: number; total: number };
};

type AlertEventsResponse = {
  alert: AlertItem;
  items: EventItem[];
  pagination: { limit: number; offset: number; total: number };
};

type WsStatus = "connecting" | "connected" | "disconnected";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function formatDate(value?: string | null) {
  if (!value) return "—";
  try { return new Date(value).toLocaleString("fr-FR"); }
  catch { return value; }
}

function formatDateShort(value?: string | null) {
  if (!value) return "—";
  try { return new Date(value).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
  catch { return value; }
}

function severityClass(s?: number | null) {
  if (s == null) return "badge";
  if (s >= 4) return "badge badge-red";
  if (s >= 3) return "badge badge-amber";
  if (s >= 2) return "badge badge-blue";
  return "badge badge-green";
}

function sourceClass(s?: string | null) {
  if (s === "suricata") return "badge badge-purple";
  if (s === "syslog") return "badge badge-cyan";
  return "badge";
}

// Supprime le masque CIDR si présent (ex: 172.20.0.1/32 → 172.20.0.1)
function stripCidr(ip?: string | null): string {
  if (!ip) return "—";
  return ip.replace(/\/\d+$/, "");
}

async function apiGet<T>(path: string): Promise<T> {
  const r = await fetch(`${API_BASE}${path}`);
  if (!r.ok) throw new Error(`API ${r.status}`);
  return r.json();
}

// ---------------------------------------------------------------------------
// Hook WebSocket avec reconnexion automatique
// ---------------------------------------------------------------------------
function useAlertWebSocket(onAlerts: (alerts: AlertItem[]) => void) {
  const [status, setStatus] = useState<WsStatus>("connecting");
  const wsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;
    setStatus("connecting");

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      if (!mountedRef.current) return;
      setStatus("connected");
    };

    ws.onmessage = (e) => {
      if (!mountedRef.current) return;
      try {
        const msg = JSON.parse(e.data as string);
        if (msg.type === "alerts_update" && Array.isArray(msg.data)) {
          onAlerts(msg.data as AlertItem[]);
        }
      } catch { /* ignore */ }
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      setStatus("disconnected");
      timerRef.current = setTimeout(connect, WS_RECONNECT_DELAY_MS);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [onAlerts]);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      if (timerRef.current) clearTimeout(timerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return status;
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
export default function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [selectedAlertEvents, setSelectedAlertEvents] = useState<EventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [tab, setTab] = useState<"alerts" | "events" | "stats">("alerts");

  // WebSocket — reçoit les mises à jour d'alertes en push
  const wsStatus = useAlertWebSocket(
    useCallback((incoming: AlertItem[]) => {
      setAlerts(incoming);
      setLastUpdate(new Date());
    }, [])
  );

  const loadDashboard = useCallback(async () => {
    try {
      setLoading(true);
      setError("");
      const [healthData, eventsData, statsData] = await Promise.all([
        apiGet<HealthResponse>("/health"),
        apiGet<ListResponse<EventItem>>("/events?limit=50"),
        apiGet<StatsResponse>("/stats"),
      ]);
      setHealth(healthData);
      setEvents(eventsData.items);
      setStats(statsData);
      setLastUpdate(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAlertDetails = useCallback(async (alert: AlertItem) => {
    try {
      setDetailsLoading(true);
      setSelectedAlert(alert);
      const data = await apiGet<AlertEventsResponse>(`/alerts/${alert.alert_id}/events?limit=100`);
      setSelectedAlertEvents(data.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load alert details");
    } finally {
      setDetailsLoading(false);
    }
  }, []);

  useEffect(() => { void loadDashboard(); }, [loadDashboard]);

  // Sélectionner la première alerte quand elles arrivent via WS
  useEffect(() => {
    if (!selectedAlert && alerts.length > 0) {
      void loadAlertDetails(alerts[0]);
    }
  }, [alerts, selectedAlert, loadAlertDetails]);

  const filteredAlerts = useMemo(() => {
    const q = search.trim().toLowerCase();
    return alerts.filter((a) => {
      if (sourceFilter !== "all" && a.source !== sourceFilter) return false;
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (q && !a.title.toLowerCase().includes(q) && !a.rule_key.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [alerts, search, sourceFilter, statusFilter]);

  const filteredEvents = useMemo(() => {
    const q = search.trim().toLowerCase();
    return events.filter((e) => {
      if (sourceFilter !== "all" && e.source !== sourceFilter) return false;
      const msg = typeof e.raw?.["message"] === "string" ? String(e.raw["message"]) : "";
      if (q && !e.source.toLowerCase().includes(q) && !e.event_type.toLowerCase().includes(q) && !msg.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [events, search, sourceFilter]);

  // KPI depuis /stats (vrais totaux) avec fallback sur les données locales
  const openAlerts = stats?.alerts.by_status["open"] ?? alerts.filter((a) => a.status === "open").length;
  const totalAlerts = health?.counts.alerts ?? 0;
  const totalEvents = health?.counts.events ?? 0;
  const highSeverity = Object.entries(stats?.alerts.by_severity ?? {})
    .filter(([k]) => Number(k) >= 3)
    .reduce((acc, [, v]) => acc + v, 0);

  return (
    <div className="app-shell">
      <div className="app-container">

        {/* ---------------------------------------------------------------- Header */}
        <header className="hero">
          <div>
            <div className="hero-chip">
              <Shield size={12} style={{ display: "inline", marginRight: 6, verticalAlign: "middle" }} />
              SentinelAI · SOC Dashboard
            </div>
            <h1>Detection & visibility</h1>
            <p>Vue unifiée des alertes Suricata et logs Syslog — mise à jour en temps réel.</p>
          </div>

          <div className="hero-actions">
            {/* Indicateur WebSocket */}
            <div className={`ws-badge ${wsStatus}`}>
              {wsStatus === "connected"
                ? <><Radio size={13} /><span>Live</span></>
                : wsStatus === "connecting"
                ? <><Activity size={13} /><span>Connecting…</span></>
                : <><WifiOff size={13} /><span>Reconnecting…</span></>
              }
            </div>

            {lastUpdate && (
              <div className="api-box">
                <div className="api-label">Dernière mise à jour</div>
                <div className="api-value">{formatDateShort(lastUpdate.toISOString())}</div>
              </div>
            )}

            <button className="btn btn-primary" onClick={() => void loadDashboard()} disabled={loading}>
              <RefreshCw size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
              {loading ? "Loading…" : "Refresh"}
            </button>
          </div>
        </header>

        {/* ---------------------------------------------------------------- KPI */}
        <section className="kpi-grid">
          <div className="card kpi-card">
            <div className="kpi-label">
              <AlertTriangle size={13} style={{ marginRight: 5, verticalAlign: "middle" }} />
              Open alerts
            </div>
            <div className="kpi-value red">{openAlerts}</div>
            <div className="kpi-sub">{highSeverity} severity ≥ 3</div>
          </div>

          <div className="card kpi-card">
            <div className="kpi-label">
              <Activity size={13} style={{ marginRight: 5, verticalAlign: "middle" }} />
              Indexed events
            </div>
            <div className="kpi-value cyan">{totalEvents.toLocaleString()}</div>
            <div className="kpi-sub">
              {stats?.events.by_source["syslog"] ?? 0} syslog · {stats?.events.by_source["suricata"] ?? 0} suricata
            </div>
          </div>

          <div className="card kpi-card">
            <div className="kpi-label">
              <Shield size={13} style={{ marginRight: 5, verticalAlign: "middle" }} />
              Total alerts
            </div>
            <div className="kpi-value amber">{totalAlerts}</div>
            <div className="kpi-sub">
              {stats?.alerts.by_status["closed"] ?? 0} closed · {stats?.alerts.by_status["open"] ?? 0} open
            </div>
          </div>

          <div className="card kpi-card">
            <div className="kpi-label">
              <Server size={13} style={{ marginRight: 5, verticalAlign: "middle" }} />
              Service state
            </div>
            <div className="kpi-value green">{health?.status === "ok" ? "ONLINE" : "CHECK"}</div>
            <div className="kpi-sub">
              {wsStatus === "connected"
                ? <span style={{ color: "#86efac" }}>WS connecté · {health?.ws_clients ?? 0} client(s)</span>
                : <span style={{ color: "#fca5a5" }}>WS {wsStatus}</span>
              }
            </div>
          </div>
        </section>

        {/* ---------------------------------------------------------------- Top IPs (si données dispo) */}
        {stats && stats.top_attacker_ips.length > 0 && (
          <section className="card top-ips-card">
            <div className="top-ips-title">
              <AlertTriangle size={13} style={{ marginRight: 6, verticalAlign: "middle", color: "#fcd34d" }} />
              Top IPs attaquantes (alertes ouvertes)
            </div>
            <div className="top-ips-list">
              {stats.top_attacker_ips.slice(0, 6).map((ip) => (
                <div key={ip.ip} className="top-ip-item">
                  <span className="top-ip-addr">{stripCidr(ip.ip)}</span>
                  <span className="badge badge-red">{ip.alert_count} alert{ip.alert_count > 1 ? "s" : ""}</span>
                  <span className="top-ip-time">{formatDateShort(ip.last_seen)}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* ---------------------------------------------------------------- Filtres */}
        <section className="card filters-card">
          <div className="filters-grid">
            <input
              className="input"
              placeholder="Rechercher alertes, règles, signatures, messages…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <select className="select" value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}>
              <option value="all">Toutes les sources</option>
              <option value="syslog">Syslog</option>
              <option value="suricata">Suricata</option>
            </select>
            <select className="select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="all">Tous les statuts</option>
              <option value="open">Open</option>
              <option value="closed">Closed</option>
            </select>
          </div>
        </section>

        {error && <div className="error-box">{error}</div>}

        {/* ---------------------------------------------------------------- Tabs */}
        <section className="tabs-row">
          <button className={`tab-btn ${tab === "alerts" ? "active" : ""}`} onClick={() => setTab("alerts")}>
            Alertes {filteredAlerts.length > 0 && <span className="tab-count">{filteredAlerts.length}</span>}
          </button>
          <button className={`tab-btn ${tab === "events" ? "active" : ""}`} onClick={() => setTab("events")}>
            Événements
          </button>
          {stats && (
            <button className={`tab-btn ${tab === "stats" ? "active" : ""}`} onClick={() => setTab("stats")}>
              Stats
            </button>
          )}
        </section>

        {/* ---------------------------------------------------------------- Alertes */}
        {tab === "alerts" && (
          <section className="alerts-layout">
            <div className="card panel">
              <div className="panel-header">
                <h2>Détections actives</h2>
                <p>Cliquez sur une alerte pour inspecter les événements corrélés.</p>
              </div>
              <div className="list-scroll">
                {loading ? (
                  <div className="empty-box">Chargement…</div>
                ) : filteredAlerts.length === 0 ? (
                  <div className="empty-box">Aucune alerte pour ces filtres.</div>
                ) : (
                  <AnimatePresence initial={false}>
                    {filteredAlerts.map((alert) => (
                      <motion.button
                        key={alert.alert_id}
                        layout
                        initial={{ opacity: 0, y: -8 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -8 }}
                        transition={{ duration: 0.18 }}
                        className={`alert-row ${selectedAlert?.alert_id === alert.alert_id ? "selected" : ""}`}
                        onClick={() => void loadAlertDetails(alert)}
                      >
                        <div className="row-top">
                          <div className="row-badges">
                            <span className={severityClass(alert.severity)}>Sev {alert.severity}</span>
                            <span className={sourceClass(alert.source)}>{alert.source}</span>
                            <span className="badge">{alert.status}</span>
                          </div>
                          <div className="row-time">{formatDateShort(alert.last_seen)}</div>
                        </div>
                        <div className="row-title">{alert.title.replace(/\/\d+/g, "")}</div>
                        <div className="row-subtitle">{alert.rule_key}</div>
                      </motion.button>
                    ))}
                  </AnimatePresence>
                )}
              </div>
            </div>

            {/* Détail alerte */}
            <div className="card panel">
              <div className="panel-header">
                <h2>Détail alerte</h2>
                <p>Événements corrélés et timeline.</p>
              </div>
              {!selectedAlert ? (
                <div className="empty-box">Sélectionnez une alerte.</div>
              ) : (
                <>
                  <div className="details-box">
                    <div className="row-badges">
                      <span className={severityClass(selectedAlert.severity)}>Sev {selectedAlert.severity}</span>
                      <span className={sourceClass(selectedAlert.source)}>{selectedAlert.source}</span>
                      <span className="badge">{selectedAlert.status}</span>
                    </div>
                    <div className="details-title">{selectedAlert.title.replace(/\/\d+/g, "")}</div>
                    <div className="details-subtitle">Règle : {selectedAlert.rule_key}</div>
                    <div className="details-meta-grid">
                      <div className="mini-box">
                        <div className="mini-label">Première détection</div>
                        <div className="mini-value">{formatDate(selectedAlert.first_seen)}</div>
                      </div>
                      <div className="mini-box">
                        <div className="mini-label">Dernière détection</div>
                        <div className="mini-value">{formatDate(selectedAlert.last_seen)}</div>
                      </div>
                      {selectedAlert.metadata?.["hit_count"] != null && (
                        <div className="mini-box">
                          <div className="mini-label">Nombre de hits</div>
                          <div className="mini-value">{String(selectedAlert.metadata["hit_count"])}</div>
                        </div>
                      )}
                      {selectedAlert.metadata?.["attacker_ip"] != null && (
                        <div className="mini-box">
                          <div className="mini-label">IP attaquante</div>
                          <div className="mini-value" style={{ fontFamily: "monospace", color: "#fca5a5" }}>
                          {stripCidr(String(selectedAlert.metadata["attacker_ip"]))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="subpanel-title">Événements corrélés</div>
                  <div className="list-scroll details-scroll">
                    {detailsLoading ? (
                      <div className="empty-box">Chargement…</div>
                    ) : selectedAlertEvents.length === 0 ? (
                      <div className="empty-box">Aucun événement corrélé.</div>
                    ) : (
                      selectedAlertEvents.map((event) => {
                        const message = typeof event.raw?.["message"] === "string"
                          ? String(event.raw["message"])
                          : event.alert_signature
                          ?? `${event.event_type} — ${stripCidr(event.src_ip)} → ${stripCidr(event.dest_ip)}`;
                        return (
                          <div key={event.event_id} className="event-row">
                            <div className="row-top">
                              <div className="row-badges">
                                <span className={sourceClass(event.source)}>{event.source}</span>
                                <span className="badge">{event.event_type}</span>
                                {event.dest_port && <span className="badge">:{event.dest_port}</span>}
                              </div>
                              <div className="row-time">{formatDateShort(event.event_ts)}</div>
                            </div>
                            <div className="event-message">{message}</div>
                            <div className="event-meta">
                              src: {stripCidr(event.src_ip)} · dest: {stripCidr(event.dest_ip)} · proto: {event.proto ?? "—"}
                            </div>
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

        {/* ---------------------------------------------------------------- Événements */}
        {tab === "events" && (
          <section className="card panel">
            <div className="panel-header">
              <h2>Flux d'événements récents</h2>
              <p>Vue unifiée Suricata + Syslog.</p>
            </div>
            <div className="list-scroll events-scroll">
              {loading ? (
                <div className="empty-box">Chargement…</div>
              ) : filteredEvents.length === 0 ? (
                <div className="empty-box">Aucun événement pour ces filtres.</div>
              ) : (
                filteredEvents.map((event) => {
                  const message = typeof event.raw?.["message"] === "string"
                    ? String(event.raw["message"])
                    : event.alert_signature
                    ?? `${event.event_type} — ${stripCidr(event.src_ip)} → ${stripCidr(event.dest_ip)}`;
                  const hostname = typeof event.raw?.["hostname"] === "string"
                    ? String(event.raw["hostname"]) : null;
                  return (
                    <div key={event.event_id} className="event-row">
                      <div className="row-top">
                        <div className="row-badges">
                          <span className={sourceClass(event.source)}>{event.source}</span>
                          <span className={severityClass(event.alert_severity)}>
                            {event.alert_severity != null ? `Sev ${event.alert_severity}` : event.event_type}
                          </span>
                          {hostname && <span className="badge">{hostname}</span>}
                          {event.dest_port && <span className="badge">:{event.dest_port}</span>}
                        </div>
                        <div className="row-time">{formatDateShort(event.event_ts)}</div>
                      </div>
                      <div className="event-message">{message}</div>
                      <div className="event-meta">
                        src: {stripCidr(event.src_ip)} · dest: {stripCidr(event.dest_ip)} · proto: {event.proto ?? "—"} · {event.event_type}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </section>
        )}

        {/* ---------------------------------------------------------------- Stats */}
        {tab === "stats" && stats && (
          <section className="stats-layout">
            <div className="card panel">
              <div className="panel-header"><h2>Alertes par règle</h2></div>
              <div className="stats-list">
                {stats.alerts.by_rule.map((r) => (
                  <div key={r.rule_key} className="stats-row">
                    <span className="stats-label">{r.rule_key}</span>
                    <div className="stats-bar-wrap">
                      <div
                        className="stats-bar"
                        style={{ width: `${Math.min(100, (r.count / (stats.alerts.by_rule[0]?.count || 1)) * 100)}%` }}
                      />
                    </div>
                    <span className="stats-count">{r.count}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="card panel">
              <div className="panel-header"><h2>Top IPs attaquantes</h2></div>
              <div className="stats-list">
                {stats.top_attacker_ips.length === 0
                  ? <div className="empty-box">Aucune IP attaquante détectée.</div>
                  : stats.top_attacker_ips.map((ip) => (
                    <div key={ip.ip} className="stats-row">
                      <span className="stats-label mono">{ip.ip}</span>
                      <div className="stats-bar-wrap">
                        <div
                          className="stats-bar stats-bar-red"
                          style={{ width: `${Math.min(100, (ip.alert_count / (stats.top_attacker_ips[0]?.alert_count || 1)) * 100)}%` }}
                        />
                      </div>
                      <span className="stats-count">{ip.alert_count}</span>
                    </div>
                  ))
                }
              </div>
            </div>

            <div className="card panel">
              <div className="panel-header"><h2>Événements par source (24h)</h2></div>
              <div className="stats-list">
                {Object.entries(stats.events.by_source).map(([src, count]) => (
                  <div key={src} className="stats-row">
                    <span className={sourceClass(src) + " stats-source-badge"}>{src}</span>
                    <div className="stats-bar-wrap">
                      <div className="stats-bar stats-bar-cyan" style={{ width: "100%" }} />
                    </div>
                    <span className="stats-count">{count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

      </div>
    </div>
  );
}
