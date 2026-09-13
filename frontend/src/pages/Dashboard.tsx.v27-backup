/**
 * Dashboard — AegisIQ v2.1 live-reactive edition.
 *
 * What changed from v2.0:
 *   * KPI numbers animate on change (count-up transition, ~450 ms).
 *   * Every new item in the live-event feed and the live-alert feed
 *     flashes for 1.2 s so the analyst's eye tracks arrival, not
 *     scroll position.
 *   * Live-stream header carries a pulsing "LIVE" indicator that
 *     brightens when events are flowing and dims after 5 s of quiet.
 *   * A new events-per-minute meter, computed from the sliding live
 *     buffer, gives an at-a-glance "is anything happening" reading.
 *   * The aggregate stats block also refreshes every 15 s on a
 *     safety-net timer — a WebSocket that drops a frame does not
 *     freeze the numbers.
 *
 * All motion respects the tokens in index.css and adds nothing to
 * the render tree while idle: the animations are pure CSS keyframes
 * driven by a transient `is-new` class.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import {
  Alert,
  DashboardStats,
  LogEvent,
  MitreCoverageRow,
  Severity,
  TimelineBucket,
  fetchDashboardStats,
  fetchMitreCoverage,
  fetchSeverityDistribution,
  fetchTimeline,
  fetchTopSources,
} from "../api/client";
import { ActivityTimeline, SeverityDonut } from "../components/charts";
import {
  EmptyState,
  ErrorBanner,
  Loading,
  MitreBadge,
  Panel,
  SeverityBadge,
  StatusBadge,
  formatRelative,
  formatTime,
} from "../components/ui";
import { useLive } from "../context/LiveContext";

const EMPTY_COUNTS: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
const FLASH_MS = 1200;
const IDLE_FADE_MS = 5000;
const AGGREGATE_REFRESH_MS = 15000;
// During an attack, alerts can arrive many-per-second. Refreshing all five
// aggregate endpoints on EVERY alert floods a single-worker backend and can
// exhaust its connection pool. Coalesce alert-driven refreshes to at most
// one per this window (leading + trailing edge) so the dashboard stays live
// and smooth under a burst instead of stampeding the API.
const ALERT_COALESCE_MS = 2500;

// Count-up animation. Given (old, new), returns a currently-rendered
// intermediate value at 60 fps for ~450 ms.
function useAnimatedNumber(target: number): number {
  const [display, setDisplay] = useState(target);
  const fromRef = useRef(target);
  useEffect(() => {
    const from = fromRef.current;
    const delta = target - from;
    if (delta === 0) { setDisplay(target); return; }
    const start = performance.now();
    const dur = 450;
    let raf = 0;
    const step = (now: number) => {
      const t = Math.min(1, (now - start) / dur);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(from + delta * eased));
      if (t < 1) raf = requestAnimationFrame(step);
      else fromRef.current = target;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target]);
  return display;
}

// Track which IDs are "new since last render" and clear the flag
// after FLASH_MS. Callers use it to add `.is-new` to their row.
function useFlashSet<T extends { id: number }>(items: T[]): Set<number> {
  const [flash, setFlash] = useState<Set<number>>(new Set());
  const seenRef = useRef<Set<number>>(new Set());
  useEffect(() => {
    const now = new Set<number>();
    for (const it of items) {
      if (!seenRef.current.has(it.id)) now.add(it.id);
    }
    if (now.size === 0) return;
    // Prime seen so the same id doesn't re-flash on unrelated re-renders.
    now.forEach((id) => seenRef.current.add(id));
    setFlash((prev) => {
      const next = new Set(prev);
      now.forEach((id) => next.add(id));
      return next;
    });
    const timer = window.setTimeout(() => {
      setFlash((prev) => {
        const next = new Set(prev);
        now.forEach((id) => next.delete(id));
        return next;
      });
    }, FLASH_MS);
    return () => window.clearTimeout(timer);
  }, [items]);
  return flash;
}

// Events per minute, computed from the live buffer (which holds the
// last 100 log events). If nothing new in 60 s, returns 0.
function useEventsPerMinute(liveLogs: LogEvent[]): number {
  const cutoff = Date.now() - 60_000;
  const recent = liveLogs.filter((l) => {
    const t = l.timestamp ? new Date(l.timestamp.endsWith("Z") ? l.timestamp : l.timestamp + "Z").getTime() : 0;
    return t >= cutoff;
  });
  return recent.length;
}

export default function Dashboard() {
  const { liveLogs, liveAlerts, onAlert, connection, lastEventAt } = useLive();

  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [severityCounts, setSeverityCounts] = useState<Record<Severity, number>>(EMPTY_COUNTS);
  const [timeline, setTimeline] = useState<TimelineBucket[]>([]);
  const [topSources, setTopSources] = useState<{ source_ip: string; alerts: number }[]>([]);
  const [coverage, setCoverage] = useState<MitreCoverageRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [tick, setTick] = useState(0);   // forces "5 s ago" style timestamps to advance

  // Overlap + burst guards so a stream of alerts can never pile up a
  // backlog of five-request refreshes against the backend.
  const inFlightRef = useRef(false);   // a load() is currently running
  const pendingRef = useRef(false);    // another load() was requested while running
  const hasDataRef = useRef(false);    // we have shown real data at least once
  const coalesceTimerRef = useRef<number | null>(null);
  const lastLoadRef = useRef(0);

  const load = useCallback(async () => {
    // Never run two refreshes at once: if one is in flight, just mark that
    // a follow-up is wanted and let the running one pick it up when it ends.
    if (inFlightRef.current) { pendingRef.current = true; return; }
    inFlightRef.current = true;
    try {
      do {
        pendingRef.current = false;
        // allSettled, not all: one slow/failed endpoint (e.g. the backend
        // briefly saturated mid-attack) must NOT blank the whole dashboard.
        // We apply every result that succeeded and keep the last-good value
        // for any that failed, so the numbers stay live instead of dropping
        // to zero or throwing up an error banner over good data.
        const [s, sev, tl, src, cov] = await Promise.allSettled([
          fetchDashboardStats(),
          fetchSeverityDistribution(),
          fetchTimeline(24),
          fetchTopSources(5),
          fetchMitreCoverage(),
        ]);
        let anyOk = false;
        if (s.status === "fulfilled")   { setStats(s.value); anyOk = true; }
        if (sev.status === "fulfilled") { setSeverityCounts({ ...EMPTY_COUNTS, ...sev.value.counts }); anyOk = true; }
        if (tl.status === "fulfilled")  { setTimeline(tl.value); anyOk = true; }
        if (src.status === "fulfilled") { setTopSources(src.value); anyOk = true; }
        if (cov.status === "fulfilled") { setCoverage(cov.value); anyOk = true; }
        if (anyOk) {
          hasDataRef.current = true;
          setError(null);
        } else if (!hasDataRef.current) {
          // Only surface the banner if we have never managed to load —
          // a transient all-fail while data is already on screen is
          // absorbed silently and retried on the next tick.
          setError("Could not load dashboard data from the backend.");
        }
      } while (pendingRef.current);
    } finally {
      inFlightRef.current = false;
      setIsLoading(false);
    }
  }, []);

  // Coalesce alert-driven refreshes: fire immediately on the leading edge,
  // then throttle to one refresh per ALERT_COALESCE_MS with a single
  // trailing refresh, so a burst of alerts costs one refresh, not hundreds.
  const scheduleLoad = useCallback(() => {
    const now = Date.now();
    const since = now - lastLoadRef.current;
    if (since >= ALERT_COALESCE_MS) {
      lastLoadRef.current = now;
      void load();
    } else if (coalesceTimerRef.current === null) {
      coalesceTimerRef.current = window.setTimeout(() => {
        coalesceTimerRef.current = null;
        lastLoadRef.current = Date.now();
        void load();
      }, ALERT_COALESCE_MS - since);
    }
  }, [load]);

  useEffect(() => { lastLoadRef.current = Date.now(); void load(); }, [load]);

  // On each alert, request a coalesced refresh (not a direct load) so an
  // attack burst can't stampede the backend.
  useEffect(() => onAlert(() => scheduleLoad()), [onAlert, scheduleLoad]);

  // Clean up any pending coalesce timer on unmount.
  useEffect(() => () => {
    if (coalesceTimerRef.current !== null) window.clearTimeout(coalesceTimerRef.current);
  }, []);

  // Safety-net timer: refresh aggregates every AGGREGATE_REFRESH_MS
  // regardless of alert traffic, so long-running dashboards don't drift.
  useEffect(() => {
    const t = window.setInterval(() => void load(), AGGREGATE_REFRESH_MS);
    return () => window.clearInterval(t);
  }, [load]);

  // 1 Hz tick so "3s ago" style timestamps advance smoothly.
  useEffect(() => {
    const t = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(t);
  }, []);

  const flashLogs = useFlashSet(liveLogs);
  const flashAlerts = useFlashSet(liveAlerts);
  const eventsPerMin = useEventsPerMinute(liveLogs);

  // Live-indicator is "hot" when the last event arrived < IDLE_FADE_MS ago
  const isHot = lastEventAt !== null && (Date.now() - lastEventAt.getTime()) < IDLE_FADE_MS;

  if (isLoading) return <Loading label="Loading dashboard…" />;

  const recentAlerts: Alert[] = liveAlerts.slice(0, 8);

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Security operations dashboard</h2>
          <p className="page-sub">
            Every figure below is computed from stored events — there are no placeholder numbers.
          </p>
        </div>
        <div className={`live-indicator ${isHot ? "hot" : "cool"}`}
             title={lastEventAt ? `Last event ${formatRelative(lastEventAt.toISOString())}` : "no events yet"}>
          <span className="live-dot" />
          <span className="live-label">LIVE</span>
          <span className="live-rate">{eventsPerMin}/min</span>
        </div>
      </div>

      {error && <ErrorBanner>{error}</ErrorBanner>}

      {stats && (
        <div className="kpi-grid">
          <KpiCard label="Total events"       n={stats.total_events}     hint={`${stats.events_today.toLocaleString()} today`} />
          <KpiCard label="Active alerts"      n={stats.active_alerts}    hint="new + investigating" tone={stats.active_alerts > 0 ? "warn" : undefined} />
          <KpiCard label="Critical alerts"    n={stats.critical_alerts}  tone={stats.critical_alerts > 0 ? "critical" : undefined} />
          <KpiCard label="High alerts"        n={stats.high_alerts}      tone={stats.high_alerts > 0 ? "high" : undefined} />
          <KpiCardText label="Endpoints online" value={`${stats.online_endpoints} / ${stats.monitored_endpoints}`} />
          <KpiCard label="Containment actions" n={stats.soar_actions}    hint="recorded, not executed" />
          <KpiCardText label="Detection rate"
                       value={stats.detection_rate === null ? "n/a" : `${stats.detection_rate}%`}
                       hint={stats.detection_rate === null ? "no alerts raised yet" : "alerts not dismissed as false positives"} />
          <KpiCardText label="Mean detection time"
                       value={stats.avg_detection_time_seconds === null ? "n/a" : `${stats.avg_detection_time_seconds}s`}
                       hint="event timestamp → alert raised" />
        </div>
      )}

      <div className="grid-2">
        <Panel title="Active alerts by severity">
          <SeverityDonut counts={severityCounts} />
        </Panel>

        <Panel title="Activity — last 24 hours">
          <ActivityTimeline buckets={timeline} />
        </Panel>
      </div>

      <div className="grid-2">
        <Panel
          title={
            <>
              Live alert feed
              {isHot && <span className="header-pulse" />}
            </>
          }
          actions={<Link className="link-btn" to="/alerts">Open alert queue →</Link>}
        >
          {recentAlerts.length === 0 ? (
            <EmptyState>
              {connection === "live"
                ? "Connected and listening. Alerts appear here the moment a rule fires — run a scenario from the Simulation lab to see it happen."
                : "The live connection is not established, so no streaming alerts can be shown."}
            </EmptyState>
          ) : (
            <ul className="feed">
              {recentAlerts.map((alert) => (
                <li key={alert.id} className={flashAlerts.has(alert.id) ? "is-new" : ""}>
                  <Link to={`/alerts/${alert.id}`} className="feed-row">
                    <SeverityBadge severity={alert.severity} />
                    <div className="feed-body">
                      <div className="feed-title">{alert.rule_name ?? "Detection rule"}</div>
                      <div className="feed-desc">{alert.description}</div>
                    </div>
                    <div className="feed-meta">
                      <StatusBadge status={alert.status} />
                      <span className="muted">{formatRelative(alert.timestamp)}</span>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title={
            <>
              Live event stream
              {isHot && <span className="header-pulse" />}
            </>
          }
          actions={<Link className="link-btn" to="/logs">Search all logs →</Link>}
        >
          {liveLogs.length === 0 ? (
            <EmptyState>
              No events received on this connection yet. Ingested logs appear here in real time.
            </EmptyState>
          ) : (
            <div className="table-scroll compact live-stream">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Event</th>
                    <th>Source</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {liveLogs.slice(0, 12).map((log) => (
                    <tr key={log.id} className={flashLogs.has(log.id) ? "is-new" : ""}>
                      <td className="muted mono">{formatTime(log.timestamp)}</td>
                      <td>{log.event_type}</td>
                      <td className="mono">{log.source_ip ?? log.hostname ?? "—"}</td>
                      <td>
                        <SeverityBadge severity={log.severity} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {/* referenced by useEffect on `tick` so relative-times stay fresh */}
              <span style={{display:"none"}}>{tick}</span>
            </div>
          )}
        </Panel>
      </div>

      <div className="grid-2">
        <Panel title="Top alerting sources">
          {topSources.length === 0 ? (
            <EmptyState>No alerts with a source address have been raised yet.</EmptyState>
          ) : (
            <ul className="ranked-list">
              {topSources.map((row) => (
                <li key={row.source_ip}>
                  <Link to={`/alerts?source_ip=${encodeURIComponent(row.source_ip)}`} className="mono">
                    {row.source_ip}
                  </Link>
                  <span className="count">{row.alerts}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="MITRE ATT&CK / Cyber Kill Chain coverage">
          <div className="table-scroll compact">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Technique</th>
                  <th>Kill chain phase</th>
                  <th>Alerts</th>
                </tr>
              </thead>
              <tbody>
                {coverage.map((row) => (
                  <tr key={row.rule_id} className={row.enabled ? "" : "row-disabled"}>
                    <td>
                      {row.rule_name}
                      {!row.enabled && <span className="tag">disabled</span>}
                    </td>
                    <td>
                      <MitreBadge id={row.mitre_id} />
                    </td>
                    <td className="muted">{row.kill_chain_phase ?? "—"}</td>
                    <td>{row.alerts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </>
  );
}

// KPI whose value is a number → animated count-up.
function KpiCard({
  label, n, hint, tone,
}: {
  label: string;
  n: number;
  hint?: string;
  tone?: "critical" | "high" | "warn";
}) {
  const rendered = useAnimatedNumber(n);
  return (
    <div className={`kpi-card ${tone ?? ""}`}>
      <div className="label">{label}</div>
      <div className="value">{rendered.toLocaleString()}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

// KPI whose value is a plain string (e.g. "3 / 8") — no animation.
function KpiCardText({
  label, value, hint, tone,
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: "critical" | "high" | "warn";
}) {
  return (
    <div className={`kpi-card ${tone ?? ""}`}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}
