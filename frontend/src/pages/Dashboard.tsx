/**
 * Dashboard v3.3 — LIVE data from existing backend endpoints.
 *
 * Fixes the "statistics don't work" bug: v3.0-v3.2 called
 * `/api/dashboard/snapshot` which doesn't exist, so everything showed 0.
 *
 * v3.3 fetches from the endpoints that ARE deployed:
 *   - fetchAlerts()       — active alerts, computed by severity
 *   - fetchLogs()         — 24h event volume + timeline bars
 *   - fetchRules()        — MITRE ATT&CK coverage from rule inventory
 *   - fetchEndpoints()    — online/total endpoint counts
 *   - fetchSoarActions()  — containment actions in the last 24h
 *   - useLive()           — WebSocket for real-time updates on top
 *
 * Every KPI card is clickable and navigates to a filtered view.
 * Everything updates automatically when the WebSocket ticks a new alert.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";

import {
  fetchAlerts, fetchLogs, fetchRules, fetchEndpoints, fetchSoarActions,
  Alert, LogEvent, DetectionRule, EndpointsOverview,
} from "../api/client";
import { useAuth } from "../context/AuthContext";
import { useLive } from "../context/LiveContext";
import {
  IconActivity, IconAlerts, IconClock, IconServer, IconIntelligence,
  IllustrationShield, IllustrationTimeline,
} from "../components/Icons";

// ---------- Extra icons per KPI ----------

const IconAlertTriangle = (p: React.SVGProps<SVGSVGElement>) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}>
    <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);
const IconZap = (p: React.SVGProps<SVGSVGElement>) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}>
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
  </svg>
);
const IconFlame = (p: React.SVGProps<SVGSVGElement>) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}>
    <path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z" />
  </svg>
);

// ---------- Helpers ----------

function formatNumber(n: number): string {
  if (n < 1000) return n.toString();
  if (n < 1_000_000) return (n / 1000).toFixed(1).replace(/\.0$/, "") + "k";
  return (n / 1_000_000).toFixed(1).replace(/\.0$/, "") + "M";
}
function formatDuration(seconds: number | null): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

function Sparkline({ points, color = "currentColor" }: { points: number[]; color?: string }) {
  const max = Math.max(1, ...points);
  const w = 240, h = 36, step = points.length > 1 ? w / (points.length - 1) : 0;
  const path = points
    .map((v, i) => `${i === 0 ? "M" : "L"} ${(i * step).toFixed(1)} ${(h - (v / max) * (h - 4) - 2).toFixed(1)}`)
    .join(" ");
  const idBase = color.replace(/[^a-z0-9]/gi, "");
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ marginTop: 8, display: "block" }}>
      <defs>
        <linearGradient id={`spark-${idBase}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={`${path} L ${w} ${h} L 0 ${h} Z`} fill={`url(#spark-${idBase})`} />
      <path d={path} fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ---------- Clickable KPI card ----------

function KpiCard({
  role, Icon, label, value, isZero, delta, spark, sparkColor, onClick,
}: {
  role: "events" | "alerts" | "critical" | "high" | "endpoints" | "mttd";
  Icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  label: string;
  value: string;
  isZero?: boolean;
  delta?: string | null;
  spark?: number[];
  sparkColor?: string;
  onClick?: () => void;
}) {
  return (
    <div
      className={`kpi-card role-${role}`}
      style={{ minHeight: 130, cursor: onClick ? "pointer" : "default" }}
      onClick={onClick}
      onKeyDown={(e) => { if ((e.key === "Enter" || e.key === " ") && onClick) { e.preventDefault(); onClick(); } }}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
    >
      <Icon className="kpi-icon" />
      <div className="kpi-label">{label}</div>
      <div className={`kpi-value ${isZero ? "zero" : ""}`}>{value}</div>
      {delta && <div className="kpi-context">{delta}</div>}
      {spark && spark.length > 0 && <Sparkline points={spark} color={sparkColor ?? "var(--brand-2)"} />}
    </div>
  );
}

// ---------- MITRE row ----------

// ATT&CK Enterprise tactic totals (as of v14, Nov 2024)
const MITRE_TACTIC_TOTALS: Record<string, number> = {
  "Initial Access": 9, "Execution": 14, "Persistence": 20, "Privilege Escalation": 13,
  "Defense Evasion": 42, "Credential Access": 17, "Discovery": 32, "Lateral Movement": 9,
  "Collection": 17, "Command and Control": 18, "Exfiltration": 9, "Impact": 14,
};

function MitreBar({ tactic, covered, total }: { tactic: string; covered: number; total: number }) {
  const pct = total > 0 ? (covered / total) * 100 : 0;
  const barColor = pct >= 60 ? "#10b981" : pct >= 25 ? "#eab308" : pct > 0 ? "#f97316" : "#374151";
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, fontSize: 12 }}>
        <span style={{ color: "var(--ink-secondary)", fontWeight: 500 }}>{tactic}</span>
        <span style={{ color: "var(--ink-tertiary)", fontSize: 11, fontVariantNumeric: "tabular-nums" }}>
          {covered}/{total} · {pct.toFixed(0)}%
        </span>
      </div>
      <div style={{ height: 6, borderRadius: 3, background: "rgba(255,255,255,0.04)", overflow: "hidden" }}>
        <div style={{
          width: `${pct}%`, height: "100%",
          background: `linear-gradient(90deg, ${barColor}, ${barColor}aa)`,
          boxShadow: pct > 0 ? `0 0 8px ${barColor}44` : "none",
          transition: "width 320ms cubic-bezier(0.16,1,0.3,1)",
        }} />
      </div>
    </div>
  );
}

// ---------- Page ----------

export default function Dashboard() {
  const { user } = useAuth();
  const { liveAlerts, eventCount } = useLive();
  const navigate = useNavigate();

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointsOverview | null>(null);
  const [soarCount, setSoarCount] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  // Fetch everything in parallel. Fail-open: any missing endpoint just
  // means that section stays empty — nothing breaks the page.
  const refresh = useCallback(async () => {
    const settle = <T,>(p: Promise<T>, fallback: T): Promise<T> =>
      p.catch(() => fallback);

    const [a, l, r, e, s] = await Promise.all([
      settle(fetchAlerts({ limit: 500 }), { items: [] as Alert[], total: 0 }),
      settle(fetchLogs({ since_hours: 24, limit: 1000 }), { items: [] as LogEvent[], total: 0 }),
      settle(fetchRules(), [] as DetectionRule[]),
      settle(fetchEndpoints(), null as EndpointsOverview | null),
      settle(fetchSoarActions(200) as Promise<any>, { items: [], total: 0 } as any),
    ]);
    setAlerts(a.items ?? []);
    setLogs(l.items ?? []);
    setRules(r ?? []);
    setEndpoints(e);
    setSoarCount(s.total ?? (s.items?.length ?? 0));
    setLastRefresh(new Date());
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Refresh when the WebSocket delivers a new alert — dashboard reacts live
  useEffect(() => {
    if (liveAlerts.length > 0) {
      const t = setTimeout(refresh, 300);  // debounce a burst
      return () => clearTimeout(t);
    }
  }, [liveAlerts.length, refresh]);

  // Auto-refresh every 30 seconds so counters don't go stale
  useEffect(() => {
    const t = setInterval(refresh, 30_000);
    return () => clearInterval(t);
  }, [refresh]);

  // -------- Derived stats --------

  const activeAlerts = useMemo(
    () => alerts.filter((a) => a.status !== "resolved" && a.status !== "false_positive"),
    [alerts]
  );

  const bySeverity = useMemo(() => {
    const b = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of activeAlerts) {
      const s = (a.severity || "low") as keyof typeof b;
      if (s in b) b[s]++;
    }
    return b;
  }, [activeAlerts]);

  const totalEvents24h = logs.length;
  const eventsLast1h = useMemo(() => {
    const cutoff = Date.now() - 60 * 60 * 1000;
    return logs.filter((e) => {
      const t = e.timestamp ? new Date(e.timestamp).getTime() : (e as any).created_at ? new Date((e as any).created_at).getTime() : 0;
      return t >= cutoff;
    }).length;
  }, [logs]);

  // Sparkline: bucket last 20 5-minute windows
  const eventsSparkline = useMemo(() => {
    if (logs.length === 0) return [];
    const buckets = new Array(20).fill(0);
    const bucketMs = 5 * 60 * 1000;
    const now = Date.now();
    for (const e of logs) {
      const t = e.timestamp ? new Date(e.timestamp).getTime() : 0;
      if (t === 0) continue;
      const idx = 19 - Math.floor((now - t) / bucketMs);
      if (idx >= 0 && idx < 20) buckets[idx]++;
    }
    return buckets;
  }, [logs]);

  // Attack timeline: bucket last 60 1-minute windows, colored by max severity in bucket
  const attackTimeline = useMemo(() => {
    const buckets: Array<{ count: number; severity: string }> =
      Array.from({ length: 60 }, () => ({ count: 0, severity: "low" }));
    const bucketMs = 60 * 1000;
    const now = Date.now();
    const sevRank: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
    for (const e of logs) {
      const t = e.timestamp ? new Date(e.timestamp).getTime() : 0;
      if (t === 0) continue;
      const idx = 59 - Math.floor((now - t) / bucketMs);
      if (idx < 0 || idx >= 60) continue;
      buckets[idx].count++;
      if ((sevRank[e.severity ?? "low"] ?? 0) > (sevRank[buckets[idx].severity] ?? 0)) {
        buckets[idx].severity = e.severity ?? "low";
      }
    }
    return buckets;
  }, [logs]);

  // Top threats: cluster alerts by rule_name and rank by count
  const topThreats = useMemo(() => {
    const map = new Map<string, { title: string; severity: string; count: number; id: number; lastAt: number }>();
    for (const a of activeAlerts) {
      const key = a.rule_name ?? "Unknown rule";
      const t = ((a as any).timestamp ?? (a as any).timestamp ?? (a as any).raised_at ?? (a as any).created_at) ? new Date((a as any).timestamp ?? (a as any).timestamp ?? (a as any).raised_at ?? (a as any).created_at).getTime() : 0;
      const existing = map.get(key);
      if (!existing) {
        map.set(key, { title: key, severity: a.severity, count: 1, id: a.id, lastAt: t });
      } else {
        existing.count++;
        if (t > existing.lastAt) { existing.lastAt = t; existing.id = a.id; }
      }
    }
    return Array.from(map.values()).sort((x, y) => y.count - x.count).slice(0, 5);
  }, [activeAlerts]);

  // MITRE coverage: count distinct MITRE ids per tactic (heuristic mapping by rule.kill_chain_phase or first digit of ID)
  const mitreCoverage = useMemo(() => {
    // Simple heuristic: use rule's kill_chain_phase (already a tactic label) or fall back to bucket by mitre_id prefix
    const covered: Record<string, Set<string>> = {};
    for (const t of Object.keys(MITRE_TACTIC_TOTALS)) covered[t] = new Set();
    for (const r of rules) {
      if (!r.enabled) continue;
      const phase = r.kill_chain_phase;
      if (phase && covered[phase] !== undefined) {
        if (r.mitre_id) covered[phase].add(r.mitre_id);
        else covered[phase].add((r as any).name ?? String(r.id));
      }
    }
    return Object.entries(MITRE_TACTIC_TOTALS).map(([tactic, total]) => ({
      tactic,
      covered: covered[tactic]?.size ?? 0,
      total,
    }));
  }, [rules]);

  // Mean time to detect: median (raised_at - first triggering event's timestamp) over recent alerts
  const meanTimeToDetect = useMemo(() => {
    if (alerts.length === 0) return null;
    // heuristic: since we don't have per-alert event timestamps here, use last N alerts
    // and estimate MTTD from the time between adjacent alert raised_at values (proxy for detection cadence).
    const times = alerts
      .map((a) => ((a as any).timestamp ?? (a as any).timestamp ?? (a as any).raised_at ?? (a as any).created_at) ? new Date((a as any).timestamp ?? (a as any).timestamp ?? (a as any).raised_at ?? (a as any).created_at).getTime() : 0)
      .filter((t) => t > 0)
      .sort((a, b) => b - a)
      .slice(0, 20);
    if (times.length < 2) return null;
    const gaps = [];
    for (let i = 0; i < times.length - 1; i++) gaps.push((times[i] - times[i + 1]) / 1000);
    gaps.sort((a, b) => a - b);
    return gaps[Math.floor(gaps.length / 2)];
  }, [alerts]);

  return (
    <div className="page stack-lg">
      {/* ---- Welcome ---- */}
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", gap: 16, marginBottom: 8 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, margin: 0, letterSpacing: "-0.02em" }}>
            Welcome back{user?.username ? `, ${user.username}` : ""}
          </h1>
          <p style={{ color: "var(--ink-tertiary)", fontSize: 13, margin: "4px 0 0" }}>
            Live security overview · {loading ? "loading…" : `refreshed ${lastRefresh.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`}
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-secondary" onClick={refresh}>Refresh</button>
          <NavLink to="/alerts" className="btn btn-secondary"><IconAlerts /> View alerts</NavLink>
          <NavLink to="/intelligence" className="btn btn-primary"><IconIntelligence /> AI Copilot</NavLink>
        </div>
      </header>

      {/* ---- KPI grid ---- */}
      <section>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14 }}>
          <KpiCard role="events"    Icon={IconActivity}      label="Events · 24h"        value={formatNumber(totalEvents24h)}
                   isZero={totalEvents24h === 0}
                   delta={eventsLast1h > 0 ? `${eventsLast1h} in last hour` : (eventCount > 0 ? `${eventCount} this session` : null)}
                   spark={eventsSparkline.length ? eventsSparkline : undefined}
                   sparkColor="#a78bfa"
                   onClick={() => navigate("/logs")} />
          <KpiCard role="alerts"    Icon={IconAlertTriangle} label="Active alerts"       value={String(activeAlerts.length)}
                   isZero={activeAlerts.length === 0}
                   delta={liveAlerts.length > 0 ? `${liveAlerts.length} new this session` : null}
                   onClick={() => navigate("/alerts")} />
          <KpiCard role="critical"  Icon={IconFlame}         label="Critical severity"   value={String(bySeverity.critical)}
                   isZero={bySeverity.critical === 0}
                   onClick={() => navigate("/alerts?severity=critical")} />
          <KpiCard role="high"      Icon={IconZap}           label="High severity"       value={String(bySeverity.high)}
                   isZero={bySeverity.high === 0}
                   onClick={() => navigate("/alerts?severity=high")} />
          <KpiCard role="endpoints" Icon={IconServer}        label="Endpoints online"    value={`${endpoints?.sources ? (endpoints.sources.local + endpoints.sources.wazuh) : 0} / ${endpoints?.total ?? 0}`}
                   isZero={(endpoints?.total ?? 0) === 0}
                   onClick={() => navigate("/endpoints")} />
          <KpiCard role="mttd"      Icon={IconClock}         label="Median alert gap"    value={formatDuration(meanTimeToDetect)}
                   delta={soarCount > 0 ? `${soarCount} containment actions` : null} />
        </div>
      </section>

      {/* ---- Attack timeline + Top threats ---- */}
      <section style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="panel-header">
            <h2>Attack timeline · last hour</h2>
            <span className="subtle-count">{eventsLast1h} events</span>
          </div>
          <div style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 130, marginTop: 8 }}>
            {attackTimeline.map((p, i) => {
              const max = Math.max(1, ...attackTimeline.map((b) => b.count));
              const color = p.severity === "critical" ? "#dc2626" :
                            p.severity === "high"     ? "#f97316" :
                            p.severity === "medium"   ? "#eab308" :
                                                        "#3b82f6";
              return (
                <div key={i}
                     title={`t-${60 - i}m: ${p.count} events (max ${p.severity})`}
                     style={{
                       flex: 1,
                       height: `${Math.max(4, (p.count / max) * 100)}%`,
                       background: `linear-gradient(180deg, ${color}, ${color}88)`,
                       borderRadius: "3px 3px 0 0",
                       boxShadow: p.count > 0 ? `0 0 12px ${color}44` : "none",
                       opacity: p.count > 0 ? 0.9 : 0.15,
                     }} />
              );
            })}
          </div>
          {totalEvents24h === 0 && (
            <p className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>
              No events in the last 24 hours. Run <code>scripts/demo_data_render.sh</code> or trigger a simulation to populate.
            </p>
          )}
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Top threats</h2>
            <NavLink to="/alerts" className="btn btn-ghost btn-sm">All →</NavLink>
          </div>
          {loading ? (
            <>{[0, 1, 2].map((i) => <div key={i} className="skeleton" style={{ height: 46, marginBottom: 8 }} />)}</>
          ) : topThreats.length > 0 ? (
            <div className="stack-sm">
              {topThreats.map((th) => (
                <div key={th.id} onClick={() => navigate(`/alerts/${th.id}`)}
                  style={{
                    padding: 12, borderRadius: 8, cursor: "pointer",
                    background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.06)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.03)")}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong style={{ fontSize: 13 }}>{th.title}</strong>
                    <span className={`severity-badge severity-${th.severity}`}>{th.severity}</span>
                  </div>
                  <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>
                    {th.count} {th.count === 1 ? "occurrence" : "occurrences"}
                    {th.lastAt > 0 && ` · ${new Date(th.lastAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <IllustrationShield className="empty-illustration" />
              <div className="empty-title">All quiet</div>
              <div className="empty-hint">No active threats. Great.</div>
            </div>
          )}
        </div>
      </section>

      {/* ---- MITRE Coverage + Live feed ---- */}
      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="panel-header">
            <h2>MITRE ATT&CK coverage</h2>
            <NavLink to="/rules-library" className="btn btn-ghost btn-sm">Library →</NavLink>
          </div>
          {loading ? (
            <>{[0, 1, 2, 3, 4, 5].map((i) => <div key={i} className="skeleton" style={{ height: 26, marginBottom: 10 }} />)}</>
          ) : (
            mitreCoverage.filter((t) => t.covered > 0 || t.tactic in { "Initial Access": 1, "Execution": 1, "Persistence": 1, "Privilege Escalation": 1, "Defense Evasion": 1, "Credential Access": 1, "Exfiltration": 1, "Impact": 1 })
              .map((t) => <MitreBar key={t.tactic} {...t} />)
          )}
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Live event feed</h2>
            <span className="subtle-count">{liveAlerts.length} in session</span>
          </div>
          {liveAlerts.length === 0 && activeAlerts.length === 0 ? (
            <div className="empty-state">
              <IllustrationTimeline className="empty-illustration" />
              <div className="empty-title">Feed is ready</div>
              <div className="empty-hint">New alerts stream here in real time.</div>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 90 }}>Time</th>
                  <th style={{ width: 100 }}>Severity</th>
                  <th>Rule</th>
                </tr>
              </thead>
              <tbody>
                {(liveAlerts.length > 0 ? liveAlerts : activeAlerts).slice(0, 8).map((a: any) => (
                  <tr key={a.id} onClick={() => navigate(`/alerts/${a.id}`)} style={{ cursor: "pointer" }}>
                    <td className="mono muted">{
                      (a as any).timestamp ? new Date((a as any).timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) :
                      a.created_at?.slice(11, 19) ?? "—"
                    }</td>
                    <td><span className={`severity-badge severity-${a.severity}`}>{a.severity}</span></td>
                    <td>{a.rule_name ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
}
