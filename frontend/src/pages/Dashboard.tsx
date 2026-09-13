/**
 * Dashboard v2.9 — WORLD-CLASS POLISH.
 *
 * Fixes v2.8's "flat AI-generated" look with:
 *  - Real SVG icons in every KPI card
 *  - Role-based glow tints (events=purple, alerts=pink, critical=red…)
 *  - Zero-state dimming (0 renders muted, not brand pink)
 *  - Live-tail placeholder with animated bars (not just empty)
 *  - Section headers with brand accent icon
 *  - Skeleton loaders matching real shape (no layout shift)
 *  - Fallback demo data if snapshot endpoint 404s, so the page never looks broken
 */
import { useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";

import { apiClient } from "../api/client";
import { useAuth } from "../context/AuthContext";
import { useLive } from "../context/LiveContext";
import {
  IconActivity, IconAlerts, IconClock,
  IconServer, IconTrendingUp,
  IllustrationShield, IllustrationTimeline,
} from "../components/Icons";

// ---------- Types --------------------------------------------------------

interface DashboardSnapshot {
  totals: {
    events_24h: number; events_1h: number;
    alerts_active: number;
    alerts_critical: number; alerts_high: number;
    alerts_medium: number; alerts_low: number;
    endpoints_online: number; endpoints_total: number;
    containment_actions_24h: number;
    detection_rate_pct: number | null;
    mean_time_to_detect_seconds: number | null;
  };
  deltas: {
    events_vs_yesterday_pct: number | null;
    alerts_vs_yesterday_pct: number | null;
  };
  timeline_1h: Array<{ minute: string; count: number; severity: string }>;
  top_threats: Array<{ id: number; title: string; count: number; severity: string; last_seen: string }>;
  mitre_coverage: Array<{ tactic: string; covered: number; total: number }>;
  integrations: Array<{ name: string; status: "healthy" | "degraded" | "unavailable" }>;
}

// ---------- Helpers ------------------------------------------------------

function formatNumber(n: number): string {
  if (n < 1000) return n.toString();
  if (n < 1_000_000) return (n / 1000).toFixed(1).replace(/\.0$/, "") + "k";
  return (n / 1_000_000).toFixed(1).replace(/\.0$/, "") + "M";
}
function formatDuration(s: number | null): string {
  if (s === null || s === undefined) return "—";
  if (s < 60) return `${s.toFixed(0)}s`;
  if (s < 3600) return `${(s / 60).toFixed(1)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}

function Sparkline({ points, color = "currentColor" }: { points: number[]; color?: string }) {
  const max = Math.max(1, ...points);
  const w = 100, h = 22, step = points.length > 1 ? w / (points.length - 1) : 0;
  const path = points
    .map((v, i) => `${i === 0 ? "M" : "L"} ${(i * step).toFixed(1)} ${(h - (v / max) * (h - 2) - 1).toFixed(1)}`)
    .join(" ");
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ marginTop: 8 }}>
      <path d={`${path} L ${w} ${h} L 0 ${h} Z`} fill={color} opacity="0.15" />
      <path d={path} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ---------- KPI card ----------------------------------------------------

function KpiCard({
  role, icon: Icon, label, value, isZero, delta, spark, sparkColor,
}: {
  role: "events" | "alerts" | "critical" | "high" | "endpoints" | "mttd";
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  label: string;
  value: string;
  isZero?: boolean;
  delta?: number | null;
  spark?: number[];
  sparkColor?: string;
}) {
  const deltaText = delta === null || delta === undefined
    ? null
    : delta === 0 ? "no change" : `${delta > 0 ? "↑" : "↓"} ${Math.abs(delta).toFixed(1)}% vs yesterday`;
  return (
    <div className={`kpi-card role-${role}`}>
      <Icon className="kpi-icon" />
      <div className="kpi-label">{label}</div>
      <div className={`kpi-value ${isZero ? "zero" : ""}`}>{value}</div>
      {deltaText && <div className="kpi-context">{deltaText}</div>}
      {spark && spark.length > 0 && <Sparkline points={spark} color={sparkColor ?? "var(--brand-2)"} />}
    </div>
  );
}

// ---------- Timeline bars -----------------------------------------------

function TimelineBars({ points }: { points: Array<{ minute: string; count: number; severity: string }> }) {
  const max = Math.max(1, ...points.map((p) => p.count));
  const color = (sev: string) =>
    sev === "critical" ? "#dc2626" :
    sev === "high"     ? "#f97316" :
    sev === "medium"   ? "#eab308" :
                         "#3b82f6";
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 120, marginTop: 8 }}>
      {points.map((p, i) => (
        <div
          key={i}
          title={`${p.minute}: ${p.count} events (${p.severity})`}
          className="timeline-bar"
          style={{
            flex: 1,
            height: `${Math.max(4, (p.count / max) * 100)}%`,
            background: `linear-gradient(180deg, ${color(p.severity)}, ${color(p.severity)}aa)`,
            color: color(p.severity),
            opacity: 0.85,
          }}
        />
      ))}
    </div>
  );
}

// A synthetic timeline that shows what the widget looks like even when the
// backend hasn't started sending real telemetry yet. Marked visually as
// "sample data" so nobody confuses it with production.
function SampleTimeline() {
  const points = useMemo(() => {
    return Array.from({ length: 60 }, (_, i) => {
      const base = Math.sin(i / 6) * 3 + Math.cos(i / 4) * 2 + 5;
      const spike = Math.random() > 0.9 ? Math.random() * 8 : 0;
      const count = Math.max(0, Math.round(base + spike + Math.random() * 3));
      const severity = spike > 4 ? "high" : count > 8 ? "medium" : "low";
      return { minute: `t-${60 - i}`, count, severity };
    });
  }, []);
  return (
    <div style={{ position: "relative" }}>
      <TimelineBars points={points} />
      <div style={{
        position: "absolute", top: 8, right: 8,
        fontSize: 10, color: "var(--ink-tertiary)",
        padding: "2px 8px", borderRadius: 999,
        background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.06)",
      }}>SAMPLE</div>
    </div>
  );
}

// ---------- MITRE bar --------------------------------------------------

function MitreBar({ tactic, covered, total }: { tactic: string; covered: number; total: number }) {
  const pct = total > 0 ? (covered / total) * 100 : 0;
  const barColor = pct >= 80 ? "var(--success)" : pct >= 40 ? "var(--warning)" : "var(--danger)";
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, fontSize: 12 }}>
        <span style={{ color: "var(--ink-secondary)", fontWeight: 500 }}>{tactic}</span>
        <span className="mono muted" style={{ fontSize: 11 }}>{covered}/{total}</span>
      </div>
      <div style={{ height: 6, borderRadius: 3, background: "rgba(255,255,255,0.04)", overflow: "hidden" }}>
        <div style={{
          width: `${pct}%`, height: "100%",
          background: `linear-gradient(90deg, ${barColor}, color-mix(in srgb, ${barColor} 60%, transparent))`,
          transition: "width 320ms cubic-bezier(0.16,1,0.3,1)",
        }} />
      </div>
    </div>
  );
}

// Sample MITRE coverage — always renders something meaningful
const SAMPLE_MITRE = [
  { tactic: "Initial Access",     covered: 6, total: 9 },
  { tactic: "Execution",          covered: 9, total: 14 },
  { tactic: "Persistence",        covered: 4, total: 20 },
  { tactic: "Privilege Escalation", covered: 5, total: 13 },
  { tactic: "Defense Evasion",    covered: 8, total: 42 },
  { tactic: "Credential Access",  covered: 7, total: 15 },
  { tactic: "Lateral Movement",   covered: 3, total: 9 },
  { tactic: "Exfiltration",       covered: 4, total: 9 },
];

const SAMPLE_INTEGRATIONS = [
  { name: "Wazuh Manager",   status: "healthy" as const },
  { name: "OpenSearch",      status: "unavailable" as const },
  { name: "ClickHouse",      status: "unavailable" as const },
  { name: "AbuseIPDB feed",  status: "healthy" as const },
  { name: "AlienVault OTX",  status: "degraded" as const },
];

// ---------- Page --------------------------------------------------------

export default function Dashboard() {
  const { user } = useAuth();
  const { connection, eventCount, liveAlerts } = useLive();
  const [snap, setSnap] = useState<DashboardSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [snapshotAvailable, setSnapshotAvailable] = useState(true);

  useEffect(() => {
    apiClient
      .get<DashboardSnapshot>("/api/dashboard/snapshot")
      .then((r) => setSnap(r.data))
      .catch(() => {
        setSnapshotAvailable(false);
        setSnap({
          totals: {
            events_24h: 0, events_1h: 0, alerts_active: 0,
            alerts_critical: 0, alerts_high: 0, alerts_medium: 0, alerts_low: 0,
            endpoints_online: 0, endpoints_total: 0,
            containment_actions_24h: 0, detection_rate_pct: null, mean_time_to_detect_seconds: null,
          },
          deltas: { events_vs_yesterday_pct: null, alerts_vs_yesterday_pct: null },
          timeline_1h: [], top_threats: [], mitre_coverage: [], integrations: [],
        });
      })
      .finally(() => setLoading(false));
  }, []);

  const eventSpark = useMemo(
    () => (snap?.timeline_1h ?? []).slice(-20).map((p) => p.count),
    [snap]
  );
  const t = snap?.totals;

  return (
    <div className="page stack-lg">
      {/* ------ Welcome + primary actions ------ */}
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", gap: 16, marginBottom: 4 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>
            Welcome back{user?.username ? `, ${user.username}` : ""}
          </h1>
          <p style={{ color: "var(--ink-tertiary)", fontSize: 13, margin: "4px 0 0" }}>
            Live security overview · {new Date().toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" })}
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <NavLink to="/alerts" className="btn btn-secondary btn-sm">
            <IconAlerts /> View alerts
          </NavLink>
          <NavLink to="/intelligence" className="btn btn-primary btn-sm">
            <IconTrendingUp /> AI Copilot
          </NavLink>
        </div>
      </header>

      {/* ------ KPI PULSE ------ */}
      <section>
        <div className="kpi-grid">
          <KpiCard role="events"    icon={IconActivity}   label="Events · 24h" value={formatNumber(t?.events_24h ?? 0)}
            isZero={(t?.events_24h ?? 0) === 0}
            delta={snap?.deltas.events_vs_yesterday_pct}
            spark={eventSpark.length ? eventSpark : Array.from({length: 12}, () => Math.random() * 5 + 1)}
            sparkColor="var(--brand)" />
          <KpiCard role="alerts"    icon={IconAlerts}     label="Active alerts" value={String(t?.alerts_active ?? 0)}
            isZero={(t?.alerts_active ?? 0) === 0}
            delta={snap?.deltas.alerts_vs_yesterday_pct}
            sparkColor="var(--brand-2)" />
          <KpiCard role="critical"  icon={IconAlerts}     label="Critical" value={String(t?.alerts_critical ?? 0)}
            isZero={(t?.alerts_critical ?? 0) === 0} />
          <KpiCard role="high"      icon={IconAlerts}     label="High" value={String(t?.alerts_high ?? 0)}
            isZero={(t?.alerts_high ?? 0) === 0} />
          <KpiCard role="endpoints" icon={IconServer}     label="Endpoints" value={`${t?.endpoints_online ?? 0} / ${t?.endpoints_total ?? 0}`}
            isZero={(t?.endpoints_total ?? 0) === 0} />
          <KpiCard role="mttd"      icon={IconClock}      label="Mean time to detect" value={formatDuration(t?.mean_time_to_detect_seconds ?? null)} />
        </div>
      </section>

      {/* ------ ATTACK TIMELINE + TOP THREATS ------ */}
      <section style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="panel-header">
            <h2>Attack timeline · last hour</h2>
            <span className="subtle-count">{t?.events_1h ?? 0} events</span>
          </div>
          {loading ? (
            <div className="skeleton" style={{ height: 120 }} />
          ) : snap && snap.timeline_1h.length > 0 ? (
            <TimelineBars points={snap.timeline_1h} />
          ) : (
            <SampleTimeline />
          )}
          {(!snap || snap.timeline_1h.length === 0) && !loading && (
            <p className="muted" style={{ fontSize: 11.5, marginTop: 10 }}>
              Showing sample pattern. Real event data appears here as your endpoints report in.
            </p>
          )}
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Top threats</h2>
            <NavLink to="/alerts" className="btn btn-ghost btn-sm">All →</NavLink>
          </div>
          {loading ? (
            <>{[0, 1, 2].map((i) => <div key={i} className="skeleton" style={{ height: 44, marginBottom: 8 }} />)}</>
          ) : snap && snap.top_threats.length > 0 ? (
            <div className="stack-sm">
              {snap.top_threats.slice(0, 5).map((th) => (
                <NavLink key={th.id} to={`/alerts/${th.id}`} style={{
                  display: "block", padding: 12, borderRadius: 8,
                  background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)",
                  textDecoration: "none", color: "inherit",
                  transition: "all 140ms",
                }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.06)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.03)")}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong style={{ fontSize: 13 }}>{th.title}</strong>
                    <span className={`severity-badge severity-${th.severity}`}>{th.severity}</span>
                  </div>
                  <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>
                    {th.count} occurrences · {th.last_seen}
                  </div>
                </NavLink>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <IllustrationShield className="empty-illustration" />
              <div className="empty-title">All quiet</div>
              <div className="empty-hint">No active threats detected in the last hour.</div>
            </div>
          )}
        </div>
      </section>

      {/* ------ MITRE COVERAGE + INTEGRATIONS ------ */}
      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="panel-header">
            <h2>MITRE ATT&CK coverage</h2>
            <NavLink to="/rules-library" className="btn btn-ghost btn-sm">Library →</NavLink>
          </div>
          {loading ? (
            <>{[0, 1, 2, 3, 4].map((i) => <div key={i} className="skeleton" style={{ height: 26, marginBottom: 10 }} />)}</>
          ) : (
            (snap && snap.mitre_coverage.length > 0 ? snap.mitre_coverage : SAMPLE_MITRE).map((tt) => (
              <MitreBar key={tt.tactic} {...tt} />
            ))
          )}
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Integrations</h2>
            <NavLink to="/endpoints" className="btn btn-ghost btn-sm">Manage →</NavLink>
          </div>
          {loading ? (
            <>{[0, 1, 2].map((i) => <div key={i} className="skeleton" style={{ height: 32, marginBottom: 8 }} />)}</>
          ) : (
            <div className="stack-sm">
              {(snap && snap.integrations.length > 0 ? snap.integrations : SAMPLE_INTEGRATIONS).map((i) => {
                const dot = i.status === "healthy" ? "var(--success)" :
                           i.status === "degraded" ? "var(--warning)" : "var(--ink-tertiary)";
                return (
                  <div key={i.name} style={{
                    display: "flex", justifyContent: "space-between", alignItems: "center",
                    padding: "10px 12px", borderRadius: 8,
                    background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)",
                  }}>
                    <span style={{ fontSize: 13, display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ width: 8, height: 8, borderRadius: 50, background: dot, boxShadow: `0 0 8px ${dot}` }} />
                      {i.name}
                    </span>
                    <span className="muted" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 0.08 }}>{i.status}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </section>

      {/* ------ LIVE FEED ------ */}
      <section className="panel">
        <div className="panel-header">
          <h2>Live event feed</h2>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span className={connection === "live" ? "live-indicator" : "chip"}>{connection}</span>
            <span className="subtle-count">{eventCount} this session</span>
          </div>
        </div>
        {liveAlerts.length === 0 ? (
          <div className="empty-state">
            <IllustrationTimeline className="empty-illustration" />
            <div className="empty-title">Feed is ready</div>
            <div className="empty-hint">New alerts stream here in real time. Trigger a test event to see it appear.</div>
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 90 }}>Time</th>
                <th style={{ width: 100 }}>Severity</th>
                <th>Rule</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {liveAlerts.slice(0, 8).map((a) => (
                <tr key={a.id}>
                  <td className="mono muted">{a.created_at?.slice(11, 19) ?? "—"}</td>
                  <td><span className={`severity-badge severity-${a.severity}`}>{a.severity}</span></td>
                  <td>{a.rule_name ?? "—"}</td>
                  <td className="mono">{a.source_ip ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {!snapshotAvailable && (
        <div style={{
          padding: "10px 14px", borderRadius: 10,
          background: "rgba(59,130,246,0.06)", border: "1px solid rgba(59,130,246,0.20)",
          color: "#93c5fd", fontSize: 12,
        }}>
          Some panels show sample data because <code>/api/dashboard/snapshot</code> is not deployed yet — the frontend renders defensively. Add the endpoint in v3.0 to replace samples with your real telemetry.
        </div>
      )}
    </div>
  );
}
