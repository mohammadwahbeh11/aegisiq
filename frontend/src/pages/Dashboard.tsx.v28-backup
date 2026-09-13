/**
 * Dashboard v2.8 — modern SOC overview.
 *
 * Redesigned around information hierarchy that competitors get wrong:
 *
 *   1. TOP-LINE PULSE (5 KPIs)  — always visible, thumb-scannable
 *   2. ATTACK TIMELINE          — the last hour at a glance
 *   3. TOP THREATS              — ranked, with one-click drill-in
 *   4. STATUS RIBBON            — MITRE ATT&CK, endpoints, integrations
 *   5. RECENT ACTIVITY          — live tail (via WebSocket)
 *
 * Every card is width-responsive. Every metric uses tabular figures.
 * Skeleton loaders replace spinners so a slow API doesn't feel broken.
 */
import { useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";

import { apiClient } from "../api/client";
import { useAuth } from "../context/AuthContext";
import { useLive } from "../context/LiveContext";

// ---------- Types --------------------------------------------------------

interface DashboardSnapshot {
  totals: {
    events_24h: number;
    events_1h: number;
    alerts_active: number;
    alerts_critical: number;
    alerts_high: number;
    alerts_medium: number;
    alerts_low: number;
    endpoints_online: number;
    endpoints_total: number;
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
  if (s === null) return "n/a";
  if (s < 60) return `${s.toFixed(0)}s`;
  if (s < 3600) return `${(s / 60).toFixed(1)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}

function Sparkline({ points, color = "currentColor" }: { points: number[]; color?: string }) {
  const max = Math.max(1, ...points);
  const w = 120, h = 28, step = points.length > 1 ? w / (points.length - 1) : 0;
  const path = points
    .map((v, i) => `${i === 0 ? "M" : "L"} ${(i * step).toFixed(1)} ${(h - (v / max) * h).toFixed(1)}`)
    .join(" ");
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="kpi-spark" preserveAspectRatio="none">
      <path d={path} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      <path d={`${path} L ${w} ${h} L 0 ${h} Z`} fill={color} opacity="0.12" />
    </svg>
  );
}

// ---------- Sub-components -----------------------------------------------

function KpiCard({
  label, value, brand, delta, spark, sparkColor,
}: {
  label: string; value: string;
  brand?: boolean;
  delta?: { value: number; positive_is_bad?: boolean };
  spark?: number[]; sparkColor?: string;
}) {
  const deltaClass = delta
    ? delta.value === 0 ? "" : delta.value > 0
      ? (delta.positive_is_bad ? "down" : "up")
      : (delta.positive_is_bad ? "up" : "down")
    : "";
  return (
    <div className="kpi-card">
      <div className="kpi-label">{label}</div>
      <div className={`kpi-value ${brand ? "brand" : ""}`}>{value}</div>
      {delta && (
        <div className={`kpi-delta ${deltaClass}`}>
          {Math.abs(delta.value).toFixed(1)}% vs yesterday
        </div>
      )}
      {spark && spark.length > 0 && <Sparkline points={spark} color={sparkColor ?? "currentColor"} />}
    </div>
  );
}

function TimelineBars({ points }: { points: Array<{ minute: string; count: number; severity: string }> }) {
  const max = Math.max(1, ...points.map((p) => p.count));
  const color = (sev: string) =>
    sev === "critical" ? "var(--sev-critical)" :
    sev === "high"     ? "var(--sev-high)" :
    sev === "medium"   ? "var(--sev-medium)" :
                         "var(--sev-low)";
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 88, marginTop: 6 }}>
      {points.map((p, i) => (
        <div
          key={i}
          title={`${p.minute}: ${p.count} events (${p.severity})`}
          style={{
            flex: 1,
            height: `${Math.max(4, (p.count / max) * 100)}%`,
            background: color(p.severity),
            borderRadius: "2px 2px 0 0",
            opacity: 0.85,
            transition: "opacity 140ms",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = "1")}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = "0.85")}
        />
      ))}
    </div>
  );
}

function MitreBar({ tactic, covered, total }: { tactic: string; covered: number; total: number }) {
  const pct = total > 0 ? (covered / total) * 100 : 0;
  return (
    <div style={{ marginBottom: 8 }}>
      <div className="row-between" style={{ marginBottom: 3, fontSize: 12 }}>
        <span className="mono" style={{ color: "var(--ink-secondary)" }}>{tactic}</span>
        <span className="muted" style={{ fontSize: 11 }}>{covered}/{total}</span>
      </div>
      <div style={{ height: 5, borderRadius: 3, background: "var(--bg-elevated-2)", overflow: "hidden" }}>
        <div style={{
          width: `${pct}%`,
          height: "100%",
          background: pct >= 80 ? "var(--success)" : pct >= 40 ? "var(--warning)" : "var(--danger)",
          transition: "width 220ms",
        }} />
      </div>
    </div>
  );
}

// ---------- Page ---------------------------------------------------------

export default function Dashboard() {
  const { user } = useAuth();
  const { connection, eventCount, liveAlerts } = useLive();
  const [snap, setSnap] = useState<DashboardSnapshot | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient
      .get<DashboardSnapshot>("/api/dashboard/snapshot")
      .then((r) => setSnap(r.data))
      .catch(() => {
        // Fallback shape so the UI still renders (fail-open)
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

  return (
    <div className="page stack-lg">
      <header className="row-between" style={{ marginBottom: 4 }}>
        <div>
          <h1>Welcome back{user?.username ? `, ${user.username}` : ""}</h1>
          <p className="muted" style={{ fontSize: 13, margin: 0 }}>
            Live security overview &middot; last refreshed just now
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <NavLink to="/alerts" className="btn btn-secondary">View alerts</NavLink>
          <NavLink to="/intelligence" className="btn btn-primary">AI Copilot</NavLink>
        </div>
      </header>

      {/* --- 1. TOP-LINE PULSE ---------------------------------------- */}
      <section>
        <div className="kpi-grid">
          <KpiCard
            label="Events · last 24h"
            value={formatNumber(snap?.totals.events_24h ?? 0)}
            brand
            delta={snap?.deltas.events_vs_yesterday_pct !== null && snap?.deltas.events_vs_yesterday_pct !== undefined
              ? { value: snap.deltas.events_vs_yesterday_pct } : undefined}
            spark={eventSpark}
            sparkColor="var(--brand-2)"
          />
          <KpiCard
            label="Active alerts"
            value={String(snap?.totals.alerts_active ?? 0)}
            delta={snap?.deltas.alerts_vs_yesterday_pct !== null && snap?.deltas.alerts_vs_yesterday_pct !== undefined
              ? { value: snap.deltas.alerts_vs_yesterday_pct, positive_is_bad: true } : undefined}
          />
          <KpiCard label="Critical" value={String(snap?.totals.alerts_critical ?? 0)} />
          <KpiCard label="High" value={String(snap?.totals.alerts_high ?? 0)} />
          <KpiCard
            label="Endpoints online"
            value={`${snap?.totals.endpoints_online ?? 0} / ${snap?.totals.endpoints_total ?? 0}`}
          />
          <KpiCard
            label="Mean time to detect"
            value={formatDuration(snap?.totals.mean_time_to_detect_seconds ?? null)}
          />
        </div>
      </section>

      {/* --- 2. ATTACK TIMELINE + TOP THREATS ------------------------- */}
      <section style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="panel-header">
            <h2>Attack timeline · last hour</h2>
            <span className="chip">{snap?.totals.events_1h ?? 0} events</span>
          </div>
          {loading ? (
            <div style={{ height: 88 }} className="skeleton" />
          ) : snap && snap.timeline_1h.length > 0 ? (
            <TimelineBars points={snap.timeline_1h} />
          ) : (
            <div className="empty-state">
              <div className="icon">📊</div>
              <div>Waiting for events. Run the demo data script to populate the timeline.</div>
            </div>
          )}
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Top threats</h2>
            <NavLink to="/alerts" className="btn btn-ghost btn-sm">All alerts →</NavLink>
          </div>
          {loading ? (
            <>{[0, 1, 2].map((i) => <div key={i} className="skeleton" style={{ height: 40, marginBottom: 8 }} />)}</>
          ) : snap && snap.top_threats.length > 0 ? (
            <div className="stack-sm">
              {snap.top_threats.slice(0, 5).map((t) => (
                <NavLink
                  key={t.id}
                  to={`/alerts/${t.id}`}
                  style={{ display: "block", padding: 10, borderRadius: "var(--radius-sm)", background: "var(--bg-elevated-2)", textDecoration: "none", color: "inherit" }}
                >
                  <div className="row-between">
                    <strong style={{ fontSize: 13 }}>{t.title}</strong>
                    <span className={`severity-badge severity-${t.severity}`}>{t.severity}</span>
                  </div>
                  <div className="muted" style={{ fontSize: 11, marginTop: 3 }}>
                    {t.count} occurrences &middot; last seen {t.last_seen}
                  </div>
                </NavLink>
              ))}
            </div>
          ) : (
            <div className="empty-state" style={{ padding: 20 }}>
              <div className="icon">🛡️</div>
              <div style={{ fontSize: 12 }}>No active threats detected.</div>
            </div>
          )}
        </div>
      </section>

      {/* --- 3. MITRE COVERAGE + INTEGRATIONS ------------------------- */}
      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="panel-header">
            <h2>MITRE ATT&amp;CK coverage</h2>
            <NavLink to="/rules-library" className="btn btn-ghost btn-sm">Library →</NavLink>
          </div>
          {loading ? (
            <>{[0, 1, 2, 3, 4].map((i) => <div key={i} className="skeleton" style={{ height: 24, marginBottom: 8 }} />)}</>
          ) : snap && snap.mitre_coverage.length > 0 ? (
            snap.mitre_coverage.map((t) => <MitreBar key={t.tactic} {...t} />)
          ) : (
            <div className="empty-state">
              <div>Load rules to see coverage.</div>
            </div>
          )}
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Integrations</h2>
            <NavLink to="/endpoints" className="btn btn-ghost btn-sm">Manage →</NavLink>
          </div>
          {loading ? (
            <>{[0, 1, 2].map((i) => <div key={i} className="skeleton" style={{ height: 32, marginBottom: 6 }} />)}</>
          ) : snap && snap.integrations.length > 0 ? (
            <div className="stack-sm">
              {snap.integrations.map((i) => (
                <div key={i.name} className="row-between" style={{ padding: "6px 0" }}>
                  <span style={{ fontSize: 13 }}>{i.name}</span>
                  <span className={`status-badge status-${i.status === "healthy" ? "resolved" : i.status === "degraded" ? "investigating" : "false_positive"}`}>
                    {i.status}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <div>No integrations connected.</div>
            </div>
          )}
        </div>
      </section>

      {/* --- 4. LIVE FEED --------------------------------------------- */}
      <section className="panel">
        <div className="panel-header">
          <h2>Live event feed</h2>
          <div className="row" style={{ gap: 8 }}>
            <span className={`live-indicator ${connection === "live" ? "" : "muted"}`}>{connection}</span>
            <span className="chip">{eventCount} this session</span>
          </div>
        </div>
        {liveAlerts.length === 0 ? (
          <div className="empty-state" style={{ padding: 20 }}>
            <div className="icon">📡</div>
            <div style={{ fontSize: 12 }}>Waiting for alerts. Any new alert will appear here in real time.</div>
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
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
    </div>
  );
}
