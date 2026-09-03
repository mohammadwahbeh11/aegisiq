/**
 * Analysis page (v2.1 PREMIUM).
 *
 * Uploads a log file, runs the analysis synchronously, and shows the
 * generated report — event breakdown, findings, top sources,
 * recommendations. HTML report opens in a new tab for print-to-PDF.
 *
 * The page ALSO handles the paid-feature gate: when the license is
 * inactive it renders a beautiful unlock CTA with the demo key
 * pre-filled, so the panel can activate + retry in one click.
 */
import { useCallback, useEffect, useRef, useState } from "react";

import {
  AnalysisReport, LicenseStatus,
  activateLicense, deleteAnalysisReport, fetchAnalysisReports,
  fetchLicenseStatus, openAnalysisReport, uploadAnalysisFile,
} from "../api/client";
import { EmptyState, ErrorBanner, Loading, Panel, SeverityBadge } from "../components/ui";
import { useAuth } from "../context/AuthContext";

export default function Analysis() {
  const { user } = useAuth();
  const isAdmin = user?.role === "administrator";

  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [reports, setReports] = useState<AnalysisReport[]>([]);
  const [selected, setSelected] = useState<AnalysisReport | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [licenseKey, setLicenseKey] = useState("");
  const [activating, setActivating] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const refreshLicense = useCallback(async () => {
    try { setLicense(await fetchLicenseStatus()); } catch { /* ignore */ }
  }, []);

  const refreshList = useCallback(async () => {
    try {
      const data = await fetchAnalysisReports();
      setReports(data.items);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      if (status !== 402) setError("Could not load analysis reports.");
    }
  }, []);

  useEffect(() => {
    void refreshLicense();
    void refreshList();
  }, [refreshLicense, refreshList]);

  async function handleUpload(file: File) {
    setUploading(true);
    setError(null);
    try {
      const report = await uploadAnalysisFile(file);
      setSelected(report);
      await refreshList();
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number; data?: unknown } })?.response?.status;
      if (status === 402) {
        setError("Log Analysis is a premium feature. Activate a license below.");
      } else {
        setError("Analysis failed. Verify the file is UTF-8 text and try again.");
      }
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  async function handleActivate() {
    if (!licenseKey.trim()) return;
    setActivating(true);
    try {
      const st = await activateLicense(licenseKey.trim());
      setLicense(st);
      if (st.active) {
        setLicenseKey("");
        await refreshList();
        setError(null);
      } else {
        setError(`License activation failed: ${st.detail}`);
      }
    } catch {
      setError("Could not reach the license activation endpoint.");
    } finally {
      setActivating(false);
    }
  }

  async function handleDelete(id: number) {
    if (!confirm(`Delete analysis report #${id}?`)) return;
    try {
      await deleteAnalysisReport(id);
      setReports((r) => r.filter((x) => x.id !== id));
      if (selected?.id === id) setSelected(null);
    } catch {
      setError("Could not delete the report.");
    }
  }

  // ── Locked view ────────────────────────────────────────────────────
  if (license && !license.active) {
    return (
      <>
        <div className="page-head">
          <div>
            <h2>Log Analysis Report <span className="tag-pro">PRO</span></h2>
            <p className="page-sub">
              Upload a historical log file and receive an executive-ready security
              analysis: parsed event breakdown, malicious-pattern findings tagged
              with MITRE ATT&amp;CK, top attackers, and prioritised recommendations.
            </p>
          </div>
        </div>

        <Panel>
          <div className="premium-lock">
            <div className="premium-lock-icon">⚡</div>
            <h3>This is a premium feature</h3>
            <p className="muted">
              Log Analysis Report is available on <b>Trial</b>, <b>Educational</b>,
              <b>Business</b> and <b>Enterprise</b> tiers. Activate a license to
              unlock. Current tier: <b>{license.tier}</b>.
            </p>

            <div className="premium-features">
              <div>✓ Parse any log format (nginx, syslog, JSON, CSV)</div>
              <div>✓ Runs every AegisIQ detection rule offline</div>
              <div>✓ MITRE ATT&amp;CK-tagged findings + Kill Chain phase</div>
              <div>✓ Printable HTML report — save-as-PDF ready</div>
              <div>✓ Prioritised remediation recommendations</div>
              <div>✓ Up to 50&nbsp;MB / 100,000 events per file</div>
            </div>

            {isAdmin ? (
              <>
                <TierPicker onPick={(key) => setLicenseKey(key)} activeKey={licenseKey} />

                <div className="premium-activate">
                  <input
                    value={licenseKey}
                    onChange={(e) => setLicenseKey(e.target.value)}
                    placeholder="Paste your license key here — AEGIS-XXXX-XXXX-XXXX-XXXX"
                    autoFocus
                  />
                  <button className="btn-primary" disabled={activating || !licenseKey.trim()} onClick={handleActivate}>
                    {activating ? "Activating…" : "Activate license"}
                  </button>
                </div>
                <p className="muted premium-hint">
                  See <code>docs/PREMIUM.md</code> for the tier-detail table and
                  <code> docs/COMPLIANCE.md</code> for the standards mapping. Keys are
                  HMAC-SHA256 signed and verified locally — no phone-home.
                </p>
              </>
            ) : (
              <p className="muted">Ask an administrator to activate a license key.</p>
            )}

            {error && <ErrorBanner>{error}</ErrorBanner>}
          </div>
        </Panel>
      </>
    );
  }

  // ── Active / unlocked view ────────────────────────────────────────
  return (
    <>
      <div className="page-head">
        <div>
          <h2>
            Log Analysis Report <span className="tag-pro active">PRO</span>
            {license && (
              <span className="license-badge" title={license.detail}>
                {license.tier.toUpperCase()} · {license.features.length} features
              </span>
            )}
          </h2>
          <p className="page-sub">
            Upload a log file; every line runs through the same normalizer + 8 detection
            rules that power the live console, and you get an executive summary with
            printable HTML export.
          </p>
        </div>
      </div>

      <Panel title="Upload log file">
        <div className="upload-drop"
             onDragOver={(e) => e.preventDefault()}
             onDrop={(e) => { e.preventDefault();
                              const f = e.dataTransfer.files?.[0];
                              if (f) void handleUpload(f); }}>
          <input
            type="file"
            ref={fileRef}
            accept=".log,.txt,.json,.jsonl,.csv,text/plain,application/json,text/csv"
            style={{ display: "none" }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleUpload(f);
            }}
          />
          {uploading ? (
            <Loading label="Analyzing…" />
          ) : (
            <>
              <div className="upload-icon">⇪</div>
              <div className="upload-title">Drop a log file here, or</div>
              <button className="btn-primary" onClick={() => fileRef.current?.click()}>
                Choose file to analyze
              </button>
              <p className="muted">
                .log · .txt · .json · .jsonl · .csv — max 50&nbsp;MB / 100,000 lines
              </p>
            </>
          )}
        </div>
        {error && <ErrorBanner>{error}</ErrorBanner>}
      </Panel>

      {selected?.summary && (
        <ReportView
          report={selected}
          onOpen={async () => {
            try {
              await openAnalysisReport(selected.id);
            } catch {
              setError("Could not open the printable report — check your session, then retry.");
            }
          }}
        />
      )}

      <Panel title={`Recent analyses (${reports.length})`}>
        {reports.length === 0 ? (
          <EmptyState>No reports yet. Upload a file above to get started.</EmptyState>
        ) : (
          <div className="table-scroll compact">
            <table>
              <thead>
                <tr>
                  <th>File</th>
                  <th>Uploaded</th>
                  <th>Status</th>
                  <th>Events</th>
                  <th>Findings</th>
                  <th>Worst</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {reports.map((r) => (
                  <tr key={r.id} className="clickable" onClick={() => setSelected(r)}>
                    <td className="mono">{r.filename}</td>
                    <td className="muted nowrap">{new Date(r.created_at ?? "").toLocaleString()}</td>
                    <td>
                      <span className={`badge status-${r.status === "complete" ? "resolved" : "new"}`}>
                        {r.status}
                      </span>
                    </td>
                    <td className="mono">{r.parsed_events ?? "—"}</td>
                    <td className="mono">{r.findings_count ?? "—"}</td>
                    <td>
                      {r.worst_severity ? <SeverityBadge severity={r.worst_severity as never} /> : "—"}
                    </td>
                    <td>
                      {isAdmin && (
                        <button
                          className="btn-danger"
                          onClick={(e) => { e.stopPropagation(); void handleDelete(r.id); }}
                          title="Delete report"
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}

// ─── tier picker ─────────────────────────────────────────────────────
//
// v2.2 — three demo tier cards with a copy-to-clipboard button. Picking
// a card also fills the license input below, so an admin can activate
// in two clicks (pick card → Activate). The keys shipped here are the
// same DEMO keys hard-coded in `backend/app/security/license.py` — real
// customers would replace them via env or the license admin API.
interface TierInfo {
  tier: string;
  key: string;
  price: string;
  headline: string;
  bullets: string[];
  accent: "trial" | "educational" | "business";
  recommended?: boolean;
}

const TIERS: TierInfo[] = [
  {
    tier: "Trial",
    key: "AEGIS-DEMO-3G4H-8K2L-P0RT",
    price: "30 days · Free",
    headline: "Kick the tires with no commitment.",
    bullets: [
      "Every premium feature unlocked",
      "5 MB / 10,000 lines per upload",
      "Auto-downgrades to Free after 30 days",
    ],
    accent: "trial",
  },
  {
    tier: "Educational",
    key: "AEGIS-EDUC-6M9N-4W7X-C1AV",
    price: "Free for graduation panels",
    headline: "Perfect for the demo — never expires.",
    bullets: [
      "Full log-analysis engine",
      "MITRE ATT&CK-tagged findings",
      "Save-as-PDF report export",
      "50 MB / 100,000 lines per upload",
    ],
    accent: "educational",
    recommended: true,
  },
  {
    tier: "Business",
    key: "AEGIS-BIZN-<contact-sales>",
    price: "€ 890 / seat / year",
    headline: "For small SOCs and MSSPs.",
    bullets: [
      "Everything in Educational",
      "PDF export server-side",
      "Priority email support",
      "500 MB / 1,000,000 lines per upload",
    ],
    accent: "business",
  },
];

function TierPicker({ onPick, activeKey }: { onPick: (key: string) => void; activeKey: string }) {
  const [copied, setCopied] = useState<string | null>(null);

  async function copyKey(key: string) {
    try {
      await navigator.clipboard.writeText(key);
      setCopied(key);
      window.setTimeout(() => setCopied((c) => (c === key ? null : c)), 1500);
    } catch {
      /* clipboard denied in some sandboxes — the paste field remains */
    }
  }

  return (
    <div className="tier-grid">
      {TIERS.map((t) => {
        const usable = !t.key.includes("<contact");
        const isActive = activeKey.trim() === t.key;
        return (
          <div
            key={t.tier}
            className={`tier-card tier-${t.accent} ${isActive ? "tier-active" : ""}`}
          >
            {t.recommended && <div className="tier-badge">RECOMMENDED</div>}
            <div className="tier-name">{t.tier}</div>
            <div className="tier-price">{t.price}</div>
            <p className="tier-headline">{t.headline}</p>
            <ul className="tier-bullets">
              {t.bullets.map((b, i) => <li key={i}>{b}</li>)}
            </ul>
            <div className="tier-key" title={usable ? "Click to copy" : "Contact sales"}>
              <code>{t.key}</code>
            </div>
            <div className="tier-actions">
              <button
                type="button"
                className="btn-ghost"
                disabled={!usable}
                onClick={() => void copyKey(t.key)}
              >
                {copied === t.key ? "✓ Copied" : "Copy key"}
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={!usable}
                onClick={() => onPick(t.key)}
              >
                Use this tier
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── report renderer ─────────────────────────────────────────────────
//
// v2.2 — much richer inline view. Immediate on-screen assessment shows
// KPIs, a verdict banner, per-finding vulnerability detail with sample
// events, IOCs, an SVG timeline, and numbered remediation steps —
// everything the downloadable HTML has, right on the page. The
// "Open printable HTML" button goes through openAnalysisReport() so
// the JWT ships with the request (previously the download opened
// blank because window.open drops the Authorization header).

const SEVERITY_HEX: Record<string, string> = {
  critical: "#f43f5e",
  high:     "#f59e0b",
  medium:   "#eab308",
  low:      "#64748b",
};

function VerdictBanner({ worst, count }: { worst: string | null; count: number }) {
  const clean = !worst || count === 0;
  const color = clean ? "#22c55e" : SEVERITY_HEX[worst || "low"];
  const label = clean ? "CLEAN" : (worst || "").toUpperCase();
  const msg = clean
    ? "No known-bad patterns detected in this log file."
    : `${count} finding${count === 1 ? "" : "s"} — highest severity: ${label}.`;
  return (
    <div className="verdict-banner" style={{ borderLeft: `4px solid ${color}` }}>
      <div className="verdict-label" style={{ color }}>{label}</div>
      <div className="verdict-msg">{msg}</div>
    </div>
  );
}

function TimelineSvg({ buckets }: { buckets: NonNullable<AnalysisReport["summary"]>["timeline"] }) {
  if (!buckets || buckets.length === 0) {
    return <p className="muted" style={{ fontSize: "0.8rem" }}>No timestamped events to plot.</p>;
  }
  const W = 720, H = 140, PAD = 20;
  const innerW = W - 2 * PAD, innerH = H - 2 * PAD;
  const maxTotal = Math.max(...buckets.map((b) => b.total), 1);
  const barW = Math.max(2, innerW / Math.max(buckets.length, 1) - 2);
  const order = ["low", "medium", "high", "critical"];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} xmlns="http://www.w3.org/2000/svg"
         style={{ width: "100%", maxWidth: 720, background: "var(--bg-elevated)", borderRadius: 8 }}>
      {buckets.map((b, i) => {
        const x = PAD + i * (barW + 2);
        let y = PAD + innerH;
        const stacks: JSX.Element[] = [];
        for (const sev of order) {
          const n = b.by_severity[sev] || 0;
          if (n === 0) continue;
          const h = (n / maxTotal) * innerH;
          y -= h;
          stacks.push(
            <rect key={sev} x={x} y={y} width={barW} height={h} fill={SEVERITY_HEX[sev]}>
              <title>{`${b.hour} · ${sev}: ${n}`}</title>
            </rect>
          );
        }
        return <g key={i}>{stacks}</g>;
      })}
      <text x={PAD} y={H - 4} fontSize="10" fill="var(--text-muted)" fontFamily="ui-monospace,monospace">
        {buckets[0].hour}
      </text>
      <text x={W - PAD} y={H - 4} fontSize="10" fill="var(--text-muted)" textAnchor="end" fontFamily="ui-monospace,monospace">
        {buckets[buckets.length - 1].hour}
      </text>
    </svg>
  );
}

function FindingCard({ f, i }: { f: NonNullable<AnalysisReport["summary"]>["findings"][number]; i: number }) {
  const color = SEVERITY_HEX[f.severity];
  return (
    <div className="finding-card" style={{ borderLeft: `4px solid ${color}` }}>
      <div className="finding-head">
        <SeverityBadge severity={f.severity as never} />
        <span className="finding-title"><b>{f.rule}</b></span>
        {f.mitre && <code className="finding-mitre">{f.mitre}</code>}
        {f.kill_chain && <span className="finding-chain">{f.kill_chain}</span>}
        <span className="finding-count">{f.count}×</span>
      </div>
      {f.mitre_blurb && <div className="finding-blurb muted">{f.mitre_blurb}</div>}
      <div className="finding-reason">{f.reason}</div>

      <div className="finding-facts">
        <div><span className="lbl">Source</span> <code>{f.source}</code></div>
        {f.first_seen && <div><span className="lbl">First seen</span> {new Date(f.first_seen).toLocaleString()}</div>}
        {f.last_seen && <div><span className="lbl">Last seen</span> {new Date(f.last_seen).toLocaleString()}</div>}
        {f.pattern && <div><span className="lbl">Pattern</span> <code>{f.pattern}</code></div>}
        {f.matched_pattern && <div><span className="lbl">Matched</span> <code>{f.matched_pattern}</code></div>}
        {f.command && <div><span className="lbl">Command</span> <code>{f.command}</code></div>}
        {f.ua_signature && <div><span className="lbl">UA signature</span> <code>{f.ua_signature}</code></div>}
        {f.compromised_account && <div><span className="lbl">Account</span> <code>{f.compromised_account}</code></div>}
        {f.targeted_usernames && f.targeted_usernames.length > 0 && (
          <div><span className="lbl">Targeted users</span> {f.targeted_usernames.join(", ")}</div>
        )}
        {f.scanned_ports && f.scanned_ports.length > 0 && (
          <div><span className="lbl">Scanned ports</span> {f.scanned_ports.join(", ")}</div>
        )}
        {f.cwe_owasp && f.cwe_owasp.length > 0 && (
          <div><span className="lbl">CWE / OWASP</span> {f.cwe_owasp.join(" · ")}</div>
        )}
      </div>

      {f.sample_events && f.sample_events.length > 0 && (
        <details className="finding-samples" open={i === 0}>
          <summary>Sample events ({f.sample_events.length})</summary>
          {f.sample_events.map((s, j) => <pre key={j}>{s}</pre>)}
        </details>
      )}
    </div>
  );
}

function IocSection({ iocs }: { iocs: NonNullable<AnalysisReport["summary"]>["iocs"] }) {
  if (!iocs) return null;
  const blocks: { title: string; rows: [string | number, number][] }[] = [
    { title: "Source IPs",    rows: iocs.source_ips ?? [] },
    { title: "Usernames",     rows: iocs.usernames ?? [] },
    { title: "Hostnames",     rows: iocs.hostnames ?? [] },
    { title: "Ports probed",  rows: iocs.ports ?? [] },
    { title: "URLs",          rows: iocs.urls ?? [] },
    { title: "User-Agents",   rows: iocs.user_agents ?? [] },
  ].filter((b) => b.rows.length > 0);
  if (blocks.length === 0) {
    return <p className="muted" style={{ fontSize: "0.8rem" }}>No IOCs extracted.</p>;
  }
  return (
    <div className="ioc-grid">
      {blocks.map((b) => (
        <div key={b.title} className="ioc-block">
          <div className="ioc-title">{b.title}</div>
          <table>
            <tbody>
              {b.rows.map(([k, n]) => (
                <tr key={String(k)}>
                  <td><code>{String(k)}</code></td>
                  <td className="mono" style={{ textAlign: "right" }}>{n.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}

function ReportView({ report, onOpen }: { report: AnalysisReport; onOpen: () => void }) {
  const s = report.summary!;
  return (
    <Panel
      title={`Report: ${report.filename}`}
      actions={
        <button className="btn-primary" onClick={onOpen}>
          Open printable HTML →
        </button>
      }
    >
      <VerdictBanner worst={s.worst_severity} count={s.findings_count} />

      <div className="report-kpis">
        <div className="report-kpi">
          <div className="label">Total lines</div>
          <div className="value">{s.total_lines.toLocaleString()}</div>
        </div>
        <div className="report-kpi">
          <div className="label">Parsed events</div>
          <div className="value">{s.parsed_events.toLocaleString()}</div>
        </div>
        <div className="report-kpi">
          <div className="label">Findings</div>
          <div className={"value " + (s.findings_count > 0 ? "value-critical" : "")}>
            {s.findings_count}
          </div>
        </div>
        <div className="report-kpi">
          <div className="label">Worst severity</div>
          <div className="value">
            {s.worst_severity ? <SeverityBadge severity={s.worst_severity as never} /> : "clean"}
          </div>
        </div>
        <div className="report-kpi">
          <div className="label">Format</div>
          <div className="value" style={{ fontSize: "1.1rem" }}>{s.input_format}</div>
        </div>
        <div className="report-kpi">
          <div className="label">Elapsed</div>
          <div className="value" style={{ fontSize: "1.1rem" }}>{s.elapsed_ms} ms</div>
        </div>
      </div>

      <h4 className="section-h">Activity timeline (hourly, coloured by severity)</h4>
      <TimelineSvg buckets={s.timeline} />

      <h4 className="section-h">Vulnerabilities &amp; attacks detected ({s.findings.length})</h4>
      {s.findings.length === 0 ? (
        <EmptyState>✓ No known-bad patterns detected in this log file.</EmptyState>
      ) : (
        <div className="findings-grid">
          {s.findings.map((f, i) => <FindingCard key={i} f={f} i={i} />)}
        </div>
      )}

      {s.recommendations.length > 0 && (
        <>
          <h4 className="section-h">Prioritised remediation</h4>
          <ul className="recommendations-list">
            {s.recommendations.map((r, i) => (
              <li key={i} className={`priority-${r.priority}`}>
                <b>{r.finding}</b> — {r.action}
                {r.steps && r.steps.length > 0 && (
                  <ol className="remediation-steps">
                    {r.steps.map((step, j) => <li key={j}>{step}</li>)}
                  </ol>
                )}
              </li>
            ))}
          </ul>
        </>
      )}

      <h4 className="section-h">Indicators of Compromise (IOCs)</h4>
      <IocSection iocs={s.iocs} />
    </Panel>
  );
}
