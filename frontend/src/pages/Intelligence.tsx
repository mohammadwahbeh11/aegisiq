/**
 * Intelligence page (v2.5).
 *
 * A single, integrated console that surfaces the three v2.5 backend
 * modules so the paid value story is visible on the dashboard:
 *
 *   1. AI Copilot   -> explain an alert / triage a batch (bilingual)
 *   2. Enrichment   -> live IP reputation from AbuseIPDB + OTX
 *   3. Compliance   -> SOC 2 / ISO 27001 / GDPR evidence report
 *
 * The page is deliberately fail-open: if the underlying provider is not
 * configured (no API key, no LLM), we render a friendly "not configured"
 * state instead of a blank error, so a demo instance still looks alive.
 */
import { FormEvent, useEffect, useState } from "react";

import { apiClient } from "../api/client";
import { EmptyState, ErrorBanner, Loading, Panel } from "../components/ui";
import { useAuth } from "../context/AuthContext";

// ---------- narrow, page-local types (kept out of client.ts to keep the ----
// drop-in patch minimal — move to client.ts if you want them shared) ------

// v3.3 — these three interfaces described an API that does not exist.
// Every field below is now the field the backend actually returns
// (app/api/routes/copilot.py, enrichment.py, compliance.py): the page
// rendered "not configured" for a working copilot, blank reputation
// details, and an empty compliance table with a message blaming the
// router, because it read `configured`, `verdict`, `pulses`, `version`
// and `controls_total` — none of which are ever sent.

interface CopilotStatus {
  enabled: boolean;
  provider: string | null;
  model: string | null;
  note?: string | null;
  error?: string | null;
}

/** /api/copilot/explain/{id}: ai_status "ok" carries `analysis`;
 *  "degraded" carries the alert itself plus the reason AI was skipped. */
interface CopilotExplanation {
  ai_status: "ok" | "degraded" | "error";
  reason?: string | null;
  alert_id?: number;
  analysis?: {
    summary?: string;
    reasoning?: string;
    recommended_actions?: string[];
    confidence?: string;
    [key: string]: unknown;
  };
  alert?: {
    id: number;
    rule_type: string | null;
    rule_name?: string | null;
    severity: string;
    source_ip: string | null;
    mitre_id: string | null;
    kill_chain_phase: string | null;
    description: string;
    status: string;
  };
  related_events_count?: number;
}

interface FeedResult {
  enabled: boolean;
  reason?: string | null;
  abuse_confidence?: number;
  total_reports?: number;
  country_code?: string | null;
  pulse_count?: number;
  tags?: string[];
  [key: string]: unknown;
}

interface EnrichmentResult {
  ip: string;
  risk_score: number;                       // 0-100 composite
  risk_label: string;                       // clean | low | suspicious | …
  abuseipdb: FeedResult | null;
  otx: FeedResult | null;
  cached: boolean;
  cache_age_seconds?: number;
}

interface ComplianceFramework {
  id: "soc2" | "iso27001" | "gdpr";
  name: string;
  standard: string;
}

// ---------- API wrappers -------------------------------------------------

async function fetchCopilotStatus(): Promise<CopilotStatus> {
  const { data } = await apiClient.get("/api/copilot/status");
  return data;
}

async function explainAlertById(alertId: number, lang: "ar" | "en"): Promise<CopilotExplanation> {
  const { data } = await apiClient.post(`/api/copilot/explain/${alertId}`, { lang });
  return data;
}

async function enrichIp(ip: string): Promise<EnrichmentResult> {
  const { data } = await apiClient.get(`/api/enrichment/ip/${encodeURIComponent(ip)}`);
  return data;
}

async function fetchComplianceFrameworks(): Promise<ComplianceFramework[]> {
  const { data } = await apiClient.get("/api/compliance/frameworks");
  // The API returns {frameworks: [...]}. This read `data.items`, which is
  // always undefined — so the panel always rendered "no frameworks
  // reported / the router may not be registered", and the compliance
  // evidence feature looked broken on every deployment that had it.
  return data.frameworks ?? data.items ?? [];
}

async function openComplianceReport(id: ComplianceFramework["id"]): Promise<void> {
  const response = await apiClient.get(`/api/compliance/${id}/report`, {
    responseType: "blob",
  });
  const blob = new Blob([response.data as BlobPart], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const w = window.open(url, "_blank", "noopener,noreferrer");
  if (!w) {
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegisiq_${id}_report.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

// ---------- small view helpers ------------------------------------------

function verdictClass(label: string | undefined): string {
  // The service returns risk_label: clean | low | suspicious | high |
  // malicious (app/enrichment/enrichment_service.py::_label). Map it onto
  // the console's severity palette so a reputation verdict reads the same
  // way an alert severity does.
  const tier = label === "malicious" ? "critical"
    : label === "high" ? "high"
    : label === "suspicious" ? "medium"
    : "low";
  return `severity-badge severity-${tier}`;
}

function riskBarColor(score: number): string {
  if (score >= 75) return "#ef4444";
  if (score >= 40) return "#f59e0b";
  return "#22c55e";
}

// ---------- page ---------------------------------------------------------

export default function Intelligence() {
  const { user } = useAuth();
  const isAdmin = user?.role === "administrator";

  // --- Copilot state ---
  const [copilot, setCopilot] = useState<CopilotStatus | null>(null);
  const [alertIdInput, setAlertIdInput] = useState("");
  const [lang, setLang] = useState<"ar" | "en">("ar");
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState<CopilotExplanation | null>(null);
  const [copilotError, setCopilotError] = useState<string | null>(null);

  // --- Enrichment state ---
  const [ipInput, setIpInput] = useState("");
  const [enriching, setEnriching] = useState(false);
  const [enrichment, setEnrichment] = useState<EnrichmentResult | null>(null);
  const [enrichError, setEnrichError] = useState<string | null>(null);

  // --- Compliance state ---
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [loadingFrameworks, setLoadingFrameworks] = useState(true);
  const [complianceError, setComplianceError] = useState<string | null>(null);

  useEffect(() => {
    fetchCopilotStatus()
      .then(setCopilot)
      .catch(() => setCopilot({ enabled: false, provider: null, model: null,
                                error: "status probe failed" }));

    fetchComplianceFrameworks()
      .then((list) => setFrameworks(list))
      .catch(() => setComplianceError("Could not load compliance frameworks."))
      .finally(() => setLoadingFrameworks(false));
  }, []);

  async function handleExplain(e: FormEvent) {
    e.preventDefault();
    const id = Number.parseInt(alertIdInput, 10);
    if (!Number.isFinite(id) || id <= 0) {
      setCopilotError("Enter a valid numeric alert ID from the Alerts page.");
      return;
    }
    setExplaining(true);
    setCopilotError(null);
    setExplanation(null);
    try {
      const result = await explainAlertById(id, lang);
      setExplanation(result);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      if (status === 404) setCopilotError(`Alert #${id} not found.`);
      else if (status === 503) setCopilotError("AI provider is not configured yet.");
      else setCopilotError("Copilot request failed. Try again shortly.");
    } finally {
      setExplaining(false);
    }
  }

  async function handleEnrich(e: FormEvent) {
    e.preventDefault();
    const ip = ipInput.trim();
    // Very light client-side sanity check — server does the real validation.
    if (!/^[0-9a-fA-F:.]+$/.test(ip) || ip.length < 3) {
      setEnrichError("Enter a valid IPv4 or IPv6 address.");
      return;
    }
    setEnriching(true);
    setEnrichError(null);
    setEnrichment(null);
    try {
      const result = await enrichIp(ip);
      setEnrichment(result);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      if (status === 400) setEnrichError("The server rejected that IP as invalid.");
      else if (status === 503) setEnrichError("No enrichment provider is configured.");
      else setEnrichError("Enrichment lookup failed.");
    } finally {
      setEnriching(false);
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Intelligence</h1>
          <p className="muted">
            AI-assisted triage, live IP reputation, and compliance evidence
          </p>
        </div>
      </header>

      {/* ------------------------------ AI COPILOT ---------------------- */}
      <Panel title="AI Copilot">
        <p className="muted" style={{ marginTop: "-0.25rem", marginBottom: "1rem" }}>
          {(() => {
            if (!copilot) return "Checking provider…";
            if (!copilot.enabled) {
              return copilot.note
                ?? copilot.error
                ?? "No AI provider configured — set AI_PROVIDER (openai | anthropic | ollama) on the server. Triage still works without it, grouped by source address.";
            }
            return `Provider: ${copilot.provider ?? "—"} • Model: ${copilot.model ?? "—"}`;
          })()}
        </p>
        <form onSubmit={handleExplain} className="inline-form" style={{ marginBottom: "1rem" }}>
          <input
            type="number"
            min={1}
            placeholder="Alert ID (e.g. 42)"
            value={alertIdInput}
            onChange={(e) => setAlertIdInput(e.target.value)}
            style={{ maxWidth: "10rem" }}
          />
          <select value={lang} onChange={(e) => setLang(e.target.value as "ar" | "en")}>
            <option value="ar">العربية</option>
            <option value="en">English</option>
          </select>
          <button type="submit" className="btn btn-primary" disabled={explaining}>
            {explaining ? "Analyzing…" : "Explain with AI"}
          </button>
        </form>

        {copilotError && <ErrorBanner>{copilotError}</ErrorBanner>}
        {explaining && <Loading label="Asking the model…" />}

        {explanation && (
          <div className="copilot-result">
            {explanation.ai_status !== "ok" && (
              <div className="info-banner">
                {explanation.reason
                  ?? "The AI provider was unavailable — showing the alert's own evidence."}
              </div>
            )}

            {explanation.analysis && (
              // Only the model's own prose follows the requested language
              // direction; the evidence grid below is field names and IPs
              // and reads left-to-right in either language.
              <div dir={lang === "ar" ? "rtl" : "ltr"}>
                {explanation.analysis.summary && (
                  <>
                    <h3>Summary</h3>
                    <p>{explanation.analysis.summary}</p>
                  </>
                )}
                {explanation.analysis.reasoning && (
                  <>
                    <h3>Reasoning</h3>
                    <p style={{ whiteSpace: "pre-wrap" }}>{explanation.analysis.reasoning}</p>
                  </>
                )}
                {(explanation.analysis.recommended_actions ?? []).length > 0 && (
                  <>
                    <h3>Recommended actions</h3>
                    <ol>
                      {(explanation.analysis.recommended_actions ?? []).map((a, i) => (
                        <li key={i}>{a}</li>
                      ))}
                    </ol>
                  </>
                )}
                {explanation.analysis.confidence && (
                  <p className="muted">
                    Confidence: <strong>{String(explanation.analysis.confidence)}</strong>
                  </p>
                )}
              </div>
            )}

            {/* Degraded mode still has something worth showing: the alert
                the analyst asked about, and how much evidence sits behind
                it. An empty panel would read as a broken feature. */}
            {!explanation.analysis && explanation.alert && (
              <dl className="kv-grid" dir="ltr">
                <div>
                  <strong>Rule</strong>
                  <p className="muted">
                    {explanation.alert.rule_name ?? explanation.alert.rule_type ?? "—"}
                    {" · "}{explanation.alert.severity}
                  </p>
                </div>
                <div>
                  <strong>Source</strong>
                  <p className="muted mono">{explanation.alert.source_ip ?? "—"}</p>
                </div>
                <div>
                  <strong>MITRE ATT&amp;CK</strong>
                  <p className="muted">
                    {explanation.alert.mitre_id ?? "—"}
                    {explanation.alert.kill_chain_phase
                      ? ` · ${explanation.alert.kill_chain_phase}` : ""}
                  </p>
                </div>
                <div>
                  <strong>Supporting events</strong>
                  <p className="muted">{explanation.related_events_count ?? 0}</p>
                </div>
                <div style={{ gridColumn: "1 / -1" }}>
                  <strong>What fired</strong>
                  <p className="muted">{explanation.alert.description}</p>
                </div>
              </dl>
            )}
          </div>
        )}
      </Panel>

      {/* ------------------------------ ENRICHMENT ---------------------- */}
      <Panel title="IP Reputation">
        <p className="muted" style={{ marginTop: "-0.25rem", marginBottom: "1rem" }}>
          Composite risk score (70% AbuseIPDB + 30% OTX) with 6-hour cache.
        </p>
        <form onSubmit={handleEnrich} className="inline-form" style={{ marginBottom: "1rem" }}>
          <input
            type="text"
            placeholder="e.g. 185.220.101.5"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            style={{ maxWidth: "16rem", fontFamily: "monospace" }}
          />
          <button type="submit" className="btn btn-primary" disabled={enriching}>
            {enriching ? "Looking up…" : "Lookup"}
          </button>
        </form>

        {enrichError && <ErrorBanner>{enrichError}</ErrorBanner>}
        {enriching && <Loading label="Querying reputation feeds…" />}

        {enrichment && (
          <div className="enrichment-result">
            <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
              <span className={verdictClass(enrichment.risk_label)}>
                {(enrichment.risk_label ?? "unknown").toUpperCase()}
              </span>
              <code>{enrichment.ip}</code>
              {enrichment.cached && (
                <span className="muted">
                  cached ({enrichment.cache_age_seconds ?? 0}s old)
                </span>
              )}
            </div>

            <div style={{ marginTop: "0.75rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <strong>Risk score</strong>
                <span>{enrichment.risk_score} / 100</span>
              </div>
              <div
                style={{
                  height: 8,
                  background: "var(--panel-bg, #1f2937)",
                  borderRadius: 4,
                  overflow: "hidden",
                  marginTop: 4,
                }}
              >
                <div
                  style={{
                    width: `${enrichment.risk_score}%`,
                    height: "100%",
                    background: riskBarColor(enrichment.risk_score),
                  }}
                />
              </div>
            </div>

            <div className="kv-grid" style={{ marginTop: "1rem" }}>
              <div>
                <strong>AbuseIPDB</strong>
                {enrichment.abuseipdb?.enabled ? (
                  <p className="muted">
                    Confidence {enrichment.abuseipdb.abuse_confidence ?? 0}% •{" "}
                    {enrichment.abuseipdb.total_reports ?? 0} reports
                    {enrichment.abuseipdb.country_code
                      ? ` • ${enrichment.abuseipdb.country_code}` : ""}
                  </p>
                ) : (
                  // Say WHY a feed is silent. "not configured" was wrong
                  // half the time — a blocked network reads identically.
                  <p className="muted">
                    {enrichment.abuseipdb?.reason ?? "not configured"}
                  </p>
                )}
              </div>
              <div>
                <strong>AlienVault OTX</strong>
                {enrichment.otx?.enabled ? (
                  <p className="muted">
                    {enrichment.otx.pulse_count ?? 0} pulses
                    {(enrichment.otx.tags ?? []).length > 0
                      && ` • ${(enrichment.otx.tags ?? []).slice(0, 4).join(", ")}`}
                  </p>
                ) : (
                  <p className="muted">{enrichment.otx?.reason ?? "not configured"}</p>
                )}
              </div>
            </div>
          </div>
        )}
      </Panel>

      {/* ------------------------------ COMPLIANCE ---------------------- */}
      <Panel title="Compliance Evidence">
        <p className="muted" style={{ marginTop: "-0.25rem", marginBottom: "1rem" }}>
          Live evidence generated from your audit log — SOC 2, ISO/IEC 27001, GDPR.
        </p>
        {complianceError && <ErrorBanner>{complianceError}</ErrorBanner>}
        {loadingFrameworks && <Loading label="Loading frameworks…" />}
        {!loadingFrameworks && frameworks.length === 0 && !complianceError && (
          <EmptyState>
            No frameworks reported. The `/api/compliance` router may not be registered on this
            deployment.
          </EmptyState>
        )}
        {frameworks.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Framework</th>
                <th>Standard</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {frameworks.map((f) => (
                <tr key={f.id}>
                  <td><strong>{f.name}</strong></td>
                  <td className="muted">{f.standard}</td>
                  <td>
                    <button
                      className="btn btn-secondary"
                      onClick={() => void openComplianceReport(f.id)}
                      disabled={!isAdmin}
                      title={isAdmin ? "Open the HTML evidence report"
                                     : "Administrator only"}
                    >
                      Evidence report
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
