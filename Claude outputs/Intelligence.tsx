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

interface CopilotStatus {
  provider: string;
  model: string;
  configured: boolean;
  degraded_reason?: string | null;
}

interface CopilotExplanation {
  summary: string;
  reasoning: string;
  recommended_actions: string[];
  confidence: "low" | "medium" | "high";
  degraded?: boolean;
}

interface EnrichmentResult {
  ip: string;
  risk_score: number;                       // 0-100 composite
  verdict: "clean" | "suspicious" | "malicious";
  abuseipdb: { confidence: number; reports: number; country?: string } | null;
  otx: { pulses: number; tags: string[] } | null;
  cached: boolean;
  cache_age_seconds?: number;
}

interface ComplianceFramework {
  id: "soc2" | "iso27001" | "gdpr";
  name: string;
  version: string;
  controls_total: number;
  controls_evidenced: number;
  updated_at: string;
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
  return data.items ?? [];
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

function verdictClass(v: EnrichmentResult["verdict"]): string {
  return `severity-badge severity-${v === "malicious" ? "critical" : v === "suspicious" ? "high" : "low"}`;
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
      .catch(() => setCopilot({ provider: "unavailable", model: "-", configured: false }));

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
            AI-assisted triage, live IP reputation, and compliance evidence — v2.5
          </p>
        </div>
      </header>

      {/* ------------------------------ AI COPILOT ---------------------- */}
      <Panel title="AI Copilot">
        <p className="muted" style={{ marginTop: "-0.25rem", marginBottom: "1rem" }}>
          {(() => {
            if (!copilot) return "Checking provider…";
            const prov = (copilot.provider && copilot.provider !== "null") ? copilot.provider : "—";
            const mdl  = (copilot.model    && copilot.model    !== "null") ? copilot.model    : "—";
            if (!copilot.configured) {
              return "No AI provider configured yet — set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OLLAMA_URL on the server to enable AI-assisted triage. (fail-open: everything else still works)";
            }
            return `Provider: ${prov} • Model: ${mdl}`;
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
          <div className="copilot-result" dir={lang === "ar" ? "rtl" : "ltr"}>
            {explanation.degraded && (
              <ErrorBanner>
                Provider unavailable — showing a rules-based fallback (no AI content).
              </ErrorBanner>
            )}
            <h3>Summary</h3>
            <p>{explanation.summary}</p>
            <h3>Reasoning</h3>
            <p style={{ whiteSpace: "pre-wrap" }}>{explanation.reasoning}</p>
            <h3>Recommended actions</h3>
            <ol>
              {explanation.recommended_actions.map((a, i) => (
                <li key={i}>{a}</li>
              ))}
            </ol>
            <p className="muted">
              Confidence: <strong>{explanation.confidence}</strong>
            </p>
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
              <span className={verdictClass(enrichment.verdict)}>
                {enrichment.verdict.toUpperCase()}
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
                {enrichment.abuseipdb ? (
                  <p className="muted">
                    Confidence {enrichment.abuseipdb.confidence}% • {enrichment.abuseipdb.reports}{" "}
                    reports{enrichment.abuseipdb.country ? ` • ${enrichment.abuseipdb.country}` : ""}
                  </p>
                ) : (
                  <p className="muted">not configured</p>
                )}
              </div>
              <div>
                <strong>AlienVault OTX</strong>
                {enrichment.otx ? (
                  <p className="muted">
                    {enrichment.otx.pulses} pulses
                    {enrichment.otx.tags.length > 0 && ` • ${enrichment.otx.tags.slice(0, 4).join(", ")}`}
                  </p>
                ) : (
                  <p className="muted">not configured</p>
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
                <th>Version</th>
                <th>Coverage</th>
                <th>Updated</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {frameworks.map((f) => {
                const pct = f.controls_total
                  ? Math.round((f.controls_evidenced / f.controls_total) * 100)
                  : 0;
                return (
                  <tr key={f.id}>
                    <td>
                      <strong>{f.name}</strong>
                    </td>
                    <td className="muted">{f.version}</td>
                    <td>
                      {f.controls_evidenced}/{f.controls_total} ({pct}%)
                    </td>
                    <td className="muted">{f.updated_at}</td>
                    <td>
                      <button
                        className="btn btn-secondary"
                        onClick={() => void openComplianceReport(f.id)}
                        disabled={!isAdmin}
                        title={isAdmin ? "Open HTML report" : "Administrator only"}
                      >
                        Report
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
