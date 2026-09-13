/**
 * RulesLibrary page (v2.7).
 *
 * The customer-facing view of the detection rule library. Shows:
 *  - Total rule count with source breakdown (core / MENA / community)
 *  - Live counters per severity and per MITRE ATT&CK tactic
 *  - Filterable table (search title/id, filter by level and source)
 *  - One-click sync with the SigmaHQ community pack (admin only)
 *
 * This is the page a customer opens to say "yes, I'm getting my money's
 * worth" — 1000+ rules visible, filterable, and searchable.
 */
import { useEffect, useMemo, useState } from "react";

import { apiClient } from "../api/client";
import { EmptyState, ErrorBanner, Loading, Panel } from "../components/ui";
import { useAuth } from "../context/AuthContext";

interface Rule {
  id: string;
  sigma_id: string;
  title: string;
  description: string;
  level: "low" | "medium" | "high" | "critical";
  source: "core" | "aegisiq" | "sigma_community";
  tags: string[];
  ingestable: boolean;
  logsource_product?: string;
  logsource_service?: string;
}

interface RulesResponse {
  total: number;
  by_source: Record<string, number>;
  by_level: Record<string, number>;
  rules: Rule[];
}

async function fetchRules(): Promise<RulesResponse> {
  const { data } = await apiClient.get("/api/rules/library");
  return data;
}

async function syncCommunity(): Promise<{ added: number; total: number }> {
  const { data } = await apiClient.post("/api/rules/sync");
  return data;
}

function levelClass(l: Rule["level"]): string {
  return `severity-badge severity-${l}`;
}

const SOURCE_LABEL: Record<Rule["source"], string> = {
  core: "Core (built-in)",
  aegisiq: "AegisIQ curated",
  sigma_community: "Sigma community",
};

export default function RulesLibrary() {
  const { user } = useAuth();
  const isAdmin = user?.role === "administrator";

  const [data, setData] = useState<RulesResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [q, setQ] = useState("");
  const [level, setLevel] = useState<string>("all");
  const [source, setSource] = useState<string>("all");

  useEffect(() => {
    fetchRules()
      .then(setData)
      .catch(() => setError("Could not load rules library."));
  }, []);

  const filtered = useMemo(() => {
    if (!data) return [];
    return data.rules.filter((r) => {
      if (level !== "all" && r.level !== level) return false;
      if (source !== "all" && r.source !== source) return false;
      if (!q) return true;
      const needle = q.toLowerCase();
      return (
        r.title.toLowerCase().includes(needle) ||
        r.sigma_id.toLowerCase().includes(needle) ||
        r.description.toLowerCase().includes(needle) ||
        r.tags.some((t) => t.toLowerCase().includes(needle))
      );
    });
  }, [data, q, level, source]);

  async function handleSync() {
    setSyncing(true);
    setError(null);
    try {
      const res = await syncCommunity();
      const refreshed = await fetchRules();
      setData(refreshed);
      alert(`Synced. Added ${res.added} rules. Library now at ${res.total}.`);
    } catch {
      setError("Community sync failed — check network + SigmaHQ availability.");
    } finally {
      setSyncing(false);
    }
  }

  if (!data && !error) return <Loading label="Loading rule library…" />;

  return (
    <div className="page">
      <header className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1rem" }}>
        <div>
          <h1>Detection Rules Library</h1>
          <p className="muted">
            {data?.total ?? 0} rules loaded &middot; the core detection surface of AegisIQ.
          </p>
        </div>
        {isAdmin && (
          <button className="btn btn-primary" onClick={handleSync} disabled={syncing}>
            {syncing ? "Syncing…" : "Sync from SigmaHQ"}
          </button>
        )}
      </header>

      {error && <ErrorBanner>{error}</ErrorBanner>}

      {data && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: "0.75rem", marginBottom: "1rem" }}>
            {Object.entries(data.by_source).map(([src, count]) => (
              <Panel key={src} title={SOURCE_LABEL[src as Rule["source"]] || src}>
                <div style={{ fontSize: "1.75rem", fontWeight: 700 }}>{count}</div>
                <p className="muted" style={{ fontSize: "0.85rem" }}>rules</p>
              </Panel>
            ))}
            {Object.entries(data.by_level).map(([lvl, count]) => (
              <Panel key={lvl} title={lvl.toUpperCase()}>
                <div style={{ fontSize: "1.75rem", fontWeight: 700 }}>{count}</div>
                <p className="muted" style={{ fontSize: "0.85rem" }}>
                  <span className={`severity-badge severity-${lvl}`}>{lvl}</span>
                </p>
              </Panel>
            ))}
          </div>

          <Panel title="Filter & search">
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", alignItems: "center" }}>
              <input
                type="search"
                placeholder="Search title, id, tag…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                style={{ flex: "1 1 240px", minWidth: 0 }}
              />
              <select value={level} onChange={(e) => setLevel(e.target.value)}>
                <option value="all">All levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select value={source} onChange={(e) => setSource(e.target.value)}>
                <option value="all">All sources</option>
                <option value="core">Core</option>
                <option value="aegisiq">AegisIQ curated</option>
                <option value="sigma_community">Sigma community</option>
              </select>
            </div>
          </Panel>

          {filtered.length === 0 ? (
            <EmptyState>No rules match your filters.</EmptyState>
          ) : (
            <table className="table" style={{ marginTop: "1rem" }}>
              <thead>
                <tr>
                  <th>Level</th>
                  <th>Title</th>
                  <th>Source</th>
                  <th>Logsource</th>
                  <th>Tags</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 500).map((r) => (
                  <tr key={r.id || r.sigma_id}>
                    <td><span className={levelClass(r.level)}>{r.level}</span></td>
                    <td>
                      <strong>{r.title}</strong>
                      {!r.ingestable && (
                        <span className="muted" style={{ marginLeft: "0.5rem", fontSize: "0.75rem" }}>(not-ingestable)</span>
                      )}
                      <div className="muted" style={{ fontSize: "0.75rem" }}>{r.sigma_id}</div>
                    </td>
                    <td className="muted">{SOURCE_LABEL[r.source] || r.source}</td>
                    <td className="muted">{r.logsource_product ?? "-"} / {r.logsource_service ?? "-"}</td>
                    <td className="muted" style={{ fontSize: "0.75rem" }}>
                      {r.tags.slice(0, 3).map((t) => (
                        <span key={t} style={{ background: "var(--panel-bg,#1f2937)", padding: "0.15rem 0.35rem", borderRadius: 4, marginRight: 4 }}>
                          {t}
                        </span>
                      ))}
                      {r.tags.length > 3 && <span>+{r.tags.length - 3}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {filtered.length > 500 && (
            <p className="muted" style={{ marginTop: "0.5rem" }}>
              Showing first 500 of {filtered.length} — refine your search.
            </p>
          )}
        </>
      )}
    </div>
  );
}
