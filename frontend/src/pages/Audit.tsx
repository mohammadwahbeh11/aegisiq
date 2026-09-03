/**
 * Audit page (v2.0). Read-only view of the append-only audit_log
 * table. Analysts see their own actions; administrators see everyone.
 * Every mutating action in the system is recorded here — login, logout,
 * password change, rule edit, alert triage, alert delete, log delete,
 * retention purge, agent registration, simulation run.
 */
import { useCallback, useEffect, useState } from "react";

import {
  AuditEntry, AuditQuery, fetchAuditEntries,
} from "../api/client";
import {
  EmptyState, ErrorBanner, Loading, Panel, formatDateTime,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";

const PAGE_SIZE = 50;

const OUTCOMES = ["success", "failure"] as const;

export default function Audit() {
  const { user } = useAuth();
  const isAdmin = user?.role === "administrator";

  const [items, setItems] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);

  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState<string>("");
  const [username, setUsername] = useState("");
  const [applied, setApplied] = useState<AuditQuery>({});

  const load = useCallback(async () => {
    try {
      const data = await fetchAuditEntries({
        ...applied,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      });
      setItems(data.items);
      setTotal(data.total);
      setError(null);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      setError(status === 403
        ? "Audit API is disabled for this deployment (AUDIT_API_ENABLED=false)."
        : "Could not load audit entries.");
    } finally {
      setIsLoading(false);
    }
  }, [applied, page]);

  useEffect(() => { setIsLoading(true); load(); }, [load]);

  function apply() {
    setApplied({
      action: action || undefined,
      outcome: outcome || undefined,
      username: username || undefined,
    });
    setPage(0);
  }
  function clear() {
    setAction(""); setOutcome(""); setUsername(""); setApplied({}); setPage(0);
  }

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Audit log</h2>
          <p className="page-sub">
            Append-only record of every action that changed system state.
            {isAdmin
              ? " You see every user's actions because you are an administrator."
              : " You see your own actions only."}
          </p>
        </div>
        <button className="btn" onClick={() => { setIsLoading(true); void load(); }}>↻ Refresh</button>
      </div>

      <Panel title="Filters">
        <div className="filter-row">
          {isAdmin && (
            <label>
              Username
              <input
                value={username}
                placeholder="admin"
                onChange={(e) => setUsername(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && apply()}
              />
            </label>
          )}
          <label>
            Action
            <input
              value={action}
              placeholder="auth.login.success"
              onChange={(e) => setAction(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && apply()}
            />
          </label>
          <label>
            Outcome
            <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
              <option value="">Any</option>
              {OUTCOMES.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          </label>
          <div className="filter-actions">
            <button className="btn btn-primary" onClick={apply}>Search</button>
            <button className="btn" onClick={clear}>Clear</button>
          </div>
        </div>
      </Panel>

      {error && <ErrorBanner>{error}</ErrorBanner>}

      <Panel>
        {isLoading ? (
          <Loading label="Loading audit entries…" />
        ) : items.length === 0 ? (
          <EmptyState>No audit entries match these filters.</EmptyState>
        ) : (
          <>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Username</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Outcome</th>
                    <th>Source IP</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((e) => (
                    <tr key={e.id}>
                      <td className="muted nowrap">{formatDateTime(e.timestamp)}</td>
                      <td>{e.username ?? "—"}</td>
                      <td className="mono">{e.action}</td>
                      <td>{e.target ?? "—"}</td>
                      <td>
                        <span className={`badge ${e.outcome === "success" ? "status-resolved" : "severity-high"}`}>
                          {e.outcome}
                        </span>
                      </td>
                      <td className="mono">{e.source_ip ?? "—"}</td>
                      <td className="audit-details">
                        {e.details ? JSON.stringify(e.details) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {pageCount > 1 && (
              <div className="pager">
                <button disabled={page === 0} onClick={() => setPage((p) => p - 1)}>← Previous</button>
                <span>Page {page + 1} of {pageCount}</span>
                <button disabled={page + 1 >= pageCount} onClick={() => setPage((p) => p + 1)}>Next →</button>
              </div>
            )}
          </>
        )}
      </Panel>
    </>
  );
}
