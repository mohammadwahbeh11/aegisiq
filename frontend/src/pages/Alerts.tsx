import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import {
  Alert,
  AlertQuery,
  AlertStatus,
  Severity,
  deleteAlert,
  exportAlertsCsv,
  fetchAlerts,
} from "../api/client";
import {
  EmptyState,
  ErrorBanner,
  Loading,
  MitreBadge,
  Panel,
  SeverityBadge,
  StatusBadge,
  formatDateTime,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { useLive } from "../context/LiveContext";

const PAGE_SIZE = 50;

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const STATUSES: AlertStatus[] = ["new", "investigating", "resolved", "false_positive"];

export default function Alerts() {
  const { onAlert } = useLive();
  const { user } = useAuth();
  const isAdmin = user?.role === "administrator";
  const [searchParams, setSearchParams] = useSearchParams();

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [exporting, setExporting] = useState(false);

  const severity = (searchParams.get("severity") as Severity | null) ?? undefined;
  const status = (searchParams.get("status") as AlertStatus | null) ?? undefined;
  const sourceIp = searchParams.get("source_ip") ?? undefined;

  const load = useCallback(async () => {
    const query: AlertQuery = {
      severity,
      status,
      source_ip: sourceIp,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    };
    try {
      const data = await fetchAlerts(query);
      setAlerts(data.items);
      setTotal(data.total);
      setError(null);
    } catch {
      setError("Could not load alerts from the backend.");
    } finally {
      setIsLoading(false);
    }
  }, [severity, status, sourceIp, page]);

  useEffect(() => {
    setIsLoading(true);
    load();
  }, [load]);

  // A new alert arriving over the live stream refreshes the queue, so an
  // analyst watching this page sees it without pressing anything --
  // re-querying rather than splicing the pushed object in keeps the
  // filters and the `total` count honest.
  useEffect(() => onAlert(() => void load()), [onAlert, load]);

  function setFilter(key: string, value: string | undefined) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    setSearchParams(next);
    setPage(0);
  }

  async function handleDelete(id: number) {
    // Explicit confirmation because deletion is permanent -- there is
    // no undo, and an alert dismissed by the SOC still belongs on the
    // audit trail (mark it Resolved / False positive for that). Delete
    // is for retention cleanup, not for triage.
    if (!window.confirm(
      `Permanently delete alert #${id}?\n\n` +
      `This removes the alert and its audit history. To dismiss without deleting, ` +
      `set the alert's status to Resolved or False positive instead.`
    )) {
      return;
    }
    setDeletingId(id);
    try {
      await deleteAlert(id);
      setAlerts((current) => current.filter((a) => a.id !== id));
      setTotal((t) => Math.max(0, t - 1));
      setError(null);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      setError(
        status === 403
          ? "Only administrators can delete alerts."
          : `Could not delete alert #${id}.`
      );
    } finally {
      setDeletingId(null);
    }
  }

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  async function handleExport() {
    setExporting(true);
    try {
      // Export up to 1000 rows (the backend's hard cap), respecting the
      // filter set the operator is currently looking at.
      await exportAlertsCsv({
        severity, status, source_ip: sourceIp, limit: 1000,
      });
      setError(null);
    } catch {
      setError("Could not export the current alerts view to CSV.");
    } finally {
      setExporting(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Alert queue</h2>
          <p className="page-sub">
            {total.toLocaleString()} alert{total === 1 ? "" : "s"} match the current filters
            {total > PAGE_SIZE && ` — showing ${alerts.length} of them`}.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button
            className="btn"
            disabled={exporting || total === 0}
            title="Download the current filter view as a CSV (up to 1000 rows)"
            onClick={() => void handleExport()}
          >
            {exporting ? "Exporting…" : "⇩ Export CSV"}
          </button>
          <button className="btn" onClick={() => { setIsLoading(true); void load(); }}>
            ↻ Refresh
          </button>
        </div>
      </div>

      <Panel
        title="Filters"
        actions={
          (severity || status || sourceIp) && (
            <button className="link-btn" onClick={() => setSearchParams(new URLSearchParams())}>
              Clear all
            </button>
          )
        }
      >
        <div className="filter-row">
          <label>
            Severity
            <select value={severity ?? ""} onChange={(e) => setFilter("severity", e.target.value || undefined)}>
              <option value="">Any</option>
              {SEVERITIES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>

          <label>
            Status
            <select value={status ?? ""} onChange={(e) => setFilter("status", e.target.value || undefined)}>
              <option value="">Any</option>
              {STATUSES.map((value) => (
                <option key={value} value={value}>
                  {value.replace("_", " ")}
                </option>
              ))}
            </select>
          </label>

          <label>
            Source address
            <input
              value={sourceIp ?? ""}
              placeholder="e.g. 198.51.100.10"
              onChange={(e) => setFilter("source_ip", e.target.value || undefined)}
            />
          </label>
        </div>
      </Panel>

      {error && <ErrorBanner>{error}</ErrorBanner>}

      <Panel>
        {isLoading ? (
          <Loading label="Loading alerts…" />
        ) : alerts.length === 0 ? (
          <EmptyState>
            No alerts match these filters. That is a real answer, not a loading state — if you
            expected some, widen the filters or run a scenario from the Simulation lab.
          </EmptyState>
        ) : (
          <>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Description</th>
                    <th>Source</th>
                    <th>Technique</th>
                    <th>Status</th>
                    <th>Raised</th>
                    {isAdmin && <th></th>}
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert) => (
                    <tr key={alert.id}>
                      <td>
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td>
                        <Link to={`/alerts/${alert.id}`}>{alert.rule_name ?? `Rule #${alert.rule_id}`}</Link>
                      </td>
                      <td className="wrap">{alert.description}</td>
                      <td className="mono">{alert.source_ip ?? "—"}</td>
                      <td>
                        <MitreBadge id={alert.mitre_id} />
                      </td>
                      <td>
                        <StatusBadge status={alert.status} />
                      </td>
                      <td className="muted nowrap">{formatDateTime(alert.timestamp)}</td>
                      {isAdmin && (
                        <td className="nowrap">
                          <button
                            className="btn-danger"
                            disabled={deletingId === alert.id}
                            onClick={() => handleDelete(alert.id)}
                            title="Permanently delete this alert (admin only)"
                          >
                            {deletingId === alert.id ? "…" : "Delete"}
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {pageCount > 1 && (
              <div className="pager">
                <button disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                  ← Previous
                </button>
                <span>
                  Page {page + 1} of {pageCount}
                </span>
                <button disabled={page + 1 >= pageCount} onClick={() => setPage((p) => p + 1)}>
                  Next →
                </button>
              </div>
            )}
          </>
        )}
      </Panel>
    </>
  );
}
