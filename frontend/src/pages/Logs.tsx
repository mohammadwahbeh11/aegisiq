import { Fragment, useCallback, useEffect, useState } from "react";

import { LogEvent, LogQuery, Severity, deleteLog, exportLogsCsv, fetchEventTypes, fetchLogs } from "../api/client";
import {
  EmptyState,
  ErrorBanner,
  Loading,
  Panel,
  SeverityBadge,
  formatDateTime,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { useLive } from "../context/LiveContext";

const PAGE_SIZE = 50;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export default function Logs() {
  const { liveLogs } = useLive();
  const { user } = useAuth();
  const isAdmin = user?.role === "administrator";

  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [eventTypes, setEventTypes] = useState<string[]>([]);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [exporting, setExporting] = useState(false);

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [eventType, setEventType] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  // Applied filters are separate from the input values so typing in the
  // search box doesn't fire a request per keystroke.
  const [applied, setApplied] = useState<LogQuery>({});

  const load = useCallback(async () => {
    try {
      const data = await fetchLogs({ ...applied, limit: PAGE_SIZE, offset: page * PAGE_SIZE });
      setLogs(data.items);
      setTotal(data.total);
      setError(null);
    } catch {
      setError("Could not search logs.");
    } finally {
      setIsLoading(false);
    }
  }, [applied, page]);

  useEffect(() => {
    setIsLoading(true);
    load();
  }, [load]);

  useEffect(() => {
    fetchEventTypes().then(setEventTypes).catch(() => setEventTypes([]));
  }, []);

  // Refresh when new events arrive, but only on the first page and only
  // with no filters applied -- silently rewriting page 4 of a filtered
  // investigation under the analyst's cursor would be hostile.
  const hasFilters = Object.values(applied).some(Boolean);
  useEffect(() => {
    if (page === 0 && !hasFilters && liveLogs.length > 0) {
      load();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveLogs.length]);

  function applyFilters() {
    setApplied({
      search: search || undefined,
      severity: severity || undefined,
      event_type: eventType || undefined,
      source_ip: sourceIp || undefined,
    });
    setPage(0);
  }

  function clearFilters() {
    setSearch("");
    setSeverity("");
    setEventType("");
    setSourceIp("");
    setApplied({});
    setPage(0);
  }

  async function handleDelete(id: number, event: React.MouseEvent) {
    event.stopPropagation(); // don't toggle the expanded row
    if (!window.confirm(`Permanently delete log event #${id}?\n\nAny alerts that referenced this log are kept; only the raw event is removed.`)) {
      return;
    }
    setDeletingId(id);
    try {
      await deleteLog(id);
      setLogs((current) => current.filter((l) => l.id !== id));
      setTotal((t) => Math.max(0, t - 1));
      setError(null);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      setError(
        status === 403
          ? "Only administrators can delete log events."
          : `Could not delete log #${id}.`
      );
    } finally {
      setDeletingId(null);
    }
  }

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  async function handleExport() {
    setExporting(true);
    try {
      // Export up to 1000 rows honouring the currently applied filters.
      await exportLogsCsv({ ...applied, limit: 1000 });
      setError(null);
    } catch {
      setError("Could not export the current search view to CSV.");
    } finally {
      setExporting(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Log search</h2>
          <p className="page-sub">
            {total.toLocaleString()} stored event{total === 1 ? "" : "s"} match
            {hasFilters ? " these filters" : " — the full archive"}.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button
            className="btn"
            disabled={exporting || total === 0}
            title="Download the current search view as a CSV (up to 1000 rows)"
            onClick={() => void handleExport()}
          >
            {exporting ? "Exporting…" : "⇩ Export CSV"}
          </button>
          <button className="btn" onClick={() => { setIsLoading(true); void load(); }}>
            ↻ Refresh
          </button>
        </div>
      </div>

      <Panel title="Search">
        <div className="filter-row">
          <label className="grow">
            Text
            <input
              value={search}
              placeholder="Search the raw log line, user, host or event type"
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && applyFilters()}
            />
          </label>

          <label>
            Severity
            <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
              <option value="">Any</option>
              {SEVERITIES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>

          <label>
            Event type
            <select value={eventType} onChange={(e) => setEventType(e.target.value)}>
              <option value="">Any</option>
              {eventTypes.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>

          <label>
            Source address
            <input value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} placeholder="e.g. 198.51.100.10" />
          </label>

          <div className="filter-actions">
            <button className="btn btn-primary" onClick={applyFilters}>
              Search
            </button>
            <button className="btn" onClick={clearFilters}>
              Clear
            </button>
          </div>
        </div>
      </Panel>

      {error && <ErrorBanner>{error}</ErrorBanner>}

      <Panel>
        {isLoading ? (
          <Loading label="Searching…" />
        ) : logs.length === 0 ? (
          <EmptyState>No stored events match this search.</EmptyState>
        ) : (
          <>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Event type</th>
                    <th>Host</th>
                    <th>Source</th>
                    <th>User</th>
                    <th>Severity</th>
                    <th>Collector</th>
                    {isAdmin && <th></th>}
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <Fragment key={log.id}>
                      <tr
                        className="clickable"
                        onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                      >
                        <td className="muted nowrap">{formatDateTime(log.timestamp)}</td>
                        <td>{log.event_type}</td>
                        <td>{log.hostname ?? "—"}</td>
                        <td className="mono">{log.source_ip ?? "—"}</td>
                        <td>{log.username ?? "—"}</td>
                        <td>
                          <SeverityBadge severity={log.severity} />
                        </td>
                        <td className="muted">{log.source}</td>
                        {isAdmin && (
                          <td className="nowrap">
                            <button
                              className="btn-danger"
                              disabled={deletingId === log.id}
                              onClick={(e) => handleDelete(log.id, e)}
                              title="Permanently delete this log event (admin only)"
                            >
                              {deletingId === log.id ? "…" : "Delete"}
                            </button>
                          </td>
                        )}
                      </tr>
                      {expanded === log.id && (
                        <tr className="expanded-row">
                          <td colSpan={isAdmin ? 8 : 7}>
                            <pre className="raw-log">{log.raw_log}</pre>
                            {log.normalized_data && Object.keys(log.normalized_data).length > 0 && (
                              <pre className="raw-log dim">
                                {JSON.stringify(log.normalized_data, null, 2)}
                              </pre>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
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
