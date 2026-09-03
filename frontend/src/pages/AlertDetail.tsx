import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import {
  AlertDetail as AlertDetailType,
  AlertStatus,
  fetchAlert,
  updateAlertStatus,
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

const TRIAGE_OPTIONS: { status: AlertStatus; label: string; hint: string }[] = [
  { status: "investigating", label: "Start investigating", hint: "Claim this alert so nobody else duplicates the work" },
  { status: "resolved", label: "Mark resolved", hint: "The threat was real and has been handled" },
  { status: "false_positive", label: "False positive", hint: "The rule fired on benign activity" },
];

export default function AlertDetailPage() {
  const { alertId } = useParams();
  const id = Number(alertId);

  const [alert, setAlert] = useState<AlertDetailType | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      setAlert(await fetchAlert(id));
      setError(null);
    } catch {
      setError("Could not load this alert. It may have been removed.");
    } finally {
      setIsLoading(false);
    }
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  async function triage(status: AlertStatus) {
    setIsSaving(true);
    try {
      await updateAlertStatus(id, status);
      await load();
    } catch {
      setError("Could not update the alert status.");
    } finally {
      setIsSaving(false);
    }
  }

  if (isLoading) return <Loading label="Loading alert…" />;
  if (error && !alert) return <ErrorBanner>{error}</ErrorBanner>;
  if (!alert) return <EmptyState>Alert not found.</EmptyState>;

  return (
    <>
      <div className="page-head">
        <div>
          <Link className="link-btn" to="/alerts">
            ← Back to alert queue
          </Link>
          <h2>
            <SeverityBadge severity={alert.severity} /> {alert.rule_name ?? `Rule #${alert.rule_id}`}
          </h2>
          <p className="page-sub">{alert.description}</p>
        </div>
        <StatusBadge status={alert.status} />
      </div>

      {error && <ErrorBanner>{error}</ErrorBanner>}

      <div className="grid-2">
        <Panel title="Why this fired">
          <dl className="detail-list">
            <div>
              <dt>Detection rule</dt>
              <dd>{alert.rule_name ?? "—"}</dd>
            </div>
            <div>
              <dt>Rule logic</dt>
              <dd>{alert.rule_description ?? "—"}</dd>
            </div>
            <div>
              <dt>Configured threshold</dt>
              <dd>
                {alert.rule_threshold !== null && alert.rule_time_window_seconds !== null
                  ? `${alert.rule_threshold} events within ${alert.rule_time_window_seconds}s`
                  : "—"}
              </dd>
            </div>
            <div>
              <dt>MITRE ATT&CK technique</dt>
              <dd>
                <MitreBadge id={alert.mitre_id} />
              </dd>
            </div>
            <div>
              <dt>Cyber Kill Chain phase</dt>
              <dd>{alert.kill_chain_phase ?? "—"}</dd>
            </div>
            <div>
              <dt>Source / destination</dt>
              <dd className="mono">
                {alert.source_ip ?? "—"}
                {alert.destination_ip ? ` → ${alert.destination_ip}` : ""}
              </dd>
            </div>
            <div>
              <dt>Raised at</dt>
              <dd>{formatDateTime(alert.timestamp)}</dd>
            </div>
          </dl>
        </Panel>

        <Panel title="Triage">
          <p className="muted small">
            Every status change is recorded with who made it and when, so a “false positive”
            verdict stays traceable.
          </p>
          <div className="button-row">
            {TRIAGE_OPTIONS.map((option) => (
              <button
                key={option.status}
                className={`btn ${alert.status === option.status ? "btn-current" : ""}`}
                disabled={isSaving || alert.status === option.status}
                title={option.hint}
                onClick={() => triage(option.status)}
              >
                {option.label}
              </button>
            ))}
          </div>

          <h4>Status history</h4>
          {alert.status_history.length === 0 ? (
            <EmptyState>Untouched since it was raised.</EmptyState>
          ) : (
            <ul className="history">
              {alert.status_history.map((entry, index) => (
                <li key={index}>
                  <span className="muted">{formatDateTime(entry.changed_at)}</span>
                  <span>
                    {entry.previous_status ? `${entry.previous_status.replace("_", " ")} → ` : ""}
                    <strong>{entry.new_status.replace("_", " ")}</strong>
                  </span>
                  <span className="muted">{entry.changed_by ?? "unknown user"}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel title="Triggering event">
        {alert.triggering_log ? (
          <>
            <pre className="raw-log">{alert.triggering_log.raw_log}</pre>
            <dl className="detail-list inline">
              <div>
                <dt>Event type</dt>
                <dd>{alert.triggering_log.event_type}</dd>
              </div>
              <div>
                <dt>Host</dt>
                <dd>{alert.triggering_log.hostname ?? "—"}</dd>
              </div>
              <div>
                <dt>User</dt>
                <dd>{alert.triggering_log.username ?? "—"}</dd>
              </div>
              <div>
                <dt>Collected from</dt>
                <dd>{alert.triggering_log.source}</dd>
              </div>
            </dl>
          </>
        ) : (
          <EmptyState>No log event is linked to this alert.</EmptyState>
        )}
      </Panel>

      <Panel
        title={`Supporting evidence (${alert.related_logs.length} event${
          alert.related_logs.length === 1 ? "" : "s"
        })`}
      >
        <p className="muted small">
          The events the engine actually counted — same source, same event type, inside the rule’s
          own detection window, up to the moment it fired.
        </p>
        {alert.related_logs.length === 0 ? (
          <EmptyState>No correlated events were recorded for this alert.</EmptyState>
        ) : (
          <div className="table-scroll compact">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>User</th>
                  <th>Port</th>
                  <th>Raw log</th>
                </tr>
              </thead>
              <tbody>
                {alert.related_logs.map((log) => (
                  <tr key={log.id}>
                    <td className="muted nowrap">{formatDateTime(log.timestamp)}</td>
                    <td className="mono">{log.source_ip ?? "—"}</td>
                    <td>{log.username ?? "—"}</td>
                    <td className="mono">{log.destination_port ?? "—"}</td>
                    <td className="wrap mono small">{log.raw_log}</td>
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
