import { useEffect, useState } from "react";

import {
  PurgeDryRun,
  PurgeRequest,
  PurgeResponse,
  RetentionConfig,
  Severity,
  fetchRetentionConfig,
  purgeDryRun,
  purgeRetention,
} from "../api/client";
import {
  EmptyState,
  ErrorBanner,
  Loading,
  Panel,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";

/**
 * Retention / cleanup console (project section 15 / resource-efficiency
 * objective O2). The console never deletes anything without confirmation
 * -- a dry-run always runs first so the analyst sees the exact counts
 * before committing.
 *
 * Administrator-only. Analysts triage; administrators shape retention.
 */

const SEVERITIES: (Severity | "none")[] = ["critical", "high", "medium", "low", "none"];

export default function Retention() {
  const { user } = useAuth();
  const isAdmin = user?.role === "administrator";

  const [config, setConfig] = useState<RetentionConfig | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [alertDays, setAlertDays] = useState<string>("");
  const [logDays, setLogDays] = useState<string>("");
  const [onlyTriaged, setOnlyTriaged] = useState(true);
  const [minKeep, setMinKeep] = useState<Severity | "none">("high");

  const [preview, setPreview] = useState<PurgeDryRun | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [purging, setPurging] = useState(false);
  const [result, setResult] = useState<PurgeResponse | null>(null);

  useEffect(() => {
    if (!isAdmin) {
      setIsLoading(false);
      return;
    }
    fetchRetentionConfig()
      .then((c) => {
        setConfig(c);
        // Pre-fill from configured defaults so a quick "purge" matches
        // whatever LOG_RETENTION_DAYS / ALERT_RETENTION_DAYS were set to.
        setAlertDays(String(c.alert_retention_days));
        setLogDays(String(c.log_retention_days));
      })
      .catch(() => setError("Could not load retention configuration."))
      .finally(() => setIsLoading(false));
  }, [isAdmin]);

  function buildPayload(): PurgeRequest | null {
    const alertsN = alertDays.trim() ? Number(alertDays) : undefined;
    const logsN = logDays.trim() ? Number(logDays) : undefined;
    if (alertsN === undefined && logsN === undefined) {
      setError("Enter a retention window for alerts OR logs (or both).");
      return null;
    }
    if (alertsN !== undefined && (!Number.isInteger(alertsN) || alertsN < 1)) {
      setError("Alert retention window must be a whole number of days ≥ 1.");
      return null;
    }
    if (logsN !== undefined && (!Number.isInteger(logsN) || logsN < 1)) {
      setError("Log retention window must be a whole number of days ≥ 1.");
      return null;
    }
    setError(null);
    return {
      alerts_older_than_days: alertsN,
      logs_older_than_days: logsN,
      only_triaged_alerts: onlyTriaged,
      min_severity_to_keep: minKeep === "none" ? null : minKeep,
    };
  }

  async function handlePreview() {
    const payload = buildPayload();
    if (!payload) return;
    setPreviewing(true);
    setResult(null);
    try {
      const p = await purgeDryRun(payload);
      setPreview(p);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      setError(status === 403 ? "Only administrators can purge." : "Preview failed.");
      setPreview(null);
    } finally {
      setPreviewing(false);
    }
  }

  async function handlePurge() {
    const payload = buildPayload();
    if (!payload) return;
    const willAlerts = preview?.would_delete_alerts ?? "?";
    const willLogs = preview?.would_delete_logs ?? "?";
    if (!window.confirm(
      `Permanently delete ${willAlerts} alert(s) and ${willLogs} log event(s)?\n\n` +
      `This cannot be undone. Alerts of severity ${minKeep === "none" ? "any" : `≥ ${minKeep}`}` +
      ` are preserved regardless of age.`
    )) return;
    setPurging(true);
    try {
      const r = await purgeRetention(payload);
      setResult(r);
      setPreview(null);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      setError(status === 403 ? "Only administrators can purge." : "Purge failed.");
    } finally {
      setPurging(false);
    }
  }

  if (isLoading) return <Loading label="Loading retention settings…" />;

  if (!isAdmin) {
    return (
      <>
        <div className="page-head">
          <div>
            <h2>Retention</h2>
            <p className="page-sub">
              Data lifecycle management. Administrator role required.
            </p>
          </div>
        </div>
        <Panel>
          <EmptyState>Signed in as {user?.username} ({user?.role}). This page is
            administrator-only. Ask an administrator to change retention settings.</EmptyState>
        </Panel>
      </>
    );
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Retention</h2>
          <p className="page-sub">
            Bulk cleanup by age. Alerts and logs older than the chosen window are removed —
            with a preview step first, and hard safety guards on unresolved / high-severity alerts.
          </p>
        </div>
      </div>

      {config && (
        <Panel title="Configured defaults">
          <div className="kpi-grid">
            <div className="kpi-card">
              <div className="label">Alert retention</div>
              <div className="value">{config.alert_retention_days} days</div>
              <div className="hint">from .env — ALERT_RETENTION_DAYS</div>
            </div>
            <div className="kpi-card">
              <div className="label">Log retention</div>
              <div className="value">{config.log_retention_days} days</div>
              <div className="hint">from .env — LOG_RETENTION_DAYS</div>
            </div>
            <div className="kpi-card">
              <div className="label">Max DB size</div>
              <div className="value">{config.max_db_size_mb} MB</div>
              <div className="hint">soft target — the console does not enforce</div>
            </div>
          </div>
        </Panel>
      )}

      {error && <ErrorBanner>{error}</ErrorBanner>}

      <Panel title="Purge — bulk delete by age">
        <div className="filter-row">
          <label>
            Delete alerts older than (days)
            <input
              type="number"
              min={1}
              value={alertDays}
              placeholder="e.g. 30 — leave blank to skip"
              onChange={(e) => setAlertDays(e.target.value)}
            />
          </label>

          <label>
            Delete logs older than (days)
            <input
              type="number"
              min={1}
              value={logDays}
              placeholder="e.g. 14 — leave blank to skip"
              onChange={(e) => setLogDays(e.target.value)}
            />
          </label>

          <label>
            Keep severity ≥
            <select
              value={minKeep}
              onChange={(e) => setMinKeep(e.target.value as Severity | "none")}
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s === "none" ? "no severity guard (allow all)" : s}
                </option>
              ))}
            </select>
          </label>

          <label className="checkbox">
            <input
              type="checkbox"
              checked={onlyTriaged}
              onChange={(e) => setOnlyTriaged(e.target.checked)}
            />
            Only delete alerts that were already triaged (Resolved / False positive)
          </label>

          <div className="filter-actions">
            <button
              className="btn"
              onClick={handlePreview}
              disabled={previewing || purging}
              title="See what would be removed without actually deleting anything"
            >
              {previewing ? "Previewing…" : "Preview"}
            </button>
            <button
              className="btn-danger"
              onClick={handlePurge}
              disabled={purging || !preview}
              title="Preview first — the button is enabled only after a preview has run"
            >
              {purging ? "Purging…" : "Purge"}
            </button>
          </div>
        </div>

        {preview && (
          <div className="preview-banner">
            <strong>Preview</strong> — this action would delete{" "}
            <strong>{preview.would_delete_alerts.toLocaleString()}</strong> alert(s)
            {" and "}
            <strong>{preview.would_delete_logs.toLocaleString()}</strong> log event(s).
            {preview.cutoff_alerts && (
              <div className="muted">
                Alerts older than {new Date(preview.cutoff_alerts).toLocaleString()}.
              </div>
            )}
            {preview.cutoff_logs && (
              <div className="muted">
                Logs older than {new Date(preview.cutoff_logs).toLocaleString()}.
              </div>
            )}
          </div>
        )}

        {result && (
          <div className="preview-banner success">
            <strong>Done.</strong> Removed {result.deleted_alerts} alert(s)
            {" ("}+{result.deleted_alert_status_history} history rows,
            {" "}+{result.deleted_soar_actions} SOAR actions)
            {" and "}{result.deleted_logs} log event(s).
            <div className="muted">{result.detail}</div>
          </div>
        )}
      </Panel>

      <Panel title="Safety notes">
        <ul>
          <li>
            <strong>Alerts of severity “{minKeep === "none" ? "any" : minKeep}” or higher are preserved</strong>
            {" "}regardless of age. To allow HIGH alerts to be removed, set this to <em>critical</em>;
            to remove the guard entirely, choose <em>no severity guard</em>.
          </li>
          <li>
            <strong>Untriaged alerts are protected</strong> by default — an alert an analyst hasn't
            marked Resolved or False positive stays. Uncheck the box only if you know you are
            deleting queue history rather than active work.
          </li>
          <li>
            Deleting a log <strong>does not</strong> delete the alert that referenced it — the
            alert's <code>log_id</code> is set to <code>NULL</code>. Losing the evidence line
            should not silently disappear the alert.
          </li>
          <li>
            Deleting an alert <strong>does</strong> cascade to its status history and its recorded
            SOAR actions — those rows are only meaningful in the alert's context.
          </li>
          <li>
            There is no schedule. Purge runs when you press the button — the .env defaults above
            are shown for reference, not applied automatically.
          </li>
        </ul>
      </Panel>
    </>
  );
}
