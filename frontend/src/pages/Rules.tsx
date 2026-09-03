import { useEffect, useState } from "react";

import { DetectionRule, fetchRules, updateRule } from "../api/client";
import {
  EmptyState,
  ErrorBanner,
  Loading,
  MitreBadge,
  Panel,
  SeverityBadge,
} from "../components/ui";
import { useAuth } from "../context/AuthContext";

export default function Rules() {
  const { user } = useAuth();
  const isAdmin = user?.role === "administrator";

  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [savingId, setSavingId] = useState<number | null>(null);
  const [drafts, setDrafts] = useState<Record<number, { threshold: string; window: string }>>({});

  useEffect(() => {
    fetchRules()
      .then((data) => {
        setRules(data);
        setDrafts(
          Object.fromEntries(
            data.map((rule) => [
              rule.id,
              { threshold: String(rule.threshold), window: String(rule.time_window_seconds) },
            ])
          )
        );
      })
      .catch(() => setError("Could not load detection rules."))
      .finally(() => setIsLoading(false));
  }, []);

  async function save(rule: DetectionRule, changes: Partial<DetectionRule>) {
    setSavingId(rule.id);
    try {
      const updated = await updateRule(rule.id, changes);
      setRules((current) => current.map((item) => (item.id === updated.id ? updated : item)));
      setDrafts((current) => ({
        ...current,
        [updated.id]: {
          threshold: String(updated.threshold),
          window: String(updated.time_window_seconds),
        },
      }));
      setError(null);
    } catch {
      setError("Could not save the rule. Thresholds must be at least 1 second / 1 event.");
    } finally {
      setSavingId(null);
    }
  }

  if (isLoading) return <Loading label="Loading detection rules…" />;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Detection rules</h2>
          <p className="page-sub">
            Rules are stored as data, not code. A change here takes effect on the next ingested
            event — no restart.
            {!isAdmin && " Editing requires an administrator account."}
          </p>
        </div>
      </div>

      {error && <ErrorBanner>{error}</ErrorBanner>}

      {rules.length === 0 ? (
        <EmptyState>No detection rules are configured.</EmptyState>
      ) : (
        rules.map((rule) => {
          const draft = drafts[rule.id] ?? {
            threshold: String(rule.threshold),
            window: String(rule.time_window_seconds),
          };
          const dirty =
            Number(draft.threshold) !== rule.threshold ||
            Number(draft.window) !== rule.time_window_seconds;

          return (
            <Panel
              key={rule.id}
              className={rule.enabled ? "" : "panel-muted"}
              title={
                <span className="rule-title">
                  {rule.name}
                  <SeverityBadge severity={rule.severity} />
                  <MitreBadge id={rule.mitre_id} />
                  {!rule.implemented && (
                    <span className="tag warn">no handler in this build</span>
                  )}
                </span>
              }
              actions={
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    disabled={!isAdmin || savingId === rule.id}
                    onChange={(e) => save(rule, { enabled: e.target.checked })}
                  />
                  <span>{rule.enabled ? "Enabled" : "Disabled"}</span>
                </label>
              }
            >
              <p className="rule-description">{rule.description}</p>

              <div className="rule-grid">
                <label>
                  Threshold (events)
                  <input
                    type="number"
                    min={1}
                    value={draft.threshold}
                    disabled={!isAdmin}
                    onChange={(e) =>
                      setDrafts((current) => ({
                        ...current,
                        [rule.id]: { ...draft, threshold: e.target.value },
                      }))
                    }
                  />
                </label>

                <label>
                  Time window (seconds)
                  <input
                    type="number"
                    min={1}
                    value={draft.window}
                    disabled={!isAdmin}
                    onChange={(e) =>
                      setDrafts((current) => ({
                        ...current,
                        [rule.id]: { ...draft, window: e.target.value },
                      }))
                    }
                  />
                </label>

                <div className="rule-meta">
                  <span className="muted">Kill chain phase</span>
                  <span>{rule.kill_chain_phase ?? "—"}</span>
                </div>

                {isAdmin && (
                  <button
                    className="btn btn-primary"
                    disabled={!dirty || savingId === rule.id}
                    onClick={() =>
                      save(rule, {
                        threshold: Number(draft.threshold),
                        time_window_seconds: Number(draft.window),
                      })
                    }
                  >
                    {savingId === rule.id ? "Saving…" : "Save changes"}
                  </button>
                )}
              </div>

              {rule.parameters && Object.keys(rule.parameters).length > 0 && (
                <details className="rule-params">
                  <summary>Rule parameters</summary>
                  <pre className="raw-log dim">{JSON.stringify(rule.parameters, null, 2)}</pre>
                </details>
              )}
            </Panel>
          );
        })
      )}
    </>
  );
}
