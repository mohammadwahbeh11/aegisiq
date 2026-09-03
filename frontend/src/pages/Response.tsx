import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { SoarActionsResponse, fetchSoarActions } from "../api/client";
import { EmptyState, ErrorBanner, Loading, Panel, formatDateTime } from "../components/ui";
import { useLive } from "../context/LiveContext";

const ACTION_LABELS: Record<string, string> = {
  block_ip: "Block source address",
  isolate_endpoint: "Isolate endpoint",
  disable_account: "Disable account",
  notify_analyst: "Notify analyst",
};

export default function Response() {
  const { liveSoarActions } = useLive();

  const [data, setData] = useState<SoarActionsResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    fetchSoarActions(200)
      .then((response) => {
        setData(response);
        setError(null);
      })
      .catch(() => setError("Could not load the automated-response history."))
      .finally(() => setIsLoading(false));
  }, []);

  useEffect(load, [load]);

  // A containment action broadcast over the live stream means the table
  // is stale; reload rather than splicing so the totals stay correct.
  useEffect(() => {
    if (liveSoarActions.length > 0) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveSoarActions.length]);

  if (isLoading) return <Loading label="Loading response history…" />;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Automated response (SOAR)</h2>
          <p className="page-sub">
            Containment decisions taken automatically in reaction to alerts.
          </p>
        </div>
      </div>

      {error && <ErrorBanner>{error}</ErrorBanner>}

      <Panel title="What this layer does — and does not do">
        <div className={`integration-status ${data?.execution_mode === "record_only" ? "neutral" : "warn"}`}>
          <span className="dot" aria-hidden="true" />
          <div>
            <strong>
              {data?.execution_mode === "record_only"
                ? "Record only — nothing is executed"
                : "Execution requested — actions are queued as pending"}
            </strong>
            <p>
              This build decides and records the containment action each alert warrants, so the
              response is fully auditable, but it ships no code that changes a firewall, isolates
              a host or disables an account. Turning on <code>SOAR_EXECUTE</code> marks actions as
              pending for an external executor; it does not create one.
            </p>
          </div>
        </div>
      </Panel>

      <Panel title={`Response history (${data?.total ?? 0})`}>
        {!data || data.items.length === 0 ? (
          <EmptyState>
            No containment actions recorded yet. One is recorded automatically for every
            high-severity or critical alert.
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Triggered by</th>
                  <th>Status</th>
                  <th>Alert</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((action) => (
                  <tr key={action.id}>
                    <td className="muted nowrap">{formatDateTime(action.timestamp)}</td>
                    <td>{ACTION_LABELS[action.action_type] ?? action.action_type}</td>
                    <td className="mono">{action.target}</td>
                    <td>{action.rule_name ?? "—"}</td>
                    <td>
                      <span className={`badge soar-${action.status}`}>{action.status}</span>
                    </td>
                    <td>
                      {action.alert_id ? (
                        <Link to={`/alerts/${action.alert_id}`}>#{action.alert_id}</Link>
                      ) : (
                        "—"
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
