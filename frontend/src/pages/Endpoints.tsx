import { useCallback, useEffect, useState } from "react";

import { EndpointsOverview, fetchEndpoints } from "../api/client";
import { EmptyState, ErrorBanner, Loading, Panel, formatDateTime } from "../components/ui";

const WAZUH_TONE: Record<string, string> = {
  connected: "ok",
  not_configured: "neutral",
  unreachable: "warn",
  unauthorized: "warn",
  error: "warn",
};

export default function Endpoints() {
  const [overview, setOverview] = useState<EndpointsOverview | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setIsLoading(true);
    fetchEndpoints()
      .then((data) => {
        setOverview(data);
        setError(null);
      })
      .catch(() => setError("Could not load endpoints."))
      .finally(() => setIsLoading(false));
  }, []);

  useEffect(load, [load]);

  if (isLoading && !overview) return <Loading label="Loading endpoints…" />;

  const wazuh = overview?.wazuh_integration;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Monitored endpoints</h2>
          <p className="page-sub">
            Endpoints registered directly with this SIEM, plus any pulled live from a Wazuh
            Manager when one is configured.
          </p>
        </div>
        <button className="btn" onClick={load} disabled={isLoading}>
          {isLoading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      {error && <ErrorBanner>{error}</ErrorBanner>}

      {wazuh && (
        <Panel title="Wazuh integration">
          <div className={`integration-status ${WAZUH_TONE[wazuh.status] ?? "neutral"}`}>
            <span className="dot" aria-hidden="true" />
            <div>
              <strong>{wazuh.status.replace("_", " ")}</strong>
              <p>{wazuh.detail}</p>
              {wazuh.url && <p className="mono small">{wazuh.url}</p>}
            </div>
          </div>

          {wazuh.status === "not_configured" && (
            <p className="muted small">
              To connect an existing Wazuh Manager, set <code>WAZUH_URL</code>,{" "}
              <code>WAZUH_USERNAME</code> and <code>WAZUH_PASSWORD</code> in <code>.env</code> and
              restart the backend. Until then this console shows locally registered endpoints
              only — it does not invent agents to fill the table.
            </p>
          )}
        </Panel>
      )}

      <Panel
        title={`Endpoints (${overview?.total ?? 0})`}
        actions={
          overview && (
            <span className="muted small">
              {overview.sources.local} local · {overview.sources.wazuh} from Wazuh
            </span>
          )
        }
      >
        {!overview || overview.items.length === 0 ? (
          <EmptyState>
            No endpoints registered yet. An endpoint appears here once it is registered through
            <code> POST /api/agents</code> or pulled from a connected Wazuh Manager.
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Address</th>
                  <th>Operating system</th>
                  <th>Status</th>
                  <th>Last seen</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {overview.items.map((endpoint, index) => (
                  <tr key={`${endpoint.source}-${endpoint.agent_id ?? index}`}>
                    <td>{endpoint.hostname ?? "—"}</td>
                    <td className="mono">{endpoint.ip_address ?? "—"}</td>
                    <td>{endpoint.operating_system ?? "—"}</td>
                    <td>
                      <span className={`badge endpoint-${endpoint.status ?? "unknown"}`}>
                        {endpoint.status ?? "unknown"}
                      </span>
                    </td>
                    <td className="muted">{formatDateTime(endpoint.last_seen)}</td>
                    <td>
                      <span className="tag">{endpoint.source}</span>
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
