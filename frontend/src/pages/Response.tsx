/**
 * Automated response (SOAR) — v3.3.
 *
 * Until v3.3 this page could only ever say "decided, not executed",
 * because that was all the backend did. It now drives real containment:
 * the response agents this SIEM may act through, the orders it has sent
 * them, and — for an administrator — the two buttons that matter during
 * an incident: carry this decision out now, and undo it.
 *
 * The honesty of the old page is kept, not dropped: every action still
 * shows whether it was simulated, queued, applied or refused, and an
 * action the guard rails refused says so in its own row rather than
 * disappearing.
 */
import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import {
  ContainmentOrder,
  ResponseAgent,
  ResponseAgentsResponse,
  SoarActionsResponse,
  deleteResponseAgent,
  enrolResponseAgent,
  executeSoarAction,
  fetchContainmentOrders,
  fetchResponseAgents,
  fetchSoarActions,
  revokeContainmentOrder,
  setResponseAgentEnabled,
} from "../api/client";
import { EmptyState, ErrorBanner, Loading, Panel, formatDateTime } from "../components/ui";
import { useAuth } from "../context/AuthContext";
import { useLive } from "../context/LiveContext";

const ACTION_LABELS: Record<string, string> = {
  block_ip: "Block source address",
  isolate_endpoint: "Isolate endpoint",
  disable_account: "Disable account",
  notify_analyst: "Notify analyst",
};

const ORDER_LABELS: Record<string, string> = {
  block_ip: "Block IP",
  unblock_ip: "Unblock IP",
  disable_user: "Disable user",
  enable_user: "Re-enable user",
};

const AGENT_STATUS_TEXT: Record<ResponseAgent["status"], string> = {
  online: "online",
  stale: "last seen minutes ago",
  offline: "not responding",
  never_seen: "never checked in",
};

export default function Response() {
  const { liveSoarActions } = useLive();
  const { user } = useAuth();
  const isAdmin = user?.role === "administrator";

  const [data, setData] = useState<SoarActionsResponse | null>(null);
  const [agents, setAgents] = useState<ResponseAgentsResponse | null>(null);
  const [orders, setOrders] = useState<ContainmentOrder[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | number | null>(null);

  // Enrolment form
  const [showEnrol, setShowEnrol] = useState(false);
  const [newEndpointId, setNewEndpointId] = useState("");
  const [newHostname, setNewHostname] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [enrolResult, setEnrolResult] = useState<{ endpoint_id: string; shared_secret: string; install_hint: string } | null>(null);

  const load = useCallback(() => {
    Promise.allSettled([
      fetchSoarActions(200),
      fetchResponseAgents(),
      fetchContainmentOrders(50),
    ])
      .then(([actions, agentList, orderList]) => {
        if (actions.status === "fulfilled") setData(actions.value);
        if (agentList.status === "fulfilled") setAgents(agentList.value);
        if (orderList.status === "fulfilled") setOrders(orderList.value.items);
        setError(actions.status === "rejected"
          ? "Could not load the automated-response history." : null);
      })
      .finally(() => setIsLoading(false));
  }, []);

  useEffect(load, [load]);

  // A containment action broadcast over the live stream means the table
  // is stale; reload rather than splicing so the totals stay correct.
  useEffect(() => {
    if (liveSoarActions.length > 0) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveSoarActions.length]);

  function describe(err: unknown, fallback: string): string {
    const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
    return typeof detail === "string" ? detail : fallback;
  }

  async function handleExecute(actionId: number) {
    setBusyId(actionId);
    setError(null);
    setNotice(null);
    try {
      const result = await executeSoarAction(actionId);
      setNotice(`Order ${result.order_uid} queued for ${result.endpoint_id ?? "the agent"} — `
        + "it is applied on the agent's next check-in (within seconds).");
      load();
    } catch (err: unknown) {
      // A refusal is the interesting case: the server explains which
      // guard rail stopped it, and that explanation is the point.
      setError(describe(err, "The containment order could not be issued."));
    } finally {
      setBusyId(null);
    }
  }

  async function handleRevoke(orderUid: string) {
    setBusyId(orderUid);
    setError(null);
    setNotice(null);
    try {
      const inverse = await revokeContainmentOrder(orderUid);
      setNotice(`Undo queued: ${ORDER_LABELS[inverse.action] ?? inverse.action} ${inverse.target}.`);
      load();
    } catch (err: unknown) {
      setError(describe(err, "That order could not be reversed."));
    } finally {
      setBusyId(null);
    }
  }

  async function handleEnrol(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    try {
      const result = await enrolResponseAgent({
        endpoint_id: newEndpointId.trim(),
        hostname: newHostname.trim() || undefined,
        label: newLabel.trim() || undefined,
      });
      setEnrolResult(result);
      setNewEndpointId("");
      setNewHostname("");
      setNewLabel("");
      load();
    } catch (err: unknown) {
      setError(describe(err, "Could not enrol that endpoint."));
    }
  }

  async function toggleAgent(agent: ResponseAgent) {
    setBusyId(agent.endpoint_id);
    try {
      await setResponseAgentEnabled(agent.endpoint_id, !agent.enabled);
      load();
    } catch (err: unknown) {
      setError(describe(err, "Could not update that endpoint."));
    } finally {
      setBusyId(null);
    }
  }

  async function removeAgent(agent: ResponseAgent) {
    setBusyId(agent.endpoint_id);
    try {
      await deleteResponseAgent(agent.endpoint_id);
      load();
    } catch (err: unknown) {
      setError(describe(err, "Could not remove that endpoint."));
    } finally {
      setBusyId(null);
    }
  }

  if (isLoading) return <Loading label="Loading response history…" />;

  const executionLive = agents?.execution_enabled ?? false;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Automated response (SOAR)</h2>
          <p className="page-sub">
            Containment decisions, the agents that carry them out, and the orders sent to them.
          </p>
        </div>
      </div>

      {error && <ErrorBanner>{error}</ErrorBanner>}
      {notice && <div className="info-banner">{notice}</div>}

      <Panel title="Execution posture">
        <div className={`integration-status ${executionLive ? "warn" : "neutral"}`}>
          <span className="dot" aria-hidden="true" />
          <div>
            <strong>
              {executionLive
                ? "Live containment — decisions are sent to registered agents"
                : "Record only — decisions are shown, nothing is sent"}
            </strong>
            <p>
              {executionLive
                ? "SOAR_EXECUTE is on. A qualifying decision becomes a signed order for the "
                  + "endpoint's agent, which applies it and reports back. Guard rails still "
                  + "refuse loopback and reserved addresses, the console's own origin and "
                  + "protected accounts, and every block auto-expires on the agent."
                : "SOAR_EXECUTE is off, so containment is decided, recorded and shown but never "
                  + "sent. An administrator can still carry out any single decision on demand "
                  + "with “Execute”, which is the analyst-in-the-loop path."}
            </p>
          </div>
        </div>
      </Panel>

      <Panel
        title={`Response agents (${agents?.items.length ?? 0})`}
        actions={isAdmin ? (
          <button className="btn btn-secondary btn-sm" onClick={() => setShowEnrol((v) => !v)}>
            {showEnrol ? "Cancel" : "+ Enrol endpoint"}
          </button>
        ) : undefined}
      >
        {showEnrol && isAdmin && (
          <form onSubmit={handleEnrol} className="filter-row" style={{ marginBottom: "1rem" }}>
            <label>
              Endpoint ID
              <input value={newEndpointId} onChange={(e) => setNewEndpointId(e.target.value)}
                     placeholder="ubuntu-lab-01" required />
            </label>
            <label>
              Hostname (optional)
              <input value={newHostname} onChange={(e) => setNewHostname(e.target.value)}
                     placeholder="ubuntu-lab-01.local" />
            </label>
            <label>
              Label (optional)
              <input value={newLabel} onChange={(e) => setNewLabel(e.target.value)}
                     placeholder="Lab Ubuntu target" />
            </label>
            <button className="btn btn-primary" type="submit">Enrol</button>
          </form>
        )}

        {enrolResult && (
          <div className="info-banner" style={{ marginBottom: "1rem" }}>
            <strong>Copy this secret now — it is never shown again.</strong>
            <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all", margin: "0.5rem 0" }}>
              {enrolResult.shared_secret}
            </pre>
            <div className="muted" style={{ fontSize: "0.8rem" }}>
              Start the agent on {enrolResult.endpoint_id}:
              <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                {enrolResult.install_hint}
              </pre>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={() => setEnrolResult(null)}>
              I have saved it
            </button>
          </div>
        )}

        {!agents || agents.items.length === 0 ? (
          <EmptyState>
            No response agent is enrolled, so containment is recorded and never executed.
            {isAdmin
              ? " Enrol an endpoint above, then run agent/kill_switch_agent_v2.py on it."
              : " An administrator can enrol one."}
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Host</th>
                  <th>Platform</th>
                  <th>Last check-in</th>
                  <th>State</th>
                  {isAdmin && <th />}
                </tr>
              </thead>
              <tbody>
                {agents.items.map((agent) => (
                  <tr key={agent.endpoint_id}>
                    <td className="mono">{agent.endpoint_id}
                      {agent.label && <div className="muted" style={{ fontSize: 11 }}>{agent.label}</div>}
                    </td>
                    <td className="mono">{agent.hostname ?? "—"}</td>
                    <td className="muted">{agent.platform ?? "—"}</td>
                    <td className="muted nowrap">
                      {agent.last_seen_at ? formatDateTime(agent.last_seen_at) : "never"}
                    </td>
                    <td>
                      <span className={`badge agent-${agent.status}`}>
                        {agent.enabled ? AGENT_STATUS_TEXT[agent.status] : "disabled"}
                      </span>
                    </td>
                    {isAdmin && (
                      <td className="nowrap">
                        <button className="btn btn-ghost btn-sm"
                                disabled={busyId === agent.endpoint_id}
                                onClick={() => void toggleAgent(agent)}>
                          {agent.enabled ? "Disable" : "Enable"}
                        </button>
                        <button className="btn-danger btn-sm"
                                disabled={busyId === agent.endpoint_id}
                                onClick={() => void removeAgent(agent)}>
                          Remove
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {orders.length > 0 && (
        <Panel title={`Containment orders (${orders.length})`}>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Issued</th>
                  <th>Order</th>
                  <th>Target</th>
                  <th>Endpoint</th>
                  <th>By</th>
                  <th>Status</th>
                  <th>Result</th>
                  {isAdmin && <th />}
                </tr>
              </thead>
              <tbody>
                {orders.map((order) => (
                  <tr key={order.order_uid}>
                    <td className="muted nowrap">{formatDateTime(order.created_at)}</td>
                    <td>{ORDER_LABELS[order.action] ?? order.action}</td>
                    <td className="mono">{order.target}</td>
                    <td className="mono">{order.endpoint_id}</td>
                    <td className="muted">{order.issued_by ?? "soar"}</td>
                    <td><span className={`badge order-${order.status}`}>{order.status}</span></td>
                    <td className="muted wrap" style={{ maxWidth: 280 }}>
                      {order.output ?? "—"}
                    </td>
                    {isAdmin && (
                      <td className="nowrap">
                        {order.revocable && (
                          <button className="btn btn-ghost btn-sm"
                                  disabled={busyId === order.order_uid}
                                  onClick={() => void handleRevoke(order.order_uid)}>
                            Undo
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

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
                  {isAdmin && <th />}
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
                      {action.detail && action.detail.startsWith("NOT executed") && (
                        <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>
                          {action.detail.replace("NOT executed: ", "")}
                        </div>
                      )}
                    </td>
                    <td>
                      {action.alert_id ? (
                        <Link to={`/alerts/${action.alert_id}`}>#{action.alert_id}</Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    {isAdmin && (
                      <td className="nowrap">
                        {(action.action_type === "block_ip"
                          || action.action_type === "disable_account") && (
                          <button
                            className="btn btn-ghost btn-sm"
                            disabled={busyId === action.id || action.status === "executed"}
                            onClick={() => void handleExecute(action.id)}
                            title="Send this decision to the endpoint's response agent"
                          >
                            {action.status === "executed" ? "Applied" : "Execute"}
                          </button>
                        )}
                      </td>
                    )}
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
