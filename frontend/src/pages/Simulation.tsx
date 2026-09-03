import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { Scenario, fetchScenarios, runScenario } from "../api/client";
import {
  EmptyState,
  ErrorBanner,
  Loading,
  Panel,
  SeverityBadge,
  formatTime,
} from "../components/ui";
import { useLive } from "../context/LiveContext";

/**
 * The demo surface: pick an attack, press run, watch the pipeline react.
 *
 * The events are generated on the backend and pushed through the same
 * ingestion path real traffic uses, so what shows up below is genuine
 * detection output. If a rule doesn't fire, nothing appears -- the page
 * never draws an alert it wasn't sent.
 */
export default function Simulation() {
  const { liveLogs, liveAlerts, connection } = useLive();

  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [lastRun, setLastRun] = useState<{ name: string; expected: string[]; at: Date } | null>(null);

  useEffect(() => {
    fetchScenarios()
      .then(setScenarios)
      .catch(() => setError("Could not load simulation scenarios."))
      .finally(() => setIsLoading(false));
  }, []);

  async function launch(scenario: Scenario) {
    setRunning(scenario.key);
    setError(null);
    try {
      const response = await runScenario(scenario.key);
      setLastRun({ name: response.name, expected: response.expected_rules, at: new Date() });
      // Re-enable the button once the backend's own estimate says the
      // scenario has finished streaming, so a second click can't
      // interleave two runs and make the feed impossible to read.
      window.setTimeout(() => setRunning(null), response.estimated_seconds * 1000 + 500);
    } catch {
      setError("Could not start the scenario. Simulation runs require an administrator account.");
      setRunning(null);
    }
  }

  if (isLoading) return <Loading label="Loading scenarios…" />;

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Simulation lab</h2>
          <p className="page-sub">
            Replays a realistic attack through the real ingestion pipeline — same normalizer, same
            detection rules, same response layer. Nothing is written straight into the alerts
            table.
          </p>
        </div>
      </div>

      {connection !== "live" && (
        <ErrorBanner>
          The live connection is {connection}. Scenarios will still run and be stored, but the feed
          below will not update until the stream reconnects.
        </ErrorBanner>
      )}
      {error && <ErrorBanner>{error}</ErrorBanner>}

      <div className="scenario-grid">
        {scenarios.map((scenario) => (
          <article className="scenario-card" key={scenario.key}>
            <h3>{scenario.name}</h3>
            <p>{scenario.description}</p>
            <div className="scenario-meta">
              <span>{scenario.event_count} events</span>
              <span>~{scenario.estimated_seconds}s</span>
            </div>
            <div className="scenario-rules">
              {scenario.expected_rules.map((rule) => (
                <span className="tag" key={rule}>
                  {rule.replace(/_/g, " ")}
                </span>
              ))}
            </div>
            <button
              className="btn btn-primary"
              disabled={running !== null}
              onClick={() => launch(scenario)}
            >
              {running === scenario.key ? "Running…" : "Run scenario"}
            </button>
          </article>
        ))}
      </div>

      {lastRun && (
        <Panel title="Last run">
          <p>
            <strong>{lastRun.name}</strong> started at {lastRun.at.toLocaleTimeString()}. Rules
            expected to fire: {lastRun.expected.map((r) => r.replace(/_/g, " ")).join(", ")}.
          </p>
          <p className="muted small">
            Compare that against the alerts below. If one of them does not appear, that is real
            information about the detection logic — not a rendering problem.
          </p>
        </Panel>
      )}

      <div className="grid-2">
        <Panel title="Alerts raised (live)">
          {liveAlerts.length === 0 ? (
            <EmptyState>No alerts on this connection yet.</EmptyState>
          ) : (
            <ul className="feed">
              {liveAlerts.slice(0, 10).map((alert) => (
                <li key={alert.id}>
                  <Link to={`/alerts/${alert.id}`} className="feed-row">
                    <SeverityBadge severity={alert.severity} />
                    <div className="feed-body">
                      <div className="feed-title">{alert.rule_name}</div>
                      <div className="feed-desc">{alert.description}</div>
                    </div>
                    <span className="muted">{formatTime(alert.timestamp)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Events ingested (live)">
          {liveLogs.length === 0 ? (
            <EmptyState>No events on this connection yet.</EmptyState>
          ) : (
            <div className="table-scroll compact">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Event</th>
                    <th>Source</th>
                    <th>Raw</th>
                  </tr>
                </thead>
                <tbody>
                  {liveLogs.slice(0, 15).map((log) => (
                    <tr key={log.id}>
                      <td className="muted">{formatTime(log.timestamp)}</td>
                      <td>{log.event_type}</td>
                      <td className="mono">{log.source_ip ?? "—"}</td>
                      <td className="wrap mono small">{log.raw_log}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
