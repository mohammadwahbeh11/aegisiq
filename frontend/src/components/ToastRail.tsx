import { useNavigate } from "react-router-dom";

import { useLive } from "../context/LiveContext";
import { MitreBadge, SeverityBadge, formatTime } from "./ui";

/**
 * The "something is happening RIGHT NOW" surface.
 *
 * A new alert pushed over the WebSocket pops a card here regardless of
 * which page the analyst is on, so an attack does not go unnoticed
 * because someone happened to be reading the Rules page. Clicking the
 * card opens the investigation view for that alert.
 *
 * Only alerts with status "new" produce a toast, and each is dismissed
 * automatically after a few seconds -- see LiveContext. A rail that
 * accumulates forever would cover the console it is meant to annotate.
 */
export default function ToastRail() {
  const { toasts, dismissToast } = useLive();
  const navigate = useNavigate();

  if (toasts.length === 0) return null;

  return (
    <div className="toast-rail" role="log" aria-live="polite">
      {toasts.map((alert) => (
        <article key={alert.id} className={`toast severity-border-${alert.severity}`}>
          <header>
            <SeverityBadge severity={alert.severity} />
            <span className="toast-rule">{alert.rule_name ?? "Detection rule"}</span>
            <button
              className="toast-close"
              aria-label="Dismiss alert notification"
              onClick={() => dismissToast(alert.id)}
            >
              ×
            </button>
          </header>

          <p className="toast-description">{alert.description}</p>

          <footer>
            <MitreBadge id={alert.mitre_id} />
            {alert.source_ip && <span className="mono">{alert.source_ip}</span>}
            <span className="muted">{formatTime(alert.timestamp)}</span>
            <button
              className="link-btn"
              onClick={() => {
                dismissToast(alert.id);
                navigate(`/alerts/${alert.id}`);
              }}
            >
              Investigate →
            </button>
          </footer>
        </article>
      ))}
    </div>
  );
}
