import { Severity } from "../api/client";

/**
 * Inline-SVG charts.
 *
 * Why not Chart.js: the console has to render on an isolated lab network
 * with no internet access, and these two charts are a donut and a column
 * chart. Hand-drawn SVG keeps the bundle small, removes a runtime
 * dependency, and inherits the CSS theme variables directly, which is
 * what makes the colours here match the severity badges everywhere else.
 */

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
};

export function SeverityDonut({
  counts,
  size = 190,
}: {
  counts: Record<Severity, number>;
  size?: number;
}) {
  const total = SEVERITY_ORDER.reduce((sum, key) => sum + (counts[key] ?? 0), 0);
  const radius = size / 2 - 16;
  const circumference = 2 * Math.PI * radius;
  const center = size / 2;

  let consumed = 0;

  return (
    <div className="donut-wrap">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img"
           aria-label={`Active alerts by severity, ${total} in total`}>
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="var(--border)"
          strokeWidth={18}
        />
        {total > 0 &&
          SEVERITY_ORDER.map((severity) => {
            const value = counts[severity] ?? 0;
            if (value === 0) return null;
            const fraction = value / total;
            const dash = fraction * circumference;
            // Rotated -90deg via the transform below so the first
            // segment starts at 12 o'clock rather than 3 o'clock.
            const offset = -consumed * circumference;
            consumed += fraction;
            return (
              <circle
                key={severity}
                cx={center}
                cy={center}
                r={radius}
                fill="none"
                stroke={SEVERITY_COLORS[severity]}
                strokeWidth={18}
                strokeDasharray={`${dash} ${circumference - dash}`}
                strokeDashoffset={offset}
                transform={`rotate(-90 ${center} ${center})`}
              />
            );
          })}
        <text x={center} y={center - 2} textAnchor="middle" className="donut-value">
          {total}
        </text>
        <text x={center} y={center + 18} textAnchor="middle" className="donut-label">
          active
        </text>
      </svg>

      <ul className="donut-legend">
        {SEVERITY_ORDER.map((severity) => (
          <li key={severity}>
            <span className="swatch" style={{ background: SEVERITY_COLORS[severity] }} />
            <span className="legend-name">{severity}</span>
            <span className="legend-value">{counts[severity] ?? 0}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export interface TimelinePoint {
  hour: string;
  events: number;
  alerts: number;
}

export function ActivityTimeline({ buckets }: { buckets: TimelinePoint[] }) {
  if (buckets.length === 0) {
    return <div className="empty-state">No activity recorded in this window.</div>;
  }

  const maxEvents = Math.max(1, ...buckets.map((bucket) => bucket.events));

  return (
    <div className="timeline">
      <div className="timeline-bars">
        {buckets.map((bucket) => {
          const eventHeight = (bucket.events / maxEvents) * 100;
          // Alerts are drawn against the SAME scale as events, not their
          // own, so the chart shows how small a fraction of traffic is
          // actually malicious rather than exaggerating it.
          const alertHeight = (bucket.alerts / maxEvents) * 100;
          const label = new Date(
            /([zZ]|[+-]\d{2}:?\d{2})$/.test(bucket.hour) ? bucket.hour : `${bucket.hour}Z`
          );
          return (
            <div
              className="timeline-column"
              key={bucket.hour}
              title={`${label.toLocaleString()} — ${bucket.events} events, ${bucket.alerts} alerts`}
            >
              <div className="timeline-stack">
                <div className="bar-events" style={{ height: `${eventHeight}%` }} />
                {bucket.alerts > 0 && (
                  <div className="bar-alerts" style={{ height: `${alertHeight}%` }} />
                )}
              </div>
              <span className="timeline-tick">{label.getHours()}</span>
            </div>
          );
        })}
      </div>
      <div className="timeline-legend">
        <span>
          <span className="swatch" style={{ background: "var(--accent)" }} /> events
        </span>
        <span>
          <span className="swatch" style={{ background: "var(--severity-critical)" }} /> alerts
        </span>
      </div>
    </div>
  );
}
