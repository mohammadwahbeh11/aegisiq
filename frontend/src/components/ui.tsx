/**
 * Shared UI primitives — v2.8 refresh.
 *
 * Kept in one file so a designer working on look-and-feel touches one
 * module. Every component here consumes the v2.8 design tokens
 * (var(--...)) so a re-theme is a token swap, not a component rewrite.
 *
 * Backwards compatible with earlier pages that imported EmptyState /
 * Loading / Panel / ErrorBanner / SeverityBadge / StatusBadge from ui.
 */
import { ReactNode } from "react";

// -- Types --------------------------------------------------------------
type Severity = "low" | "medium" | "high" | "critical";
type AlertStatus = "new" | "investigating" | "resolved" | "false_positive";

// -- Panel --------------------------------------------------------------
export function Panel({
  title,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-header">
          {typeof title === "string" ? <h2>{title}</h2> : title}
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

// -- Empty state --------------------------------------------------------
export function EmptyState({
  icon = "📭",
  title,
  children,
}: {
  icon?: ReactNode;
  title?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="icon" aria-hidden>{icon}</div>
      {title && <div style={{ fontWeight: 600, marginBottom: 4 }}>{title}</div>}
      {children && <div style={{ fontSize: 13 }}>{children}</div>}
    </div>
  );
}

// -- Loading ------------------------------------------------------------
export function Loading({ label = "Loading…" }: { label?: string }) {
  return <div className="loading" role="status" aria-live="polite">{label}</div>;
}

// -- Skeleton -----------------------------------------------------------
export function Skeleton({
  height = 16,
  width = "100%",
  count = 1,
  gap = 6,
}: {
  height?: number | string;
  width?: number | string;
  count?: number;
  gap?: number;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap }}>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="skeleton"
          style={{
            height: typeof height === "number" ? `${height}px` : height,
            width:  typeof width  === "number" ? `${width}px`  : width,
          }}
        />
      ))}
    </div>
  );
}

// -- Error banner -------------------------------------------------------
export function ErrorBanner({ children }: { children: ReactNode }) {
  return <div className="error-banner" role="alert">{children}</div>;
}

// -- Severity badge -----------------------------------------------------
export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge severity-${severity}`}>{severity}</span>;
}

// -- Status badge -------------------------------------------------------
export function StatusBadge({ status }: { status: AlertStatus }) {
  const label = status === "false_positive" ? "false positive" : status;
  return <span className={`status-badge status-${status}`}>{label}</span>;
}

// -- MITRE badge --------------------------------------------------------
export function MitreBadge({ id }: { id: string | null }) {
  if (!id) return null;
  return (
    <a
      href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`}
      target="_blank"
      rel="noopener noreferrer"
      className="chip"
      style={{ textDecoration: "none" }}
    >
      {id}
    </a>
  );
}

// -- Time helpers -------------------------------------------------------
export function parseUtc(v: string | null | undefined): Date | null {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d;
}
export function formatTime(v: string | null | undefined): string {
  const d = parseUtc(v);
  return d ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
}
export function formatDateTime(v: string | null | undefined): string {
  const d = parseUtc(v);
  return d ? d.toLocaleString() : "—";
}
export function formatRelative(v: string | null | undefined): string {
  const d = parseUtc(v);
  if (!d) return "—";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
