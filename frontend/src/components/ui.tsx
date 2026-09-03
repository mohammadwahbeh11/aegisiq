import { ReactNode } from "react";

import { AlertStatus, Severity } from "../api/client";

/** Small presentational pieces shared by every page. Kept in one file
 *  because each is a handful of lines -- one file per badge would be
 *  more folders to navigate, not more clarity. */

export function Panel({
  title,
  actions,
  children,
  className,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className ?? ""}`}>
      {(title || actions) && (
        <header className="panel-header">
          {title && <h3>{title}</h3>}
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge severity-${severity}`}>{severity}</span>;
}

const STATUS_LABELS: Record<AlertStatus, string> = {
  new: "New",
  investigating: "Investigating",
  resolved: "Resolved",
  false_positive: "False positive",
};

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`badge status-${status}`}>{STATUS_LABELS[status]}</span>;
}

export function MitreBadge({ id }: { id: string | null }) {
  if (!id) return <span className="muted">—</span>;
  return <span className="badge mitre">{id}</span>;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>;
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="loading-state">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function ErrorBanner({ children }: { children: ReactNode }) {
  return <div className="error-banner">{children}</div>;
}

/**
 * Timestamps arrive from the API as naive UTC ISO strings (the backend
 * stores UTC). Appending "Z" when there is no explicit offset is what
 * stops the browser from re-interpreting them as local time and showing
 * events three hours in the future.
 */
export function parseUtc(value: string | null | undefined): Date | null {
  if (!value) return null;
  const normalized = /([zZ]|[+-]\d{2}:?\d{2})$/.test(value) ? value : `${value}Z`;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export function formatTime(value: string | null | undefined): string {
  const date = parseUtc(value);
  return date ? date.toLocaleTimeString() : "—";
}

export function formatDateTime(value: string | null | undefined): string {
  const date = parseUtc(value);
  return date ? date.toLocaleString() : "—";
}

export function formatRelative(value: string | null | undefined): string {
  const date = parseUtc(value);
  if (!date) return "—";
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
