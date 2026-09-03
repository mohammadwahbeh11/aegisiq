import { useEffect, useMemo, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useAuth } from "../context/AuthContext";
import { useLive } from "../context/LiveContext";
import { installShortcuts, SHORTCUT_HELP } from "../keyboard";
import { idleSecondsRemaining } from "../security";
import {
  applyTheme, getPreference, resolveTheme, setPreference, ThemePreference,
} from "../theme";
import ToastRail from "./ToastRail";

// v2.1 — nav grouped into three sections. The section headers make
// the paid tier visible at first glance and separate day-to-day SOC
// pages from administrative + premium ones.
interface NavItem {
  to: string;
  label: string;
  glyph: string;
  pro?: boolean;
  adminOnly?: boolean;
}

interface NavSection {
  label: string;
  accent?: "pro" | "admin";
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    label: "Platform",
    items: [
      { to: "/dashboard", label: "Dashboard",         glyph: "▤" },
      { to: "/alerts",    label: "Alerts",            glyph: "!" },
      { to: "/logs",      label: "Log search",        glyph: "≡" },
      { to: "/rules",     label: "Detection rules",   glyph: "◈" },
      { to: "/endpoints", label: "Endpoints",         glyph: "▣" },
      { to: "/response",  label: "Automated response",glyph: "⚙" },
    ],
  },
  {
    label: "Premium",
    accent: "pro",
    items: [
      { to: "/analysis",  label: "Log analysis",      glyph: "◐", pro: true },
    ],
  },
  {
    label: "Admin",
    accent: "admin",
    items: [
      { to: "/security",   label: "Two-factor auth",   glyph: "⚷" },
      { to: "/audit",      label: "Audit log",         glyph: "⛨" },
      { to: "/retention",  label: "Retention",         glyph: "⌫", adminOnly: true },
      { to: "/simulation", label: "Simulation lab",    glyph: "▶", adminOnly: true },
    ],
  },
];

const CONNECTION_LABEL: Record<string, string> = {
  connecting: "Connecting…",
  live: "Live",
  reconnecting: "Reconnecting…",
  offline: "Offline",
};

const THEME_LABEL: Record<ThemePreference, string> = {
  light: "Light",
  dark:  "Dark",
  system:"System",
};

function ShortcutsHelpModal({ onClose }: { onClose: () => void }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <header className="modal-header">
          <h3>Keyboard shortcuts</h3>
          <button className="modal-close" onClick={onClose} aria-label="Close">×</button>
        </header>
        <div className="modal-body">
          <p className="muted" style={{ marginBottom: "0.75rem" }}>
            Press <kbd>?</kbd> at any time to bring this back up. Shortcuts are
            ignored while you are typing in a form field.
          </p>
          <table className="shortcut-table">
            <tbody>
              {SHORTCUT_HELP.map((s) => (
                <tr key={s.keys}>
                  <td><kbd>{s.keys}</kbd></td>
                  <td>{s.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default function Layout() {
  const { user, logout } = useAuth();
  const { connection, eventCount, liveAlerts } = useLive();
  const navigate = useNavigate();

  const [now, setNow] = useState(() => new Date());
  const [themePref, setThemePref] = useState<ThemePreference>(getPreference);
  const [showHelp, setShowHelp] = useState(false);
  const [idle, setIdle] = useState(() => idleSecondsRemaining());

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(new Date());
      setIdle(idleSecondsRemaining());
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => installShortcuts({
    onNavigate: navigate,
    onFocusSearch: () => {
      const el = document.querySelector<HTMLInputElement>(
        'input[placeholder*="Search"], input[type="search"], input[placeholder*="search"]'
      );
      el?.focus();
    },
    onShowHelp: () => setShowHelp(true),
    onCloseModal: () => setShowHelp(false),
  }), [navigate]);

  const isAdmin = user?.role === "administrator";
  const newAlertCount = liveAlerts.filter((alert) => alert.status === "new").length;

  const idleLabel = useMemo(() => {
    if (idle > 120) return null;
    const mm = Math.floor(idle / 60);
    const ss = String(idle % 60).padStart(2, "0");
    return `Idle logout in ${mm}:${ss}`;
  }, [idle]);

  function cycleTheme() {
    const order: ThemePreference[] = ["system", "light", "dark"];
    const next = order[(order.indexOf(themePref) + 1) % order.length];
    setPreference(next);
    setThemePref(next);
    applyTheme(next);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand">
            <span className="brand-mark">◆</span>
            AegisIQ
          </div>
          <div className="brand-sub">Intelligent Shield · SIEM &amp; SOAR</div>
        </div>

        <nav>
          {NAV_SECTIONS.map((section) => {
            const visible = section.items.filter((it) => !it.adminOnly || isAdmin);
            if (visible.length === 0) return null;
            return (
              <div key={section.label} className={`nav-section nav-section-${section.accent ?? "default"}`}>
                <div className="nav-section-label">
                  {section.label}
                  {section.accent === "pro" && <span className="section-badge pro">PRO</span>}
                </div>
                {visible.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                  >
                    <span className="nav-glyph" aria-hidden="true">{item.glyph}</span>
                    <span className="nav-label">{item.label}</span>
                    {item.pro && <span className="nav-pro">PRO</span>}
                    {item.to === "/alerts" && newAlertCount > 0 && (
                      <span className="nav-count">{newAlertCount}</span>
                    )}
                  </NavLink>
                ))}
              </div>
            );
          })}
        </nav>

        <div className="user-footer">
          <div className="user-name">{user?.username}</div>
          <div className="role">{user?.role?.replace("_", " ")}</div>
          <div className="sidebar-actions">
            <button
              className="icon-btn"
              title={`Theme: ${THEME_LABEL[themePref]} — click to cycle`}
              onClick={cycleTheme}
            >
              {resolveTheme(themePref) === "dark" ? "☾" : "☀"} <span>{THEME_LABEL[themePref]}</span>
            </button>
            <button
              className="icon-btn"
              title="Keyboard shortcuts (?)"
              onClick={() => setShowHelp(true)}
            >
              ⌘ <span>Shortcuts</span>
            </button>
          </div>
          <button className="logout-btn" onClick={logout}>
            Sign out
          </button>
        </div>
      </aside>

      <div className="main-column">
        <header className="top-status-bar">
          <div className={`connection-pill ${connection}`}>
            <span className="dot" aria-hidden="true" />
            {CONNECTION_LABEL[connection] ?? connection}
            {connection === "live" && (
              <span className="pill-detail">{eventCount} events this session</span>
            )}
          </div>
          {idleLabel && (
            <div className="idle-warning" title="Move the mouse or press a key to stay signed in">
              ⏱ {idleLabel}
            </div>
          )}
          <div className="clock">{now.toLocaleString()}</div>
        </header>

        <main className="main-content">
          <Outlet />
        </main>
      </div>

      <ToastRail />
      {showHelp && <ShortcutsHelpModal onClose={() => setShowHelp(false)} />}
    </div>
  );
}
