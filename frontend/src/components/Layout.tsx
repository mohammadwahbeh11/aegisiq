/**
 * Layout v3.0 — the professional shell that v2.9 was missing.
 *
 * Adds what a Panther/Vanta/Linear-quality console actually has:
 *   - Sidebar with real SVG icons per nav item (not monospace glyphs)
 *   - Top bar with search shortcut (Cmd+K), notifications bell,
 *     theme toggle, and a user avatar dropdown
 *   - Command palette (Cmd+K anywhere) with fuzzy navigation
 *   - Notification dropdown showing recent alerts
 *
 * Kept API-compatible with the earlier Layout: same useAuth / useLive
 * usage, same Outlet, same idle-timeout enforcement. Only presentation
 * changed — nothing on any other page needs to know.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useAuth } from "../context/AuthContext";
import { useLive } from "../context/LiveContext";
import { idleSecondsRemaining } from "../security";
import {
  applyTheme, getPreference, resolveTheme, setPreference, ThemePreference,
} from "../theme";
import ToastRail from "./ToastRail";
import {
  IconDashboard, IconAlerts, IconLogs, IconRules, IconEndpoints,
  IconResponse, IconAnalysis, IconIntelligence, IconRulesLibrary,
  IconPricing, IconMFA, IconAudit, IconRetention, IconSimulation,
  IconSearch, IconBell, IconMoon, IconSun, IconLogout,
} from "./Icons";

// ---------- Nav definition -------------------------------------------------

interface NavItem {
  to: string;
  label: string;
  Icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  pro?: boolean;
  adminOnly?: boolean;
}
interface NavSection { label: string; items: NavItem[]; }

const NAV_SECTIONS: NavSection[] = [
  {
    label: "Platform",
    items: [
      { to: "/dashboard", label: "Dashboard",          Icon: IconDashboard },
      { to: "/alerts",    label: "Alerts",             Icon: IconAlerts },
      { to: "/logs",      label: "Log search",         Icon: IconLogs },
      { to: "/rules",     label: "Detection rules",    Icon: IconRules },
      { to: "/endpoints", label: "Endpoints",          Icon: IconEndpoints },
      { to: "/response",  label: "Automated response", Icon: IconResponse },
    ],
  },
  {
    label: "Premium",
    items: [
      { to: "/analysis",      label: "Log analysis",   Icon: IconAnalysis,     pro: true },
      { to: "/intelligence",  label: "Intelligence",   Icon: IconIntelligence, pro: true },
      { to: "/rules-library", label: "Rules library",  Icon: IconRulesLibrary, pro: true },
      { to: "/pricing",       label: "Pricing",        Icon: IconPricing,      pro: true },
    ],
  },
  {
    label: "Admin",
    items: [
      { to: "/security",   label: "Two-factor auth", Icon: IconMFA },
      { to: "/audit",      label: "Audit log",       Icon: IconAudit },
      { to: "/retention",  label: "Retention",       Icon: IconRetention, adminOnly: true },
      { to: "/simulation", label: "Simulation lab",  Icon: IconSimulation, adminOnly: true },
    ],
  },
];

// ---------- Command Palette (Cmd+K / Ctrl+K) ------------------------------

function CommandPalette({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  const items = useMemo(() => {
    const all = NAV_SECTIONS.flatMap((s) => s.items.map((i) => ({ ...i, section: s.label })));
    if (!q.trim()) return all;
    const needle = q.toLowerCase();
    return all.filter((i) =>
      i.label.toLowerCase().includes(needle) ||
      i.section.toLowerCase().includes(needle)
    );
  }, [q]);

  useEffect(() => { setActive(0); }, [q]);

  function onKey(e: React.KeyboardEvent) {
    if (e.key === "Escape") { onClose(); return; }
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((i) => Math.min(items.length - 1, i + 1)); }
    if (e.key === "ArrowUp")   { e.preventDefault(); setActive((i) => Math.max(0, i - 1)); }
    if (e.key === "Enter" && items[active]) {
      onClose();
      navigate(items[active].to);
    }
  }

  return (
    <div className="cmdk-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="cmdk-panel" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="cmdk-input"
          placeholder="Search pages, actions…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={onKey}
          autoComplete="off"
          spellCheck={false}
        />
        <div className="cmdk-list">
          {items.length === 0 && <div className="cmdk-item" style={{ opacity: 0.6 }}>No matches</div>}
          {items.map((it, idx) => {
            const Icon = it.Icon;
            return (
              <div
                key={it.to}
                className={`cmdk-item ${idx === active ? "active" : ""}`}
                onMouseEnter={() => setActive(idx)}
                onClick={() => { onClose(); navigate(it.to); }}
              >
                <Icon />
                <span>{it.label}</span>
                <span className="muted" style={{ marginLeft: "auto", fontSize: 11 }}>{it.section}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ---------- Notifications dropdown ---------------------------------------

function NotificationsDropdown({
  alerts, onClose, onOpenAll,
}: {
  alerts: any[];
  onClose: () => void;
  onOpenAll: () => void;
}) {
  return (
    <>
      <div style={{ position: "fixed", inset: 0, zIndex: 40 }} onClick={onClose} />
      <div style={{
        position: "absolute", top: "calc(100% + 8px)", right: 0, zIndex: 41,
        width: 340,
        background: "rgba(16,20,31,0.98)",
        border: "1px solid rgba(255,255,255,0.10)",
        borderRadius: 12,
        boxShadow: "0 24px 60px -12px rgba(0,0,0,0.6)",
        overflow: "hidden",
      }}>
        <div style={{ padding: "12px 14px", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <strong style={{ fontSize: 13 }}>Recent alerts</strong>
          <span className="muted" style={{ fontSize: 11 }}>{alerts.length} unread</span>
        </div>
        <div style={{ maxHeight: 400, overflowY: "auto" }}>
          {alerts.length === 0 ? (
            <div className="muted" style={{ padding: 24, textAlign: "center", fontSize: 12 }}>
              No new alerts. All quiet.
            </div>
          ) : (
            alerts.slice(0, 6).map((a) => (
              <div key={a.id} style={{ padding: "10px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)", cursor: "pointer" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <span className={`severity-badge severity-${a.severity}`}>{a.severity}</span>
                  <span className="muted" style={{ fontSize: 10 }}>{a.created_at?.slice(11, 19) ?? ""}</span>
                </div>
                <div style={{ fontSize: 12.5 }}>{a.rule_name ?? "Alert"}</div>
              </div>
            ))
          )}
        </div>
        <button
          className="btn btn-ghost btn-sm"
          style={{ width: "100%", borderRadius: 0, borderTop: "1px solid rgba(255,255,255,0.06)" }}
          onClick={() => { onClose(); onOpenAll(); }}
        >
          View all alerts →
        </button>
      </div>
    </>
  );
}

// ---------- User menu dropdown -------------------------------------------

function UserMenu({ user, onLogout, onClose }: { user: any; onLogout: () => void; onClose: () => void }) {
  return (
    <>
      <div style={{ position: "fixed", inset: 0, zIndex: 40 }} onClick={onClose} />
      <div style={{
        position: "absolute", top: "calc(100% + 8px)", right: 0, zIndex: 41,
        width: 240,
        background: "rgba(16,20,31,0.98)",
        border: "1px solid rgba(255,255,255,0.10)",
        borderRadius: 12,
        boxShadow: "0 24px 60px -12px rgba(0,0,0,0.6)",
        overflow: "hidden",
      }}>
        <div style={{ padding: "12px 14px", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>{user?.username}</div>
          <div className="muted" style={{ fontSize: 11 }}>{user?.role}</div>
        </div>
        <button
          onClick={onLogout}
          className="btn btn-ghost"
          style={{
            width: "100%", borderRadius: 0, justifyContent: "flex-start",
            padding: "10px 14px", color: "var(--danger)",
          }}
        >
          <IconLogout /> <span>Sign out</span>
        </button>
      </div>
    </>
  );
}

// ---------- Layout -------------------------------------------------------

export default function Layout() {
  const { user, logout } = useAuth();
  const { connection, eventCount, liveAlerts } = useLive();
  const navigate = useNavigate();

  const [now, setNow] = useState(() => new Date());
  const [themePref, setThemePref] = useState<ThemePreference>(getPreference);
  const [idle, setIdle] = useState(() => idleSecondsRemaining());
  const [cmdkOpen, setCmdkOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false); // mobile

  // Tick clock + idle
  useEffect(() => {
    const t = window.setInterval(() => {
      setNow(new Date());
      setIdle(idleSecondsRemaining());
    }, 1000);
    return () => window.clearInterval(t);
  }, []);

  // Idle logout
  useEffect(() => {
    if (idle <= 0) logout();
  }, [idle, logout]);

  // Theme
  useEffect(() => { applyTheme(resolveTheme(themePref)); }, [themePref]);
  const cycleTheme = () => {
    const next: ThemePreference = themePref === "light" ? "dark" : themePref === "dark" ? "system" : "light";
    setPreference(next); setThemePref(next);
  };


  // Cmd+K / Ctrl+K to open command palette
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmdkOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const initial = (user?.username ?? "?").slice(0, 1).toUpperCase();
  const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
  const kbd = isMac ? "⌘" : "Ctrl";

  return (
    <div className="app-shell">
      {/* ---------- Sidebar ---------- */}
      <aside className={`sidebar ${sidebarOpen ? "open" : ""}`}>
        <div className="brand">AegisIQ</div>
        <div className="muted" style={{ fontSize: 10, padding: "0 10px 12px", letterSpacing: "0.1em", textTransform: "uppercase" }}>
          Intelligent Shield · SIEM &amp; SOAR
        </div>

        {NAV_SECTIONS.map((sec) => (
          <div key={sec.label} className="nav-section">
            <div className="nav-section-label">{sec.label}</div>
            {sec.items
              .filter((i) => !i.adminOnly || user?.role === "administrator")
              .map((it) => {
                const Icon = it.Icon;
                return (
                  <NavLink
                    key={it.to}
                    to={it.to}
                    className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                    onClick={() => setSidebarOpen(false)}
                  >
                    <Icon className="glyph" />
                    <span>{it.label}</span>
                    {it.pro && <span className="pro-tag">PRO</span>}
                  </NavLink>
                );
              })}
          </div>
        ))}

        <div style={{ marginTop: "auto", padding: "16px 10px 4px", fontSize: 10, color: "var(--ink-tertiary)" }}>
          <div>v3.2 · {new Date().getFullYear()} AegisIQ</div>
          <div>Idle logout in {Math.max(0, Math.floor(idle / 60))}m {Math.max(0, idle % 60)}s</div>
        </div>
      </aside>

      {/* ---------- Main ---------- */}
      <div>
        <header className="top-bar">
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button
              className="icon-btn"
              onClick={() => setSidebarOpen((v) => !v)}
              aria-label="Toggle sidebar"
              style={{ display: window.innerWidth <= 900 ? "inline-flex" : "none" }}
            >
              ☰
            </button>
            <span className={connection === "live" ? "live-indicator" : "chip"}>
              {connection === "live" ? "Live" : connection}
            </span>
            <span className="chip">{eventCount} events this session</span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <button className="search-shortcut" onClick={() => setCmdkOpen(true)}>
              <IconSearch />
              <span>Search…</span>
              <kbd>{kbd}K</kbd>
            </button>

            <div style={{ position: "relative" }}>
              <button
                className="icon-btn"
                onClick={() => setNotifOpen((v) => !v)}
                aria-label="Notifications"
                title="Recent alerts"
              >
                <IconBell />
                {liveAlerts.length > 0 && <span className="dot" />}
              </button>
              {notifOpen && (
                <NotificationsDropdown
                  alerts={liveAlerts}
                  onClose={() => setNotifOpen(false)}
                  onOpenAll={() => navigate("/alerts")}
                />
              )}
            </div>

            <button
              className="icon-btn"
              onClick={cycleTheme}
              aria-label={`Theme: ${themePref}`}
              title={`Theme: ${themePref} (click to change)`}
            >
              {themePref === "dark" ? <IconMoon /> : themePref === "light" ? <IconSun /> : <IconMoon />}
            </button>

            <span className="muted mono" style={{ fontSize: 12 }}>{now.toLocaleString()}</span>

            <div style={{ position: "relative" }}>
              <button
                className="user-avatar"
                onClick={() => setUserMenuOpen((v) => !v)}
                aria-label="User menu"
                title={user?.username ?? "Signed in"}
              >
                {initial}
              </button>
              {userMenuOpen && (
                <UserMenu
                  user={user}
                  onLogout={logout}
                  onClose={() => setUserMenuOpen(false)}
                />
              )}
            </div>
          </div>
        </header>

        <main className="main-content">
          <Outlet />
        </main>

        <ToastRail />
      </div>

      {cmdkOpen && <CommandPalette onClose={() => setCmdkOpen(false)} />}
    </div>
  );
}
