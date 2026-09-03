/**
 * frontend/src/keyboard.ts — global keyboard shortcuts.
 *
 * SOC analysts spend all day at the keyboard. A console that requires
 * a mouse to move between the alert queue and the log search is a
 * console that costs them dozens of context switches per shift.
 *
 * Grammar borrowed from GitHub / Linear / Superhuman:
 *   g d   Dashboard      g a   Alerts           g l   Log search
 *   g r   Rules          g e   Endpoints        g p   Response (Play)
 *   g t   Retention      g s   Simulation       g u   Audit
 *   /     Focus search   ?     Show help        Esc   Close modal
 *
 * "g" is a leader key — press g, then within 800 ms press the
 * destination letter. Prevents collisions with normal typing: any
 * shortcut is refused while an input is focused.
 */
import { NavigateFunction } from "react-router-dom";

const LEADER_TIMEOUT_MS = 800;

let awaitingLeader = false;
let leaderTimer: number | null = null;

function inTypingContext(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  if (target.isContentEditable) return true;
  return false;
}

const G_ROUTES: Record<string, string> = {
  d: "/dashboard",
  a: "/alerts",
  l: "/logs",
  r: "/rules",
  e: "/endpoints",
  p: "/response",
  t: "/retention",
  s: "/simulation",
  u: "/audit",
};

export interface KeyboardHandlers {
  onNavigate: NavigateFunction;
  onFocusSearch?: () => void;
  onShowHelp?: () => void;
  onCloseModal?: () => void;
}

export function installShortcuts(handlers: KeyboardHandlers): () => void {
  const handler = (e: KeyboardEvent) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;

    // Global shortcuts that ARE allowed to fire while typing:
    if (e.key === "Escape") {
      handlers.onCloseModal?.();
      return;
    }

    if (inTypingContext(e.target)) return;

    if (awaitingLeader) {
      const route = G_ROUTES[e.key.toLowerCase()];
      if (route) {
        e.preventDefault();
        handlers.onNavigate(route);
      }
      awaitingLeader = false;
      if (leaderTimer !== null) window.clearTimeout(leaderTimer);
      leaderTimer = null;
      return;
    }

    if (e.key === "g") {
      awaitingLeader = true;
      if (leaderTimer !== null) window.clearTimeout(leaderTimer);
      leaderTimer = window.setTimeout(() => { awaitingLeader = false; }, LEADER_TIMEOUT_MS);
      return;
    }

    if (e.key === "/") {
      e.preventDefault();
      handlers.onFocusSearch?.();
      return;
    }

    if (e.key === "?") {
      e.preventDefault();
      handlers.onShowHelp?.();
      return;
    }
  };

  window.addEventListener("keydown", handler);
  return () => {
    window.removeEventListener("keydown", handler);
    if (leaderTimer !== null) window.clearTimeout(leaderTimer);
  };
}

/** Static reference: keys → labels for the help modal. */
export const SHORTCUT_HELP: { keys: string; description: string }[] = [
  { keys: "g d", description: "Go to Dashboard" },
  { keys: "g a", description: "Go to Alerts" },
  { keys: "g l", description: "Go to Log search" },
  { keys: "g r", description: "Go to Rules" },
  { keys: "g e", description: "Go to Endpoints" },
  { keys: "g p", description: "Go to Response" },
  { keys: "g t", description: "Go to Retention" },
  { keys: "g s", description: "Go to Simulation" },
  { keys: "g u", description: "Go to Audit" },
  { keys: "/",   description: "Focus the search input on the current page" },
  { keys: "?",   description: "Show this shortcut list" },
  { keys: "Esc", description: "Close the open modal" },
];
