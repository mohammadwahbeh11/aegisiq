/**
 * frontend/src/theme.ts — light / dark theme with system-preference default.
 *
 * Three states: "light", "dark", "system". "system" follows the OS
 * preference and re-renders when the user flips it in their OS.
 *
 * Applies by stamping data-theme on <html>, which the CSS reads. Never
 * touches the DOM's individual element styles — the switch is a single
 * attribute change; every color comes from a --var in index.css.
 *
 * Choice is persisted in localStorage so a fresh tab respects it.
 */

export type ThemePreference = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

const STORAGE_KEY = "aegisiq_theme";
let listeners: Array<(t: ResolvedTheme) => void> = [];

function systemPref(): ResolvedTheme {
  if (typeof window === "undefined" || !window.matchMedia) return "dark";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function getPreference(): ThemePreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    // ignore; treat as system
  }
  return "system";
}

export function resolveTheme(pref: ThemePreference = getPreference()): ResolvedTheme {
  return pref === "system" ? systemPref() : pref;
}

export function applyTheme(pref: ThemePreference = getPreference()) {
  const resolved = resolveTheme(pref);
  document.documentElement.setAttribute("data-theme", resolved);
  document.documentElement.style.colorScheme = resolved;
  listeners.forEach((cb) => cb(resolved));
}

export function setPreference(pref: ThemePreference) {
  try {
    localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    // ignore
  }
  applyTheme(pref);
}

/** Notified when the RESOLVED theme changes (either user or OS). */
export function onThemeChange(cb: (t: ResolvedTheme) => void): () => void {
  listeners.push(cb);
  return () => {
    listeners = listeners.filter((x) => x !== cb);
  };
}

// Wire up OS-preference listener once, at module load, so "system" mode
// updates automatically.
if (typeof window !== "undefined" && window.matchMedia) {
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  const handler = () => {
    if (getPreference() === "system") applyTheme("system");
  };
  if (mq.addEventListener) {
    mq.addEventListener("change", handler);
  } else if ((mq as unknown as { addListener: (h: () => void) => void }).addListener) {
    (mq as unknown as { addListener: (h: () => void) => void }).addListener(handler);
  }
}
