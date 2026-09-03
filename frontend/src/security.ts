/**
 * frontend/src/security.ts — client-side security controls.
 *
 * The server enforces authentication with a JWT; the client controls
 * that already-authenticated humans do not walk away from an open
 * console. Three concerns handled here:
 *
 *   1. IDLE TIMEOUT: on N minutes of no input, log out and redirect
 *      to /login. Cross-tab: any user activity in any tab resets the
 *      timer everywhere via a broadcast on localStorage.
 *
 *   2. VISIBILITY: when the tab is hidden, we do NOT count that as
 *      idle time — a backgrounded tab is not a walked-away user. But
 *      we DO refresh the countdown when the tab comes back so the
 *      analyst always sees a truthful "N minutes left" figure.
 *
 *   3. TOKEN EXPIRY: JWTs carry an `exp` claim. Once we know that
 *      timestamp, we schedule a proactive logout at 30 s BEFORE it,
 *      so a request that fires exactly at expiry does not fail with a
 *      raw 401 the user has to reason about.
 *
 * All three controls fail-open: if localStorage is denied, if the JWT
 * can't be decoded, if setTimeout is throttled by a browser, the
 * regular server-side JWT expiration still kicks in eventually. The
 * client is a UX improvement, not the security boundary.
 */

const IDLE_MS_DEFAULT = 15 * 60 * 1000;    // 15 min — matches backend IDLE_TIMEOUT_SECONDS
const PRE_EXPIRY_MS = 30 * 1000;            // log out 30 s before token expires
const ACTIVITY_KEY = "aegisiq_last_activity";  // shared across tabs
const ACTIVITY_THROTTLE_MS = 5000;          // don't spam localStorage on every mousemove

let idleTimer: number | null = null;
let expiryTimer: number | null = null;
let lastLocalActivity = Date.now();
let idleCallback: (() => void) | null = null;

/** Parse a JWT payload without validation — for reading exp only. */
function decodeJwt(token: string): { exp?: number; sub?: string } | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

function markActivity() {
  const now = Date.now();
  if (now - lastLocalActivity < ACTIVITY_THROTTLE_MS) return;
  lastLocalActivity = now;
  try {
    localStorage.setItem(ACTIVITY_KEY, String(now));
  } catch {
    // Private-mode fallback: local timer still works, cross-tab sync
    // is degraded. That is acceptable.
  }
  scheduleIdleCheck();
}

function scheduleIdleCheck() {
  if (idleTimer !== null) window.clearTimeout(idleTimer);
  idleTimer = window.setTimeout(() => {
    // Recheck against the shared localStorage value in case another
    // tab moved recently — never log out because THIS tab is quiet.
    const shared = Number(localStorage.getItem(ACTIVITY_KEY) || "0");
    const last = Math.max(lastLocalActivity, shared);
    const idleFor = Date.now() - last;
    if (idleFor >= IDLE_MS_DEFAULT) {
      idleCallback?.();
    } else {
      scheduleIdleCheck();
    }
  }, Math.max(1000, IDLE_MS_DEFAULT - (Date.now() - lastLocalActivity)));
}

/**
 * Install idle + expiry watchers. Returns a cleanup function.
 * Call once on login; call the returned function on logout.
 */
export function armSession(token: string, onExpire: () => void): () => void {
  idleCallback = onExpire;
  lastLocalActivity = Date.now();
  markActivity();

  const events: (keyof DocumentEventMap)[] = [
    "mousemove", "keydown", "click", "scroll", "touchstart",
  ];
  const handler = () => markActivity();
  events.forEach((e) => document.addEventListener(e, handler, { passive: true }));

  // Cross-tab: another tab writing the activity key resets our clock.
  const storageHandler = (e: StorageEvent) => {
    if (e.key === ACTIVITY_KEY && e.newValue) {
      lastLocalActivity = Number(e.newValue);
    }
  };
  window.addEventListener("storage", storageHandler);

  // When the tab becomes visible again, don't punish it for having
  // been backgrounded — reset the local counter.
  const visHandler = () => {
    if (document.visibilityState === "visible") markActivity();
  };
  document.addEventListener("visibilitychange", visHandler);

  // Proactive logout 30 s before JWT exp.
  const claims = decodeJwt(token);
  if (claims?.exp) {
    const msUntil = claims.exp * 1000 - Date.now() - PRE_EXPIRY_MS;
    if (msUntil > 0) {
      expiryTimer = window.setTimeout(() => onExpire(), msUntil);
    } else {
      // Token is essentially expired already.
      window.setTimeout(() => onExpire(), 0);
    }
  }

  scheduleIdleCheck();

  return () => {
    events.forEach((e) => document.removeEventListener(e, handler));
    window.removeEventListener("storage", storageHandler);
    document.removeEventListener("visibilitychange", visHandler);
    if (idleTimer !== null) window.clearTimeout(idleTimer);
    if (expiryTimer !== null) window.clearTimeout(expiryTimer);
    idleTimer = null;
    expiryTimer = null;
    idleCallback = null;
  };
}

/** Seconds until the currently-armed idle timer fires. UI display. */
export function idleSecondsRemaining(): number {
  const shared = Number(localStorage.getItem(ACTIVITY_KEY) || String(lastLocalActivity));
  const last = Math.max(lastLocalActivity, shared);
  const remaining = Math.floor((IDLE_MS_DEFAULT - (Date.now() - last)) / 1000);
  return Math.max(0, remaining);
}
