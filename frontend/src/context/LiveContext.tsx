import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  ReactNode,
} from "react";

import { Alert, LogEvent, SoarAction, fetchAlerts, getToken, streamUrl } from "../api/client";
import { useAuth } from "./AuthContext";

/**
 * One WebSocket for the whole console.
 *
 * Every page that wants live data subscribes to this context instead of
 * opening its own socket: five pages each opening a connection would mean
 * the backend broadcasting every event five times to the same browser,
 * and the alert toast firing five times per alert.
 *
 * Reconnection uses exponential backoff capped at 15s. A dropped socket
 * is expected (laptop sleeps, backend restarts during a demo), so the
 * console has to recover on its own rather than needing a page reload --
 * and it has to SAY when it is disconnected, because a live dashboard
 * that has silently stopped updating is worse than one that admits it.
 */

export type ConnectionState = "connecting" | "live" | "reconnecting" | "offline";

interface StreamMessage {
  seq?: number;
  type: string;
  at?: string;
  data: unknown;
}

interface LiveContextValue {
  connection: ConnectionState;
  /** Newest first, capped -- the live feed, not a history store. */
  liveLogs: LogEvent[];
  liveAlerts: Alert[];
  liveSoarActions: SoarAction[];
  /** Alerts that arrived and have not been dismissed from the toast rail. */
  toasts: Alert[];
  dismissToast: (id: number) => void;
  eventCount: number;
  lastEventAt: Date | null;
  /** Register a callback fired for every alert as it arrives. */
  onAlert: (handler: (alert: Alert) => void) => () => void;
}

const LiveContext = createContext<LiveContextValue | undefined>(undefined);

// Buffer caps. The live feed is a window on the last few minutes; the
// REST endpoints remain the source of truth for real history, so there
// is no reason to let these grow without bound in a long-running tab.
const MAX_LIVE_LOGS = 100;
const MAX_LIVE_ALERTS = 50;
const MAX_LIVE_SOAR = 50;
const MAX_TOASTS = 4;
const TOAST_DISMISS_MS = 12000;

const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 15000;

// Polling fallback. Even when the WebSocket is "live", the browser can
// silently miss frames (proxy reset, laptop wake, tab throttled in the
// background). Polling /api/alerts every N seconds catches anything the
// socket dropped and guarantees the console never falls behind reality
// -- if the WS is working, this call is a cheap no-op that finds no new
// alerts; if the WS is broken, the console still updates on its own.
const POLL_INTERVAL_MS = 8000;

// Ask the browser for permission to show desktop notifications the first
// time an authenticated session comes up. A missing permission is not an
// error -- the toast rail still fires -- but a granted permission means
// the analyst gets pinged when a CRITICAL alert lands and the browser
// tab is in the background.
async function requestNotifyPermission(): Promise<void> {
  if (typeof Notification === "undefined") return;
  if (Notification.permission === "default") {
    try {
      await Notification.requestPermission();
    } catch {
      // Some browsers throw on non-user-gesture calls; swallowing is fine.
    }
  }
}

function fireDesktopNotification(alert: Alert): void {
  if (typeof Notification === "undefined") return;
  if (Notification.permission !== "granted") return;
  // Skip low/medium — analysts should not be interrupted for those.
  if (alert.severity !== "critical" && alert.severity !== "high") return;
  try {
    const title = `${alert.severity.toUpperCase()} · ${alert.rule_name ?? "Alert"}`;
    const notification = new Notification(title, {
      body: alert.description,
      tag: `siem-alert-${alert.id}`,
      // requireInteraction on CRITICAL so it does not auto-dismiss
      requireInteraction: alert.severity === "critical",
    });
    notification.onclick = () => {
      window.focus();
      window.location.hash = `#/alerts/${alert.id}`;
      notification.close();
    };
  } catch {
    // Notifications throw on some restricted contexts (file://, etc.)
  }
}

function prepend<T>(list: T[], item: T, cap: number): T[] {
  return [item, ...list].slice(0, cap);
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const { isAuthenticated, logout } = useAuth();

  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [liveLogs, setLiveLogs] = useState<LogEvent[]>([]);
  const [liveAlerts, setLiveAlerts] = useState<Alert[]>([]);
  const [liveSoarActions, setLiveSoarActions] = useState<SoarAction[]>([]);
  const [toasts, setToasts] = useState<Alert[]>([]);
  const [eventCount, setEventCount] = useState(0);
  const [lastEventAt, setLastEventAt] = useState<Date | null>(null);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);
  const attemptRef = useRef(0);
  const alertHandlersRef = useRef(new Set<(alert: Alert) => void>());
  // Guards against a reconnect being scheduled after the provider has
  // unmounted or the user has signed out.
  const activeRef = useRef(true);

  const dismissToast = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const onAlert = useCallback((handler: (alert: Alert) => void) => {
    alertHandlersRef.current.add(handler);
    return () => {
      alertHandlersRef.current.delete(handler);
    };
  }, []);

  // Tracks alert ids that were already surfaced (via WS or via polling)
  // so the polling loop doesn't re-toast the same alert every 8 seconds.
  const seenAlertIdsRef = useRef<Set<number>>(new Set());

  const handleAlert = useCallback((alert: Alert) => {
    setLiveAlerts((current) => {
      // A status change re-broadcasts an alert that may already be in the
      // feed; replace it in place rather than showing it twice.
      const without = current.filter((item) => item.id !== alert.id);
      return [alert, ...without].slice(0, MAX_LIVE_ALERTS);
    });

    const isFirstTimeSeen = !seenAlertIdsRef.current.has(alert.id);
    seenAlertIdsRef.current.add(alert.id);

    // Only NEW alerts pop a toast, and only the first time we see them.
    // A toast for "an analyst marked this resolved" would be noise, and
    // re-toasting the alert you just triaged is actively confusing.
    if (alert.status === "new" && isFirstTimeSeen) {
      setToasts((current) => {
        if (current.some((toast) => toast.id === alert.id)) return current;
        return [alert, ...current].slice(0, MAX_TOASTS);
      });
      window.setTimeout(() => dismissToast(alert.id), TOAST_DISMISS_MS);
      // Desktop notification for HIGH/CRITICAL so the analyst is pinged
      // even when the console tab is in the background.
      fireDesktopNotification(alert);
    }

    alertHandlersRef.current.forEach((handler) => handler(alert));
  }, [dismissToast]);

  const handleMessage = useCallback(
    (message: StreamMessage) => {
      switch (message.type) {
        case "hello": {
          const data = message.data as { replay?: StreamMessage[] };
          // Replay oldest-first so the feed ends up in the right order.
          (data.replay ?? []).forEach((replayed) => handleMessage(replayed));
          break;
        }
        case "log":
          setLiveLogs((current) => prepend(current, message.data as LogEvent, MAX_LIVE_LOGS));
          setEventCount((count) => count + 1);
          setLastEventAt(new Date());
          break;
        case "alert":
          handleAlert(message.data as Alert);
          setLastEventAt(new Date());
          break;
        case "soar_action":
          setLiveSoarActions((current) =>
            prepend(current, message.data as SoarAction, MAX_LIVE_SOAR)
          );
          setLastEventAt(new Date());
          break;
        default:
          break; // "pong" and anything a future backend adds
      }
    },
    [handleAlert]
  );

  const connect = useCallback(() => {
    if (!activeRef.current) return;

    const token = getToken();
    if (!token) {
      setConnection("offline");
      return;
    }

    setConnection(attemptRef.current === 0 ? "connecting" : "reconnecting");

    const socket = new WebSocket(streamUrl(token));
    socketRef.current = socket;

    socket.onopen = () => {
      attemptRef.current = 0;
      setConnection("live");
    };

    socket.onmessage = (event) => {
      try {
        handleMessage(JSON.parse(event.data) as StreamMessage);
      } catch {
        // A malformed frame must not kill the connection; skip it.
      }
    };

    socket.onclose = (event) => {
      socketRef.current = null;
      if (!activeRef.current) return;

      // 1008 is the policy-violation code the backend uses for an
      // invalid or expired token (see app/api/routes/stream.py).
      // Reconnecting with the same dead token would loop forever, so the
      // honest response is to end the session and let the user sign in.
      if (event.code === 1008) {
        setConnection("offline");
        logout();
        return;
      }

      setConnection("reconnecting");
      const delay = Math.min(RECONNECT_BASE_MS * 2 ** attemptRef.current, RECONNECT_MAX_MS);
      attemptRef.current += 1;
      reconnectTimerRef.current = window.setTimeout(connect, delay);
    };

    socket.onerror = () => {
      // onclose always follows; the reconnect is scheduled there so the
      // backoff is not advanced twice for one failure.
      socket.close();
    };
  }, [handleMessage, logout]);

  useEffect(() => {
    if (!isAuthenticated) {
      setConnection("offline");
      return;
    }

    activeRef.current = true;
    attemptRef.current = 0;
    connect();
    void requestNotifyPermission();

    return () => {
      activeRef.current = false;
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [isAuthenticated, connect]);

  // Polling fallback. Runs alongside the WebSocket so a broken socket
  // doesn't mean a broken console -- if the WS is delivering fine,
  // handleAlert's dedup by id makes each poll a cheap no-op. This is
  // the "why don't I see the alert until I refresh?" fix: even if the
  // WS never lands a frame, the browser catches up on its own within
  // POLL_INTERVAL_MS. On the first poll we seed `seenAlertIdsRef` with
  // whatever the API already has, so historical alerts don't all pop
  // as toasts the moment the console loads.
  const primedRef = useRef(false);
  useEffect(() => {
    if (!isAuthenticated) return;
    let cancelled = false;

    const pollOnce = async () => {
      try {
        const data = await fetchAlerts({ limit: 25 });
        if (cancelled) return;
        if (!primedRef.current) {
          // First poll after login/reload: everything currently in the
          // API is "already seen" so we don't blast the analyst with
          // toasts for historical alerts.
          data.items.forEach((a) => seenAlertIdsRef.current.add(a.id));
          primedRef.current = true;
          // Still populate the live feed so the pages have data even
          // before the first WS frame arrives.
          setLiveAlerts((current) => {
            const known = new Set(current.map((a) => a.id));
            const additions = data.items.filter((a) => !known.has(a.id));
            return [...additions, ...current].slice(0, MAX_LIVE_ALERTS);
          });
          return;
        }
        // Subsequent polls: any alert we haven't seen -> route through
        // handleAlert so it gets a toast, a notification and shows up in
        // liveAlerts, exactly like a WS-delivered one.
        for (const alert of data.items) {
          if (!seenAlertIdsRef.current.has(alert.id)) {
            handleAlert(alert);
            setLastEventAt(new Date());
          }
        }
      } catch {
        // Poll failed (server restart etc). Ignore; the next tick retries.
      }
    };

    // Prime immediately, then on the interval.
    void pollOnce();
    const timer = window.setInterval(pollOnce, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [isAuthenticated, handleAlert]);

  const value = useMemo<LiveContextValue>(
    () => ({
      connection,
      liveLogs,
      liveAlerts,
      liveSoarActions,
      toasts,
      dismissToast,
      eventCount,
      lastEventAt,
      onAlert,
    }),
    [connection, liveLogs, liveAlerts, liveSoarActions, toasts, dismissToast, eventCount, lastEventAt, onAlert]
  );

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveContextValue {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive must be used within a LiveProvider");
  return ctx;
}
