/**
 * frontend/src/context/AuthContext.tsx
 *
 * v2.0 changes:
 *   * on successful login, arm the client-side session watchers
 *     (idle timeout + JWT-expiry pre-warning) via security.armSession.
 *   * on logout (manual or automatic), disarm the watchers.
 *   * USER_KEY renamed to "aegisiq_user" (was "siem_user"). The old
 *     key is checked once and migrated so no analyst is logged out on
 *     upgrade.
 */
import { createContext, useCallback, useContext, useEffect, useRef, useState, ReactNode } from "react";

import {
  clearCsrfCookie, clearToken, getToken, hasCookieSession,
  login as loginRequest, logoutRequest, mfaVerify, setToken,
  LoginResponse,
} from "../api/client";
import { armSession } from "../security";

interface AuthUser {
  username: string;
  role: "administrator" | "security_analyst";
}

// What AuthContext.login returns so the Login page knows whether to show
// the second-factor step.
export interface LoginOutcome {
  done: boolean;              // true => fully logged in
  mfaRequired: boolean;       // true => must call completeMfa next
  enrollmentRequired: boolean;// true => user must enrol MFA first
  mfaToken: string | null;    // pass back to completeMfa
}

interface AuthContextValue {
  user: AuthUser | null;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<LoginOutcome>;
  completeMfa: (mfaToken: string, code: string) => Promise<void>;
  /** v3.2 — adopt a session minted by /api/mfa/confirm at the end of a
   *  first-run enrolment. Both factors were just proven there, so the
   *  console signs the user in rather than returning them to the form. */
  adoptSession: (response: LoginResponse) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const USER_KEY = "aegisiq_user";
// Used only when the server did not report expires_in (an older backend).
const SESSION_FALLBACK_SECONDS = 60 * 60;
const LEGACY_USER_KEY = "siem_user";  // migrated once on load

function loadStoredUser(): AuthUser | null {
  try {
    // Migrate from the v1 storage key if present.
    if (!localStorage.getItem(USER_KEY)) {
      const legacy = localStorage.getItem(LEGACY_USER_KEY);
      if (legacy) {
        localStorage.setItem(USER_KEY, legacy);
        localStorage.removeItem(LEGACY_USER_KEY);
      }
    }
    const raw = localStorage.getItem(USER_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(loadStoredUser());
  const sessionCleanupRef = useRef<(() => void) | null>(null);

  const disarmSession = useCallback(() => {
    if (sessionCleanupRef.current) {
      sessionCleanupRef.current();
      sessionCleanupRef.current = null;
    }
  }, []);

  const logout = useCallback(() => {
    // v3.2 — sign out on the SERVER too. Clearing local state only ever
    // ended the session in this tab: the token stayed valid for the rest
    // of its lifetime, so "log out" did not evict anyone holding a copy.
    // POST /api/auth/logout clears the httpOnly cookie and bumps
    // token_version, which revokes every token issued to this account.
    void logoutRequest();
    disarmSession();
    clearToken();
    clearCsrfCookie();
    try {
      localStorage.removeItem(USER_KEY);
    } catch {
      // ignore
    }
    setUser(null);
  }, [disarmSession]);

  const armForToken = useCallback((token: string | null, expiresInSeconds?: number) => {
    disarmSession();
    const expiresAt = expiresInSeconds
      ? Math.floor(Date.now() / 1000) + expiresInSeconds
      : undefined;
    sessionCleanupRef.current = armSession(token, () => {
      // Idle timeout or session pre-expiry -> log out.
      logout();
    }, expiresAt);
  }, [disarmSession, logout]);

  // On a page refresh, re-arm the watchers using the persisted token.
  useEffect(() => {
    const token = getToken();
    if (user && (token || hasCookieSession())) {
      // After a refresh the cookie session's exact expiry is not known to
      // the page (it is inside the httpOnly cookie). The idle watcher
      // still arms; the server's own expiry, surfaced as a 401 by the API
      // client, ends the session cleanly if it lapses first.
      armForToken(token, token ? undefined : SESSION_FALLBACK_SECONDS);
    }
    return disarmSession;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Shared: persist a full token + user and arm the session watchers.
  const finalize = useCallback((response: LoginResponse) => {
    // v3.2 — when the server issued an httpOnly session cookie, the token
    // is NOT written to localStorage: keeping a copy there would hand it
    // straight back to any XSS and undo the point of the cookie. The
    // bearer path is kept for deployments with AUTH_COOKIE_ENABLED=false.
    const cookieSession = hasCookieSession();
    if (!cookieSession) {
      setToken(response.access_token);
    } else {
      clearToken();
    }
    const authUser: AuthUser = { username: response.username, role: response.role };
    try {
      localStorage.setItem(USER_KEY, JSON.stringify(authUser));
    } catch {
      // ignore
    }
    setUser(authUser);
    armForToken(
      cookieSession ? null : response.access_token,
      response.expires_in ?? SESSION_FALLBACK_SECONDS,
    );
  }, [armForToken]);

  const adoptSession = useCallback((response: LoginResponse) => {
    finalize(response);
  }, [finalize]);

  async function login(username: string, password: string): Promise<LoginOutcome> {
    const result = await loginRequest(username, password);
    // No second factor needed → we already have a full token.
    if (result.access_token && result.username && result.role) {
      finalize({
        access_token: result.access_token,
        token_type: result.token_type,
        username: result.username,
        role: result.role,
      });
      return { done: true, mfaRequired: false, enrollmentRequired: false, mfaToken: null };
    }
    // MFA challenge (or enrolment) required.
    return {
      done: false,
      mfaRequired: !!result.mfa_required,
      enrollmentRequired: !!result.enrollment_required,
      mfaToken: result.mfa_token,
    };
  }

  async function completeMfa(mfaToken: string, code: string): Promise<void> {
    const response = await mfaVerify(mfaToken, code);
    finalize(response);
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user && (!!getToken() || hasCookieSession()),
        login, completeMfa, logout, adoptSession,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
