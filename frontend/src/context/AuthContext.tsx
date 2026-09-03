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
  clearToken, getToken, login as loginRequest, mfaVerify, setToken,
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
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const USER_KEY = "aegisiq_user";
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
    disarmSession();
    clearToken();
    try {
      localStorage.removeItem(USER_KEY);
    } catch {
      // ignore
    }
    setUser(null);
  }, [disarmSession]);

  const armForToken = useCallback((token: string) => {
    disarmSession();
    sessionCleanupRef.current = armSession(token, () => {
      // Idle timeout or JWT pre-expiry -> log out.
      logout();
    });
  }, [disarmSession, logout]);

  // On a page refresh, re-arm the watchers using the persisted token.
  useEffect(() => {
    const token = getToken();
    if (token && user) {
      armForToken(token);
    }
    return disarmSession;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Shared: persist a full token + user and arm the session watchers.
  const finalize = useCallback((response: LoginResponse) => {
    setToken(response.access_token);
    const authUser: AuthUser = { username: response.username, role: response.role };
    try {
      localStorage.setItem(USER_KEY, JSON.stringify(authUser));
    } catch {
      // ignore
    }
    setUser(authUser);
    armForToken(response.access_token);
  }, [armForToken]);

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
      value={{ user, isAuthenticated: !!user && !!getToken(), login, completeMfa, logout }}
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
