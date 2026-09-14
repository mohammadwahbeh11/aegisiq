import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  fetchHealth, mfaConfirmWithChallenge, mfaEnrollWithChallenge,
  MfaConfirmResponse, MfaEnrollResponse,
} from "../api/client";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const { login, completeMfa, adoptSession } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [backend, setBackend] = useState<"checking" | "up" | "down">("checking");

  // v2.3 — second-factor step state.
  const [stage, setStage] = useState<"credentials" | "mfa" | "enroll">("credentials");
  // v3.2 — first-run enrolment, driven by the login challenge token.
  const [enrollment, setEnrollment] = useState<MfaEnrollResponse | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [enrolledSession, setEnrolledSession] = useState<MfaConfirmResponse | null>(null);

  // v3.2 — the API client redirects here with ?reason=session_expired when
  // a token stops being accepted mid-session (expiry, a password change
  // that revoked it, or a disabled/locked account). Saying so is the
  // difference between "you were signed out" and "the console is broken".
  const [notice, setNotice] = useState<string | null>(() => {
    try {
      const reason = new URLSearchParams(window.location.search).get("reason");
      if (reason === "session_expired") {
        return "Your session ended — sign in again to continue.";
      }
    } catch {
      /* no-op */
    }
    return null;
  });
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [enrollmentNeeded, setEnrollmentNeeded] = useState(false);
  const [code, setCode] = useState("");

  useEffect(() => {
    // Render's free tier spins the backend down after ~15 min of idle;
    // waking it takes 30-60 s during which Render serves its own loading
    // interstitial. Retry the health check with back-off so the login
    // page recovers gracefully from cold start instead of getting stuck
    // on "Checking backend..." or falsely showing "down". We only mark
    // the backend "up" once /health returns real JSON with api === "ok".
    let cancelled = false;
    const MAX_TRIES = 20;      // ~90 s total, covers Render cold start
    const BASE_DELAY_MS = 1500;

    async function probe() {
      for (let attempt = 0; attempt < MAX_TRIES && !cancelled; attempt++) {
        try {
          const h = await fetchHealth();
          // During Render cold start we may get their HTML loader (200)
          // whose parsed body has no `api` field — treat that as still
          // waking and retry.
          if (h && (h as { api?: string }).api === "ok") {
            if (!cancelled) setBackend("up");
            return;
          }
        } catch {
          // Network/timeout/HTML — fall through to retry.
        }
        const delay = Math.min(BASE_DELAY_MS * Math.pow(1.3, attempt), 8000);
        await new Promise((r) => setTimeout(r, delay));
      }
      if (!cancelled) setBackend("down");
    }
    void probe();
    return () => { cancelled = true; };
  }, []);

  function describeError(err: unknown, fallback: string): string {
    const status = (err as { response?: { status?: number } })?.response?.status;
    if (status === 401) return fallback;
    if (status === undefined)
      return "Could not reach the backend. Check that the API is running and that VITE_API_URL points at it.";
    return `The backend rejected the request (HTTP ${status}).`;
  }

  async function handleCredentials(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    setIsSubmitting(true);
    try {
      const outcome = await login(username, password);
      if (outcome.done) {
        navigate("/dashboard");
        return;
      }
      // Second factor required.
      setMfaToken(outcome.mfaToken);
      setEnrollmentNeeded(outcome.enrollmentRequired);
      if (outcome.enrollmentRequired && outcome.mfaToken) {
        // MFA is mandatory and this account has never enrolled: start the
        // enrolment here rather than telling the user to go and find a
        // settings page they cannot reach without logging in first.
        try {
          setEnrollment(await mfaEnrollWithChallenge(outcome.mfaToken));
          setStage("enroll");
          return;
        } catch (enrollErr: unknown) {
          setError(describeError(enrollErr, "Could not start two-factor setup."));
        }
      }
      setStage("mfa");
    } catch (err: unknown) {
      setError(describeError(err, "Incorrect username or password."));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleMfa(event: FormEvent) {
    event.preventDefault();
    if (!mfaToken) return;
    setError(null);
    setIsSubmitting(true);
    try {
      await completeMfa(mfaToken, code.trim());
      navigate("/dashboard");
    } catch (err: unknown) {
      setError(describeError(err, "That authentication code is not valid."));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleEnrollConfirm(event: FormEvent) {
    event.preventDefault();
    if (!mfaToken) return;
    setError(null);
    setIsSubmitting(true);
    try {
      const result = await mfaConfirmWithChallenge(mfaToken, code.trim());
      if (result.backup_codes?.length) {
        // Shown once — the user must copy them before entering the console.
        setEnrolledSession(result);
        setBackupCodes(result.backup_codes);
        setCode("");
        return;
      }
      await completeMfa(mfaToken, code.trim());
      navigate("/dashboard");
    } catch (err: unknown) {
      setError(describeError(err, "That code did not verify. Check your device clock."));
    } finally {
      setIsSubmitting(false);
    }
  }

  function finishEnrollment() {
    // /api/mfa/confirm already minted a session (and set the httpOnly
    // cookie): both factors were proven a moment ago, so the console
    // signs the user in instead of sending them back to the password box.
    const session = enrolledSession;
    if (session?.access_token && session.username && session.role) {
      adoptSession({
        access_token: session.access_token,
        token_type: "bearer",
        username: session.username,
        role: session.role,
        expires_in: session.expires_in ?? null,
      });
      navigate("/dashboard");
      return;
    }
    // No session came back (an older backend): fall back to a normal
    // sign-in, which now finds an enrolled authenticator.
    setBackupCodes(null);
    setEnrollment(null);
    setEnrolledSession(null);
    resetToCredentials();
    setNotice("Two-factor is set up. Sign in with your password and a code from your app.");
  }

  function resetToCredentials() {
    setStage("credentials");
    setCode("");
    setMfaToken(null);
    setEnrollment(null);
    setBackupCodes(null);
    setEnrolledSession(null);
    setError(null);
  }

  return (
    <div className="centered-screen">
      <div className="login-card">
        <h1>AegisIQ</h1>
        <p className="brand-tagline">Intelligent Shield · SIEM &amp; SOAR</p>
        <p className="subtitle">
          {stage === "credentials"
            ? "Sign in to the security operations console"
            : "Two-factor authentication"}
        </p>

        {stage === "credentials" && (
          <div className={`backend-check ${backend}`}>
            <span className="dot" aria-hidden="true" />
            {backend === "checking" && "Checking backend…"}
            {backend === "up" && "Backend reachable"}
            {backend === "down" && "Backend unreachable"}
          </div>
        )}

        {notice && !error && <div className="info-banner">{notice}</div>}

        {error && <div className="error-banner">{error}</div>}

        {stage === "credentials" ? (
          <form onSubmit={handleCredentials}>
            <div className="field">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus
                required
              />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </div>
            <button className="btn-primary" type="submit" disabled={isSubmitting}>
              {isSubmitting ? "Signing in…" : "Sign in"}
            </button>
          </form>
        ) : stage === "enroll" && backupCodes ? (
          <div className="mfa-enroll-notice">
            <p>
              <b>Two-factor is active.</b> Save these backup codes now — each one
              works once if you lose your authenticator, and they are not shown
              again.
            </p>
            <ul className="backup-code-list">
              {backupCodes.map((c) => <li key={c}><code>{c}</code></li>)}
            </ul>
            <button
              className="btn-primary"
              disabled={isSubmitting}
              onClick={finishEnrollment}
            >
              I have saved them — continue
            </button>
          </div>
        ) : stage === "enroll" && enrollment ? (
          <form onSubmit={handleEnrollConfirm}>
            <p className="mfa-hint">
              This console requires two-factor authentication. Add the key below
              to Google Authenticator, Authy, 1Password or Microsoft
              Authenticator, then enter the 6-digit code it shows.
            </p>
            <div className="field">
              <label htmlFor="setup-key">Setup key</label>
              <code id="setup-key" className="mfa-secret">{enrollment.secret}</code>
            </div>
            <details className="mfa-uri">
              <summary>Or paste this otpauth:// URI</summary>
              <code>{enrollment.otpauth_uri}</code>
            </details>
            <div className="field">
              <label htmlFor="code">Code from your app</label>
              <input
                id="code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                autoFocus
                required
              />
            </div>
            <button className="btn-primary" type="submit" disabled={isSubmitting}>
              {isSubmitting ? "Verifying…" : "Activate two-factor"}
            </button>
            <button type="button" className="btn-secondary" onClick={resetToCredentials}>
              ← Back
            </button>
          </form>
        ) : enrollmentNeeded ? (
          <div className="mfa-enroll-notice">
            <p>
              This account must set up two-factor authentication, but the setup
              step could not be started. Try signing in again, or ask an
              administrator to check the server logs.
            </p>
            <button className="btn-secondary" onClick={resetToCredentials}>
              ← Back
            </button>
          </div>
        ) : (
          <form onSubmit={handleMfa}>
            <p className="mfa-hint">
              Enter the 6-digit code from your authenticator app, or an
              <code>xxxx-xxxx</code> backup code.
            </p>
            <div className="field">
              <label htmlFor="code">Authentication code</label>
              <input
                id="code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                autoFocus
                required
              />
            </div>
            <button className="btn-primary" type="submit" disabled={isSubmitting}>
              {isSubmitting ? "Verifying…" : "Verify"}
            </button>
            <button
              type="button"
              className="btn-secondary"
              style={{ marginTop: "0.5rem" }}
              onClick={resetToCredentials}
            >
              ← Back
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
