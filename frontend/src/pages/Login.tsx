import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { fetchHealth } from "../api/client";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const { login, completeMfa } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [backend, setBackend] = useState<"checking" | "up" | "down">("checking");

  // v2.3 — second-factor step state.
  const [stage, setStage] = useState<"credentials" | "mfa">("credentials");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [enrollmentNeeded, setEnrollmentNeeded] = useState(false);
  const [code, setCode] = useState("");

  useEffect(() => {
    fetchHealth()
      .then(() => setBackend("up"))
      .catch(() => setBackend("down"));
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

  function resetToCredentials() {
    setStage("credentials");
    setCode("");
    setMfaToken(null);
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
        ) : enrollmentNeeded ? (
          <div className="mfa-enroll-notice">
            <p>
              This account is required to set up two-factor authentication before
              first use. Sign in on a session where you can reach the
              <b> Security → Two-factor</b> settings, or ask an administrator to
              relax <code>MFA_REQUIRED</code> for the initial setup.
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
