/**
 * Security.tsx (v2.3) — per-user two-factor authentication management.
 *
 * Enrol → confirm → active, plus disable and backup-code awareness.
 *
 * QR note: the backend returns the otpauth:// URI and the base32 setup
 * key. Every authenticator app (Google Authenticator, Authy, 1Password,
 * Microsoft Authenticator) supports "enter a setup key manually", so we
 * present the key prominently with a copy button — that path always
 * works, on desktop and mobile, with no QR-rendering dependency. The
 * otpauth URI is also copyable for password managers that accept it.
 */
import { useCallback, useEffect, useState } from "react";

import {
  MfaStatus,
  fetchMfaStatus, mfaConfirm, mfaDisable, mfaEnroll,
} from "../api/client";
import { EmptyState, ErrorBanner, Loading, Panel } from "../components/ui";

export default function Security() {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Enrolment working state
  const [secret, setSecret] = useState<string | null>(null);
  const [otpauthUri, setOtpauthUri] = useState<string | null>(null);
  const [confirmCode, setConfirmCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  // Disable working state
  const [disableCode, setDisableCode] = useState("");

  const refresh = useCallback(async () => {
    try {
      setStatus(await fetchMfaStatus());
      setError(null);
    } catch {
      setError("Could not load MFA status.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  async function copy(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
      window.setTimeout(() => setCopied((c) => (c === label ? null : c)), 1500);
    } catch { /* clipboard blocked — the value is visible to select manually */ }
  }

  async function startEnroll() {
    setBusy(true); setError(null); setBackupCodes(null);
    try {
      const r = await mfaEnroll();
      setSecret(r.secret);
      setOtpauthUri(r.otpauth_uri);
    } catch (e: unknown) {
      const s = (e as { response?: { status?: number } })?.response?.status;
      setError(s === 409 ? "MFA is already active — disable it first to re-enrol." : "Could not start enrolment.");
    } finally {
      setBusy(false);
    }
  }

  async function confirmEnroll() {
    if (!confirmCode.trim()) return;
    setBusy(true); setError(null);
    try {
      const r = await mfaConfirm(confirmCode.trim());
      setBackupCodes(r.backup_codes);
      setSecret(null); setOtpauthUri(null); setConfirmCode("");
      await refresh();
    } catch {
      setError("That code did not verify. Check your phone's clock and use the current 6-digit code.");
    } finally {
      setBusy(false);
    }
  }

  async function disable() {
    if (!disableCode.trim()) return;
    setBusy(true); setError(null);
    try {
      await mfaDisable(disableCode.trim());
      setDisableCode("");
      setBackupCodes(null);
      await refresh();
    } catch {
      setError("Provide a current authenticator or backup code to disable MFA.");
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <Loading label="Loading security settings…" />;

  const active = status?.status === "active";

  return (
    <>
      <div className="page-head">
        <div>
          <h2>Two-factor authentication</h2>
          <p className="page-sub">
            Add a time-based one-time code (TOTP, RFC 6238) as a second factor at
            login. Works with Google Authenticator, Authy, 1Password, and Microsoft
            Authenticator.
          </p>
        </div>
      </div>

      {error && <ErrorBanner>{error}</ErrorBanner>}

      <Panel title="Status">
        <div className="mfa-status-row">
          <span className={`mfa-badge mfa-${status?.status}`}>
            {status?.status?.toUpperCase()}
          </span>
          {active && (
            <span className="muted">
              Backup codes remaining: <b>{status?.backup_codes_remaining}</b>
              {status?.confirmed_at && ` · enabled ${new Date(status.confirmed_at).toLocaleString()}`}
            </span>
          )}
          {status?.required_globally && !active && (
            <span className="mfa-warning">Your organization requires MFA — please enrol.</span>
          )}
          {!status?.enabled_globally && (
            <span className="muted">MFA is disabled globally by configuration.</span>
          )}
        </div>
      </Panel>

      {/* Newly-issued backup codes (shown once) */}
      {backupCodes && (
        <Panel title="Save your backup codes — shown only once">
          <p className="muted">
            Each code works once if you lose your authenticator. Store them in a
            password manager or print them.
          </p>
          <div className="backup-codes-grid">
            {backupCodes.map((c) => <code key={c}>{c}</code>)}
          </div>
          <button className="btn" onClick={() => copy(backupCodes.join("\n"), "backup")}>
            {copied === "backup" ? "✓ Copied" : "Copy all"}
          </button>
        </Panel>
      )}

      {/* Enrolment flow */}
      {!active && !secret && (
        <Panel title="Enable two-factor authentication">
          <EmptyState>
            You have not enabled MFA. Click below to generate a setup key for your
            authenticator app.
          </EmptyState>
          <button className="btn-primary" disabled={busy} onClick={() => void startEnroll()}>
            {busy ? "Generating…" : "Set up two-factor"}
          </button>
        </Panel>
      )}

      {secret && (
        <Panel title="Step 1 · Add the key to your authenticator">
          <ol className="mfa-steps">
            <li>Open your authenticator app and choose <b>“Enter a setup key”</b> (manual entry).</li>
            <li>Issuer / account name: <code>AegisIQ</code> · Key type: <b>Time-based</b>.</li>
            <li>Paste this setup key:</li>
          </ol>

          <div className="mfa-secret-box">
            <code>{secret}</code>
            <button className="btn" onClick={() => copy(secret, "secret")}>
              {copied === "secret" ? "✓ Copied" : "Copy key"}
            </button>
          </div>

          <details className="mfa-uri">
            <summary>Or paste this otpauth:// URI (for password managers)</summary>
            <div className="mfa-secret-box">
              <code style={{ wordBreak: "break-all" }}>{otpauthUri}</code>
              <button className="btn" onClick={() => copy(otpauthUri!, "uri")}>
                {copied === "uri" ? "✓ Copied" : "Copy URI"}
              </button>
            </div>
          </details>

          <h4 className="section-h">Step 2 · Confirm the current 6-digit code</h4>
          <div className="mfa-confirm-row">
            <input
              value={confirmCode}
              onChange={(e) => setConfirmCode(e.target.value)}
              placeholder="123456"
              inputMode="numeric"
              maxLength={6}
            />
            <button className="btn-primary" disabled={busy} onClick={() => void confirmEnroll()}>
              {busy ? "Confirming…" : "Confirm & activate"}
            </button>
          </div>
        </Panel>
      )}

      {/* Disable flow */}
      {active && (
        <Panel title="Disable two-factor authentication">
          <p className="muted">
            Enter a current authenticator or backup code to turn MFA off. This is
            audited.
          </p>
          <div className="mfa-confirm-row">
            <input
              value={disableCode}
              onChange={(e) => setDisableCode(e.target.value)}
              placeholder="Current code"
              inputMode="numeric"
            />
            <button className="btn-danger" disabled={busy} onClick={() => void disable()}>
              {busy ? "Disabling…" : "Disable MFA"}
            </button>
          </div>
        </Panel>
      )}
    </>
  );
}
