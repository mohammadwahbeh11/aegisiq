"""
app/analysis/report.py -- turn the raw analysis output into a
structured Report + a printable HTML export.

v2.2 --- Rich vulnerability report.
The HTML export is self-contained (single file, no external CSS or JS),
so it can be emailed, printed to PDF, or embedded in an incident-response
ticket without breaking. It now includes:

  * Executive summary card (verdict + KPI row)
  * Findings table with MITRE, Kill Chain, OWASP/CWE mapping, and
    verbatim SAMPLE EVENTS from the log
  * Per-finding remediation steps (numbered, actionable)
  * IOC block (source IPs, usernames, ports, URLs, User-Agents)
  * Event type breakdown with inline SVG bars
  * Hourly timeline of activity (inline SVG stacked bars)
  * Recommendations, prioritised

Public API:
  build_summary(raw)   -> dict  (JSON-serializable, stored on the row)
  render_html(raw, fn) -> str   (self-contained HTML doc)
"""
from __future__ import annotations

import html
from typing import Any


_SEVERITY_COLORS = {
    "critical": "#f43f5e",
    "high":     "#f59e0b",
    "medium":   "#eab308",
    "low":      "#64748b",
}


# ─────────────────────────────────────────────────────────────────────
# Remediation playbook — numbered actionable steps per rule type
# ─────────────────────────────────────────────────────────────────────
_REMEDIATION_STEPS: dict[str, list[str]] = {
    "brute_force": [
        "Block the source IP at the perimeter firewall or WAF.",
        "Enable fail2ban (or its equivalent) with a threshold below the observed burst.",
        "Force a password reset for the targeted account and rotate any shared secrets.",
        "Review the account's access to sensitive systems for signs of successful compromise.",
        "Enable MFA on the targeted account if not already active.",
    ],
    "port_scan": [
        "Block the scanning source IP at the firewall for at least 24 hours.",
        "Audit which of the scanned services should be publicly reachable — remove or firewall the rest.",
        "Check whether any of the scanned services are running vulnerable versions (compare against CVE feeds).",
        "Add the source IP to your threat-intel blocklist and share with your ISAC if in one.",
    ],
    "login_after_failure": [
        "Treat the account as compromised until proven otherwise.",
        "Reset the password AND revoke all active sessions / API tokens for the account.",
        "Review activity logs for lateral movement from the compromised account.",
        "Check whether the credential pair appears in HaveIBeenPwned or an internal breach corpus.",
        "Enable MFA and require step-up authentication for privileged operations.",
    ],
    "credential_stuffing": [
        "Block the source IP and add it to threat intelligence.",
        "Cross-reference the targeted usernames against HaveIBeenPwned — force resets for any that match.",
        "Deploy CAPTCHA on the login page for new sessions from unknown networks.",
        "Enable adaptive rate-limiting keyed on (source IP, username).",
        "Enable MFA globally; credential stuffing is a defeated attack against MFA-protected accounts.",
    ],
    "file_integrity": [
        "Restore the affected file from a known-good backup or the golden image.",
        "Investigate how the modification bypassed change control — was auditd running? Was root compromised?",
        "Rotate all secrets and keys stored on the affected host as a precaution.",
        "Enable AIDE, tripwire, or auditd file-watches on the affected path.",
        "Audit sudoers and SSH authorized_keys on the host for unauthorized entries.",
    ],
    "privilege_escalation": [
        "Assume the actor's account is compromised; disable it immediately.",
        "Audit sudoers, SSH keys, and cron jobs owned by the actor.",
        "Enable command logging (auditd rules, or shell auditing) if not already active.",
        "Check for new SUID binaries or writable service unit files created recently.",
        "Rotate any credentials the actor could have accessed while root.",
    ],
    "web_attack": [
        "Deploy or tighten a WAF rule blocking the specific attack pattern shown.",
        "Review server-side input validation for the affected endpoint.",
        "Search application logs for successful responses to similar payloads — look for exfiltrated data.",
        "Rate-limit or block the source IP; add to threat intelligence.",
        "If the pattern is a known CVE (e.g. Log4Shell), verify the affected library is patched.",
    ],
    "suspicious_user_agent": [
        "Silently drop or 403 requests carrying the flagged UA at the reverse proxy — do not respond.",
        "Correlate the source IP with other findings; scanners often precede a real attack.",
        "Verify the WAF signature database includes the tool version seen.",
        "Consider blocking the source ASN if the same tool signature repeats across IPs.",
    ],
}


def _recommendation(finding: dict) -> str:
    """One-line action for the summary block. Detailed steps live in
    _REMEDIATION_STEPS and land in the report HTML."""
    m = {
        "brute_force":
            f"Block source IP {finding['source']} and force a password reset for the targeted account.",
        "port_scan":
            f"Block {finding['source']} at the firewall; audit which scanned services should not be publicly reachable.",
        "login_after_failure":
            f"Treat {finding.get('compromised_account') or 'the account'} as compromised — reset password and revoke sessions.",
        "credential_stuffing":
            f"Block {finding['source']}; cross-check the targeted usernames against HaveIBeenPwned.",
        "file_integrity":
            f"Restore {finding['source']} from backup and audit how change control was bypassed.",
        "privilege_escalation":
            f"Assume {finding['source']} is compromised; audit sudoers and rotate the account's credentials.",
        "web_attack":
            f"Deploy a WAF rule blocking the '{finding.get('pattern', 'observed')}' pattern; review server-side input validation.",
        "suspicious_user_agent":
            f"Drop requests carrying UA '{finding.get('ua_signature', 'scanner')}' at the reverse proxy.",
    }
    return m.get(finding["rule_type"], "Investigate the flagged events and correlate with other alerts.")


def build_summary(raw: dict[str, Any]) -> dict[str, Any]:
    """Compact JSON shape stored on the AnalysisReport row and
    returned from GET /api/analysis/{id}."""
    findings = raw.get("findings", [])
    worst = "low"
    order = ["low", "medium", "high", "critical"]
    for f in findings:
        if order.index(f["severity"]) > order.index(worst):
            worst = f["severity"]

    return {
        "generated_at": raw["generated_at"],
        "elapsed_ms": raw["elapsed_ms"],
        "input_format": raw["format"],
        "truncated": raw["truncated"],
        "total_bytes": raw["total_bytes"],
        "total_lines": raw["total_lines"],
        "parsed_events": raw["parsed_events"],
        "unparsed_events": raw["unparsed_events"],
        "parse_errors": raw["parse_errors"],
        "worst_severity": worst if findings else None,
        "event_type_counts": raw["event_type_counts"],
        "severity_counts": raw["severity_counts"],
        "top_sources": raw["top_sources"],
        "top_users": raw["top_users"],
        "findings_count": len(findings),
        "findings_by_severity": raw["findings_by_severity"],
        "findings_by_rule": raw["findings_by_rule"],
        "findings": findings,
        "recommendations": [
            {
                "finding": f["rule"],
                "action": _recommendation(f),
                "priority": f["severity"],
                "steps": _REMEDIATION_STEPS.get(f["rule_type"], []),
                "mitre": f.get("mitre"),
            }
            for f in findings
        ],
        "first_event_ts": raw["first_event_ts"],
        "last_event_ts": raw["last_event_ts"],
        # v2.2 enrichment fields
        "iocs": raw.get("iocs", {}),
        "timeline": raw.get("timeline", []),
    }


# ─────────────────────────────────────────────────────────────────────
# HTML rendering helpers
# ─────────────────────────────────────────────────────────────────────
def _bar(pct: float, color: str) -> str:
    pct = max(0.0, min(100.0, pct))
    return (
        f'<div style="background:#f1f5f9;border-radius:4px;height:6px;overflow:hidden">'
        f'<div style="background:{color};height:6px;width:{pct}%"></div></div>'
    )


def _sample_events_block(finding: dict) -> str:
    samples = finding.get("sample_events") or []
    if not samples:
        return ""
    rows = "".join(
        f'<pre style="margin:4px 0;padding:8px;background:#0f172a;color:#e2e8f0;'
        f'border-radius:4px;font-size:11px;overflow-x:auto;white-space:pre-wrap;'
        f'word-break:break-all">{html.escape(s)}</pre>'
        for s in samples
    )
    return (
        f'<details style="margin-top:6px"><summary style="cursor:pointer;'
        f'color:#64748b;font-size:11px">Sample events ({len(samples)})</summary>'
        f'{rows}</details>'
    )


def _remediation_block(rec: dict) -> str:
    steps = rec.get("steps") or []
    if not steps:
        return f'<b>{html.escape(rec["finding"])}</b> — {html.escape(rec["action"])}'
    steps_html = "".join(f'<li style="margin:4px 0">{html.escape(s)}</li>' for s in steps)
    return (
        f'<b>{html.escape(rec["finding"])}</b> — {html.escape(rec["action"])}'
        f'<ol style="margin:6px 0 4px 20px;font-size:12px;color:#0f172a">{steps_html}</ol>'
    )


def _timeline_svg(buckets: list[dict]) -> str:
    """Inline SVG stacked bars — one per hour bucket, coloured by
    severity. No external chart lib needed; renders in print."""
    if not buckets:
        return '<p style="color:#94a3b8;font-size:12px">No timestamped events.</p>'
    width, height, pad = 720, 140, 20
    inner_w = width - 2 * pad
    inner_h = height - 2 * pad
    max_total = max((b["total"] for b in buckets), default=1) or 1
    bar_w = max(2, inner_w / max(len(buckets), 1) - 2)

    parts = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
             'style="width:100%;max-width:720px;background:#f8f9fc;border-radius:8px">']
    for i, b in enumerate(buckets):
        x = pad + i * (bar_w + 2)
        y = pad + inner_h
        # Stack in severity order (low bottom, critical top)
        for sev in ("low", "medium", "high", "critical"):
            n = b["by_severity"].get(sev, 0)
            if n == 0:
                continue
            h = (n / max_total) * inner_h
            y -= h
            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" '
                f'fill="{_SEVERITY_COLORS[sev]}"><title>{html.escape(b["hour"])} '
                f'· {sev}: {n}</title></rect>'
            )
    # X-axis labels: first + last hour
    if buckets:
        parts.append(
            f'<text x="{pad}" y="{height - 4}" font-size="10" fill="#64748b" '
            f'font-family="ui-monospace,monospace">{html.escape(buckets[0]["hour"])}</text>'
        )
        parts.append(
            f'<text x="{width - pad}" y="{height - 4}" font-size="10" fill="#64748b" '
            f'text-anchor="end" font-family="ui-monospace,monospace">'
            f'{html.escape(buckets[-1]["hour"])}</text>'
        )
    parts.append('</svg>')
    return "".join(parts)


def _ioc_table(title: str, rows: list, is_ip: bool = False) -> str:
    if not rows:
        return ""
    body = "".join(
        f'<tr><td><code>{html.escape(str(k))}</code></td>'
        f'<td style="text-align:right;font-variant-numeric:tabular-nums">{n:,}</td></tr>'
        for k, n in rows
    )
    return (
        f'<div style="flex:1;min-width:260px">'
        f'<h3 style="font-size:12px;text-transform:uppercase;letter-spacing:.06em;'
        f'color:#64748b;margin:0 0 6px 0">{html.escape(title)}</h3>'
        f'<table><tbody>{body}</tbody></table></div>'
    )


def render_html(raw: dict[str, Any], filename: str) -> str:
    """Self-contained HTML report — sends over email, prints to PDF."""
    s = build_summary(raw)
    findings = s["findings"]
    total_events = s["parsed_events"] or 1
    esc = html.escape

    # ── Findings rows (with sample events tucked into <details>)
    def _finding_row(f: dict) -> str:
        sev_bg = _SEVERITY_COLORS.get(f["severity"], "#64748b")
        blurb_html = (
            '<div style="color:#64748b;font-size:11px;margin-top:2px">'
            + esc(f["mitre_blurb"]) + '</div>'
        ) if f.get("mitre_blurb") else ""
        cwe_html = (
            '<div style="font-size:10px;color:#64748b;margin-top:2px">'
            + " · ".join(esc(x) for x in f.get("cwe_owasp", [])) + '</div>'
        ) if f.get("cwe_owasp") else ""
        return (
            f'<tr>'
            f'<td><span style="background:{sev_bg};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:11px;font-weight:600">'
            f'{esc(f["severity"].upper())}</span></td>'
            f'<td><b>{esc(f["rule"])}</b>{blurb_html}</td>'
            f'<td><code style="background:#eef2ff;color:#4338ca;padding:2px 6px;'
            f'border-radius:4px">{esc(f.get("mitre") or "-")}</code>{cwe_html}</td>'
            f'<td>{esc(f.get("kill_chain") or "-")}</td>'
            f'<td><code>{esc(str(f["source"]))}</code></td>'
            f'<td style="text-align:right;font-variant-numeric:tabular-nums">{f["count"]}</td>'
            f'<td>{esc(f["reason"])}{_sample_events_block(f)}</td>'
            f'</tr>'
        )

    if findings:
        findings_rows = "".join(_finding_row(f) for f in findings)
    else:
        findings_rows = (
            '<tr><td colspan="7" style="text-align:center;color:#22c55e;'
            'padding:32px;font-weight:600">✓ No malicious patterns detected in this log file.</td></tr>'
        )

    # ── Event type breakdown
    if s["event_type_counts"]:
        event_type_rows = "".join(
            f'<tr><td>{esc(et)}</td>'
            f'<td style="text-align:right;font-variant-numeric:tabular-nums">{cnt:,}</td>'
            f'<td>{_bar(100 * cnt / total_events, "#7c7ef5")}</td></tr>'
            for et, cnt in sorted(s["event_type_counts"].items(), key=lambda x: -x[1])
        )
    else:
        event_type_rows = '<tr><td colspan="3" style="color:#94a3b8;padding:12px">No events parsed.</td></tr>'

    # ── Top sources
    top_sources_rows = "".join(
        f'<tr><td><code>{esc(ip)}</code></td><td style="text-align:right">{cnt:,}</td></tr>'
        for ip, cnt in s["top_sources"]
    ) or '<tr><td colspan="2" style="color:#94a3b8;padding:12px">No source addresses in the log.</td></tr>'

    # ── Recommendations (with numbered steps)
    recommendations_rows = "".join(
        f'<li style="margin:14px 0;padding:12px 14px;background:#f8f9fc;'
        f'border-radius:8px;border-left:4px solid {_SEVERITY_COLORS.get(r["priority"], "#64748b")}">'
        f'{_remediation_block(r)}'
        f'</li>'
        for r in s["recommendations"]
    ) or '<li style="color:#22c55e;padding:12px;background:#f0fdf4;border-radius:8px">✓ No specific actions required — no findings.</li>'

    # ── IOCs
    iocs = s.get("iocs", {}) or {}
    ioc_blocks = (
        _ioc_table("Source IPs",   iocs.get("source_ips", []), is_ip=True) +
        _ioc_table("Usernames",    iocs.get("usernames", [])) +
        _ioc_table("Hostnames",    iocs.get("hostnames", [])) +
        _ioc_table("Ports probed", iocs.get("ports", [])) +
        _ioc_table("URLs",         iocs.get("urls", [])) +
        _ioc_table("User-Agents",  iocs.get("user_agents", []))
    )

    # ── Timeline SVG
    timeline_svg = _timeline_svg(s.get("timeline", []))

    # ── Verdict header colour
    worst = s["worst_severity"] or "clean"
    worst_color = _SEVERITY_COLORS.get(worst, "#22c55e")
    verdict_msg = (
        f"{s['findings_count']} finding(s) — highest severity: {worst.upper()}"
        if findings else "Clean — no known-bad patterns detected"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AegisIQ · Log Analysis Report · {esc(filename)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          background: #f8f9fc; color: #0f172a; margin: 0; padding: 40px 20px;
          -webkit-font-smoothing: antialiased; }}
  .page {{ max-width: 960px; margin: 0 auto; background: #fff; border-radius: 12px;
           padding: 40px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); }}
  .header {{ border-bottom: 2px solid #e3e7ef; padding-bottom: 20px; margin-bottom: 20px;
             display: flex; justify-content: space-between; align-items: flex-start; gap: 20px; }}
  .brand {{ font-size: 24px; font-weight: 700; letter-spacing: -0.02em;
            background: linear-gradient(120deg, #0f172a, #7c7ef5);
            -webkit-background-clip: text; background-clip: text; color: transparent; }}
  .brand-sub {{ font-size: 10px; color: #94a3b8; letter-spacing: 0.14em;
                text-transform: uppercase; font-weight: 600; margin-top: 2px; }}
  .report-badge {{ background: {worst_color}; color: #fff; padding: 10px 18px;
                   border-radius: 8px; font-weight: 600; font-size: 12px;
                   text-transform: uppercase; letter-spacing: 0.06em;
                   text-align: center; min-width: 120px; }}
  .report-badge .msg {{ font-size: 10px; opacity: 0.9; text-transform: none;
                        letter-spacing: 0; margin-top: 4px; font-weight: 500; }}
  h1 {{ font-size: 26px; margin: 0 0 8px 0; letter-spacing: -0.02em; }}
  h2 {{ font-size: 14px; margin: 28px 0 10px 0; color: #0f172a;
        text-transform: uppercase; letter-spacing: 0.08em; }}
  .meta {{ color: #64748b; font-size: 13px; }}
  .kpi-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 24px 0; }}
  .kpi {{ background: #f8f9fc; border: 1px solid #e3e7ef; border-radius: 10px;
          padding: 16px; }}
  .kpi .label {{ font-size: 10px; color: #94a3b8; text-transform: uppercase;
                 letter-spacing: 0.08em; font-weight: 600; }}
  .kpi .value {{ font-size: 26px; font-weight: 700; letter-spacing: -0.02em;
                 margin-top: 4px; font-variant-numeric: tabular-nums; }}
  .kpi.warn .value {{ color: #f59e0b; }}
  .kpi.critical .value {{ color: #f43f5e; }}
  .kpi.clean .value {{ color: #22c55e; }}
  table {{ width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 13px; }}
  th {{ background: #f8f9fc; color: #64748b; text-align: left;
        padding: 10px 12px; font-size: 11px; text-transform: uppercase;
        letter-spacing: 0.06em; font-weight: 600; border-bottom: 1px solid #e3e7ef; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
  code {{ font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 12px; }}
  ul, ol {{ padding-left: 8px; list-style: none; }}
  .ioc-grid {{ display: flex; flex-wrap: wrap; gap: 20px; margin-top: 8px; }}
  .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #e3e7ef;
             color: #94a3b8; font-size: 11px; text-align: center; }}
  details summary::-webkit-details-marker {{ display: none; }}
  @media print {{
    body {{ background: #fff; padding: 0; }}
    .page {{ box-shadow: none; padding: 20px; }}
  }}
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div>
      <div class="brand">AegisIQ</div>
      <div class="brand-sub">Log Analysis Report · Intelligent Shield SIEM &amp; SOAR</div>
    </div>
    <div class="report-badge">{esc(worst.upper())}<div class="msg">{esc(verdict_msg)}</div></div>
  </div>

  <h1>Analysis of <code style="font-size:22px">{esc(filename)}</code></h1>
  <p class="meta">
    Generated <b>{esc(s["generated_at"])}</b> · Elapsed <b>{s["elapsed_ms"]}&nbsp;ms</b> ·
    Input format <b>{esc(s["input_format"])}</b>
    {'· <b style="color:#f59e0b">Truncated at ' + f'{s["parsed_events"]:,}' + ' events</b>' if s["truncated"] else ""}
    {'· First event: <b>' + esc(s["first_event_ts"]) + '</b>' if s.get("first_event_ts") else ""}
    {'· Last event: <b>' + esc(s["last_event_ts"]) + '</b>' if s.get("last_event_ts") else ""}
  </p>

  <div class="kpi-row">
    <div class="kpi"><div class="label">Total lines</div>
      <div class="value">{s["total_lines"]:,}</div></div>
    <div class="kpi"><div class="label">Parsed events</div>
      <div class="value">{s["parsed_events"]:,}</div></div>
    <div class="kpi {'critical' if s['findings_count'] else 'clean'}">
      <div class="label">Findings</div>
      <div class="value">{s["findings_count"]:,}</div></div>
    <div class="kpi warn"><div class="label">Unparsed</div>
      <div class="value">{s["unparsed_events"]:,}</div></div>
  </div>

  <h2>Activity timeline (hourly, coloured by severity)</h2>
  {timeline_svg}

  <h2>Findings — vulnerabilities &amp; attacks detected</h2>
  <table>
    <thead><tr>
      <th>Severity</th><th>Rule / Technique</th><th>MITRE / CWE</th><th>Kill Chain</th>
      <th>Source</th><th style="text-align:right">#</th><th>Details</th>
    </tr></thead>
    <tbody>{findings_rows}</tbody>
  </table>

  <h2>Prioritised remediation</h2>
  <ul style="padding:0;list-style:none">{recommendations_rows}</ul>

  <h2>Indicators of Compromise (IOCs)</h2>
  <div class="ioc-grid">{ioc_blocks or '<p style="color:#94a3b8;font-size:12px">No IOCs extracted.</p>'}</div>

  <h2>Event type breakdown</h2>
  <table><thead><tr><th>Event type</th><th style="text-align:right">Count</th><th>Share</th></tr></thead>
    <tbody>{event_type_rows}</tbody></table>

  <h2>Top source addresses</h2>
  <table><thead><tr><th>Source IP</th><th style="text-align:right">Events</th></tr></thead>
    <tbody>{top_sources_rows}</tbody></table>

  <div class="footer">
    Generated by <b>AegisIQ v2.3</b> — Intelligent Shield SIEM &amp; SOAR ·
    This report is confidential. Do not distribute without authorization.
  </div>
</div>
</body>
</html>"""
