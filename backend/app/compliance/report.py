"""
app/compliance/report.py -- HTML report renderer.

Turns a compliance-evidence dict (from soc2.py / iso27001.py / gdpr.py)
into an auditor-friendly HTML page. Self-contained -- no JS, inline
CSS -- so the customer can Save-As and email to the auditor without a
web server.
"""
from __future__ import annotations

import html
import json
from typing import Any


def render_html(evidence: dict[str, Any]) -> str:
    """Render one framework's evidence dict as a standalone HTML page."""
    framework = html.escape(str(evidence.get("framework", "Compliance Report")))
    generated = html.escape(str(evidence.get("generated_at", "")))
    controls = evidence.get("controls", [])

    controls_html = "\n".join(_render_control(c) for c in controls)

    processing_html = ""
    if "processing_activities" in evidence:  # GDPR shape
        processing_html = _render_processing(evidence)

    return f"""<!doctype html>
<meta charset="utf-8">
<title>{framework} — AegisIQ Compliance Report</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: -apple-system, "Segoe UI", Arial, sans-serif;
         max-width: 900px; margin: 40px auto; padding: 0 20px;
         color: #1a1a2e; line-height: 1.55; }}
  h1 {{ color: #6b46c1; border-bottom: 3px solid #6b46c1; padding-bottom: 10px; }}
  h2 {{ color: #4a3a80; margin-top: 40px; }}
  h3 {{ margin-top: 24px; font-size: 1.1rem; }}
  .meta {{ background: #f5f2ff; padding: 12px 20px; border-radius: 8px;
          border-left: 4px solid #6b46c1; font-size: 0.9rem; color: #555; }}
  .control {{ border: 1px solid #ddd; border-radius: 10px; padding: 18px 22px;
             margin: 18px 0; background: #fafafc; }}
  .control h3 {{ margin: 0 0 6px 0; }}
  .status {{ display: inline-block; padding: 3px 10px; border-radius: 12px;
            font-size: 0.75rem; font-weight: 600; margin-left: 8px; }}
  .status.met         {{ background: #d1fae5; color: #065f46; }}
  .status.partial     {{ background: #fef3c7; color: #92400e; }}
  .status.customer_supplied {{ background: #dbeafe; color: #1e40af; }}
  .evidence-table {{ width: 100%; border-collapse: collapse; margin-top: 8px;
                    font-size: 0.9rem; }}
  .evidence-table td {{ padding: 6px 10px; border-bottom: 1px solid #eee;
                       vertical-align: top; }}
  .evidence-table td:first-child {{ width: 30%; color: #666; font-weight: 500; }}
  .narrative {{ margin-top: 10px; padding: 10px 14px; background: white;
               border-left: 3px solid #a78bfa; font-size: 0.92rem; }}
  .gap {{ margin-top: 8px; padding: 8px 14px; background: #fef2f2;
         border-left: 3px solid #ef4444; font-size: 0.85rem; color: #7f1d1d; }}
  .footer {{ margin-top: 60px; padding: 20px; background: #f5f2ff; border-radius: 8px;
            font-size: 0.8rem; color: #666; text-align: center; }}
  code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px;
         font-family: ui-monospace, monospace; font-size: 0.85em; }}
</style>

<h1>{framework}</h1>
<p class="meta">Generated: <code>{generated}</code><br>
Reporting window: last {evidence.get('window_days', '—')} days<br>
Source: AegisIQ SIEM & SOAR — live database evidence.</p>

<h2>Controls Evidence</h2>
{controls_html}
{processing_html}

<div class="footer">
  This report was generated automatically from AegisIQ's audit log,
  detection engine, and configuration tables. Evidence is real — no
  fabricated data. Present to your external auditor together with the
  process artifacts they request (onboarding SOP, IR runbook, vendor
  DPAs).
</div>
"""


def _render_control(c: dict) -> str:
    control_id = html.escape(str(c.get("control_id", "?")))
    title = html.escape(str(c.get("title", "")))
    status = html.escape(str(c.get("status", "partial")))
    narrative = html.escape(str(c.get("narrative", "")))
    gap = c.get("gap")
    ev_rows = "\n".join(
        f"<tr><td>{html.escape(str(e.get('metric', '')))}</td>"
        f"<td><code>{html.escape(_val_to_str(e.get('value')))}</code></td></tr>"
        for e in c.get("evidence", [])
    )
    gap_html = f'<div class="gap"><b>Customer must supply:</b> {html.escape(str(gap))}</div>' if gap else ""
    return f"""<div class="control">
  <h3>{control_id} — {title}
    <span class="status {status}">{status.upper()}</span>
  </h3>
  <table class="evidence-table">{ev_rows}</table>
  <div class="narrative">{narrative}</div>
  {gap_html}
</div>"""


def _render_processing(evidence: dict) -> str:
    activities = evidence.get("processing_activities", [])
    html_parts = ["<h2>Records of Processing Activities</h2>"]
    for a in activities:
        html_parts.append(f'<div class="control"><h3>{html.escape(a.get("activity",""))}</h3>')
        html_parts.append(f'<div class="narrative">{html.escape(a.get("purpose",""))}</div>')
        html_parts.append('<table class="evidence-table">')
        for key in ("categories_of_data_subjects", "categories_of_personal_data",
                    "recipients", "retention", "security_measures", "record_count_snapshot"):
            if key in a:
                html_parts.append(
                    f'<tr><td>{key.replace("_", " ")}</td>'
                    f'<td><code>{html.escape(_val_to_str(a[key]))}</code></td></tr>'
                )
        html_parts.append("</table></div>")
    if "data_subject_rights_support" in evidence:
        html_parts.append("<h3>Data-Subject Rights Support</h3>")
        html_parts.append('<table class="evidence-table">')
        for right, method in evidence["data_subject_rights_support"].items():
            html_parts.append(
                f'<tr><td>{html.escape(right)}</td>'
                f'<td><code>{html.escape(str(method))}</code></td></tr>'
            )
        html_parts.append("</table>")
    return "\n".join(html_parts)


def _val_to_str(v: Any) -> str:
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False, default=str)
    return str(v)
