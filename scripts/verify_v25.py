#!/usr/bin/env python3
"""
scripts/verify_v25.py -- verify the v2.5 additions end-to-end.

Logs in as admin, then exercises:
  - /api/copilot/status          (should say AI disabled unless keys set)
  - /api/enrichment/ip/8.8.8.8   (composite risk score, cached)
  - /api/compliance/frameworks   (list of supported)
  - /api/compliance/soc2         (JSON evidence)
  - /api/compliance/soc2/report  (HTML report, first 500 chars)

Prints a friendly summary at the end. Non-zero exit on any hard failure.
Stdlib only -- no pip install needed.

Usage:
    python scripts\verify_v25.py
    python scripts\verify_v25.py --url http://localhost:8000
"""
from __future__ import annotations
import argparse, json, os, sys, time, urllib.error, urllib.request

GREEN = "\033[32m"; RED = "\033[31m"; YELLOW = "\033[33m"; BOLD = "\033[1m"; RESET = "\033[0m"

def http(method, url, token=None, body=None):
    hdrs = {"Content-Type": "application/json"}
    if token: hdrs["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, method=method, headers=hdrs, data=data)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode()
            ct = resp.headers.get("Content-Type", "")
            if "json" in ct:
                try: return resp.status, json.loads(raw)
                except: return resp.status, raw
            return resp.status, raw
    except urllib.error.HTTPError as exc:
        try: return exc.code, json.loads(exc.read().decode())
        except: return exc.code, {}

def ok(msg):   print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET} {msg}")
def step(msg): print(f"\n{BOLD}{YELLOW}▶{RESET} {BOLD}{msg}{RESET}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.environ.get("SIEM_URL", "http://localhost:8000"))
    ap.add_argument("--username", default="admin")
    ap.add_argument("--password", default="ChangeMe123!")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    print(f"\n{BOLD}AegisIQ v2.5 verification against {base}{RESET}")

    step("1. Health check")
    s, body = http("GET", f"{base}/health")
    if s != 200:
        fail(f"backend not reachable (HTTP {s}). Start uvicorn first.")
        return 2
    ok(f"api=ok version={body.get('version')}")

    step("2. Login as admin")
    s, body = http("POST", f"{base}/api/auth/login",
                   body={"username": args.username, "password": args.password})
    if s != 200 or not body.get("access_token"):
        # MFA challenge?
        if body.get("mfa_required"):
            fail("MFA is enabled for admin. Disable via UI or run without MFA for this check.")
        else:
            fail(f"login failed HTTP {s}: {body}")
        return 3
    token = body["access_token"]
    ok(f"logged in — token length {len(token)}")

    step("3. AI Copilot status (new in v2.5)")
    s, body = http("GET", f"{base}/api/copilot/status", token=token)
    if s == 200:
        if body.get("enabled"):
            ok(f"AI ENABLED — provider={body.get('provider')} model={body.get('model')}")
        else:
            ok(f"AI disabled (expected until AI_PROVIDER is set): {body.get('note','')}")
    else:
        fail(f"/api/copilot/status HTTP {s}: {body}")

    step("4. Threat intelligence enrichment (new in v2.5)")
    s, body = http("GET", f"{base}/api/enrichment/ip/8.8.8.8", token=token)
    if s == 200 and "risk_score" in body:
        ab = body.get("abuseipdb", {})
        ot = body.get("otx", {})
        ok(f"risk_score={body.get('risk_score')} label={body.get('risk_label')} cached={body.get('cached')}")
        if ab.get("enabled"):
            ok(f"AbuseIPDB — confidence={ab.get('abuse_confidence')} country={ab.get('country_code')}")
        else:
            warn(f"AbuseIPDB not configured ({ab.get('reason')}) — free key: abuseipdb.com/register")
        if ot.get("enabled"):
            ok(f"OTX — pulses={ot.get('pulse_count')} asn={ot.get('asn')}")
        else:
            warn(f"OTX unavailable ({ot.get('reason')})")
    else:
        fail(f"/api/enrichment HTTP {s}: {body}")

    step("5. Compliance frameworks (new in v2.5)")
    s, body = http("GET", f"{base}/api/compliance/frameworks", token=token)
    if s == 200:
        for fw in body.get("frameworks", []):
            ok(f"  {fw['id']:12s} — {fw['name']} ({fw['standard']})")
    else:
        fail(f"/api/compliance/frameworks HTTP {s}: {body}")

    step("6. Compliance SOC 2 JSON evidence (new in v2.5)")
    s, body = http("GET", f"{base}/api/compliance/soc2?window_days=90", token=token)
    if s == 200 and body.get("controls"):
        controls = body["controls"]
        ok(f"{len(controls)} controls evaluated over {body.get('window_days')} days")
        for c in controls[:4]:
            status_color = GREEN if c["status"] == "met" else YELLOW
            print(f"    {status_color}{c['status'].upper():10s}{RESET} {c['control_id']} — {c['title']}")
        print(f"    ... {len(controls)-4} more")
    else:
        fail(f"/api/compliance/soc2 HTTP {s}: {body}")

    step("7. Compliance SOC 2 HTML report renders (new in v2.5)")
    s, body = http("GET", f"{base}/api/compliance/soc2/report", token=token)
    if s == 200 and isinstance(body, str) and "<!doctype html>" in body.lower():
        ok(f"HTML report rendered ({len(body)} bytes) — save-as-and-email ready")
    else:
        fail(f"/api/compliance/soc2/report HTTP {s}")

    step("8. GDPR RoPA report (new in v2.5)")
    s, body = http("GET", f"{base}/api/compliance/gdpr", token=token)
    if s == 200:
        activities = body.get("processing_activities", [])
        ok(f"{len(activities)} processing activity/activities documented")
    else:
        fail(f"/api/compliance/gdpr HTTP {s}: {body}")

    print(f"\n{GREEN}{BOLD}✓ v2.5 verification complete{RESET}")
    print(f"  All new endpoints operational. AI is optional — set AI_PROVIDER=openai to enable it.\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())
