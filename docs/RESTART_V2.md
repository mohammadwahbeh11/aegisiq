# AegisIQ v2.0 — Restart from Scratch

Follow this exact sequence to bring AegisIQ v2.0 up on a machine that
previously ran v1.x, without carrying over any old alerts/logs so the
demo starts on a clean slate.

## 0. Stop everything

In every open terminal:

```powershell
# In the backend terminal:  Ctrl+C
# In the frontend terminal: Ctrl+C
```

If you used Docker for v1:

```powershell
docker compose down
```

## 1. Wipe the demo database (optional but recommended)

Delete the SQLite file. The backend will re-create it with the fresh
v2.0 schema on first startup and re-seed:

```powershell
cd C:\Users\ASUS\Downloads\lightweight-siem
Remove-Item .\data\siem.db -ErrorAction SilentlyContinue
```

If you want to keep v1 data, skip this step — the schema migration is
additive and idempotent. Existing rules/alerts/logs will remain; the
three new v2.0 rules are added, and the `audit_log` table is created.

## 2. Regenerate the secret key (recommended for anything beyond a local demo)

Open `.env` at the project root and replace the SECRET_KEY value:

```powershell
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"
```

Paste the output into `.env`.

## 3. Start the backend

```powershell
cd C:\Users\ASUS\Downloads\lightweight-siem
.\venv\Scripts\Activate.ps1
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Look for these lines in the startup output:

```
INFO:     Started server process
INFO:     Application startup complete.
```

## 4. Start the frontend

In a new terminal:

```powershell
cd C:\Users\ASUS\Downloads\lightweight-siem\frontend
npm run dev
```

## 5. Verify

Open your browser at `http://localhost:5173`.

Log in with `admin / ChangeMe123!`, then run this from a third terminal:

```powershell
cd C:\Users\ASUS\Downloads\lightweight-siem
.\venv\Scripts\Activate.ps1
python scripts\smoke_test.py
```

You should see **24 green checks** — the same 19 from v1 plus 5 new
ones for the three v2.0 rules and the security headers + health
posture. The final line should read:

```
✓ all checks passed  (24 checks — 8 rules fire, security headers active, audit + retention work)
```

## 6. Change the admin password immediately

```powershell
$token = (Invoke-RestMethod -Uri http://localhost:8000/api/auth/login `
    -Method Post -ContentType 'application/json' `
    -Body '{"username":"admin","password":"ChangeMe123!"}').access_token

$body = @{
    current_password = 'ChangeMe123!'
    new_password     = 'MyN3wStr0ngPass!2026'   # meets the v2.0 policy
} | ConvertTo-Json

Invoke-RestMethod -Uri http://localhost:8000/api/auth/password `
    -Method Patch -ContentType 'application/json' `
    -Headers @{ Authorization = "Bearer $token" } `
    -Body $body
```

You should see `ok: True`. Sign out of the console and back in with
the new password. The old password is now invalid.

Confirm the audit trail recorded the change: navigate to **Audit log**
(or press `g u`) — you'll see:

- `auth.login.success` (your initial login)
- `auth.password_change` (success)
- `auth.login.success` (your login with the new password)

## 7. Post-restart verification checklist

- [ ] `/health` returns `product: AegisIQ`, `version: 2.0.0`
- [ ] Dashboard shows every KPI computed from live data (or "n/a" honestly)
- [ ] Alerts page shows the 5 alerts the smoke test raised
- [ ] Rules page shows **8 rules** (5 original + 3 new)
- [ ] Audit log page shows every action (only your own if you are an analyst)
- [ ] Sidebar has a theme toggle (☀ / ☾ / System) that cycles
- [ ] Pressing `?` shows the keyboard shortcuts modal
- [ ] Pressing `g d` jumps to Dashboard, `g a` to Alerts, etc.
- [ ] Idle for 13 minutes → warning appears; 15 minutes → auto logout

If every box is checked, v2.0 is up and clean.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ImportError: No module named app.security` | v2.0 files not on disk | Verify `backend/app/security/` exists with 5 files |
| `/health` still says `Lightweight SIEM` | Backend restart missed | Ctrl+C the uvicorn, restart |
| Console still says "Lightweight SIEM" | Vite HMR missed the brand change | Ctrl+F5 in the browser |
| Smoke test fails on rule 20 (web_attack) | v2.0 rules not seeded | Delete `data/siem.db` and restart backend (step 1) |
| 429 Too Many Requests on login | Rate limiter triggered by a script | Wait 30 s or restart the backend |
| Password change 401 with correct password | Copy-paste picked up a trailing space | Retype it |
