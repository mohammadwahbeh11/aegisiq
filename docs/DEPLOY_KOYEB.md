# Deploy AegisIQ backend to Koyeb (always-on, free forever)

> **Why this exists:** Render's free tier sleeps the backend after 15 min
> idle (30-60 s cold start on wake). Koyeb's free tier keeps one web
> service **always on**, no credit card, no sleep. Perfect for the
> AegisIQ backend.
>
> **Architecture after this:**
> - Backend  → `https://<name>-<org>.koyeb.app` (Koyeb, always on)
> - Console  → `https://aegisiq-frontend.onrender.com` (Render, static — never sleeps)
>
> The frontend stays on Render (Render static sites don't sleep). Only the
> backend moves.

---

## Step 1 — Sign up (30 s, no credit card)

1. Go to https://app.koyeb.com/auth/signup
2. Click **Sign up with GitHub** (fastest — same account as Render)
3. Confirm email if asked

## Step 2 — Create the backend service

1. In Koyeb dashboard → **Create Service**
2. Choose **GitHub** as the source
3. Grant Koyeb access to your `aegisiq` repository (Koyeb opens the GitHub
   permissions dialog — approve for this repo)
4. Select the `aegisiq` repository → branch `main`

## Step 3 — Configure the build

Koyeb reads the `backend/Dockerfile` automatically, but tell it where to look:

- **Builder:** `Dockerfile`
- **Work directory:** `backend`     ← important; sets Docker context
- **Dockerfile location:** `Dockerfile`  (relative to work directory)

## Step 4 — Configure the runtime

- **Service type:** `Web service`
- **Instance type:** `Free` (Nano, 0.1 vCPU, 512 MB RAM — enough)
- **Regions:** pick the nearest (Frankfurt for Middle East / Europe)
- **Ports:** Koyeb usually auto-detects; if it asks, set **Port `8000`**,
  Protocol **HTTP**. (The Dockerfile now respects `$PORT` — Koyeb injects
  one and the container binds to it automatically.)

## Step 5 — Environment variables

Add these under **Environment variables** (click "Add variable" for each):

| Key | Value | Secret? |
|---|---|---|
| `SECRET_KEY` | run `openssl rand -hex 32` and paste (or click "Generate" if Koyeb offers it) | ✅ yes |
| `DATA_ENCRYPTION_KEY` | run `openssl rand -hex 32` and paste | ✅ yes |
| `DEFAULT_ADMIN_USERNAME` | `admin` | no |
| `DEFAULT_ADMIN_PASSWORD` | pick a strong one you'll remember; you'll log in with this | ✅ yes |
| `ENV` | `production` | no |
| `SOAR_ENABLED` | `true` | no |
| `SOAR_EXECUTE` | `false` | no |
| `DATABASE_URL` | `sqlite:////app/data/siem.db` | no |
| `CORS_ORIGINS` | `https://aegisiq-frontend.onrender.com` | no |

**On Windows** (no `openssl`), generate a hex key in PowerShell instead:
```powershell
-join ((1..32) | ForEach-Object {'{0:x2}' -f (Get-Random -Max 256)})
```

## Step 6 — Service name & deploy

- **Service name:** `aegisiq-backend`
- **App name:** `aegisiq` (or anything)
- Click **Deploy**.

Koyeb now builds the Docker image (~5-8 min) and boots the service. Once
you see 🟢 **Healthy**, the URL under the service (something like
`https://aegisiq-backend-<yourorg>.koyeb.app`) is live.

**Verify:**
```
https://aegisiq-backend-<yourorg>.koyeb.app/health
```
returns JSON with `"api":"ok"` **instantly** (no cold-start screen).

## Step 7 — Point the Render frontend at the Koyeb backend

The frontend has the old Render backend URL baked in. Update it:

1. In Render dashboard → **aegisiq-frontend** → **Environment**
2. Edit `VITE_API_URL` → set to your Koyeb URL:
   `https://aegisiq-backend-<yourorg>.koyeb.app`
3. Click **Save Changes** → Render redeploys the frontend automatically
   (~3 min).

Also update the backend's `CORS_ORIGINS` (Step 5) if you haven't yet,
and keep both in sync when adding custom domains later.

## Step 8 — Log in

Open `https://aegisiq-frontend.onrender.com`. The "Checking backend"
badge turns 🟢 within a second (the backend is always up now).

- Username: `admin`
- Password: whatever you set as `DEFAULT_ADMIN_PASSWORD` in Step 5
- Immediately open **Security** page → change the password.

## Redeploys

Every `git push` to `main` triggers Koyeb to rebuild the backend
automatically (same behaviour as Render).

## Rollback

Koyeb keeps every deployment. To go back: **Deployments** → click the old
one → **Redeploy**.

---

## Cost check

Koyeb's free tier = 1 Nano service, always on, 100 GB egress/month. AegisIQ
comfortably fits. If you outgrow it, the smallest paid tier ($5.50/mo)
gives you 512 MB → 1 GB and more compute.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Build fails with `no such file: backend/Dockerfile` | Set **Work directory** = `backend` (Step 3) so the build context is `backend/` and the Dockerfile path is `Dockerfile`. |
| `/health` returns 502 for the first minute | First-ever boot; wait a bit. After that Koyeb keeps it warm. |
| Frontend still gets CORS error after Step 7 | You forgot to redeploy the frontend after changing `VITE_API_URL`, OR the backend's `CORS_ORIGINS` doesn't include the frontend URL. Both must match exactly (including `https://`). |
| Login says "cannot reach backend" | Check the new Koyeb URL in a browser tab: `<koyeb-url>/health` should return JSON. |

*See also: `docs/DEPLOY_RENDER.md` (the original Render-only flow),
`docs/SECURITY.md` (production hardening).*
