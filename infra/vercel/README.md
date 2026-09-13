# AegisIQ + Vercel — frontend hosting (free tier)

## Why

Render's free tier serves the frontend from the same container as the backend — cold-start is ~800 ms even for a static page. Vercel serves the same files from a global CDN with ~40 ms latency in MENA.

**Free tier:** 100 GB bandwidth/month, unlimited builds, global CDN, automatic HTTPS.

## Setup (5 minutes)

### Step 1 — Sign up

1. Open <https://vercel.com/signup>
2. Sign in with GitHub (no card required)
3. When Vercel asks for permission to your GitHub, allow it — it needs to read `mohammadwahbeh11/aegisiq`.

### Step 2 — Import the repo

1. Vercel Dashboard → **Add New** → **Project**
2. Find `mohammadwahbeh11/aegisiq` → **Import**
3. In the "Configure Project" screen, set:
   - **Framework Preset:** `Vite`
   - **Root Directory:** click **Edit** → type `frontend` → **Continue**
   - **Build Command:** `npm run build` (auto-detected)
   - **Output Directory:** `dist` (auto-detected)
   - **Install Command:** `npm ci`

### Step 3 — Environment variables

Expand **Environment Variables** and add:

| Name | Value |
|---|---|
| `VITE_API_URL` | `https://aegisiq-backend.onrender.com` |
| `VITE_STRIPE_PRO_PRICE_ID` | *your Stripe Price ID (once created), or leave blank* |

Click **Deploy**. Wait ~90 seconds — build succeeds and Vercel gives you `aegisiq-XXXXX.vercel.app`.

### Step 4 — Add your custom domain (once you register `aegisiq.io`)

1. Vercel project → **Settings** → **Domains** → **Add**
2. Enter `app.aegisiq.io` → **Add**
3. Vercel shows a `CNAME` record → go to Cloudflare DNS → add it:
   - **Type:** CNAME
   - **Name:** `app`
   - **Target:** `cname.vercel-dns.com`
   - **Proxy status:** DNS only (grey cloud) — Vercel handles TLS
4. Wait 30 seconds → Vercel auto-issues Let's Encrypt cert → live at `https://app.aegisiq.io`

### Step 5 — Update CORS on the backend

On Render → `aegisiq-backend` → **Environment**:

```
CORS_ORIGINS=https://app.aegisiq.io,https://*.vercel.app,http://localhost:5173
```

Save → Render redeploys → the new Vercel frontend can now call the backend.

### Step 6 — Turn off the frontend on Render (optional)

Once Vercel is live and working, you can delete the frontend service on Render — it saves you nothing on the free tier but keeps the dashboard cleaner.

## What you get vs Render

| Metric | Render Free (frontend) | Vercel Free |
|---|---|---|
| Cold-start latency | 400-800 ms | 0 ms (always warm) |
| MENA latency (RTT) | ~700 ms | ~40 ms |
| Bandwidth | 100 GB / mo | 100 GB / mo |
| Custom domain | Paid tier only | Free |
| Preview deployments | No | Yes — every PR gets its own URL |
| Analytics | No | Free basic tier |

## Preview deployments

Every push to a non-main branch on GitHub triggers a Vercel preview build with a unique URL like `aegisiq-git-feature-name-user.vercel.app`. Share it with a design partner without touching production.

## Cost projection

- **Under 100 GB/mo** (typical for 10k monthly active users): $0
- **Pro plan** ($20/mo per member): 1 TB bandwidth, analytics, password protection
- **Enterprise** (custom): dedicated CDN, SLA
