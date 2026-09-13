# AegisIQ + Firebase Hosting — frontend hosting alternative (free tier)

Only pick this over Vercel if you already use Firebase for other things — Vercel is simpler for a Vite/React app. Documented so you have the option.

**Free tier:** 10 GB storage, 360 MB/day bandwidth, custom domain, automatic HTTPS.

## Setup

### Step 1 — Install the CLI

```powershell
npm install -g firebase-tools
firebase login
```

### Step 2 — Initialize (from repo root)

```powershell
cd "C:\Users\ONE BY ONE\Downloads\lightweight-siem"
firebase init hosting
```

Answer:
- **Use an existing project** → pick or create `aegisiq-prod`
- **Public directory:** `frontend/dist`
- **Configure as single-page app:** `Yes`
- **Set up automatic builds with GitHub:** `Yes` (recommended)
- **Overwrite index.html:** `No`

Firebase generates `firebase.json` and `.firebaserc`. **Replace the generated `firebase.json` with the one from this folder** (adds security headers).

### Step 3 — Build and deploy

```powershell
cd frontend
npm run build
cd ..
firebase deploy --only hosting
```

Firebase gives you `aegisiq-prod.web.app` in ~60 seconds.

### Step 4 — Custom domain

1. Firebase Console → **Hosting** → **Add custom domain**
2. Enter `app.aegisiq.io`
3. Copy the two TXT and A records → add to Cloudflare DNS
4. Wait 5-30 minutes for cert issuance

## Trade-off vs Vercel

| Feature | Firebase | Vercel |
|---|---|---|
| Setup complexity | Higher (CLI + init) | Lower (GitHub connect) |
| Preview deployments | Manual (channels) | Automatic per PR |
| Analytics | Included | Paid tier |
| Bandwidth/month | ~11 GB (360 MB × 30) | 100 GB |
| Best for | Existing Firebase users | Everyone else |
