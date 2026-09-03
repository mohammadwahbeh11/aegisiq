# Deployment & sharing guide

Three ways to let someone else try your Lightweight SIEM — ordered from
"5-minute demo link" to "permanent public URL" to "self-hostable Docker
image anyone can run".

Pick the one that matches your goal. All three can coexist.

---

## Option A — Ngrok tunnel (5 minutes, best for a graduation defense demo)

Ngrok exposes your **localhost** through a public `https://` URL. The
person you send the link to opens it in their browser, and they are
talking to the SIEM running on your laptop. It works even behind NAT or
university Wi-Fi. The free tier gives you a randomly-generated URL that
changes every restart — perfect for a live defense.

### 1) Install ngrok on Windows

```powershell
# via winget (Windows 10/11):
winget install --id Ngrok.Ngrok
# or download the .exe from https://ngrok.com/download and put it on PATH
```

Sign up for a free account at <https://ngrok.com>, copy your authtoken
from the dashboard, then:

```powershell
ngrok config add-authtoken <YOUR_TOKEN>
```

### 2) Expose the frontend + backend at once

Create `C:\Users\ASUS\Downloads\lightweight-siem\ngrok.yml`:

```yaml
version: "2"
authtoken: <YOUR_TOKEN>
tunnels:
  frontend:
    proto: http
    addr: 5173
    # No basic-auth — you WANT people to try it. Add basic_auth: user:pass here
    # if you'd rather gate access.
  backend:
    proto: http
    addr: 8000
```

Start both tunnels with one command:

```powershell
ngrok start --config C:\Users\ASUS\Downloads\lightweight-siem\ngrok.yml --all
```

You'll see two public URLs like:

```
frontend  https://a1b2-x-x-x-x.ngrok-free.app -> http://localhost:5173
backend   https://c3d4-x-x-x-x.ngrok-free.app -> http://localhost:8000
```

### 3) Rebuild the frontend so it points at the PUBLIC backend URL

The React bundle bakes `VITE_API_URL` in at build time. When you share
the frontend URL, the browser has to be able to reach the backend from
the outside — so put the ngrok backend URL there, not `localhost`.

Edit `frontend/.env`:

```
VITE_API_URL=https://c3d4-x-x-x-x.ngrok-free.app
```

Also add the frontend URL to backend CORS in `.env`:

```
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,https://a1b2-x-x-x-x.ngrok-free.app
```

Restart both (Ctrl+C then re-run `npm run dev` and `uvicorn ...`).

### 4) Send the frontend URL

Share `https://a1b2-x-x-x-x.ngrok-free.app` + credentials
(`admin / ChangeMe123!` — change them first) with whoever will demo.

**Ngrok caveats (free tier):**
- URL changes on every restart. Use a paid ngrok plan for a reserved
  subdomain, or use Option B below.
- 1 GB/month traffic cap. Fine for demos, not for a running service.
- The ngrok interstitial page appears once per browser session (browser
  warning that this is a tunneled site) — this is normal.

---

## Option B — Cloudflare Tunnel (permanent free public URL)

Cloudflare gives you a permanent `https://siem.<your-domain>` for free,
survives restarts, no traffic cap. Needs a Cloudflare account and any
domain (a free `.pages.dev` won't work — Cloudflare Tunnel needs a
real domain, which you can get free at <https://freenom.com> or for
$1/year at <https://porkbun.com>).

### 1) Install cloudflared on Windows

```powershell
winget install --id Cloudflare.cloudflared
```

### 2) Authenticate and create a tunnel

```powershell
cloudflared tunnel login          # opens browser -> pick your domain
cloudflared tunnel create siem
```

This writes a JSON credentials file whose path is printed — copy the
path, you'll paste it into the config below.

### 3) Configure the tunnel

Create `C:\Users\ASUS\.cloudflared\config.yml`:

```yaml
tunnel: <TUNNEL_UUID_FROM_STEP_2>
credentials-file: C:\Users\ASUS\.cloudflared\<TUNNEL_UUID>.json

ingress:
  - hostname: siem.your-domain.com
    service: http://localhost:5173
  - hostname: siem-api.your-domain.com
    service: http://localhost:8000
  - service: http_status:404
```

### 4) Route DNS and run

```powershell
cloudflared tunnel route dns siem     siem.your-domain.com
cloudflared tunnel route dns siem     siem-api.your-domain.com
cloudflared tunnel run siem
```

Rebuild the frontend with `VITE_API_URL=https://siem-api.your-domain.com`
and add it to CORS the same way as Option A. Done — the URL is
permanent and free.

**Optional:** run cloudflared as a Windows service so the tunnel stays
up after logout:

```powershell
cloudflared service install
```

---

## Option C — Docker image on Docker Hub (self-hostable)

Anyone with Docker can run your SIEM with a single command. This is what
a graduation project's "how to install" section wants.

### 1) Build and tag the image

From the project root:

```powershell
cd C:\Users\ASUS\Downloads\lightweight-siem

# Backend image (uses your existing backend/Dockerfile)
docker build -t <your-dockerhub-username>/lightweight-siem-backend:1.0 ./backend

# Frontend image (multi-stage build baked with a placeholder API URL —
# consumers override VITE_API_URL at build time if needed)
docker build --build-arg VITE_API_URL=http://localhost:8000 `
             -t <your-dockerhub-username>/lightweight-siem-frontend:1.0 ./frontend
```

### 2) Push to Docker Hub

```powershell
docker login
docker push <your-dockerhub-username>/lightweight-siem-backend:1.0
docker push <your-dockerhub-username>/lightweight-siem-frontend:1.0
```

### 3) Ship a one-command run recipe

Publish this `docker-compose.public.yml` in your repo README:

```yaml
services:
  backend:
    image: <your-dockerhub-username>/lightweight-siem-backend:1.0
    ports: ["8000:8000"]
    volumes: ["./data:/app/data"]
    environment:
      DATABASE_URL: "sqlite:////app/data/siem.db"
      SECRET_KEY: "change-me-in-production"
      DEFAULT_ADMIN_PASSWORD: "ChangeMe123!"
      CORS_ORIGINS: "http://localhost:5173"

  frontend:
    image: <your-dockerhub-username>/lightweight-siem-frontend:1.0
    ports: ["5173:80"]
    depends_on: [backend]
```

Anyone can then run:

```bash
mkdir siem-demo && cd siem-demo
curl -O https://raw.githubusercontent.com/<you>/<repo>/main/docker-compose.public.yml
docker compose -f docker-compose.public.yml up
```

Open <http://localhost:5173>, log in `admin / ChangeMe123!`. Done.

---

## Which option should you pick?

| Goal | Use |
| --- | --- |
| Demo for graduation defense — 30 minutes on a Zoom link | **Ngrok (A)** |
| Send to a colleague to test all week from their laptop | **Cloudflare Tunnel (B)** |
| Publish so anyone with Docker can install | **Docker Hub (C)** |
| Real-world deployment on a lab network with fixed IPs | **Neither — see `README.md` "Developer flow"** |

For a graduation project, do **A + C**: ngrok for the live defense demo,
Docker Hub for the "how to install" section of your written thesis.

---

## Security checklist BEFORE sharing publicly

Whichever option you pick, do these first — the demo defaults are
open on purpose so they need tightening before public exposure.

- [ ] **Change the admin password** from the console immediately (Login →
      Rules → Users? or from the API: `PATCH /api/users/me`). The
      shipped `admin / ChangeMe123!` is a well-known default; anyone
      with the URL can log in until you change it.
- [ ] **Rotate `SECRET_KEY`** in `.env` to a real random string:
      `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- [ ] **Narrow `CORS_ORIGINS`** to only the URL you're sharing — remove
      `http://localhost` from the list once you're on a public URL.
- [ ] **Keep `SOAR_EXECUTE=false`** (default). Never set it to true on
      a public URL — the shipped code records containment, doesn't
      execute it, but the flag exists for a future executor and you do
      not want to hand strangers a "block IP" button.
- [ ] **Set the correct backend URL** in the frontend bundle so the
      console talks to the right host — otherwise the browser will try
      `localhost:8000` from the visitor's machine and see nothing.
- [ ] **If you accept real traffic**, put a reverse proxy in front
      (Nginx / Caddy / Cloudflare) for TLS termination and rate limiting.

Once the checklist is done, share the URL.
