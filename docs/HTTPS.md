# AegisIQ — Secure HTTPS / TLS

> How to run the console and API over an encrypted TLS connection —
> locally with a self-signed certificate, or in production behind a
> CA-issued certificate. Complements the at-rest encryption (AES-256-GCM,
> see `SECURITY.md`): this is **data-in-transit** protection.

---

## 1 · Why

Without TLS, JWTs, passwords and log data cross the wire in cleartext —
anyone on the path (a lab switch, a coffee-shop Wi-Fi) can read the bearer
token and impersonate the analyst. TLS encrypts the whole channel: REST
and the live WebSocket alert stream both.

The frontend already derives the stream scheme from the API scheme:
`streamUrl()` turns `https://` into `wss://` automatically, so switching
to TLS needs no WebSocket code change.

## 2 · Local development (self-signed, one command)

```bash
# 1. Generate a self-signed cert (localhost + 127.0.0.1 SANs, 825 days)
./scripts/generate_certs.sh              # Windows: scripts\generate_certs.ps1

# 2. Run the backend over TLS  ->  https://localhost:8443
./scripts/run_https.sh                   # Windows: scripts\run_https.ps1

# 3. Point the console at it
#    frontend/.env :  VITE_API_URL=https://localhost:8443
```

The browser warns once ("your connection is not private") because the cert
is self-signed — click through (Advanced → Proceed), or trust
`certs/aegis.crt` in your OS/browser trust store to silence it. This is
expected for a lab and does **not** weaken the encryption; it only means
the cert isn't signed by a public CA.

**Mixed content:** an `http://localhost:5173` page is allowed to call an
`https://localhost:8443` backend, so you can keep the plain Vite dev server
and only put the backend on TLS. Browsers block the reverse (https page →
http API), never this direction.

## 3 · Docker

```bash
./scripts/generate_certs.sh
docker compose -f docker-compose.yml -f docker-compose.https.yml up --build
# backend now on https://localhost:8443
```

The overlay (`docker-compose.https.yml`) mounts `./certs` read-only and
restarts uvicorn with `--ssl-keyfile/--ssl-certfile`.

## 4 · Verifying it

```bash
# smoke test against the TLS listener (skips cert verification for the
# self-signed local cert; add --verify-tls to enforce a trusted chain)
python scripts/smoke_test.py --url https://localhost:8443

# or a raw check
curl -k https://localhost:8443/health
```

`smoke_test.py` auto-detects an `https://` URL and disables certificate
verification so the self-signed cert doesn't block the run; it prints a
one-line notice when it does. Pass `--verify-tls` once you have a real
(trusted) certificate to confirm the chain validates.

## 5 · Production

Do **not** ship the self-signed cert. Two supported patterns:

1. **TLS at a reverse proxy (recommended).** Put Caddy, nginx or Traefik in
   front; it terminates TLS with a CA-issued cert (Let's Encrypt / your
   internal CA) and forwards to the backend on the internal network. The
   app needs no cert of its own. Set `CORS_ORIGINS` to the public https
   origin and `VITE_API_URL` to the public https URL.
2. **TLS at uvicorn.** Pass a CA-issued `--ssl-keyfile/--ssl-certfile`
   (same flags as the local run). Simplest for a single node.

Either way, in production also set (see `SECURITY.md` / `config.py`
`validate_production_security()`):

- a strong `SECRET_KEY` and a real `DEFAULT_ADMIN_PASSWORD`,
- `DATA_ENCRYPTION_KEY` for at-rest encryption,
- `CORS_ORIGINS` pinned to the exact https origin (never `*`),
- HSTS at the proxy (`Strict-Transport-Security`) so browsers refuse to
  downgrade to http.

## 6 · Certificate files

| File | What | Commit? |
|---|---|---|
| `certs/aegis.key` | private key | **NO** — `.gitignore`d |
| `certs/aegis.crt` | public certificate | no (regenerate locally) |

`certs/` is ignored by git; each developer generates their own. Never
commit a private key.

*See also: `SECURITY.md` (auth, MFA, at-rest encryption),
`HOW_IT_WORKS.md` (architecture).*
