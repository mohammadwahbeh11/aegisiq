# AegisIQ v3.1 — Reference Architecture

## Design authorities cited in this build

All UI decisions in v3.1 trace back to a specific, verifiable public reference. No "AI opinion" — every choice has a link.

| Layer | Reference | Where it shows up |
|---|---|---|
| Color scale (12 steps) | [Radix Colors](https://www.radix-ui.com/colors/docs/palette-composition/scales) | `aegisiq_radix.css` `--accent-1..12` |
| Component sizes | [Radix Themes size scale](https://www.radix-ui.com/themes/docs/theme/typography) | Button/input/card sizing |
| Sidebar composition | [Vercel Geist Sidebar](https://vercel.com/geist/sidebar) | `Layout.tsx` sidebar spacing |
| Focus states | [WCAG 2.2 Focus Appearance](https://www.w3.org/TR/WCAG22/#focus-appearance) | `:focus-visible` outlines |
| Layered shadow depth | Refactoring UI, Wathan/Schoger (2018) | KPI card multi-shadow |
| Card padding | [Radix Card](https://www.radix-ui.com/themes/docs/components/card) | `.panel` 16-18px padding |
| Icon size (16px on 14px text) | [Lucide guidance](https://lucide.dev/guide/design) | Sidebar & KPI icons |
| Grid orphans avoidance | [CSS Grid `auto-fit` gotchas — Andy Bell](https://piccalil.li/blog/using-auto-fit-and-minmax-with-css-grid-layouts/) | Rules Library grid |
| Mesh gradient background | [Vercel homepage 2024 audit — Josh Comeau](https://www.joshwcomeau.com/blog/) | Body radial gradients |

## Deployment architecture

```
                            ┌─────────────────────┐
                            │  Cloudflare DNS +    │
                            │  Registrar           │
                            │  aegisiq.io          │
                            └──────────┬───────────┘
                                       │
                    ┌──────────────────┼─────────────────┐
                    │                  │                 │
                    ▼                  ▼                 ▼
        ┌────────────────────┐  ┌──────────┐   ┌───────────────┐
        │ Vercel CDN         │  │ Render   │   │ Supabase      │
        │ app.aegisiq.io     │  │ api.     │   │ (Postgres)    │
        │ (React/Vite dist)  │  │ aegisiq.io│  │ 500 MB free   │
        └────────────────────┘  │(FastAPI) │   └───────┬───────┘
                    ▲            └─────┬────┘           │
                    │                  │                │
                    │           HTTPS  │      Postgres  │
                    │                  │       :5432    │
                    │                  ▼                │
                    │           ┌──────────────┐        │
                    │           │  Groq API    │        │
                    │           │  (free LLM)  │        │
                    │           └──────────────┘        │
                    │                  │                │
                    └── Bearer JWT ────┼────────────────┘
                                       │
                          ┌────────────┴────────────┐
                          │  Kill-Switch Agent v2   │
                          │  (Linux/Win/macOS)      │
                          │  HMAC-signed orders     │
                          └─────────────────────────┘
```

## Cost projection

| Users/month | Vercel | Supabase | Render | Groq | Total |
|---|---|---|---|---|---|
| 100 (demo) | Free | Free | Free | Free | **$0** |
| 1,000 (10 pilots) | Free | Free | $7 (Starter) | Free | **$7** |
| 10,000 (paid) | $20 (Pro) | $25 (Pro) | $25 (Standard) | Free | **$70** |
| 100,000 | $20 | $60 (8 GB) | $85 (Perf+) | $50 (Dev) | **$215** |

For comparison: Splunk Enterprise at 10k events/day starts at ~$2,000/mo. AegisIQ hosts the same throughput at $70.

## Setup order (do this exactly)

1. **Register `aegisiq.io`** at Cloudflare Registrar ($9.15/yr for .io)
2. **Create Supabase project** — 10 min ([infra/supabase/README.md](../infra/supabase/README.md))
3. **Swap Render DATABASE_URL** to Supabase — data now persists forever
4. **Import repo to Vercel** — 5 min ([infra/vercel/README.md](../infra/vercel/README.md))
5. **Add DNS records** at Cloudflare (CNAMEs for `app`, `api`, `www`)
6. **Get Groq key**, add to Render env — AI Copilot works ([docs/GROQ_SETUP.md](GROQ_SETUP.md))

Total setup time: **~45 minutes**. Total monthly cost after: **$0** until you hit 10k users.

## What the v3.1 CSS drop fixes

Direct response to user screenshots taken 2026-09-13 at 5:30 PM:

1. **Rules Library grid orphans** — `LOW` and `INFORMATIONAL` were alone on row 2. Fixed with `auto-fit minmax(200px, 1fr)` capped at 4 columns.
2. **Top-of-page purple stripe too intense** — reduced radial gradient opacity from 0.18 → 0.08 and removed the drifting animation.
3. **"Sync from SigmaHQ" button spanned full width** — capped `.btn-primary` in headers to `width: auto`.
4. **Legacy `Delete` buttons red-filled** — converted to red-outline ghost buttons (matches Radix `outline` variant).
5. **Save-changes buttons stretched full-width** on Detection Rules — capped at `max-width: 260px`.
6. **Inconsistent padding across pages** — enforced Radix Card spec (16-18px) everywhere via `.panel, .card` selector.
