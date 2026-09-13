# AegisIQ + Supabase — production database (free tier)

## Why

Render's free tier has ephemeral disk — SQLite loses data on redeploy or after 15 min idle. Supabase gives you real Postgres for free, permanent.

**Free tier:** 500 MB storage, unlimited API requests, no credit card.

## 3-step setup (10 minutes)

### Step 1 — Create the Supabase project

1. Open <https://supabase.com> → **Start your project**
2. Sign in with GitHub (no card required)
3. Click **New project**
4. Fill:
   - **Name:** `aegisiq-prod`
   - **Database Password:** *use a strong one — you can't recover it later*
   - **Region:** closest to your Render backend (Render Oregon → Supabase West US)
   - **Pricing plan:** Free
5. Click **Create new project**. Wait ~2 minutes for provisioning.

### Step 2 — Run the schema

1. In Supabase Studio → **SQL Editor** (left sidebar)
2. Click **+ New query**
3. Paste the entire contents of `schema.sql` (in this folder)
4. Click **Run** (bottom-right, or Ctrl+Enter)
5. Confirm you see "Success. No rows returned" — all 6 tables now exist.

### Step 3 — Connect Render backend to Supabase

1. In Supabase → **Project Settings** → **Database** → scroll to **Connection string**
2. Choose **URI** tab, click **Copy**. Format:
   ```
   postgresql://postgres:[YOUR-PASSWORD]@db.xxxxxxxxxxxxxx.supabase.co:5432/postgres
   ```
3. Replace `[YOUR-PASSWORD]` with the password you set in Step 1.
4. On Render → `aegisiq-backend` → **Environment** → edit `DATABASE_URL` → paste it → **Save Changes**
5. Also add `psycopg2-binary>=2.9` to `backend/requirements.txt`, commit, push. Render redeploys.

### Step 4 — Verify

1. Watch Render logs. You should see:
   ```
   ✔ Connected to Postgres at db.xxxxxxxxxxxxxx.supabase.co
   ✔ First admin user created (username=admin)
   ```
2. Log into the site — refresh once — your data now survives every restart.

## Migrate existing SQLite data (optional)

If you have working SQLite data on Render you want to preserve:

```bash
# On your local machine, download the SQLite file from Render:
# (Render → aegisiq-backend → Shell → cd data && cat siem.db > /tmp/dump ...)
# Then locally:
sqlite3 siem.db .dump > dump.sql

# Clean up SQLite-only statements:
grep -v -E "^(PRAGMA|BEGIN TRANSACTION|COMMIT)" dump.sql | \
  sed 's/AUTOINCREMENT/SERIAL/g' | \
  sed 's/DATETIME/TIMESTAMPTZ/g' > clean.sql

# Paste `clean.sql` into Supabase SQL Editor. Small datasets migrate in seconds.
```

For larger migrations use `pgloader` (10× faster):

```bash
docker run --rm dimitri/pgloader:latest \
  pgloader sqlite:///data/siem.db \
           postgresql://postgres:PASSWORD@db.xxxxxx.supabase.co:5432/postgres
```

## Backup

Supabase runs daily backups on the Pro tier ($25/mo). Free tier: use `pg_dump`:

```bash
pg_dump "postgresql://postgres:PASSWORD@db.xxxxxx.supabase.co:5432/postgres" \
  > aegisiq_backup_$(date +%Y%m%d).sql
```

Schedule this in GitHub Actions once a day.

## Scaling

- **Free tier** = 500 MB storage. AegisIQ typical footprint: 1 GB per 1M events.
- Beyond 500 MB → upgrade to **Pro** ($25/mo, 8 GB) or migrate `log_events` to ClickHouse (see `docs/STORAGE.md`).
- Relational tables (users, rules, alerts, audit) always stay in Postgres — never migrate those away.
