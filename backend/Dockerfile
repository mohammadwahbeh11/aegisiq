FROM python:3.11-slim

# The container mounts <repo>/backend at /app (see docker-compose.yml).
# Working directory sits at /app so the `app` package resolves as
# `app.main`, matching how the code is imported everywhere else.
WORKDIR /app

# Install system deps needed by bcrypt/cryptography wheels on slim images.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The rest of the backend is bind-mounted by docker-compose, but a copy
# is baked in too so the image can run standalone without a mount.
COPY . .

# SQLite lives under /app/data. Create it in the image so a bare
# `docker run` (Render's free tier: no bind mount) still has a writable
# directory for the DB.
RUN mkdir -p /app/data

EXPOSE 8000

# Boot the REAL FastAPI backend (app/main.py), NOT the legacy
# in-memory prototype at /app/main.py. The prototype file is kept
# only for historical reference and is never launched.
# Use $PORT if the host injects one (Render, Koyeb, Fly.io, …); default to
# 8000 for docker-compose and bare `docker run`. Shell form so ${PORT:-8000}
# actually expands at container start.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
