FROM python:3.11-slim

# NOTE ON BUILD CONTEXT: this Dockerfile expects the REPOSITORY ROOT as its
# context, not ./backend. The reason is sigma_rules/, which lives at the repo
# root and is part of the running application (app/detection/sigma.py loads
# it at analysis time). With a ./backend context those rules are outside the
# context and cannot be COPYed, so the Sigma engine silently finds an empty
# directory and disables itself in every container build.
#
#   docker build -f backend/Dockerfile .          <-- correct
#   docker build ./backend                        <-- Sigma rules missing
#
# docker-compose.yml and render.yaml both set the context accordingly.

WORKDIR /app

# Install system deps needed by bcrypt/cryptography wheels on slim images.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The backend package. docker-compose additionally bind-mounts the host's
# ./backend over /app so local edits take effect on restart; the baked copy
# is what Render and a bare `docker run` actually execute.
COPY backend/ .

# Sigma rules go under /opt, deliberately NOT under /app: the compose bind
# mount of ./backend onto /app would shadow anything placed inside it, so a
# developer running compose would lose the rules the image ships.
COPY sigma_rules/ /opt/aegisiq/sigma_rules/
ENV SIGMA_RULES_DIR=/opt/aegisiq/sigma_rules

# SQLite lives under /app/data. Created in the image so a bare `docker run`
# (and Render's free tier, which has no mountable disk) still has a writable
# directory. app/config.py derives its default DB path from the source tree,
# which resolves to "/" inside this image — so pin it explicitly here rather
# than relying on that default.
RUN mkdir -p /app/data
ENV DATABASE_URL=sqlite:////app/data/siem.db

EXPOSE 8000

# Boot the REAL FastAPI backend (app/main.py), NOT the legacy in-memory
# prototype at /app/main.py, which is kept only for historical reference.
# Shell form so ${PORT:-8000} expands at container start: Render, Koyeb and
# Fly all inject $PORT dynamically, while compose and `docker run` get 8000.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
