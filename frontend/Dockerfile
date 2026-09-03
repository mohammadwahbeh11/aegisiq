# Multi-stage build: install deps + build the React bundle with Vite,
# then serve the static output through nginx. The previous single-stage
# `nginx:alpine COPY .` never ran Vite, so the container served the raw
# TypeScript sources instead of the compiled bundle.

# ---- Stage 1: build the React bundle ---------------------------------------
FROM node:20-alpine AS build

WORKDIR /app

# npm ci needs both files, and reproducible installs need the lockfile.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .

# VITE_API_URL is baked in at build time. Override at build:
#   docker build --build-arg VITE_API_URL=http://<host-ip>:8000 ...
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build

# ---- Stage 2: serve the built assets --------------------------------------
FROM nginx:alpine AS runtime

# Small SPA-friendly nginx config so refreshing on /alerts/42 doesn't 404.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
