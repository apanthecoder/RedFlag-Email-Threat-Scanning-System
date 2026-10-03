# Two stages: build the React app with Node, then run Flask with Python and
# serve that build from it. Render's Python runtime has no guaranteed Node,
# and one image keeps the site and the API on a single address, which the
# SameSite=Lax session cookies need.

FROM node:20-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# Baked in at build time: the browser then calls the API on whatever address
# it loaded the page from.
ENV VITE_API_URL=/api
RUN npm run build

FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ backend/
COPY --from=frontend /app/frontend/dist frontend/dist

WORKDIR /app/backend

# One worker with threads: the login rate limiter counts attempts in memory
# and scans run in background threads, so a second worker process would
# split both. PORT is set by the host.
CMD gunicorn --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:${PORT:-10000} app:app
