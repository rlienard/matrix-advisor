# Matrix Advisor: web UI + API in one image.

FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    MA_CONFIG=/data/config.yaml MA_STATIC_DIR=/app/ui MA_PORT=8000
WORKDIR /app
COPY backend/pyproject.toml /app/
COPY backend/matrix_advisor /app/matrix_advisor
RUN pip install --no-cache-dir /app && mkdir -p /data /flows
COPY --from=ui /ui/dist /app/ui
COPY deploy /app/deploy
EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["matrix-advisor"]
