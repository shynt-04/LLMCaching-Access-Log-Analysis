FROM node:22-alpine AS web-build

WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV LOG_INPUT_DIR=/app/input
ENV LOG_SOURCE=auto
ENV USE_CACHE=true
ENV AUTO_START_ANALYSIS=true

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY api ./api
COPY src ./src
COPY data/models/lgbm_content.pkl ./data/models/lgbm_content.pkl
COPY data/rules ./data/rules
COPY data/cve_lookup.json ./data/cve_lookup.json
COPY --from=web-build /app/web/dist ./web/dist

RUN mkdir -p /app/input

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
