# LLM-Augmented Web Access Log Analysis System

## Overview

This project provides an access-log analysis tool for detecting web attacks in Apache/Nginx-style logs. The current advisor demo is dashboard-only: when the backend starts, it reads log files from a fixed local `input/` directory, runs the Rule + content-only LightGBM + LLM analysis pipeline, and streams alerts to the React dashboard.

## Runtime Pipeline

1. **Rule-Based Engine**: Fast attack pattern matching with local rules and CRS-derived rules.
2. **Content-Only LightGBM Model**: Scores request content without behavior/bruteforce features.
3. **Attack-Type-Aware Semantic Cache**: Reuses LLM verdicts only when the cache policy accepts the attack type and context.
4. **LLM Analysis**: Runs on cache misses for flagged events and returns structured alert details.
5. **Dashboard**: Shows progress, alert filters, alert details, latency/token metadata, and cache metadata.

## Features

- Dashboard-only demo flow with no user upload page.
- Automatic analysis of files placed in `input/` when the backend starts.
- REST and WebSocket APIs for sessions, progress, alerts, search, and metrics.
- NVIDIA NIM runtime for the current Docker demo, including LLM analysis and semantic-cache embeddings.
- Optional multi-provider LLM support remains available for local experiments, including local Ollama.
- Docker packaging for a single backend + built frontend container.

## Project Structure

```text
LLMCaching-Access-Log-Analysis/
|-- api/                  # FastAPI backend and WebSocket manager
|-- src/                  # Core pipeline source code
|   |-- ingestion/        # Log parsing, normalization, source detection
|   |-- detection/        # Rule-based and content-only ML detectors
|   |-- llm/              # LLM integrations and semantic cache
|   `-- pipeline.py       # Main orchestrator
|-- web/                  # React/Vite dashboard frontend
|-- input/                # Local demo log directory mounted into Docker
|-- data/models/          # Trained content model artifact: lgbm_content.pkl
|-- data/rules/           # Rule data
|-- data/synthetic/       # Thesis synthetic dataset splits, when copied locally
|-- legacy/               # Archived benchmark, CLI, UI, and behavior/temporal code
|-- Dockerfile
|-- docker-compose.yml
|-- requirements.txt
`-- .env
```

## Environment Variables

Create or update `.env` in the project root:

```env
LLM_PROVIDER="nvidia"
CACHE_EMBED_PROVIDER="nvidia"

# NVIDIA NIM settings.
NVIDIA_API_KEY="add_key_here"
NVIDIA_BASE_URL="https://integrate.api.nvidia.com/v1"
NVIDIA_LLM_MODEL="google/gemma-4-31b-it"
NVIDIA_EMBED_MODEL="nvidia/llama-nemotron-embed-1b-v2"

# Optional Ollama settings.
# Use these for local experiments instead of NVIDIA.
# If the app runs in Docker and Ollama runs on the host, set
# OLLAMA_HOST="http://host.docker.internal:11434" on Docker Desktop.
# LLM_PROVIDER="ollama"
# CACHE_EMBED_PROVIDER="ollama"
# OLLAMA_HOST="http://localhost:11434"
# OLLAMA_LLM_MODEL="llama3.1:8b"
# OLLAMA_EMBED_MODEL="nomic-embed-text"

# Demo input settings.
LOG_INPUT_DIR="input"
LOG_SOURCE="auto"
USE_CACHE="true"
AUTO_START_ANALYSIS="true"
```

`docker-compose.yml` reads `LLM_PROVIDER` and `CACHE_EMBED_PROVIDER` from
`.env`, defaulting to NVIDIA when the variables are not set.

For local Ollama, make sure the models are available before running the app:

```bash
ollama pull llama3.1:8b
ollama pull nomic-embed-text
```

## Docker Demo

Put one or more access-log files into `input/`, then run:

```bash
docker compose up --build
```

Open:

```text
http://localhost:8000
```

The container mounts `./input` as read-only at `/app/input`. The backend creates a new analysis session at startup and the dashboard attaches to the newest session automatically.

## Thesis Dataset

The thesis training pipeline uses the validated CSIC-inspired synthetic dataset
(`data/synthetic/train.jsonl`, `validation.jsonl`, and `test.jsonl`). If these
files are not copied into the current repository, `src/detection/ml/trainer.py`
falls back to the legacy artifact directory:

```text
../LLMCaching-Access-Log-Analysis_old/LLMCaching-Access-Log-Analysis/data/synthetic/
```

Train the content model with:

```bash
python -m src.detection.ml.trainer
```

## Local Development

Backend:

```bash
pip install -r requirements.txt
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

Frontend:

```bash
cd web
npm install
npm run dev
```

For local frontend development, set `VITE_API_URL=http://localhost:8000` if needed.

## API Reference

- `GET /api/sessions`: List active and completed analysis sessions.
- `GET /api/alerts/{session_id}`: Get all alerts for a session.
- `GET /api/alerts/{session_id}/search`: Filter, search, sort, and paginate alerts.
- `GET /api/metrics/{session_id}`: Get processing metrics for a session.
- `POST /api/reload-input`: Start a fresh session from the configured local input directory.
- `WS /api/ws/{session_id}`: Stream progress and alerts to the dashboard.
- `GET /api/health`: Health check and runtime input settings.
