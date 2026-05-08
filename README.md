# LLM-Augmented Web Log Analysis System

## Tên đề tài (Project Title)
**LLM-Augmented Web Log Analysis System** (Hệ thống phân tích log web tăng cường bằng LLM).

## Overview
This project provides a high-performance, hybrid log detection pipeline designed to identify web attacks in access logs (e.g., Apache, Nginx). It leverages a multi-layer architecture combining rule-based heuristics, machine learning classification, and Large Language Models (LLMs) with a semantic caching mechanism to provide rapid and accurate threat detection, reducing both false positives and operational costs.

## Architecture
The system employs a 3-layer detection pipeline:
1. **Rule-Based Engine**: Uses OWASP ModSecurity Core Rule Set (CRS) patterns and regular expressions for fast, initial filtering of known attack vectors.
2. **Machine Learning Model**: Utilizes an optimized LightGBM classifier to evaluate behavior and content, catching complex anomalies and reducing false positives before they reach the LLM.
3. **LLM Analysis & Semantic Caching**: Employs an LLM (Gemini or local Ollama) for deep contextual analysis of suspicious logs that bypass earlier filters. To ensure low latency and high throughput, an embedding-based Semantic Cache (using FAISS) clusters and retrieves identical or semantically similar logs, significantly reducing redundant LLM API calls and execution time.

## Features
- **Multi-Provider LLM Integration**: Seamlessly switch between local, privacy-preserving inference (Ollama - `gemma4:e4b`) and fast, cloud-based APIs (Google Gemini).
- **High-Performance Semantic Caching**: Uses FAISS and sentence transformers to cache LLM evaluations. This drastically reduces evaluation time for redundant log events.
- **Real-Time Alert Dashboard**: A React-based web dashboard to monitor log analysis progress, visualize alerts via WebSockets, and manage detected threats.
- **Analysis Lab**: A dedicated environment for researchers to benchmark performance, compare ML vs. LLM accuracy, and visualize latency and cache hit rate metrics.
- **RESTful API & WebSockets**: Robust FastAPI backend for log ingestion, asynchronous background processing, and real-time streaming.

## Technology Stack
- **Backend**: Python 3.10+, FastAPI, Uvicorn, Pydantic
- **Machine Learning**: Scikit-Learn, LightGBM, Numpy, Scipy
- **LLM & Embeddings**: Google Generative AI (Gemini), Ollama, FAISS (Semantic Search)
- **Frontend**: React, Vite (communicating via WebSockets and REST APIs)
- **Deployment**: Docker, Docker Compose

## Project Structure
```text
LLMCaching-Access-Log-Analysis/
├── api/                  # FastAPI backend application & WebSocket manager
├── src/                  # Core pipeline source code
│   ├── ingestion/        # Log parsing, normalization, and source detection
│   ├── detection/        # Rule-based and ML classification engines
│   ├── llm/              # LLM integrations and FAISS Semantic Caching
│   └── pipeline.py       # Main orchestrator linking all layers
├── web/                  # React/Vite frontend Dashboard and Analysis Lab
├── data/                 # Datasets, synthetic logs, and pre-trained models
├── benchmark/            # Benchmarking and performance testing scripts
├── eval/                 # Evaluation and pipeline validation scripts
├── scripts/              # Utility scripts for data generation and training
├── docker-compose.yml    # Docker services configuration
├── requirements.txt      # Python dependencies
└── .env                  # Environment variables configuration
```

## Environment Variables
Create a `.env` file in the root directory with the following configurations (adjust based on your setup):

```env
# === LLM PROVIDER ===
# Options: "ollama" (local, free) or "gemini" (cloud, fast)
LLM_PROVIDER="gemini"

# === LLM API KEYS ===
GEMINI_API_KEY="your_google_gemini_api_key_here"

# === LOCAL OLLAMA CONFIG ===
OLLAMA_HOST="http://localhost:11434" # Use http://host.docker.internal:11434 inside Docker
OLLAMA_MODEL="gemma4:e4b"
OLLAMA_EMBED_MODEL="all-minilm"
```

## Deployment

### Using Docker Compose (Recommended)
1. Ensure Docker and Docker Compose are installed on your machine.
2. Configure your `.env` file properly.
3. Start the services using Docker Compose:
   ```bash
   docker-compose up --build -d
   ```
4. Access the backend API at `http://localhost:8000` and the frontend dashboard at `http://localhost:3000`.

### Local Development (Manual Setup)
**Backend:**
```bash
# Install dependencies
pip install -r requirements.txt

# Start the FastAPI server
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

**Frontend:**
```bash
cd web
# Install dependencies
npm install

# Start the development server
npm run dev
```

## API Reference
The FastAPI backend exposes several endpoints to interact with the pipeline:

- `POST /api/analyze`: Upload a log file and start background processing.
  - **Form Data**: `file` (UploadFile), `source` (auto/apache/nginx), `use_cache` (boolean).
- `GET /api/sessions`: List all active and completed processing sessions.
- `GET /api/metrics/{session_id}`: Fetch benchmark metrics (latency, throughput, cache hits, token usage) for a specific session.
- `GET /api/alerts/{session_id}`: Retrieve the complete list of alerts generated during a session.
- `WS /api/ws/{session_id}`: WebSocket endpoint to stream analysis progress and real-time alerts to the dashboard.
