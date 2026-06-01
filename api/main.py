# api/main.py
"""FastAPI backend — serves Alert Dashboard + Analysis Lab.

Endpoints:
  POST /api/analyze       — upload log file, start background processing
  GET  /api/sessions      — list active/completed sessions
  GET  /api/metrics/{id}  — fetch benchmark metrics for a session
  WS   /api/ws/{session}  — stream alerts in real-time
"""
import asyncio
import json
import os
import sys
import time
import uuid
import warnings
from collections import defaultdict
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load .env before any src imports (config reads env vars)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# Ensure project root is on sys.path for src imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

warnings.filterwarnings("ignore", category=UserWarning)

from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.pipeline import Pipeline
from src.ingestion.normalizer import Normalizer

app = FastAPI(title="LLM Log Analysis", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory state ──────────────────────────────────────────────────
# session_id → { "status", "alerts", "metrics", "progress", "total_lines" }
sessions: dict[str, dict] = {}
# session_id → list of connected WebSocket clients
ws_clients: dict[str, list[WebSocket]] = defaultdict(list)


# ── WebSocket manager ────────────────────────────────────────────────
async def broadcast(session_id: str, message: dict) -> None:
    """Push a JSON message to all WebSocket clients subscribed to a session."""
    dead = []
    for ws in ws_clients[session_id]:
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_clients[session_id].remove(ws)


@app.websocket("/api/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await websocket.accept()
    ws_clients[session_id].append(websocket)

    # Send existing alerts to newly connected client (catch-up)
    if session_id in sessions:
        for alert_json in sessions[session_id].get("alerts", []):
            try:
                await websocket.send_json({"type": "alert", "data": alert_json})
            except Exception:
                break

    try:
        while True:
            # Keep connection alive; client sends pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_clients[session_id].remove(websocket)


# ── Upload & Analyze ─────────────────────────────────────────────────
@app.post("/api/analyze")
async def analyze_log(
    file: UploadFile = File(...),
    source: str = Form("auto"),
    use_cache: bool = Form(True),
):
    """Accept a log file upload and start background processing."""
    session_id = str(uuid.uuid4())
    content = (await file.read()).decode("utf-8", errors="replace")
    lines = [l for l in content.splitlines() if l.strip()]

    sessions[session_id] = {
        "status": "processing",
        "alerts": [],
        "metrics": {},
        "progress": 0,
        "total_lines": len(lines),
        "use_cache": use_cache,
        "filename": file.filename,
    }

    # Run pipeline in background to avoid blocking
    asyncio.create_task(_process_lines(session_id, lines, source, use_cache))

    return {
        "session_id": session_id,
        "total_lines": len(lines),
        "message": "Processing started",
    }


async def _process_lines(
    session_id: str,
    lines: list[str],
    source: str,
    use_cache: bool,
) -> None:
    """Process log lines through the pipeline and stream results via WS."""
    pipeline = Pipeline(use_cache=use_cache)
    normalizer = Normalizer()

    if source == "auto":
        source = normalizer.detect_source(lines[:10])

    latencies: list[float] = []
    total_input_tokens = 0
    total_output_tokens = 0
    cache_hits = 0
    total_alerts = 0

    progress_interval = max(1, len(lines) // 100)

    for i, line in enumerate(lines):
        t0 = time.perf_counter()

        try:
            alert = await asyncio.to_thread(pipeline.process_line, line, source=source)
        except Exception as e:
            print(f"[Pipeline] Error on line {i}: {e}")
            alert = None

        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies.append(elapsed_ms)

        if alert:
            total_alerts += 1
            alert_data = json.loads(alert.model_dump_json())
            alert_data["line_number"] = i + 1
            alert_data["latency_ms"] = round(elapsed_ms, 2)

            sessions[session_id]["alerts"].append(alert_data)
            total_input_tokens += alert.input_tokens
            total_output_tokens += alert.output_tokens
            if alert.cache_hit:
                cache_hits += 1

            # Stream alert to all connected clients
            await broadcast(session_id, {"type": "alert", "data": alert_data})

        # Throttle progress broadcasts to ~1% intervals
        sessions[session_id]["progress"] = i + 1
        if (i + 1) % progress_interval == 0 or i == len(lines) - 1:
            await broadcast(session_id, {
                "type": "progress",
                "data": {"processed": i + 1, "total": len(lines)},
            })

        # Yield control to event loop to allow WS sends
        await asyncio.sleep(0)

    # Compute final metrics
    sorted_lat = sorted(latencies)
    p95_idx = int(len(sorted_lat) * 0.95) if sorted_lat else 0
    total_time_s = sum(latencies) / 1000.0

    metrics = {
        "total_lines": len(lines),
        "total_alerts": total_alerts,
        "total_time_s": round(total_time_s, 2),
        "throughput_ev_s": round(len(lines) / total_time_s, 1) if total_time_s > 0 else 0,
        "latency_p95_ms": round(sorted_lat[p95_idx], 2) if sorted_lat else 0,
        "latency_avg_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0,
        "cache_hits": cache_hits,
        "cache_hit_rate": round(cache_hits / total_alerts, 3) if total_alerts > 0 else 0,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
        "total_llm_calls": total_alerts - cache_hits,
        "use_cache": use_cache,
    }

    sessions[session_id]["metrics"] = metrics
    sessions[session_id]["status"] = "done"

    await broadcast(session_id, {"type": "done", "data": metrics})


# ── REST endpoints ───────────────────────────────────────────────────
@app.get("/api/sessions")
async def list_sessions():
    """List all sessions with summary info."""
    return {
        sid: {
            "status": s["status"],
            "progress": s["progress"],
            "total_lines": s["total_lines"],
            "total_alerts": len(s["alerts"]),
            "use_cache": s.get("use_cache"),
            "filename": s.get("filename"),
        }
        for sid, s in sessions.items()
    }


@app.get("/api/metrics/{session_id}")
async def get_metrics(session_id: str):
    """Fetch benchmark metrics for a completed session."""
    if session_id not in sessions:
        return {"error": "Session not found"}
    return sessions[session_id]["metrics"]


@app.get("/api/alerts/{session_id}")
async def get_alerts(session_id: str):
    """Fetch all alerts for a session."""
    if session_id not in sessions:
        return {"error": "Session not found"}
    return sessions[session_id]["alerts"]


# ── Filter/Search API ────────────────────────────────────────────────
def _get_severity(score: float) -> str:
    """Classify merged_score into severity level."""
    if score >= 0.85:
        return "critical"
    if score >= 0.70:
        return "high"
    if score >= 0.50:
        return "medium"
    return "low"


@app.get("/api/alerts/{session_id}/search")
async def search_alerts(
    session_id: str,
    severity: Optional[list[str]] = Query(None),
    attack_type: Optional[list[str]] = Query(None),
    ip: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "line_number",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 50,
):
    """Server-side filter, search, sort, and paginate alerts for a session."""
    if session_id not in sessions:
        return {"error": "Session not found"}

    all_alerts = sessions[session_id]["alerts"]
    filtered = []

    for alert in all_alerts:
        # Severity filter
        if severity:
            if _get_severity(alert.get("merged_score", 0)) not in severity:
                continue

        # Attack type filter
        if attack_type:
            a_type = (alert.get("analysis") or {}).get("attack_type", "unknown")
            if a_type not in attack_type:
                continue

        # IP substring filter
        if ip:
            if ip.lower() not in (alert.get("source_ip") or "").lower():
                continue

        # Full-text search across alert fields, including the original line for alerted events.
        if search:
            q = search.lower()
            haystack = " ".join(
                str(v) for v in [
                    alert.get("line_number"),
                    alert.get("source_ip"),
                    alert.get("method"),
                    alert.get("path"),
                    alert.get("query_string"),
                    alert.get("status_code"),
                    alert.get("user_agent"),
                    alert.get("raw_line"),
                    alert.get("matched_rules"),
                    alert.get("attack_types"),
                    (alert.get("analysis") or {}).get("attack_type"),
                    (alert.get("analysis") or {}).get("explanation"),
                    (alert.get("analysis") or {}).get("cve_refs"),
                ] if v
            ).lower()
            if q not in haystack:
                continue

        filtered.append(alert)

    # Sorting
    reverse = sort_order == "desc"
    if sort_by == "merged_score":
        filtered.sort(key=lambda a: a.get("merged_score", 0), reverse=reverse)
    elif sort_by == "timestamp":
        filtered.sort(key=lambda a: a.get("timestamp", ""), reverse=reverse)
    else:  # line_number (default)
        filtered.sort(key=lambda a: a.get("line_number", 0), reverse=reverse)

    # Pagination
    total = len(filtered)
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    end = start + page_size

    return {
        "alerts": filtered[start:end],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "provider": os.environ.get("LLM_PROVIDER", "ollama")}
