"""FastAPI backend for the alert dashboard demo.

At startup the app reads access-log files from a fixed local input directory and
starts one background analysis session. The React dashboard connects to that
session through REST and WebSocket APIs.
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

sys.path.insert(0, str(PROJECT_ROOT))

warnings.filterwarnings("ignore", category=UserWarning)

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.ingestion.normalizer import Normalizer
from src.pipeline import Pipeline

app = FastAPI(title="LLM Log Analysis", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_INPUT_DIR = Path(os.environ.get("LOG_INPUT_DIR", "input"))
if not LOG_INPUT_DIR.is_absolute():
    LOG_INPUT_DIR = PROJECT_ROOT / LOG_INPUT_DIR

LOG_SOURCE = os.environ.get("LOG_SOURCE", "auto")
USE_CACHE = os.environ.get("USE_CACHE", "true").lower() not in {"0", "false", "no"}
AUTO_START_ANALYSIS = (
    os.environ.get("AUTO_START_ANALYSIS", "true").lower() not in {"0", "false", "no"}
)
STATIC_DIR = PROJECT_ROOT / "web" / "dist"

# session_id -> { "status", "alerts", "metrics", "progress", "total_lines" }
sessions: dict[str, dict] = {}
ws_clients: dict[str, list[WebSocket]] = defaultdict(list)


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

    if session_id in sessions:
        for alert_json in sessions[session_id].get("alerts", []):
            try:
                await websocket.send_json({"type": "alert", "data": alert_json})
            except Exception:
                break

        session = sessions[session_id]
        if session.get("status") == "processing":
            await websocket.send_json(
                {
                    "type": "progress",
                    "data": {
                        "processed": session.get("progress", 0),
                        "total": session.get("total_lines", 0),
                    },
                }
            )
        elif session.get("status") == "done":
            await websocket.send_json({"type": "done", "data": session.get("metrics", {})})

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_clients[session_id].remove(websocket)


def _read_input_directory(input_dir: Path) -> tuple[list[str], list[str]]:
    """Read non-empty lines from all regular files in the configured directory."""
    input_dir.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    filenames: list[str] = []

    for path in sorted(input_dir.iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        file_lines = [line for line in text.splitlines() if line.strip()]
        if not file_lines:
            continue
        filenames.append(path.name)
        lines.extend(file_lines)

    return lines, filenames


async def start_input_directory_analysis() -> dict:
    """Create a dashboard session from files in LOG_INPUT_DIR."""
    session_id = str(uuid.uuid4())
    lines, input_files = _read_input_directory(LOG_INPUT_DIR)

    sessions[session_id] = {
        "status": "processing" if lines else "idle",
        "alerts": [],
        "metrics": {},
        "progress": 0,
        "total_lines": len(lines),
        "use_cache": USE_CACHE,
        "filename": ", ".join(input_files) if input_files else None,
        "input_files": input_files,
        "input_dir": str(LOG_INPUT_DIR),
        "source": LOG_SOURCE,
        "created_at": time.time(),
    }

    if lines:
        asyncio.create_task(_process_lines(session_id, lines, LOG_SOURCE, USE_CACHE))

    return {
        "session_id": session_id,
        "total_lines": len(lines),
        "input_files": input_files,
        "input_dir": str(LOG_INPUT_DIR),
        "message": "Processing started" if lines else "No log files found in input directory",
    }


@app.on_event("startup")
async def startup_analysis() -> None:
    if AUTO_START_ANALYSIS:
        await start_input_directory_analysis()


@app.post("/api/reload-input")
async def reload_input_directory():
    """Start a fresh session from the fixed local input directory."""
    return await start_input_directory_analysis()


async def _process_lines(
    session_id: str,
    lines: list[str],
    source: str,
    use_cache: bool,
) -> None:
    """Process log lines through the pipeline and stream results via WebSocket."""
    pipeline = Pipeline(use_cache=use_cache)
    normalizer = Normalizer()

    if source == "auto":
        source = normalizer.detect_source(lines[:10])
        sessions[session_id]["source"] = source

    latencies: list[float] = []
    total_input_tokens = 0
    total_output_tokens = 0
    cache_hits = 0
    cache_hit_types: dict[str, int] = defaultdict(int)
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
                cache_hit_types[alert.cache_hit_type or "unknown"] += 1

            await broadcast(session_id, {"type": "alert", "data": alert_data})

        sessions[session_id]["progress"] = i + 1
        if (i + 1) % progress_interval == 0 or i == len(lines) - 1:
            await broadcast(
                session_id,
                {"type": "progress", "data": {"processed": i + 1, "total": len(lines)}},
            )

        await asyncio.sleep(0)

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
        "cache_hit_types": dict(cache_hit_types),
        "cache_hit_rate": round(cache_hits / total_alerts, 3) if total_alerts > 0 else 0,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
        "total_llm_calls": total_alerts - cache_hits,
        "use_cache": use_cache,
        "input_files": sessions[session_id].get("input_files", []),
        "input_dir": sessions[session_id].get("input_dir"),
        "source": source,
    }

    sessions[session_id]["metrics"] = metrics
    sessions[session_id]["status"] = "done"

    await broadcast(session_id, {"type": "done", "data": metrics})


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
            "input_files": s.get("input_files", []),
            "input_dir": s.get("input_dir"),
            "source": s.get("source"),
            "created_at": s.get("created_at"),
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


_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_SEVERITY_ALIASES = {
    "crit": "critical",
    "med": "medium",
    "warn": "medium",
    "warning": "medium",
    "info": "low",
    "informational": "low",
}


def _normalize_severity(value: object) -> str | None:
    text = str(value or "").strip().lower()
    text = _SEVERITY_ALIASES.get(text, text)
    if text in _VALID_SEVERITIES:
        return text
    return None


def _score_fallback_severity(score: float) -> str:
    """Fallback only for older alerts that do not include analysis.severity."""
    if score >= 0.85:
        return "critical"
    if score >= 0.70:
        return "high"
    if score >= 0.50:
        return "medium"
    return "low"


def _get_severity(alert: dict) -> str:
    """Return alert severity from LLM analysis, with score fallback for old data."""
    analysis = alert.get("analysis") or {}
    return (
        _normalize_severity(alert.get("severity"))
        or _normalize_severity(analysis.get("severity"))
        or _score_fallback_severity(float(alert.get("merged_score", 0) or 0))
    )


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
        if severity and _get_severity(alert) not in severity:
            continue

        if attack_type:
            a_type = (alert.get("analysis") or {}).get("attack_type", "unknown")
            if a_type not in attack_type:
                continue

        if ip and ip.lower() not in (alert.get("source_ip") or "").lower():
            continue

        if search:
            q = search.lower()
            haystack = " ".join(
                str(v)
                for v in [
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
                    alert.get("severity"),
                    (alert.get("analysis") or {}).get("attack_type"),
                    (alert.get("analysis") or {}).get("severity"),
                    (alert.get("analysis") or {}).get("explanation"),
                    (alert.get("analysis") or {}).get("cve_refs"),
                ]
                if v
            ).lower()
            if q not in haystack:
                continue

        filtered.append(alert)

    reverse = sort_order == "desc"
    if sort_by == "merged_score":
        filtered.sort(key=lambda a: a.get("merged_score", 0), reverse=reverse)
    elif sort_by == "timestamp":
        filtered.sort(key=lambda a: a.get("timestamp", ""), reverse=reverse)
    else:
        filtered.sort(key=lambda a: a.get("line_number", 0), reverse=reverse)

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
    return {
        "status": "ok",
        "provider": os.environ.get("LLM_PROVIDER", "nvidia"),
        "input_dir": str(LOG_INPUT_DIR),
        "auto_start_analysis": AUTO_START_ANALYSIS,
    }


if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
