"""Ollama local runtime client for LLM inference and embeddings."""
import json
import os
import urllib.error
import urllib.request

import numpy as np

from src.config import LLM_MAX_TOKENS


_DEFAULT_HOST = "http://localhost:11434"
_DEFAULT_LLM_MODEL = "llama3.1:8b"
_DEFAULT_EMBED_MODEL = "nomic-embed-text"


def _host() -> str:
    return os.environ.get("OLLAMA_HOST", _DEFAULT_HOST).rstrip("/")


def _post_json(path: str, payload: dict, timeout: float = 120.0) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{_host()}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Ollama HTTP {exc.code}: {body}") from exc


class OllamaLLMClient:
    """Ollama /api/generate client returning the pipeline JSON schema."""

    def __init__(self, model: str | None = None) -> None:
        self._model = model or os.environ.get("OLLAMA_LLM_MODEL", _DEFAULT_LLM_MODEL)

    @property
    def model(self) -> str:
        return self._model

    def analyze(
        self,
        prompt: str,
    ) -> dict:
        payload = {
            "model": self._model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": LLM_MAX_TOKENS,
            },
        }
        try:
            response = _post_json("/api/generate", payload)
            raw = str(response.get("response", "")).strip()
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            analysis = json.loads(raw)
            analysis.update({
                "provider": "ollama",
                "model": self._model,
                "ttft_ms": None,
                "input_tokens": int(response.get("prompt_eval_count") or 0),
                "output_tokens": int(response.get("eval_count") or 0),
            })
            if response.get("total_duration") is not None:
                analysis["latency_ms"] = round(float(response["total_duration"]) / 1_000_000, 2)
            return analysis
        except Exception as exc:
            print(f"[ERROR] Ollama LLM failed: {exc}")
            return {
                "attack_type": "unknown",
                "confidence": 0.0,
                "severity": "medium",
                "explanation": "Ollama analysis failed or unavailable; manual review required.",
                "recommended_actions": ["monitor"],
                "cve_refs": [],
                "attack_stage": "unknown",
                "provider": "ollama",
                "model": self._model,
                "ttft_ms": None,
                "input_tokens": 0,
                "output_tokens": 0,
            }


class OllamaEmbedder:
    """Ollama embedding client.

    Uses /api/embed when available and falls back to /api/embeddings for older
    Ollama versions.
    """

    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.environ.get("OLLAMA_EMBED_MODEL", _DEFAULT_EMBED_MODEL)

    def embed(self, text: str, truncate: int = 512) -> np.ndarray:
        text = text[:truncate]
        try:
            response = _post_json("/api/embed", {"model": self.model, "input": text})
            embeddings = response.get("embeddings")
            if embeddings:
                vector = embeddings[0]
            else:
                vector = response.get("embedding")
        except Exception:
            response = _post_json("/api/embeddings", {"model": self.model, "prompt": text})
            vector = response.get("embedding")

        if not vector:
            raise RuntimeError("Ollama embedding response did not include a vector")
        arr = np.array(vector, dtype=np.float32)
        norm = np.linalg.norm(arr)
        if norm > 0:
            arr = arr / norm
        return arr
