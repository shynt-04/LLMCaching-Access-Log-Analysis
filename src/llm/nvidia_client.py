# src/llm/nvidia_client.py
"""NVIDIA NIM API client — OpenAI-compatible interface for LLM + Embeddings.

Usage:
    # LLM inference
    client = NvidiaLLMClient(model="meta/llama-3.1-8b-instruct")
    result = client.analyze(event_summary, context_summary, matched_rules)

    # Embeddings
    embedder = NvidiaEmbedder(model="nvidia/llama-nemotron-embed-1b-v2")
    vector = embedder.embed("some text")

Provider config via env vars:
    NVIDIA_API_KEY      — required, get from https://build.nvidia.com
    NVIDIA_BASE_URL     — optional, defaults to https://integrate.api.nvidia.com/v1
    NVIDIA_LLM_MODEL    — default LLM model for inference
    NVIDIA_EMBED_MODEL  — default embedding model
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import numpy as np

_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "classify.txt"
_PROMPT = _PROMPT_PATH.read_text(encoding="utf-8") if _PROMPT_PATH.exists() else ""

# ── Defaults ────────────────────────────────────────────────────────
_DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"

# Popular LLM models on NVIDIA NIM (as of 2025-2026)
NVIDIA_LLM_MODELS = {
    "llama-3.1-8b":   "meta/llama-3.1-8b-instruct",
    "llama-3.1-70b":  "meta/llama-3.1-70b-instruct",
    "llama-3.1-405b": "meta/llama-3.1-405b-instruct",
    "llama-3.3-70b":  "meta/llama-3.3-70b-instruct",
    "nemotron-70b":   "nvidia/llama-3.1-nemotron-70b-instruct",
    "mistral-large":  "mistralai/mistral-large-latest",
    "mistral-small":  "mistralai/mistral-small-latest",
    "mixtral-8x22b":  "mistralai/mixtral-8x22b-instruct-v0.1",
    "deepseek-r1":    "deepseek-ai/deepseek-r4-pro",
    "phi-4":          "microsoft/phi-4",
    "gemma-4-31b":    "google/gemma-4-31b-it",
    "qwen2.5-72b":    "qwen/qwen2.5-72b-instruct",
    "glm5.1": ""
}

# Popular embedding models on NVIDIA NIM
NVIDIA_EMBED_MODELS = {
    "nemotron-embed-1b":  "nvidia/llama-nemotron-embed-1b-v2",
    "nemotron-embed-300m": "nvidia/llama-nemotron-embed-300m-v2",
    "nv-embedqa-e5":      "nvidia/nv-embedqa-e5-v5",
    "bge-m3":             "baai/bge-m3",
}

_DEFAULT_LLM_MODEL = "meta/llama-3.1-8b-instruct"
_DEFAULT_EMBED_MODEL = "nvidia/llama-nemotron-embed-1b-v2"


def _resolve_model(model: str | None, alias_map: dict, env_key: str, default: str) -> str:
    """Resolve model name: check alias map, then env var, then default."""
    if model:
        return alias_map.get(model, model)
    env_val = os.environ.get(env_key)
    if env_val:
        return alias_map.get(env_val, env_val)
    return default


def _get_openai_client():
    """Create OpenAI client pointing to NVIDIA NIM."""
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError(
            "openai package required for NVIDIA NIM client. "
            "Install with: pip install openai"
        )
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        raise ValueError(
            "NVIDIA_API_KEY must be set. "
            "Get your key at https://build.nvidia.com"
        )
    base_url = os.environ.get("NVIDIA_BASE_URL", _DEFAULT_BASE_URL)
    return OpenAI(base_url=base_url, api_key=api_key)


# ═══════════════════════════════════════════════════════════════════
#  LLM Client — Chat Completions
# ═══════════════════════════════════════════════════════════════════

class NvidiaLLMClient:
    """NVIDIA NIM LLM client for web attack log analysis.

    Compatible with the existing LLMClient interface (same .analyze() signature).

    Args:
        model: Model name or alias. See NVIDIA_LLM_MODELS for aliases.
               Falls back to NVIDIA_LLM_MODEL env var, then default.
        temperature: Sampling temperature (default 0.1 for deterministic output).
        max_tokens: Max output tokens (default 2048).

    Example:
        client = NvidiaLLMClient(model="llama-3.1-8b")
        result = client.analyze(event_summary, context_summary)
    """

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> None:
        self._client = _get_openai_client()
        self._model = _resolve_model(
            model, NVIDIA_LLM_MODELS, "NVIDIA_LLM_MODEL", _DEFAULT_LLM_MODEL
        )
        self._temperature = temperature
        self._max_tokens = max_tokens
        print(f"[NvidiaLLM] Using model: {self._model}")

    @property
    def model(self) -> str:
        return self._model

    def analyze(
        self,
        event_summary: str,
        context_summary: str,
        matched_rules: list | None = None,
    ) -> dict:
        """Analyze a flagged log event — same interface as LLMClient.analyze()."""
        user_content = f"Event:\n{event_summary}\n\nContext:\n{context_summary}"
        if matched_rules:
            user_content += f"\n\nMatched Local Rules:\n{matched_rules}"

        t_start = time.perf_counter()
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": _PROMPT},
                    {"role": "user", "content": user_content},
                ],
                temperature=self._temperature,
                max_tokens=self._max_tokens,
                response_format={"type": "json_object"},
            )
            ttft_ms = (time.perf_counter() - t_start) * 1000

            raw = response.choices[0].message.content.strip()
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            try:
                analysis = json.loads(raw)
            except json.JSONDecodeError as e:
                preview = raw.replace("\n", " ")[:300]
                print(f"[ERROR] NVIDIA NIM returned invalid JSON: {e}; raw={preview!r}")
                analysis = self.fallback()
            analysis.update({
                "ttft_ms": round(ttft_ms, 2),
                "input_tokens": getattr(response.usage, "prompt_tokens", 0),
                "output_tokens": getattr(response.usage, "completion_tokens", 0),
                "model": self._model,
                "provider": "nvidia",
            })
            return analysis
        except Exception as e:
            print(f"[ERROR] NVIDIA NIM LLM failed: {e}")
            return self.fallback()

    def fallback(self) -> dict:
        """Safe default when LLM is unavailable or returns invalid JSON."""
        return {
            "attack_type": "unknown", "confidence": 0.0,
            "severity": "medium",
            "explanation": "LLM analysis failed or unavailable — manual review required.",
            "recommended_actions": ["monitor"],
            "cve_refs": [], "attack_stage": "unknown",
            "ttft_ms": None, "input_tokens": 0, "output_tokens": 0,
            "model": self._model, "provider": "nvidia",
        }

    @staticmethod
    def list_aliases() -> dict[str, str]:
        """Return available short aliases → full model IDs."""
        return dict(NVIDIA_LLM_MODELS)


# ═══════════════════════════════════════════════════════════════════
#  Embedding Client
# ═══════════════════════════════════════════════════════════════════

class NvidiaEmbedder:
    """NVIDIA NIM embedding client for semantic cache vectors.

    Args:
        model: Model name or alias. See NVIDIA_EMBED_MODELS for aliases.
               Falls back to NVIDIA_EMBED_MODEL env var, then default.

    Example:
        embedder = NvidiaEmbedder(model="nemotron-embed-1b")
        vec = embedder.embed("GET /search?q=test")
        vecs = embedder.embed_batch(["text1", "text2", "text3"])
    """

    def __init__(self, model: str | None = None) -> None:
        self._client = _get_openai_client()
        self._model = _resolve_model(
            model, NVIDIA_EMBED_MODELS, "NVIDIA_EMBED_MODEL", _DEFAULT_EMBED_MODEL
        )
        self._dims: int | None = None
        print(f"[NvidiaEmbed] Using model: {self._model}")

    @property
    def model(self) -> str:
        return self._model

    def embed(self, text: str, truncate: int = 512, input_type: str = "passage") -> np.ndarray:
        """Embed a single text string -> L2-normalized numpy vector.

        Args:
            text: Text to embed.
            truncate: Max characters to keep (default 512).
            input_type: 'passage' for stored documents, 'query' for search queries.
                        Required by asymmetric models like nemotron-embed.
        """
        kwargs: dict = {
            "input": [text[:truncate]],
            "model": self._model,
            "encoding_format": "float",
        }
        # Asymmetric models require input_type via extra_body
        kwargs["extra_body"] = {"input_type": input_type}
        try:
            response = self._client.embeddings.create(**kwargs)
        except Exception as e:
            # Fallback: some models don't support input_type, retry without it
            if "input_type" in str(e):
                del kwargs["extra_body"]
                response = self._client.embeddings.create(**kwargs)
            else:
                raise
        vec = np.array(response.data[0].embedding, dtype=np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        self._dims = len(vec)
        return vec

    def embed_batch(
        self,
        texts: list[str],
        truncate: int = 512,
        batch_size: int = 32,
        input_type: str = "passage",
    ) -> list[np.ndarray]:
        """Embed multiple texts in batches -> list of L2-normalized vectors."""
        all_vecs: list[np.ndarray] = []
        for i in range(0, len(texts), batch_size):
            batch = [t[:truncate] for t in texts[i : i + batch_size]]
            kwargs: dict = {
                "input": batch,
                "model": self._model,
                "encoding_format": "float",
            }
            kwargs["extra_body"] = {"input_type": input_type}
            try:
                response = self._client.embeddings.create(**kwargs)
            except Exception as e:
                if "input_type" in str(e):
                    del kwargs["extra_body"]
                    response = self._client.embeddings.create(**kwargs)
                else:
                    raise
            # Sort by index to preserve order
            sorted_data = sorted(response.data, key=lambda d: d.index)
            for item in sorted_data:
                vec = np.array(item.embedding, dtype=np.float32)
                norm = np.linalg.norm(vec)
                if norm > 0:
                    vec /= norm
                all_vecs.append(vec)
            self._dims = len(all_vecs[-1]) if all_vecs else None
        return all_vecs

    @property
    def dims(self) -> int | None:
        """Embedding dimensionality (known after first call)."""
        return self._dims

    @staticmethod
    def list_aliases() -> dict[str, str]:
        """Return available short aliases → full model IDs."""
        return dict(NVIDIA_EMBED_MODELS)
