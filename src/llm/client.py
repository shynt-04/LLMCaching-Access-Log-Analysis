# src/llm/client.py
"""Multi-provider LLM client — supports Ollama (local), Gemini API, and Claude API.

Provider selection via LLM_PROVIDER env var:
  - "ollama" (default): local inference, $0 cost, higher latency
  - "gemini": Google cloud API, fast TTFT, requires GEMINI_API_KEY
  - "claude": Anthropic cloud API (Haiku — fastest), requires CLAUDE_API_KEY
"""
import os, json, time
from pathlib import Path
from src.config import (
    OLLAMA_MODEL, OLLAMA_NUM_CTX, OLLAMA_NUM_PREDICT,
    OLLAMA_TEMPERATURE, OLLAMA_NUM_GPU, GEMINI_MODEL, CLAUDE_MODEL,
)

_PROMPT = Path("src/llm/prompts/classify.txt").read_text()

# Ollama-specific options
_OPTIONS = {
    "num_ctx":     OLLAMA_NUM_CTX,
    "num_predict": OLLAMA_NUM_PREDICT,
    "temperature": OLLAMA_TEMPERATURE,
    "num_gpu": OLLAMA_NUM_GPU
}


class LLMClient:
    """Unified LLM interface — dispatches to Ollama or Gemini based on config."""

    def __init__(self) -> None:
        self._provider = os.environ.get("LLM_PROVIDER", "ollama").lower()
        if self._provider == "gemini":
            self._init_gemini()
        elif self._provider == "claude":
            self._init_claude()
        else:
            self._init_ollama()

    # ── Gemini setup ──────────────────────────────────────────────────
    def _init_gemini(self) -> None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY must be set when LLM_PROVIDER=gemini")
        import google.genai as genai
        self._gemini_client = genai.Client(api_key=api_key)
        self._gemini_model_name = os.environ.get("GEMINI_MODEL", GEMINI_MODEL)

    # ── Claude setup ──────────────────────────────────────────────────
    def _init_claude(self) -> None:
        api_key = os.environ.get("CLAUDE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("CLAUDE_API_KEY must be set when LLM_PROVIDER=claude")
        import anthropic
        self._claude_client = anthropic.Anthropic(api_key=api_key)
        self._claude_model_name = os.environ.get("CLAUDE_MODEL", CLAUDE_MODEL)

    # ── Ollama setup ──────────────────────────────────────────────────
    def _init_ollama(self) -> None:
        import ollama as _ollama
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self._model = os.environ.get("OLLAMA_MODEL", OLLAMA_MODEL)
        self._client = _ollama.Client(host=host)
        try:
            available = [m.model for m in self._client.list().models]
            if self._model not in available:
                print(f"[WARN] Model '{self._model}' not found. Run: ollama pull {self._model}")
        except Exception as e:
            print(f"[WARN] Could not connect to Ollama: {e}")

    # ── Public API ────────────────────────────────────────────────────
    def analyze(
        self,
        event_summary: str,
        window_summary: str,
        matched_rules: list | None = None,
    ) -> dict:
        """Analyze a flagged log event and return structured JSON analysis."""
        user_content = f"Event:\n{event_summary}\n\nContext:\n{window_summary}"
        if matched_rules:
            user_content += f"\n\nMatched Local Rules:\n{matched_rules}"

        if self._provider == "gemini":
            return self._analyze_gemini(user_content)
        if self._provider == "claude":
            return self._analyze_claude(user_content)
        return self._analyze_ollama(user_content)

    # ── Gemini inference ──────────────────────────────────────────────
    def _analyze_gemini(self, user_content: str) -> dict:
        """Call Gemini API — returns structured JSON with token counts."""
        from google.genai import types
        t_start = time.perf_counter()
        try:
            response = self._gemini_client.models.generate_content(
                model=self._gemini_model_name,
                contents=_PROMPT + "\n\n" + user_content,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.1,
                ),
            )
            ttft_ms = (time.perf_counter() - t_start) * 1000

            raw = response.text.strip()
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            analysis = json.loads(raw)
            analysis.update({
                "ttft_ms": round(ttft_ms, 2),
                "input_tokens": getattr(
                    response.usage_metadata, "prompt_token_count", 0
                ),
                "output_tokens": getattr(
                    response.usage_metadata, "candidates_token_count", 0
                ),
            })
            return analysis
        except Exception as e:
            print(f"[ERROR] Gemini API failed: {e}")
            return self.fallback()

    # ── Claude inference ──────────────────────────────────────────────
    def _analyze_claude(self, user_content: str) -> dict:
        """Call Anthropic Claude — returns structured JSON with token counts."""
        t_start = time.perf_counter()
        try:
            response = self._claude_client.messages.create(
                model=self._claude_model_name,
                max_tokens=OLLAMA_NUM_PREDICT,
                temperature=0.1,
                system=_PROMPT,
                messages=[{"role": "user", "content": user_content}],
            )
            ttft_ms = (time.perf_counter() - t_start) * 1000

            raw = "".join(
                block.text for block in response.content
                if getattr(block, "type", None) == "text"
            ).strip()
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            analysis = json.loads(raw)
            analysis.update({
                "ttft_ms": round(ttft_ms, 2),
                "input_tokens":  getattr(response.usage, "input_tokens", 0),
                "output_tokens": getattr(response.usage, "output_tokens", 0),
            })
            return analysis
        except Exception as e:
            print(f"[ERROR] Claude API failed: {e}")
            return self.fallback()

    # ── Ollama inference ──────────────────────────────────────────────
    def _analyze_ollama(self, user_content: str) -> dict:
        """Call local Ollama — streams response and measures TTFT."""
        messages = [
            {"role": "system", "content": _PROMPT},
            {"role": "user",   "content": user_content},
        ]
        chunks, ttft_ms = [], None
        input_tokens = output_tokens = 0
        t_start = time.perf_counter()

        try:
            for chunk in self._client.chat(
                model=self._model, messages=messages,
                stream=True, options=_OPTIONS,
            ):
                content = chunk["message"]["content"]
                if content and ttft_ms is None:
                    # Record time of first non-empty token
                    ttft_ms = (time.perf_counter() - t_start) * 1000
                chunks.append(content)
                # Final chunk carries usage stats
                if chunk.get("done"):
                    input_tokens  = chunk.get("prompt_eval_count", 0)
                    output_tokens = chunk.get("eval_count", 0)

            raw = "".join(chunks).strip()
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            analysis = json.loads(raw)
            analysis["ttft_ms"]       = round(ttft_ms or 0, 2)
            analysis["input_tokens"]  = input_tokens
            analysis["output_tokens"] = output_tokens
            return analysis
        except Exception as e:
            print(f"[ERROR] Ollama failed: {e}")
            return self.fallback()

    # ── Fallback ──────────────────────────────────────────────────────
    def fallback(self) -> dict:
        """Safe default when LLM is unavailable or returns invalid JSON."""
        return {
            "attack_type": "unknown", "confidence": 0.0,
            "explanation": "LLM analysis failed or unavailable — manual review required.",
            "recommended_actions": ["monitor"],
            "cve_refs": [], "attack_stage": "unknown",
            "ttft_ms": None, "input_tokens": 0, "output_tokens": 0,
        }
