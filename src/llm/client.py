# src/llm/client.py
import os, json, time
import ollama as _ollama
from pathlib import Path
from src.config import OLLAMA_MODEL, OLLAMA_HOST, OLLAMA_NUM_CTX, OLLAMA_NUM_PREDICT, OLLAMA_TEMPERATURE

_PROMPT_PATH = Path(__file__).parent / "prompts" / "classify.txt"
_PROMPT = _PROMPT_PATH.read_text() if _PROMPT_PATH.exists() else ""

# Ollama options applied to every call
_OPTIONS = {
    "num_ctx":     OLLAMA_NUM_CTX,
    "num_predict": OLLAMA_NUM_PREDICT,
    "temperature": OLLAMA_TEMPERATURE,
    # Thinking mode deliberately omitted — <|think|> not in system prompt
    # Enabling it would add ~500ms for no benefit on structured JSON tasks
}

class LLMClient:
    def __init__(self):
        host  = os.environ.get("OLLAMA_HOST", OLLAMA_HOST)
        model = os.environ.get("OLLAMA_MODEL", OLLAMA_MODEL)
        self._client = _ollama.Client(host=host)
        self._model  = model
        self._verify_model()

    def _verify_model(self) -> None:
        """Fail fast if the model is not available in Ollama."""
        try:
            # Ollama SDK returns Pydantic objects — use attribute access
            response = self._client.list()
            available = [m.model for m in response.models]
            if self._model not in available and f"{self._model}:latest" not in available:
                raise RuntimeError(
                    f"Model '{self._model}' not found in Ollama. "
                    f"Run: ollama pull {self._model}"
                )
        except Exception as e:
            print(f"[Ollama] Connection Failed: {e}")
            pass

    def analyze(self, event_summary: str, window_summary: str) -> dict:
        """
        Call Gemma4 E4B and return parsed analysis with token counts and TTFT.
        Uses streaming to measure time-to-first-token (TTFT) separately from
        total generation time.
        """
        messages = [
            {"role": "system",  "content": _PROMPT},
            {"role": "user",    "content": f"Event:\n{event_summary}\n\nContext:\n{window_summary}"},
        ]

        chunks, ttft_ms = [], None
        input_tokens, output_tokens = 0, 0
        t_start = time.perf_counter()

        # debug only
        # print("[PROMPT]:", _PROMPT)
        # print("[MESSAGES]:", messages)

        try:
            stream = self._client.chat(
                model=self._model,
                messages=messages,
                stream=True,
                options=_OPTIONS,
            )

            for chunk in stream:
                # Ollama SDK returns Pydantic objects — use attribute access
                content = chunk.message.content
                if content and ttft_ms is None:
                    # Record time of first non-empty token
                    ttft_ms = (time.perf_counter() - t_start) * 1000
                chunks.append(content)

                # Final chunk carries usage stats
                if getattr(chunk, "done", False):
                    input_tokens  = getattr(chunk, "prompt_eval_count", 0) or 0
                    output_tokens = getattr(chunk, "eval_count", 0) or 0

            raw = "".join(chunks).strip()
            # Strip markdown fences if model wraps the JSON
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

            analysis = json.loads(raw)
            analysis["ttft_ms"]       = round(ttft_ms or 0, 2)
            analysis["input_tokens"]  = input_tokens
            analysis["output_tokens"] = output_tokens
            return analysis
        except Exception as e:
            print(f"[Ollama Fallback] Error during analysis: {e}")
            return self.fallback()

    def fallback(self) -> dict:
        """Safe default when Ollama is unavailable or returns invalid JSON."""
        return {
            "attack_type": "unknown", "confidence": 0.0,
            "explanation": "LLM unavailable — manual review required.",
            "recommended_actions": ["monitor"],
            "cve_refs": [], "attack_stage": "unknown",
            "ttft_ms": None, "input_tokens": 0, "output_tokens": 0,
        }
