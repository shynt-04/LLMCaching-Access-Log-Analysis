# src/llm/client.py
"""Multi-provider LLM client — supports NVIDIA NIM, Ollama, Gemini, and Claude.

Provider selection via LLM_PROVIDER env var:
  - "nvidia" (default): NVIDIA NIM API (OpenAI-compatible), requires NVIDIA_API_KEY
  - "ollama": local Ollama runtime, requires OLLAMA_LLM_MODEL to be available
  - "gemini": Google cloud API, fast TTFT, requires GEMINI_API_KEY
  - "claude": Anthropic cloud API (Haiku — fastest), requires CLAUDE_API_KEY
"""
import os, json, time
from pathlib import Path
from src.config import LLM_MAX_TOKENS, GEMINI_MODEL, CLAUDE_MODEL

_PROMPT = Path("src/llm/prompts/classify.txt").read_text()

class LLMClient:
    """Unified LLM interface, dispatching by LLM_PROVIDER."""

    def __init__(self) -> None:
        self._provider = os.environ.get("LLM_PROVIDER", "nvidia").lower()
        if self._provider == "gemini":
            self._init_gemini()
        elif self._provider == "claude":
            self._init_claude()
        elif self._provider == "nvidia":
            self._init_nvidia()
        elif self._provider == "ollama":
            self._init_ollama()
        else:
            raise ValueError(
                f"Unsupported LLM_PROVIDER={self._provider!r}. "
                "Use 'nvidia', 'ollama', 'gemini', or 'claude'."
            )

    # ── Gemini setup ──────────────────────────────────────────────────
    def _init_gemini(self) -> None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY must be set when LLM_PROVIDER=gemini")
        import google.genai as genai
        self._gemini_client = genai.Client(api_key=api_key)
        self._gemini_model_name = os.environ.get("GEMINI_MODEL", GEMINI_MODEL)

    # ── NVIDIA NIM setup ──────────────────────────────────────────────
    def _init_nvidia(self) -> None:
        from src.llm.nvidia_client import NvidiaLLMClient
        model = os.environ.get("NVIDIA_LLM_MODEL")
        self._nvidia_client = NvidiaLLMClient(model=model)

    # ── Ollama setup ─────────────────────────────────────────────────
    def _init_ollama(self) -> None:
        from src.llm.ollama_client import OllamaLLMClient
        model = os.environ.get("OLLAMA_LLM_MODEL")
        self._ollama_client = OllamaLLMClient(model=model)

    # ── Claude setup ──────────────────────────────────────────────────
    def _init_claude(self) -> None:
        api_key = os.environ.get("CLAUDE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("CLAUDE_API_KEY must be set when LLM_PROVIDER=claude")
        import anthropic
        self._claude_client = anthropic.Anthropic(api_key=api_key)
        self._claude_model_name = os.environ.get("CLAUDE_MODEL", CLAUDE_MODEL)

    # ── Public API ────────────────────────────────────────────────────
    def analyze(
        self,
        event_summary: str,
        context_summary: str,
        matched_rules: list | None = None,
    ) -> dict:
        """Analyze a flagged log event and return structured JSON analysis."""
        user_content = f"Event:\n{event_summary}\n\nContext:\n{context_summary}"
        if matched_rules:
            user_content += f"\n\nMatched Local Rules:\n{matched_rules}"

        if self._provider == "gemini":
            return self._analyze_gemini(user_content)
        if self._provider == "claude":
            return self._analyze_claude(user_content)
        if self._provider == "nvidia":
            return self._nvidia_client.analyze(event_summary, context_summary, matched_rules)
        if self._provider == "ollama":
            return self._ollama_client.analyze(_PROMPT + "\n\n" + user_content)
        raise ValueError(
            f"Unsupported LLM_PROVIDER={self._provider!r}. "
            "Use 'nvidia', 'ollama', 'gemini', or 'claude'."
        )

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
                max_tokens=LLM_MAX_TOKENS,
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

    # ── Fallback ──────────────────────────────────────────────────────
    def fallback(self) -> dict:
        """Safe default when LLM is unavailable or returns invalid JSON."""
        return {
            "attack_type": "unknown", "confidence": 0.0,
            "severity": "medium",
            "explanation": "LLM analysis failed or unavailable — manual review required.",
            "recommended_actions": ["monitor"],
            "cve_refs": [], "attack_stage": "unknown",
            "ttft_ms": None, "input_tokens": 0, "output_tokens": 0,
        }
