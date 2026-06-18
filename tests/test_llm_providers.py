import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_llm_client_accepts_ollama_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_LLM_MODEL", "llama3.1:8b")

    from src.llm.client import LLMClient

    client = LLMClient()

    assert client._provider == "ollama"
    assert client._ollama_client.model == "llama3.1:8b"


def test_cache_accepts_ollama_embedding_provider(monkeypatch):
    monkeypatch.setenv("CACHE_EMBED_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")

    from src.llm.cache import SemanticCache

    cache = SemanticCache()

    assert cache._embed_provider == "ollama"
    assert cache._embed_model == "nomic-embed-text"
