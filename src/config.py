# src/config.py
# All tunable constants — import from here, never hardcode in modules

ALERT_THRESHOLD  = 0.5    # min merged score to flag an event
WINDOW_MINUTES   = 5      # temporal buffer duration
CACHE_SIMILARITY = 0.85   # cosine threshold for cache hit (Phase 3)
RULE_WEIGHT      = 0.4    # weight for rule score in merge
ML_WEIGHT        = 0.6    # weight for ML score in merge
TEMPORAL_CAP     = 1.5    # max temporal multiplier
IF_CONTAMINATION = 0.05   # expected anomaly fraction for IF training
IF_N_ESTIMATORS  = 100    # number of trees in Isolation Forest
RANDOM_STATE     = 42     # global random seed for reproducibility

# Ollama settings
OLLAMA_HOST        = "http://localhost:11434"  # override with env var
OLLAMA_MODEL       = "gemma4:e4b"
OLLAMA_EMBED_MODEL = "all-minilm"             # embedding model for semantic cache
OLLAMA_NUM_CTX     = 4096   # context window
OLLAMA_NUM_PREDICT = 2048   # Gemma4 uses ~500 tokens for thinking before JSON output
OLLAMA_TEMPERATURE = 0.1    # low temp for deterministic classification
