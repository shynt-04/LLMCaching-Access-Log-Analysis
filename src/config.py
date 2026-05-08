# src/config.py
# All tunable constants — import from here, never hardcode in modules

ALERT_THRESHOLD    = 0.5
WINDOW_MINUTES     = 5
CACHE_SIMILARITY   = 0.85
CONTENT_WEIGHT     = 0.5   # weight for TF-IDF+LightGBM content score
BEHAVIOR_WEIGHT    = 0.3   # weight for behavioral score
RULE_WEIGHT        = 0.2   # weight for rule-based score
CONTENT_FLOOR_FACTOR = 0.85 # floor factor: content_score * this must exceed threshold alone
TEMPORAL_CAP       = 1.5

# Ollama settings
OLLAMA_HOST        = "http://localhost:11434"  # override with env var
OLLAMA_MODEL       = "gemma4:e4b"
OLLAMA_EMBED_MODEL = "all-minilm"             # embedding model for semantic cache
OLLAMA_NUM_CTX     = 4096
OLLAMA_NUM_PREDICT = 2048
OLLAMA_TEMPERATURE = 0.1

# Gemini API settings (cloud alternative to Ollama)
GEMINI_MODEL       = "gemini-3-flash-preview"


# Synthetic data generation
SYNTH_BATCH_SIZE   = 100   # logs per LLM call
SYNTH_ATTACK_RATIO = 0.25  # fraction of attack logs in each batch

# Label encoding — binary (used by behavior model and merger)
LABEL_NORMAL       = 0
LABEL_ATTACK       = 1

# Label encoding — multiclass (used by content model for attack type classification)
LABEL_SQLI         = 1
LABEL_XSS          = 2
LABEL_PATH_TRAV    = 3
LABEL_DIR_SCAN     = 4
LABEL_CVE          = 5
LABEL_LFI          = 6

