import os
# src/config.py
# All tunable constants — import from here, never hardcode in modules

ALERT_THRESHOLD    = 0.5
CACHE_SIMILARITY   = 0.85
CACHE_MAX_SIZE     = 2048
CONTENT_WEIGHT     = 0.7   # weight for TF-IDF+LightGBM content score
RULE_WEIGHT        = 0.3   # weight for rule-based score
CONTENT_FLOOR_FACTOR = 0.85 # floor factor: content_score * this must exceed threshold alone

# Attack-type-aware semantic cache policy.
CACHE_MIN_CONFIDENCE = 0.8
CACHE_POLICY_MODE = "attack_type_aware"
CACHE_ATTACK_THRESHOLDS = {
    "sqli": 0.85,
    "xss": 0.85,
    "lfi": 0.87,
    "path_traversal": 0.87,
    "ssti": 0.92,
    "ssrf": 0.92,
    "file_upload": 0.92,
    "csrf": 0.95,
    "cve": 0.92,
    "dir_scan": 0.88,
}
CACHE_EXACT_ONLY_TYPES = {"normal", "unknown", "csrf"}

LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "2048"))

# Gemini API settings
GEMINI_MODEL       = "gemini-3-flash-preview"

# Anthropic Claude API settings (cloud alternative — Haiku is the fastest)
CLAUDE_MODEL       = "claude-haiku-4-5-20251001"

# Synthetic data generation
SYNTH_BATCH_SIZE   = 100   # logs per LLM call
SYNTH_ATTACK_RATIO = 0.25  # fraction of attack logs in each batch

# Label encoding - binary labels used by training/evaluation scripts
LABEL_NORMAL       = 0
LABEL_ATTACK       = 1

# Label encoding — multiclass (used by content model for attack type classification)
LABEL_SQLI         = 1
LABEL_XSS          = 2
LABEL_PATH_TRAV    = 3
LABEL_DIR_SCAN     = 4
LABEL_CVE          = 5
LABEL_LFI          = 6
