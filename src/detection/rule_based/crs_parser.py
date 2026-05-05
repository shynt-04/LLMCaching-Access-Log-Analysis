import re
from pathlib import Path

# CRS rule format: SecRule ARGS|REQUEST_URI "@rx <regex>" "id:...,..."
# We extract the regex and map it to our attack_type taxonomy
_RULE_PATTERN = re.compile(
    r'SecRule\s+(?P<target>\S+)\s+"@rx\s+(?P<regex>.+?)"\s*(?:\\\s*)?"(?P<opts>[^"]+)"',
    re.DOTALL
)
_ID_PATTERN = re.compile(r'id:(\d+)')

# Map CRS rule ID ranges to attack types
_ID_TO_TYPE = {
    range(941000, 942000): "xss",
    range(942000, 943000): "sqli",
    range(930000, 931000): "lfi",
    range(932000, 933000): "rce",
}

def parse_crs_file(conf_path: str) -> list[dict]:
    """Extract usable regex rules from a CRS .conf file.

    Returns list of dicts with keys: id, regex, attack_type, target.
    Skips rules with empty regex or unsupported targets.
    """
    rules = []
    text = Path(conf_path).read_text(errors="ignore")

    for m in _RULE_PATTERN.finditer(text):
        id_match = _ID_PATTERN.search(m["opts"])
        if not id_match:
            continue
        rule_id = int(id_match.group(1))
        attack_type = next(
            (t for r, t in _ID_TO_TYPE.items() if rule_id in r), "unknown"
        )
        if attack_type == "unknown":
            continue

        try:
            re.compile(m["regex"])  # validate regex compiles
        except re.error:
            continue  # skip malformed CRS regexes

        rules.append({
            "id":          rule_id,
            "regex":       m["regex"],
            "attack_type": attack_type,
            "target":      m["target"],
        })

    return rules
