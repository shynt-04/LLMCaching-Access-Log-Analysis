import json, re
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class Rule:
    name: str
    score: float
    pattern: re.Pattern
    field: str          # "path" | "query_string" | "content" | "user_agent" | "any"
    attack_type: str
    source: str         # "custom" | "crs"

# CRS target keywords that map to fields we have in access logs
# If a rule targets ARGS or REQUEST_FILENAME, it applies to path/query
# If it targets REQUEST_HEADERS:User-Agent, it applies to user_agent
# If it only targets REQUEST_HEADERS:Referer or cookies, skip (no access log field)
_USABLE_TARGETS = {"ARGS", "ARGS_NAMES", "REQUEST_FILENAME", "XML:/*", "REQUEST_LINE",
                   "REQUEST_URI_RAW", "FILES", "FILES_NAMES"}
_UA_TARGETS = {"REQUEST_HEADERS:User-Agent"}
_SKIP_ONLY_TARGETS = {"REQUEST_HEADERS:Referer", "REQUEST_COOKIES",
                      "REQUEST_COOKIES_NAMES", "REQUEST_HEADERS:Cookie"}


def _should_include_crs_rule(target: str) -> str | None:
    """Determine the field mapping for a CRS rule target string.

    Returns 'any', 'user_agent', or None (skip).
    A target like 'REQUEST_COOKIES|ARGS|XML:/*' contains ARGS, so we include it.
    A target like 'REQUEST_HEADERS:Referer' alone has no access log equivalent.
    """
    parts = set(target.replace("!", "").split("|"))

    # If it contains usable targets (ARGS, REQUEST_FILENAME, etc.), apply to path/query
    if parts & _USABLE_TARGETS:
        return "any"
    # If it only has User-Agent, apply to user_agent
    if parts & _UA_TARGETS:
        return "user_agent"
    # Otherwise skip (cookie-only, referer-only rules)
    return None


def _load_crs_rules(crs_json: str = "data/rules/crs_rules.json") -> list[Rule]:
    """Load pre-parsed CRS rules from JSON (built by crs_parser.py).

    Filters out rules that target HTTP headers/cookies not present in
    access logs (Referer-only, Cookie-only). Maps remaining rules to
    the appropriate NormalizedLog field.
    """
    if not Path(crs_json).exists():
        return []
    entries = json.loads(Path(crs_json).read_text())
    rules = []
    for e in entries:
        field = _should_include_crs_rule(e.get("target", ""))
        if field is None:
            continue  # skip header/cookie-only rules

        # Skip overly broad regexes that match everything
        regex = e.get("regex", "")
        if regex in ("^[^#]+", ".*", ".+"):
            continue

        # Skip known false-positive CRS rules on access log data
        rule_id = e.get("id", 0)
        if rule_id in (942130,):  # 942130 triggers on numeric query params like model=9893
            continue

        try:
            rules.append(Rule(
                name=f"crs_{e['id']}",
                score=0.75,              # uniform CRS base score
                pattern=re.compile(regex, re.IGNORECASE),
                field=field,
                attack_type=e["attack_type"],
                source="crs",
            ))
        except re.error:
            continue  # skip if regex fails to compile
    return rules

# Custom rules — high-confidence CVE patterns not in CRS
_CUSTOM_RULES: list[Rule] = [
    Rule("cve_telerik", 0.92,
         re.compile(r'Telerik\.Web\.UI\.(WebResource|DialogHandler)', re.I),
         "path", "cve", "custom"),
    Rule("cve_liferay", 0.92,
         re.compile(r'/api/jsonws|/c/portal/json_service', re.I),
         "path", "cve", "custom"),
    Rule("cve_log4shell", 0.95,
         re.compile(r'\$\{.*j.*n.*d.*i.*:', re.I),
         "any", "cve", "custom"),
    Rule("cve_spring4shell", 0.92,
         re.compile(r'class\.module\.classLoader', re.I),
         "any", "cve", "custom"),
    Rule("path_traversal_plain", 0.70,
         re.compile(r'\.\.[/\\]'),
         "path", "path_traversal", "custom"),
    Rule("path_traversal_encoded", 0.75,
         re.compile(r'%2e%2e|%252e|\.\.%2f', re.I),
         "path", "path_traversal", "custom"),
    Rule("lfi_sensitive_file", 0.85,
         re.compile(r'(/etc/passwd|/etc/shadow|/proc/self|boot\.ini|win\.ini|wp-config\.php)', re.I),
         "any", "lfi", "custom"),
    Rule("lfi_stream_wrapper", 0.88,
         re.compile(r'(php://filter|php://input|zip://|data://|expect://|file=)', re.I),
         "any", "lfi", "custom"),
    Rule("sqli_union_or_boolean", 0.86,
         re.compile(r"(\bunion\b\s+(?:all\s+)?\bselect\b|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|--|#)", re.I),
         "any", "sqli", "custom"),
    Rule("sqli_time_or_metadata", 0.86,
         re.compile(r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|information_schema|load_file\s*\()", re.I),
         "any", "sqli", "custom"),
    Rule("xss_script_or_handler", 0.86,
         re.compile(r"(<script|<svg|onerror\s*=|onload\s*=|javascript:|document\.cookie)", re.I),
         "any", "xss", "custom"),
    Rule("ssrf_internal_metadata", 0.92,
         re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1|0\.0\.0\.0|::1)", re.I),
         "any", "ssrf", "custom"),
    Rule("ssrf_dangerous_scheme", 0.90,
         re.compile(r"\b(file|gopher|dict|ftp)://", re.I),
         "any", "ssrf", "custom"),
    Rule("ssti_template_expression", 0.90,
         re.compile(r"(\{\{[^{}]{1,80}\}\}|\$\{[^{}]{1,80}\}|<%=?|freemarker|velocity|jinja|tpl=)", re.I),
         "any", "ssti", "custom"),
    Rule("file_upload_executable", 0.88,
         re.compile(r"(upload|file|avatar|attachment).*(\.php|\.jsp|\.jspx|\.aspx|\.phtml|\.phar|filename=)", re.I),
         "any", "file_upload", "custom"),
    Rule("csrf_state_change_no_token", 0.45,
         re.compile(r"(^/|/)(transfer|change-password|delete-account|checkout|wire)(/|$)", re.I),
         "path", "csrf", "custom"),
    Rule("dir_scan", 0.50,
         re.compile(r'/(wp-admin|phpmyadmin|\.git|\.env|backup|config)(/|$)', re.I),
         "path", "dir_scan", "custom"),
    Rule("dir_scan_cfide_admin", 0.70,
         re.compile(r'^/CFIDE/administrator(?:/|$)', re.I),
         "path", "dir_scan", "custom"),
    Rule("scanner_ua_dirbuster", 0.65,
         re.compile(r'DirBuster|Nikto|sqlmap|nmap|masscan|wpscan', re.I),
         "user_agent", "dir_scan", "custom"),
]

# Combined ruleset — custom first (faster, higher confidence)
RULES: list[Rule] = _CUSTOM_RULES + _load_crs_rules()
