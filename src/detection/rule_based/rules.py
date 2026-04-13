# src/detection/rule_based/rules.py
"""Rule definitions for pattern-based attack detection.

Each rule matches a specific attack pattern against a log field.
Rules are frozen dataclasses with pre-compiled regex patterns for
zero-allocation matching at runtime.
"""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Rule:
    name: str
    score: float        # base score if pattern matches (0.0–1.0)
    pattern: re.Pattern
    field: str          # "path" | "query_string" | "user_agent"
    attack_type: str    # "path_traversal" | "sqli" | "dir_scan" | "cve"


RULES: list[Rule] = [
    # ─── Path Traversal ─────────────────────────────────────────
    Rule(
        name="path_traversal_plain",
        score=0.70,
        pattern=re.compile(r'\.\.[/\\]'),
        field="path",
        attack_type="path_traversal",
    ),
    Rule(
        name="path_traversal_encoded",
        score=0.75,
        # URL-encoded and double-encoded ../ variants
        pattern=re.compile(r'%2e%2e|%252e|\.\.%2f|%2e%2e%2f', re.IGNORECASE),
        field="path",
        attack_type="path_traversal",
    ),
    Rule(
        name="path_traversal_backslash",
        score=0.70,
        # Backslash variants: ..\ or encoded %5c
        pattern=re.compile(r'\.\.%5c|%2e%2e%5c', re.IGNORECASE),
        field="path",
        attack_type="path_traversal",
    ),
    Rule(
        name="path_traversal_double_dot_slash",
        score=0.70,
        # Double-dot-slash: ....//
        pattern=re.compile(r'\.{3,}/|\.{2,}/\.{2,}/'),
        field="path",
        attack_type="path_traversal",
    ),
    Rule(
        name="path_traversal_in_query",
        score=0.65,
        pattern=re.compile(r'\.\.[/\\]'),
        field="query_string",
        attack_type="path_traversal",
    ),
    # ─── SQL Injection ───────────────────────────────────────────
    Rule(
        name="sqli_or_based",
        score=0.80,
        pattern=re.compile(
            r"(\bOR\b\s+\S+=\S+|'\s*OR\s*'1'\s*=\s*'1|\bOR\b\s+1\s*=\s*1)",
            re.IGNORECASE,
        ),
        field="query_string",
        attack_type="sqli",
    ),
    Rule(
        name="sqli_union_select",
        score=0.85,
        pattern=re.compile(r'\bUNION\b.+\bSELECT\b', re.IGNORECASE),
        field="query_string",
        attack_type="sqli",
    ),
    Rule(
        name="sqli_comment_terminator",
        score=0.70,
        pattern=re.compile(r"(--\s*$|;\s*--\s*$|'\s*--)", re.IGNORECASE),
        field="query_string",
        attack_type="sqli",
    ),
    Rule(
        name="sqli_drop_table",
        score=0.90,
        pattern=re.compile(r'\bDROP\b\s+\bTABLE\b', re.IGNORECASE),
        field="query_string",
        attack_type="sqli",
    ),
    Rule(
        name="sqli_sleep",
        score=0.75,
        pattern=re.compile(r'\bSLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(', re.IGNORECASE),
        field="query_string",
        attack_type="sqli",
    ),
    Rule(
        name="sqli_xp_cmdshell",
        score=0.90,
        pattern=re.compile(r'\bEXEC\b\s+\bxp_cmdshell\b', re.IGNORECASE),
        field="query_string",
        attack_type="sqli",
    ),
    Rule(
        name="sqli_load_file",
        score=0.85,
        pattern=re.compile(r'\bLOAD_FILE\b\s*\(', re.IGNORECASE),
        field="query_string",
        attack_type="sqli",
    ),
    Rule(
        name="sqli_information_schema",
        score=0.80,
        pattern=re.compile(r'\binformation_schema\b', re.IGNORECASE),
        field="query_string",
        attack_type="sqli",
    ),
    Rule(
        name="sqli_and_based",
        score=0.70,
        pattern=re.compile(
            r"\bAND\b\s+(1\s*=\s*1|\bSLEEP\b|\(SELECT\b)",
            re.IGNORECASE,
        ),
        field="query_string",
        attack_type="sqli",
    ),
    # ─── Directory Scanning ──────────────────────────────────────
    Rule(
        name="dir_scan_common",
        score=0.50,
        pattern=re.compile(
            r'/(wp-admin|wp-login|phpmyadmin|phpMyAdmin|pma|\.git|\.env|'
            r'admin|backup|config|\.htaccess|\.htpasswd|server-status|'
            r'server-info|swagger-ui|api-docs|debug|console|actuator)'
            r'(/|$|\?|\.)',
            re.IGNORECASE,
        ),
        field="path",
        attack_type="dir_scan",
    ),
    Rule(
        name="dir_scan_backup_files",
        score=0.55,
        pattern=re.compile(
            r'\.(sql|bak|old|orig|swp|zip|tar\.gz|tgz)$',
            re.IGNORECASE,
        ),
        field="path",
        attack_type="dir_scan",
    ),
    Rule(
        name="dir_scan_scanner_ua",
        score=0.60,
        pattern=re.compile(
            r'(DirBuster|Nikto|gobuster|dirsearch|sqlmap|Nmap|masscan)',
            re.IGNORECASE,
        ),
        field="user_agent",
        attack_type="dir_scan",
    ),
    # ─── CVE Exploits ────────────────────────────────────────────
    Rule(
        name="cve_telerik",
        score=0.90,
        pattern=re.compile(
            r'Telerik\.Web\.UI\.(WebResource|DialogHandler)',
            re.IGNORECASE,
        ),
        field="path",
        attack_type="cve",
    ),
    Rule(
        name="cve_liferay",
        score=0.90,
        pattern=re.compile(
            r'/api/jsonws|/c/portal/json_service',
            re.IGNORECASE,
        ),
        field="path",
        attack_type="cve",
    ),
    Rule(
        name="cve_log4shell",
        score=0.95,
        pattern=re.compile(
            r'\$\{jndi:|'
            r'\$\{\$\{lower:j\}ndi:|'
            r'\$\{\$\{::-j\}\$\{::-n\}\$\{::-d\}\$\{::-i\}:',
            re.IGNORECASE,
        ),
        field="user_agent",
        attack_type="cve",
    ),
    Rule(
        name="cve_spring4shell",
        score=0.90,
        pattern=re.compile(
            r'class\.module\.classLoader',
            re.IGNORECASE,
        ),
        field="query_string",
        attack_type="cve",
    ),
]
