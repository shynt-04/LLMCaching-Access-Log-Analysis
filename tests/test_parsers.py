"""
Unit tests — Parsers, Schema, and Normalizer.

Run:
    python -m pytest tests/test_parsers.py -v
"""

import os
import sys
import pytest
from datetime import datetime, timezone, timedelta

from src.ingestion.schema import NormalizedLog
from src.ingestion.parsers.nginx_parser import NginxParser
from src.ingestion.parsers.apache_parser import ApacheParser
from src.ingestion.parsers.iis_parser import IISParser
from src.ingestion.normalizer import Normalizer


# ═══════════════════════════════════════════════════════════════════
#  NormalizedLog Schema Tests
# ═══════════════════════════════════════════════════════════════════

class TestNormalizedLogSchema:
    def test_url_decode_path(self):
        """Path must be URL-decoded: %2F → /, %2E → ."""
        log = NormalizedLog(
            timestamp=datetime.now(tz=timezone.utc),
            source_ip="10.0.0.1",
            method="GET",
            path="/%2e%2e/%2e%2e/etc/passwd",
            status_code=400,
            source="nginx",
        )
        assert log.path == "/../../../etc/passwd" or "etc/passwd" in log.path
        assert "%2e" not in log.path.lower()

    def test_double_encoded_path(self):
        """Decode correctly double encoding: %252e → %2e → ."""
        log = NormalizedLog(
            timestamp=datetime.now(tz=timezone.utc),
            source_ip="10.0.0.1",
            method="GET",
            path="/%252e%252e/etc/passwd",
            status_code=400,
            source="nginx",
        )
        assert "%25" not in log.path
        assert ".." in log.path

    def test_method_uppercase(self):
        """Method is always uppercase."""
        log = NormalizedLog(
            timestamp=datetime.now(tz=timezone.utc),
            source_ip="10.0.0.1",
            method="get",
            path="/",
            status_code=200,
            source="nginx",
        )
        assert log.method == "GET"

    def test_invalid_status_code_rejected(self):
        """Status code outside 100-599 range is rejected."""
        with pytest.raises(ValueError):
            NormalizedLog(
                timestamp=datetime.now(tz=timezone.utc),
                source_ip="10.0.0.1",
                method="GET",
                path="/",
                status_code=999,
                source="nginx",
            )

    def test_defaults(self):
        """Check default values of optional fields."""
        log = NormalizedLog(
            timestamp=datetime.now(tz=timezone.utc),
            source_ip="10.0.0.1",
            method="GET",
            path="/",
            status_code=200,
            source="nginx",
        )
        assert log.user_agent is None
        assert log.response_size is None
        assert log.query_string is None
        assert log.rule_score == 0.0
        assert log.flagged is False


# ═══════════════════════════════════════════════════════════════════
#  Nginx Parser Tests
# ═══════════════════════════════════════════════════════════════════

class TestNginxParser:
    """Tests for NginxParser."""

    @pytest.fixture
    def parser(self):
        return NginxParser()

    def test_parse_normal_line(self, parser):
        """Parse normal Nginx log line."""
        line = '31.56.96.51 - - [22/Jan/2019:03:56:16 +0330] "GET /image/60844/productModel/200x200 HTTP/1.1" 200 5667 "https://www.zanbil.ir/m/filter/b113" "Mozilla/5.0 (Linux; Android 6.0)" "-"'
        result = parser.parse(line)

        assert result is not None
        assert result.source_ip == "31.56.96.51"
        assert result.method == "GET"
        assert result.path == "/image/60844/productModel/200x200"
        assert result.status_code == 200
        assert result.response_size == 5667
        assert result.source == "nginx"
        assert result.user_agent == "Mozilla/5.0 (Linux; Android 6.0)"

    def test_parse_with_query_string(self, parser):
        """Parse line with query string."""
        line = '207.46.13.136 - - [22/Jan/2019:03:56:21 +0330] "GET /product/30649?model=60398 HTTP/1.1" 200 41198 "-" "Mozilla/5.0 (compatible; bingbot/2.0)" "-"'
        result = parser.parse(line)

        assert result is not None
        assert result.path == "/product/30649"
        assert result.query_string == "model=60398"

    def test_parse_attack_path_traversal(self, parser):
        """Parse line with path traversal attack."""
        line = '192.168.1.100 - - [22/Jan/2019:04:01:00 +0330] "GET /../../etc/passwd HTTP/1.1" 400 512 "-" "curl/7.68.0" "-"'
        result = parser.parse(line)

        assert result is not None
        assert ".." in result.path
        assert result.status_code == 400

    def test_parse_url_encoded_attack(self, parser):
        """URL-encoded path must be decoded correctly."""
        line = '192.168.1.100 - - [22/Jan/2019:04:01:10 +0330] "GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 400 512 "-" "python-requests/2.25.1" "-"'
        result = parser.parse(line)

        assert result is not None
        assert "%2e" not in result.path.lower()
        # Schema has decoded the path

    def test_malformed_line_returns_none(self, parser):
        """Malformed line returns None."""
        assert parser.parse("") is None
        assert parser.parse("this is not a log line") is None
        assert parser.parse("   ") is None

    def test_parse_404_status(self, parser):
        """Parse line with status 404."""
        line = '207.46.13.136 - - [22/Jan/2019:03:56:19 +0330] "GET /product/14926 HTTP/1.1" 404 33617 "-" "Mozilla/5.0 (compatible; bingbot/2.0)" "-"'
        result = parser.parse(line)

        assert result is not None
        assert result.status_code == 404

    def test_timestamp_has_timezone(self, parser):
        """Timestamp must have timezone info."""
        line = '10.0.0.1 - - [22/Jan/2019:04:00:01 +0330] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0" "-"'
        result = parser.parse(line)

        assert result is not None
        assert result.timestamp.tzinfo is not None

    def test_referer_dash_is_none(self, parser):
        """Referer = '-' must become None."""
        line = '10.0.0.1 - - [22/Jan/2019:04:00:01 +0330] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0" "-"'
        result = parser.parse(line)

        assert result is not None
        assert result.referer is None

    def test_referer_with_value(self, parser):
        """Referer with value must be preserved."""
        line = '10.0.0.1 - - [22/Jan/2019:04:00:01 +0330] "GET /page HTTP/1.1" 200 100 "https://www.example.com/" "Mozilla/5.0" "-"'
        result = parser.parse(line)

        assert result is not None
        assert result.referer == "https://www.example.com/"

    def test_raw_line_preserved(self, parser):
        """raw_line must preserve original line."""
        line = '10.0.0.1 - - [22/Jan/2019:04:00:01 +0330] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0" "-"'
        result = parser.parse(line)

        assert result is not None
        assert result.raw_line == line


# ═══════════════════════════════════════════════════════════════════
#  Apache Parser Tests
# ═══════════════════════════════════════════════════════════════════

class TestApacheParser:
    """Tests for ApacheParser."""

    @pytest.fixture
    def parser(self):
        return ApacheParser()

    def test_parse_combined_format(self, parser):
        """Parse Apache Combined Log Format."""
        line = '192.168.1.10 - admin [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 5432 "https://www.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        result = parser.parse(line)

        assert result is not None
        assert result.source_ip == "192.168.1.10"
        assert result.method == "GET"
        assert result.path == "/index.html"
        assert result.status_code == 200
        assert result.response_size == 5432
        assert result.source == "apache"
        assert result.referer == "https://www.example.com/"

    def test_parse_with_query(self, parser):
        """Parse Apache line with query string."""
        line = '10.0.0.5 - - [10/Oct/2024:13:57:00 -0700] "GET /products?category=electronics&page=2 HTTP/1.1" 200 34567 "https://www.example.com/products" "Mozilla/5.0"'
        result = parser.parse(line)

        assert result is not None
        assert result.path == "/products"
        assert result.query_string == "category=electronics&page=2"

    def test_parse_basic_format(self, parser):
        """Parse Apache Basic Log Format (no referer/UA)."""
        line = '127.0.0.1 - frank [10/Oct/2024:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.1" 200 2326'
        result = parser.parse(line)

        assert result is not None
        assert result.source_ip == "127.0.0.1"
        assert result.path == "/apache_pb.gif"

    def test_parse_path_traversal(self, parser):
        """Parse Apache line with path traversal."""
        line = '192.168.1.50 - - [10/Oct/2024:14:00:00 -0700] "GET /../../etc/passwd HTTP/1.1" 400 512 "-" "curl/7.68.0"'
        result = parser.parse(line)

        assert result is not None
        assert ".." in result.path
        assert result.status_code == 400

    def test_malformed_returns_none(self, parser):
        """Malformed line returns None."""
        assert parser.parse("") is None
        assert parser.parse("not a log line") is None

    def test_response_size_dash(self, parser):
        """Response size '-' must become 0."""
        line = '127.0.0.1 - - [10/Oct/2024:13:55:36 -0700] "GET /page HTTP/1.1" 304 -'
        result = parser.parse(line)

        assert result is not None
        assert result.response_size == 0


# ═══════════════════════════════════════════════════════════════════
#  IIS Parser Tests
# ═══════════════════════════════════════════════════════════════════

class TestIISParser:
    """Tests for IISParser."""

    @pytest.fixture
    def parser(self):
        return IISParser()

    def test_parse_with_fields_header(self, parser):
        """Parse with #Fields header then data line."""
        fields_line = "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken"
        parser.parse(fields_line)  # Should update fields

        data_line = "2024-03-13 14:23:45 192.168.1.1 GET /default.aspx - 80 - 10.0.0.50 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - 200 0 0 125"
        result = parser.parse(data_line)

        assert result is not None
        assert result.source_ip == "10.0.0.50"
        assert result.method == "GET"
        assert result.path == "/default.aspx"
        assert result.status_code == 200
        assert result.source == "iis"

    def test_skip_comment_lines(self, parser):
        """Lines starting with # return None."""
        assert parser.parse("#Software: Microsoft Internet Information Services 10.0") is None
        assert parser.parse("#Version: 1.0") is None
        assert parser.parse("#Date: 2024-03-13 00:00:00") is None

    def test_parse_with_query(self, parser):
        """Parse IIS data line with query string."""
        fields_line = "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken"
        parser.parse(fields_line)

        data_line = "2024-03-13 14:25:00 192.168.1.1 GET /products/list ProductID=100&page=1 80 admin 10.0.0.51 Mozilla/5.0+(Windows+NT+10.0) https://www.example.com 200 0 0 300"
        result = parser.parse(data_line)

        assert result is not None
        assert result.query_string == "ProductID=100&page=1"

    def test_timestamp_utc(self, parser):
        """IIS timestamp must be UTC."""
        fields_line = "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken"
        parser.parse(fields_line)

        data_line = "2024-03-13 14:23:45 192.168.1.1 GET /default.aspx - 80 - 10.0.0.50 Mozilla/5.0 - 200 0 0 125"
        result = parser.parse(data_line)

        assert result is not None
        assert result.timestamp.tzinfo == timezone.utc

    def test_user_agent_decode(self, parser):
        """User agent must decode + to space."""
        fields_line = "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken"
        parser.parse(fields_line)

        data_line = "2024-03-13 14:23:45 192.168.1.1 GET /page - 80 - 10.0.0.50 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - 200 0 0 125"
        result = parser.parse(data_line)

        assert result is not None
        assert "+" not in result.user_agent
        assert "Windows NT 10.0" in result.user_agent

    def test_malformed_returns_none(self, parser):
        """Malformed data line returns None."""
        fields_line = "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken"
        parser.parse(fields_line)
        assert parser.parse("only two fields") is None

    def test_query_dash_is_none(self, parser):
        """Query string '-' must become None."""
        fields_line = "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken"
        parser.parse(fields_line)

        data_line = "2024-03-13 14:23:45 192.168.1.1 GET /page - 80 - 10.0.0.50 Mozilla/5.0 - 200 0 0 125"
        result = parser.parse(data_line)

        assert result is not None
        assert result.query_string is None


# ═══════════════════════════════════════════════════════════════════
#  Normalizer Tests
# ═══════════════════════════════════════════════════════════════════

class TestNormalizer:
    """Tests for Normalizer."""

    @pytest.fixture
    def normalizer(self):
        return Normalizer()

    def test_detect_nginx(self, normalizer):
        """Auto-detect Nginx format."""
        lines = [
            '10.0.0.1 - - [22/Jan/2019:04:00:01 +0330] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0" "-"',
        ]
        assert normalizer.detect_source(lines) == "nginx"

    def test_detect_apache(self, normalizer):
        """Auto-detect Apache format."""
        lines = [
            '192.168.1.10 - admin [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 5432 "https://example.com/" "Mozilla/5.0"',
        ]
        assert normalizer.detect_source(lines) == "apache"

    def test_detect_iis(self, normalizer):
        """Auto-detect IIS format."""
        lines = [
            "#Software: Microsoft Internet Information Services 10.0",
            "#Fields: date time s-ip cs-method ...",
        ]
        assert normalizer.detect_source(lines) == "iis"

    def test_parse_line_nginx(self, normalizer):
        """Parse single line with specific source."""
        line = '10.0.0.1 - - [22/Jan/2019:04:00:01 +0330] "GET /test HTTP/1.1" 200 100 "-" "Mozilla/5.0" "-"'
        result = normalizer.parse_line(line, source="nginx")

        assert result is not None
        assert result.path == "/test"
        assert result.source == "nginx"

    def test_parse_file_sample_nginx(self, normalizer):
        """Parse sample_nginx.log file."""
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "raw", "sample_nginx.log"
        )
        if not os.path.isfile(filepath):
            pytest.skip("sample_nginx.log not found")

        results = normalizer.parse_file(filepath)
        assert len(results) > 0
        for r in results:
            assert isinstance(r, NormalizedLog)
            assert r.source == "nginx"

    def test_parse_file_sample_apache(self, normalizer):
        """Parse sample_apache.log file."""
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "raw", "sample_apache.log"
        )
        if not os.path.isfile(filepath):
            pytest.skip("sample_apache.log not found")

        results = normalizer.parse_file(filepath, source="apache")
        assert len(results) > 0
        for r in results:
            assert isinstance(r, NormalizedLog)
            assert r.source == "apache"

    def test_parse_file_sample_iis(self, normalizer):
        """Parse sample_iis.log file."""
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "raw", "sample_iis.log"
        )
        if not os.path.isfile(filepath):
            pytest.skip("sample_iis.log not found")

        results = normalizer.parse_file(filepath, source="iis")
        assert len(results) > 0
        for r in results:
            assert isinstance(r, NormalizedLog)
            assert r.source == "iis"

    def test_parse_file_max_lines(self, normalizer):
        """parse_file respects max_lines parameter."""
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "raw", "sample_nginx.log"
        )
        if not os.path.isfile(filepath):
            pytest.skip("sample_nginx.log not found")

        results = normalizer.parse_file(filepath, max_lines=5)
        assert len(results) == 5

    def test_parse_file_not_found(self, normalizer):
        """parse_file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            normalizer.parse_file("nonexistent.log")

    def test_parse_lines_auto_detect(self, normalizer):
        """parse_lines with auto-detect."""
        lines = [
            '10.0.0.1 - - [22/Jan/2019:04:00:01 +0330] "GET /page1 HTTP/1.1" 200 100 "-" "Mozilla/5.0" "-"',
            '10.0.0.2 - - [22/Jan/2019:04:00:02 +0330] "GET /page2 HTTP/1.1" 200 200 "-" "Mozilla/5.0" "-"',
        ]
        results = normalizer.parse_lines(lines)
        assert len(results) == 2


# ═══════════════════════════════════════════════════════════════════
#  Integration Tests — Parse rate
# ═══════════════════════════════════════════════════════════════════

class TestParseRate:
    """Tests ensuring parse rate >= 95% on sample files."""

    def _get_line_count(self, filepath: str) -> int:
        count = 0
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    count += 1
        return count

    def test_nginx_parse_rate(self):
        """Nginx parser must parse >= 95% lines in sample."""
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "raw", "sample_nginx.log"
        )
        if not os.path.isfile(filepath):
            pytest.skip("sample_nginx.log not found")

        normalizer = Normalizer()
        results = normalizer.parse_file(filepath, source="nginx")
        total_lines = self._get_line_count(filepath)

        rate = len(results) / total_lines if total_lines > 0 else 0
        assert rate >= 0.95, f"Nginx parse rate {rate:.1%} < 95%"

    def test_apache_parse_rate(self):
        """Apache parser must parse >= 95% lines in sample."""
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "raw", "sample_apache.log"
        )
        if not os.path.isfile(filepath):
            pytest.skip("sample_apache.log not found")

        normalizer = Normalizer()
        results = normalizer.parse_file(filepath, source="apache")
        total_lines = self._get_line_count(filepath)

        rate = len(results) / total_lines if total_lines > 0 else 0
        assert rate >= 0.95, f"Apache parse rate {rate:.1%} < 95%"

    def test_iis_parse_rate(self):
        """IIS parser must parse >= 95% data lines in sample."""
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "raw", "sample_iis.log"
        )
        if not os.path.isfile(filepath):
            pytest.skip("sample_iis.log not found")

        normalizer = Normalizer()
        results = normalizer.parse_file(filepath, source="iis")
        total_lines = self._get_line_count(filepath)

        rate = len(results) / total_lines if total_lines > 0 else 0
        assert rate >= 0.95, f"IIS parse rate {rate:.1%} < 95%"
