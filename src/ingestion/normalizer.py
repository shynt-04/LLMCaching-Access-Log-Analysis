import os
from typing import Optional

from src.ingestion.schema import NormalizedLog
from src.ingestion.parsers.nginx_parser import NginxParser
from src.ingestion.parsers.apache_parser import ApacheParser
from src.ingestion.parsers.iis_parser import IISParser
from src.ingestion.parsers.base import BaseParser


class Normalizer:
    def __init__(self):
        self._parsers: dict[str, BaseParser] = {
            "nginx": NginxParser(),
            "apache": ApacheParser(),
            "iis": IISParser(),
        }

    def detect_source(self, sample_lines: list[str]) -> str:
        """
        Auto-detect log source from content.

        Heuristics:
        - IIS: lines start with # (comment/fields header)
        - Nginx/Apache: uses Combined Log Format, distinguished by
          minor format differences or by full parsing
        """
        for line in sample_lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith("#"):
                return "iis"

            if len(line) > 10 and line[4] == "-" and line[7] == "-":
                return "iis"

            if line.rstrip().endswith('"-"'):
                return "nginx"

            return "apache"

        return "nginx"  # fallback

    def parse_file(
        self,
        filepath: str,
        source: Optional[str] = None,
        max_lines: Optional[int] = None,
    ) -> list[NormalizedLog]:
        """
        Parse entire log file
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            if source is None:
                sample = []
                for i, line in enumerate(f):
                    sample.append(line)
                    if i >= 10:
                        break
                source = self.detect_source(sample)
                f.seek(0)

            parser = self._parsers.get(source)
            if parser is None:
                raise ValueError(f"Unsupported log source: {source}")

            results: list[NormalizedLog] = []
            for i, line in enumerate(f):
                if max_lines is not None and len(results) >= max_lines:
                    break
                parsed = parser.parse(line)
                if parsed is not None:
                    results.append(parsed)

        return results

    def parse_line(
        self, line: str, source: str = "nginx"
    ) -> NormalizedLog | None:
        """
        Parse 1 line
        """
        parser = self._parsers.get(source)
        if parser is None:
            raise ValueError(f"Unsupported log source: {source}")
        return parser.parse(line)

    def parse_lines(
        self, lines: list[str], source: Optional[str] = None
    ) -> list[NormalizedLog]:
        """
        Parse list of lines
        """
        if source is None:
            source = self.detect_source(lines[:10])

        parser = self._parsers.get(source)
        if parser is None:
            raise ValueError(f"Unsupported log source: {source}")

        return parser.parse_many(lines)
