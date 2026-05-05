from datetime import datetime, timezone
from urllib.parse import unquote

from .base import BaseParser
from src.ingestion.schema import NormalizedLog


DEFAULT_IIS_FIELDS = [
    "date", "time", "s-ip", "cs-method", "cs-uri-stem",
    "cs-uri-query", "s-port", "cs-username", "c-ip",
    "cs(User-Agent)", "cs(Referer)", "sc-status",
    "sc-substatus", "sc-win32-status", "time-taken",
]


class IISParser(BaseParser):
    def __init__(self, fields: list[str] | None = None):
        self.fields = fields or DEFAULT_IIS_FIELDS

    def update_fields(self, fields_line: str) -> None:
        """
        Update field list from #Fields line.
        """
        if fields_line.startswith("#Fields:"):
            self.fields = fields_line[len("#Fields:"):].strip().split()

    def parse(self, line: str) -> NormalizedLog | None:
        """
        Parse 1 line
        """
        line = line.strip()
        if not line:
            return None

        if line.startswith("#Fields:"):
            self.update_fields(line)
            return None

        if line.startswith("#"):
            return None

        try:
            parts = line.split(" ")

            if len(parts) < len(self.fields):
                return None

            raw_data = dict(zip(self.fields, parts))

            date_str = raw_data.get("date", "")
            time_str = raw_data.get("time", "")
            if date_str and time_str:
                timestamp = datetime.strptime(
                    f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S"
                ).replace(tzinfo=timezone.utc)
            else:
                return None

            path = raw_data.get("cs-uri-stem", "/")
            query = raw_data.get("cs-uri-query", "-")
            query = None if query == "-" else query

            user_agent = raw_data.get("cs(User-Agent)", "-")
            if user_agent != "-":
                user_agent = unquote(user_agent.replace("+", " "))
            else:
                user_agent = None

            referer = raw_data.get("cs(Referer)", "-")
            if referer == "-":
                referer = None
                
            status_raw = raw_data.get("sc-status", "200")
            try:
                status = int(status_raw)
                if status == 0:
                    status = 200
            except ValueError:
                status = 200
                
            source_ip = raw_data.get("c-ip", raw_data.get("s-ip", ""))
            method = raw_data.get("cs-method", "GET")

            return NormalizedLog(
                timestamp=timestamp,
                source_ip=source_ip,
                method=method,
                path=path,
                query_string=query,
                status_code=status,
                response_size=None,
                user_agent=user_agent,
                referer=referer,
                source="iis",
                raw_line=line,
            )

        except (ValueError, IndexError, KeyError):
            return None
