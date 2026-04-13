import re
from datetime import datetime
from urllib.parse import unquote

from .base import BaseParser
from src.ingestion.schema import NormalizedLog


NGINX_PATTERN = re.compile(
    r'^(?P<ip>\S+)'                         # remote_addr
    r' \S+ \S+'                             # remote_user
    r' \[(?P<time>[^\]]+)\]'                # time_local
    r' "(?P<method>[A-Z]+)'                 # request method
    r' (?P<uri>[^ "]*)'                     # request URI
    r' HTTP/[0-9.]+"'                       # protocol
    r' (?P<status>\d{3})'                   # status
    r' (?P<size>\S+)'                       # body_bytes_sent
    r'(?: "(?P<referer>[^"]*)")?'           # http_referer
    r'(?: "(?P<ua>[^"]*)")?'               # http_user_agent
)


class NginxParser(BaseParser):
    def parse(self, line: str) -> NormalizedLog | None:
        """
        Parse 1 line
        """
        line = line.strip()
        if not line:
            return None

        match = NGINX_PATTERN.match(line)
        if not match:
            return None

        try:
            uri = match.group("uri") or ""
            if "?" in uri:
                path, query = uri.split("?", 1)
            else:
                path, query = uri, None

            timestamp = datetime.strptime(
                match.group("time"), "%d/%b/%Y:%H:%M:%S %z"
            )

            size_str = match.group("size")
            response_size = int(size_str) if size_str != "-" else 0

            referer = match.group("referer")
            if referer == "-":
                referer = None
            user_agent = match.group("ua")
            if user_agent == "-":
                user_agent = None

            return NormalizedLog(
                timestamp=timestamp,
                source_ip=match.group("ip"),
                method=match.group("method"),
                path=path,
                query_string=query,
                status_code=int(match.group("status")),
                response_size=response_size,
                user_agent=user_agent,
                referer=referer,
                source="nginx",
                raw_line=line,
            )

        except (ValueError, IndexError):
            return None
