import re
from datetime import datetime

from .base import BaseParser
from src.ingestion.schema import NormalizedLog


APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+)'                         # client IP
    r' \S+ \S+'                             # user
    r' \[(?P<time>[^\]]+)\]'                # timestamp
    r' "(?P<method>[A-Z]+)'                 # request method
    r' (?P<uri>[^ "]*)'                     # request URI
    r' HTTP/[0-9.]+"'                       # protocol
    r' (?P<status>\d{3})'                   # status code
    r' (?P<size>\S+)'                       # response size
    r'(?:\s+"(?P<referer>[^"]*)")?'         # referer 
    r'(?:\s+"(?P<ua>[^"]*)")?'              # user-agent 
)


class ApacheParser(BaseParser):
    def parse(self, line: str) -> NormalizedLog | None:
        """
        Parse 1 line
        """
        line = line.strip()
        if not line:
            return None

        match = APACHE_PATTERN.match(line)
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
            if referer in ("-", None, ""):
                referer = None
            user_agent = match.group("ua")
            if user_agent in ("-", None, ""):
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
                source="apache",
                raw_line=line,
            )

        except (ValueError, IndexError):
            return None
