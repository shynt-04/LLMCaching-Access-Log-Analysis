from abc import ABC, abstractmethod
from src.ingestion.schema import NormalizedLog


class BaseParser(ABC):
    """
    Abstract base class for all log parsers.
    """

    @abstractmethod
    def parse(self, line: str) -> NormalizedLog | None:
        """
        Parse 1 line
        """
        ...

    def parse_many(self, lines: list[str]) -> list[NormalizedLog]:
        """
        Parse 1 list of lines
        """
        results = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parsed = self.parse(line)
            if parsed is not None:
                results.append(parsed)
        return results
