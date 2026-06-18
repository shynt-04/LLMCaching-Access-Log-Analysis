from src.ingestion.schema import NormalizedLog


def build_content_text(log: NormalizedLog) -> str:
    """Construct the content representation fed to TF-IDF.

    Concatenates request fields where payloads commonly appear. The current
    thesis pipeline is content-only; legacy behavioral features live under
    the top-level legacy/ directory.
    """
    parts = [log.path or ""]
    if log.query_string:
        parts.append(log.query_string)
    if log.content:
        parts.append(log.content)
    if log.user_agent:
        parts.append(log.user_agent[:100])
    return " ".join(parts)
