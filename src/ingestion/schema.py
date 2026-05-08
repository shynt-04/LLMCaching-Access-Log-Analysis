from pydantic import BaseModel, field_validator
from datetime import datetime
from typing import Optional
from urllib.parse import unquote


class NormalizedLog(BaseModel):
    """
    Normalized log structure
    """

    #  Core fields 
    timestamp: datetime
    source_ip: str
    method: str                       
    path: str                # or URI           
    status_code: int
    source: str                         
    user_agent: Optional[str] = None
    response_size: Optional[int] = None
    query_string: Optional[str] = None
    content: Optional[str] = None
    referer: Optional[str] = None
    raw_line: str = ""                 

    # Filled by detectors
    rule_score: float = 0.0
    ml_score: float = 0.0
    flagged: bool = False

    #  Validators 
    @field_validator("path", mode="before")
    @classmethod
    def url_decode_path(cls, v: str) -> str:
        if isinstance(v, str):
            decoded = unquote(unquote(v))
            return decoded
        return v

    @field_validator("query_string", mode="before")
    @classmethod
    def url_decode_query(cls, v: Optional[str]) -> Optional[str]:
        if isinstance(v, str):
            return unquote(unquote(v))
        return v

    @field_validator("content", mode="before")
    @classmethod
    def url_decode_content(cls, v: Optional[str]) -> Optional[str]:
        if isinstance(v, str):
            return unquote(unquote(v))
        return v

    @field_validator("method", mode="before")
    @classmethod
    def uppercase_method(cls, v: str) -> str:
        if isinstance(v, str):
            return v.upper()
        return v

    @field_validator("status_code", mode="before")
    @classmethod
    def validate_status_code(cls, v: int) -> int:
        v = int(v)
        if not (100 <= v <= 599):
            raise ValueError(f"Invalid HTTP status code: {v}")
        return v
