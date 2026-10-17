from typing import Literal

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    payload: str = Field(min_length=1, max_length=10_000)
    ai: Literal["auto", "always", "never"] = "auto"


class BatchRequest(BaseModel):
    payloads: list[str] = Field(min_length=1, max_length=100)
    ai: Literal["auto", "always", "never"] = "never"


class MatchOut(BaseModel):
    rule_id: str
    name: str
    category: str
    weight: int
    evidence: str


class AIOut(BaseModel):
    is_injection: bool
    confidence: float
    attack_type: str
    explanation: str
    safe_fix: str


class AnalyzeResponse(BaseModel):
    id: int | None = None
    score: int
    verdict: str
    normalized: str
    matches: list[MatchOut]
    ai_used: bool
    ai: AIOut | None = None
    ai_error: str | None = None


class LogRequest(BaseModel):
    log_text: str = Field(min_length=1, max_length=2_000_000)


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    ports: str | None = Field(default=None, max_length=100)
    authorized: bool = False  # caller must confirm they own / may test the target
