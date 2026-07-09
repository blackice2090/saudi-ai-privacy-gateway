from __future__ import annotations

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    prompt: str = Field(
        min_length=1,
        description="User prompt that may contain sensitive information.",
    )


class DetectionSummary(BaseModel):
    pii_detected: bool
    redacted_count: int
    cross_border_transfer: bool


class ChatResponse(BaseModel):
    safe_prompt: str
    llm_response: str
    detection: DetectionSummary