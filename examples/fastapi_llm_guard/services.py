from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from tabayyan import AuditLog, Guard

from examples.fastapi_llm_guard.config import AppSettings
from examples.fastapi_llm_guard.schemas import DetectionSummary


class LlmClient(Protocol):
    """Minimal interface for an LLM client used by this example."""

    def generate(self, prompt: str) -> str:
        """Generate a response from a protected prompt."""


class FakeLlmClient:
    """Fake LLM client.

    This keeps the example offline and safe. Replace this class with a real
    provider client in production.
    """

    def generate(self, prompt: str) -> str:
        return f"Protected prompt received: {prompt}"


@dataclass
class ProtectedChatResult:
    safe_prompt: str
    llm_response: str
    detection: DetectionSummary


class LlmGuardService:
    """Coordinates PII protection before a prompt reaches an LLM client."""

    def __init__(self, settings: AppSettings, llm_client: LlmClient) -> None:
        self._settings = settings
        self._llm_client = llm_client
        self._guard = Guard(
            mode=settings.redaction_mode,
            audit=AuditLog(path=str(settings.audit_path)),
            block_cross_border=settings.block_cross_border,
        )

    def chat(self, prompt: str) -> ProtectedChatResult:
        protected = self._guard.protect(
            prompt,
            destination=self._settings.llm_destination,
        )

        llm_response = self._llm_client.generate(protected.text)

        return ProtectedChatResult(
            safe_prompt=protected.text,
            llm_response=llm_response,
            detection=DetectionSummary(
                pii_detected=bool(protected.matches),
                redacted_count=len(protected.matches),
                cross_border_transfer=protected.audit.cross_border_transfer,
            ),
        )