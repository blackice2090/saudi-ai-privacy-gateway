from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from tabayyan import RedactionMode


@dataclass(frozen=True)
class AppSettings:
    """Runtime settings for the FastAPI LLM guard example."""

    audit_path: Path
    redaction_mode: RedactionMode = RedactionMode.MASK
    llm_destination: str = "https://api.openai.com"
    block_cross_border: bool = False


def get_settings() -> AppSettings:
    base_dir = Path(__file__).resolve().parent

    return AppSettings(
        audit_path=base_dir / "audit.jsonl",
    )