"""Configuration: customise detection without editing code.

Load a JSON config to enable/disable detectors, add custom regex
detectors, extend the confusable map, and tune thresholds. JSON is used
(not TOML) to keep zero runtime dependencies on Python 3.9.

Schema (all keys optional):
{
  "disable": ["saudi_cr", "arabic_name"],
  "typosquat_max_distance": 2,
  "confusables": {"ⅴ": "v"},
  "custom_detectors": [
    {"label": "employee_id", "pattern": "EMP-\\\\d{6}",
     "category": "organisation", "confidence": "medium"}
  ]
}

Custom-detector matches use entity_type CUSTOM; their configured label is
preserved in the `detector` and `notes` fields and in the mask placeholder.
"""
from __future__ import annotations

import json
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .confusables import register_confusables
from .detectors import DEFAULT_DETECTORS, Detector
from .engine import DetectionEngine
from .entities import Category, Confidence, EntityType, Match

_CONF = {c.value: c for c in Confidence}
_CAT = {c.value: c for c in Category}


class CustomRegexDetector(Detector):
    """A user-defined regex detector loaded from config."""

    def __init__(self, label: str, pattern: str, category: Category,
                 confidence: Confidence) -> None:
        self.name = f"custom:{label}"
        self.label = label
        self._rx = re.compile(pattern)
        self._category = category
        self._confidence = confidence

    def detect(self, text: str) -> Iterable[Match]:
        for m in self._rx.finditer(text):
            yield Match(
                entity_type=EntityType.CUSTOM, category=self._category,
                confidence=self._confidence, start=m.start(), end=m.end(),
                value=m.group(0), detector=self.name, label=self.label,
                notes=f"custom detector '{self.label}'",
            )

    def mask_label(self) -> str:
        return f"[{self.label.upper()}]"


_KNOWN_KEYS = {"disable", "typosquat_max_distance", "confusables", "custom_detectors"}


@dataclass
class Config:
    disable: set[str] = field(default_factory=set)
    typosquat_max_distance: int = 1
    custom_detectors: list[CustomRegexDetector] = field(default_factory=list)
    confusables: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        """Build a validated Config. Malformed entries raise ValueError with
        the offending entry and field named; probable mistakes (unknown keys,
        disable names that match nothing) warn instead of failing silently.
        """
        if not isinstance(data, dict):
            raise ValueError(
                f"config root must be a JSON object, got {type(data).__name__}"
            )
        unknown = set(data) - _KNOWN_KEYS
        if unknown:
            warnings.warn(
                f"tabayyan config: unknown key(s) ignored: {sorted(unknown)} "
                f"(recognised: {sorted(_KNOWN_KEYS)})",
                RuntimeWarning, stacklevel=2,
            )

        customs = []
        for i, spec in enumerate(data.get("custom_detectors", [])):
            where = f"custom_detectors[{i}]"
            if not isinstance(spec, dict):
                raise ValueError(f"{where} must be an object, got {type(spec).__name__}")
            missing = [k for k in ("label", "pattern") if not spec.get(k)]
            if missing:
                raise ValueError(f"{where} is missing required field(s): {', '.join(missing)}")
            where = f"{where} ({spec['label']!r})"
            category = spec.get("category", "organisation")
            if category not in _CAT:
                raise ValueError(
                    f"{where}: invalid category {category!r}; valid: {sorted(_CAT)}"
                )
            confidence = spec.get("confidence", "medium")
            if confidence not in _CONF:
                raise ValueError(
                    f"{where}: invalid confidence {confidence!r}; valid: {sorted(_CONF)}"
                )
            try:
                det = CustomRegexDetector(
                    label=spec["label"], pattern=spec["pattern"],
                    category=_CAT[category], confidence=_CONF[confidence],
                )
            except re.error as exc:
                raise ValueError(f"{where}: invalid regex pattern: {exc}") from exc
            customs.append(det)

        disable = set(data.get("disable", []))
        known_names = {d.name for d in DEFAULT_DETECTORS}
        unmatched = disable - known_names
        if unmatched:
            warnings.warn(
                f"tabayyan config: 'disable' name(s) match no built-in detector "
                f"and have no effect: {sorted(unmatched)} "
                f"(built-in names: {sorted(known_names)})",
                RuntimeWarning, stacklevel=2,
            )

        try:
            distance = int(data.get("typosquat_max_distance", 1))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"typosquat_max_distance must be an integer, "
                f"got {data.get('typosquat_max_distance')!r}"
            ) from exc

        confusables = data.get("confusables") or {}
        if not isinstance(confusables, dict):
            raise ValueError(
                f"confusables must be an object mapping characters to their "
                f"skeleton, got {type(confusables).__name__}"
            )

        return cls(
            disable=disable,
            typosquat_max_distance=distance,
            custom_detectors=customs,
            confusables=dict(confusables),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Config":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def apply_confusables(self) -> None:
        """Merge this config's confusable mappings into the process-global
        map used by the homoglyph/lookalike subsystem.

        Explicit by design: the merge affects every engine and every
        ``skeleton()`` call in the process, not just engines built from this
        config, so loading a Config no longer has that side effect
        implicitly. The CLI calls this when ``--config`` is given.
        """
        if self.confusables:
            register_confusables(self.confusables)

    def build_engine(self) -> DetectionEngine:
        detectors = [d for d in DEFAULT_DETECTORS if d.name not in self.disable]
        detectors.extend(self.custom_detectors)
        return DetectionEngine(detectors)
