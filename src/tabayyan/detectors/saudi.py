"""Saudi-specific entity detectors — the differentiator."""
from __future__ import annotations

import re
from typing import Iterable

from ..checksums import iban_mod97_is_valid, saudi_id_is_valid
from ..entities import Category, Confidence, EntityType, Match
from .base import Detector

_ARABIC_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789")

# Context window (chars) within which a label must sit for a context-gated,
# format-only identifier to be accepted. Mirrors the original CR heuristic.
_CONTEXT_WINDOW = 40


def _normalise_digits(text: str) -> str:
    # Deliberately duplicated work when running under DetectionEngine (which
    # already folds digits in its normalization pre-pass): detectors are also
    # used standalone (direct .detect() calls, custom engine compositions
    # with normalize_input=False), and this length-preserving fold keeps them
    # safe there. str.translate is a single C-level pass; the overhead is
    # negligible relative to the regex scans.
    return text.translate(_ARABIC_DIGITS)


def _near(start: int, end: int, spans: list[tuple[int, int]], window: int = _CONTEXT_WINDOW) -> bool:
    """True if [start, end) is within `window` chars of any context span."""
    return any(abs(start - ke) <= window or abs(ks - end) <= window for ks, ke in spans)


class _ContextGatedDetector(Detector):
    """Shared loop for format+context detectors.

    These entities have a distinctive format but no checksum, so a candidate
    is accepted only when a context label sits within ``_CONTEXT_WINDOW``
    chars. Subclasses supply the context/number patterns (the candidate must
    be group 1), the classification triple, and the notes string;
    ``_fold_digits`` controls whether Arabic-Indic digits are folded first
    (label patterns that are letters-only don't need it).
    """

    _context: "re.Pattern[str]"
    _number: "re.Pattern[str]"
    _entity: EntityType
    _category: Category
    _confidence: Confidence
    _notes: str
    _fold_digits: bool = True

    def detect(self, text: str) -> Iterable[Match]:
        hay = _normalise_digits(text) if self._fold_digits else text
        spans = [m.span() for m in self._context.finditer(hay)]
        if not spans:
            return
        for m in self._number.finditer(hay):
            if not _near(m.start(1), m.end(1), spans):
                continue
            yield Match(
                entity_type=self._entity, category=self._category,
                confidence=self._confidence, start=m.start(1), end=m.end(1),
                value=m.group(1), detector=self.name, notes=self._notes,
            )


class SaudiNationalIdDetector(Detector):
    name = "saudi_national_id"
    _pattern = re.compile(r"(?<!\d)([12]\d{9})(?!\d)")

    def detect(self, text: str) -> Iterable[Match]:
        norm = _normalise_digits(text)
        for m in self._pattern.finditer(norm):
            value = m.group(1)
            if not saudi_id_is_valid(value):
                continue
            is_iqama = value[0] == "2"
            yield Match(
                entity_type=EntityType.SAUDI_IQAMA if is_iqama else EntityType.SAUDI_NATIONAL_ID,
                category=Category.NATIONAL_IDENTIFIER,
                confidence=Confidence.HIGH,
                start=m.start(1), end=m.end(1), value=value, detector=self.name,
                notes="checksum-valid; not verified against any registry",
            )


class SaudiIbanDetector(Detector):
    name = "saudi_iban"
    _pattern = re.compile(r"(?<![A-Z0-9])SA\d{2}(?:\s?[A-Z0-9]){20}(?![A-Z0-9])", re.IGNORECASE)

    def detect(self, text: str) -> Iterable[Match]:
        for m in self._pattern.finditer(text):
            compact = re.sub(r"\s", "", m.group(0)).upper()
            if len(compact) != 24 or not iban_mod97_is_valid(compact):
                continue
            yield Match(
                entity_type=EntityType.SAUDI_IBAN, category=Category.FINANCIAL,
                confidence=Confidence.HIGH, start=m.start(), end=m.end(),
                value=compact, detector=self.name, notes="mod-97 valid",
            )


class SaudiMobileDetector(Detector):
    name = "saudi_mobile"
    _pattern = re.compile(r"(?<!\d)(?:(?:00|\+)?966|0)5\d{8}(?!\d)")

    def detect(self, text: str) -> Iterable[Match]:
        norm = _normalise_digits(text)
        for m in self._pattern.finditer(norm):
            yield Match(
                entity_type=EntityType.SAUDI_MOBILE, category=Category.CONTACT,
                confidence=Confidence.MEDIUM, start=m.start(), end=m.end(),
                value=m.group(0), detector=self.name,
                notes="format-only; no checksum exists for MSISDN",
            )


class SaudiCrDetector(_ContextGatedDetector):
    name = "saudi_cr"
    _context = re.compile(r"(?:C\.?R\.?|commercial\s+registration|سجل\s*تجاري|س\.?ت\.?)", re.IGNORECASE)
    _number = re.compile(r"(?<!\d)(\d{10})(?!\d)")
    _entity = EntityType.SAUDI_CR
    _category = Category.ORGANISATION
    _confidence = Confidence.LOW
    _notes = "format+context only; no published checksum"


class MedicalRecordNumberDetector(Detector):
    name = "medical_record_number"
    _pattern = re.compile(
        r"(?:MRN|medical\s+record(?:\s+(?:no|number))?\.?"
        r"|رقم\s*(?:ال)?(?:ملف|سجل)(?:\s*(?:ال)?طبي)?"
        r"|(?:ال)?سجل\s*(?:ال)?طبي)"
        r"\s*[:#\-]?\s*([A-Za-z0-9\-]{4,20})",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> Iterable[Match]:
        for m in self._pattern.finditer(text):
            yield Match(
                entity_type=EntityType.MEDICAL_RECORD_NUMBER, category=Category.SENSITIVE_HEALTH,
                confidence=Confidence.LOW, start=m.start(1), end=m.end(1),
                value=m.group(1), detector=self.name,
                notes="context-only; MRN has no national format. Health data: PDPL/NDMO.",
            )


class SaudiLandlineDetector(Detector):
    """Fixed-line numbers: +966 1X XXXXXXX or 0 1X XXXXXXX.

    Area codes per the CITC/ITU-T national numbering plan for Saudi Arabia:
    011 (Riyadh/Central), 012 (Makkah/Western), 013 (Eastern), 014
    (Madinah/Northern), 016 (Hail/Qassim), 017 (Southern). 015 is not
    assigned, so it is excluded to avoid false positives.

    Distinct prefix from mobile (5...), so it is reliable standalone.
    """
    name = "saudi_landline"
    _pattern = re.compile(r"(?<!\d)(?:(?:00|\+)?966|0)1[1-46-7]\d{7}(?!\d)")

    def detect(self, text: str) -> Iterable[Match]:
        norm = _normalise_digits(text)
        for m in self._pattern.finditer(norm):
            yield Match(
                entity_type=EntityType.SAUDI_LANDLINE, category=Category.CONTACT,
                confidence=Confidence.MEDIUM, start=m.start(), end=m.end(),
                value=m.group(0), detector=self.name,
                notes="format-only; no checksum exists for a landline number",
            )


class SaudiVatDetector(_ContextGatedDetector):
    """ZATCA VAT / tax registration number: 15 digits, context-gated.

    A bare 15-digit run also matches some card PANs (e.g. Amex), so this is
    gated on a tax-context label and emitted at MEDIUM; if a span also looks
    like a Luhn-valid card, the engine keeps the higher-confidence card match.
    """
    name = "saudi_vat"
    _context = re.compile(
        r"(?:VAT|TRN|tax\s+(?:id|number|registration)|الرقم\s*الضريبي|ضريب)",
        re.IGNORECASE,
    )
    _number = re.compile(r"(?<!\d)(\d{15})(?!\d)")
    _entity = EntityType.SAUDI_VAT
    _category = Category.FINANCIAL
    _confidence = Confidence.MEDIUM
    _notes = "format+context only; ZATCA TRN has no public checksum"


class SaudiPassportDetector(_ContextGatedDetector):
    """Saudi passport number: one letter + 8 digits. Context-gated (LOW)."""
    name = "saudi_passport"
    _context = re.compile(r"(?:passport|جواز(?:\s*سفر)?|رقم\s*الجواز)", re.IGNORECASE)
    _number = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]\d{8})(?![A-Za-z0-9])")
    _entity = EntityType.SAUDI_PASSPORT
    _category = Category.NATIONAL_IDENTIFIER
    _confidence = Confidence.LOW
    _notes = "format+context only; passport numbers have no public checksum"
    _fold_digits = False  # candidate embeds a letter; original behavior ran on raw text


class SaudiBorderNumberDetector(_ContextGatedDetector):
    """Border/visa number (رقم الحدود / رقم التأشيرة): 10 digits, context-gated."""
    name = "saudi_border_number"
    _context = re.compile(
        r"(?:border\s*(?:no|number)|رقم\s*الحدود|تأشير|visa\s*(?:no|number))",
        re.IGNORECASE,
    )
    _number = re.compile(r"(?<!\d)(\d{10})(?!\d)")
    _entity = EntityType.SAUDI_BORDER_NUMBER
    _category = Category.NATIONAL_IDENTIFIER
    _confidence = Confidence.LOW
    _notes = "format+context only; issued to visitors (Hajj/Umrah/visa)"


class SaudiNationalAddressDetector(_ContextGatedDetector):
    """National Address short code (e.g. RRRD2929): 4 letters + 4 digits, context-gated."""
    name = "saudi_national_address"
    _context = re.compile(
        r"(?:national\s*address|short\s*address|العنوان\s*الوطني|الرمز\s*البريدي|رمز\s*المبنى)",
        re.IGNORECASE,
    )
    _number = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{4}\d{4})(?![A-Za-z0-9])")
    _entity = EntityType.SAUDI_NATIONAL_ADDRESS
    _category = Category.CONTACT
    _confidence = Confidence.LOW
    _notes = "format+context only; Saudi Post short address"
    _fold_digits = False  # candidate embeds letters; original behavior ran on raw text


class SaudiUnifiedNumberDetector(_ContextGatedDetector):
    """Unified national number for establishments (700 number): starts with 7,
    10 digits. Context-gated (LOW)."""
    name = "saudi_unified_number"
    # \b700\b matches the colloquial "700 number" but NOT a "700" that is just
    # a digit run inside the candidate itself (which would self-trigger).
    _context = re.compile(r"(?:unified\s*(?:national\s*)?number|الرقم\s*الموحد|\b700\b)", re.IGNORECASE)
    _number = re.compile(r"(?<!\d)(7\d{9})(?!\d)")
    _entity = EntityType.SAUDI_UNIFIED_NUMBER
    _category = Category.ORGANISATION
    _confidence = Confidence.LOW
    _notes = "format+context only; establishment unified number"


SAUDI_DETECTORS = [
    SaudiNationalIdDetector(), SaudiIbanDetector(), SaudiMobileDetector(),
    SaudiLandlineDetector(), SaudiCrDetector(), SaudiVatDetector(),
    SaudiPassportDetector(), SaudiBorderNumberDetector(),
    SaudiNationalAddressDetector(), SaudiUnifiedNumberDetector(),
    MedicalRecordNumberDetector(),
]
