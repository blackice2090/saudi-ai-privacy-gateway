"""Property-based tests (Hypothesis).

The project is built on Unicode normalization, offset mapping, checksums, and
reversible tokenization — all areas where hand-written examples miss edge
cases. These check invariants that must hold for *any* input, not a chosen few.
"""
from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from tabayyan import RedactionMode, restore, scan, scan_and_redact
from tabayyan.checksums import (
    iban_check_digits, iban_mod97_is_valid, luhn_check_digit, luhn_is_valid,
    saudi_id_check_digit, saudi_id_is_valid,
)
from tabayyan.normalize import normalize

# Hypothesis' own deadline is flaky on shared CI runners; disable it.
settings.register_profile("ci", deadline=None, max_examples=200)
settings.load_profile("ci")

_DIGITS = "0123456789"
# Historically this blacklisted angle brackets so generated input could not
# collide with a tokenize placeholder like <SAUDI_NATIONAL_ID_1>. Token
# assignment now skips token strings that already occur in the input, so the
# restriction is kept only to preserve this test's historical corpus; the
# unrestricted case is covered separately below.
_safe_text = st.text(st.characters(blacklist_characters="<>"), max_size=120)


# --- normalization invariants ---

@given(st.text(max_size=200))
def test_normalize_is_idempotent(t):
    once = normalize(t).text
    assert normalize(once).text == once


@given(st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=200))
def test_normalize_is_identity_on_ascii(t):
    n = normalize(t)
    assert n.text == t
    if t:
        assert n.map_span(0, len(t)) == (0, len(t))


@given(st.text(max_size=200))
def test_normalized_offsets_stay_in_bounds(t):
    n = normalize(t)
    for k in range(len(n.text)):
        o_start, o_end = n.map_span(k, k + 1)
        assert 0 <= o_start <= o_end <= len(t)


@given(st.text(max_size=200))
def test_normalization_never_grows_unboundedly(t):
    # back-map has exactly one source index per normalized char
    n = normalize(t)
    assert len(n._src) == len(n.text)


# --- checksum invariants ---

@given(st.text(alphabet=_DIGITS, min_size=8, max_size=8), st.sampled_from(["1", "2"]))
def test_saudi_id_checkdigit_roundtrips(rest, lead):
    first_nine = lead + rest
    valid = first_nine + str(saudi_id_check_digit(first_nine))
    assert saudi_id_is_valid(valid)


@given(st.text(alphabet=_DIGITS, min_size=8, max_size=8), st.sampled_from(["1", "2"]))
def test_saudi_id_rejects_wrong_checkdigit(rest, lead):
    first_nine = lead + rest
    correct = saudi_id_check_digit(first_nine)
    for wrong in range(10):
        if wrong != correct:
            assert not saudi_id_is_valid(first_nine + str(wrong))


@given(st.text(alphabet=_DIGITS, min_size=1, max_size=22))
def test_luhn_checkdigit_roundtrips(body):
    assert luhn_is_valid(body + str(luhn_check_digit(body)))


@given(st.text(alphabet=_DIGITS, min_size=20, max_size=20))
def test_iban_checkdigits_roundtrip(bban):
    check = iban_check_digits("SA", bban)
    assert iban_mod97_is_valid("SA" + check + bban)


# --- redaction invariants ---

@given(_safe_text)
def test_tokenize_restore_is_lossless(t):
    result = scan_and_redact(t, RedactionMode.TOKENIZE)
    assert restore(result.text, result.vault) == t


@given(st.text(max_size=120))
def test_tokenize_restore_is_lossless_with_token_like_text(t):
    # BUG-004 regression: round trips must hold even when the input already
    # contains angle brackets or literal token-shaped strings.
    result = scan_and_redact(t, RedactionMode.TOKENIZE)
    assert restore(result.text, result.vault) == t


@given(st.text(max_size=200))
def test_resolved_match_spans_are_disjoint_in_original_text(t):
    # INFO-005 regression: after projection back onto the original text, the
    # spans the engine returns must be in-bounds and pairwise disjoint, so
    # redaction can never rewrite overlapping ranges.
    spans = sorted((m.start, m.end) for m in scan(t))
    for s, e in spans:
        assert 0 <= s <= e <= len(t)
    for (_, e1), (s2, _) in zip(spans, spans[1:]):
        assert e1 <= s2


@given(_safe_text)
def test_mask_redaction_is_idempotent_on_clean_text(t):
    # masking text that has no detectable PII leaves it unchanged
    first = scan_and_redact(t, RedactionMode.MASK)
    if first.count == 0:
        assert first.text == t
