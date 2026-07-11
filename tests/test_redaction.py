import random

from tabayyan import (
    DetectionEngine, RedactionMode, redact, scan_and_redact,
)
from tests.synthetic import make_iban, make_national_id

engine = DetectionEngine()


def test_mask_replaces_with_placeholder():
    nid = make_national_id(random.Random(40), "1")
    text = f"id {nid} done"
    result = scan_and_redact(text, RedactionMode.MASK)
    assert "[SAUDI_NATIONAL_ID]" in result.text
    assert nid not in result.text
    assert result.count == 1


def test_remove_deletes_value():
    nid = make_national_id(random.Random(41), "1")
    result = scan_and_redact(f"id {nid} done", RedactionMode.REMOVE)
    assert nid not in result.text
    assert "id  done" == result.text


def test_hash_is_deterministic_and_irreversible():
    nid = make_national_id(random.Random(42), "1")
    r1 = scan_and_redact(f"a {nid}", "hash", salt="s")
    r2 = scan_and_redact(f"b {nid}", "hash", salt="s")
    tok1 = r1.items[0].replacement
    tok2 = r2.items[0].replacement
    assert tok1 == tok2          # deterministic across inputs
    assert nid not in tok1       # value not present
    assert tok1.startswith("[HASH:")


def test_hash_salt_changes_token():
    nid = make_national_id(random.Random(43), "1")
    a = scan_and_redact(f"x {nid}", "hash", salt="A").items[0].replacement
    b = scan_and_redact(f"x {nid}", "hash", salt="B").items[0].replacement
    assert a != b


def test_hash_requires_non_empty_salt():
    nid = make_national_id(random.Random(431), "1")
    import pytest
    with pytest.raises(ValueError):
        scan_and_redact(f"x {nid}", "hash")           # empty default salt
    with pytest.raises(ValueError):
        scan_and_redact(f"x {nid}", "hash", salt="")  # explicit empty salt


def test_partial_keeps_last_n():
    nid = make_national_id(random.Random(44), "1")
    result = scan_and_redact(f"id {nid}", "partial", partial_keep_last=4)
    repl = result.items[0].replacement
    assert repl.endswith(nid[-4:])
    assert repl.count("*") == len(nid) - 4


def test_keep_last_alias_matches_cli_naming():
    nid = make_national_id(random.Random(441), "1")
    # keep_last (CLI's --keep-last) is an alias for partial_keep_last
    a = scan_and_redact(f"id {nid}", "partial", keep_last=2).items[0].replacement
    b = scan_and_redact(f"id {nid}", "partial", partial_keep_last=2).items[0].replacement
    assert a == b
    assert a.endswith(nid[-2:])


def test_multiple_matches_offsets_preserved():
    rng = random.Random(45)
    nid = make_national_id(rng, "1")
    iban = make_iban(rng)
    text = f"ID={nid} and IBAN={iban} end"
    result = scan_and_redact(text, RedactionMode.MASK)
    # Both redacted, surrounding literals intact, nothing leaked.
    assert nid not in result.text and iban not in result.text
    assert result.text.startswith("ID=[")
    assert result.text.endswith(" end")
    assert result.count == 2


def test_partial_short_value_is_fully_masked():
    # PRIV-001 regression: keep_last >= len(value) must never return the raw
    # value. A 4-char MRN under the default keep_last=4 previously leaked.
    result = scan_and_redact("MRN: AB12", "partial")
    assert "AB12" not in result.text
    assert result.items[0].replacement == "****"


def test_partial_keep_last_equal_to_length_masks_everything():
    nid = make_national_id(random.Random(47), "1")
    result = scan_and_redact(f"id {nid}", "partial", keep_last=len(nid))
    assert nid not in result.text
    assert result.items[0].replacement == "*" * len(nid)


def test_partial_keep_last_larger_than_length_masks_everything():
    nid = make_national_id(random.Random(48), "1")
    result = scan_and_redact(f"id {nid}", "partial", keep_last=100)
    assert nid not in result.text
    assert result.items[0].replacement == "*" * len(nid)


def test_partial_zero_and_negative_keep_last_mask_everything():
    nid = make_national_id(random.Random(49), "1")
    for kl in (0, -3):
        result = scan_and_redact(f"id {nid}", "partial", keep_last=kl)
        assert nid not in result.text
        assert result.items[0].replacement == "*" * len(nid)


def test_partial_short_custom_detector_value_is_fully_masked():
    from tabayyan.config import CustomRegexDetector
    from tabayyan.entities import Category, Confidence

    det = CustomRegexDetector("code", r"C-\d", Category.ORGANISATION, Confidence.MEDIUM)
    custom_engine = DetectionEngine([det])
    text = "ref C-7 ok"
    result = redact(text, custom_engine.scan(text), "partial", keep_last=4)
    assert "C-7" not in result.text
    assert result.items[0].replacement == "***"


def test_redact_accepts_string_mode():
    nid = make_national_id(random.Random(46), "1")
    matches = engine.scan(f"id {nid}")
    result = redact(f"id {nid}", matches, "mask")
    assert nid not in result.text


def test_clean_text_unchanged():
    result = scan_and_redact("nothing sensitive here", RedactionMode.MASK)
    assert result.text == "nothing sensitive here"
    assert result.count == 0
