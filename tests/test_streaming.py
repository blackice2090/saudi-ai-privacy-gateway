import random

from tabayyan import EntityType
from tabayyan.streaming import scan_file
from tests.synthetic import make_iban, make_national_id


def test_streaming_matches_inmemory(tmp_path):
    rng = random.Random(70)
    # Build a large-ish file with entities scattered throughout.
    ids = [make_national_id(rng, "1") for _ in range(50)]
    ibans = [make_iban(rng) for _ in range(50)]
    parts = []
    for i in range(50):
        parts.append("lorem ipsum " * 20)
        parts.append(f" id {ids[i]} and iban {ibans[i]} ")
    text = "".join(parts)
    f = tmp_path / "big.txt"
    f.write_text(text)

    # Small chunk to force many boundaries.
    found_ids = set()
    found_ibans = set()
    for m in scan_file(f, chunk_size=256, overlap=64):
        if m.entity_type == EntityType.SAUDI_NATIONAL_ID:
            found_ids.add(m.value)
        elif m.entity_type == EntityType.SAUDI_IBAN:
            found_ibans.add(m.value)
    assert found_ids == set(ids)
    assert found_ibans == set(ibans)


def test_streaming_global_offsets(tmp_path):
    rng = random.Random(71)
    nid = make_national_id(rng, "1")
    prefix = "x" * 1000
    f = tmp_path / "off.txt"
    f.write_text(f"{prefix} id {nid}")
    matches = [m for m in scan_file(f, chunk_size=300, overlap=64)
               if m.entity_type == EntityType.SAUDI_NATIONAL_ID]
    assert len(matches) == 1
    m = matches[0]
    # Offset must index into the original text correctly.
    assert f"{prefix} id {nid}"[m.start:m.end] == nid


def test_no_duplicates_across_boundary(tmp_path):
    rng = random.Random(72)
    nid = make_national_id(rng, "1")
    # Place an entity so it lands near a chunk edge.
    f = tmp_path / "edge.txt"
    f.write_text("a" * 250 + f" {nid} " + "b" * 250)
    ids = [m for m in scan_file(f, chunk_size=256, overlap=64)
           if m.entity_type == EntityType.SAUDI_NATIONAL_ID]
    assert len(ids) == 1


def test_streaming_preserves_all_match_fields(tmp_path):
    # BUG-003 regression: scan_file must carry every Match field through,
    # including the label of custom detectors.
    from tabayyan.config import Config
    from tabayyan.engine import DetectionEngine  # noqa: F401 (parity import)

    cfg = Config.from_dict({
        "custom_detectors": [
            {"label": "employee_id", "pattern": "EMP-\\d{6}"},
        ]
    })
    engine = cfg.build_engine()

    f = tmp_path / "custom.txt"
    f.write_text("staff EMP-123456 record")

    streamed = list(scan_file(f, engine))
    in_memory = engine.scan(f.read_text())

    assert len(streamed) == len(in_memory) == 1
    s, m = streamed[0], in_memory[0]
    assert s.label == m.label == "employee_id"
    assert s.redacted() == m.redacted() == "[EMPLOYEE_ID]"
    assert (s.entity_type, s.category, s.confidence, s.value,
            s.detector, s.notes) == (m.entity_type, m.category,
                                     m.confidence, m.value,
                                     m.detector, m.notes)


def test_streaming_equivalent_to_inmemory_across_fields(tmp_path):
    rng = random.Random(71)
    text = " ".join(
        f"note id {make_national_id(rng, '1')} iban {make_iban(rng)}"
        for _ in range(20)
    )
    f = tmp_path / "eq.txt"
    f.write_text(text)

    from tabayyan.engine import DetectionEngine
    engine = DetectionEngine()

    streamed = sorted(
        ((m.start, m.end, m.entity_type, m.value, m.label, m.notes)
         for m in scan_file(f, engine, chunk_size=256, overlap=64)),
    )
    in_memory = sorted(
        ((m.start, m.end, m.entity_type, m.value, m.label, m.notes)
         for m in engine.scan(text)),
    )
    assert streamed == in_memory
