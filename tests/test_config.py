import json

import pytest

from tabayyan.config import Config


def _cfg(tmp_path, data):
    f = tmp_path / "c.json"
    f.write_text(json.dumps(data))
    return Config.from_file(f)


def test_disable_detector(tmp_path):
    eng = _cfg(tmp_path, {"disable": ["saudi_cr"]}).build_engine()
    ms = eng.scan("commercial registration 1010123456")
    assert all(m.entity_type.value != "saudi_cr" for m in ms)


def test_custom_detector_with_label(tmp_path):
    eng = _cfg(tmp_path, {"custom_detectors": [
        {"label": "employee_id", "pattern": r"EMP-\d{6}",
         "category": "organisation", "confidence": "medium"}]}).build_engine()
    ms = eng.scan("staff EMP-004521")
    assert len(ms) == 1
    assert ms[0].entity_type.value == "custom"
    assert ms[0].label == "employee_id"
    assert ms[0].redacted() == "[EMPLOYEE_ID]"


def test_confusables_extension_is_explicit(tmp_path):
    # Loading a config must NOT mutate the process-global confusable map;
    # apply_confusables() is the explicit opt-in (the CLI calls it).
    from tabayyan.confusables import skeleton

    cfg = _cfg(tmp_path, {"confusables": {"\u24e6": "w"}})  # circled w -> w
    assert skeleton("\u24e6eb") != "web"  # not applied by mere loading
    cfg.apply_confusables()
    assert skeleton("\u24e6eb") == "web"  # applied after explicit opt-in


def test_typosquat_distance_passthrough(tmp_path):
    cfg = _cfg(tmp_path, {"typosquat_max_distance": 3})
    assert cfg.typosquat_max_distance == 3


# --- validation (BUG-006) ---

def test_missing_required_fields_raise_actionable_error(tmp_path):
    with pytest.raises(ValueError, match=r"custom_detectors\[0\].*pattern"):
        _cfg(tmp_path, {"custom_detectors": [{"label": "x"}]})
    with pytest.raises(ValueError, match=r"custom_detectors\[0\].*label"):
        _cfg(tmp_path, {"custom_detectors": [{"pattern": "X-\\d"}]})


def test_invalid_category_and_confidence_raise(tmp_path):
    with pytest.raises(ValueError, match="invalid category 'people'"):
        _cfg(tmp_path, {"custom_detectors": [
            {"label": "x", "pattern": "X-\\d", "category": "people"}]})
    with pytest.raises(ValueError, match="invalid confidence 'certain'"):
        _cfg(tmp_path, {"custom_detectors": [
            {"label": "x", "pattern": "X-\\d", "confidence": "certain"}]})


def test_invalid_regex_raises_with_entry_named(tmp_path):
    with pytest.raises(ValueError, match=r"'broken'.*invalid regex"):
        _cfg(tmp_path, {"custom_detectors": [
            {"label": "broken", "pattern": "(unclosed"}]})


def test_non_object_spec_raises(tmp_path):
    with pytest.raises(ValueError, match=r"custom_detectors\[0\] must be an object"):
        _cfg(tmp_path, {"custom_detectors": ["EMP-\\d{6}"]})


def test_unknown_top_level_keys_warn(tmp_path):
    with pytest.warns(RuntimeWarning, match="unknown key"):
        _cfg(tmp_path, {"disble": ["saudi_cr"]})  # typo'd key


def test_unknown_disable_names_warn(tmp_path):
    with pytest.warns(RuntimeWarning, match="match no built-in detector"):
        cfg = _cfg(tmp_path, {"disable": ["saudi_nationalid"]})  # typo
    # and the typo has no effect: all built-ins still active
    assert cfg.build_engine().scan("id 1158813996")


def test_invalid_typosquat_distance_raises(tmp_path):
    with pytest.raises(ValueError, match="typosquat_max_distance"):
        _cfg(tmp_path, {"typosquat_max_distance": "three"})


def test_config_isolated_between_engines(tmp_path):
    # A config's custom detectors must not leak into engines built without it.
    from tabayyan.engine import DetectionEngine

    cfg = _cfg(tmp_path, {"custom_detectors": [
        {"label": "employee_id", "pattern": "EMP-\\d{6}"}]})
    with_cfg = cfg.build_engine().scan("EMP-123456")
    without_cfg = DetectionEngine().scan("EMP-123456")
    assert len(with_cfg) == 1
    assert without_cfg == []
