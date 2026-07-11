"""Detector plugin system: explicit registration + entry-point discovery."""
import pytest

from tabayyan import (
    DetectionEngine, discover_plugins, register_detector, registered_detectors,
    scan, unregister_all,
)
from tabayyan.detectors import registry
from tabayyan.detectors.base import Detector
from tabayyan.entities import Category, Confidence, EntityType, Match

_MARKER = "ZZSECRETZZ"


class KeywordDetector(Detector):
    name = "keyword_marker"

    def detect(self, text):
        i = text.find(_MARKER)
        if i >= 0:
            yield Match(EntityType.CUSTOM, Category.PERSON, Confidence.LOW,
                        i, i + len(_MARKER), _MARKER, self.name, label="marker")


@pytest.fixture(autouse=True)
def _clean_registry():
    unregister_all()
    yield
    unregister_all()


def test_register_instance_is_used_by_default_engine():
    register_detector(KeywordDetector())
    matches = scan(f"text with {_MARKER} inside")
    assert EntityType.CUSTOM in {m.entity_type for m in matches}


def test_register_decorator_on_class():
    @register_detector
    class _Dec(KeywordDetector):
        name = "decorated"

    assert any(isinstance(d, _Dec) for d in registered_detectors())


def test_register_rejects_non_detector():
    with pytest.raises(TypeError):
        register_detector(object())
    with pytest.raises(TypeError):
        register_detector(42)


def test_default_engine_is_unaffected_when_nothing_registered():
    # baseline: the marker is not a built-in entity
    assert EntityType.CUSTOM not in {m.entity_type for m in scan(f"text {_MARKER}")}


def test_explicit_detectors_override_ignores_registry():
    register_detector(KeywordDetector())
    # passing detectors explicitly bypasses the registry entirely
    eng = DetectionEngine(detectors=[])
    assert eng.scan(f"text {_MARKER}") == []


def test_discover_plugins_loads_entry_points(monkeypatch):
    class _FakeEP:
        name = "kw"
        def load(self):
            return KeywordDetector  # a class; registry coerces to an instance

    monkeypatch.setattr(registry, "_iter_entry_points", lambda group: [_FakeEP()])
    found = discover_plugins()
    assert len(found) == 1 and isinstance(found[0], KeywordDetector)
    assert EntityType.CUSTOM in {m.entity_type for m in scan(f"{_MARKER} here")}


def test_discover_plugins_contains_non_detector_entry_point(monkeypatch):
    # SEC-002: a bad plugin is reported, not registered — and it must not
    # abort discovery (see the isolation test below for the multi-EP case).
    class _BadEP:
        name = "bad"
        def load(self):
            return object
    monkeypatch.setattr(registry, "_iter_entry_points", lambda group: [_BadEP()])
    with pytest.warns(RuntimeWarning, match="failed to load detector plugin 'bad'"):
        found = discover_plugins()
    assert found == []
    assert registered_detectors() == []


def test_discover_plugins_isolates_individual_failures(monkeypatch):
    # SEC-002: one broken third-party plugin must not prevent the healthy
    # ones from loading.
    class _Boom:
        name = "boom"
        def load(self):
            raise ImportError("plugin import exploded")

    class _Good:
        name = "kw"
        def load(self):
            return KeywordDetector

    monkeypatch.setattr(
        registry, "_iter_entry_points", lambda group: [_Boom(), _Good()]
    )
    with pytest.warns(RuntimeWarning, match="'boom'.*ImportError"):
        found = discover_plugins()
    assert len(found) == 1 and isinstance(found[0], KeywordDetector)


def test_discover_plugins_is_idempotent(monkeypatch):
    # SEC-002: calling discovery twice must not register duplicates.
    class _EP:
        name = "kw"
        value = "tests.test_plugins:KeywordDetector"
        def load(self):
            return KeywordDetector

    monkeypatch.setattr(registry, "_iter_entry_points", lambda group: [_EP()])
    first = discover_plugins()
    second = discover_plugins()
    assert len(first) == 1
    assert second == []
    assert len(registered_detectors()) == 1


def test_unregister_all_resets_discovery(monkeypatch):
    class _EP:
        name = "kw"
        value = "tests.test_plugins:KeywordDetector"
        def load(self):
            return KeywordDetector

    monkeypatch.setattr(registry, "_iter_entry_points", lambda group: [_EP()])
    assert len(discover_plugins()) == 1
    unregister_all()
    assert registered_detectors() == []
    assert len(discover_plugins()) == 1  # discoverable again after reset
