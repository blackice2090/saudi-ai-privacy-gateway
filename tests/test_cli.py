import json
import random


from tabayyan.cli import main
from tests.synthetic import make_national_id

def test_scan_stdin_table(capsys, monkeypatch):
    nid = make_national_id(random.Random(50), "1")
    monkeypatch.setattr("sys.stdin", _FakeStdin(f"id {nid}"))
    rc = main(["scan"])
    out = capsys.readouterr().out
    assert "saudi_national_id" in out
    assert rc == 0

def test_scan_json(capsys, monkeypatch):
    nid = make_national_id(random.Random(51), "1")
    monkeypatch.setattr("sys.stdin", _FakeStdin(f"id {nid}"))
    main(["scan", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data[0]["matches"][0]["entity_type"] == "saudi_national_id"

def test_fail_on_find_exit_code(capsys, monkeypatch):
    nid = make_national_id(random.Random(52), "1")
    monkeypatch.setattr("sys.stdin", _FakeStdin(f"id {nid}"))
    rc = main(["scan", "--fail-on-find"])
    assert rc == 1

def test_fail_on_find_clean(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", _FakeStdin("clean text"))
    rc = main(["scan", "--fail-on-find"])
    assert rc == 0

def test_redact_stdin(capsys, monkeypatch):
    nid = make_national_id(random.Random(53), "1")
    monkeypatch.setattr("sys.stdin", _FakeStdin(f"id {nid} x"))
    main(["redact", "--mode", "mask"])
    out = capsys.readouterr().out
    assert nid not in out
    assert "[SAUDI_NATIONAL_ID]" in out

def test_min_confidence_filter(capsys, monkeypatch):
    # MRN is LOW; filtering to high should drop it.
    monkeypatch.setattr("sys.stdin", _FakeStdin("MRN: A1234567"))
    main(["scan", "--min-confidence", "high", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["matches"] == []

def test_file_input(tmp_path, capsys):
    nid = make_national_id(random.Random(54), "1")
    f = tmp_path / "sample.txt"
    f.write_text(f"patient id {nid}")
    main(["scan", str(f)])
    assert "saudi_national_id" in capsys.readouterr().out

def test_directory_batch(tmp_path, capsys):
    rng = random.Random(55)
    (tmp_path / "a.txt").write_text(f"id {make_national_id(rng, '1')}")
    (tmp_path / "b.md").write_text(f"id {make_national_id(rng, '1')}")
    (tmp_path / "ignore.bin").write_text("should be skipped")
    main(["scan", str(tmp_path)])
    out = capsys.readouterr().out
    assert out.count("saudi_national_id") == 2

class _FakeStdin:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text


# --- exit codes (BUG-002) ---

def test_missing_path_exits_2(capsys):
    rc = main(["scan", "definitely_missing_xyz.txt", "--fail-on-find"])
    assert rc == 2
    assert "cannot read" in capsys.readouterr().err


def test_missing_path_exits_2_without_fail_on_find(capsys):
    rc = main(["scan", "definitely_missing_xyz.txt"])
    assert rc == 2


def test_mixed_missing_and_found_prefers_error_code(tmp_path, capsys):
    nid = make_national_id(random.Random(56), "1")
    f = tmp_path / "a.txt"
    f.write_text(f"id {nid}")
    rc = main(["scan", str(f), "definitely_missing_xyz.txt", "--fail-on-find"])
    assert rc == 2  # I/O error outranks the findings code


def test_empty_directory_scan_warns_but_exits_0(tmp_path, capsys):
    (tmp_path / "ignore.bin").write_text("skipped")
    rc = main(["scan", str(tmp_path), "--fail-on-find"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "no scannable text files" in err


def test_stream_without_paths_exits_2(capsys):
    rc = main(["scan", "--stream"])
    assert rc == 2


def test_stream_with_stdin_exits_2(capsys):
    rc = main(["scan", "--stream", "-"])
    assert rc == 2


def test_redact_missing_path_exits_2(capsys):
    rc = main(["redact", "definitely_missing_xyz.txt"])
    assert rc == 2


def test_domains_missing_watchlist_exits_2(tmp_path, capsys):
    f = tmp_path / "note.txt"
    f.write_text("visit example.com")
    rc = main(["domains", str(f), "--watchlist", "no_such_watchlist.txt"])
    assert rc == 2


# --- hash salt sources (INFO-004) ---

def test_hash_salt_from_file(tmp_path, capsys, monkeypatch):
    nid = make_national_id(random.Random(57), "1")
    monkeypatch.setattr("sys.stdin", _FakeStdin(f"id {nid}"))
    keyfile = tmp_path / "key"
    keyfile.write_text("unit-test-key\n")
    rc = main(["redact", "--mode", "hash", "--salt-file", str(keyfile)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[HASH:" in out and nid not in out


def test_hash_salt_from_environment(capsys, monkeypatch):
    nid = make_national_id(random.Random(58), "1")
    monkeypatch.setattr("sys.stdin", _FakeStdin(f"id {nid}"))
    monkeypatch.setenv("TABAYYAN_SALT", "env-test-key")
    rc = main(["redact", "--mode", "hash"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[HASH:" in out and nid not in out


def test_hash_unreadable_salt_file_exits_2(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", _FakeStdin("x"))
    rc = main(["redact", "--mode", "hash", "--salt-file", "no_such_key_file"])
    assert rc == 2


def test_hash_without_any_salt_source_exits_2(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", _FakeStdin("x"))
    monkeypatch.delenv("TABAYYAN_SALT", raising=False)
    rc = main(["redact", "--mode", "hash"])
    assert rc == 2
