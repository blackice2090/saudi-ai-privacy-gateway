"""Command-line interface for Tabayyan. Stdlib only.

Commands:
  tabayyan scan    [paths...]  detect entities, print findings
  tabayyan redact  [paths...]  detect + redact, print sanitised text

Reads stdin when no path is given or path is '-'. Supports batch over
files and directories.

Exit codes:
  0  clean run (or findings without --fail-on-find)
  1  entities found and --fail-on-find was given (CI / pre-commit gates)
  2  input, usage, or I/O error (missing/unreadable path, bad salt source,
     broken pipe, ...)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable

from . import __version__
from .config import Config
from .engine import DetectionEngine
from .streaming import scan_file
from .entities import Confidence, Match
from .homoglyph import scan_text as _scan_domains
from .redaction import RedactionMode, redact

_CONFIDENCE_ORDER = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
_TEXT_SUFFIXES = {".txt", ".md", ".log", ".json", ".csv", ".eml", ".text"}


def _iter_inputs(paths: list[str], errors: list[str]) -> Iterable[tuple[str, str]]:
    """Yield (source_name, text). '-' or empty -> stdin.

    Unreadable or missing paths are reported on stderr and recorded in
    `errors` so callers can exit non-zero: a gate that silently scans
    nothing must not look like a clean pass.
    """
    if not paths or paths == ["-"]:
        yield ("<stdin>", sys.stdin.read())
        return
    for raw in paths:
        if raw == "-":
            yield ("<stdin>", sys.stdin.read())
            continue
        p = Path(raw)
        if p.is_dir():
            matched_any = False
            for child in sorted(p.rglob("*")):
                if child.is_file() and child.suffix.lower() in _TEXT_SUFFIXES:
                    matched_any = True
                    try:
                        yield (str(child), child.read_text(encoding="utf-8", errors="replace"))
                    except OSError as exc:
                        errors.append(str(child))
                        print(f"tabayyan: cannot read '{child}': {exc}", file=sys.stderr)
            if not matched_any:
                suffixes = " ".join(sorted(_TEXT_SUFFIXES))
                print(
                    f"tabayyan: warning: no scannable text files under '{raw}' "
                    f"(recognised suffixes: {suffixes})",
                    file=sys.stderr,
                )
        elif p.is_file():
            try:
                yield (str(p), p.read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                errors.append(raw)
                print(f"tabayyan: cannot read '{raw}': {exc}", file=sys.stderr)
        else:
            errors.append(raw)
            print(f"tabayyan: cannot read '{raw}'", file=sys.stderr)


def _engine_from_args(args) -> DetectionEngine:
    cfg = getattr(args, "config", None)
    if not cfg:
        return DetectionEngine()
    config = Config.from_file(cfg)
    config.apply_confusables()  # CLI runs are process-scoped; opt in globally
    return config.build_engine()


def _filter_matches(matches: list[Match], args) -> list[Match]:
    out = matches
    if args.min_confidence:
        floor = _CONFIDENCE_ORDER[Confidence(args.min_confidence)]
        out = [m for m in out if _CONFIDENCE_ORDER[m.confidence] >= floor]
    if args.only:
        only = set(args.only)
        out = [m for m in out if m.entity_type.value in only]
    if args.exclude:
        excl = set(args.exclude)
        out = [m for m in out if m.entity_type.value not in excl]
    return out


def _exit_code(found_any: bool, errors: list[str], fail_on_find: bool) -> int:
    if errors:
        return 2
    return 1 if (found_any and fail_on_find) else 0


def _emit_scan_result(name: str, matches: list[Match], args, report: list) -> None:
    """Print one source's matches (table mode) or append them to `report`
    (JSON mode). Shared by the streaming and in-memory scan paths."""
    if args.json:
        report.append({"source": name, "matches": [m.to_dict() for m in matches]})
        return
    for m in matches:
        val = "" if args.no_values else f"  {m.value!r}"
        print(f"{name}:{m.start}-{m.end}\t{m.entity_type.value}\t"
              f"{m.confidence.value}\t{m.category.value}{val}")


def _cmd_scan(args) -> int:
    engine = _engine_from_args(args)
    found_any = False
    errors: list[str] = []
    report: list = []
    if args.stream:
        if not args.paths or any(raw in ("", "-") for raw in args.paths):
            print("tabayyan: --stream requires file paths, not stdin", file=sys.stderr)
            return 2
        sources = None
    else:
        sources = _iter_inputs(args.paths, errors)

    if sources is None:
        for raw in args.paths:
            try:
                matches = _filter_matches(list(scan_file(raw, engine)), args)
            except OSError as exc:
                errors.append(raw)
                print(f"tabayyan: cannot read '{raw}': {exc}", file=sys.stderr)
                continue
            found_any = found_any or bool(matches)
            _emit_scan_result(raw, matches, args, report)
    else:
        for name, text in sources:
            matches = _filter_matches(engine.scan(text), args)
            found_any = found_any or bool(matches)
            _emit_scan_result(name, matches, args, report)

    if args.json:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    return _exit_code(found_any, errors, args.fail_on_find)


def _resolve_salt(args) -> str | None:
    """HMAC key for hash mode: --salt, then --salt-file, then TABAYYAN_SALT.

    A file or environment variable keeps the key out of shell history and
    process listings. Returns None when a given salt file cannot be read.
    """
    if args.salt:
        return args.salt
    if args.salt_file:
        try:
            return Path(args.salt_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            print(f"tabayyan: cannot read salt file '{args.salt_file}': {exc}",
                  file=sys.stderr)
            return None
    return os.environ.get("TABAYYAN_SALT", "")


def _cmd_redact(args) -> int:
    engine = _engine_from_args(args)
    mode = RedactionMode(args.mode)
    salt = _resolve_salt(args)
    if salt is None:
        return 2
    if mode is RedactionMode.HASH and not salt:
        print(
            "error: --mode hash requires a non-empty HMAC key via --salt, "
            "--salt-file, or the TABAYYAN_SALT environment variable; "
            "an empty key leaves short identifiers reversible by brute force.",
            file=sys.stderr,
        )
        return 2
    found_any = False
    errors: list[str] = []
    inputs = list(_iter_inputs(args.paths, errors))
    multi = len(inputs) > 1
    for name, text in inputs:
        matches = _filter_matches(engine.scan(text), args)
        if matches:
            found_any = True
        result = redact(
            text, matches, mode,
            salt=salt, hash_length=args.hash_length,
            partial_keep_last=args.keep_last,
        )
        if args.json:
            payload = result.to_dict()
            payload["source"] = name
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
        else:
            if multi:
                print(f"===== {name} =====")
            sys.stdout.write(result.text)
            if not result.text.endswith("\n"):
                sys.stdout.write("\n")
            if result.vault:
                print(f"# vault ({len(result.vault)} tokens) — store securely; "
                      f"use --json to capture", file=sys.stderr)
    return _exit_code(found_any, errors, args.fail_on_find)


def _load_watchlist(path: str | None) -> list[str]:
    if not path:
        return []
    return [ln.strip() for ln in Path(path).read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")]


def _cmd_domains(args) -> int:
    try:
        watchlist = _load_watchlist(args.watchlist)
    except OSError as exc:
        print(f"tabayyan: cannot read watchlist '{args.watchlist}': {exc}",
              file=sys.stderr)
        return 2
    found_any = False
    errors: list[str] = []
    report = []
    for name, text in _iter_inputs(args.paths, errors):
        findings = _scan_domains(text, watchlist,
                                 typosquat_max_distance=args.max_distance)
        if findings:
            found_any = True
        if args.json:
            report.append({"source": name, "findings": [vars(f) for f in findings]})
        else:
            for f in findings:
                tgt = f" -> {f.target}" if f.target else ""
                print(f"{name}:{f.start}-{f.end}\t{f.domain}\t{f.reason}\t"
                      f"{f.confidence}{tgt}\t{f.detail}")
    if args.json:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    return _exit_code(found_any, errors, args.fail_on_find)


def _add_common_filters(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="*", help="files/dirs, or '-' for stdin")
    p.add_argument("--min-confidence", choices=["low", "medium", "high"],
                   help="drop matches below this confidence")
    p.add_argument("--only", nargs="+", metavar="TYPE", help="keep only these entity types")
    p.add_argument("--exclude", nargs="+", metavar="TYPE", help="drop these entity types")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--fail-on-find", action="store_true",
                   help="exit 1 if any entity is found (for CI / pre-commit)")
    p.add_argument("--config", help="JSON config: disable/add detectors, thresholds")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tabayyan", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"tabayyan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    ps = sub.add_parser("scan", help="detect entities")
    _add_common_filters(ps)
    ps.add_argument("--no-values", action="store_true", help="hide raw values in output")
    ps.add_argument("--stream", action="store_true",
                    help="scan large files incrementally (file paths only)")
    ps.set_defaults(func=_cmd_scan)

    pr = sub.add_parser("redact", help="detect and redact")
    _add_common_filters(pr)
    pr.add_argument("--mode", choices=[m.value for m in RedactionMode], default="mask")
    pr.add_argument("--salt", default="",
                    help="HMAC key for hash mode; prefer --salt-file or the "
                         "TABAYYAN_SALT env var to keep it out of shell history")
    pr.add_argument("--salt-file",
                    help="file containing the HMAC key for hash mode "
                         "(trailing whitespace stripped)")
    pr.add_argument("--hash-length", type=int, default=12, help="hash token length")
    pr.add_argument("--keep-last", type=int, default=4, help="kept chars in partial mode")
    pr.set_defaults(func=_cmd_redact)
    pd = sub.add_parser("domains", help="detect lookalike / homoglyph domains")
    pd.add_argument("paths", nargs="*", help="files/dirs, or '-' for stdin")
    pd.add_argument("--watchlist", help="file of legitimate domains, one per line")
    pd.add_argument("--max-distance", type=int, default=1,
                    help="max edit distance for typosquat flag")
    pd.add_argument("--json", action="store_true", help="emit JSON")
    pd.add_argument("--fail-on-find", action="store_true",
                    help="exit 1 if any suspicious domain is found")
    pd.set_defaults(func=_cmd_domains)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        # Downstream consumer (e.g. `| head`) closed the pipe: exit quietly
        # with the I/O-error code instead of a traceback. Redirect stdout to
        # devnull so the interpreter's shutdown flush cannot raise again.
        try:
            sys.stdout = open(os.devnull, "w", encoding="utf-8")
        except OSError:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
