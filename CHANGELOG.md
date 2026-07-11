# Changelog

## 0.10.0

Security & privacy fixes from the 0.9.1 comprehensive code review
(tracking: issue #26). A minor version because middleware failure behavior,
CLI error exit codes, and extension-loading semantics changed observably —
details below.

- **Redaction:** `partial` mode now fully masks values no longer than
  `keep_last` instead of returning them unchanged (previously a short value —
  e.g. a 4-char MRN under the default `keep_last=4` — passed through raw).
  Tokenize skips token strings already present in the input so `restore()`
  can never rewrite user-authored token-lookalike text.
- **FastAPI middleware:** malformed or pathologically deep JSON on a
  protected route now returns `400` (fail closed) instead of passing through
  unscanned with `pii-detected: false`; `block_cross_border=True` returns a
  non-leaking `403` and no longer forwards "blocked" requests; new `salt`
  parameter with construction-time HASH validation; `TOKENIZE` is rejected
  (no vault channel) instead of silently discarding the vault; the request
  body is delivered once and `http.disconnect` propagates (no infinite
  replay, no truncated bodies); clean bodies are forwarded byte-identical.
- **Audit:** local destinations (`local`, `localhost`, loopback IPs, none)
  are no longer recorded as cross-border transfers; new `destination_scope`
  audit field; audit files are created `0600` where POSIX modes apply, with
  in-process write locking (one writer per file across processes).
- **CLI:** exit code contract enforced — `0` clean, `1` findings with
  `--fail-on-find`, `2` input/usage/I/O error (missing paths no longer exit
  0); empty directory scans warn; broken pipes exit quietly; new
  `--salt-file` and `TABAYYAN_SALT` hash-key sources.
- **Providers:** unrecognized message shapes (typed SDK objects) now emit
  `UnscannedContentWarning` (configurable `Guard(on_unrecognized=
  "warn"|"error"|"pass")`) instead of silently passing unscanned; OpenAI
  `tool_calls`/`function_call` arguments, Anthropic `tool_use` input and
  `tool_result` content are now redacted.
- **Streaming:** `scan_file` preserves every `Match` field (custom-detector
  labels were dropped).
- **Config & plugins:** malformed `custom_detectors` entries raise
  `ValueError` naming the entry and field; unknown keys and ineffective
  `disable` names warn; config confusables no longer merge into the global
  map implicitly (explicit `Config.apply_confusables()`; CLI unchanged);
  `discover_plugins()` is idempotent and isolates individual plugin failures.
- **Packaging:** runtime install hints and all docs use `tabayyan-privacy`;
  README migration note for the rename; explicit sdist manifest (local
  builds no longer sweep in untracked files); `py.typed` shipped.
- **Docs:** corrected benchmark commands (`python -m benchmarks.run`),
  roadmap versions, CLI exit-code documentation; refreshed Arabic README;
  FastAPI middleware assigned an API-stability tier (Experimental);
  compatibility matrix lists the `fastapi` extra; ADRs added to docs nav.

## 0.9.1

Packaging: changed the PyPI distribution name to `tabayyan-privacy` because
the `tabayyan` project name is already registered on PyPI. The Python import
namespace remains unchanged as `tabayyan`.

## 0.9.0

FastAPI route filtering: added `include_paths` and `exclude_paths` options to
control which exact application routes are processed by the privacy middleware.
Excluded paths take precedence, configured paths are normalized, and skipped
routes pass through without body rewriting or Tabayyan response headers.

Tests: added FastAPI middleware coverage for default route behavior, included
and excluded paths, exclusion precedence, non-matching route passthrough, and
configured path normalization.

FastAPI method filtering: added `include_methods` and `exclude_methods` options
to control which HTTP methods are processed by the privacy middleware. Method
names are normalized to uppercase, exclusions take precedence, and filtering
runs before JSON detection, body reading, and body-size validation.

Tests: added FastAPI middleware coverage for default method behavior, included
and excluded methods, exclusion precedence, method normalization, route-and-
method composition, and body-size-limit bypass for skipped methods.

FastAPI JSON media types: expanded request detection to support
`application/json` and structured `+json` media types such as
`application/problem+json`, `application/vnd.api+json`, and
`application/merge-patch+json`. Media type matching is case-insensitive,
parameters are ignored, and unsupported lookalikes such as `application/jsonp`
and `text/json` pass through unchanged.

Tests: added parameterized FastAPI middleware coverage for supported JSON media
types, content-type parameters, case normalization, and unsupported JSON-like
media types.

FastAPI integration hardening: added a reusable FastAPI / Starlette privacy
middleware that redacts PII from JSON request bodies before they reach route
handlers. The middleware supports response protection headers, configurable
request body limits, and optional field-level filtering.

FastAPI middleware configuration: added `max_body_size` with a default
1,000,000-byte limit; oversized JSON requests return `413 Payload Too Large`.
The limit can be disabled with `max_body_size=None`.

FastAPI field filtering: added `include_fields` and `exclude_fields` options
to target specific JSON fields such as `prompt`, `messages`, and `content`,
or skip subtrees such as `metadata`. When both are configured,
`exclude_fields` takes precedence.

Examples: added a FastAPI LLM guard example under
`examples/fastapi_llm_guard`, including a runnable app, schemas, services,
sample requests, and tests.

Tests: expanded FastAPI middleware coverage for nested JSON, list payloads,
non-JSON passthrough, invalid JSON, empty bodies, disabled response headers,
oversized JSON rejection, disabled body limits, and field filtering behavior.

CI: added a GitHub Actions workflow that runs Ruff and Pytest on Python
3.10, 3.11, and 3.12. Added a README CI status badge.
- **README polish (scannability):** added compact **Typical use cases** and
  **Examples** nav sections, a **Project layout** tree, and a "▶ Run it locally"
  Playground CTA; tightened the "Works with" section to a one-liner; surfaced a
  one-line CLI example in Quick start; trimmed duplicated "offline" phrasing;
  refreshed the roadmap to v0.8.0; and noted a post-1.0 "Trusted by" section
  (no placeholder logos). Verified all links/anchors and code snippets.
- **Official brand identity:** adopted the Tabayyan brand kit (from a Claude
  Design handoff) — glyph (scan dots echoing ت + a redacted-document mark),
  gradient app icon, ink icon, and the horizontal lockup — under
  `docs/assets/brand/` with a favicon PNG set. The README header now uses the
  official **lockup** (replacing the improvised banner); the Playground gains a
  favicon and the brand icon in its header; the docs site (mkdocs) gets the
  glyph logo + favicon; and a new `docs/brand.md` documents assets, palette
  (`#0f766e`→`#0e7490`, ink `#0f172a`), type (Sora / Noto Kufi Arabic), and
  usage. Committed SVGs use a system-sans fallback so they render without web
  fonts.
## 0.8.1

FastAPI integration hardening: added a reusable FastAPI / Starlette privacy
middleware that redacts PII from JSON request bodies before they reach route
handlers. The middleware supports response protection headers, configurable
request body limits, and optional field-level filtering.

FastAPI middleware configuration: added `max_body_size` with a default
1,000,000-byte limit; oversized JSON requests return `413 Payload Too Large`.
The limit can be disabled with `max_body_size=None`.

FastAPI field filtering: added `include_fields` and `exclude_fields` options
to target specific JSON fields such as `prompt`, `messages`, and `content`,
or skip subtrees such as `metadata`. When both are configured,
`exclude_fields` takes precedence.

Examples: added a FastAPI LLM guard example under
`examples/fastapi_llm_guard`, including a runnable app, schemas, services,
sample requests, and tests.

Tests: expanded FastAPI middleware coverage for nested JSON, list payloads,
non-JSON passthrough, invalid JSON, empty bodies, disabled response headers,
oversized JSON rejection, disabled body limits, and field filtering behavior.

CI: added a GitHub Actions workflow that runs Ruff and Pytest on Python
3.10, 3.11, and 3.12. Added a README CI status badge.

## 0.8.0
- **Playground (demo web UI):** a new `playground/` FastAPI app — a lightweight,
  fully-offline demo that lets anyone try Tabayyan in the browser (highlighted
  detections, confidence/category cards, JSON view, redaction preview, synthetic
  Arabic samples, `.txt` upload, light/dark themes). It's an **external
  consumer** — imports only the public API, duplicates no logic, and ships
  separately from the zero-dependency core. No external calls/CDNs/telemetry.
- **README redesign (UX):** a centered, product-grade header — SVG banner
  (`docs/assets/banner.svg`), centered badges (PyPI/Python/tests/license), an
  emoji nav row, and a one-line metrics strip — followed by a Mermaid pipeline
  diagram, a before/after example, a capability-comparison table, a "Works
  with" section, and a `> [!NOTE]` scope callout. A first-time visitor grasps
  the value, the differentiator, and how to start in seconds. Metrics are
  verified, not aspirational; integrations list only what actually exists
  (built-in OpenAI/Azure/Anthropic/Presidio + the provider-agnostic building
  block) — no invented screenshots, demos, or integrations.

## 0.7.2
- **Packaging:** richer PyPI listing — added project URLs (Documentation,
  Changelog, Source alongside Homepage/Issues) and classifiers (explicit
  Python 3.9–3.13, `OS Independent`, `Natural Language :: Arabic`/`English`,
  `Text Processing :: Linguistic`); Development Status bumped `Alpha → Beta`.
  No code changes.

## 0.7.1
Thanks to **Ali .Z** for the thorough 0.7.0 hands-on review (Windows 11 /
Python 3.12) that surfaced all of the following.

- **Fix (docs):** the README quick-start used National ID `1010864543`, which
  fails the checksum and was therefore not detected — replaced with a valid
  `1010864542`. New `tests/test_readme_examples.py` asserts every `National ID`
  example in the README passes the checksum and is detected, so this can't
  recur. (#22)
- **DX:** `redact()` / `scan_and_redact()` now accept `keep_last` as an alias
  for `partial_keep_last`, matching the CLI's `--keep-last`. (#23)
- **Docs:** FAQ entries for Windows console encoding
  (`PYTHONIOENCODING=utf-8`, #24) and for when Arabic names are/aren't detected
  (trigger/particle examples, #25).

## 0.7.0
- **Release engineering & governance docs:** `RELEASE.md` (reproducible release
  checklist + trusted-publishing flow), `docs/compatibility.md` (supported
  Python/OS/extras matrix), `docs/adr/` (six Architecture Decision Records —
  normalize-before-detect, single-package, opt-in plugins, API-stability,
  Unicode philosophy, detector/validator split), `docs/detector-guide.md`
  (contributor design guide), and a post-1.0 roadmap in the README.
- **Scheduled fuzzing:** a coverage-guided fuzz target (`fuzz/fuzz_pipeline.py`,
  Atheris) drives the full pipeline — normalize → scan → redact — asserting the
  same invariants as the property tests. It is meant to run **weekly and
  non-blocking**, never on PRs; if Atheris can't be installed the job skips
  rather than adding a fallback fuzzer, and slow inputs are observations, not
  failures. The workflow ships as `fuzz/scheduled-fuzz.yml.example` — copy it to
  `.github/workflows/` to enable. Ships a curated `fuzz/seeds/` corpus (zero-width,
  bidi, mixed-script, Arabic-Indic/fullwidth digits, malformed UTF-8, long
  numeric/whitespace runs, placeholder-collision), a dependency-free
  `python -m fuzz.replay` repro tool, and a `test_fuzz_smoke.py` that runs the
  invariants over the seeds in normal CI.
- **Threat model expanded:** `docs/threat-model.md` now uses non-absolute
  wording ("substantially mitigated for supported rules"), separates upstream
  dependencies (OCR, PDF extraction) from out-of-scope concerns (prompt
  injection/jailbreak), calls out Unicode letter-confusables as ⚠ partial
  (folded for domains, not free text), and adds sections on encoding
  assumptions, resource exhaustion, and regex (ReDoS) safety — plus a threat
  summary table and an explicit "Security guarantees & non-goals" section.
- **Docs consistency:** the README performance section and roadmap no longer
  claim the overlap resolver is O(n log n); they now match the engine docstring
  (sort is O(n log n), worst case O(n²) via `list.insert`). The historical
  v0.4.0 changelog note is annotated with the correction. Code is the reference.
- **Detector plugin system:** extend the engine without touching the core.
  `register_detector()` (instance or `@register_detector` class decorator) adds
  a detector to the default set; `discover_plugins()` loads detectors a package
  advertises under the `tabayyan.detectors` entry-point group. Discovery is
  opt-in — third-party code runs only when you call it, not on import. New
  `docs/plugins.md`; plugins inherit the existing contract tests.
- **API stability & versioning policy:** new `docs/api-stability.md` defines the
  SemVer rules, what counts as a breaking change, the Stable / Experimental /
  Internal surface, and the deprecation policy. `tests/test_public_api.py`
  freezes the Stable export set and key signatures so an accidental
  removal/rename of a public symbol fails CI.
- **Golden corpus + contract tests:** a version-controlled synthetic corpus
  (`tests/golden/detections.json`, regenerated via `python -m
  tests.golden._generate`) locks the engine's exact detections (type, value,
  span) per case, so any unintended detection drift fails CI. New contract
  tests hold **every** detector in the default set to the same invariants —
  valid in-bounds spans, proper enum types, determinism, and no crash on
  arbitrary Unicode (Hypothesis-fuzzed) — so third-party detectors inherit the
  same bar.
- **Property-based tests (Hypothesis):** new `tests/test_properties.py` asserts
  input-agnostic invariants — normalization is idempotent and ASCII-identity,
  offset back-maps stay in bounds, checksum check-digits round-trip (and reject
  every wrong digit), and tokenize→restore is lossless. Part of the v1.0
  hardening track. `hypothesis` added to the dev extra.

## 0.6.0
- **Benchmark expansion:** `benchmarks/run.py` now measures the new Saudi
  entities (landline, VAT, passport, border, National Address, unified 700),
  each with hard negatives that probe the keyword-context gate (valid format,
  no context → must not match), plus a new **evasion-robustness** section
  reporting recall on zero-width / Arabic-Indic / fullwidth-obfuscated
  identifiers with normalization on vs off. The expanded run surfaced and fixed
  a real precision leak: the unified-number `700` context trigger now uses
  `\b700\b` so a `700` digit-substring inside a candidate no longer self-gates.
- **Encrypted vault:** the tokenize vault (token → original — the reversal
  key) can now be persisted password-encrypted via `tabayyan.vault`
  (`save_vault`/`load_vault`, `encrypt_vault`/`decrypt_vault`). Uses the vetted
  `cryptography` library (Fernet + PBKDF2-HMAC-SHA256, 600k iterations) — no
  home-rolled crypto — behind the optional `tabayyan-privacy[crypto]` extra, so the
  detection core stays zero-dependency. Files are written `0600`; wrong
  password or tampering raises a clear error.
- **NDMO data classification:** every audit record now carries
  `data_classification` (the highest NDMO sensitivity level among detected
  entities — health → secret, most PII → confidential, org/network → public)
  and a `classification_summary` (level → count). New `tabayyan.ndmo` module
  with `Classification`, `classify()`, `classification_summary()`, and an
  overridable `CATEGORY_CLASSIFICATION` map. Complements the PDPL cross-border
  evidence trail.
- **Provider adapters — one guard, every SDK:** new `Guard.wrap(client,
  provider="auto")` gives a uniform `create(**kwargs)` entry point across LLM
  SDKs, with built-in OpenAI/Azure and **Anthropic** adapters (Anthropic also
  redacts the `system` prompt) and tokenize-restore on responses. Auto-detects
  the provider by client shape; extend to any SDK via
  `tabayyan.providers.register_adapter`. `guard_openai()` is now a deprecated
  alias of `wrap(..., provider="openai")` (still works, warns).
- **Anti-evasion normalization:** an offset-preserving pre-pass
  (`normalize.py`) now runs in the engine before detection — it strips
  zero-width/bidi format characters (Unicode Cf) and folds Arabic-Indic,
  Persian and fullwidth digits (plus per-character NFKC) so evasion via
  invisible or look-alike characters is defeated for **all** detectors, not
  just the Saudi ones. Matches are projected back onto original offsets, so
  redaction still rewrites the real span (invisibles included). Pure-ASCII
  input is unchanged. Opt out with `DetectionEngine(normalize_input=False)`.
- **New Saudi entities:** landline (`+966 1X`), VAT/tax number (ZATCA TRN,
  context-gated), passport, border/visa number, National Address short code,
  and unified establishment number (700) — each format-only and, where
  ambiguous, gated on a keyword context like CR/MRN. Presidio recognizers
  (`SA_VAT`, `SA_PASSPORT`, `SA_BORDER_NUMBER`, `SA_NATIONAL_ADDRESS`,
  `SA_UNIFIED_NUMBER`) added alongside.
- **Security:** `hash` redaction now uses HMAC-SHA256 (keyed) instead of a
  bare `salt||value` digest, and **requires a non-empty salt**. Short
  identifiers (e.g. a 10-digit National ID) were otherwise reversible by
  brute force from the token. CLI exits with a clear error if `--salt` is
  missing in hash mode.
- **Security:** `Guard.protect()` no longer returns the raw original text on a
  blocked call — the returned `text` is MASK-redacted so a caller that
  mistakenly forwards it cannot leak PII.
- **Fix:** audit `timestamp` is now a timezone-aware UTC ISO-8601 value
  (`datetime.now(timezone.utc)`); removed dead `%z`-fallback code.
- **Detection:** Saudi mobile detector now also matches the `00966`
  international prefix.
- Corrected the engine's overlap-resolution complexity note (worst case is
  O(n²) via list.insert, not O(n log n)).

## 0.5.1
- **Fix:** Arabic comma (U+060C) and other Arabic punctuation no longer
  corrupt Arabic-name tokenization (tightened the letter range).
- **Fix:** tokenize/restore now reproduces the original span exactly,
  including Arabic-Indic digits (vault stores the source span, not the
  normalized value).
- **Middleware hardening:** `protect_messages()` building block; handles
  multimodal/list content, system/tool roles, and streaming (request
  redacted, stream passed through). Honest 'reference adapter' disclaimer.
- **Recall benchmark** (`benchmarks/recall.py`): recall under formatting
  noise + an honest context-free section exposing heuristic limits.
- **Arabic README**, before/after showcase, and an interactive notebook.
- Broadened MRN trigger phrasing (recall 0.69 -> 1.0 with context).

## 0.5.0
- **Middleware + audit** (`Guard`, `AuditLog`): scan -> redact/block -> audit
  before a prompt leaves for an LLM endpoint. Cross-border transfer flagging
  (PDPL Art. 29), category-aware blocking, JSONL audit (values withheld by
  default), and a duck-typed OpenAI/Azure wrapper with tokenize-restore.
- **Presidio integration** (`tabayyan-privacy[presidio]`): validated Saudi/Arabic
  recognizers (SA_NATIONAL_ID, SA_IQAMA, SA_IBAN, SA_CR, SA_PHONE_NUMBER,
  MEDICAL_RECORD_NUMBER, PERSON, lookalike domains). Complements Presidio;
  parity-tested against the standalone engine. Runtime core stays zero-dep.
- Name detector: added field-label stopwords (الهوية، الآيبان، …) for tighter
  boundaries in record-style text.

## 0.4.2
- **IBAN & Luhn cross-validation**: differential tests against
  `python-stdnum` (dev-only oracle) — Luhn over 20k random samples, IBAN
  over 12k generated Saudi IBANs + mutations.
- **Golden vectors**: official card-network test PANs (Visa, Mastercard,
  Amex, Discover, JCB, Diners) and canonical public example IBANs
  (SA/GB/DE/FR). Runtime stays zero-dependency.

## 0.4.1
- **National ID cross-validation**: validator differentially tested against
  the community reference alhazmy13/Saudi-ID-Validator (MIT; algorithm by
  Abdul-Aziz Al-Oraij) — 100% agreement on a 50k+ random sample. Updated
  REFERENCES.md and the checksum disclaimer accordingly.

## 0.4.0
- **Arabic name detection** (heuristic, context-gated, LOW confidence) — new
  PERSON category; improves recall on health-sector PII.
- **Streaming** large-file scan with overlap windows (`tabayyan scan --stream`,
  `tabayyan.streaming.scan_file`).
- **Reversible tokenize** redaction mode + `restore()` and a token vault.
- **Config** (`--config`, `tabayyan.config.Config`): disable/add detectors,
  custom regex detectors with labels, extend confusables, tune thresholds.
- **Performance**: rewrote overlap resolution to a sorted + bisect approach
  (~110x faster on dense input). Added `benchmarks/perf.py`. (The original note
  claimed O(n log n); the true worst case is O(n²) via `list.insert` — corrected
  in a later release.)
- **Docs**: REFERENCES.md (algorithm provenance), FAQ, threat model, config.
- Golden-vector tests; National ID disclaimer clarifying it is the
  community algorithm, not an authoritative spec.

## 0.3.0
- **Homoglyph / lookalike-domain detection** (opt-in): IDN homograph
  impersonation via confusable skeletons, mixed-script labels
  (incl. Arabic+Latin), and edit-distance typosquats against a watchlist.
  Punycode (`xn--`) labels decoded before analysis. New `tabayyan domains`
  CLI command.
- **Benchmark suite** (`benchmarks/run.py`): precision/recall/F1 on a
  synthetic corpus with hard negatives, plus a naive-regex baseline that
  quantifies the false positives checksum validation eliminates.
- **Adoption**: Dockerfile, pre-commit hook, PyPI release workflow (OIDC
  trusted publishing), MkDocs docs, Makefile.

## 0.2.0
- Redaction engine: mask / remove / hash / partial.
- CLI: `scan` and `redact` with stdin/file/dir input, filters, JSON, exit codes.

## 0.1.0
- Detection core: Saudi (National ID, Iqama, IBAN, CR, mobile, MRN) +
  generic (email, credit card, IP) detectors with checksum validation.
