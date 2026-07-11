# Tabayyan Project Review Report

**Project:** Saudi AI Privacy Gateway / Tabayyan  
**Repository:** https://github.com/blackice2090/saudi-ai-privacy-gateway  
**Local path used during work:** `C:\Users\acer32\Downloads\Tabayyan-main`  
**Prepared on:** 2026-07-10  
**Purpose:** This file documents what was completed, what changed, the current verified repository state, and what remains for future work. Keep this file in the project root so it can be reviewed in a future ChatGPT conversation or by any developer joining the project.

---

## 1. Executive Summary

We completed a full professional development cycle around Tabayyan, focused on making the project more production-ready and GitHub-ready.

The work included:

- Initializing and pushing the project to the new GitHub repository.
- Adding a runnable FastAPI LLM guard example.
- Adding a reusable FastAPI / Starlette privacy middleware.
- Expanding middleware coverage with tests.
- Adding request body size protection.
- Adding field-level filtering.
- Improving and documenting middleware usage.
- Adding and later cleaning GitHub Actions workflows.
- Restoring and updating the changelog after an accidental overwrite.
- Preparing and tagging release `v0.8.1`.
- Fixing README badges so they point to this repository instead of the upstream repository.
- Updating README status and roadmap to reflect `v0.8.1`.

The repository is currently clean on `main`, up to date with `origin/main`, and has tag `v0.8.1`.

---

## 2. Current Verified State

The final local verification showed:

```text
Branch: main
Remote: origin/main
Working tree: clean
Tag: v0.8.1 exists
pyproject.toml version: 0.8.1
README: references v0.8.1
Old upstream badge/reference: nasser-gh did not appear in README search
GitHub workflows present:
- docs.yml
- release.yml
- tests.yml
```

Latest confirmed local log:

```text
4aa18ed (HEAD -> main, origin/main, origin/HEAD) Merge pull request #14 from blackice2090/docs/update-readme-version
670f0b1 docs: update README current version
b0f88d2 Merge pull request #13 from blackice2090/docs/fix-readme-badges
da75ee8 docs: fix README workflow badges
fe3fef6 Merge pull request #12 from blackice2090/ci/remove-duplicate-ci-workflow
139aec0 ci: remove duplicate CI workflow
90957f4 (tag: v0.8.1, docs/add-release-checklist) Merge pull request #11 from blackice2090/release/v0.8.1
741bf74 release: prepare v0.8.1
```

Final workflow folder state:

```text
.github/workflows/
├── docs.yml
├── release.yml
└── tests.yml
```

---

## 3. Repository and Branch Workflow Used

The project was handled with a professional branch-and-PR workflow:

1. Work on a short-lived branch.
2. Run local validation.
3. Commit with a clean conventional-style message.
4. Push branch.
5. Open PR.
6. Merge PR after checks.
7. Pull `main`.
8. Delete local and remote branch.
9. Continue with the next focused change.

This workflow was used consistently across feature, docs, test, release, and CI cleanup changes.

---

## 4. Completed Pull Requests and Changes

### PR #1 — FastAPI LLM Guard Example

**Branch:** `examples/fastapi-llm-guard`  
**Commit:** `3acc8c2 docs(examples): add FastAPI LLM guard example`  
**Merge commit:** `c653608 Merge pull request #1 from blackice2090/examples/fastapi-llm-guard`

Added a runnable FastAPI example under:

```text
examples/fastapi_llm_guard/
```

Files added included:

```text
examples/__init__.py
examples/fastapi_llm_guard/__init__.py
examples/fastapi_llm_guard/README.md
examples/fastapi_llm_guard/app.py
examples/fastapi_llm_guard/config.py
examples/fastapi_llm_guard/schemas.py
examples/fastapi_llm_guard/services.py
examples/fastapi_llm_guard/sample_requests.http
examples/fastapi_llm_guard/tests/test_app.py
```

Also added `.gitignore` entry for:

```text
examples/fastapi_llm_guard/audit.jsonl
```

Validation completed:

```powershell
pytest examples\fastapi_llm_guard\tests -q
ruff check examples\fastapi_llm_guard
```

Both passed.

Example run command:

```powershell
python -m uvicorn examples.fastapi_llm_guard.app:app --host 127.0.0.1 --port 8010 --reload --reload-dir examples
```

Observed behavior:

- `/docs` returned 200.
- `/chat` returned 200.
- `/` returned 404, which was normal because no root route was defined.

---

### PR #2 — FastAPI / Starlette Privacy Middleware

**Branch:** `feat/fastapi-privacy-middleware`  
**Commit:** `195e419 feat(integrations): add FastAPI privacy middleware`  
**Merge commit:** `ec1b90a Merge pull request #2 from blackice2090/feat/fastapi-privacy-middleware`

Added reusable middleware:

```text
src/tabayyan/integrations/fastapi.py
tests/test_fastapi_integration.py
```

Updated:

```text
pyproject.toml
tests/test_vault.py
```

Main class added:

```python
TabayyanPrivacyMiddleware
```

Core behavior:

- ASGI middleware for FastAPI and Starlette.
- Redacts PII inside JSON request bodies before the request reaches handlers.
- Recursively scans strings inside dictionaries and lists.
- Updates `content-length` after rewriting the request body.
- Adds response headers:
  - `x-tabayyan-pii-detected`
  - `x-tabayyan-redacted-count`
- Passes through non-HTTP scopes.
- Passes through non-JSON content.
- Allows audit logging.
- Supports destination-aware cross-border behavior.

Important middleware parameters at this stage:

```python
destination: str = "local"
mode: RedactionMode = RedactionMode.MASK
audit_path: str | None = None
block_cross_border: bool = False
include_response_headers: bool = True
```

Validation completed:

```powershell
pytest tests\test_fastapi_integration.py -q
ruff check src\tabayyan\integrations\fastapi.py tests\test_fastapi_integration.py
pytest -q
```

Full suite result at this point:

```text
252 passed, 1 skipped, 4 warnings
```

Warnings were related to old `Guard.guard_openai()` deprecation and were not blockers.

Windows compatibility fix in `tests/test_vault.py`:

```python
def test_save_load_file_roundtrip_and_perms(tmp_path):
    p = tmp_path / "vault.enc"
    save_vault(VAULT, str(p), "pw")
    assert load_vault(str(p), "pw") == VAULT

    if os.name != "nt":
        mode = stat.S_IMODE(os.stat(p).st_mode)
        assert mode == 0o600  # owner-only on POSIX systems
```

---

### PR #3 — Middleware Usage Documentation

**Branch:** `docs/fastapi-middleware-usage`  
**Commit:** `e4e00a8 docs: document FastAPI middleware usage`  
**Merge commit:** `0a600a3 Merge pull request #3 from blackice2090/docs/fastapi-middleware-usage`

Updated documentation for the FastAPI middleware.

Documentation areas:

- README usage section.
- `docs/middleware.md`.
- Install command for the optional FastAPI extra:

```bash
pip install "tabayyan-privacy[fastapi]"
```

Basic middleware usage example:

```python
from fastapi import FastAPI

from tabayyan.integrations.fastapi import TabayyanPrivacyMiddleware

app = FastAPI()
app.add_middleware(TabayyanPrivacyMiddleware, destination="https://api.openai.com")
```

---

### PR #4 — Harden FastAPI Middleware Test Coverage

**Branch:** `test/fastapi-middleware-coverage`  
**Commit:** `533374e test(integrations): harden FastAPI middleware coverage`  
**Merge commit:** `e427e63 Merge pull request #4 from blackice2090/test/fastapi-middleware-coverage`

Expanded tests in:

```text
tests/test_fastapi_integration.py
```

Coverage added for:

- Nested JSON.
- Lists and chat-style messages.
- Non-sensitive JSON.
- Non-JSON pass-through.
- Invalid JSON pass-through.
- Disabled response headers.
- Empty body.

Validation completed:

```powershell
pytest tests\test_fastapi_integration.py -q
ruff check tests\test_fastapi_integration.py
pytest -q
```

Results:

```text
7 passed for FastAPI integration tests
258 passed, 1 skipped, 4 warnings for full suite
```

---

### PR #5 — FastAPI Middleware Body Size Limit

**Branch:** `feat/fastapi-middleware-body-limit`  
**Commits:**

```text
239b942 feat(integrations): add FastAPI middleware body size limit
f769460 docs: document FastAPI middleware body size limit
```

**Merge commit:** `eb09bb5 Merge pull request #5 from blackice2090/feat/fastapi-middleware-body-limit`

Added request body protection:

```python
DEFAULT_MAX_BODY_SIZE = 1_000_000
RequestBodyTooLarge
max_body_size: int | None = DEFAULT_MAX_BODY_SIZE
```

Behavior added:

- Checks `content-length` before reading body.
- Checks body size while streaming body chunks.
- Returns HTTP 413 if body exceeds limit.
- Response body:

```json
{"detail":"Request body too large"}
```

- `max_body_size=None` disables the limit.

Tests added:

- Rejects JSON body larger than configured limit.
- Allows disabling the body size limit.

Validation completed:

```powershell
pytest tests\test_fastapi_integration.py -q
ruff check src\tabayyan\integrations\fastapi.py tests\test_fastapi_integration.py
pytest -q
```

Results:

```text
9 passed for FastAPI integration tests
260 passed, 1 skipped, 4 warnings for full suite
```

Docs updated in:

```text
docs/middleware.md
```

---

### PR #6 — FastAPI Middleware Field Filtering

**Branch:** `feat/fastapi-middleware-field-filtering`  
**Commit:** `4efabfb feat(integrations): add FastAPI middleware field filtering`  
**Merge commit:** `6998188 Merge pull request #6 from blackice2090/feat/fastapi-middleware-field-filtering`

Added field-level controls:

```python
include_fields: Collection[str] | None = None
exclude_fields: Collection[str] | None = None
```

Import updated:

```python
from collections.abc import Collection, Mapping
```

Helper logic added:

```python
_normalize_fields
_normalize_field
_field_is_included
_field_is_excluded
_should_protect_field
_protect_value(value, field_name=None, force_protect=False)
```

Field filtering semantics:

- Default behavior protects all strings.
- `include_fields` restricts protection to selected field names.
- `exclude_fields` skips selected fields and their subtrees.
- `exclude_fields` wins over `include_fields`.
- If a parent field is included, nested values under it are protected using `force_protect`.

Tests added:

- `include_fields` only protects selected fields.
- `include_fields` can target nested content.
- `exclude_fields` skips selected subtree.
- `exclude_fields` wins over `include_fields`.

Validation completed:

```powershell
pytest tests\test_fastapi_integration.py -q
ruff check src\tabayyan\integrations\fastapi.py tests\test_fastapi_integration.py
pytest -q
```

Results:

```text
13 passed for FastAPI integration tests
264 passed, 1 skipped, 4 warnings for full suite
```

Docs updated with include/exclude examples.

---

### PR #7 — Add GitHub Actions CI

**Branch:** `ci/add-github-actions`  
**Commit:** `a5d2e2b ci: add GitHub Actions workflow`  
**Merge commit:** `34e7c43 Merge pull request #7 from blackice2090/ci/add-github-actions`

Added:

```text
.github/workflows/ci.yml
```

The workflow ran:

- Checkout.
- Setup Python.
- Install dependencies.
- `ruff check .`
- `pytest -q`.

Matrix used:

```yaml
python-version:
  - "3.10"
  - "3.11"
  - "3.12"
```

This was later removed in PR #12 because the repository already had a stronger `tests.yml` workflow.

---

### PR #8 — Add CI Badge

**Branch:** `docs/add-ci-badge`  
**Commit:** `e8514ce docs: add CI status badge`  
**Merge commit:** `4438f92 Merge pull request #8 from blackice2090/docs/add-ci-badge`

Added a CI badge to the README.

This was later adjusted in PR #12 and PR #13 to point to the correct workflow and repository.

---

### PR #9 — Changelog Update Attempt

**Branch:** `docs/add-changelog`  
**Commit:** `57e07b7 docs: update changelog`  
**Merge commit:** `bee569d Merge pull request #9 from blackice2090/docs/add-changelog`

Issue:

The changelog was accidentally overwritten and most historical entries were removed.

Observed diff:

```text
1 insertion(+), 247 deletions(-)
```

This was corrected in the next fix.

---

### PR #10 — Restore Changelog History

**Branch:** `fix/restore-changelog-history`  
**Merge commit in log:** `8b2eb1b Merge pull request #10 from blackice2090/fix/restore-changelog-history`

Restored changelog history.

Verification after fix:

```powershell
(Get-Content CHANGELOG.md).Count
Select-String -Path CHANGELOG.md -Pattern "0.8.0","0.7.0","0.1.0"
```

Expected and observed:

```text
271 lines
CHANGELOG.md:45:## 0.8.0
CHANGELOG.md:84:## 0.7.0
CHANGELOG.md:269:## 0.1.0
```

Important lesson:

Do not replace the entire changelog. Add new release notes under the proper section while preserving history.

---

### PR #11 — Release v0.8.1

**Branch:** `release/v0.8.1`  
**Commit:** `741bf74 release: prepare v0.8.1`  
**Merge commit:** `90957f4 Merge pull request #11 from blackice2090/release/v0.8.1`  
**Tag:** `v0.8.1`

Release preparation included:

- Bumping package version in `pyproject.toml` to:

```toml
version = "0.8.1"
```

- Updating changelog for `v0.8.1`.
- Tagging the release:

```powershell
git tag -a v0.8.1 -m "Release v0.8.1"
git push origin v0.8.1
```

Release highlights prepared:

```markdown
## Highlights

- Added FastAPI / Starlette privacy middleware
- Added request body size limit with `max_body_size`
- Added field filtering with `include_fields` and `exclude_fields`
- Added FastAPI example app
- Expanded middleware test coverage
- Added GitHub Actions CI and README badge
```

Final local verification showed:

```powershell
git tag -l "v0.8.1"
type pyproject.toml | findstr version
```

Output:

```text
v0.8.1
version = "0.8.1"
target-version = "py39"
```

---

### PR #12 — Remove Duplicate CI Workflow

**Branch:** `ci/remove-duplicate-ci-workflow`  
**Commit:** `139aec0 ci: remove duplicate CI workflow`  
**Merge commit:** `fe3fef6 Merge pull request #12 from blackice2090/ci/remove-duplicate-ci-workflow`

Reason:

The repository already had:

```text
.github/workflows/tests.yml
```

That workflow was stronger than the newly added `ci.yml` because it ran:

- Ruff.
- Pytest.
- Python matrix: `3.9`, `3.11`, `3.13`.
- Presidio integration job.

Therefore, duplicate `ci.yml` was removed.

Changes:

```text
.github/workflows/ci.yml deleted
README badge updated
```

Validation after merge:

```text
.github/workflows/
├── docs.yml
├── release.yml
└── tests.yml
```

---

### PR #13 — Fix README Workflow Badges

**Branch:** `docs/fix-readme-badges`  
**Commit:** `da75ee8 docs: fix README workflow badges`  
**Merge commit:** `b0f88d2 Merge pull request #13 from blackice2090/docs/fix-readme-badges`

Reason:

The README still contained an old workflow badge pointing to the upstream repository:

```text
github.com/nasser-gh/tabayyan
```

Fix:

- Removed the old upstream badge.
- Kept only the project-specific badge pointing to:

```text
https://github.com/blackice2090/saudi-ai-privacy-gateway/actions/workflows/tests.yml
```

Final verification:

```powershell
Select-String -Path README.md -Pattern "nasser-gh"
```

Expected result:

```text
No output
```

---

### PR #14 — Update README Current Version

**Branch:** `docs/update-readme-version`  
**Commit:** `670f0b1 docs: update README current version`  
**Merge commit:** `4aa18ed Merge pull request #14 from blackice2090/docs/update-readme-version`

Updated README to reflect `v0.8.1` as current.

Changes:

- Status section changed from `v0.8.0` to `v0.8.1`.
- Roadmap updated to mark `v0.8.1` as current.
- Added current release summary:

```markdown
- **v0.8.1** *(current)* — FastAPI middleware hardening, request body limits, field filtering, CI cleanup, and release polish.
```

Final verification:

```powershell
Select-String -Path README.md -Pattern "v0.8.1","260+ tests","nasser-gh"
```

Observed:

```text
README.md:143:Public release (v0.8.1). The pre-1.0 version numbers track development
README.md:426:- **v0.8.1** *(current)* — FastAPI middleware hardening, request body limits, field filtering, CI cleanup, and release polish.
```

No `nasser-gh` appeared.

Note:

PowerShell `Select-String` treats `+` as a regex operator. To search for literal `260+ tests`, use:

```powershell
Select-String -Path README.md -Pattern "260+ tests" -SimpleMatch
```

---

## 5. Middleware Technical Summary

The current FastAPI / Starlette middleware provides request-side privacy protection.

### Main capabilities

- Intercepts HTTP requests.
- Processes JSON bodies.
- Recursively scans strings.
- Redacts detected PII before application handlers receive the body.
- Preserves non-sensitive JSON structure.
- Skips invalid JSON safely.
- Skips non-JSON bodies.
- Updates `content-length`.
- Adds optional response headers.
- Supports audit logging.
- Supports destination-aware cross-border control.
- Supports request body size limits.
- Supports field-level include/exclude filtering.

### Important configuration

```python
app.add_middleware(
    TabayyanPrivacyMiddleware,
    destination="https://api.openai.com",
    mode=RedactionMode.MASK,
    audit_path="audit.jsonl",
    block_cross_border=False,
    include_response_headers=True,
    max_body_size=1_000_000,
    include_fields=None,
    exclude_fields=None,
)
```

### Field filtering behavior

Default:

```python
include_fields=None
exclude_fields=None
```

Means protect all string values in JSON.

Include-only behavior:

```python
include_fields={"message", "prompt"}
```

Means only protect matching fields and nested values under those fields.

Exclude behavior:

```python
exclude_fields={"metadata", "debug"}
```

Means skip these fields and nested subtrees.

Precedence:

```text
exclude_fields wins over include_fields
```

---

## 6. Current GitHub Actions Setup

Current workflows:

```text
.github/workflows/docs.yml
.github/workflows/release.yml
.github/workflows/tests.yml
```

### tests.yml

Responsible for the main validation pipeline.

It runs:

- Python matrix.
- Ruff linting.
- Pytest test suite.
- Presidio integration test job.

Known matrix from earlier inspection:

```yaml
python-version: ["3.9", "3.11", "3.13"]
```

Integration job:

```text
pip install -e ".[dev,presidio]"
pytest tests/test_presidio_integration.py -q
```

### release.yml

Used for release publishing according to `RELEASE.md`.

The release process documentation says pushing a tag like `vX.Y.Z` should trigger release publishing via GitHub Actions and PyPI trusted publishing.

Important:

This conversation verified the existence of `release.yml`, but did not fully verify whether PyPI trusted publishing is configured correctly in PyPI settings.

### docs.yml

Used for docs-related validation/building.

---

## 7. Current Release State

Current release:

```text
v0.8.1
```

Confirmed:

```text
git tag -l "v0.8.1" -> v0.8.1
pyproject.toml -> version = "0.8.1"
README -> Public release (v0.8.1)
README roadmap -> v0.8.1 marked current
```

Important note:

PRs #12, #13, and #14 happened after the `v0.8.1` tag. These were CI/docs/README cleanup changes. They do not require a new package release by themselves unless the project owner wants all docs changes included under a new tag.

Recommended interpretation:

- `v0.8.1` is the released code version.
- `main` now contains additional docs/CI polish after the release tag.
- No urgent `v0.8.2` is needed unless package code or release-critical metadata changes.

---

## 8. Things Still Worth Checking

These are not confirmed as completed in the conversation.

### 8.1 Verify `src/tabayyan/__init__.py` version

`RELEASE.md` says releases should bump both:

```text
pyproject.toml
src/tabayyan/__init__.py
```

We verified `pyproject.toml`, but did not verify `src/tabayyan/__init__.py`.

Run:

```powershell
Select-String -Path src\tabayyan\__init__.py -Pattern "__version__","0.8.0","0.8.1"
```

If it shows `0.8.0`, fix it.

Suggested branch:

```powershell
git switch main
git pull origin main
git switch -c fix/sync-package-version
```

Update:

```python
__version__ = "0.8.1"
```

Then:

```powershell
pytest -q
ruff check .
git add src\tabayyan\__init__.py
git commit -m "fix: sync package version"
git push -u origin fix/sync-package-version
```

Open PR:

```text
fix: sync package version
```

If PyPI/GitHub release was already published, consider whether to release `v0.8.2` after this fix rather than moving tag `v0.8.1`.

---

### 8.2 Verify GitHub Actions are green

Open the repository Actions tab and confirm:

- `tests.yml` green.
- `docs.yml` green.
- `release.yml` behavior is understood.

If any job fails, inspect logs before continuing feature work.

---

### 8.3 Verify PyPI publishing status

If the project was intended to publish to PyPI on tag `v0.8.1`, verify:

```powershell
pip index versions tabayyan
```

Or check PyPI manually.

If `v0.8.1` did not publish:

- Check `release.yml` logs.
- Check PyPI trusted publishing configuration.
- Do not create another tag until root cause is understood.

---

### 8.4 Verify README test count

If README should show the current test count as `260+ tests` or `264+ tests`, use `-SimpleMatch` because `+` is special in regex:

```powershell
Select-String -Path README.md -Pattern "260+ tests" -SimpleMatch
Select-String -Path README.md -Pattern "264+ tests" -SimpleMatch
Get-Content README.md -TotalCount 25
```

Recommended:

- If README says `240+ tests`, update it.
- If README says `260+ tests`, it is acceptable.
- If README says `264+ tests`, it is also accurate based on the latest full local test suite observed after field filtering.

---

## 9. Recommended Next Milestone: v0.9.0

The next milestone should focus on one strong production feature rather than many scattered changes.

Recommended options:

### Option A — Route Allowlist / Exclude Paths for Middleware

Add middleware parameters:

```python
include_paths: Collection[str] | None = None
exclude_paths: Collection[str] | None = None
```

Use cases:

- Skip health checks.
- Skip file uploads.
- Protect only `/chat`, `/llm`, `/messages`.
- Avoid processing endpoints where body rewriting is not desired.

Example:

```python
app.add_middleware(
    TabayyanPrivacyMiddleware,
    destination="https://api.openai.com",
    include_paths={"/chat", "/messages"},
    exclude_paths={"/health", "/metrics"},
)
```

This is a strong `v0.9.0` candidate.

---

### Option B — Oversize Body Handling Strategy

Currently oversized bodies return HTTP 413.

Add:

```python
on_oversize: Literal["reject", "skip"] = "reject"
```

Behavior:

- `reject`: return 413.
- `skip`: pass body through unchanged and optionally add audit/header signal.

This helps real systems where rejecting large payloads is not always desirable.

---

### Option C — Response Redaction

Add optional response-side redaction:

```python
protect_responses: bool = False
```

Use case:

- Prevent accidental PII returned from backend to frontend.
- Useful for internal dashboards and AI gateway responses.

Caution:

- More complex because responses can be streaming.
- Should start with non-streaming JSON responses only.

---

### Option D — Structured Audit Enhancements

Improve audit events with:

- Request path.
- HTTP method.
- Redacted count.
- Entity types.
- Body size.
- Cross-border flag.
- Whether request was blocked, skipped, or redacted.

Need to avoid logging raw PII.

---

## 10. Suggested Future Branch Names

Use short focused branches:

```text
feat/fastapi-route-filtering
feat/fastapi-oversize-strategy
feat/fastapi-response-redaction
docs/improve-fastapi-middleware-guide
test/fastapi-middleware-edge-cases
fix/sync-package-version
```

---

## 11. Suggested Future Commit Messages

```text
feat(integrations): add FastAPI middleware route filtering
feat(integrations): add oversize request handling strategy
feat(integrations): support response redaction for JSON responses
test(integrations): cover FastAPI route filtering
docs: improve FastAPI middleware configuration guide
fix: sync package version
```

---

## 12. Commands for Future Work

Always start future work like this:

```powershell
git switch main
git pull origin main
git status
```

Then create a branch:

```powershell
git switch -c feat/name-of-change
```

Run validation before commit:

```powershell
ruff check .
pytest -q
```

Commit and push:

```powershell
git add .
git commit -m "type(scope): message"
git push -u origin branch-name
```

After PR merge:

```powershell
git switch main
git pull origin main
git status
git branch -d branch-name
git push origin --delete branch-name
```

---

## 13. Future ChatGPT Context Prompt

If opening a future ChatGPT conversation, paste this prompt:

```text
I am working on the repository blackice2090/saudi-ai-privacy-gateway.

Please read PROJECT_REVIEW.md first. It contains the full history of completed PRs, release v0.8.1, middleware features, CI cleanup, README fixes, and remaining checks.

Current expected state:
- main is clean and up to date
- v0.8.1 tag exists
- pyproject.toml version is 0.8.1
- README references v0.8.1
- workflows are docs.yml, release.yml, tests.yml
- ci.yml was intentionally removed
- old upstream nasser-gh badge was removed

Before suggesting new work, first check whether src/tabayyan/__init__.py version matches 0.8.1 and whether GitHub Actions are green.
```

## Manual Runtime Validation

Validated locally on Windows from:

`C:\Users\acer32\Downloads\Tabayyan-main`

### Package installation

Installed the project successfully in editable mode:

```text
Successfully installed tabayyan-0.8.1

---

## 14. Final Notes

The project is currently in a good professional state.

Most important completed outcomes:

- The repository now has a clear release `v0.8.1`.
- The FastAPI middleware is a strong production-facing integration.
- Tests were expanded significantly.
- CI was cleaned and now avoids duplicate workflows.
- README no longer points to upstream workflow badges.
- Changelog history was recovered after accidental deletion.

Most important remaining check:

```text
Verify src/tabayyan/__init__.py version sync with pyproject.toml.
```

Recommended next milestone:

```text
v0.9.0 — FastAPI middleware route filtering or oversize handling strategy.
```
