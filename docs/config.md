# Configuration

Pass a JSON config to the CLI (`--config c.json`) or load it in code
(`Config.from_file(...)`). All keys are optional.

```json
{
  "disable": ["saudi_cr", "arabic_name"],
  "typosquat_max_distance": 2,
  "confusables": { "ⅴ": "v" },
  "custom_detectors": [
    {
      "label": "employee_id",
      "pattern": "EMP-\\d{6}",
      "category": "organisation",
      "confidence": "medium"
    }
  ]
}
```

- **disable** — detector names to drop (e.g. `saudi_cr`, `arabic_name`).
- **typosquat_max_distance** — edit-distance threshold for the domain
  detector.
- **confusables** — extra character → skeleton mappings. In the CLI these
  apply for the run; in library code call `Config.apply_confusables()`
  explicitly — the merge is process-global (it affects every engine and
  `skeleton()` call in the process), so merely loading a config no longer
  applies it implicitly.
- **custom_detectors** — regex detectors. `category` is one of the data
  categories; `confidence` is `high`/`medium`/`low`. Matches mask using the
  uppercased `label` (e.g. `[EMPLOYEE_ID]`).

Validation: malformed `custom_detectors` entries (missing `label`/`pattern`,
invalid `category`/`confidence`, broken regex) raise a `ValueError` naming
the offending entry and field; unknown top-level keys and `disable` names
that match no built-in detector emit a `RuntimeWarning` instead of failing
silently.

In code:

```python
from tabayyan.config import Config
engine = Config.from_file("c.json").build_engine()
engine.scan("staff EMP-004521")
```
