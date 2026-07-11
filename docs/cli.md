# CLI

```bash
tabayyan scan <paths|->            # detect entities
tabayyan redact <paths|-> --mode mask|remove|hash|partial
tabayyan domains <paths|-> --watchlist domains.txt
```

Common filters: `--min-confidence {low,medium,high}`, `--only TYPE...`,
`--exclude TYPE...`, `--json`, `--fail-on-find` (non-zero exit for CI).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | clean run — nothing found, or findings without `--fail-on-find` |
| 1 | entities found and `--fail-on-find` was given |
| 2 | input, usage, or I/O error: missing/unreadable path, unreadable salt file or watchlist, missing hash key, broken output pipe |

A directory scan that matches no recognised text files prints a warning to
stderr (the run itself still exits 0 unless something was unreadable).

## Hash-mode key (salt)

`--mode hash` needs a non-empty HMAC key. Prefer a source that stays out of
shell history and process listings:

```bash
tabayyan redact note.txt --mode hash --salt-file /path/to/keyfile
TABAYYAN_SALT=... tabayyan redact note.txt --mode hash
```

Precedence: `--salt` > `--salt-file` > `TABAYYAN_SALT`.

## Output privacy

`scan` prints matched values by default — use `--no-values` before piping
scan output into CI logs or tickets. `redact --json` includes each item's
original value and (in tokenize mode) the vault: treat that JSON with the
same care as the source text.
