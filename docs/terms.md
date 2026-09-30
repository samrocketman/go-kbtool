# kbtool terms — full reference

A complete occurrence census of one exact identifier or string across the
indexed source, so presence — and especially **absence** — is a citable result
rather than an inference. Part of the context-bundle feature set
(`plans/context-bundle-plan.md`); it is also the MCP tool `kb_terms`.

```
kbtool terms <identifier-or-string> [-k N] [-json] [-db PATH]
             [-db-key-env NAME | -db-key-file PATH]
```

## Options

| Option | Default | Description |
|---|---|---|
| `<term>` | — | Exact identifier or string. Case-sensitive substring match over every indexed chunk (identifiers *and* string literals). |
| `-k N` | 20 | Max files to show. The true total is always reported (`fileCount`), so truncation is visible. |
| `-json` | off | Machine-readable JSON (see below). |
| `-db PATH` | config db, else `<state>/kb.db` | Db file, used when the daemon is down. |
| `-db-key-env NAME` | — | DB-at-rest key from `$NAME` (encrypted stores). |
| `-db-key-file PATH` | — | DB-at-rest key from file `PATH` (encrypted stores). |

## Behavior

- **Complete, not ranked.** The census scans every indexed chunk once and
  counts exact substring occurrences per file. An identifier that "exists but
  didn't rank" in a hybrid search is still reported present — the two answers
  are deliberately independent.
- **Distinct absence.** Zero hits print the line
  `ABSENT in indexed sources: "<term>" (0 occurrences in 0 files)` and exit
  `3`. That is the feature's reason to exist: absence as evidence.
- **Access paths.** Daemon socket when the daemon is up (via the `kb_terms`
  tool), else the direct db. Identical results either way; encrypted stores are
  read with the usual key flags.
- Board messages are excluded — the census is over indexed *sources*.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | term is present in the indexed source |
| `3` | term is ABSENT in the indexed source |
| `1` | error (no db, bad key, …) |

## JSON form (`-json`)

```json
{
  "identifier": "encodeEcosystem",
  "present": true,
  "occurrences": 9,
  "fileCount": 3,
  "files": [
    {"path": "repo/src/foo/bar.go", "count": 2,
     "lines": [":7  func EncodeEcosystem(name string) string {"]},
    {"path": "repo/src/foo/bar_test.go", "count": 5, "lines": ["…"]}
  ],
  "truncated": false
}
```

`files` is capped by `-k`; `fileCount` is the true total.

## Examples

```sh
kbtool terms "encodeEcosystem"
kbtool terms "nvdcve-2.0" -json
kbtool terms "EncodeEcosystem" ; echo "exit=$?"   # 0 present / 3 absent / 1 error
```

## Related

- Simple example: [terms-simple.md](terms-simple.md)
- Context-bundle expansion: [bundle.md](bundle.md)
- Back to [README](../README.md)
