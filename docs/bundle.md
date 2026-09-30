# kbtool bundle — full reference

Context-bundle expansion for search: for a known location (or the top hits of a
query), emit one consolidated "read pack" that follows the code's own *written*
pointers — its neighbors, the strings/identifiers it carries (searched
tree-wide), its imports (with honest verdicts), and its test files. Part of the
context-bundle feature set (`plans/context-bundle-plan.md`).

Three equivalent entry points:

```
kbtool bundle <file:line>                      expand a known location
kbtool bundle -q "query text" [-k N]           expand a query's top hits
kbtool query "query text" -bundle [-k N]       the same, as a flag on query
```

All three also take `[-db PATH] [-db-key-env NAME | -db-key-file PATH]` and go
through the daemon socket when the daemon is up (MCP tool: `kb_bundle`, args
`target` or `q` plus `k`). Results are identical across access paths.

## The four components

Each hit renders one pack with these sections (all capped, with an explicit
`…truncated` marker when a cap fires):

### 1. Package neighborhood
Sibling files in the hit's directory (chunk paths are `label/rel`, so
directory ≈ package for Java/Go), each with a one-line summary: the first
doc-comment line, else up to 3 exported symbol names, else the first line.
Cap: 20 files.

### 2. Literal/identifier propagation
String literals and identifiers present in the hit chunk (comment lines
stripped), longest first, 8 candidates. Each is reduced to **stable
fragments** — split on format verbs (`%s`, …) and non-`[A-Za-z0-9._-]` runs,
keeping runs of ≥ 6 chars — and each fragment is searched tree-wide with an
exact substring scan. This is what makes a *constructed* string surface:
`"…nvdcve-2.0-%s.json.gz".formatted(…)` is found by the fragment `nvdcve-2.0`
in every file that contains it (factory defaults, test stubs, …). The matched
fragment and per-file counts are printed so a human can judge relevance.
Caps: 6 fragments / 10 files per fragment.

### 3. Import verdicts
Per-language import *line* patterns (Go `import` + blocks; Java/Kotlin
`import a.b.C;`; JS/TS `import … from` / `require`; Python `import` /
`from … import`) resolved against the indexed file set:

- `internal (path)` — a matching indexed file/directory exists (for
  module-style imports the matched suffix is shown so a partial match is
  judgeable);
- `external (not-in-tree)` — deterministic mapping, no indexed file matches;
- `unresolved (…)` — ambiguous syntax: Python relative imports
  (`from .x import y`) and wildcard imports (`from a.b import *`).

Worst case is `unresolved`, never a wrong verdict. Unknown languages produce no
verdicts. Cap: 20 statements.

### 4. Test-file pairing
Files matching test naming conventions (`*Test.java`, `*_test.go`, `*.test.*`
/ `*.spec.*`, `test_*.py`) that share identifiers with the hit (its extracted
identifiers plus the hit file's name stem — how `bar.go` finds `bar_test.go`
and `X.java` finds `XTest.java`). Cap: 10 files, 3 shared identifiers shown.

## Behavior and limits

- **Lexical only.** File layout, string/identifier search, and import-line
  patterns — no AST, no type inference, no call graphs, no per-language parser
  packages. It follows what the code *wrote* (paths, strings, import lines),
  not what it semantically means.
- **Capped output.** Neighborhood 20 files, 8 propagation candidates, 6
  fragments / 10 files per fragment, 20 imports, 10 test files; every cap that
  fires prints `…truncated`.
- **No new index.** Everything reads the existing chunk store (path, line
  range, full chunk text); no new index artifact.
- Board chunks are excluded (the pack follows code pointers, not conversation).

## Examples

```sh
kbtool bundle "repo/src/foo/bar.go:10"
kbtool bundle -q "nvdcve feed url" -k 3
kbtool query "nvdcve feed url" -bundle
kbtool call kb_bundle '{"target":"repo/src/foo/bar.go:10"}'
```

## Related

- Simple example: [bundle-simple.md](bundle-simple.md)
- Presence/absence census: [terms.md](terms.md)
- Search: [query.md](query.md)
- Back to [README](../README.md)
