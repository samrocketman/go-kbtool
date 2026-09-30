# kbtool bundle — quick start

**Context-bundle expansion**: instead of a list of snippets, get one
consolidated "read pack" per hit that follows the code's own *written*
pointers — its neighbors, the strings/identifiers it carries (searched
tree-wide), its imports (with honest verdicts), and its test files.

```sh
# Expand a known location (file:line, as reported by search_codebase):
kbtool bundle "repo/src/foo/bar.go:10"

# …or the top hits of a query:
kbtool bundle -q "nvdcve feed url" -k 3

# …or as a flag on query itself:
kbtool query "nvdcve feed url" -bundle
```

One pack looks like:

```
== repo/src/foo/bar.go:1-14 [code] ==

neighborhood (2 file(s) in repo/src/foo/):
* repo/src/foo/bar.go  EncodeEcosystem
  repo/src/foo/bar_test.go  TestEncodeEcosystem

propagation (literals/identifiers searched tree-wide):
  candidate "https://nvd.nist.gov/feeds/json/cves/2.0/nvdcve-2.0-%s.json.gz":
    fragment "nvdcve-2.0" — 2 file(s):
      repo/com/example/Foo.java (1)
      repo/src/foo/bar.go (1)

imports: 2 statement(s)
  L4  fmt  ->  external  (not-in-tree)
  L6  acme/repo/src/bar  ->  internal  (repo/src/bar/bar.go (matched suffix "src/bar"))

tests: 1 paired test file(s)
  repo/src/foo/bar_test.go — shared: EncodeEcosystem
```

Notes:

- The four components: **neighborhood** (sibling files + one-line summary),
  **propagation** (stable fragments of the hit's literals/identifiers searched
  tree-wide — so a URL built with `%s`/`formatted` still surfaces), **imports**
  (each statement judged `internal (path)` / `external (not-in-tree)` /
  `unresolved` — worst case is unresolved, never a wrong verdict), and **tests**
  (files matching test naming conventions that share identifiers with the hit).
- Everything is lexical (file layout + string/identifier search + import-line
  patterns) — no AST, no type inference.
- Sections are capped (e.g. 20 neighborhood files) with an explicit
  `…truncated` marker, so large repos never flood the terminal.
- Also available as the MCP tool `kb_bundle` (args: `target` or `q`, plus `k`).

Full reference: [bundle.md](bundle.md) · back to [README](../README.md)
