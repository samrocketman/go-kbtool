# kbtool terms — quick start

A **complete occurrence census** of one exact identifier or string across the
indexed source — per-file counts plus representative lines. It exists so that
*"this identifier doesn't exist in the tree"* is a **citable result**, not an
inference: a zero-hit census is explicitly distinct from "present but didn't
rank" in a search.

```sh
# Where does this identifier live, and how many times?
kbtool terms "encodeEcosystem"

# Machine-readable (for scripts / agents):
kbtool terms "encodeEcosystem" -json
```

Present:

```
3 occurrence(s) in 2 file(s) for "encodeEcosystem":
  repo/src/foo/bar.go  (1)
      :7  func EncodeEcosystem(name string) string {
  repo/src/foo/bar_test.go  (2)
      :4  func TestEncodeEcosystem(t *testing.T) {
```

Absent (a distinct, unambiguous line):

```
ABSENT in indexed sources: "encodeEcosystem" (0 occurrences in 0 files)
```

Notes:

- **Exit codes:** `0` = present, `3` = ABSENT in indexed sources, `1` = error.
  Script the absence check on the exit code.
- Matching is an exact, case-sensitive **substring** over every indexed chunk —
  no ranking is involved, so a rare identifier is found even when a search
  wouldn't surface it.
- Goes through the session's daemon (it fails when none runs), and is also the
  MCP tool `kb_terms`.

Full reference: [terms.md](terms.md) · back to [README](../README.md)
