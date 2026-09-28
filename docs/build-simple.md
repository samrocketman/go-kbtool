# kbtool build — quick start

Build the local search index from one or more source directories (each may be
a git repo) and write it to the default database file.

```sh
# One-time install first: a release binary (see README → Install), or from
# a source checkout:
#   go build -o /usr/local/bin/kbtool kbtool.go

# Index one or more directories
kbtool build /path/to/repoA /path/to/repoB

# Include git history (commit messages + diffs) and per-line provenance
kbtool build -git /path/to/repoA
```

Typical output:

```
built 1 source(s): 1842 chunks -> /home/you/.config/kbtool/kb.db (1520.3 KB)
config: wrote /home/you/.config/kbtool/config.json (a bare `kbtool daemon start` will use these options)
```

Now try it:

```sh
kbtool query "how do we parse config"
kbtool status
```

Notes:

- With no directory arguments, `kbtool build` indexes the current directory (`.`).
- Every build records its options in `config.json`, so a later bare
  `kbtool daemon start` / `kbtool mcp` reproduces the same index. A `-git`
  build also records the repos as *live*, enabling `git_blame` / `git_log`.
- Indexing is local: no network calls, no external embedding service.

Full reference with every option: [build.md](build.md) · back to [README](../README.md)
