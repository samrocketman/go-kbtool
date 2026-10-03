# kbtool build — snapshot builds

Applies to snapshot builds only (`make release-snapshot` or `go build`).
Release builds refuse `build` with sources or options other than the key
flags, and outside an active session. The bare in-session `kbtool build`,
what gets indexed, live reindex, the board announcement and at-rest
encryption basics are in [../build.md](../build.md).

Snapshot builds can index any source directories, with options, without a
session, and write the local KB file (optionally with git history,
optionally **encrypted at rest**).

```
kbtool build [opts] dirA dirB …
```

With no directory arguments, `build` rebuilds the sources recorded in
`config.json` by the last build (every git and non-git directory), with the
recorded options for every flag you do not pass, and lists them on stderr.
When nothing is recorded yet, the current directory (`.`) is indexed. To
index the current directory instead of the recorded sources, pass `.`.

## Options

| Option | Default | Description |
|---|---|---|
| `-dim N` | 1024 | Embedding dimension (local hashing backend). |
| `-chunk N` | 48 | Chunk size, in lines. |
| `-overlap N` | 12 | Overlap between consecutive chunks, in lines. |
| `-maxkb N` | 512 | Skip files larger than N KB. |
| `-git` | off | Index git history (commit messages + diffs) and bake a provenance summary into code chunks. Also records the repos as live (see below). |
| `-gitmaxcommits N` | 200 | Per-repo commit cap for `-git` history. |
| `-gitdiffmaxkb M` | 8000 | Global KB cap on baked diff content. |
| `-kwpath[=false]` | on | Include path-leaf + kind tokens in the keyword (BM25) index. Disable with `-kwpath=false`. |
| `-db PATH` | `<state>/kb.db` (or `$KBTOOL_DB`) | Output db file. |
| `-db-key-env NAME` | — | DB-at-rest key from environment variable `$NAME`: write the store **ENCRYPTED**. |
| `-db-key-file PATH` | — | DB-at-rest key from file `PATH`: write the store **ENCRYPTED**. |
| `-encrypt` | off | Prompt for a DB-at-rest key (hidden input) and write the store **ENCRYPTED**. Wins over the key-source flags. |

## Git history (`-git`)

With `-git`, chunks are also classified `commit` and `diff`: up to
`-gitmaxcommits` recent commits per repo are indexed (messages + diffs,
capped globally at `-gitdiffmaxkb` KB), and each code chunk gets a baked
provenance summary (which commits touched its line range).

## At-rest encryption without a session

Key precedence: `-encrypt` (prompt) > `-db-key-env` > `-db-key-file` >
`$KBTOOL_SECRET` > plain (no key). With any key, `build` writes the db file
as a KBX1 bundle; without a key the store stays plain. KBX1 files written
before the iteration count rose from 100,000 do not open (they fail like a
wrong key): move the old db file aside and build again; its board cannot be
carried over. A pre-existing plain `board.bin` is absorbed into the bundle
and removed. Rebuilding an encrypted store requires its key (`-db-key-env`,
`-db-key-file`, or `-encrypt`).

Under a running daemon `-encrypt` is refused (stop the daemon first), and a
different `-db` is just written to that file. Without a daemon, `build`
posts its board announcement through the local store.

## Config side effects

Every build updates `config.json` (state dir). Only the build fields are
replaced; every other key is kept as is. It records:

- sources (absolutized), `-db`, `-dim/-chunk/-overlap/-maxkb`, `-git`
  settings, `-kwpath`;
- with `-git`: `live=true` plus the repo list (as git toplevels) — a bare
  `kbtool daemon start` then starts with `-live <repos>`, so `git_blame` /
  `git_log` work;
- the tool options are seeded if absent, preserved verbatim if present;
- network/mTLS, relay, message board and path-trust settings are kept
  unchanged.

So the next daemon start, and the next bare `kbtool build`, use the new
sources and options. Precedence everywhere: **explicit flag > config >
default**.

## Examples

```sh
kbtool build /path/to/repoA /path/to/repoB
kbtool build -git /path/to/repoA
kbtool build -encrypt .
```

## Related

- Release reference: [../build.md](../build.md)
- Serve it without a session: [daemon.md](daemon.md) / [mcp.md](mcp.md)
- Benchmark the result: [bench.md](bench.md)
- Back to [README](../../README.md)
