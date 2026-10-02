# kbtool build — full reference

Build a search index from one or more source directories and write the local
KB file. Optionally index git history. Optionally write the store
**encrypted at rest**.

```
kbtool build [opts] dirA dirB …
```

With no directory arguments the current directory (`.`) is indexed.

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

`<state>` is the state dir: `~/.config/kbtool` by default, override with
`KBTOOL_DIR`.

## What gets indexed

- Every text/code file under each source dir, chunked by lines with overlap;
  files larger than `-maxkb` are skipped.
- Standard junk is skipped: `.git`, `node_modules`, `vendor`, `dist`, `build`,
  lockfiles, minified/binary files, etc.
- Each chunk is classified: `code`, `doc`, `text`, and (with `-git`)
  `commit` and `diff`.
- With `-git`, up to `-gitmaxcommits` recent commits per repo are indexed
  (messages + diffs, capped globally at `-gitdiffmaxkb` KB), and each code
  chunk gets a baked provenance summary (which commits touched its line range).
- Local (hashing) embeddings are computed in-process — no network. Set
  `KB_EMBED_URL` / `KB_EMBED_KEY` / `KB_EMBED_MODEL` to use a remote
  OpenAI-compatible embeddings endpoint instead.

## At-rest encryption

Key precedence: `-encrypt` (prompt) > `-db-key-env` > `-db-key-file` >
`$KBTOOL_DBKEY` > plain (no key).

With any key, `build` writes the db file as a **KBX1 bundle** (PBKDF2-HMAC-SHA256
with 600,000 iterations + AES-256-GCM over a tar.gz) holding both the database
and the message board. The key is derived once per process that opens the
store, not on every board read or save. KBX1 files written before the
iteration count rose from 100,000 do not open (they fail like a wrong key):
move the old db file aside and build again; its board cannot be carried over.
Without a key the store stays plain. The key is held in memory only; it is
never written to `config.json`, argv, or any file kbtool owns. A pre-existing
plain `board.bin` is absorbed into the bundle and removed. Rebuilding an
encrypted store requires its key (`-db-key-env`, `-db-key-file`, or
`-encrypt`); the key is resolved **before** the (expensive) build, so a wrong
key fails fast.

## Rebuilding while the daemon runs

On the daemon host, when the daemon serves the same db file, `build` indexes
on the client side and then swaps the new index into the running daemon
through its unix socket: no restart, and clients see the new index at once.

```
built 1 source(s): 1234 chunks -> swapped into the running daemon (unix /home/you/.config/kbtool/daemon.sock, plain); no restart needed
```

- The daemon writes the new index under its save lock (`kb.db.lock` when
  encrypted, `board.bin.lock` when plain), so a message-board save can never
  re-bundle the old index. With an encrypted store the daemon re-seals with
  its in-memory key: `build` needs no key, and no plaintext touches the disk.
- The at-rest shape can't change under a running daemon: `-encrypt`, or a key
  for a plain store, is refused (stop the daemon first).
- A different `-db` is just written to that file.
- The swap only goes through the unix socket; it is not available over HTTP,
  a relay or stdio. A remote client refuses `build` altogether.
- An older daemon that can't swap gets the file written instead, with a
  warning to restart it.

## Config side effects

Every build writes `config.json` (state dir), recording:

- sources (absolutized), `-db`, `-dim/-chunk/-overlap/-maxkb`, `-git`
  settings, `-kwpath`;
- with `-git`: `live=true` plus the repo list (as git toplevels) — a bare
  `kbtool daemon start` then starts with `-live <repos>`, so `git_blame` /
  `git_log` work;
- the tool options (`git_tools`, `message_board`, `disable_tools`) are
  **seeded if absent, preserved verbatim if present** — a build never
  re-stamps a value you set;
- network/mTLS and path-trust settings are copied across from the previous
  file.

Precedence everywhere: **explicit flag > config > default**.

## Related

- Simple example: [build-simple.md](build-simple.md)
- Query the result: [query-simple.md](query-simple.md)
- Serve it: [daemon-simple.md](daemon-simple.md) / [mcp-simple.md](mcp-simple.md)
- Config file reference: [client-server-config.md](client-server-config.md)
- Back to [README](../README.md)
