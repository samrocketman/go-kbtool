# kbtool build — full reference

Reindex the active session's sources and swap the new index into the running
daemon, without a restart. Only the session host runs it, from the host
session's state dir.

```
kbtool build [-db-key-env NAME | -db-key-file PATH]
```

`kbtool collaborate host` indexes the working directory when the session
starts (a git checkout, else its child dirs when one is a git checkout, else
the directory itself) and records those sources and the index options in
`config.json`. A bare `kbtool build` rebuilds exactly those sources with the
recorded options and lists them on stderr; run it after the code changed.
`build` takes no sources and no other options, and refuses outside an active
host session and on an attendee's state dir.

## Options

| Option | Description |
|---|---|
| `-db-key-env NAME` | Key of an encrypted state dir from environment variable `$NAME`. Only used when no daemon serves the store (below). |
| `-db-key-file PATH` | The same key from file `PATH`. |

`<state>` is the state dir: `~/.config/kbtool` by default, override with
`KBTOOL_DIR`.

## What gets indexed

- Every text/code file under each source dir, chunked by lines with overlap;
  files larger than 512 KB are skipped.
- Standard junk is skipped: `.git`, `node_modules`, `vendor`, `dist`, `build`,
  lockfiles, minified/binary files, etc.
- Each chunk is classified: `code`, `doc` or `text`.
- Every git source records its HEAD commit and whether its work tree has
  uncommitted or untracked changes.
- Local (hashing) embeddings are computed in-process — no network. Set
  `KB_EMBED_URL` / `KB_EMBED_KEY` / `KB_EMBED_MODEL` to use a remote
  OpenAI-compatible embeddings endpoint instead.

## Rebuilding while the daemon runs

On the session host, `build` indexes on the client side and then swaps the
new index into the running daemon through its unix socket: no restart, and
every attendee sees the new index at once.

```
built 1 source(s): 1234 chunks -> swapped into the running daemon (unix /home/you/.config/kbtool/daemon.sock, plain); no restart needed
```

- The daemon writes the new index under its save lock (`kb.db.lock` when
  encrypted, `board.bin.lock` when plain), so a message-board save can never
  re-bundle the old index. With an encrypted store the daemon re-seals with
  its in-memory key: `build` needs no key, and no plaintext touches the disk.
- The at-rest shape can't change under a running daemon: a key for a plain
  store is refused.
- The swap only goes through the unix socket; it is not available over a
  relay or stdio. An attendee's state dir refuses `build` altogether.
- An older daemon that can't swap gets the file written instead, with a
  warning to restart it (`kbtool collaborate finish && kbtool collaborate
  resume`).

## At-rest encryption

In an encrypted state dir (`kbtool collaborate host -encrypt`) the store is
always encrypted. With the daemon running, `build` needs no key (above).
Without a running daemon it writes the store itself and needs the key from
`-db-key-env`, `-db-key-file` or `$KBTOOL_SECRET`; it never prompts. The key
is resolved **before** the (expensive) build, so a wrong key fails fast.

The encrypted store is a **KBX1 bundle** (PBKDF2-HMAC-SHA256 with 600,000
iterations + AES-256-GCM over a tar.gz) holding both the database and the
message board. The key is held in memory only; it is never written to
`config.json`, argv, or any file kbtool owns. See
[cryptography.md](cryptography.md).

## Message board announcement

When the message board is enabled and exists, every build posts a message
in the read-only `system` thread (and a notice in `welcome`). Sources are
named by label, never by path:

```
The search index was rebuilt by `kbtool build`: 1234 chunks from 3 source(s).
- `repoA` indexed at commit `3f2c…` with a clean git workspace
- `repoB` was rebuilt at commit `9ab1…` with a dirty git workspace
- `notes` indexed (not a git repo)
- `old` was removed from the index
```

"indexed" means the source is new to the index; "was rebuilt" means it was
already there. When a daemon serves the index, the daemon posts after the
swap. See
[message-board.md](message-board.md#the-system-account-and-thread).

## Config side effects

Every build rewrites the build fields of `config.json` (state dir) with the
same sources and options; every other key is kept as is. The tool options
(`git_tools`, `message_board`, `disable_tools`) are **seeded if absent,
preserved verbatim if present** — a build never re-stamps a value you set.
See [client-server-config.md](client-server-config.md).

## Related

- Simple example: [build-simple.md](build-simple.md)
- Sessions (where the sources come from): [collaborate.md](collaborate.md)
- Query the result: [query-simple.md](query-simple.md)
- The daemon it swaps into: [daemon.md](daemon.md)
- Config file reference: [client-server-config.md](client-server-config.md)
- Back to [README](../README.md)
