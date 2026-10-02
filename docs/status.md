# kbtool status — full reference

Print the resolved state of a kbtool installation. `status` and `stats` are
the same command. Non-interactive: it never prompts.

```
kbtool status [-db-key-env NAME | -db-key-file PATH]
```

## Options

| Option | Description |
|---|---|
| `-db-key-env NAME` | DB-at-rest key from `$NAME`, so an encrypted store's shape and board stats can be inspected. |
| `-db-key-file PATH` | DB-at-rest key from file `PATH`. |

## Output sections

| Section | What it reports |
|---|---|
| `db:` | db path + size (or "not found" when the recorded/`KBTOOL_DB` path is missing). |
| `at-rest:` | Store shape — `ENCRYPTED (KBX1 bundle: kb.db + message board)` and whether the key is loaded or required. |
| `config:` | `config.json` path, recorded build options (`sources`, `git`, `live`, `liveRepos`, `dim/chunk/overlap/maxKB`, `kwPath`, `db`, `updated`); or "not found" (run `kbtool build …`). |
| `tool options:` | `git_tools`, `message_board`, `disable_tools` (with defaults annotated when the fields are absent). |
| `disabled tools:` | The effective disabled set (list ∪ group-off tools). |
| `path trust:` | `trusted_paths`, `forbidden_paths` and the rule: git tools read only `-live` repos + indexed git sources + `trusted_paths`; `forbidden_paths` always wins. |
| `network:` | `http`, `mtls`, `insecure`, bind address (default shown: `127.0.0.1:9876` without mTLS, `:9876` with), CRL file (exists + refresh mode). "unix socket only" when no network is configured. |
| `relay:` | Only in relay mode: `relay_url`, `relay_session` and whether a token is set ([relay.md](relay.md)). |
| `client:` | On a daemon host: that its CLI uses the unix socket only (plus a note about a leftover `client.json`). On a remote client, status shows the `client.json` endpoint (`https://host:port`, plus the relay session) and whether it is reachable instead of the local sections. |
| `board:` | Thread/message/agent counts (when a board is present). |
| `daemon:` / `mcp:` | Running (pid + socket) or stopped, per service. |

## Behavior notes

- Read-only; never writes `config.json` or `client.json`.
- A corrupt config or unreadable store is reported inline, not fatal.
- With an encrypted store and no key flag, the `at-rest:` line tells you the
  key is required and which flags supply it (`-db-key-env` / `-db-key-file` /
  `$KBTOOL_DBKEY`).

## Related

- Simple example: [status-simple.md](status-simple.md)
- What the sections mean in depth: [client-server-config.md](client-server-config.md)
- Back to [README](../README.md)
