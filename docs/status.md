# kbtool status — full reference

Print the resolved state of a kbtool installation: session, relay, daemon,
board and tools. `status` and `stats` are the same command.
Non-interactive: it never prompts.

```
kbtool status [-db-key-env NAME | -db-key-file PATH]
```

## Options

| Option | Description |
|---|---|
| `-db-key-env NAME` | DB-at-rest key from `$NAME`, so an encrypted store's shape and board stats can be inspected. |
| `-db-key-file PATH` | DB-at-rest key from file `PATH`. |

## Output sections

On a session host (or a state dir without a session):

| Section | What it reports |
|---|---|
| `db:` | db path + size (or "not found"). |
| `at-rest:` | Store shape — `ENCRYPTED (KBX1 bundle: kb.db + message board)` and whether the key is loaded or required. |
| `config:` | `config.json` path and the recorded index options (`sources`, `git`, `live`, `liveRepos`, `dim/chunk/overlap/maxKB`, `kwPath`, `db`, `updated`); or "not found" (no session has been hosted from this state dir). |
| `tool options:` | `git_tools`, `message_board`, `disable_tools` (with defaults annotated when the fields are absent). |
| `message_board_max_memory:` | The resolved board memory limit. |
| `disabled tools:` | The effective disabled set (list ∪ group-off tools). |
| `path trust:` | `trusted_paths`, `forbidden_paths` and the rule: git tools read only the indexed git sources + `trusted_paths`; `forbidden_paths` always wins. |
| `network:` | "unix socket only (no mtls configured)" for a local session; for a session through a relay, `https=false mtls=true` with the bind address and CRL file names from `config.json`. |
| `relay:` | `relay.json` (relays enabled or disabled, how many joined, self-hosting) and the session's `relay_session` and sticky relay ([relay.md](relay.md)). |
| `ca:` | The session CA's fingerprint, when there is one. |
| `client:` | That the host's CLI uses the unix socket only (plus a note about a leftover `client.json`). |
| `board:` | Thread/message/agent counts (when a board is present). |
| `daemon:` | Running (pid + socket) or stopped. |

On an attendee, status opens nothing local and shows instead: `client:` (the
relay session it reaches through `client.json`), `relay:`, `ca:`, `daemon:`
(reachable or not) and the daemon's enabled tools.

## Behavior notes

- Read-only; never writes `config.json` or `client.json`.
- A corrupt config or unreadable store is reported inline, not fatal.
- With an encrypted store and no key flag, the `at-rest:` line tells you the
  key is required and which flags supply it (`-db-key-env` / `-db-key-file` /
  `$KBTOOL_SECRET`).

## Related

- Simple example: [status-simple.md](status-simple.md)
- The session itself: [session.md](session.md) (`kbtool session ls`)
- What the sections mean in depth: [client-server-config.md](client-server-config.md)
- Back to [README](../README.md)
