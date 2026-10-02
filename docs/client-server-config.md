# Client & server configuration

kbtool keeps all state under one directory (**the state dir**):
`~/.config/kbtool` by default, override with `KBTOOL_DIR`. This page covers
the two configuration files the CLI and the service read, who writes them,
and the environment knobs.

## State dir layout

| File | Written by | Purpose |
|---|---|---|
| `config.json` | `build`, `daemon start`, `mcp start`, `mtls` | Server-side configuration: recorded build options, tool options, path trust, network/mTLS. |
| `client.json` | `client -import` (remote clients only) | Client-side: where a remote client connects, and with which certs. A daemon host has none (`mtls` / `daemon start` / `mcp start` remove a leftover one). |
| `kb.db` | `build`, the service | The index (plain KBV1, or the KBX1 encrypted bundle holding db + board). |
| `board.bin` | the service / one-shot board calls (never on a remote client) | Message board (absent when the store is encrypted — it's inside `kb.db`). |
| `ca.crt` / `ca.key` | `mtls` | Local CA. |
| `server.crt` / `server.key` | `mtls` | Daemon's TLS cert/key. |
| `client.crt` / `client.key` | `mtls`, `client -import` | Client cert/key presented by the local CLI. |
| `crl.pem` | you (optional) | CRL PEM — revoked client certs; enforced at handshake when present. |
| `daemon.sock` / `mcp.sock` | the service | Unix sockets (`KBTOOL_SOCKET` overrides). |
| `relay.pid` / `relay.log` | `relay start` | Relay service pid and log. A relay and a daemon cannot share one state dir. |
| pid files / logs | `daemon start`, `mcp start` | Background service bookkeeping. Logs are 0600 (an mTLS daemon logs its client-enrollment line). |

## Roles

What the CLI does depends on what the state dir holds:

| Role | The state dir has | The CLI talks to |
|---|---|---|
| **daemon host** | any of `server.key`, `ca.key`, `config.json`, `daemon.sock`, `mcp.sock` | its own daemon over the unix socket only (`KBTOOL_SOCKET`, `daemon.sock`, `mcp.sock`), never HTTP or a relay; with no daemon running it uses the local store |
| **remote client** | `client.json` and no host file | only the `client.json` endpoint (HTTPS or relay); no local db or board fallback |
| **plain local** | neither | a local socket if one is live, else the local store |

- The host's socket uses mTLS when `config.json` has `mtls: true`, with the
  state dir's `client.crt` / `client.key` and `ca.crt`.
- A remote client refuses the commands that only make sense next to a daemon:
  `build`, `bench`, `daemon`, `mtls`, `relay`, and `mcp serve|run|start|stop|status`.
- `client -import` refuses a daemon host's state dir; enroll from another one
  (`KBTOOL_DIR=…`).
- On the host, `build` with the daemon running swaps the new index into it
  through the socket, with no restart ([build.md](build.md)).

## `config.json` (server side)

Hand-editable JSON. Precedence for every option: **explicit flag > config >
default**. `build` / `daemon start` / `mcp start` write it; a corrupt file is
ignored with a one-line warning (it never blocks serving).

### Recorded build options (written by `build`)

| Field | Meaning |
|---|---|
| `sources` | Absolutized source dirs. |
| `db` | Db file path (default when `-db` is not given). |
| `dim`, `chunk`, `overlap`, `maxKB` | Indexing knobs. |
| `git` | Whether the index includes git history. |
| `gitMaxCommits`, `gitDiffMaxKB` | Git-history caps. |
| `kwPath` | Keyword-index path/kind tokens (null when absent). |
| `live`, `liveRepos` | Set by `build -git` or `daemon start -live …`: the repos `git_blame`/`git_log` run against. |
| `version`, `updated` | Bookkeeping. |

### MCP tool options (seed-or-preserve — never re-stamped once present)

| Field | Default (seeded) | Meaning |
|---|---|---|
| `git_tools` | `false` | Enable the git tools: `git_blame`, `git_log`. |
| `message_board` | `false` (`true` in relay mode) | Enable the board tools: `board_signup`, `board_whoami`, `board_sign`, `board_post`, `board_read`, `board_fetch`, `board_threads`, `board_search`, `board_confirm`. |
| `disable_tools` | `["kb_status", "board_sign"]` | Per-tool kill switch, **always** honored — it beats the group options. Remove a name (even a core one) to re-enable it; `[]` disables nothing. Unknown names are harmless. |

In relay mode the message board defaults to on: `kbtool mtls -relay` (and so
`kbtool relay establish`) writes `"message_board": true`, and a missing value
counts as `true` while `relay_url` is set. A later `false` is kept until the
next relay setup.
| `message_board_max_memory` | `"25%"` (not seeded) | Memory limit for the whole message board: every message, agent and attachment, measured as the encoded board (the `board.bin` bytes). A percentage of the memory available when kbtool launched (`MemAvailable`; an assumed 1 GiB where unreadable, e.g. macOS), or a size: bytes, `K`/`KiB`, `M`/`MiB`, `G`/`GiB`, `T`/`TiB` (binary) or `KB`/`MB`/`GB`/`TB` (decimal), e.g. `"512MiB"`. Posts and signups that would pass it are refused; reads keep working. The daemon flag `-board-max-memory` overrides it, and `daemon start -board-max-memory …` records it here. |

**A tool is served when its group option is on AND its name is not in
`disable_tools`.** Enabled by default: `search_codebase`, `get_chunk`,
`list_files`. `kbtool tools`, MCP `tools/list`, and the `initialize`
instructions show only enabled tools; disabled tools are refused at
`tools/call` with an explanation. `kbtool status` reports the resolved set.

### Path trust (git tools only)

| Field | Meaning |
|---|---|
| `trusted_paths` | Extra directories the git tools may read. |
| `forbidden_paths` | **Always wins over trusted** — forbids a default-trusted repo or a subpath of one. |

Trusted set = `-live` repos + indexed git sources + `trusted_paths`. Absent ≡
empty. `kbtool status` / `kb_status` report the effective set.

### Network / mTLS (written by `mtls`, `daemon start`, `mcp start`)

| Field | Meaning |
|---|---|
| `http` | Also serve TCP (`GET /healthz`, `POST /mcp`). Implied when `mtls` is true (default bind then: all interfaces, `:9876`) unless `relay_url` is set; only `daemon start -http=false` turns it off. |
| `mtls` | Require client certs on the served socket(s). |
| `http_addr` | Bind address (`HOST:PORT`; empty = `127.0.0.1:9876` without mTLS, `:9876` with). |
| `http_allow_insecure` | Allow cleartext HTTP on a non-loopback bind (default false — refused; loudly warned when on). |
| `ca_cert`, `server_cert`, `server_key` | PEM file names (relative to the state dir unless absolute). |
| `crl_file` | CRL PEM (default `crl.pem`; may not exist = no revocation data). |
| `crl_refresh` | `true`: reload the CRL every `crl_interval` seconds; `false` (default): **watch** the file for changes. |
| `crl_interval` | Reload period seconds (default 60). |

### Relay (written by `mtls -relay`, `relay establish`, `relay start`)

See [relay.md](relay.md).

| Key | Meaning |
|---|---|
| `relay_url` | Daemon: the relay to register with (`https://HOST:PORT/`). Set, the daemon opens no TCP port unless `http` is true or `-http` is given. Plain `kbtool mtls` clears it. |
| `relay_session` | Daemon: the session ID (32 lowercase hex characters, the SNI clients use), derived from `relay-session.key` and the team CA's expiry. Created by `mtls -relay` / `relay establish`, reused across daemon restarts and reconnects until the CA expires. |
| `relay_token` | Daemon: the token it presents when registering. Relay service: the token it requires (empty = open registration). |
| `relay_bind` | Relay service: listen address (default `:9876`). `KBTOOL_RELAY_BIND` / `KBTOOL_RELAY_PORT` win over it. |
| `relay_ca` | Daemon: how it verifies the relay's TLS. Unset: the CA from the relay's `/ca.crt`, host name unchecked. `system`: the system roots. A path: that PEM CA. The last two check the relay's host name. Set by `mtls -relay … -relay-ca`. |
| `relay_max_sessions` | Relay service: most sessions registered at once (default 5000). `KBTOOL_RELAY_MAX_SESSIONS` and `-max-sessions` win over it. |

## `client.json` (client side)

Tells a **remote client** where to reach a daemon. Relative cert names are
resolved against the state dir. A daemon host never reads it.

| Field | Meaning |
|---|---|
| `unix_socket` | Unix socket to use (when set, `host`/`port` are ignored). |
| `host`, `port` | TCP endpoint (used when `unix_socket` is empty). |
| `hosts` | Optional ordered list of further endpoints for a multi-interface server (written by `kbtool mtls` as every SAN): tried in order after `host`, first live one wins. |
| `tls` | `true` ⇒ mTLS: present the client cert; over TCP the dialed host is verified against the server cert's SANs (unless `server_name` overrides). |
| `server_name` | Optional override of the expected server identity (unix-socket TLS uses it by default, from the local `server.crt`'s first SAN). |
| `ca_cert` | CA to trust. |
| `client_cert`, `client_key` | Cert/key to present. |
| `session` | Relay session ID: `host`/`port` then name the relay, the TLS SNI is the session, and the server certificate is still verified for `host` ([relay.md](relay.md)). |
| `version`, `updated` | Bookkeeping. |

Rules:

- Written only by `client -import`. On a daemon host, `mtls`, `daemon start`
  and `mcp start` remove a leftover one; `status` mentions it until then.
- The `client.json` endpoint is the only API path. Local sockets
  (`KBTOOL_SOCKET`, `daemon.sock`, `mcp.sock`) are never tried. `call` / `query` / `terms` /
  `bundle` / `tools` / `status` / stdio `mcp` never touch a local db,
  `board.bin`, or lock file. `tools` and `status` show the daemon's enabled
  tools (its `config.json` decides, e.g. `message_board`), not local defaults.
  The state dir needs only `client.json`, `ca.crt`, `client.crt`, and
  `client.key`. An unreachable endpoint or an unloadable cert/key/CA is an
  error, so an agent can't end up on a private message board without noticing.
- Enroll another machine with the daemon's one-line
  [client -import](client-simple.md); it writes `client.json` pointing at
  the imported URL's host and port.

## Environment variables

| Variable | Meaning |
|---|---|
| `KBTOOL_DIR` | State dir (default `~/.config/kbtool`; `config.json` lives here too). |
| `KBTOOL_DB` | Db file (default `<state>/kb.db`). |
| `KBTOOL_SOCKET` | Daemon socket override. |
| `KBTOOL_BOARD` | Board file (default `<dir-of-db>/board.bin`; moot when the store is encrypted). |
| `KBTOOL_BOARD_TTL` | Seconds an agent stays `ACTIVE` after last-seen (default 120). |
| `KBTOOL_DBKEY` | DB-at-rest key hand-off: set by `daemon start` for its child; also honored directly by one-shot commands (precedence: `-db-key-env` > `-db-key-file` > `$KBTOOL_DBKEY` > prompt). |
| `KBTOOL_RELAY_PORT`, `KBTOOL_RELAY_BIND`, `KBTOOL_RELAY_TOKEN`, `KBTOOL_RELAY_ROTATE`, `KBTOOL_RELAY_CA_TTL` | Relay service settings (flag > environment > `config.json`); see [relay-systemd.md](relay-systemd.md). |
| `KB_EMBED_URL` / `KB_EMBED_KEY` / `KB_EMBED_MODEL` | Remote OpenAI-compatible embeddings endpoint (instead of the local hashing backend). |

## Typical configurations

**Local single-agent dev:** no network fields in `config.json`; CLI and agent
talk over the unix socket / stdio. Nothing else to configure.

**Shared service (mTLS):** `mtls: true`, `http: true`, cert names set
(`kbtool mtls` does this); friends enroll with the `kbtool client -import …` line the daemon prints at
boot; revoked clients go into `crl.pem`.

**Behind NAT (relay):** `kbtool relay start` on a reachable machine;
`kbtool relay establish https://RELAY:9876/` on the daemon host; clients
paste the printed `kbtool client -import kb1…` line
([relay-simple.md](relay-simple.md)).

**Private index (encrypted at rest):** build with `-encrypt` (or key flags);
the key then travels via `-db-key-env` / `-db-key-file` / `$KBTOOL_DBKEY` —
never in any file kbtool owns.

Back to [README](../README.md) · related: [status.md](status.md) (see the
resolved values) · [mtls.md](mtls.md) · [client.md](client.md)
