# Client & server configuration

kbtool keeps all state under one directory (**the state dir**):
`~/.config/kbtool` by default, override with `KBTOOL_DIR`. This page covers
the two configuration files the CLI and the service read, who writes them,
and the environment knobs.

## State dir layout

| File | Written by | Purpose |
|---|---|---|
| `config.json` | `build`, `daemon start`, `mcp start`, `mtls` | Server-side configuration: recorded build options, tool options, path trust, network/mTLS. |
| `client.json` | `daemon start`, `mcp start` (absent only), `mtls`, `client -import` | Client-side: where the local CLI connects, and with which certs. |
| `kb.db` | `build`, the service | The index (plain KBV1, or the KBX1 encrypted bundle holding db + board). |
| `board.bin` | the service / one-shot board calls | Message board (absent when the store is encrypted — it's inside `kb.db`). |
| `ca.crt` / `ca.key` | `mtls` | Local CA. |
| `server.crt` / `server.key` | `mtls` | Daemon's TLS cert/key. |
| `client.crt` / `client.key` | `mtls`, `client -import` | Client cert/key presented by the local CLI. |
| `crl.pem` | you (optional) | CRL PEM — revoked client certs; enforced at handshake when present. |
| `daemon.sock` / `mcp.sock` | the service | Unix sockets (`KBTOOL_SOCKET` overrides). |
| `kbtool-client.kbx` | `client -export` | Portable encrypted client bundle. |
| pid files / logs | `daemon start`, `mcp start` | Background service bookkeeping. |

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
| `message_board` | `false` | Enable the board tools: `board_signup`, `board_whoami`, `board_sign`, `board_post`, `board_read`, `board_threads`, `board_search`, `board_confirm`. |
| `disable_tools` | `["kb_status", "board_sign"]` | Per-tool kill switch, **always** honored — it beats the group options. Remove a name (even a core one) to re-enable it; `[]` disables nothing. Unknown names are harmless. |

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
| `http` | Also serve TCP (`GET /healthz`, `POST /mcp`). |
| `mtls` | Require client certs on the served socket(s). |
| `http_addr` | Bind address (`HOST:PORT`; empty = `127.0.0.1:9876` without mTLS, `:9876` with). |
| `http_allow_insecure` | Allow cleartext HTTP on a non-loopback bind (default false — refused; loudly warned when on). |
| `ca_cert`, `server_cert`, `server_key` | PEM file names (relative to the state dir unless absolute). |
| `crl_file` | CRL PEM (default `crl.pem`; may not exist = no revocation data). |
| `crl_refresh` | `true`: reload the CRL every `crl_interval` seconds; `false` (default): **watch** the file for changes. |
| `crl_interval` | Reload period seconds (default 60). |

## `client.json` (client side)

Tells the **local CLI** where to reach a service. Relative cert names are
resolved against the state dir.

| Field | Meaning |
|---|---|
| `unix_socket` | Unix socket to use (when set, `host`/`port` are ignored). |
| `host`, `port` | TCP endpoint (used when `unix_socket` is empty). |
| `tls` | `true` ⇒ mTLS: present the client cert, verify the server via `server_name`. |
| `server_name` | Expected server identity (defaults to the host). |
| `ca_cert` | CA to trust. |
| `client_cert`, `client_key` | Cert/key to present. |
| `version`, `updated` | Bookkeeping. |

Rules:

- Created **when absent** by `daemon start` / `mcp start` (from the flags you
  passed) and by `mtls` (always rewritten — a fresh PKI invalidates the old
  setup).
- A broken/missing `client.json` never blocks local use: the CLI falls back
  to the local unix sockets.
- Migrate a whole working setup to another machine with
  [client -export / -import](client-simple.md).

## Environment variables

| Variable | Meaning |
|---|---|
| `KBTOOL_DIR` | State dir (default `~/.config/kbtool`; `config.json` lives here too). |
| `KBTOOL_DB` | Db file (default `<state>/kb.db`). |
| `KBTOOL_SOCKET` | Daemon socket override. |
| `KBTOOL_BOARD` | Board file (default `<dir-of-db>/board.bin`; moot when the store is encrypted). |
| `KBTOOL_BOARD_TTL` | Seconds an agent stays `ACTIVE` after last-seen (default 120). |
| `KBTOOL_DBKEY` | DB-at-rest key hand-off: set by `daemon start` for its child; also honored directly by one-shot commands (precedence: `-db-key-env` > `-db-key-file` > `$KBTOOL_DBKEY` > prompt). |
| `KB_EMBED_URL` / `KB_EMBED_KEY` / `KB_EMBED_MODEL` | Remote OpenAI-compatible embeddings endpoint (instead of the local hashing backend). |

## Typical configurations

**Local single-agent dev:** no network fields in `config.json`; CLI and agent
talk over the unix socket / stdio. Nothing else to configure.

**Shared service (mTLS):** `mtls: true`, `http: true`, cert names set
(`kbtool mtls` does this); friends get the client side via
`kbtool client -export`; revoked clients go into `crl.pem`.

**Private index (encrypted at rest):** build with `-encrypt` (or key flags);
the key then travels via `-db-key-env` / `-db-key-file` / `$KBTOOL_DBKEY` —
never in any file kbtool owns.

Back to [README](../README.md) · related: [status.md](status.md) (see the
resolved values) · [mtls.md](mtls.md) · [client.md](client.md)
