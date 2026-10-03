# Client & server configuration — snapshot builds

Applies to snapshot builds only (`make release-snapshot` or `go build`).
The state dir layout, `config.json`, `relay.json`, `client.json` and the
environment as sessions use them are in
[../client-server-config.md](../client-server-config.md). This page lists
only what snapshot builds add: direct mode and sessionless use.

## State dir: additional writers and files

| File | Written by (snapshot builds) | Purpose |
|---|---|---|
| `config.json` | `build`, `daemon start`, `mcp start`, `mtls` | `build` records its sources and options; `daemon start` / `mcp start` the flags passed explicitly; `mtls` the network/mTLS fields. |
| `relay.json` | `client -import` of a relay token | Sets `enabled` on a client. |
| `client.json` | `client -import` | Written for remote clients of a direct or relayed daemon. On a daemon host `mtls`, `daemon start` and `mcp start` remove a leftover one. |
| `ca.crt` / `ca.key`, `server.crt` / `server.key`, `client.crt` / `client.key` | `mtls`, `client -import` | The hand-made PKI ([mtls.md](mtls.md)). |
| `crl.pem` | you (optional) | CRL PEM — revoked client certs; enforced at handshake when present ([mtls.md](mtls.md)). |
| `mcp.sock` | `mcp serve\|start` | The socket MCP service ([mcp.md](mcp.md)). |
| pid files / logs | `daemon start`, `mcp start` | Background service bookkeeping. Logs are 0600 (an mTLS daemon logs its client-enrollment line). |

## Roles: additions

- A **daemon host** also counts `mcp.sock` as a host file, and its CLI tries
  `KBTOOL_SOCKET`, `daemon.sock` and `mcp.sock`.
- A **remote client** may reach a direct daemon over HTTPS with mTLS
  (`client.json` `host`/`port`) as well as a relay session. It also refuses
  `bench`, `mtls` and `mcp serve|run|start|stop|status`.
- `client -import` refuses a daemon host's state dir; enroll from another one
  (`KBTOOL_DIR=…`).

## `config.json`: options of `build` and `daemon start`

`build` / `daemon start` / `mcp start` write `config.json`; explicit flag >
config > default.

| Field | Meaning |
|---|---|
| `sources`, `db`, `dim`, `chunk`, `overlap`, `maxKB`, `git`, `gitMaxCommits`, `gitDiffMaxKB`, `kwPath` | Recorded by `build [opts] DIR…` ([build.md](build.md)); a bare `daemon start` / `build` reuse them. |
| `live`, `liveRepos` | Set by `build -git` or `daemon start -live …`: the repos `git_blame`/`git_log` run against (they also join the git tools' trusted set). |
| `message_board_max_memory` | The daemon flag `-board-max-memory` overrides it, and `daemon start -board-max-memory …` records it here. |

### Network / mTLS (written by `mtls`, `daemon start`, `mcp start`)

| Field | Meaning |
|---|---|
| `http` | Also serve HTTPS over TCP (`GET /healthz`, `POST /mcp`, client certificate required); needs `mtls` (the daemon refuses to start otherwise). Implied when `mtls` is true (default bind then: all interfaces, `:9876`) unless `relay_session` is set; only `daemon start -http=false` turns it off. |
| `mtls` | Require client certs on the served socket(s). |
| `http_addr` | Bind address (`HOST:PORT`; empty = `:9876`). `mtls` with exactly one IP and no DNS name binds that IP. |
| `ca_cert`, `server_cert`, `server_key` | PEM file names (relative to the state dir unless absolute). |
| `crl_file` | CRL PEM (default `crl.pem`; may not exist = no revocation data). `-crl FILE` overrides it. |
| `crl_refresh` | `true`: reload the CRL every `crl_interval` seconds; `false` (default): **watch** the file for changes. |
| `crl_interval` | Reload period seconds (default 60). |

### Relay fields written by `mtls`

`kbtool mtls` creates `relay_session` when relays are enabled and joined
(and clears it, with `relay_url`, without them); a bare `daemon start` then
runs in relay mode with no relay arguments. Set, the daemon opens no TCP
port unless `http` is true or `-http` is given.

## `client.json`: direct-mode fields

| Field | Meaning |
|---|---|
| `unix_socket` | Unix socket to use (when set, `host`/`port` are ignored). |
| `host`, `port` | TCP endpoint of a direct daemon (used when `unix_socket` is empty). |
| `hosts` | Optional ordered list of further endpoints for a multi-interface server (written by `kbtool mtls` as every SAN): tried in order after `host`, first live one wins. |
| `server_name` | Optional override of the expected server identity (unix-socket TLS uses it by default, from the local `server.crt`'s first SAN). Over TCP the dialed host is verified against the server cert's SANs unless it is set. |

Written only by `client -import` in snapshot builds. Enroll another machine
with the daemon's one-line [client -import](client-simple.md); it writes
`client.json` pointing at the imported URL's host and port (a relay token
writes `relay.json` instead, and `client.json` keeps only the session).

## Environment variables

| Variable | Meaning |
|---|---|
| `KBTOOL_DB` | Db file (default `<state>/kb.db`). |
| `KBTOOL_SOCKET` | Daemon socket override. |
| `KBTOOL_BOARD` | Board file (default `<dir-of-db>/board.bin`; moot when the store is encrypted). |

Without a session, `daemon start` hands `$KBTOOL_SECRET` to its child, and
the key may also come from a prompt.

## Typical configurations

**Local single-agent dev:** `kbtool build DIR`, `kbtool daemon start`; no
network fields in `config.json`; CLI and agent talk over the unix socket /
stdio.

**Shared service (mTLS):** `mtls: true`, `http: true`, cert names set
(`kbtool mtls` does this); friends enroll with the `kbtool client -import …`
line the daemon prints at boot; revoked clients go into `crl.pem`.

**Direct session:** `kbtool collaborate host -ip …`/`-dns …` (mTLS on all
interfaces, `:9876`, no relay); the others run
`kbtool collaborate attend https://HOST:PORT/ kb1…`.

**Private index (encrypted at rest):** build with `-encrypt` (or key flags);
the key then travels via `-db-key-env` / `-db-key-file` / `$KBTOOL_SECRET`.

Back to [README](../../README.md) · release reference:
[../client-server-config.md](../client-server-config.md) ·
[mtls.md](mtls.md) · [client.md](client.md)
