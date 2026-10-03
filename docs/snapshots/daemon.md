# kbtool daemon — snapshot builds

Applies to snapshot builds only (`make release-snapshot` or `go build`).
Release builds refuse everything on this page. `daemon status | stop` and how
the session's daemon behaves are in [../daemon.md](../daemon.md).

Snapshot builds can start a daemon without a session: load the pre-built DB,
serve it (and the message board) on a unix socket, optionally rebuild,
optionally serve TCP with mTLS (direct mode).

```
kbtool daemon run  [opts] [-live] [repo …]     # foreground (same flags as start)
kbtool daemon start [opts] [-live] [repo …]    # background (detached, pid file)
```

## Options (shared by `run` and `start`)

### Build / store

| Flag | Default | Description |
|---|---|---|
| `-src DIR` | config sources | Source dir to build from when no DB exists. |
| `-build` | off | Force rebuild from sources. |
| `-dim N` | config, else 1024 | Embedding dimension. |
| `-chunk N` | config, else 48 | Chunk size (lines). |
| `-overlap N` | config, else 12 | Chunk overlap (lines). |
| `-maxkb N` | config, else 512 | Max file size (KB). |
| `-git` | config | Rebuild with git history + provenance. |
| `-gitmaxcommits N` | config, else 200 | Per-repo commit cap. |
| `-gitdiffmaxkb M` | config, else 8000 | Global KB cap on baked diffs. |
| `-kwpath[=false]` | config, else on | Path-leaf + kind tokens in the keyword index. |
| `-db PATH` | config, else `<state>/kb.db` | Db file. |
| `-db-key-env NAME` | — | DB-at-rest key from `$NAME` (encrypted store). |
| `-db-key-file PATH` | — | DB-at-rest key from file `PATH` (encrypted store). |

### Live repos

| Flag | Description |
|---|---|
| `-live` | Boolean: the **positional args after it** are live git repos used by `git_blame` / `git_log` (post-build state). Without `-live`, live repos come from config (recorded by `build -git` or an earlier `daemon start -live …`). |

### Network / mTLS

| Flag | Default | Description |
|---|---|---|
| `-http` | config, else **on with mTLS** | Also serve HTTPS over TCP: `GET /healthz` + `POST /mcp` (JSON-RPC), client certificate required. Needs mTLS: there is no plain-HTTP mode, and `-http` (or config `http`) without mTLS refuses to start. With mTLS on (`-mtls` or config) HTTP is on by default, on all interfaces (`:9876`); pass `-http=false` for a unix-socket-only mTLS daemon (needed on each start: `config.json` cannot record "off"). In relay mode (`relay_session`), HTTP is off unless `-http` or config `http: true`. |
| `-mtls` | off (or config) | Require mTLS on the served socket(s). Requires server + client certs ([kbtool mtls](mtls.md)). With mTLS the protocol is TLS (HTTP/2 via ALPN). |
| `-bind HOST:PORT` | config, else `:9876` | TCP listen address (IPv6 in brackets). |
| `-crl FILE` | config, else `<state>/crl.pem` | CRL PEM file with revoked client certs (may not exist — no revocation data). Enforced at the TLS handshake. |
| `-crlrefresh` | off | Periodically re-load the CRL file. Default (off): the file is **watched** for changes. |
| `-crlinterval SEC` | 60 | CRL reload period when `-crlrefresh`. |

### Message board

| Flag | Default | Description |
|---|---|---|
| `-board-max-memory VALUE` | config `message_board_max_memory`, else `25%` | Memory limit for the whole board (messages + agents + attachments), e.g. `25%` of the memory available at launch or `512MiB`. An invalid value refuses to start. The resolved limit is logged at startup, with a warning if the existing board is already over it. See [../client-server-config.md](../client-server-config.md). |

> The CRL is the kill switch for a shared client identity: revoking the
> certificate revokes **every** holder of it.

## Behavior (snapshot additions)

- **Precedence:** explicit flag > `config.json` > default — for every option,
  including network fields. `kbtool status` shows the resolved values.
- **No plain HTTP:** the TCP port is only ever HTTPS with client
  certificates. Without mTLS the daemon serves its unix socket only, and
  `-http` refuses to start; a rejected start leaves no state behind (it fails
  before the pid file and socket exist).
- **At-rest encryption without a session:** the key resolves from
  `-db-key-env` > `-db-key-file` > `$KBTOOL_SECRET` > prompt (hidden input,
  TTY). `daemon start` passes the key to the detached child via
  `$KBTOOL_SECRET` only. After an unclean shutdown of an encrypted session,
  `daemon start` refuses until `kbtool session validate` has sealed it.
- **Client enrollment in direct mode (`-http -mtls`):** the TCP port speaks
  three protocols, split on the first byte of each connection. Plain HTTP
  serves only `GET /ca.crt`. TLS without a client certificate reaches only
  `GET /bundle/<id>`: the client bundle, encrypted per request with a key the
  daemon generates at boot and keeps in memory. Every other route (`/mcp`,
  `/healthz`) requires a verified client certificate, and the CRL still
  applies; the unix socket keeps requiring a client certificate at the
  handshake. At boot the daemon prints one
  `kbtool client -import https://HOST:PORT/ kb1…`
  command per server-certificate SAN endpoint, so you can pick the address the
  client can reach and copy its line. With `start` (or `run` in a terminal)
  stdout is the log, so the log holds exactly those bare commands, and `start`
  relays them to the console. When stdout is redirected elsewhere (e.g.
  `daemon run > enroll.txt`), the log also gets one
  `enroll a client via HOST:PORT: kbtool client -import …` entry per endpoint. The key (and so the `kb1…`
  token) changes on every start. If `client.crt`/`client.key` are missing, enrollment is disabled
  with a warning and the port is mTLS-only. See [client.md](client.md).
- **Relay mode without a session:** `kbtool mtls` writes `relay_session`
  when relays are enabled and joined; a bare `daemon start` then needs no
  relay arguments and no reachable relay. Snapshot builds print the relay
  enrollment line as `kbtool client -import kb1…`. The daemon opens no TCP
  port unless HTTP is asked for.
- **start vs run:** `start` detaches (pid file, logs under the state dir,
  mode 0600) and records explicitly-passed flags into `config.json`. `run`
  never writes config. Both remove a leftover `client.json`.
- **Config persistence:** `daemon start` (and `mcp start`) record the flags
  you pass explicitly in `<state>/config.json`; a bare `start` leaves the
  file untouched and reuses the recorded options (the last build's sources
  and options included). Explicit flag > config > default.
- `KBTOOL_SOCKET` overrides the unix socket path. `mcp serve/start` is the
  same engine under `<state>/mcp.sock` — see [mcp.md](mcp.md).

## Examples

```sh
kbtool daemon start                          # bare: last build's options
kbtool daemon start -live /path/to/repoA     # override + re-record
kbtool daemon run -http -mtls -bind 10.0.0.5:9876
kbtool daemon stop && kbtool daemon status
```

## Related

- Release reference: [../daemon.md](../daemon.md)
- mTLS PKI setup: [mtls-simple.md](mtls-simple.md)
- Client bundle for other machines: [client-simple.md](client-simple.md)
- Build options: [build.md](build.md)
- Back to [README](../../README.md)
