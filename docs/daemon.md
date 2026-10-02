# kbtool daemon — full reference

The background service. Load the pre-built DB, serve it (and the message
board) on a unix socket, optionally rebuild, optionally serve TCP with mTLS.

```
kbtool daemon run  [opts] [-live] [repo …]     # foreground (same flags as start)
kbtool daemon start [opts] [-live] [repo …]    # background (detached, pid file)
kbtool daemon stop
kbtool daemon status                            # pid + socket
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
| `-http` | config, else **on with mTLS**, off without | Also serve over TCP: `GET /healthz` + `POST /mcp` (JSON-RPC). With mTLS on (`-mtls` or config) HTTP is on by default, on all interfaces (`:9876`); pass `-http=false` for a unix-socket-only mTLS daemon (needed on each start: `config.json` cannot record "off"). With a relay configured (`relay_url`), HTTP is off unless `-http` or config `http: true`. |
| `-mtls` | off (or config) | Require mTLS on the served socket(s). Requires server + client certs (`kbtool mtls`). With mTLS the protocol is TLS (HTTP/2 via ALPN). |
| `-http-allow-insecure` | off | Allow cleartext (unauthenticated) HTTP on a **non-loopback** bind. Default: refused — use `-mtls`, or bind `127.0.0.1`. Loudly warned when in effect. |
| `-bind HOST:PORT` | config, else `:9876` with `-mtls` / `127.0.0.1:9876` without | TCP listen address (IPv6 in brackets). |
| `-crl FILE` | config, else `<state>/crl.pem` | CRL PEM file with revoked client certs (may not exist — no revocation data). Enforced at the TLS handshake. |
| `-crlrefresh` | off | Periodically re-load the CRL file. Default (off): the file is **watched** for changes. |
| `-crlinterval SEC` | 60 | CRL reload period when `-crlrefresh`. |

### Message board

| Flag | Default | Description |
|---|---|---|
| `-board-max-memory VALUE` | config `message_board_max_memory`, else `25%` | Memory limit for the whole board (messages + agents + attachments), e.g. `25%` of the memory available at launch or `512MiB`. An invalid value refuses to start. The resolved limit is logged at startup, with a warning if the existing board is already over it. See [client-server-config.md](client-server-config.md). |

> **Shared client certificates are allowed by design.** Many clients may
> present the same `client.crt`/`client.key` (one enrollment line authorizes a
> dozen+ concurrent clients) — TLS and the daemon enforce no per-certificate
> uniqueness. The CRL is the kill switch for a shared identity: revoking the
> certificate revokes **every** holder of it.

## Behavior

- **Precedence:** explicit flag > `config.json` > default — for every option,
  including network fields. `kbtool status` shows the resolved values.
- **Cleartext-HTTP guard:** a non-loopback `-http` bind is refused unless
  `-mtls` or `-http-allow-insecure`. Default bind is loopback without mTLS
  (local trust) and dual-stack `:9876` with mTLS. A rejected start leaves no
  state behind (fails before pid file / socket exist).
- **At-rest encryption:** with an encrypted store the key resolves from
  `-db-key-env` > `-db-key-file` > `$KBTOOL_DBKEY` > prompt (hidden input,
  TTY). `daemon start` passes the key to the detached child via `$KBTOOL_DBKEY`
  only. A mixed plain/encrypted state is refused before serving.
- **Message board:** when `message_board: true` in `config.json`, the board
  is auto-initialized at daemon start (board file + `welcome` thread) and
  stays searchable (`kind=board`) and live across clients.
- **Client enrollment (`-http -mtls`):** the TCP port speaks three protocols,
  split on the first byte of each connection. Plain HTTP serves only
  `GET /ca.crt`. TLS without a client certificate reaches only
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
- **Relay mode (`relay_url` in `config.json`):** written by
  `kbtool mtls -relay` / `kbtool relay establish`. The daemon registers its
  stored `relay_session` with the relay, re-registers the same ID after every
  restart or reconnect (it retries forever with jittered backoff, and a
  bare `daemon start` needs no relay arguments and no reachable relay),
  receives client streams through it, and sends its CA
  in the TLS chain (plain HTTP cannot pass the relay). It prints
  `kbtool client -import kb1…` first; that token carries the relay address and
  session. It opens
  no TCP port unless HTTP is asked for, requires mTLS, and refuses to start
  while a relay runs in the same state dir. See [relay.md](relay.md).
- **start vs run:** `start` detaches (pid file, logs under the state dir,
  mode 0600),
  records explicitly-passed flags into `config.json`. `run` never writes
  config. Both remove a leftover `client.json`: the host's CLI uses the unix
  socket only.
- The unix socket is `<state>/daemon.sock` (`KBTOOL_SOCKET` overrides).
  `mcp serve/start` is the same engine under `<state>/mcp.sock` — see
  [mcp.md](mcp.md).

## Examples

```sh
kbtool daemon start                          # bare: last build's options
kbtool daemon start -live /path/to/repoA     # override + re-record
kbtool daemon run -http -mtls -bind 10.0.0.5:9876
kbtool daemon stop && kbtool daemon status
```

## Related

- Simple example: [daemon-simple.md](daemon-simple.md)
- mTLS PKI setup: [mtls-simple.md](mtls-simple.md)
- Daemon behind NAT: [relay.md](relay.md)
- Client bundle for other machines: [client-simple.md](client-simple.md)
- Server/client config files: [client-server-config.md](client-server-config.md)
- Back to [README](../README.md)
