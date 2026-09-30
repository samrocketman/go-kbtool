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
| `-http` | off (or config) | Also serve over TCP: `GET /healthz` + `POST /mcp` (JSON-RPC). |
| `-mtls` | off (or config) | Require mTLS on the served socket(s). Requires server + client certs (`kbtool mtls`). With mTLS the protocol is TLS (HTTP/2 via ALPN). |
| `-http-allow-insecure` | off | Allow cleartext (unauthenticated) HTTP on a **non-loopback** bind. Default: refused — use `-mtls`, or bind `127.0.0.1`. Loudly warned when in effect. |
| `-bind HOST:PORT` | config, else `:9876` with `-mtls` / `127.0.0.1:9876` without | TCP listen address (IPv6 in brackets). |
| `-crl FILE` | config, else `<state>/crl.pem` | CRL PEM file with revoked client certs (may not exist — no revocation data). Enforced at the TLS handshake. |
| `-crlrefresh` | off | Periodically re-load the CRL file. Default (off): the file is **watched** for changes. |
| `-crlinterval SEC` | 60 | CRL reload period when `-crlrefresh`. |

> **Shared client certificates are allowed by design.** Many clients may
> present the same `client.crt`/`client.key` (one exported bundle authorizes a
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
- **start vs run:** `start` detaches (pid file, logs under the state dir),
  records explicitly-passed flags into `config.json`, and creates
  `client.json` when absent. `run` never writes config.
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
- Client bundle for other machines: [client-simple.md](client-simple.md)
- Server/client config files: [client-server-config.md](client-server-config.md)
- Back to [README](../README.md)
