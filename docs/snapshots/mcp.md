# kbtool mcp — snapshot builds

Applies to snapshot builds only (`make release-snapshot` or `go build`).
Release builds refuse every `mcp` subcommand; the stdio server (bare
`kbtool mcp`) is in [../mcp.md](../mcp.md).

Snapshot builds can also run the daemon as a socket MCP service without a
session:

```
kbtool mcp serve [opts] [-live] [repo …]     # foreground, unix socket (alias: run)
kbtool mcp start [opts] [-live] [repo …]     # background (detached)
kbtool mcp stop
kbtool mcp status
```

## serve / run / start

`mcp serve|run` runs in the **foreground** (like `daemon run`); `mcp start`
detaches it in the background. All accept the full serving flag set —
identical to the daemon's (see [daemon.md](daemon.md) for the complete table):

- build options: `-src -build -dim -chunk -overlap -maxkb -git -gitmaxcommits
  -gitdiffmaxkb -kwpath -db`
- live repos: `-live repoA repoB …` (positional args after `-live` feed
  `git_blame` / `git_log`)
- at-rest key: `-db-key-env NAME | -db-key-file PATH`
- network: `-http -mtls -bind HOST:PORT -crl FILE
  -crlrefresh -crlinterval SEC`
- message board: `-board-max-memory 25%|512MiB` (memory limit for all
  messages + attachments; default: config `message_board_max_memory`, else
  `25%`)

Extra `start` behavior:

- Records the flags you explicitly passed into `config.json` (a bare `start`
  leaves the file untouched), so the next bare start reproduces the setup.
- Removes a leftover `client.json`: the host's CLI uses the unix socket only.

`stop` terminates the running service; `status` prints pid + socket. A
remote client refuses all four.

## Behavior notes

- Serves the unix socket `<state>/mcp.sock` (or `$KBTOOL_SOCKET`) by default;
  with mTLS it also serves HTTPS (`GET /healthz`, `POST /mcp`, client
  certificate required) on its own TCP port (direct mode). There is no
  plain-HTTP mode; see [daemon.md](daemon.md).
- Client commands (`query`, `call`, …) reach whichever service's socket is
  live; `kbtool status` shows a `mcp:` line next to `daemon:`.
- Encrypted store: the key resolves from flag > `$KBTOOL_SECRET` > prompt
  (TTY) for serve/run/start.

## MCP over HTTPS in direct mode

A daemon started with `-http -mtls` serves one JSON-RPC message per
`POST /mcp` request (16 MiB body cap) on its TCP port, for clients that
speak MCP over HTTP or any raw JSON-RPC client:

```sh
# Health check (mTLS: --cacert + --cert/--key required)
curl --cacert ~/.config/kbtool/ca.crt \
     --cert   ~/.config/kbtool/client.crt \
     --key    ~/.config/kbtool/client.key \
     https://kb.example.net:9876/healthz

# tools/list
curl --cacert ~/.config/kbtool/ca.crt \
     --cert   ~/.config/kbtool/client.crt \
     --key    ~/.config/kbtool/client.key \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
     https://kb.example.net:9876/mcp

# tools/call
curl … -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"search_codebase","arguments":{"q":"how do we parse config","k":5}}}' \
     https://kb.example.net:9876/mcp
```

Without mTLS the daemon serves only its unix socket. A harness can also
dispatch the `kbtool tools -qwen` function calls against this endpoint.

## Related

- Release reference: [../mcp.md](../mcp.md) ·
  harness config: [../mcp-server-config.md](../mcp-server-config.md)
- Daemon options: [daemon.md](daemon.md)
- Network sharing with mTLS: [mtls-simple.md](mtls-simple.md)
- Back to [README](../../README.md)
