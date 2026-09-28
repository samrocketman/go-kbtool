# kbtool mcp — full reference

The MCP server in three shapes:

```
kbtool mcp                                   # stdio server (agent spawns it)
kbtool mcp serve [opts] [-live] [repo …]     # foreground, unix socket (alias: run)
kbtool mcp start [opts] [-live] [repo …]     # background (detached)
kbtool mcp stop
kbtool mcp status
```

## stdio mode: `kbtool mcp`

- Serves MCP over **stdin/stdout** (newline-delimited JSON-RPC:
  `initialize`, `ping`, `tools/list`, `tools/call`).
- Loads the db from config (`sources`, dim, chunk, …) and builds it if the db
  file is missing. No socket, no pid file, no prompt — ideal for agents.
- **Key flags** (must come before any subcommand; the stdio server never
  prompts, it fails closed without a key):

| Flag | Description |
|---|---|
| `-db-key-env NAME` | DB-at-rest key from `$NAME` (encrypted stores). |
| `-db-key-file PATH` | DB-at-rest key from file `PATH` (encrypted stores). |

- The agent receives the enabled tool list via `tools/list` (disabled tools
  hidden; see [client-server-config.md](client-server-config.md)) and
  `initialize` returns server info + instructions.

## serve / run / start

`mcp serve|run` runs in the **foreground** (like `daemon run`); `mcp start`
detaches it in the background. All accept the full serving flag set —
identical to the daemon's (see [daemon.md](daemon.md) for the complete table):

- build options: `-src -build -dim -chunk -overlap -maxkb -git -gitmaxcommits
  -gitdiffmaxkb -kwpath -db`
- live repos: `-live repoA repoB …` (positional args after `-live` feed
  `git_blame` / `git_log`)
- at-rest key: `-db-key-env NAME | -db-key-file PATH`
- network: `-http -mtls -http-allow-insecure -bind HOST:PORT -crl FILE
  -crlrefresh -crlinterval SEC`

Extra `start` behavior:

- Records the flags you explicitly passed into `config.json` (a bare `start`
  leaves the file untouched), so the next bare start reproduces the setup.
- Creates `client.json` **when absent** so the local CLI finds the endpoint.

`stop` terminates the running service; `status` prints pid + socket.

## Behavior notes

- Serves the unix socket `<state>/mcp.sock` (or `$KBTOOL_SOCKET`) by default;
  `-http` adds TCP (`GET /healthz`, `POST /mcp`); `-mtls` makes it mTLS.
  Cleartext on a non-loopback bind is refused unless `-mtls` or
  `-http-allow-insecure` — see [daemon.md](daemon.md) for the rules.
- If a **daemon** (`daemon.sock`) is already running, one-shot CLI commands
  (`query`, `call`) may route through either service; run `kbtool status` to
  see which are up.
- Encrypted store: the key resolves from flag > `$KBTOOL_DBKEY` > prompt
  (TTY) for serve/run/start; stdio never prompts.

## Related

- Simple example: [mcp-simple.md](mcp-simple.md)
- Background service details: [daemon-simple.md](daemon-simple.md)
- Network sharing with mTLS: [mtls-simple.md](mtls-simple.md)
- Register with an agent harness: [mcp-server-config.md](mcp-server-config.md)
- Back to [README](../README.md)
