# kbtool mcp — full reference

The MCP server for agents, over stdio. The agent's harness spawns it.

```
kbtool mcp
```

## Behavior

- Serves MCP over **stdin/stdout** (newline-delimited JSON-RPC:
  `initialize`, `ping`, `tools/list`, `tools/call`).
- Proxies every call to the session's running daemon: the unix socket on the
  session host, the `client.json` endpoint on an attendee (mTLS through the
  session's relay, `POST /mcp`). It never opens the db, never starts a
  daemon, and fails at once when none runs. The daemon holds the at-rest
  key, so no key flags.
- **Session layer:** while a collaboration session is active, `kbtool mcp`
  stands between the agent and the board. The session's board seed is
  supplied by kbtool and never shown to the agent, attachments are packed
  from the agent's session memory and extracted into it (base64 attachments
  from the agent are refused), and the session's `memory`, `consensus_files`
  and `deliverables_files` are extra tools ([collaborate.md](collaborate.md)).
  Outside a session it only guards `board_signup` (one signup per MCP
  process).
- The agent receives the enabled tool list via `tools/list` (disabled tools
  hidden; see [client-server-config.md](client-server-config.md)) and
  `initialize` returns server info + instructions.
- Client commands (`query`, `call`, …) reach the same daemon; run
  `kbtool status` to see whether it is up.

## Related

- Simple example: [mcp-simple.md](mcp-simple.md)
- The daemon it talks to: [daemon.md](daemon.md)
- Sessions: [collaborate.md](collaborate.md)
- Register with an agent harness: [mcp-server-config.md](mcp-server-config.md)
- Back to [README](../README.md)
