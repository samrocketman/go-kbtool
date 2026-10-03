# Configuring your agent to use the kbtool MCP server

kbtool exposes its tools in two ways; pick the one your harness supports.

1. **MCP over stdio** — the agent spawns `kbtool mcp` and talks to it on
   stdin/stdout. Works with any MCP-capable harness (Claude, LM Studio,
   etc.).
2. **OpenAI-compatible function calling** — `kbtool tools -qwen` prints the
   exact `tools` array for harnesses that do their own tool dispatch (LM
   Studio / Qwen / OpenAI-compatible chat endpoints).

The tool set is the same everywhere (after applying the `disable_tools` /
`git_tools` / `message_board` rules — see [client-server-config.md](client-server-config.md)).

Both need the session's daemon: host or join a session first
(`kbtool collaborate host` / `kbtool collaborate attend kb1…`) and start the
harness in the session's working directory, where
`AGENTS_COLLABORATION.md` teaches the agent the tools
([collaborate.md](collaborate.md)).

## 1a. Claude Code / Claude Desktop style (`mcpServers`)

stdio — the harness spawns the process:

```json
{
  "mcpServers": {
    "kbtool": {
      "command": "/usr/local/bin/kbtool",
      "args": ["mcp"]
    }
  }
}
```

`kbtool mcp` proxies to the session's running daemon: the unix socket on the
session host, or the `client.json` endpoint (the host's daemon over mTLS
through the session's relay) on an attendee. Without a running daemon the
stdio server exits at once. The daemon holds the key of an encrypted store,
and kbtool supplies the session's board seed, so the agent's config needs
neither.

## 1b. Generic MCP stdio config (any harness)

Most MCP hosts use the same shape: a command + args that speak
newline-delimited JSON-RPC on stdio.

```json
{
  "name": "kbtool",
  "transport": "stdio",
  "command": "kbtool",
  "args": ["mcp"]
}
```

Protocol: MCP `2024-11-05`; methods `initialize`, `ping`, `tools/list`,
`tools/call`; responses are `content: [{type:"text",text:"…"}]` + `isError`.

If the harness lets you set the working directory, point it at the session's
working directory (the directory holding `AGENTS_COLLABORATION.md`).

## 2. OpenAI-compatible / LM Studio function calling

`kbtool tools -qwen` prints a ready-to-use `tools` array. Embed it in a
`chat/completions` request and dispatch `tool_calls` yourself with
`kbtool call` (run from the session's working directory):

```sh
kbtool tools -qwen > /tmp/kbtool-tools.json
# then:  "tools": $(cat /tmp/kbtool-tools.json)   in your chat/completions body
# each tool call:  kbtool call <name> '<arguments json>'
```

Works with LM Studio, Qwen (local or API), or any OpenAI-compatible endpoint.

## Getting the right tool set

Tools are only listed/served when enabled (group option on AND not in
`disable_tools`). The session host's `config.json` decides for everyone in
the session. Typical setup for a full dev agent:

```json
// ~/.config/kbtool/config.json (session host)
{
  "git_tools": true,
  "message_board": true,
  "disable_tools": []
}
```

See [client-server-config.md](client-server-config.md) for every field and
[call.md](call.md) for each tool's arguments. Back to [README](../README.md)
