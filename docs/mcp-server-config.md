# Configuring your agent to use the kbtool MCP server

kbtool exposes its tools in three ways; pick the one your harness supports.

1. **MCP over stdio** — the agent spawns `kbtool mcp` and talks to it on
   stdin/stdout. Works with any MCP-capable harness (Claude, LM Studio,
   etc.).
2. **MCP over HTTP** — a running daemon serves `POST /mcp` (JSON-RPC) and
   `GET /healthz`, optionally with mandatory mTLS. For clients that speak
   MCP over HTTP, or any raw JSON-RPC client.
3. **OpenAI-compatible function calling** — `kbtool tools -qwen` prints the
   exact `tools` array for harnesses that do their own tool dispatch (LM
   Studio / Qwen / OpenAI-compatible chat endpoints).

The tool set is the same everywhere (after applying the `disable_tools` /
`git_tools` / `message_board` rules — see [client-server-config.md](client-server-config.md)).

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

For an **encrypted** store, pass the key via environment (the stdio server
never prompts — it fails closed without a key):

```json
{
  "mcpServers": {
    "kbtool": {
      "command": "/usr/local/bin/kbtool",
      "args": ["mcp", "-db-key-file", "/run/keys/kbtool.key"]
    }
  }
}
```

You can also inject the key through the environment — e.g. set
`KBTOOL_DBKEY` in `env` — precedence is
`-db-key-env` > `-db-key-file` > `$KBTOOL_DBKEY`.

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

## 2. MCP over HTTP (daemon with `-http`, or `-http -mtls`)

One JSON-RPC message per `POST /mcp` request (16 MiB body cap).

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

Loopback cleartext (local-only daemon, no mTLS) is plain `http://127.0.0.1:9876`.

## 3. OpenAI-compatible / LM Studio function calling

`kbtool tools -qwen` prints a ready-to-use `tools` array. Embed it in a
`chat/completions` request and dispatch `tool_calls` yourself against the
daemon (e.g. via the `POST /mcp` calls above, or `kbtool call`):

```sh
kbtool tools -qwen > /tmp/kbtool-tools.json
# then:  "tools": $(cat /tmp/kbtool-tools.json)   in your chat/completions body
```

Works with LM Studio, Qwen (local or API), or any OpenAI-compatible endpoint.

## Getting the right tool set

Tools are only listed/served when enabled (group option on AND not in
`disable_tools`). Typical setup for a full local dev agent:

```json
// ~/.config/kbtool/config.json
{
  "git_tools": true,
  "message_board": false,
  "disable_tools": []
}
```

See [client-server-config.md](client-server-config.md) for every field and
[call.md](call.md) for each tool's arguments. Back to [README](../README.md)
