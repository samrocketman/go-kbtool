# kbtool tools — full reference

Print the MCP tool schemas (the same list the MCP server exposes via
`tools/list`), filtered by the disabled-tool rules in `config.json`.

```
kbtool tools [-qwen]
```

## Options

| Option | Default | Description |
|---|---|---|
| `-qwen` | off | Emit an OpenAI/Qwen function-calling `tools` array (`{"type":"function","function":{…}}`) instead of the MCP `{"name","description","inputSchema"}` objects. |

## Tools listed (when enabled)

| Group | Tools | Enabled when |
|---|---|---|
| core | `search_codebase`, `get_chunk`, `list_files` | always (unless individually disabled) |
| core | `kb_status` | disabled by default (seeded `disable_tools`) |
| git | `git_blame`, `git_log` | `git_tools: true` in `config.json` |
| message board | `board_signup`, `board_whoami`, `board_sign`, `board_post`, `board_read`, `board_fetch`, `board_threads`, `board_search`, `board_confirm` | `message_board: true` in `config.json` |

The per-tool `disable_tools` list always wins over the group options. Full
rules: [client-server-config.md](client-server-config.md).

## Behavior

- No arguments, no network. Output is pretty-printed JSON on stdout.
- The list is computed with the same precedence as the server: `disable_tools`
  (or the seeded default `["kb_status", "board_sign"]`) ∪ group options.
- Use `-qwen` to drop the exact schemas into an OpenAI-compatible
  `chat/completions` request (e.g. LM Studio / Qwen local models).

## Related

- Simple example: [tools-simple.md](tools-simple.md)
- Call a tool from the shell: [call-simple.md](call-simple.md)
- Register these tools in an agent: [mcp-server-config.md](mcp-server-config.md)
- Back to [README](../README.md)
