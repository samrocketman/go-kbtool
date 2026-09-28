# kbtool tools — quick start

Print the MCP tool schemas that the server will expose (after applying the
disabled-tool rules from `config.json`).

```sh
# JSON (MCP shape):
kbtool tools | head -40

# OpenAI / Qwen function-calling "tools" array:
kbtool tools -qwen > qwen-tools.json
```

The output lists each enabled tool's name, description, and input schema —
exactly what `tools/list` returns to an MCP client, and exactly what
`kbtool call <tool> …` accepts. Disabled tools (see
[client-server-config.md](client-server-config.md)) do not appear.

Full reference: [tools.md](tools.md) · back to [README](../README.md)
