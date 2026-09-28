# kbtool mcp — quick start

Run the MCP server. Two common modes:

**1. stdio — your agent spawns it (simplest, local development):**

```sh
# Point your agent's MCP config at:
#   command: kbtool
#   args:    ["mcp"]
```

`kbtool mcp` loads the index from your last `kbtool build` and speaks MCP
(newline-delimited JSON-RPC) over stdin/stdout. No socket, no port, no daemon.

**2. background service — share one instance across many clients:**

```sh
kbtool daemon start            # or: kbtool mcp start
kbtool status                  # see it running
kbtool query "how do we parse config"   # CLI now talks to the service
kbtool daemon stop
```

**Which one to pick:** stdio for a single local agent; `daemon`/`mcp start`
when you want one long-lived service (optionally over mTLS TCP — see
[mtls-simple.md](mtls-simple.md)) shared by several agents or machines.

Full reference with every option: [mcp.md](mcp.md) · back to [README](../README.md)
