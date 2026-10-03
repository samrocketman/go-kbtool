# kbtool mcp — quick start

Everything goes through the session's daemon; host or join a session first,
from the working directory holding the code:

```sh
kbtool collaborate host        # or: kbtool collaborate attend kb1…
kbtool status                  # see the daemon running
kbtool query "how do we parse config"   # the CLI talks to the daemon
```

Then point your agent's MCP config at the stdio server:

```sh
#   command: kbtool
#   args:    ["mcp"]
```

`kbtool mcp` speaks MCP (newline-delimited JSON-RPC) over stdin/stdout and
forwards every call to the session's daemon: its unix socket on the host, or
the host's daemon through the session's relay on an attendee. In a session it
also supplies the agent's board seed and the session memory tools. Without a
daemon it exits with an error. `kbtool collaborate finish` ends the session.

Full reference: [mcp.md](mcp.md) · back to [README](../README.md)
