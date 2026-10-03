# kbtool daemon — quick start

The session's background service: it serves the session's index and the
message board on a unix socket, and to collaborators through the session's
relay. Hosting or resuming a session starts it:

```sh
# Starts the daemon (and indexes the working directory):
kbtool collaborate host

# Check / stop:
kbtool daemon status
kbtool status
kbtool daemon stop             # finishes the session, like kbtool collaborate finish

# Continue later (starts it again):
kbtool collaborate resume
```

While it runs, every CLI command (`query`, `call`, …) routes through it, and
your agent points at `kbtool mcp` (stdio).

Full reference: [daemon.md](daemon.md) · back to [README](../README.md)
