# kbtool daemon — quick start

The long-lived background service: load the pre-built index and serve it (and
the message board) on a unix socket — optionally over mTLS TCP.

```sh
# Bare start: reuses the options recorded by your last `kbtool build`
kbtool daemon start

# …or with overrides:
kbtool daemon start -live /path/to/repoA -git

# Check / stop:
kbtool status
kbtool daemon stop
```

While it runs, every CLI command (`query`, `call`, …) routes through it, and
your agent can point at `kbtool mcp` (stdio) or the socket directly.

Full reference with every option: [daemon.md](daemon.md) · back to [README](../README.md)
