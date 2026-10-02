# kbtool relay — quick start

Share an mTLS daemon that cannot accept connections (NAT, firewall, Docker)
through a relay that only forwards encrypted bytes.

**Relay machine (reachable by everyone):**

```sh
kbtool relay start                       # listens on :9876 (or KBTOOL_RELAY_PORT)
kbtool relay status
```

**Daemon host:**

```sh
kbtool daemon stop                       # establish refuses while the daemon runs
kbtool relay establish https://relay.example.net:9876/
# prints:
#   kbtool client -import kb1…
```

**Each client machine — paste that line:**

```sh
kbtool client -import kb1…               # the relay address and session are inside the token
kbtool status                            # reachable via the relay
```

The session ID is stored on the daemon host and reused across daemon restarts,
so enrolled clients keep working until the certificates expire (24h by
default; `relay establish … -expire 72h` for a longer session). The relay
cannot read the traffic: the team's own mTLS runs end to end. The message
board is on by default in relay mode (`"message_board": false` in
`config.json` turns it off).

As a systemd service: [relay-systemd.md](relay-systemd.md)

Full reference: [relay.md](relay.md) · back to [README](../README.md)
