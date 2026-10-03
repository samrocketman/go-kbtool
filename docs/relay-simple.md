# kbtool relay — quick start

Open a collaboration session to others through a relay that only forwards encrypted bytes:
the daemon's own relay for a LAN or VPN, or a public relay for remote
collaborators behind NAT, firewalls or Docker.

## Same LAN or VPN: self-hosted relay

**Daemon host:**

```sh
kbtool relay self-host start             # once: a random port (20000-32767) and token, kept for good
kbtool collaborate host
# prints one line per address of this machine:
#   kbtool collaborate attend kb1…   # via 192.168.1.20:27824
```

Send the line whose address the others can reach. The relay runs inside the
daemon, in memory, and starts and stops with it; enrolled attendees keep
working across restarts and resumes. Allow the port (`kbtool relay ls`) in
your firewall. `kbtool relay self-host stop` goes back to the joined relays.

## Remote collaborators: public relay

**Relay machine (reachable by everyone):**

```sh
kbtool relay start                       # listens on :9876 (or KBTOOL_RELAY_PORT)
kbtool relay status
```

**Daemon host:**

```sh
kbtool relay join https://relay.example.net:9876/   # once: adds it to relay.json
kbtool relay join https://relay2.example.org:9876/  # optional: more relays to fall back on
kbtool collaborate host                             # index, mTLS via a relay, daemon
# prints:
#   kbtool collaborate attend kb1…
```

**Each other machine — paste that line:**

```sh
kbtool collaborate attend kb1…           # the relay address and session are inside the token
kbtool status                            # reachable via the relay
```

The session ID is stored on the daemon host and reused across daemon restarts,
so enrolled clients keep working until the certificates expire (24h by
default; `collaborate host -expire 72h` for a longer session). The relay
cannot read the traffic: the team's own mTLS runs end to end. The message
board is on by default (`"message_board": false` in `config.json` turns it
off).

With several relays joined, each new session tries them round robin and
sticks to the first that accepts it. If that relay goes down, the daemon
logs errors and waits for it; it never switches on its own. To move the
session: `kbtool collaborate finish`, then
`kbtool collaborate resume -relay https://relay2.example.org:9876/`, and send
the new line to the others. `kbtool relay ls` shows the relays and which one
the session uses.

`kbtool relay disable` keeps the relays but stops using them: new and resumed
sessions are local, and no relay connectivity is needed. `kbtool relay enable`
turns them back on; then `kbtool collaborate finish` and
`kbtool collaborate resume` open a local session to collaborators.
`kbtool relay leave URL` forgets one relay (`-all`: every relay).

As a systemd service: [relay-systemd.md](relay-systemd.md)

Full reference: [relay.md](relay.md) · back to [README](../README.md)
