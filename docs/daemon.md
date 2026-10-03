# kbtool daemon — full reference

The session's background service. `kbtool collaborate host` (and
`kbtool collaborate resume` on the host) starts it: it loads the session's
index, serves it and the message board on a unix socket and, when the session
goes through a relay, to collaborators over mTLS through that relay.

```
kbtool daemon status                            # pid + socket
kbtool daemon stop                              # stops it and finishes the host's session
```

There is nothing to start by hand: hosting or resuming a session starts the
daemon, and finishing it (`kbtool collaborate finish`, or `daemon stop`)
stops it ([collaborate.md](collaborate.md)).

> **Shared client certificates are allowed by design.** Every attendee who
> enrolls with the same enrollment line presents the same
> `client.crt`/`client.key` (one line authorizes a dozen+ concurrent clients)
> — TLS and the daemon enforce no per-certificate uniqueness. Finishing the
> session and resuming it once the certificates expire issues new ones;
> attendees then enroll again with the new line.

## Behavior

- **Unix socket:** the daemon always serves `<state>/daemon.sock`. The
  host's CLI (`query`, `build`, `board`, …) and its agent's `kbtool mcp`
  talk to it there, never over the network. When the session uses a relay
  the socket also requires mTLS, with the state dir's `client.crt` /
  `client.key` and `ca.crt`.
- **Clients need the daemon:** `query`, `terms`, `bundle`, `call`, `tools`,
  stdio `mcp` and the `board` verbs all go through a running daemon and fail
  when none runs; none of them opens the store.
- **Stopping finishes the host's session:** when the daemon hosts the active
  session, stopping it gracefully (`daemon stop`, SIGTERM, SIGINT, an
  operating system shutdown) finishes the session like
  `kbtool collaborate finish`: in an encrypted state dir the session is
  sealed before the process exits ([collaborate.md](collaborate.md)).
  `daemon stop` waits up to two minutes for the daemon to exit. A daemon that
  dies without that (SIGKILL, a crash, power loss) leaves the session plain;
  every command except `kbtool session validate` (and `help`/`version`) then
  refuses until `session validate` has checked and sealed it
  ([session.md](session.md#after-an-unclean-shutdown)).
- **Encryption key:** in an encrypted state dir (`kbtool collaborate host
  -encrypt`, session.json `"encrypt": true`) the session commands resolve the
  key from `-db-key-env` > `-db-key-file` > `$KBTOOL_SECRET` (prompting only
  when `-encrypt` turns encryption on) and hand it to the daemon through
  `$KBTOOL_SECRET` only, never argv or a file. The daemon keeps it in memory,
  re-seals the store with it (so `kbtool build` and the board need no key)
  and seals the session with it when it stops. Without a key the daemon does
  not start. A mixed plain/encrypted state is refused before serving.
- **Message board:** the board is on in sessions (`collaborate host` turns
  `message_board` back on), auto-initialized at daemon start (board file +
  `welcome` thread), and stays searchable (`kind=board`) and live across
  clients.
- **Local session:** with no enabled relay the daemon serves only its unix
  socket and prints no enrollment line: the index and the board are yours and
  your agent's alone. `kbtool relay disable` has the same effect on a
  session that has a relay.
- **Relay mode (`relay_session` in `config.json`):** written by
  `kbtool collaborate host` (or `collaborate resume`) when relays are enabled
  and joined (`kbtool relay join`; `relay.json` holds each relay's URL, token
  and trust) or self-hosted. The session uses its sticky relay
  (`relay_url`), or on first start the first joined relay, round robin, that
  accepts it ([relay.md](relay.md#round-robin-and-sticky-relays)). With
  `selfhost` on in `relay.json` (`kbtool relay self-host start`), the daemon
  runs its own relay in memory on `selfhost_port` and the session uses it
  alone, printing one enrollment line per covered address
  ([relay.md](relay.md#self-hosted-relay-relay-self-host-startstop-daemon-host)).
  The daemon registers its `relay_session` with the relay, re-registers the
  same ID after every restart or reconnect (it retries forever with jittered
  backoff), receives client streams through it, and sends its CA in the TLS
  chain. It opens no TCP port of its own and refuses to start while a relay
  service runs in the same state dir. See [relay.md](relay.md).
- **What attendees reach:** relayed streams end at the daemon as TLS. Without
  a client certificate a stream reaches only the encrypted enrollment bundle
  (`GET /bundle/<id>`, encrypted per request with a key the daemon generates
  at boot and keeps in memory); `POST /mcp` (JSON-RPC, the attendees' CLI and
  `kbtool mcp`) and `GET /healthz` require a verified client certificate.
- **Enrollment lines:** at boot a relayed daemon prints one
  `kbtool collaborate attend kb1…` line per relay address; the token carries
  the relay address, the session and the boot key, so it changes on every
  start. `collaborate host`/`resume` relay the lines to the console; the
  daemon log (mode 0600) holds them too. If `client.crt`/`client.key` are
  missing, enrollment is disabled with a warning.
- **Bookkeeping:** the pid file and the log live in the state dir (mode
  0600). Starting the daemon removes a leftover `client.json`: the host's CLI
  uses the unix socket only.

## Examples

```sh
kbtool daemon status          # is the session's daemon up?
kbtool status                 # the whole picture: session, relay, daemon, board, tools
kbtool daemon stop            # same as kbtool collaborate finish on the host
kbtool collaborate resume     # start it again
```

## Related

- Simple example: [daemon-simple.md](daemon-simple.md)
- Sessions that start and stop it: [collaborate.md](collaborate.md)
- Collaborators behind NAT, LAN or VPN: [relay.md](relay.md)
- Server/client config files: [client-server-config.md](client-server-config.md)
- Back to [README](../README.md)
