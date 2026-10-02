# kbtool relay — full reference

A relay lets clients reach an mTLS daemon that cannot accept connections
(behind NAT, a firewall, or Docker port mappings). The daemon connects **out**
to the relay and registers a session; clients connect to the relay, and the
relay forwards their bytes to the daemon without decrypting them. One relay
carries many team sessions at once.

```
kbtool relay run|start [-bind :9876] [-token T] [-ip IP,…] [-dns NAME,…] [-rotate 12h] [-ca-ttl 24h]
                       [-max-sessions 5000] [-conn-rate 20] [-register-rate 30] [-cert FILE -key FILE]
kbtool relay stop | status
kbtool relay unit [-port N] [-bind HOST:PORT] [-name NAME]
kbtool relay establish https://RELAY:PORT/ [-expire 24h] [-ip IP…] [-dns NAME…] [-token T] [-relay-ca system|FILE] [daemon start options…]
```

## Recommended setup

On a reachable machine (a small cloud VM, for example):

```sh
kbtool relay start                    # :9876; add -token T to restrict registration
```

On the daemon host, one command:

```sh
kbtool relay establish https://relay.example.net:9876/
```

It prints the client command: one token that carries the relay host, port,
session and the bundle key:

```
kbtool client -import kb1TOKEN
```

Paste that line on each client machine ([client.md](client.md)).

## Trust model

| Layer | Protects | Trust anchor |
|---|---|---|
| Relay TLS | Session registration between daemon and relay (session proof, token) | By default the relay CA, fetched over plain HTTP from `/ca.crt` and always trusted; with `-relay-ca` the system roots or a pinned CA, host name checked |
| Session key | Who may register a session ID | The daemon's `relay-session.key`; the session ID is derived from its public key and the team CA's expiry |
| Team TLS / mTLS, end to end through the relay | Everything that matters: bundle, MCP traffic | The token's bundle key (enrollment: the decrypted bundle names the team CA), then the team mTLS |

The relay operator, or anyone who intercepts the relay CA download, can see
metadata (session IDs in SNI, who connects when, byte counts) and can drop
traffic. They cannot read or alter team traffic, enroll a client, or
impersonate a team daemon. The relay holds no team keys. Nobody without the
daemon's session key can register its session, not even with a captured
registration (the signature is bound to one TLS connection).

## The relay service: `run`, `start`, `stop`, `status`

| Option | Default | Description |
|---|---|---|
| `-bind ADDR` | `$KBTOOL_RELAY_BIND`, `$KBTOOL_RELAY_PORT`, config `relay_bind`, else `:9876` | Listen address. `start` records it in `config.json`. The default is the daemon's port: a relay and a daemon never share a state dir, so a host runs one or the other. |
| `-token T` | `$KBTOOL_RELAY_TOKEN`, config `relay_token`, else none | When set, daemons must present this token to register. `start` records it in `config.json`, so it never appears in the process list. |
| `-ip LIST`, `-dns LIST` | — | Extra SANs for the relay certificate, added to the defaults of `kbtool mtls` (interface IPs, hostname, `host.docker.internal`). Daemons do not check the relay's host name, so these are rarely needed. |
| `-rotate D` | `$KBTOOL_RELAY_ROTATE`, else `12h` | How often the in-memory CA is replaced. |
| `-ca-ttl D` | `$KBTOOL_RELAY_CA_TTL`, else `24h` | Lifetime of each CA and its leaf; must be longer than `-rotate`. |
| `-max-sessions N` | `$KBTOOL_RELAY_MAX_SESSIONS`, config `relay_max_sessions`, else `5000` | Most sessions registered at once; more registrations get 503. `start` records it in `config.json`. |
| `-conn-rate R` | `$KBTOOL_RELAY_CONN_RATE`, else `20` | New connections per second per source IP, burst 5×; over the rate, connections are closed at once. `0` = unlimited. |
| `-register-rate R` | `$KBTOOL_RELAY_REGISTER_RATE`, else `30` | Registrations per minute per source IP, burst 10; over the rate, 429. `0` = unlimited. |
| `-cert FILE`, `-key FILE` | `$KBTOOL_RELAY_CERT`, `$KBTOOL_RELAY_KEY` | Serve an operator certificate chain instead of the in-memory CA. `/ca.crt` serves the chain's last certificate. Not combinable with `-rotate`, `-ca-ttl`, `-ip`, `-dns`. |

Precedence: flag, then environment, then `config.json`, then the default. An
invalid environment value stops the relay with the variable named.

- `run` serves in the foreground; `start` runs it in the background (log:
  `<state>/relay.log`) and waits for `/healthz`; `stop` ends it; `status`
  shows the pid, a `/healthz` probe and the current CA fingerprint.
- **In-memory CA.** At every start the relay generates a new CA and a leaf
  signed by it, valid for `-ca-ttl`, and writes neither to disk. Leftover
  `relay-ca.crt`, `relay-ca.key`, `relay.crt` and `relay.key` files from older
  versions are deleted at start.
- **Rotation.** Every `-rotate`, and at once on `SIGHUP`, a new CA and leaf
  replace the old ones: `/ca.crt` serves the new CA and new handshakes get
  the new leaf. Established connections (daemon control streams, forwarded
  client streams) are not affected, because certificates are only checked at
  the handshake. Daemons fetch the CA at every registration, and when a
  stream's handshake fails they fetch it again and retry once, so nothing
  needs to be redistributed. The fingerprint that `relay establish` prints
  changes with every rotation and restart.
- **Operator certificate.** With `-cert`/`-key` there is no rotation; `SIGHUP`
  reads both files again (a broken pair is logged and the old one kept).
  Daemons set up with `-relay-ca system` (a public certificate) or
  `-relay-ca FILE` (your CA) verify it including the host name.
- **systemd.** `run` sends `READY=1`, a `STATUS=` line after each rotation and
  `STOPPING=1` when `NOTIFY_SOCKET` is set (`Type=notify`). `relay unit`
  prints a service unit for the running binary. See
  [relay-systemd.md](relay-systemd.md).
- One port serves everything:
  - plain HTTP: `GET /ca.crt` (the relay CA) and `GET /healthz`;
  - TLS whose SNI is a live session ID: forwarded to that daemon unopened;
  - TLS whose SNI looks like a session ID that is not live: closed;
  - any other TLS: terminated by the relay, which serves `/healthz`,
    `POST /v1/register` and `POST /v1/accept/<id>` to daemons.
- **A relay and a daemon cannot share one state dir**: each refuses to start
  while the other runs there.

### Limits

| Limit | Value |
|---|---|
| Concurrent streams per session | 64 |
| Concurrent streams in total | 1024 |
| Time for the daemon to accept an announced stream | 10 s |
| Idle timeout of a forwarded stream (no bytes either way) | 5 min |
| Control-stream keepalive | 30 s (the session drops after 90 s of silence) |
| Control line length | 128 bytes (longer: the stream is closed, on both ends) |
| Registered sessions | `-max-sessions`, default 5000 |
| New connections per source IP | `-conn-rate`, default 20/s, burst 100 |
| Registrations per source IP | `-register-rate`, default 30/min, burst 10 |

Idle rate-limit entries are dropped every minute; the table holds at most
100,000 addresses (new addresses are refused while it is full). Clients and
daemons behind one NAT share a budget.

Nothing is written to disk except the relay's config, pid file and log.

## `relay establish` (daemon host)

1. **Refuses if the daemon is running**: "the daemon must not be running to
   establish a relay connection; run 'kbtool daemon stop' first". Also refuses
   if a relay runs in this state dir.
2. **Checks the relay**: calls `/healthz` over HTTPS, verified the way the
   daemon will (by default with the CA downloaded over HTTP; with `-relay-ca`
   against the system roots or the given CA, host name included). Nothing is
   written if the relay is not usable.
3. **New session**: exactly `kbtool mtls -relay URL` with `-expire`, `-ip`,
   `-dns`, `-token` and `-relay-ca` (see below). New certificates (default
   24h), a new session key and session ID.
4. **Starts the daemon**: `kbtool daemon start` with every other option. It
   registers the session and prints the client command.

## `kbtool mtls -relay URL` (manual step 1)

```
kbtool mtls -relay https://RELAY[:PORT]/ [-token T] [-relay-ca system|FILE] [-ip …] [-dns …] [-expire 24h]
```

- Issues a new CA, server and client certificate. The server certificate's
  SAN is **the relay host** (IP or DNS name), plus any `-ip`/`-dns` given;
  the default SANs are not used.
- `config.json`: `mtls: true`, `http` off, no `http_addr`, `relay_url`
  (normalized, port 9876 by default), a new `relay_session`,
  `relay_token` (cleared when `-token` is not given), `relay_ca` (`system`,
  the absolute path of the CA file, or unset to fetch `/ca.crt`), and
  `message_board: true`, so the team's agents can use the board right away.
  Set `"message_board": false` afterwards to turn it off; that choice is kept
  until the next `mtls -relay` or `relay establish`.
- `relay-session.key` (mode 0600): the session's Ed25519 key. The daemon
  refuses to start in relay mode without it, or when `relay_session` does not
  match it and `ca.crt`; rerun `mtls -relay` or `relay establish`.
- No `client.json` on the daemon host: its CLI always uses the unix socket
  (with TLS), never the relay.
- Then `kbtool daemon start`. Running plain `kbtool mtls` later turns relay
  mode off again.

## Sessions

- The session ID is the first 128 bits of SHA-256 over a label, the session
  key's public key and the team CA's expiry, as 32 lowercase hex characters: a
  valid DNS label, so it can travel as SNI. It is created once by `mtls -relay`
  / `relay establish` and stored as `relay_session`. Every daemon start and
  every reconnect registers **the same ID**, so enrolled clients keep working
  across daemon restarts for as long as the certificates are valid (pick a
  longer `-expire` for a multi-day session).
- The ID only routes; it is not a secret. It is in every client's
  `client.json` and in cleartext SNI. Registering it takes the key: the
  daemon sends the public key, the expiry and an Ed25519 signature over the
  session, the expiry and keying material exported from that very TLS
  connection. The relay recomputes the ID, checks the signature and keeps no
  per-session state. Registrations without a key (older daemons) are refused.
- **Expiry.** The session expires with the team CA. The relay refuses an
  expired session and closes a live one at that moment; the daemon keeps
  retrying and logs why. Rerun `relay establish` for a new CA and session.
- The relay keeps a session only while the daemon's control stream is up. When
  the daemon disconnects the relay forgets it and closes connections for it.
  The daemon never gives up: it reconnects forever with jittered exponential
  backoff (the ceiling doubles from 1 s to 30 s and resets after a successful
  registration; each wait is between half the ceiling and the ceiling), so the
  daemons of a restarted relay don't all retry at the same moment.
- A second registration of a live ID by its own daemon (for example a stale
  connection the relay has not noticed yet) is refused with 409 until the old
  one drops. Without the key, nobody else can register the ID at all.

## The daemon in relay mode

- Opens **no TCP port** by default, so nothing bypasses the relay. `-http`
  on `daemon start`, or `http: true` in `config.json`, adds the usual HTTPS
  port as well.
- Sends its CA certificate in the TLS handshake (relay mode only), so the full
  chain is visible through the relay (plain HTTP cannot pass SNI routing).
- Logs and prints the relay import line first, then one line per server
  address if HTTP is on. `kbtool status` shows the relay URL and session.

## Clients

- `kbtool client -import kb1TOKEN` opens TLS to the relay with SNI = session,
  downloads and decrypts the bundle with the token's key, then requires the
  daemon certificate on that connection to be valid for the relay host under
  the bundled CA ([client.md](client.md)).
- Later connections use SNI = session ID while still verifying the daemon
  certificate against the team CA for the relay host.

## Related

- Simple example: [relay-simple.md](relay-simple.md)
- Running the relay as a systemd service: [relay-systemd.md](relay-systemd.md)
- PKI: [mtls.md](mtls.md)
- Daemon options: [daemon.md](daemon.md)
- Enrollment: [client.md](client.md)
- Config fields: [client-server-config.md](client-server-config.md)
- Cryptography and trust protocols: [cryptography.md](cryptography.md)
- Back to [README](../README.md)
