# kbtool relay — full reference

A relay lets collaborators reach a session's mTLS daemon that cannot accept connections
(behind NAT, a firewall, or Docker port mappings). The daemon connects **out**
to the relay and registers a session; clients connect to the relay, and the
relay forwards their bytes to the daemon without decrypting them. One relay
carries many team sessions at once.

```
kbtool relay run|start [-bind :9876] [-token T] [-ip IP,…] [-dns NAME,…] [-rotate 12h]
                       [-max-sessions 5000] [-conn-rate 20] [-register-rate 30] [-cert FILE -key FILE]
kbtool relay stop | status
kbtool relay unit [-port N] [-bind HOST:PORT] [-name NAME]
kbtool relay join https://RELAY:PORT/ [-token T] [-relay-ca system|FILE]
kbtool relay ls | move https://RELAY:PORT/ | enable | disable
kbtool relay leave https://RELAY:PORT/ … | -all
kbtool relay self-host start | stop
```

## Recommended setup

On a reachable machine (a small cloud VM, for example):

```sh
kbtool relay start                    # :9876; add -token T to restrict registration
```

On the daemon host, record the relay once, then host a session:

```sh
kbtool relay join https://relay.example.net:9876/
kbtool collaborate host
```

The daemon prints the enrollment command: one token that carries the relay
host, port, session and the bundle key:

```
kbtool collaborate attend kb1TOKEN
```

Each other human runs that line in their workspace ([collaborate.md](collaborate.md)).

## Trust model

| Layer | Protects | Trust anchor |
|---|---|---|
| Relay TLS | Session registration between daemon and relay (session proof, token) | By default the certificate the relay presents in the handshake, always trusted (its CA fingerprint is reported); with `-relay-ca` (stored in `relay.json`) the system roots or a pinned CA, host name checked |
| Session key | Who may register a session ID | The daemon's `relay-session.key`; the session ID is derived from its public key and the team CA's expiry |
| Team TLS / mTLS, end to end through the relay | Everything that matters: bundle, MCP traffic | The token's bundle key (enrollment: the decrypted bundle names the team CA), then the team mTLS |

The relay operator, or anyone who can intercept the daemon's connection to the relay, can see
metadata (session IDs in SNI, who connects when, byte counts) and can drop
traffic. They cannot read or alter team traffic, enroll a client, or
impersonate a team daemon. The relay holds no team keys. Nobody without the
daemon's session key can register its session, not even with a captured
registration (the signature is bound to one TLS connection).

## The relay service: `run`, `start`, `stop`, `status`

| Option | Default | Description |
|---|---|---|
| `-bind ADDR` | `$KBTOOL_RELAY_BIND`, `$KBTOOL_RELAY_PORT`, config `relay_bind`, else `:9876` | Listen address. `start` records it in `config.json`. At start the relay connects to its own port on each loopback address the bind covers; if another program answers there (macOS lets an IDE's port forward keep the IPv4 or IPv6 side of a port), or the port is taken, it logs the error with an `lsof` command to find the holder, and `start` fails at once. |
| `-token T` | `$KBTOOL_RELAY_TOKEN`, config `relay_token`, else none | When set, daemons must present this token to register. `start` records it in `config.json`, so it never appears in the process list. |
| `-ip LIST`, `-dns LIST` | — | Extra SANs for the relay certificate, added to the host name (the only default; interface addresses are never included). Daemons do not check the relay's host name, so these are rarely needed. |
| `-rotate D` | `$KBTOOL_RELAY_ROTATE`, else `12h` | How often the in-memory CA and its keys are replaced. |
| `-max-sessions N` | `$KBTOOL_RELAY_MAX_SESSIONS`, config `relay_max_sessions`, else `5000` | Most sessions registered at once; more registrations get 503. `start` records it in `config.json`. |
| `-conn-rate R` | `$KBTOOL_RELAY_CONN_RATE`, else `20` | New connections per second per source IP, burst 5×; over the rate, connections are closed at once. `0` = unlimited. |
| `-register-rate R` | `$KBTOOL_RELAY_REGISTER_RATE`, else `30` | Registrations per minute per source IP, burst 10; over the rate, 429. `0` = unlimited. |
| `-cert FILE`, `-key FILE` | `$KBTOOL_RELAY_CERT`, `$KBTOOL_RELAY_KEY` | Serve an operator certificate chain instead of the in-memory CA. Its last certificate is the fingerprint daemons report. Not combinable with `-rotate`, `-ip`, `-dns`. |
| `-healthz-interval MS` | `$KBTOOL_RELAY_HEALTHZ_INTERVAL`, else `1000` | Milliseconds between answered `/healthz` requests, whoever asks; others get 429 with `Retry-After`. `0` = unlimited. |
| `-honeypot-remember MS` | `$KBTOOL_RELAY_HONEYPOT_REMEMBER`, else `7200000` (2 h) | How long a seen or suspicious client is remembered after its last answered request. |
| `-honeypot-block MS` | `$KBTOOL_RELAY_HONEYPOT_BLOCK`, else `900000` (15 min) | How long a client is dropped when it first turns suspicious. |
| `-honeypot-reblock MS` | `$KBTOOL_RELAY_HONEYPOT_REBLOCK`, else `3600000` (1 h) | How long an already suspicious client is dropped on each further honeypot request. |
| `-honeypot-max-memory M` | `$KBTOOL_RELAY_HONEYPOT_MAX_MEMORY`, else `10%` | Memory for remembered clients: a share of the memory available at launch, or a size like `64MiB` (about 512 bytes per client, at least 1024 clients). |

Precedence: flag, then environment, then `config.json`, then the default. An
invalid environment value stops the relay with the variable named.

- `run` serves in the foreground; `start` runs it in the background (log:
  `<state>/relay.log`) and waits for `/healthz`; `stop` ends it; `status`
  shows the pid, a `/healthz` probe and the current CA fingerprint.
- **In-memory CA.** At every start the relay generates a new CA and a leaf
  signed by it, and writes neither to disk. Leftover
  `relay-ca.crt`, `relay-ca.key`, `relay.crt` and `relay.key` files from older
  versions are deleted at start.
- **Disguised certificate.** Anyone can open a TLS connection to the relay,
  so its certificate looks like a sysadmin's own long-lived self-signed one
  and never names kbtool: the CA is `CN=Easy-RSA CA`, the leaf's CN is the
  host name, its SANs are the host name plus `-ip`/`-dns`, and it is for
  server authentication only. The handshake sends the leaf and the CA. Every
  certificate of one relay process carries the same validity, issued 30 to
  365 days before the start and valid for ten years, so rotations do not show
  as short-lived certificates. `status` therefore prints no expiry for it.
- **Rotation.** Every `-rotate`, and at once on `SIGHUP`, a new CA and leaf
  replace the old ones, and new handshakes get them. Established connections
  (daemon control streams, forwarded client streams) are not affected,
  because certificates are only checked at the handshake. Daemons in the
  default trust mode accept whatever certificate the relay presents, so
  nothing needs to be redistributed. The CA fingerprint that `relay join`
  prints changes with every rotation and restart.
- **Operator certificate.** With `-cert`/`-key` there is no rotation; `SIGHUP`
  reads both files again (a broken pair is logged and the old one kept).
  Daemon hosts that joined with `-relay-ca system` (a public certificate) or
  `-relay-ca FILE` (your CA) verify it including the host name.
- **systemd.** `run` sends `READY=1`, a `STATUS=` line after each rotation and
  `STOPPING=1` when `NOTIFY_SOCKET` is set (`Type=notify`). `relay unit`
  prints a service unit for the running binary. See
  [relay-systemd.md](relay-systemd.md).
- One port serves everything:
  - plain HTTP: `GET /healthz`, and the honeypot (below) for every other
    path;
  - TLS whose SNI is a live session ID: forwarded to that daemon unopened;
  - TLS whose SNI looks like a session ID that is not live: closed;
  - any other TLS: terminated by the relay, which serves
    `/healthz`, `POST /v1/register` and `POST /v1/accept/<id>` to daemons,
    and the honeypot for every other path.
- **A relay and a daemon can share one state dir.** The relay service's
  files (`relay.pid`, `relay.log`, `relay.sock`) stay in the state dir when a
  collaboration session finishes. A session's daemon in relay mode opens no
  TCP port (a self-hosted relay listens on its own `selfhost_port`, drawn
  from 20000-32767), so it does not compete with the relay service for
  `:9876`.

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
| `/healthz` answers (all clients together) | `-healthz-interval`, default 1 per second |

Idle rate-limit entries are dropped every minute; the table holds at most
100,000 addresses (new addresses are refused while it is full). Clients and
daemons behind one NAT share a budget.

Nothing is written to disk except the relay's config, pid file, log and
control socket (`<state>/relay.sock`, mode 0600).

### Honeypot

To anyone browsing it, the relay's port looks like an Apache httpd. Every
answer carries `Server: Apache` (no version, like `ServerTokens Prod`; no page signature, like `ServerSignature Off`), and every path that is not a
kbtool endpoint gets Apache's pages:

- `GET /` (plain HTTP or HTTPS) is a 200 Apache directory listing
  (`honeypot.gohtml`) of 1 to 5 directories. Their names come from 32
  random words (and dates) generated at every start and kept in memory
  only. A client's listing is a 32-bit mask with 1 to 5 bits set, derived
  from its address, so one client sees the same listing over HTTP and HTTPS
  for as long as the relay runs, and no listing is stored per client. The
  word count is fixed; there is no option for it. The listing never shows
  `/healthz` or another path kbtool uses.
- `/icons/blank.gif`, `/icons/folder.gif` and `/icons/back.gif`, the icons
  the listing shows, are Apache's own public-domain files with stock
  `Last-Modified` and `ETag` headers (conditional and range requests work).
  Fetching them never marks a client.
- Any other path is an Apache 404, other methods on `/` a 405.

kbtool never requests `/` or a listed directory: daemons and clients use
only `/healthz`, `/v1/register`, `/v1/accept/…` and session
pass-through. So:

- `GET /` marks the client **seen** (a curious person, or a scanner).
- Any request for one of the honeypot directories makes it **suspicious**.
  The relay answers it (a listing with only a parent link), then drops all
  of the client's connections for `-honeypot-block` (15 min). A client that
  is already suspicious and asks again is dropped for `-honeypot-reblock`
  (1 h) from that request.
- Dropped means the client gets nothing: new connections are accepted but
  never read from or written to, then reset after a minute (at most 4096
  are held; beyond that they are reset at once), and requests on a
  connection that was already open get no answer. Only answered requests
  refresh a client's last-seen time; dropped connections do not.
- A client is forgotten `-honeypot-remember` (2 h) after its last answered
  request, once it is no longer blocked. A forgotten client that comes back
  starts over as seen.
- The table of clients is capped by `-honeypot-max-memory`. When it is full
  the least recently seen clients are forgotten first, so a swarm of
  addresses cannot exhaust memory; it can only push older clients out
  sooner. A relay with more memory remembers more clients.

A user-space process cannot drop TCP packets: the handshake still
completes. For a true drop, feed `kbtool relay honeypot ls -json` into a
firewall. Addresses behind one NAT share a fate: a curious person blocks
everyone behind the same address, including daemons and clients.

`kbtool relay honeypot` talks to the running relay over its control socket
(run it with the relay's `KBTOOL_DIR`; under systemd,
`sudo KBTOOL_DIR=/var/lib/kbtool-relay kbtool relay honeypot ls`):

| Command | Effect |
|---|---|
| `ls [-json]` | The remembered clients: state, last seen, blocked until, when they will be forgotten, requests answered, connections dropped; and how many were forgotten early to stay within memory. |
| `rm IP…` | Forget these clients (unblocks them). |
| `clear [-suspicious]` | Forget every client, or only the suspicious ones. |

## Joined relays: `relay join`, `ls`, `move`, `enable|disable`, `leave` (daemon host)

```
kbtool relay join https://RELAY[:PORT]/ [-token T] [-relay-ca system|FILE]
kbtool relay ls
kbtool relay move https://RELAY[:PORT]/
kbtool relay enable | disable
kbtool relay leave https://RELAY[:PORT]/ … | -all
```

These are daemon-host settings; the relay service itself is configured
separately (above). The host keeps one global list of relays in
`<state>/relay.json` (mode 0600). It survives `kbtool collaborate finish`, so
a host joins each relay once. Relays only forward encrypted bytes (the team's
mTLS runs end to end), so any of them, trusted or not, can carry a session.

`relay join` adds a relay to the list, or updates it when its URL is already
there:

1. **Checks the relay**: calls `/healthz` over HTTPS, verified the way the
   daemon will (by default trusting the certificate presented; with
   `-relay-ca` against the system roots or the given CA, host name
   included). Nothing is written if the relay is not usable.
2. **Writes the entry**: the normalized URL (port 9876 by default), the
   registration token (`-token`, when the relay requires one) and the relay
   trust (`ca`: `system`, the absolute path of the CA file, or unset to trust
   the certificate presented). It also sets `"enabled": true`.

### Round robin and sticky relays

A new relay session (`collaborate host`, or `collaborate resume` opening a
local session) does not pick a relay yet. When the daemon
first starts with it:

1. It tries the joined relays in order, starting at `next` in `relay.json`.
2. The first relay that accepts the registration takes the session. The
   daemon logs each relay that could not take it and moves on.
3. The session **sticks** to that relay: `config.json` records it as
   `relay_url`. `next` moves past it, so the next new session starts on the
   following relay.
4. The daemon prints the enrollment line for that relay.

If no relay accepts the session, the daemon logs an error and keeps trying
all of them. It prints the enrollment line once one does.

A session that has a sticky relay only ever uses that relay. When it is
down, the daemon logs the errors and keeps retrying it, never another relay.
If the sticky relay was removed with `relay leave`, the daemon logs an error
and serves locally only.

### Moving a session (manual)

Only the host moves a session to another relay:

- `kbtool relay move URL`, with the daemon stopped.
- `kbtool collaborate resume -relay URL` for a collaboration session. Run
  `kbtool collaborate finish` first if the daemon still runs, since stopping
  the host's daemon finishes the session.

The target must be joined. Every relay host joined when the certificates
were issued is in the server certificate, so moving to one of them keeps
the session ID. For a relay joined later, kbtool issues new certificates and
a new session that sticks to it. Either way the daemon prints a new
enrollment line at its next start, and attendees re-enroll with it
(`kbtool collaborate resume <line>`).

`relay ls` lists the joined relays. It shows how each is verified, where the
next new session starts and which relay this host's session sticks to.

### Enabling, disabling and leaving

`relay disable` sets `"enabled": false` for all relays and keeps the list.
The machine then works without any relay connectivity, for example for code
search alone:

- `collaborate host` starts a local session: index, message board (the
  agent's own session memory) and a daemon on the unix socket only. There
  are no certificates and no enrollment line.
- A resumed session whose config still has a `relay_session` starts its
  daemon without a relay; the daemon logs that it serves locally only and
  prints no enrollment line. A running
  daemon keeps its relay connection until it stops.
- On a client, commands refuse a relay session and say to run
  `kbtool relay enable`.

`relay enable` turns relays back on. To open a local session to
collaborators, run `kbtool collaborate finish`, then
`kbtool collaborate resume`: resume sets up relay-mode mTLS and starts the
daemon, which picks a relay as above. The session keeps its board and
files. Both commands refuse without a `relay.json` (run `relay join` first)
and also work on a client.

`relay leave URL…` removes relays from the list, and warns when this host's
session sticks to one of them. `relay leave -all` deletes `relay.json`;
later sessions are local.

### Clients

A client needs no list. `kbtool collaborate attend kb1TOKEN` stores the relay named in the token in `client.json`
(`relay`), next to the session, and the client always uses it. It also
writes `relay.json` with `"enabled": true` if it was missing or disabled.

## Self-hosted relay: `relay self-host start|stop` (daemon host)

```
kbtool relay self-host start | stop
```

For collaboration on a LAN or through a VPN, the daemon can host its own
**personal relay**. It runs inside the daemon process, in memory only: there
is no relay pid file, log or control socket, and its CA lives in memory and is
replaced every 12h like a standalone relay's. The daemon starts it when it
starts and stops it when it stops.

- `relay self-host start` sets `"selfhost": true` in `relay.json` (creating
  the file with `"enabled": true` if needed). The first time, it draws a free
  port from 20000-32767 (above the common service ports, below every OS's
  ephemeral range) and a random registration token, and stores them as
  `selfhost_port` and `selfhost_token`. Both are kept for good: the relay
  always listens on that port, on all interfaces, and only this daemon knows
  the token, so the relay stays personal and enrolled attendees keep working
  across daemon restarts and `collaborate resume`. If the port is taken at a
  later start, the daemon logs an error and serves locally only; free the
  port, or set another `selfhost_port` and have the attendees enroll again.
- `relay self-host stop` clears `selfhost`; the port and token stay.
- Both tell a running daemon over its unix socket: `start` starts its relay
  (and, when the daemon's session uses it, prints the enrollment lines);
  `stop` stops it, and attendees of a self-hosted session cannot connect
  until it starts again. Without a running daemon they only change
  `relay.json`.
- Self-hosting needs relays enabled (`relay enable`).

While self-hosting is on:

- A relay session uses only the self-hosted relay. No joined relay is tried,
  and the session's `relay_url` is ignored and left as it is: nothing about
  the self-hosted relay is recorded in the session.
- `collaborate host` and `collaborate resume` add this machine's addresses
  to the server certificate: the default SANs (every interface address, the
  hostname and `host.docker.internal`) next to the joined relay hosts.
  `collaborate resume` issues new certificates when the old ones cover none of
  this machine's addresses (a session hosted on a remote relay); attendees
  then need the new enrollment line.
- The daemon prints one enrollment line per address the certificate covers,
  each ending in `# via HOST:PORT`. Send the one your collaborators can reach.
- `relay ls` and `kbtool status` say the session is on the self-hosted relay
  and name the remembered remote relay, if any.

With self-hosting off again, sessions use the joined relays as before: a
session that already stuck to a remote relay returns to it, and one created
while self-hosting (no `relay_url`) picks one round robin and sticks to it.
Picking a relay the certificates do not cover means new certificates (`relay
move`, `collaborate resume -relay`), so attendees enroll again.

## Certificates in relay mode

Sessions issue and renew their certificates themselves. When relays are
enabled and at least one is joined (or self-hosting is on), certificates are
issued by `collaborate host`; by `collaborate resume` when certificates
expired, a local session is opened to collaborators, or a self-hosting host
resumes a session hosted on a remote relay; and by `relay move` or
`collaborate resume -relay` when a session moves to a relay its certificates
do not cover. Each time kbtool:

- Issues a new CA, server and client certificate (lifetime `-expire`,
  default 24h). The server certificate's SANs are **every joined relay
  host** (IP or DNS name), because clients verify the host they dial. Only
  while self-hosting are this machine's addresses added (see above).
- `config.json`: `mtls: true`, `http` off, no `http_addr`, a new
  `relay_session`, and `relay_url` empty (the daemon picks the relay round
  robin) or set when renewing or moving (the session keeps or gets that
  relay). The message board is on unless `config.json` says
  `"message_board": false`.
- `relay-session.key` (mode 0600): the session's Ed25519 key. The daemon
  refuses to start in relay mode without it, or when `relay_session` does not
  match it and `ca.crt`; run `kbtool collaborate resume`.
- No `client.json` on the daemon host: its CLI always uses the unix socket
  (with TLS), never the relay.

Without an enabled relay (none joined and self-hosting off, or relays
disabled) a session is local and gets no certificates.

## Sessions

- The session ID is the first 128 bits of SHA-256 over a label, the session
  key's public key and the team CA's expiry, as 32 lowercase hex characters: a
  valid DNS label, so it can travel as SNI. It is created with the
  certificates (above) and stored as `relay_session`. Every daemon start and
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
  retrying and logs why. `kbtool collaborate finish && kbtool collaborate
  resume` issues a new CA and session.
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

- Relay mode is on when `config.json` has `relay_session` and relays are
  enabled. The relay is `relay_url` (sticky) or, for a new session, the
  first joined relay that accepts it (see
  [Round robin and sticky relays](#round-robin-and-sticky-relays)). Its
  token and trust come from its `relay.json` entry; the daemon refuses to
  start when `relay.json` is missing.
- Opens **no TCP port**, so nothing bypasses the relay.
- Sends its CA certificate in the TLS handshake (relay mode only), so the full
  chain is visible through the relay (plain HTTP cannot pass SNI routing).
- Logs and prints the enrollment line (`kbtool collaborate attend kb1…`; one
  per address of this machine with a self-hosted relay). `kbtool status`
  shows the session and its sticky relay.

## Clients

- `kbtool collaborate attend kb1TOKEN` opens TLS to the relay with SNI = session,
  downloads and decrypts the bundle with the token's key, then requires the
  daemon certificate on that connection to be valid for the relay host under
  the bundled CA. `client.json` keeps the session
  ID and that relay (`relay`); `relay.json` only gets `"enabled": true`.
- Later connections use SNI = session ID while still verifying the daemon
  certificate against the team CA for the relay host.

## Related

- Simple example: [relay-simple.md](relay-simple.md)
- Collaboration sessions: [collaborate.md](collaborate.md)
- Running the relay as a systemd service: [relay-systemd.md](relay-systemd.md)
- The session's daemon: [daemon.md](daemon.md)
- Config fields: [client-server-config.md](client-server-config.md)
- Cryptography and trust protocols: [cryptography.md](cryptography.md)
- Back to [README](../README.md)
