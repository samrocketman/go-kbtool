# kbtool mtls — full reference

Generate the local mTLS PKI: an ECDSA P-256 CA plus server and client leaf
certificates, all under the state dir. This is the prerequisite for
`daemon start -http -mtls` (shared, authenticated network access).

```
kbtool mtls [-ip IP[,IP…]] [-dns NAME[,NAME…]] [-expire 24h] [IP-or-NAME …]
kbtool mtls -relay https://RELAY[:PORT]/ [-token T] [-relay-ca system|FILE] [-ip …] [-dns …] [-expire 24h]
```

With no SAN arguments (only `-expire`, or nothing), the server certificate
gets the **default SANs**:

- every IP address of the host's interfaces, loopback included, except
  link-local (`fe80::/10`, `169.254.0.0/16`), unspecified and multicast
  addresses, which cannot be dialed without an interface zone;
- the hostname as a DNS SAN (skipped with a warning if it is not a valid DNS
  name);
- `host.docker.internal`, so containers on the same machine can connect.

The chosen defaults are printed. Any `-ip`, `-dns` or bare SAN argument
replaces the defaults entirely.

## Options

| Option | Default | Description |
|---|---|---|
| `-ip LIST` | default SANs | IP SANs, comma-separated (IPv4/IPv6); repeatable, and bare IP tokens are accepted too (`-ip 10.0.0.1 10.0.0.2`). Entries must be valid IP addresses. |
| `-dns LIST` | default SANs | DNS SANs, comma-separated; repeatable, and bare name tokens are accepted. A bare token that parses as an IP is classified as an IP SAN. |
| `-expire D` | 24h | CA + server + client certificate validity (e.g. `24h`, `720h`). Must be > 0. |
| `-relay URL` | — | Relay mode ([relay.md](relay.md)): the server SAN is the relay host plus any `-ip`/`-dns` (no default SANs); `config.json` gets `relay_url`, a new `relay_session` (derived from a new `relay-session.key` and the CA's expiry), `http` off, `message_board` on; `client.json` points at the unix socket. |
| `-token T` | — | With `-relay`: the relay registration token, stored as `relay_token`. |
| `-relay-ca system\|FILE` | fetch `/ca.crt` | With `-relay`: verify the relay with the system roots or this PEM CA (host name checked), stored as `relay_ca`. |

**Nothing is silently dropped.** Flags may appear in any order; a name passed
where an IP is expected (or vice versa), an unknown flag, or a bad `-expire`
is a hard error. After generation the issued `server.crt` is **re-read and
verified to carry every requested SAN** — a PKI that drops a requested SAN is
never left on disk. (A silently missing IP SAN is exactly the “connects by DNS
but not by IP” failure.)

## Files written (state dir, `~/.config/kbtool`)

| File | Purpose | Mode |
|---|---|---|
| `ca.crt` / `ca.key` | Self-signed CA that vouches for server and clients. | 0644 / 0600 |
| `server.crt` / `server.key` | Daemon's TLS certificate, carrying the requested IP/DNS SANs. | 0644 / 0600 |
| `client.crt` / `client.key` | Client certificate for the local CLI (and handed to clients that enroll with the daemon). | 0644 / 0600 |

## Side effects

- `config.json`: `http: true`, `mtls: true`, cert file names, `crl_file:
  crl.pem`. Tool options and other fields are preserved (seed-or-preserve).
  **Bind address rule:** exactly one `-ip` and no `-dns` ⇒ bind that IP on
  port 9876; otherwise dual-stack `:9876` (so DNS-name clients with any
  resolution can reach the daemon).
- `client.json`: none on this host (a leftover one is removed); the host's
  CLI uses the daemon's unix socket over mTLS. `mtls` prints the remote client
  endpoints — every SAN, DNS names first, then IPs — one enrollment line each
  once the daemon runs.

## Multiple clients, one client certificate

Allowed by design, and the intended way to share access: TLS has no
per-certificate uniqueness, and the daemon enforces none. A dozen (or more)
clients may hold the **same** `client.crt`/`client.key` pair — e.g. everyone
enrolls with the same boot line — and connect concurrently. To cut that shared
identity off later, revoke it with the CRL file (`crl.pem`) — that revokes
**every** holder of the certificate (see [daemon.md](daemon.md)).

## Troubleshooting: connects by one name/IP but not another

TLS name verification requires the **dialed** address to appear in the server
certificate's SAN. In order of likelihood:

1. **The dialed IP/name is not in the SAN.** Check on the server:
   `openssl x509 -in <state>/server.crt -noout -ext subjectAltName`.
   Regenerate with it included (`kbtool mtls -ip 10.0.0.5,10.0.0.6 -dns kb.local`),
   re-start the daemon, and re-enroll the clients with its new boot line.
2. **The client is pointed elsewhere.** On the remote client, `client.json`
   `host`/`hosts` control where the CLI dials; `kbtool status` there shows the
   effective endpoint list.
3. The failure is now reported explicitly — e.g.
   `x509: certificate is valid for kb.local, not 10.0.0.5` — with a hint
   telling you exactly which of the above applies, instead of the old opaque
   "no daemon running".

## Notes

- Certificates are local-trust material: the CA signs both sides. Revocation
  is per-client via the CRL file (`<state>/crl.pem`, see
  [daemon.md](daemon.md)); a missing CRL means "no revocation data".
- `kbtool mtls` prints the CA fingerprint (SHA-256, 43-character base64url);
  `kbtool status` shows it too.
- To enroll another machine, run the daemon with `-http -mtls` and paste the
  `kbtool client -import …` line it prints at boot there
  ([client-simple.md](client-simple.md)). The port then also answers plain
  HTTP `GET /ca.crt` and certificate-less TLS `GET /bundle/<id>`; every API
  route still requires a client certificate.
- Without `-relay`, `kbtool mtls` clears `relay_url`, `relay_session` and
  `relay_ca` and deletes `relay-session.key` (relay mode off).
- Re-running `kbtool mtls` regenerates **all** keys; previously enrolled
  clients stop validating (new CA) and must enroll again. Plan accordingly.

## Related

- Simple example: [mtls-simple.md](mtls-simple.md)
- Serving with it: [daemon.md](daemon.md)
- Sharing the client side: [client.md](client.md)
- Daemon behind NAT: [relay.md](relay.md)
- All config files: [client-server-config.md](client-server-config.md)
- Cryptography and trust protocols: [cryptography.md](cryptography.md)
- Back to [README](../README.md)
