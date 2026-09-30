# kbtool mtls — full reference

Generate the local mTLS PKI: an ECDSA P-256 CA plus server and client leaf
certificates, all under the state dir. This is the prerequisite for
`daemon start -http -mtls` (shared, authenticated network access).

```
kbtool mtls [-ip IP[,IP…]] [-dns NAME[,NAME…]] [-expire 24h] [IP-or-NAME …]
```

At least one of `-ip` / `-dns` (or a bare IP/DNS argument) is required.

## Options

| Option | Default | Description |
|---|---|---|
| `-ip LIST` | — | IP SANs, comma-separated (IPv4/IPv6); repeatable, and bare IP tokens are accepted too (`-ip 10.0.0.1 10.0.0.2`). Entries must be valid IP addresses. |
| `-dns LIST` | — | DNS SANs, comma-separated; repeatable, and bare name tokens are accepted. A bare token that parses as an IP is classified as an IP SAN. |
| `-expire D` | 24h | CA + server + client certificate validity (e.g. `24h`, `720h`). Must be > 0. |

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
| `client.crt` / `client.key` | Client certificate for the local CLI (and exportable to others). | 0644 / 0600 |

## Side effects

- `config.json`: `http: true`, `mtls: true`, cert file names, `crl_file:
  crl.pem`. Tool options and other fields are preserved (seed-or-preserve).
  **Bind address rule:** exactly one `-ip` and no `-dns` ⇒ bind that IP on
  port 9876; otherwise dual-stack `:9876` (so DNS-name clients with any
  resolution can reach the daemon).
- `client.json`: **always** rewritten (a fresh PKI invalidates the old client
  setup) — `host` = first DNS name (portable for import on another machine),
  else the first IP (never empty); **`hosts` = every SAN endpoint in order**
  (DNS names first, then IPs) — the client tries them in order, so a
  multi-interface server is reachable by each of its addresses (first live one
  wins); `port: 9876`, `tls: true`, cert names. The local CLI now speaks mTLS.

## Multiple clients, one client certificate

Allowed by design, and the intended way to share access: TLS has no
per-certificate uniqueness, and the daemon enforces none. A dozen (or more)
clients may hold the **same** `client.crt`/`client.key` pair — e.g. everyone
imports one exported bundle — and connect concurrently. To cut that shared
identity off later, revoke it with the CRL file (`crl.pem`) — that revokes
**every** holder of the certificate (see [daemon.md](daemon.md)).

## Troubleshooting: connects by one name/IP but not another

TLS name verification requires the **dialed** address to appear in the server
certificate's SAN. In order of likelihood:

1. **The dialed IP/name is not in the SAN.** Check on the server:
   `openssl x509 -in <state>/server.crt -noout -ext subjectAltName`.
   Regenerate with it included (`kbtool mtls -ip 10.0.0.5,10.0.0.6 -dns kb.local`),
   re-start the daemon, and re-export the client bundle for the clients.
2. **The client is pointed elsewhere.** `client.json` `host`/`hosts` control
   where the CLI dials; `kbtool status` shows the effective endpoint list.
3. The failure is now reported explicitly — e.g.
   `x509: certificate is valid for kb.local, not 10.0.0.5` — with a hint
   telling you exactly which of the above applies, instead of the old opaque
   "no daemon running".

## Notes

- Certificates are local-trust material: the CA signs both sides. Revocation
  is per-client via the CRL file (`<state>/crl.pem`, see
  [daemon.md](daemon.md)); a missing CRL means "no revocation data".
- To hand the client setup to another machine, use
  [client -export](client-simple.md) — the bundle carries `ca.crt`,
  `client.crt`, `client.key`, `client.json`.
- Re-running `kbtool mtls` regenerates **all** keys; previously exported
  client bundles stop validating (new CA). Plan accordingly.

## Related

- Simple example: [mtls-simple.md](mtls-simple.md)
- Serving with it: [daemon.md](daemon.md)
- Sharing the client side: [client.md](client.md)
- All config files: [client-server-config.md](client-server-config.md)
- Back to [README](../README.md)
