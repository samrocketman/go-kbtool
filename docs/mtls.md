# kbtool mtls — full reference

Generate the local mTLS PKI: an ECDSA P-256 CA plus server and client leaf
certificates, all under the state dir. This is the prerequisite for
`daemon start -http -mtls` (shared, authenticated network access).

```
kbtool mtls -ip 10.0.0.5 [-dns kb.local] [-expire 24h]
```

At least one of `-ip` / `-dns` is required.

## Options

| Option | Default | Description |
|---|---|---|
| `-ip LIST` | — | Comma-separated IP SANs (IPv4/IPv6). |
| `-dns LIST` | — | Comma-separated DNS SANs. |
| `-expire D` | 24h | CA + server + client certificate validity (e.g. `24h`, `720h`). Must be > 0. |

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
  setup) — `host` = first DNS name, else the single bound IP; `port: 9876`,
  `tls: true`, cert names. The local CLI now speaks mTLS.

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
