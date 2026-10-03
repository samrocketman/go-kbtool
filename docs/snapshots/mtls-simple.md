# kbtool mtls — quick start

Applies to snapshot builds only (`make release-snapshot` or `go build`); release builds refuse this command.

Generate the local mTLS PKI (CA + server + client certificates) so the daemon
can be shared over the network with mutual TLS, and point the local CLI at
the new setup.

```sh
# Defaults: every interface IP (not link-local), the hostname, and
# host.docker.internal:
kbtool mtls

# By DNS name (portable to other machines that resolve it):
kbtool mtls -dns kb.example.net

# …or by IP (e.g. a private LAN address):
kbtool mtls -ip 10.0.0.5

# Multi-interface server: every address clients may dial goes into the SAN
# (comma- or space-separated; flags in any order; nothing is silently dropped):
kbtool mtls -ip 10.0.0.5,192.168.1.20 -dns kb.example.net

# Long-lived certs:
kbtool mtls -dns kb.example.net -expire 720h

# Now serve with it:
kbtool daemon start -http -mtls

# Daemon behind NAT: join a relay first; mtls then issues relay-mode
# certificates (see relay-simple.md):
kbtool relay join https://relay.example.net:9876/
kbtool mtls
```

Many clients may share one client certificate (e.g. a dozen friends importing
with the same `kbtool client -import` line) — that is allowed by design; revoke it via
the CRL if you need to cut them all off.

What it does:

- Writes `ca.crt`, `ca.key`, `server.crt`, `server.key`, `client.crt`,
  `client.key` under the state dir (`~/.config/kbtool`).
- Records `http: true`, `mtls: true` (and the bind address for a single `-ip`)
  in `config.json`.
- Writes no `client.json`: this host's CLI keeps using the daemon's unix
  socket (over mTLS). It prints the endpoints remote clients will reach.
- Prints the CA fingerprint. Once the daemon runs with `-http -mtls`, it
  prints a one-line `kbtool client -import …` for other machines — see
  [client-simple.md](client-simple.md).

Full reference: [mtls.md](mtls.md) · back to [README](../../README.md)
