# kbtool mtls — quick start

Generate the local mTLS PKI (CA + server + client certificates) so the daemon
can be shared over the network with mutual TLS, and point the local CLI at
the new setup.

```sh
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
```

Many clients may share one client certificate (e.g. a dozen friends importing
one `kbtool client -export` bundle) — that is allowed by design; revoke it via
the CRL if you need to cut them all off.

What it does:

- Writes `ca.crt`, `ca.key`, `server.crt`, `server.key`, `client.crt`,
  `client.key` under the state dir (`~/.config/kbtool`).
- Records `http: true`, `mtls: true` (and the bind address for a single `-ip`)
  in `config.json`.
- Writes `client.json`, so the local CLI immediately uses the mTLS endpoint.
- Share the client side with a friend via
  `kbtool client -export` — see [client-simple.md](client-simple.md).

Full reference: [mtls.md](mtls.md) · back to [README](../README.md)
