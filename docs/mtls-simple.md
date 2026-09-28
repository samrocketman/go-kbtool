# kbtool mtls — quick start

Generate the local mTLS PKI (CA + server + client certificates) so the daemon
can be shared over the network with mutual TLS, and point the local CLI at
the new setup.

```sh
# By DNS name (portable to other machines that resolve it):
kbtool mtls -dns kb.example.net

# …or by IP (e.g. a private LAN address):
kbtool mtls -ip 10.0.0.5

# Long-lived certs:
kbtool mtls -dns kb.example.net -expire 720h

# Now serve with it:
kbtool daemon start -http -mtls
```

What it does:

- Writes `ca.crt`, `ca.key`, `server.crt`, `server.key`, `client.crt`,
  `client.key` under the state dir (`~/.config/kbtool`).
- Records `http: true`, `mtls: true` (and the bind address for a single `-ip`)
  in `config.json`.
- Writes `client.json`, so the local CLI immediately uses the mTLS endpoint.
- Share the client side with a friend via
  `kbtool client -export` — see [client-simple.md](client-simple.md).

Full reference: [mtls.md](mtls.md) · back to [README](../README.md)
