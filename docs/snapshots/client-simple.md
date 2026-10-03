# kbtool client — quick start

Applies to snapshot builds only (`make release-snapshot` or `go build`); release builds refuse this command.

Enroll another machine with an mTLS daemon in one line.

**Server host:**

```sh
kbtool mtls -dns kb.example.net          # first, if not done
kbtool daemon start -http -mtls
# prints, among other lines:
#   enroll a client with one of:
#     kbtool client -import https://kb.example.net:9876/ kb1…
```

**Other machine — paste that line:**

```sh
kbtool client -import https://kb.example.net:9876/ kb1AJ2gMRkuJr1FmCx8tX0gkRg
kbtool status                            # now shows the mTLS endpoint
kbtool query "how do we parse config"    # routed over mTLS to the daemon
```

The `kb1…` token carries the bundle key. The client downloads the encrypted
bundle (`ca.crt`, `client.crt`, `client.key`, `client.json`) over TLS,
decrypts it with the key, checks the daemon against the bundled CA, and
confirms an mTLS connection. The line is valid until the daemon restarts.

Daemon behind NAT? Through a relay the line is just `kbtool client -import
kb1…`, with the relay address baked into the token (the import records it in
`client.json`); see [relay-simple.md](../relay-simple.md).

For a collaboration session use `kbtool collaborate attend` with the same
arguments: it also sets up the session directory and AGENTS_COLLABORATION.md
([collaborate-simple.md](../collaborate-simple.md)).

Full reference: [client.md](client.md) · back to [README](../../README.md)
