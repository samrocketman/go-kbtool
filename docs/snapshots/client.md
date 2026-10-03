# kbtool client — full reference

Applies to snapshot builds only (`make release-snapshot` or `go build`); release builds refuse this command.

Enroll this machine with an mTLS daemon in one line. The daemon prints the
line at boot; the client downloads an encrypted client bundle, checks the
daemon against the CA inside it, and from then on talks to the daemon over
mTLS.

```
kbtool client -import https://HOST:PORT/ kb1TOKEN [-yes]     direct daemon
kbtool client -import kb1TOKEN [-yes]                        daemon behind a relay
```

Both forms come ready to paste from the daemon's boot output: one
`kbtool client -import …` command per server address, in the daemon log
(mode 0600) and, with `kbtool daemon start -http -mtls`, on the console. For a
direct daemon every line carries the same token behind a different readable
URL: pick the address the client can reach. A daemon behind a relay prints one
line whose token already names the relay.

## Options

| Option | Default | Description |
|---|---|---|
| `-import URL TOKEN` | — | The daemon URL, `https://HOST[:PORT][/]` only (port defaults to 9876), followed by its direct token. |
| `-import TOKEN` | — | A relay token alone: relay host, port and session are inside it ([relay.md](../relay.md)). |
| `-yes` | off | Replace existing client files in the state dir that differ from the bundle. |

The long forms (`-bundle`, `-fingerprint`, `-key`, `-session`) and file
import are gone.

## The token

`kb1` followed by unpadded base64url of a small binary record:

| Field | Size | Present |
|---|---|---|
| flags | 1 byte | always: host kind (none, IPv4, IPv6, DNS name), port present, session present |
| relay host | 4, 16, or 1 + name length bytes | relay tokens |
| relay port | 2 bytes, big-endian | relay tokens whose port is not 9876 |
| relay session | 16 bytes | relay tokens |
| bundle key | 16 bytes | always |

A direct token is 26 characters; a relay token for `relay.example.net` on the
default port is 71. The token is checked strictly before any network traffic
(unknown flags, wrong lengths, bad host names, port 0 and trailing bytes are
refused). The bundle ID is derived from the key (HMAC-SHA256), and no CA
fingerprint is carried: the encrypted bundle authenticates the CA.

## What happens

1. **Bundle.** Over TLS, without a client certificate and without trusting
   the server yet, the client downloads `https://HOST:PORT/bundle/ID`, with ID
   derived from the key. An unknown ID gets 404, usually because the daemon
   was restarted: copy the current line.
2. **Decrypt.** The bundle (KBX1: PBKDF2-HMAC-SHA256 with 600,000 iterations
   + AES-256-GCM over a tar.gz) is decrypted with the token's key in memory.
   The client pays the 600,000 iterations once. The daemon derives the key
   once at boot and keeps it in memory, so serving a bundle costs it no
   PBKDF2; each response still uses a fresh nonce. All four members must be
   present.
3. **Check the server.** The certificate the server presented on that same
   connection must be valid for the host under the bundled `ca.crt`;
   otherwise the import stops before writing anything.
4. **Install.** The files are written to the state dir (`client.key` at
   0600). Identical existing files are left alone; differing ones are only
   replaced with `-yes`. `client.json` is written to reach the daemon at the
   imported host and port. The state dir must not belong to a daemon host
   (no `config.json`, server or CA key, or socket); enroll from another one.
5. **Confirm.** One mTLS `GET /healthz` with the new certificate; the command
   fails if it does not succeed.

**Through a relay (relay token):** the client opens TLS to the relay with
SNI = session; the relay splices it to the daemon without terminating it.
The same steps run through the relay, the server certificate is checked for
the relay host. `client.json` records the `session` and that relay
(`relay`, the client's only relay), and `relay.json` gets `"enabled": true`
(any joined relays in it are kept).

## Bundle contents

| Member | Purpose |
|---|---|
| `ca.crt` | CA the client trusts (vouches for the daemon). |
| `client.crt` / `client.key` | The client certificate/key to present at the mTLS handshake. |
| `client.json` | Endpoint config; rewritten on import to the imported host and port (relay token: only the session), `tls: true`. |

## Security notes

- The key (128 bits) is what protects the bundle. Only the real daemon can
  produce a bundle that decrypts under it, so the CA inside is authentic,
  and an interceptor that relays the real bundle under its own certificate
  fails step 3.
- The bundle ID only keeps the bundle from being found by scanning; deriving
  it from the key reveals nothing about the key.
- The line is a credential: anyone who has it and can reach the port can
  enroll. It stays valid until the daemon stops; restarting the daemon issues
  a new key (and so a new token).
- **Many clients, one identity:** all enrolled clients share the server's
  client certificate by design. To cut them off, revoke the certificate in
  the server's CRL (`crl.pem`) and re-run `kbtool mtls`.

## Related

- Simple example: [client-simple.md](client-simple.md)
- Creating the PKI first: [mtls-simple.md](mtls-simple.md)
- Daemon options: [daemon.md](daemon.md)
- Enrolling through a relay: [relay.md](../relay.md)
- Endpoint config file reference: [client-server-config.md](../client-server-config.md)
- Back to [README](../../README.md)
