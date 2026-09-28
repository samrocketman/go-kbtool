# kbtool client — full reference

Export or import the local mTLS client setup as a passphrase-encrypted
bundle (KBX1: PBKDF2-HMAC-SHA256 + AES-256-GCM over a tar.gz).

```
kbtool client -export [file] -key PASS
kbtool client -import file -key PASS [-yes]
```

Provide **exactly one** of `-export` / `-import`; `-key` is always required.

## Options

| Option | Default | Description |
|---|---|---|
| `-export [file]` | `<state>/kbtool-client.kbx` | Export the client setup as an encrypted bundle; optional value = output file. Requires the certs to exist (`kbtool mtls` first). A missing `client.json` is synthesized (local socket + default mTLS names). |
| `-import file` | — | Decrypt the bundle and extract it into the state dir. |
| `-key PASS` | — (required) | Bundle passphrase. |
| `-yes` | off | `-import`: overwrite existing files in the state dir (without it, an existing file is never clobbered). |

## Bundle contents

| Member | Purpose |
|---|---|
| `ca.crt` | CA the client trusts (vouches for the daemon). |
| `client.crt` / `client.key` | The client certificate/key to present at the mTLS handshake. |
| `client.json` | Endpoint config: `host:port` (or `unix_socket`), `tls`, cert names. |

## Behavior

- **Export** reads the files from the state dir, packs them (sorted, tar.gz),
  encrypts, and writes atomically with mode 0600.
- **Import** decrypts (wrong passphrase fails with a clear error), extracts
  only the four whitelisted members (path-traversal safe), and refuses to
  overwrite existing files unless `-yes`.
- After import, the local CLI (`query`, `call`, `status`, …) automatically
  uses the imported `client.json` — no other setup needed.
- The passphrase travels **out-of-band** (it is not in the bundle). Treat the
  bundle + passphrase together as secret: possession of both equals a valid
  client identity.

## Related

- Simple example: [client-simple.md](client-simple.md)
- Creating the PKI first: [mtls-simple.md](mtls-simple.md)
- Endpoint config file reference: [client-server-config.md](client-server-config.md)
- Back to [README](../README.md)
