# kbtool collaborate — snapshot builds

Applies to snapshot builds only (`make release-snapshot` or `go build`).
Everything else about sessions is in [collaborate.md](../collaborate.md).

Snapshot builds add **direct sessions**: no relay, the daemon serves mTLS on
all interfaces (port 9876) and collaborators connect to it directly.

```
kbtool collaborate host … [-ip IP,…] [-dns NAME,…]
kbtool collaborate attend [-yes] https://HOST:PORT/ kb1TOKEN
kbtool collaborate resume … https://HOST:PORT/ kb1TOKEN
```

## `collaborate host -ip/-dns`

| Option | Default | Description |
|---|---|---|
| `-ip LIST`, `-dns LIST` | — | Server certificate SANs ([mtls.md](mtls.md)); with a relay, extra SANs next to the relay host. Without a relay they make the session direct instead of local. |

The network step of `collaborate host` gains one more case:

- **direct**: no enabled relay but `-ip`/`-dns` given: mTLS with `http`
  on (all interfaces, port 9876).

The daemon then prints one enrollment line per server address,
`kbtool collaborate attend https://HOST:PORT/ kb1TOKEN`.

## `collaborate attend` and `resume` with a direct line

`attend` takes the daemon URL followed by a direct token as well as a relay
token, and enrolls exactly like `kbtool client -import`
([client.md](client.md)); a relay token also writes `relay.json`.

`resume` accepts `https://HOST:PORT/ kb1TOKEN` as the new enrollment line of
an attendee after the host renewed its certificates. On the host, renewal of
expiring certificates reuses the session's original `-ip`/`-dns`/`-expire`.

`relay leave -all` leaves later sessions local, or direct with
`collaborate host -ip …`.

## Other snapshot-only details

- In an encrypted state dir, `kbtool build` without a daemon and
  `kbtool daemon start` also fail without a key.
- `collaborate finish` also stops the socket MCP service (`kbtool mcp start`),
  if running.

## Related

- Sessions: [collaborate.md](../collaborate.md)
- PKI by hand: [mtls.md](mtls.md)
- Enrollment without a session: [client.md](client.md)
