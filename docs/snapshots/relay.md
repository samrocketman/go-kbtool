# kbtool relay — snapshot builds

Applies to snapshot builds only (`make release-snapshot` or `go build`).
The relay service, joined relays, self-hosting and relay-mode sessions are
in [relay.md](../relay.md).

Snapshot builds can use relays without a collaboration session: issue the
PKI by hand with `kbtool mtls`, start the daemon with `kbtool daemon start`,
and enroll clients with `kbtool client -import kb1TOKEN`.

## Relay mode in `kbtool mtls`

When relays are enabled and at least one is joined, `kbtool mtls` issues the
same relay-mode certificates a session does
([relay.md](../relay.md#certificates-in-relay-mode)), and it is what
`collaborate host|resume` run underneath. In addition:

- Any `-ip`/`-dns` given are added to the server certificate's SANs; the
  default SANs are not used (except while self-hosting).
- Like `collaborate resume`, rerunning `mtls` issues a new CA and relay
  session (after expiry, or when `relay-session.key` does not match).
- Without an enabled, non-empty relay list, `kbtool mtls` sets up a direct
  daemon and turns relay mode off. After `relay disable`, `mtls` sets up
  direct mode; after `relay leave -all`, later sessions are local, or direct
  with `collaborate host -ip …` ([collaborate.md](collaborate.md)).

See [mtls.md](mtls.md) for the PKI itself.

## The daemon in relay mode

- `-http` on `daemon start`, or `http: true` in `config.json`, adds the
  usual HTTPS port (`:9876`) next to the relay. The daemon then logs and
  prints the relay import line first, then one line per server address.
- A relay service and a direct daemon in one state dir both listen on 9876
  by default, so give one of them another port (`relay run -bind`, or a
  daemon without `-http`).

## Clients

`kbtool client -import kb1TOKEN` enrolls through the relay exactly like
`kbtool collaborate attend kb1TOKEN`, without creating a session
([client.md](client.md)). It stores the relay named in the token in
`client.json` and writes `relay.json` with `"enabled": true` if it was
missing or disabled.

## Related

- Relays: [relay.md](../relay.md)
- PKI by hand: [mtls.md](mtls.md)
- Enrollment without a session: [client.md](client.md)
- Direct sessions: [collaborate.md](collaborate.md)
