# kbtool client — quick start

Move a working mTLS client setup between machines as an encrypted bundle.

**Server host — export:**

```sh
kbtool mtls -dns kb.example.net          # first, if not done
kbtool client -export /tmp/kbtool.kbx -key 'the-passphrase'
# send /tmp/kbtool.kbx + the passphrase to the other machine
```

**Other machine — import:**

```sh
kbtool client -import /tmp/kbtool.kbx -key 'the-passphrase' -yes
kbtool status                            # now shows the mTLS endpoint
kbtool query "how do we parse config"    # routed over mTLS to the daemon
```

The bundle contains `ca.crt`, `client.crt`, `client.key`, `client.json` —
everything the local CLI needs to authenticate to the daemon.

Full reference: [client.md](client.md) · back to [README](../README.md)
