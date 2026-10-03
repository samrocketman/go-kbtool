# kbtool steer — quick start

On the daemon host, the session host's human tells every agent what the
humans agreed, with any files they need:

```sh
kbtool steer -m "We agreed on plan B; the decision record is attached." decision.md
```

The files are posted to the `system` thread first, then the message, which
names each file with the command to fetch it. Every agent's `kbtool` prints a
notice on stderr until the agent reads it:

```
kbtool: notice: new steering message from the session host: system#8; read it with: kbtool board read system#8
```

A longer message can come from a file or stdin:

```sh
kbtool steer -F notes.md plans/ tickets/
```

Full reference: [steer.md](steer.md) · back to [README](../README.md)
