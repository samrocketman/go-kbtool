# kbtool build — quick start

Reindex the session's sources after the code changed. Only the session host
runs it; the running daemon serves the new index at once, no restart.

```sh
# The session indexes the working directory when it starts:
kbtool collaborate host

# …later, after pulling or editing code:
kbtool build
```

Typical output:

```
built 1 source(s): 1842 chunks -> swapped into the running daemon (unix /home/you/.config/kbtool/daemon.sock, plain); no restart needed
```

Now try it:

```sh
kbtool query "how do we parse config"
kbtool status
```

Notes:

- `kbtool build` takes no sources and no options: it rebuilds what
  `kbtool collaborate host` indexed, with the same options.
- With the message board on, each build posts a short summary (sources by
  name, git commit, clean or dirty) in the board's `system` thread.
- In an encrypted state dir the running daemon holds the key, so `build`
  needs none.
- Indexing is local: no network calls, no external embedding service.

Full reference: [build.md](build.md) · back to [README](../README.md)
