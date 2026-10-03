# kbtool query — snapshot additions

Applies to snapshot builds only (`make release-snapshot` or `go build`).

Everything else about `query` / `search` is in the release reference
([../query.md](../query.md)); this page covers only what snapshot builds add.

## Git history search

Git history is indexed only by `kbtool build -git` ([build.md](build.md)): up
to `-gitmaxcommits` recent commits per repo, as two extra chunk kinds that
`-kind` can filter on:

| Kind | Chunk path | Content |
|---|---|---|
| `commit` | `<label>/git/<sha7>` | The commit message (subject and body). |
| `diff` | `<label>/git/<sha7>/<file>` | The commit subject plus one file's hunk, capped globally at `-gitdiffmaxkb` KB. |

A session (`kbtool collaborate host`) never indexes git history, so in
release builds these kinds return nothing.

```sh
kbtool build -git /path/to/repoA
kbtool daemon start
kbtool query "why was this refactored" -kind commit
kbtool query "retry backoff" -kind diff -full -k 3
```

## Sessionless use

Outside a session, `query` goes through a daemon started with
`kbtool daemon start` ([daemon.md](daemon.md)) on an index written by
`kbtool build DIR…`, or through the `client.json` endpoint of a machine
enrolled with `kbtool client -import` ([client.md](client.md)).

## Related

- Benchmark search latency: [bench-simple.md](bench-simple.md)
- Release reference: [../query.md](../query.md)
- Back to [README](../../README.md)
