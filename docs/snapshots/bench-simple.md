# kbtool bench — quick start

Applies to snapshot builds only (`make release-snapshot` or `go build`); release builds refuse this command.

Run a deterministic in-process query benchmark against an existing index and
report min/p50/p95/max latency.

**Pre-release builds only.** `bench` is a development tool. Snapshot builds
(`make release-snapshot`) and `go build` include it; release binaries refuse
it and leave it out of `kbtool help`.

```sh
# After building:
kbtool bench

# 500 queries, keyword-only mode:
kbtool bench -n 500 -mode keyword
```

Output:

```
bench: 100 queries, mode=hybrid, chunks=1842, terms=4123
  min=842.1µs p50=1.12ms p95=2.4ms max=3.9ms
```

Notes:

- This measures pure query cost — no process spawn, no socket, no DB reload.
- The query pool is derived from real identifier tokens in your corpus and is
  deterministic for a given `-seed`.

Full reference with every option: [bench.md](bench.md) · back to [README](../../README.md)
