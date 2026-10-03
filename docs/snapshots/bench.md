# kbtool bench — full reference

Applies to snapshot builds only (`make release-snapshot` or `go build`); release builds refuse this command.

In-process query benchmark: load the db once, then run N deterministic
synthetic queries (1–3 real identifier tokens drawn from the corpus) and
report min/p50/p95/max latency. This is the honest way to measure pure query
cost (no process spawn, no socket, no DB reload).

**Pre-release builds only.** `bench` is a development tool. Snapshot builds
(`make release-snapshot`) and `go build` include it; release binaries refuse
it and leave it out of `kbtool help`.

```
kbtool bench -db PATH [-n N] [-mode M] [-k N] [-seed S]
             [-db-key-env NAME | -db-key-file PATH]
```

## Options

| Option | Default | Description |
|---|---|---|
| `-db PATH` | config db, else `<state>/kb.db` | Db file to load. |
| `-n N` | 100 | Number of queries to run. |
| `-mode M` | `hybrid` | Search mode: `hybrid` \| `vector` \| `keyword` \| `weighted`. |
| `-k N` | 8 | Results per query. |
| `-seed S` | 42 | RNG seed for the synthetic query pool (deterministic — same seed ⇒ same pool). |
| `-db-key-env NAME` | — | DB-at-rest key from `$NAME` (encrypted stores). |
| `-db-key-file PATH` | — | DB-at-rest key from file `PATH` (encrypted stores). |

## Behavior

- The db must exist and contain chunks (`kbtool build` first).
- A one-time warmup query is run (first query pays one-time allocations) and
  is not counted.
- The pool holds up to 64 unique queries and is cycled over `-n` runs.
- Output: `bench: <n> queries, mode=<mode>, chunks=<n>, terms=<kw terms>`
  followed by `min=… p50=… p95=… max=…`.

## Examples

```sh
kbtool bench
kbtool bench -n 1000 -mode weighted
kbtool bench -seed 7 -k 16
```

## Related

- Simple example: [bench-simple.md](bench-simple.md)
- Search modes in detail: [query.md](../query.md)
- Back to [README](../../README.md)
