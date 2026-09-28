# kbtool query — quick start

Search the index. `query` and `search` are the same command.

```sh
# Build first (once):
kbtool build -git /path/to/repoA

# Ask questions — hybrid (BM25 + vector) search by default:
kbtool query "how do we parse config"

# Exact-identifier style:
kbtool query "TokenBucketLimiter"

# Only code, full chunk text, 5 results:
kbtool query "retry backoff" -kind code -full -k 5
```

Output looks like:

```
1. repoA/pkg/config/parse.go:41-78 [code] score=0.6231
   func ParseConfig(r io.Reader) (*Config, error) { …
```

Notes:

- If the daemon is running, `query` goes through the daemon (same results,
  and message-board messages become searchable); otherwise it searches the
  db file directly.
- `-min` gates only the vector channel; the keyword channel is never gated by it.

Full reference with every option: [query.md](query.md) · back to [README](../README.md)
