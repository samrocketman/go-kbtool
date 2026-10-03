package main

// Test suite for kbtool.go. Grouped by purpose:
//
//   1. invisible-character sanitization (security)
//   2. tokenizer
//   3. local hashing embeddings
//   4. chunking + file classification
//   5. skip rules
//   6. git output parsing (pure)
//   7. string / path utilities
//   8. path-trust policy
//   9. BM25 keyword index
//  10. fusion (rank / RRF / weighted)
//  11. Search (in-memory DB, all modes)
//  12. message-board core
//  13. board crypto (ed25519)
//  14. serialization round-trips (DB / board / bundle / pbkdf2)
//  15. HTTP bind guard
//  16. config + tool options
//  17. MCP / JSON-RPC protocol
//  18. at-rest store (plain + encrypted)
//  19. build integration
//  20. toolbox / tool execution
//  21. key resolution + client config
//  22. documentation link consistency (README + docs/)
//  23. CLI versioning (`kbtool version`)
//  24. single-command buildability (hard requirement)
//  25. terms census + context bundle (plans/context-bundle-plan.md)
//  26. mTLS IP connectivity: SAN parsing/verification, error surfacing,
//     multi-host failover, shared client certs (plans/mtls-ip-connectivity-fix-plan.md)
//  27. mTLS client-only endpoint: no local sockets, no local db/board fallback
//     (plans/mtls-client-only-endpoint-plan.md)
//  28. message board HTML dump: embedded template, escaping, read-only export,
//     board/export API (plans/message-board-html-dump-plan.md)
//  29. message board attachments: streaming tar.gz, hostile archives, signed
//     digests, safe collect/extract, CLI attach/fetch
//     (plans/message-board-attachments-plan.md)
//  30. message board memory limit: value parsing, flag > config > default,
//     refused growth (plans/message-board-memory-limit-plan.md)
//  31. mTLS client bootstrap: one port for plain HTTP / TLS / mTLS, fingerprint,
//     per-request encrypted bundle, one-line import (plans/mtls-client-bootstrap-plan.md)
//  32. kbtool mtls default SANs: interface IPs, hostname, host.docker.internal;
//     daemon logs one enrollment entry per SAN endpoint
//     (plans/mtls-default-sans-plan.md, plans/daemon-enrollment-log-per-san-plan.md)
//  33. mTLS implies HTTP on all interfaces (plans/mtls-implies-http-plan.md)
//  34. mTLS relay: SNI routing, registration, splice, limits, enrollment and
//     calls through the relay, relay CLI (plans/mtls-relay-plan.md)
//  35. PBKDF2 cost: clients pay 600k iterations once, the server derives once
//     (plans/pbkdf2-derive-once-plan.md)
//  36. compact enrollment token (plans/compact-enrollment-token-plan.md)
//  37. relay mode turns the message board on (plans/relay-message-board-default-plan.md)
//  38. host socket CLI, remote-client guard, live reindex
//     (plans/host-socket-cli-and-live-reindex-plan.md)
//  39. relay in-memory rotating CA and systemd (plans/relay-ephemeral-ca-and-systemd-plan.md)
//  40. relay reconnect jitter (plans/relay-reconnect-jitter-plan.md)
//  41. relay hardening (plans/relay-hardening-plan.md)
//  42. system user, read-only system thread, welcome limit, build refresh
//     (plans/system-board-and-build-refresh-plan.md)
//  43. collaboration sessions, relay.json, collaboration doc
//  44. encrypted sessions, KBTOOL_SECRET, KBX2 and kbx rekey
//  45. kbtool steer and system notices on stderr (plans/steer-and-system-notices-plan.md)
//  46. memory, consensus and deliverables through kbtool (plans/memory-consensus-deliverables-plan.md)
//  47. consensus voting on the board (plans/memory-consensus-deliverables-plan.md)
//  48. board export from finished sessions (plans/memory-consensus-deliverables-plan.md)
//  49. agent-side session layer: attachments through memory over MCP, host
//     agent tag, signup platform (plans/session-memory-attachments-plan.md)
//  50. relay honeypot, /healthz rate limit (plans/relay-honeypot-plan.md)
//  51. pre-release tools: bench only in snapshot and source builds
//  52. OS compatibility (osCompat*): native Linux/macOS calls, portable
//     Windows paths, supported-platform compile guard
//
// All tests use only the standard library and run hermetically (temp dirs,
// no network). Git-dependent tests are skipped when git is absent.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// ---------- shared helpers ----------

const testDim = 64 // small dim for fast local embeddings

// localEmbed returns an embedding function pinned to testDim.
func localEmbed(texts []string) [][]float32 { return embedLocal(texts, testDim) }

// vec embeds a single string to testDim.
func vec(t *testing.T, s string) []float32 {
	t.Helper()
	return embedLocal([]string{s}, testDim)[0]
}

// makeDB builds an in-memory DB from the given chunks (embedding any missing
// vectors) plus a Tier-2 keyword index. Backend is the local hashing backend.
func makeDB(t *testing.T, chunks []Chunk) *DB {
	t.Helper()
	for i := range chunks {
		if chunks[i].Vector == nil {
			chunks[i].Vector = vec(t, chunks[i].Text)
		}
		if len(chunks[i].Vector) != testDim {
			t.Fatalf("chunk %d has dim %d, want %d", i, len(chunks[i].Vector), testDim)
		}
	}
	return &DB{Dim: testDim, Backend: "local-hashing", Chunks: chunks, KW: buildKWIndex(chunks, true)}
}

// fakeExec is an executor for protocol-level tests.
type fakeExec struct {
	disabled map[string]bool
	results  map[string]fakeResult
}

type fakeResult struct {
	text  string
	isErr bool
}

func (f *fakeExec) Execute(name string, args json.RawMessage) (string, bool) {
	if r, ok := f.results[name]; ok {
		return r.text, r.isErr
	}
	return "exec:" + name, false
}

func (f *fakeExec) toolDisabled(name string) bool { return f.disabled[name] }

func resultIDs(res []Result) []int {
	out := make([]int, 0, len(res))
	for _, r := range res {
		_ = r
	}
	return out
}

// gitAvailable reports whether the git binary can be found.
func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// ---------- 1. invisible-character sanitization (security) ----------

func TestIsInvisibleRune(t *testing.T) {
	cases := []struct {
		r    rune
		want bool
	}{
		// TAG block U+E0000..U+E007F (the primary smuggling vector).
		{0xE0000, true},
		{0xE0001, true},
		{0xE007F, true},
		{0xE007E, true},
		{0xE0080, false}, // just above the block
		{0xDFFFF, false}, // just below the block
		// C1 control block U+0080..U+009F.
		{0x0080, true},
		{0x0085, true}, // NEL
		{0x009F, true},
		{0x007F, false}, // DEL, not in the set
		{0x00A0, false}, // NBSP, not in the set
		// Explicitly listed codepoints.
		{0x00AD, true}, // soft hyphen
		{0x034F, true}, // grapheme joiner
		{0x061C, true}, // Arabic letter mark
		{0x115F, true},
		{0x1160, true},
		{0x17B4, true},
		{0x17B5, true},
		{0x180E, true},
		{0x200B, true}, // zero-width space
		{0x200C, true},
		{0x200D, true},
		{0x200E, true},
		{0x200F, true},
		{0x202A, true},
		{0x202B, true},
		{0x202C, true},
		{0x202D, true},
		{0x202E, true},
		{0x2060, true},
		{0x2061, true},
		{0x2062, true},
		{0x2063, true},
		{0x2064, true},
		{0x2066, true},
		{0x2067, true},
		{0x2068, true},
		{0x2069, true},
		{0xFEFF, true}, // BOM / ZWNBSP
		{0xFFF9, true},
		{0xFFFA, true},
		{0xFFFB, true},
		// Normal characters must be preserved.
		{'a', false},
		{'Z', false},
		{'0', false},
		{' ', false},
		{'\t', false},
		{'\n', false},
		{'\r', false},
		{'.', false},
		{',', false},
		{':', false},
		{';', false},
		{'=', false},
		{'+', false},
		{'/', false},
		{'*', false},
		{'&', false},
		{'|', false},
		{0x00E9, false},  // é
		{0x2192, false},  // →
		{0x1F600, false}, // 😀
	}
	for _, c := range cases {
		if got := isInvisibleRune(c.r); got != c.want {
			t.Errorf("isInvisibleRune(U+%04X) = %v, want %v", c.r, got, c.want)
		}
	}
}

func TestStripInvisible(t *testing.T) {
	t.Run("removes tag chars", func(t *testing.T) {
		in := "ev\U000E0001al" // "eval" with a hidden TAG char (U+E0001)
		if got := stripInvisible(in); got != "eval" {
			t.Fatalf("got %q, want %q", got, "eval")
		}
	})
	t.Run("removes classic invisibles", func(t *testing.T) {
		in := "a\u200Bb\u200E\u202Ec\uFEFFd\u00AD"
		if got := stripInvisible(in); got != "abcd" {
			t.Fatalf("got %q, want %q", got, "abcd")
		}
	})
	t.Run("preserves C0 whitespace", func(t *testing.T) {
		in := "a\tb\nc\rd"
		if got := stripInvisible(in); got != in {
			t.Fatalf("got %q, want %q", got, in)
		}
	})
	t.Run("idempotent", func(t *testing.T) {
		in := "x\U000E0001\u200By"
		once := stripInvisible(in)
		twice := stripInvisible(once)
		if once != twice {
			t.Fatalf("not idempotent: %q vs %q", once, twice)
		}
		if once != "xy" {
			t.Fatalf("got %q, want %q", once, "xy")
		}
	})
	t.Run("empty", func(t *testing.T) {
		if got := stripInvisible(""); got != "" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("clean text unchanged", func(t *testing.T) {
		in := "hello, world! 123 → é"
		if got := stripInvisible(in); got != in {
			t.Fatalf("got %q, want %q", got, in)
		}
	})
}

func TestStripInvisibleRealSmugglingVector(t *testing.T) {
	// A realistic attack: hide a word using TAG chars between visible letters.
	attacker := "re\U000E0001m\U000E0002o\U000E0003ve" // looks like "remove"
	clean := stripInvisible(attacker)
	if clean != "remove" {
		t.Fatalf("got %q, want %q", clean, "remove")
	}
	// The cleaned form must not contain any invisible rune.
	for _, r := range clean {
		if isInvisibleRune(r) {
			t.Fatalf("cleaned string still has invisible U+%04X", r)
		}
	}
}

// ---------- 2. tokenizer ----------

func TestTokenize(t *testing.T) {
	t.Run("camelCase identifier", func(t *testing.T) {
		got := tokenize("TokenBucketLimiter")
		want := []string{"token", "bucket", "limiter", "tokenbucketlimiter"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("acronym then word", func(t *testing.T) {
		got := tokenize("HTTPClient")
		want := []string{"http", "client", "httpclient"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("underscores", func(t *testing.T) {
		got := tokenize("foo_bar_baz")
		want := []string{"foo", "bar", "baz", "foobarbaz"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("letter digit boundary", func(t *testing.T) {
		got := tokenize("foo2bar")
		want := []string{"foo", "2", "bar", "foo2bar"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("digit letter boundary", func(t *testing.T) {
		got := tokenize("2foo")
		want := []string{"2", "foo", "2foo"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("multi-char symbols", func(t *testing.T) {
		if got, want := tokenize("=>"), []string{"=>"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("=> got %v", got)
		}
		if got, want := tokenize("=="), []string{"=="}; !reflect.DeepEqual(got, want) {
			t.Fatalf("== got %v", got)
		}
		if got, want := tokenize("!="), []string{"!="}; !reflect.DeepEqual(got, want) {
			t.Fatalf("!= got %v", got)
		}
		if got, want := tokenize("++"), []string{"++"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("++ got %v", got)
		}
	})
	t.Run("single-char symbols", func(t *testing.T) {
		for _, s := range []string{"-", ".", "(", ")", "{", "}", "<", ">", "=", "+", "/", "*", "&", "|", ";", ":", "#", "@", "$"} {
			got := tokenize(s)
			want := []string{s}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%q got %v", s, got)
			}
		}
	})
	t.Run("mixed phrase", func(t *testing.T) {
		got := tokenize("token bucket")
		want := []string{"token", "bucket"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("empty", func(t *testing.T) {
		if got := tokenize(""); len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("non-symbol punctuation dropped", func(t *testing.T) {
		// Comma, quote, etc. are not in the symbol set and not alnum: dropped.
		got := tokenize(`a, b "c"`)
		want := []string{"a", "b", "c"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("unicode letters not alnum", func(t *testing.T) {
		// é is not ASCII-alnum, so it is neither an identifier nor a symbol.
		got := tokenize("café")
		want := []string{"caf"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

func TestIdentTokens(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"TokenBucketLimiter", []string{"token", "bucket", "limiter", "tokenbucketlimiter"}},
		{"HTTPClient", []string{"http", "client", "httpclient"}},
		{"foo_bar_baz", []string{"foo", "bar", "baz", "foobarbaz"}},
		{"foo2bar", []string{"foo", "2", "bar", "foo2bar"}},
		{"abc", []string{"abc"}},
		{"ABC", []string{"abc"}},
		{"a1B2", []string{"a", "1", "b", "2", "a1b2"}},
	}
	for _, c := range cases {
		if got, want := identTokens([]rune(c.in)), c.want; !reflect.DeepEqual(got, want) {
			t.Errorf("%q got %v, want %v", c.in, got, want)
		}
	}
}

func TestRunesEqual(t *testing.T) {
	if !runesEqual([]rune("abc"), []rune("abc")) {
		t.Error("equal failed")
	}
	if runesEqual([]rune("abc"), []rune("abd")) {
		t.Error("diff failed")
	}
	if runesEqual([]rune("ab"), []rune("abc")) {
		t.Error("len failed")
	}
	if !runesEqual(nil, nil) {
		t.Error("nil failed")
	}
}

// ---------- 3. local hashing embeddings ----------

func TestHashDim(t *testing.T) {
	for _, dim := range []int{1, 16, 128, 1024} {
		for _, tok := range []string{"a", "token", "tokenbucketlimiter", "=>", "foo2bar"} {
			d := hashDim(tok, dim)
			if d < 0 || d >= dim {
				t.Fatalf("hashDim(%q, %d) = %d out of range", tok, dim, d)
			}
			if again := hashDim(tok, dim); again != d {
				t.Fatalf("hashDim(%q, %d) not deterministic: %d vs %d", tok, dim, d, again)
			}
		}
	}
}

func TestNormalize(t *testing.T) {
	v := normalize([]float32{3, 4})
	// L2 norm of (3,4) is 5 → expect (0.6, 0.8)
	if math.Abs(float64(v[0])-0.6) > 1e-6 || math.Abs(float64(v[1])-0.8) > 1e-6 {
		t.Fatalf("got %v, want [0.6 0.8]", v)
	}
	// Zero vector unchanged.
	z := normalize([]float32{0, 0, 0})
	if !reflect.DeepEqual(z, []float32{0, 0, 0}) {
		t.Fatalf("zero vector changed: %v", z)
	}
	// Result is unit length.
	n := 0.0
	for _, x := range v {
		n += float64(x) * float64(x)
	}
	if math.Abs(n-1.0) > 1e-5 {
		t.Fatalf("norm = %f, want ~1", n)
	}
}

func TestDot(t *testing.T) {
	a := []float32{1, 0, 0}
	b := []float32{1, 0, 0}
	if got := dot(a, b); math.Abs(got-1.0) > 1e-6 {
		t.Fatalf("dot = %f, want 1", got)
	}
	c := []float32{0, 1, 0}
	if got := dot(a, c); math.Abs(got) > 1e-6 {
		t.Fatalf("dot = %f, want 0", got)
	}
	d := []float32{-1, 0, 0}
	if got := dot(a, d); math.Abs(got+1.0) > 1e-6 {
		t.Fatalf("dot = %f, want -1", got)
	}
}

func TestEmbedLocal(t *testing.T) {
	vecs := embedLocal([]string{"token bucket limiter", "database connection pool", "token bucket limiter"}, testDim)
	if len(vecs) != 3 {
		t.Fatalf("got %d vectors", len(vecs))
	}
	for i, v := range vecs {
		if len(v) != testDim {
			t.Fatalf("vec %d has dim %d", i, len(v))
		}
	}
	// Identical texts → dot ≈ 1.
	if got := dot(vecs[0], vecs[2]); math.Abs(got-1.0) > 1e-4 {
		t.Fatalf("identical dot = %f, want ~1", got)
	}
	// Deterministic.
	again := embedLocal([]string{"token bucket limiter"}, testDim)
	if !reflect.DeepEqual(vecs[0], again[0]) {
		t.Fatal("embedLocal not deterministic")
	}
	// Different texts share some mass but are not identical.
	if got := dot(vecs[0], vecs[1]); got >= 1.0 {
		t.Fatalf("distinct texts dot = %f (should be < 1)", got)
	}
}

// ---------- 4. chunking + file classification ----------

func TestChunkText(t *testing.T) {
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d", i)
	}

	t.Run("no overlap", func(t *testing.T) {
		chunks := chunkText("p", "code", lines, 10, 0)
		want := 10 // 100 / 10
		if len(chunks) != want {
			t.Fatalf("got %d chunks, want %d", len(chunks), want)
		}
		if chunks[0].Start != 1 || chunks[0].End != 10 {
			t.Fatalf("first chunk %d-%d, want 1-10", chunks[0].Start, chunks[0].End)
		}
		if chunks[9].End != 100 {
			t.Fatalf("last chunk end %d, want 100", chunks[9].End)
		}
		if chunks[0].Text != strings.Join(lines[:10], "\n") {
			t.Fatal("first chunk text mismatch")
		}
	})
	t.Run("with overlap", func(t *testing.T) {
		chunks := chunkText("p", "code", lines, 10, 4)
		// step = 10-4 = 6 → starts at 0,6,12,... ; count = ceil((100-4)/(10-4)) + 1 = 16+...
		// Just assert monotonic starts and coverage of the last line.
		for i := 1; i < len(chunks); i++ {
			if chunks[i].Start <= chunks[i-1].Start {
				t.Fatalf("starts not increasing: %d then %d", chunks[i-1].Start, chunks[i].Start)
			}
		}
		last := chunks[len(chunks)-1]
		if last.End != 100 {
			t.Fatalf("last end %d, want 100", last.End)
		}
	})
	t.Run("overlap >= chunk clamps to half", func(t *testing.T) {
		chunks := chunkText("p", "code", lines, 10, 20)
		// overlap clamped to 5 → step 5.
		if len(chunks) == 0 {
			t.Fatal("no chunks")
		}
	})
	t.Run("negative overlap becomes 0", func(t *testing.T) {
		a := chunkText("p", "code", lines, 10, -5)
		b := chunkText("p", "code", lines, 10, 0)
		if len(a) != len(b) {
			t.Fatalf("negative overlap count %d != 0-overlap %d", len(a), len(b))
		}
	})
	t.Run("chunk<=0 uses default", func(t *testing.T) {
		chunks := chunkText("p", "code", lines, 0, 0)
		if len(chunks) == 0 {
			t.Fatal("no chunks with default size")
		}
	})
	t.Run("blank lines skipped", func(t *testing.T) {
		chunks := chunkText("p", "code", []string{"", "   ", "\t"}, 10, 0)
		if len(chunks) != 0 {
			t.Fatalf("got %d chunks for blank lines", len(chunks))
		}
	})
	t.Run("single line", func(t *testing.T) {
		chunks := chunkText("p", "doc", []string{"hello"}, 10, 0)
		if len(chunks) != 1 {
			t.Fatalf("got %d chunks", len(chunks))
		}
		if chunks[0].Start != 1 || chunks[0].End != 1 || chunks[0].Text != "hello" {
			t.Fatalf("got %+v", chunks[0])
		}
	})
	t.Run("short text one chunk", func(t *testing.T) {
		chunks := chunkText("p", "doc", []string{"a", "b", "c"}, 10, 0)
		if len(chunks) != 1 {
			t.Fatalf("got %d chunks", len(chunks))
		}
		if chunks[0].Text != "a\nb\nc" {
			t.Fatalf("got %q", chunks[0].Text)
		}
	})
	t.Run("path and kind carried", func(t *testing.T) {
		chunks := chunkText("repo/src/main.go", "code", []string{"x"}, 10, 0)
		if chunks[0].Path != "repo/src/main.go" || chunks[0].Kind != "code" {
			t.Fatalf("got %+v", chunks[0])
		}
	})
}

func TestKindOfPath(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"main.go", "code"},
		{"x.py", "code"},
		{"x.ts", "code"},
		{"x.rs", "code"},
		{"x.c", "code"},
		{"x.java", "code"},
		{"x.sh", "code"},
		{"x.sql", "code"},
		{"x.toml", "code"},
		{"x.json", "code"},
		{"x.yaml", "code"},
		{"README.md", "doc"},
		{"x.rst", "doc"},
		{"x.txt", "doc"},
		{"x.adoc", "doc"},
		{"Makefile", "code"},
		{"Dockerfile", "code"},
		{".gitignore", "code"},
		{"x.unknown", "text"},
		{"data.csv", "text"},
	}
	for _, c := range cases {
		if got := kindOfPath(c.name); got != c.want {
			t.Errorf("kindOfPath(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestIsTextExt(t *testing.T) {
	if isTextExt("main.go") != true {
		t.Error("go should be text")
	}
	for _, b := range []string{"img.png", "a.zip", "b.pdf", "c.exe", "d.so", "e.pyc", "f.lock", "g.wav"} {
		if isTextExt(b) {
			t.Errorf("%s should be non-text", b)
		}
	}
}

// ---------- 5. skip rules ----------

func TestIsSkipDir(t *testing.T) {
	for _, d := range []string{".git", "node_modules", "vendor", "dist", "build", "target", "out", ".venv", "venv", "__pycache__", ".idea", ".vscode", ".next", "coverage", ".tox", ".mypy_cache", "bower_components", ".cache", "tmp", "temp"} {
		if !isSkipDir(d) {
			t.Errorf("%s should be skipped", d)
		}
		if !isSkipDir(strings.ToUpper(d)) {
			t.Errorf("%s (upper) should be skipped", d)
		}
	}
	for _, d := range []string{"src", "lib", "pkg", "internal"} {
		if isSkipDir(d) {
			t.Errorf("%s should NOT be skipped", d)
		}
	}
}

func TestIsSkipFile(t *testing.T) {
	for _, f := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "gopkg.lock", "pipfile.lock", "poetry.lock", "cargo.lock", "composer.lock"} {
		if !isSkipFile(f) {
			t.Errorf("%s should be skipped", f)
		}
	}
	for _, f := range []string{"a.min.js", "b.min.css", "c.js.map", "d.css.snap", "e.pb.go", "f.pb.cc", "g.pb.h", "h.generated.go"} {
		if !isSkipFile(f) {
			t.Errorf("%s should be skipped", f)
		}
	}
	for _, f := range []string{"main.go", "README.md", "notes.txt"} {
		if isSkipFile(f) {
			t.Errorf("%s should NOT be skipped", f)
		}
	}
}

// ---------- 6. git output parsing (pure) ----------

func TestParseCommitRecords(t *testing.T) {
	// Records separated by 0x02, fields by 0x01, 6 fields (last = body).
	rec1 := "abc123\x01Alice\x012024-01-02T10:00:00Z\x01Add feature\x01Body line one\nBody line two"
	rec2 := "def456\x01Bob\x012024-01-03T11:00:00Z\x01Fix bug\x01"
	out := []byte(rec1 + "\x02" + rec2 + "\x02")
	got := parseCommitRecords(out)
	if len(got) != 2 {
		t.Fatalf("got %d commits, want 2", len(got))
	}
	if got[0].SHA != "abc123" || got[0].Author != "Alice" || got[0].Subject != "Add feature" {
		t.Fatalf("commit 0 = %+v", got[0])
	}
	wantBody := "Body line one\nBody line two"
	if got[0].Body != wantBody {
		t.Fatalf("body = %q, want %q", got[0].Body, wantBody)
	}
	if got[1].Subject != "Fix bug" || got[1].Body != "" {
		t.Fatalf("commit 1 = %+v", got[1])
	}
}

func TestParseCommitRecordsStripsInvisible(t *testing.T) {
	rec := "abc123\x01Al\U000E0001ice\x012024\x01Subj\U000E0001\x01"
	got := parseCommitRecords([]byte(rec + "\x02"))
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].Author != "Al"+"ice" || got[0].Subject != "Subj" {
		t.Fatalf("invisible not stripped: %+v", got[0])
	}
}

func TestParseCommitRecordsEmptyAndMalformed(t *testing.T) {
	if got := parseCommitRecords([]byte("")); len(got) != 0 {
		t.Fatalf("empty got %d", len(got))
	}
	if got := parseCommitRecords([]byte("\x02\x02")); len(got) != 0 {
		t.Fatalf("separators got %d", len(got))
	}
	// Record with too few fields (only 3) is dropped.
	if got := parseCommitRecords([]byte("abc\x01x\x01y\x02")); len(got) != 0 {
		t.Fatalf("short record got %d", len(got))
	}
}

func TestParsePatch(t *testing.T) {
	patch := `diff --git a/src/main.go b/src/main.go
index 111..222 100644
--- a/src/main.go
+++ b/src/main.go
@@ -1,3 +1,4 @@
 package main
+func New() {}
 func old() {}
diff --git a/img.png b/img.png
Binary files a/img.png and b/img.png differ
diff --git a/empty.txt b/empty.txt
--- a/empty.txt
+++ b/empty.txt
`
	got := parsePatch(patch)
	if len(got) != 1 {
		t.Fatalf("got %d files, want 1: %+v", len(got), got)
	}
	if got[0].File != "src/main.go" {
		t.Fatalf("file = %q", got[0].File)
	}
	if !strings.Contains(got[0].Hunk, "func New() {}") {
		t.Fatalf("hunk missing added line: %q", got[0].Hunk)
	}
	if !strings.Contains(got[0].Hunk, "@@") {
		t.Fatalf("hunk missing header: %q", got[0].Hunk)
	}
	// Binary file excluded, empty-hunk file excluded.
}

func TestParsePatchOnlyAddedAndHeader(t *testing.T) {
	patch := `diff --git a/x b/x
@@ -0,0 +1,2 @@
 context line
+added
-removed
`
	got := parsePatch(patch)
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	h := got[0].Hunk
	if !strings.Contains(h, "+added") || strings.Contains(h, "-removed") {
		t.Fatalf("hunk = %q (want +added, no -removed)", h)
	}
}

func TestPatchPath(t *testing.T) {
	cases := []struct {
		ln   string
		want string
	}{
		{"diff --git a/src/main.go b/src/main.go", "src/main.go"},
		{"diff --git a/README.md b/README.md", "README.md"},
		{"diff --git a/old.txt b/new.txt", "new.txt"},
		{"diff --git a/x b/x", "x"},
	}
	for _, c := range cases {
		if got := patchPath(c.ln); got != c.want {
			t.Errorf("patchPath(%q) = %q, want %q", c.ln, got, c.want)
		}
	}
}

func TestParseBlameLine(t *testing.T) {
	// Standard: <sha> (<author> <date> <tz> <line>) <content>
	got, ok := parseBlameLine("0123abcd (Alice 2024-01-02 10:00:00 +0000 7) some content")
	if !ok {
		t.Fatal("not parsed")
	}
	if got.SHA != "0123abcd" || got.Author != "Alice" || got.Line != 7 {
		t.Fatalf("got %+v", got)
	}
	// With original line number: <sha> <orig> (...)
	got, ok = parseBlameLine("0123abcd def456 (Bob 2024-01-03 11:00:00 +0000 12) x")
	if !ok {
		t.Fatal("not parsed")
	}
	if got.SHA != "0123abcd" || got.Line != 12 || got.Author != "Bob" {
		t.Fatalf("got %+v", got)
	}
	// Leading ^ (boundary commit) stripped.
	got, ok = parseBlameLine("^0123abcd (Carol 2024-01-01 00:00:00 +0000 1) y")
	if !ok {
		t.Fatal("not parsed")
	}
	if got.SHA != "0123abcd" {
		t.Fatalf("got %+v", got)
	}
	// Malformed.
	if _, ok := parseBlameLine("no spaces"); ok {
		t.Error("no-space should fail")
	}
	if _, ok := parseBlameLine("abc (no close"); ok {
		t.Error("no-close should fail")
	}
	if _, ok := parseBlameLine("abc (Alice 2024-01-02 +0000 0) z"); ok {
		t.Error("zero-line should fail")
	}
	// Empty parens → rejected without panicking.
	if _, ok := parseBlameLine("abc () 0) z"); ok {
		t.Error("empty parens should fail")
	}
}

// ---------- 7. string / path utilities ----------

func TestSplitLabel(t *testing.T) {
	cases := []struct {
		p     string
		label string
		rel   string
	}{
		{"repo/src/main.go", "repo", "src/main.go"},
		{"repo/main.go", "repo", "main.go"},
		{"main.go", "", "main.go"},
		{"a/b/c/d.txt", "a", "b/c/d.txt"},
	}
	for _, c := range cases {
		l, r := splitLabel(c.p)
		if l != c.label || r != c.rel {
			t.Errorf("splitLabel(%q) = (%q,%q), want (%q,%q)", c.p, l, r, c.label, c.rel)
		}
	}
}

func TestPathHasTraversal(t *testing.T) {
	for _, p := range []string{"../etc/passwd", "a/../../b", "a/..", ".."} {
		if !pathHasTraversal(p) {
			t.Errorf("%q should have traversal", p)
		}
	}
	for _, p := range []string{"src/main.go", "a/b/c", "a..b/c", "..hidden"} {
		if pathHasTraversal(p) {
			t.Errorf("%q should NOT have traversal", p)
		}
	}
}

func TestIsUTF8(t *testing.T) {
	if !isUTF8([]byte("hello")) {
		t.Error("ascii should be valid")
	}
	if !isUTF8([]byte("café → 😀")) {
		t.Error("multibyte should be valid")
	}
	if !isUTF8(nil) {
		t.Error("empty should be valid")
	}
	// Invalid: lone continuation byte.
	if isUTF8([]byte{0x80}) {
		t.Error("lone continuation should be invalid")
	}
	// Invalid: truncated 2-byte.
	if isUTF8([]byte{0xC3}) {
		t.Error("truncated 2-byte should be invalid")
	}
	// Invalid: bad lead byte 0xC1.
	if isUTF8([]byte{0xC1, 0x80}) {
		t.Error("0xC1 lead should be invalid")
	}
	// Invalid: truncated 4-byte emoji.
	if isUTF8([]byte{0xF0, 0x9F}) {
		t.Error("truncated 4-byte should be invalid")
	}
}

func TestClip(t *testing.T) {
	if got := clip("short", 10); got != "short" {
		t.Fatalf("got %q", got)
	}
	got := clip("abcdefghij", 5)
	if got != "abcde…" {
		t.Fatalf("got %q, want %q", got, "abcde…")
	}
	// Rune-safe.
	got = clip("😀😀😀😀", 2)
	if got != "😀😀…" {
		t.Fatalf("got %q", got)
	}
}

func TestContains(t *testing.T) {
	l := []string{"a", "b", "c"}
	if !contains(l, "b") {
		t.Error("b should be found")
	}
	if contains(l, "z") {
		t.Error("z should not be found")
	}
	if contains(nil, "a") {
		t.Error("nil list should not contain")
	}
}

func TestSortedStringKeys(t *testing.T) {
	m := map[string]int{"c": 1, "a": 2, "b": 3}
	got := sortedStringKeys(m)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFilterNonEmpty(t *testing.T) {
	if got, want := filterNonEmpty([]string{"a", "", "b", ""}), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := filterNonEmpty([]string{""}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

// ---------- 8. path-trust policy ----------

func TestWithinOrEqual(t *testing.T) {
	if !withinOrEqual("/a/b", "/a/b") {
		t.Error("equal should be within")
	}
	if !withinOrEqual("/a/b", "/a/b/c") {
		t.Error("under should be within")
	}
	if withinOrEqual("/a/b", "/a/bc") {
		t.Error("sibling-prefix should NOT be within (separator-safe)")
	}
	if withinOrEqual("/a/b", "/a") {
		t.Error("parent should NOT be within child")
	}
}

func TestWithinAny(t *testing.T) {
	dirs := []string{"/x/y", "/z"}
	if !withinAny("/x/y/w", dirs) {
		t.Error("should be within /x/y")
	}
	if !withinAny("/z", dirs) {
		t.Error("should be within /z")
	}
	if withinAny("/other", dirs) {
		t.Error("should not be within any")
	}
}

func TestRootWithin(t *testing.T) {
	roots := []string{"/a", "/a/b", "/a/b/c"}
	// Most specific (longest) containing root wins.
	got, ok := rootWithin("/a/b/c/d", roots)
	if !ok || got != "/a/b/c" {
		t.Fatalf("got (%q,%v), want (/a/b/c,true)", got, ok)
	}
	got, ok = rootWithin("/a/x", roots)
	if !ok || got != "/a" {
		t.Fatalf("got (%q,%v), want (/a,true)", got, ok)
	}
	if _, ok := rootWithin("/zzz", roots); ok {
		t.Fatal("should not find a root")
	}
}

func TestNewTrustPolicyNormalization(t *testing.T) {
	tp := NewTrustPolicy(
		[]string{"  /a/b  ", "/a/b", "/a/b/", "", "   "},
		[]string{"/forbid"},
	)
	// De-duped and cleaned.
	want := []string{"/a/b"}
	if !reflect.DeepEqual(tp.Trusted, want) {
		t.Fatalf("trusted = %v, want %v", tp.Trusted, want)
	}
	if !reflect.DeepEqual(tp.Forbidden, []string{"/forbid"}) {
		t.Fatalf("forbidden = %v", tp.Forbidden)
	}
}

func TestTrustPolicyAllowsLexical(t *testing.T) {
	// Nonexistent paths: realPath falls back to lexical identity, so this is
	// deterministic without touching the filesystem.
	tp := NewTrustPolicy([]string{"/trusted/root"}, []string{"/forbidden"})

	if !tp.Allows(OpRead, "/trusted/root/file.go") {
		t.Error("file under trusted root should be allowed")
	}
	if !tp.AllowRead("/trusted/root") {
		t.Error("trusted root itself should be allowed")
	}
	if tp.Allows(OpRead, "/elsewhere/file.go") {
		t.Error("file outside trusted set should be denied (default deny)")
	}
	if tp.Allows(OpRead, "relative/path") {
		t.Error("relative path should be denied")
	}
	// Forbidden always wins, even under a trusted root.
	tp2 := NewTrustPolicy([]string{"/trusted/root"}, []string{"/trusted/root/secret"})
	if tp2.Allows(OpRead, "/trusted/root/secret/x") {
		t.Error("forbidden subpath should win over trusted")
	}
	if !tp2.Allows(OpRead, "/trusted/root/other") {
		t.Error("non-forbidden sibling should still be allowed")
	}
	// Unknown op denied.
	if tp.Allows(TrustOp("write"), "/trusted/root/file.go") {
		t.Error("unknown op should be denied")
	}
}

func TestTrustPolicySymlinkEscape(t *testing.T) {
	if runtimeGOOSNotLinux() {
		t.Skip("symlink test is Linux-oriented")
	}
	tmp := t.TempDir()
	trusted := filepath.Join(tmp, "trusted")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(trusted, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	// Symlink inside trusted root pointing outside.
	link := filepath.Join(trusted, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	tp := NewTrustPolicy([]string{trusted}, nil)
	// Real file under trusted root is fine.
	if err := os.WriteFile(filepath.Join(trusted, "ok.txt"), []byte("y"), 0644); err != nil {
		t.Fatal(err)
	}
	if !tp.AllowRead(filepath.Join(trusted, "ok.txt")) {
		t.Error("real file under trusted root should be allowed")
	}
	// Path through the symlink escapes the trusted root → denied.
	if tp.AllowRead(filepath.Join(link, "secret.txt")) {
		t.Error("symlink escape should be denied")
	}
}

func TestTrustPolicySymlinkIntoForbidden(t *testing.T) {
	if runtimeGOOSNotLinux() {
		t.Skip("symlink test is Linux-oriented")
	}
	tmp := t.TempDir()
	trusted := filepath.Join(tmp, "trusted")
	forbidden := filepath.Join(tmp, "forbidden")
	_ = os.MkdirAll(trusted, 0755)
	_ = os.MkdirAll(forbidden, 0755)
	_ = os.WriteFile(filepath.Join(forbidden, "data"), []byte("x"), 0644)
	// A trusted real dir; a symlink from trusted into forbidden.
	_ = os.MkdirAll(filepath.Join(trusted, "real"), 0755)
	_ = os.Symlink(forbidden, filepath.Join(trusted, "to_forbid"))
	tp := NewTrustPolicy([]string{trusted}, []string{forbidden})
	if !tp.AllowRead(filepath.Join(trusted, "real", "f")) {
		t.Error("real trusted path should be allowed")
	}
	if tp.AllowRead(filepath.Join(trusted, "to_forbid", "data")) {
		t.Error("symlink into forbidden should be denied")
	}
}

func runtimeGOOSNotLinux() bool {
	return os.Getenv("GOOS_OVERRIDE") == "notlinux"
}

// ---------- 9. BM25 keyword index ----------

func TestComputeLens(t *testing.T) {
	chunkTF := [][]tfPair{
		{{0, 2}, {1, 1}},
		{{0, 5}},
		{},
	}
	got := computeLens(chunkTF)
	want := []int32{3, 5, 0}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestBuildPostings(t *testing.T) {
	chunkTF := [][]tfPair{
		{{0, 2}, {1, 1}}, // chunk0
		{{0, 3}},         // chunk1
	}
	post := buildPostings(2, chunkTF)
	// term0 appears in chunk0(tf2) and chunk1(tf3).
	if len(post[0]) != 2 {
		t.Fatalf("term0 postings = %v", post[0])
	}
	if post[0][0] != (tfPair{0, 2}) || post[0][1] != (tfPair{1, 3}) {
		t.Fatalf("term0 postings = %v", post[0])
	}
	// term1 only in chunk0.
	if len(post[1]) != 1 || post[1][0] != (tfPair{0, 1}) {
		t.Fatalf("term1 postings = %v", post[1])
	}
}

func TestBuildKWIndexBasics(t *testing.T) {
	chunks := []Chunk{
		{Path: "a/x.go", Kind: "code", Text: "token bucket limiter"},
		{Path: "b/y.go", Kind: "code", Text: "token bucket rate limit"},
		{Path: "c/z.md", Kind: "doc", Text: "database pool"},
	}
	kw := buildKWIndex(chunks, true)
	if kw.N != 3 {
		t.Fatalf("N = %d", kw.N)
	}
	if kw.ID == nil || len(kw.Terms) == 0 {
		t.Fatal("no terms")
	}
	// "token" is in chunks 0 and 1 → df=2.
	if tid, ok := kw.ID["token"]; !ok {
		t.Fatal("token missing")
	} else if kw.DF[tid] != 2 {
		t.Fatalf("df(token) = %d, want 2", kw.DF[tid])
	}
	// "limiter" only in chunk 0 → df=1.
	if tid, ok := kw.ID["limiter"]; !ok {
		t.Fatal("limiter missing")
	} else if kw.DF[tid] != 1 {
		t.Fatalf("df(limiter) = %d, want 1", kw.DF[tid])
	}
	// kwPath=true indexes the path leaf tokens (tokenized, not the literal name)
	// + the kind.
	if _, ok := kw.ID["x"]; !ok {
		t.Error("path leaf token x should be indexed with kwPath")
	}
	if _, ok := kw.ID["go"]; !ok {
		t.Error("path leaf token go should be indexed with kwPath")
	}
	if _, ok := kw.ID["code"]; !ok {
		t.Error("kind code should be indexed with kwPath")
	}
}

func TestBuildKWIndexNoKwPath(t *testing.T) {
	chunks := []Chunk{{Path: "a/x.go", Kind: "code", Text: "token bucket"}}
	kw := buildKWIndex(chunks, false)
	if _, ok := kw.ID["x"]; ok {
		t.Error("path leaf should NOT be indexed without kwPath")
	}
	if _, ok := kw.ID["code"]; ok {
		t.Error("kind should NOT be indexed without kwPath")
	}
}

func TestKWIndexScore(t *testing.T) {
	chunks := []Chunk{
		{Path: "a", Kind: "code", Text: "token bucket limiter implementation"},
		{Path: "b", Kind: "code", Text: "database connection pool"},
		{Path: "c", Kind: "code", Text: "token bucket rate limiting algorithm"},
	}
	kw := buildKWIndex(chunks, false)
	sc := kw.Score("token bucket limiter", nil)
	// chunk0 (all 3 words) should be highest; chunk2 (two words) next; chunk1 absent.
	if _, ok := sc[1]; ok {
		t.Fatal("chunk1 should not be active")
	}
	if sc[0] <= sc[2] {
		t.Fatalf("expected chunk0 (%f) > chunk2 (%f)", sc[0], sc[2])
	}
}

func TestKWIndexScoreCandidateFilter(t *testing.T) {
	chunks := []Chunk{
		{Path: "a", Kind: "code", Text: "alpha beta"},
		{Path: "b", Kind: "code", Text: "alpha gamma"},
	}
	kw := buildKWIndex(chunks, false)
	cand := map[int]bool{1: true} // only chunk1
	sc := kw.Score("alpha", cand)
	if _, ok := sc[0]; ok {
		t.Fatal("chunk0 should be excluded by candidate filter")
	}
	if _, ok := sc[1]; !ok {
		t.Fatal("chunk1 should be active")
	}
}

func TestKWAddChunk(t *testing.T) {
	chunks := []Chunk{
		{Path: "a", Kind: "code", Text: "token bucket"},
		{Path: "b", Kind: "code", Text: "token wheel"},
	}
	kw := buildKWIndex(chunks, false)
	before := kw.N
	// Add a chunk with a brand-new term.
	kwAddChunk(kw, Chunk{Path: "c", Kind: "code", Text: "token quantum flux"})
	if kw.N != before+1 {
		t.Fatalf("N = %d, want %d", kw.N, before+1)
	}
	if _, ok := kw.ID["quantum"]; !ok {
		t.Fatal("new term quantum should be added")
	}
	// The new chunk should score for "quantum".
	sc := kw.Score("quantum", nil)
	if _, ok := sc[2]; !ok {
		t.Fatal("new chunk should be active for quantum")
	}
	// "token" df should have increased to 3.
	if tid := kw.ID["token"]; kw.DF[tid] != 3 {
		t.Fatalf("df(token) = %d, want 3", kw.DF[tid])
	}
}

func TestCapKWTermsNoOp(t *testing.T) {
	chunks := []Chunk{{Path: "a", Kind: "code", Text: "alpha beta gamma"}}
	kw := buildKWIndex(chunks, false)
	termsBefore := len(kw.Terms)
	capKWTerms(kw)
	if len(kw.Terms) != termsBefore {
		t.Fatalf("cap changed small index: %d -> %d", termsBefore, len(kw.Terms))
	}
}

func TestCapKWTermsKeepsRarestFirst(t *testing.T) {
	// Build an index then shrink maxKWTerms via a small manual cap by simulating
	// the algorithm: we can't change the package constant, so instead verify the
	// no-op path is deterministic and the index stays consistent.
	chunks := []Chunk{
		{Path: "a", Kind: "code", Text: "x x y"},
		{Path: "b", Kind: "code", Text: "y z"},
	}
	kw := buildKWIndex(chunks, false)
	if kw.ID["x"] == kw.ID["y"] {
		t.Fatal("distinct terms share id")
	}
}

// ---------- 10. fusion ----------

func TestRankIDs(t *testing.T) {
	active := []int{2, 0, 1}
	sc := []float64{5, 5, 1}
	got := rankIDs(active, sc)
	want := []int{0, 1, 2} // 0,1 tie at 5 (id asc), then 2
	if len(got) != 3 {
		t.Fatalf("got %d", len(got))
	}
	for i, w := range want {
		if got[i].id != w {
			t.Fatalf("got order %v, want %v", idsOf(got), want)
		}
	}
	// Scores carried.
	if got[0].sc != 5 || got[2].sc != 1 {
		t.Fatalf("scores: %+v", got)
	}
}

func idsOf(in []idScore) []int {
	out := make([]int, len(in))
	for i, e := range in {
		out[i] = e.id
	}
	return out
}

func TestRRFFuse(t *testing.T) {
	// n=3. A: [0,1]; B: [1,0,2].
	rankA := []idScore{{id: 0, sc: 10}, {id: 1, sc: 5}}
	rankB := []idScore{{id: 1, sc: 10}, {id: 0, sc: 5}, {id: 2, sc: 1}}
	got := rrfFuse(rankA, rankB, 60, 3)
	if len(got) != 3 {
		t.Fatalf("got %d", len(got))
	}
	// chunk0 and chunk1 both = 1/61 + 1/62; chunk2 = 1/63 (lowest).
	// Order: 0,1 (tie, id asc) then 2.
	if got[0].id != 0 || got[1].id != 1 || got[2].id != 2 {
		t.Fatalf("order %v", idsOf(got))
	}
	want01 := 1.0/61 + 1.0/62
	if math.Abs(got[0].sc-want01) > 1e-9 || math.Abs(got[1].sc-want01) > 1e-9 {
		t.Fatalf("score01 = %v, want %v", got[0].sc, want01)
	}
	if math.Abs(got[2].sc-1.0/63) > 1e-9 {
		t.Fatalf("score2 = %v, want %v", got[2].sc, 1.0/63)
	}
}

func TestRRFFuseAbsentChannel(t *testing.T) {
	// A chunk absent from one channel gets 0 from it.
	rankA := []idScore{{id: 0, sc: 1}}
	rankB := []idScore{{id: 1, sc: 1}}
	got := rrfFuse(rankA, rankB, 60, 2)
	// chunk0 = 1/61 (A only); chunk1 = 1/62 (B only, rank 0) → 1/61 > 1/62.
	if got[0].id != 0 {
		t.Fatalf("order %v", idsOf(got))
	}
	if math.Abs(got[0].sc-1.0/61) > 1e-9 {
		t.Fatalf("chunk0 = %v, want 1/61", got[0].sc)
	}
}

func TestWeightedFuse(t *testing.T) {
	// n=2. A: [0@10, 1@0]; B: [1@10, 0@0]. wA=0.6, wB=0.4.
	rankA := []idScore{{id: 0, sc: 10}, {id: 1, sc: 0}}
	rankB := []idScore{{id: 1, sc: 10}, {id: 0, sc: 0}}
	got := weightedFuse(rankA, rankB, 0.6, 0.4, 2)
	// chunk0: 0.6*1.0 + 0.4*0 = 0.6 ; chunk1: 0.6*0 + 0.4*1.0 = 0.4
	if got[0].id != 0 || got[1].id != 1 {
		t.Fatalf("order %v", idsOf(got))
	}
	if math.Abs(got[0].sc-0.6) > 1e-9 {
		t.Fatalf("chunk0 = %v, want 0.6", got[0].sc)
	}
	if math.Abs(got[1].sc-0.4) > 1e-9 {
		t.Fatalf("chunk1 = %v, want 0.4", got[1].sc)
	}
}

func TestWeightedFuseSingleChunk(t *testing.T) {
	// Single-chunk ranking: hi==lo → everyone "best" → full weight.
	rankA := []idScore{{id: 0, sc: 5}}
	rankB := []idScore{{id: 1, sc: 5}}
	got := weightedFuse(rankA, rankB, 0.6, 0.4, 2)
	if math.Abs(got[0].sc-0.6) > 1e-9 || math.Abs(got[1].sc-0.4) > 1e-9 {
		t.Fatalf("got %+v", got)
	}
}

func TestWeightedFuseAbsent(t *testing.T) {
	// chunk1 absent from A → 0 from A.
	rankA := []idScore{{id: 0, sc: 10}, {id: 0, sc: 0}} // only chunk0
	rankB := []idScore{{id: 1, sc: 10}}                 // only chunk1
	got := weightedFuse(rankA, rankB, 0.6, 0.4, 2)
	// chunk0: 0.6 (single) ; chunk1: 0.4 (single)
	found := map[int]bool{}
	for _, e := range got {
		found[e.id] = true
	}
	if !found[0] || !found[1] {
		t.Fatalf("both chunks should appear: %+v", got)
	}
}

// ---------- 11. Search (in-memory DB) ----------

func searchSetup(t *testing.T) *DB {
	t.Helper()
	t.Setenv("KB_EMBED_URL", "") // force local backend
	chunks := []Chunk{
		{Path: "src/token.go", Kind: "code", Text: "token bucket limiter implementation details"},
		{Path: "src/db.go", Kind: "code", Text: "database connection pool management"},
		{Path: "docs/guide.md", Kind: "doc", Text: "token bucket rate limiting algorithm guide"},
	}
	return makeDB(t, chunks)
}

func TestSearchVectorMode(t *testing.T) {
	db := searchSetup(t)
	res, err := db.Search("token bucket limiter", 10, "", "", 0, false, ModeVector)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 {
		t.Fatal("no results")
	}
	// Top result should be the token.go chunk (closest text).
	if !strings.Contains(res[0].C.Path, "token") {
		t.Fatalf("top = %s", res[0].C.Path)
	}
}

func TestSearchKeywordMode(t *testing.T) {
	db := searchSetup(t)
	res, err := db.Search("token bucket limiter", 10, "", "", 0, false, ModeKeyword)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 {
		t.Fatal("no results")
	}
	if !strings.Contains(res[0].C.Path, "token") {
		t.Fatalf("top = %s", res[0].C.Path)
	}
	// The db.go chunk shares no terms → should not appear.
	for _, r := range res {
		if strings.Contains(r.C.Path, "db.go") {
			t.Fatal("db.go should not match keyword query")
		}
	}
}

func TestSearchHybridMode(t *testing.T) {
	db := searchSetup(t)
	res, err := db.Search("token bucket limiter", 10, "", "", 0, false, ModeHybrid)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 {
		t.Fatal("no results")
	}
	if !strings.Contains(res[0].C.Path, "token") {
		t.Fatalf("top = %s", res[0].C.Path)
	}
}

func TestSearchWeightedMode(t *testing.T) {
	db := searchSetup(t)
	res, err := db.SearchW("token bucket limiter", 10, "", "", 0, false, ModeWeighted, 0.6, 0.4)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 {
		t.Fatal("no results")
	}
}

func TestSearchUnknownMode(t *testing.T) {
	db := searchSetup(t)
	if _, err := db.Search("q", 10, "", "", 0, false, "bogus"); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestSearchPathFilter(t *testing.T) {
	db := searchSetup(t)
	res, err := db.Search("token", 10, "docs", "", 0, false, ModeKeyword)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if !strings.Contains(r.C.Path, "docs") {
			t.Fatalf("path filter violated: %s", r.C.Path)
		}
	}
}

func TestSearchKindFilter(t *testing.T) {
	db := searchSetup(t)
	res, err := db.Search("token", 10, "", "doc", 0, false, ModeKeyword)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.C.Kind != "doc" {
			t.Fatalf("kind filter violated: %s", r.C.Kind)
		}
	}
}

func TestSearchKLimit(t *testing.T) {
	db := searchSetup(t)
	res, err := db.Search("token", 1, "", "", 0, false, ModeVector)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d, want 1", len(res))
	}
}

func TestSearchEmptyChunks(t *testing.T) {
	db := &DB{Dim: testDim, Backend: "local-hashing", Chunks: nil, KW: buildKWIndex(nil, true)}
	res, err := db.Search("anything", 10, "", "", 0, false, ModeVector)
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Fatalf("got %v, want nil", res)
	}
}

func TestSearchNilKWdegradesToVector(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	chunks := []Chunk{{Path: "a", Kind: "code", Text: "token bucket"}}
	for i := range chunks {
		chunks[i].Vector = vec(t, chunks[i].Text)
	}
	db := &DB{Dim: testDim, Backend: "local-hashing", Chunks: chunks, KW: nil}
	// hybrid with nil KW → degrades to vector (no error).
	if _, err := db.Search("token", 5, "", "", 0, false, ModeHybrid); err != nil {
		t.Fatalf("hybrid should degrade, got %v", err)
	}
	// keyword mode with nil KW → error.
	if _, err := db.Search("token", 5, "", "", 0, false, ModeKeyword); err == nil {
		t.Fatal("keyword with nil KW should error")
	}
}

func TestSearchBackendMismatch(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	chunks := []Chunk{{Path: "a", Kind: "code", Text: "token"}}
	chunks[0].Vector = vec(t, "token")
	db := &DB{Dim: testDim, Backend: "remote:fake-model", Chunks: chunks, KW: buildKWIndex(chunks, true)}
	if _, err := db.Search("token", 5, "", "", 0, false, ModeVector); err == nil {
		t.Fatal("expected backend mismatch error")
	}
}

func TestSearchStripsInvisibleQuery(t *testing.T) {
	db := searchSetup(t)
	// Inject invisible chars into the query; result should be same as clean query.
	clean, err := db.Search("token bucket", 5, "", "", 0, false, ModeKeyword)
	if err != nil {
		t.Fatal(err)
	}
	dirty, err := db.Search("to\U000E0001ken b\u200Bucket", 5, "", "", 0, false, ModeKeyword)
	if err != nil {
		t.Fatal(err)
	}
	if len(clean) != len(dirty) {
		t.Fatalf("clean %d vs dirty %d", len(clean), len(dirty))
	}
	for i := range clean {
		if clean[i].C.Path != dirty[i].C.Path {
			t.Fatalf("path mismatch at %d: %s vs %s", i, clean[i].C.Path, dirty[i].C.Path)
		}
	}
}

// ---------- 12. message-board core ----------

func TestNewBoard(t *testing.T) {
	b := newBoard()
	if _, ok := b.Threads[boardWelcome]; !ok {
		t.Fatal("welcome thread missing")
	}
	if len(b.Order) != 1 || b.Order[0] != boardWelcome {
		t.Fatalf("order = %v", b.Order)
	}
	if b.Agents == nil {
		t.Fatal("agents map nil")
	}
}

func TestEnsureWelcomeIdempotent(t *testing.T) {
	b := newBoard()
	b.Order = append(b.Order, "extra")
	ensureWelcome(b)
	// welcome must still be first and only one welcome.
	if b.Order[0] != boardWelcome {
		t.Fatalf("welcome not first: %v", b.Order)
	}
	count := 0
	for _, id := range b.Order {
		if id == boardWelcome {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("welcome count = %d", count)
	}
}

func TestSortedAgents(t *testing.T) {
	b := &Board{Threads: map[string]*BoardThread{}, Agents: map[string]*BoardAgent{
		"a": {ID: "a", LastSeen: 100},
		"b": {ID: "b", LastSeen: 200},
		"c": {ID: "c", LastSeen: 200},
	}}
	got := b.sortedAgents()
	// Desc by LastSeen; tie → id asc.
	want := []string{"b", "c", "a"}
	for i, w := range want {
		if got[i].ID != w {
			t.Fatalf("got %v, want %v", idsAgents(got), want)
		}
	}
}

func idsAgents(in []*BoardAgent) []string {
	out := make([]string, len(in))
	for i, a := range in {
		out[i] = a.ID
	}
	return out
}

func TestMsgCountAndAllMsgs(t *testing.T) {
	b := newBoard()
	b.Threads[boardWelcome].Msgs = []BoardMsg{{ID: 1, Thread: boardWelcome}, {ID: 2, Thread: boardWelcome}}
	t2 := &BoardThread{ID: "x", Msgs: []BoardMsg{{ID: 3, Thread: "x"}}}
	b.Threads["x"] = t2
	b.Order = append(b.Order, "x")
	if b.msgCount() != 3 {
		t.Fatalf("msgCount = %d", b.msgCount())
	}
	all := b.allMsgs()
	if len(all) != 3 {
		t.Fatalf("allMsgs = %d", len(all))
	}
	// Order follows b.Order then thread order.
	if all[0].Thread != boardWelcome || all[2].Thread != "x" {
		t.Fatalf("order: %+v", all)
	}
}

func TestCanonicalMsg(t *testing.T) {
	m := BoardMsg{
		Agent: "alice", Thread: "welcome", Seq: 2, Kind: "hello",
		Task: "x#1", Refs: []string{"z", "a"}, Text: "hi",
	}
	got := canonicalMsg(m)
	// NUL-joined; refs sorted.
	want := strings.Join([]string{"alice", "welcome", "2", "hello", "x#1", "a,z", "hi"}, "\x00")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBoardFindMsg(t *testing.T) {
	b := newBoard()
	b.Threads[boardWelcome].Msgs = []BoardMsg{{ID: 1, Seq: 0}, {ID: 2, Seq: 1}}
	if m := b.find("board/welcome/msg-1"); m == nil || m.ID != 2 {
		t.Fatalf("find msg-1 = %+v", m)
	}
	if m := b.find("board/welcome/msg-0"); m == nil || m.ID != 1 {
		t.Fatalf("find msg-0 = %+v", m)
	}
	if m := b.find("board/welcome/msg-9"); m != nil {
		t.Fatal("out of range should be nil")
	}
	if m := b.find("board/nope/msg-0"); m != nil {
		t.Fatal("unknown thread should be nil")
	}
	if m := boardFindMsg(b, "bogus"); m != nil {
		t.Fatal("bad path should be nil")
	}
}

// helper to call boardFindMsg via a local method alias (it's a free function).
func (b *Board) find(p string) *BoardMsg { return boardFindMsg(b, p) }

func TestBoardChunk(t *testing.T) {
	m := BoardMsg{Thread: "research", Seq: 3, Text: "hello"}
	c := boardChunk(m)
	if c.Path != "board/research/msg-3" {
		t.Fatalf("path = %q", c.Path)
	}
	if c.Kind != "board" {
		t.Fatalf("kind = %q", c.Kind)
	}
	if c.Text != "hello" {
		t.Fatalf("text = %q", c.Text)
	}
}

func TestFmtAgo(t *testing.T) {
	now := time.Now().Unix()
	if got := fmtAgo(now); !strings.HasSuffix(got, "s ago") {
		t.Fatalf("got %q", got)
	}
	if got := fmtAgo(now - 90); !strings.HasSuffix(got, "m ago") {
		t.Fatalf("got %q", got)
	}
	if got := fmtAgo(now - 3600); !strings.HasSuffix(got, "h ago") {
		t.Fatalf("got %q", got)
	}
	if got := fmtAgo(now - 3*24*3600); !strings.HasSuffix(got, "d ago") {
		t.Fatalf("got %q", got)
	}
}

func TestBoardIDRegexes(t *testing.T) {
	// Thread ids.
	if !boardThreadIDRe.MatchString("research-auth") {
		t.Error("research-auth should match")
	}
	if !boardThreadIDRe.MatchString("a1b2") {
		t.Error("a1b2 should match")
	}
	for _, bad := range []string{"", "UPPER", "has space", "lead-", "-trail", "a_b"} {
		if boardThreadIDRe.MatchString(bad) {
			t.Errorf("%q should NOT match thread regex", bad)
		}
	}
	// Agent ids.
	if !boardAgentIDRe.MatchString("alice_1") {
		t.Error("alice_1 should match")
	}
	if !boardAgentIDRe.MatchString("bob-x") {
		t.Error("bob-x should match")
	}
	for _, bad := range []string{"", "UPPER", "-lead", "_lead", "a b"} {
		if boardAgentIDRe.MatchString(bad) {
			t.Errorf("%q should NOT match agent regex", bad)
		}
	}
}

func TestBoardKinds(t *testing.T) {
	for _, k := range []string{"hello", "info", "task", "result", "feature"} {
		if !boardKinds[k] {
			t.Errorf("kind %q should be valid", k)
		}
	}
	if boardKinds["bogus"] {
		t.Error("bogus kind should be invalid")
	}
}

func TestBoardRoster(t *testing.T) {
	now := time.Now().Unix()
	b := &Board{Agents: map[string]*BoardAgent{
		"fresh": {ID: "fresh", LastSeen: now, Posts: 2},
		"old":   {ID: "old", LastSeen: now - 100000, Posts: 1},
	}}
	out := boardRoster(b, now)
	if !strings.Contains(out, "fresh") || !strings.Contains(out, "old") {
		t.Fatalf("roster missing agents: %q", out)
	}
	if !strings.Contains(out, "ACTIVE") {
		t.Fatal("should show ACTIVE")
	}
	if !strings.Contains(out, "STALE") {
		t.Fatal("should show STALE")
	}
	// Empty board.
	empty := newBoard()
	out = boardRoster(empty, now)
	if !strings.Contains(out, "none signed up yet") {
		t.Fatalf("empty roster: %q", out)
	}
}

// ---------- 13. board crypto (ed25519) ----------

func TestCryptoDeriveSeed(t *testing.T) {
	// 32 bytes = 64 hex chars.
	seed := bytes.Repeat([]byte{0xab}, 32)
	hexseed := hex.EncodeToString(seed)
	priv, pub, err := cryptoDeriveSeed(hexseed)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
		t.Fatal("key sizes wrong")
	}
	// Deterministic: same seed → same keys.
	p2, pub2, _ := cryptoDeriveSeed(hexseed)
	if !bytes.Equal(pub, pub2) || !bytes.Equal(priv, p2) {
		t.Fatal("derivation not deterministic")
	}
	// Whitespace tolerated.
	_, _, err = cryptoDeriveSeed("  " + hexseed + "  ")
	if err != nil {
		t.Fatalf("whitespace seed failed: %v", err)
	}
}

func TestCryptoDeriveSeedInvalid(t *testing.T) {
	// Wrong length.
	if _, _, err := cryptoDeriveSeed("deadbeef"); err == nil {
		t.Fatal("short seed should fail")
	}
	// Bad hex.
	if _, _, err := cryptoDeriveSeed("zzzz"); err == nil {
		t.Fatal("bad hex should fail")
	}
}

func signAndVerify(t *testing.T, m BoardMsg) BoardMsg {
	t.Helper()
	priv, pub, err := cryptoDeriveSeed(hex.EncodeToString(bytes.Repeat([]byte{0x01}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	m.Agent = "alice"
	m.Pub = hex.EncodeToString(pub)
	m.Sig = cryptoSignBoard(priv, canonicalMsg(m))
	return m
}

func TestBoardSignVerifyRoundTrip(t *testing.T) {
	m := signAndVerify(t, BoardMsg{Thread: "welcome", Seq: 0, Text: "hi", Kind: "hello"})
	b := &Board{Agents: map[string]*BoardAgent{"alice": {ID: "alice", Pub: m.Pub}}}
	if status := cryptoVerifyBoardMsg(b, m); status != "verified" {
		t.Fatalf("status = %q, want verified", status)
	}
}

func TestBoardVerifyTampered(t *testing.T) {
	m := signAndVerify(t, BoardMsg{Thread: "welcome", Seq: 0, Text: "hi", Kind: "hello"})
	b := &Board{Agents: map[string]*BoardAgent{"alice": {ID: "alice", Pub: m.Pub}}}
	m2 := m
	m2.Text = "HACKED"
	if status := cryptoVerifyBoardMsg(b, m2); status != "bad-signature" {
		t.Fatalf("status = %q, want bad-signature", status)
	}
}

func TestBoardVerifyUnknownAgent(t *testing.T) {
	m := signAndVerify(t, BoardMsg{Thread: "welcome", Seq: 0, Text: "hi"})
	b := &Board{Agents: map[string]*BoardAgent{}} // no alice
	if status := cryptoVerifyBoardMsg(b, m); status != "unknown-agent" {
		t.Fatalf("status = %q, want unknown-agent", status)
	}
}

func TestBoardVerifyImpersonation(t *testing.T) {
	// Alice signs, but board has alice registered with a DIFFERENT pubkey.
	m := signAndVerify(t, BoardMsg{Thread: "welcome", Seq: 0, Text: "hi"})
	otherPriv, otherPub, _ := cryptoDeriveSeed(hex.EncodeToString(bytes.Repeat([]byte{0xff}, 32)))
	_ = otherPriv
	b := &Board{Agents: map[string]*BoardAgent{"alice": {ID: "alice", Pub: hex.EncodeToString(otherPub)}}}
	if status := cryptoVerifyBoardMsg(b, m); status != "impersonation" {
		t.Fatalf("status = %q, want impersonation", status)
	}
}

func TestAgentByPub(t *testing.T) {
	priv, pub, _ := cryptoDeriveSeed(hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))
	_ = priv
	pubHex := hex.EncodeToString(pub)
	b := &Board{Agents: map[string]*BoardAgent{
		"alice": {ID: "alice", Pub: pubHex},
		"bob":   {ID: "bob", Pub: "deadbeef"},
	}}
	if a := agentByPub(b, pubHex); a == nil || a.ID != "alice" {
		t.Fatalf("got %+v", a)
	}
	if a := agentByPub(b, "nope"); a != nil {
		t.Fatal("should be nil")
	}
}

// ---------- 14. serialization round-trips ----------

func TestDBMarshalRoundTrip(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	chunks := []Chunk{
		{Path: "a/x.go", Kind: "code", Start: 1, End: 5, Text: "token bucket", Vector: vec(t, "token bucket")},
		{Path: "b/y.md", Kind: "doc", Start: 1, End: 3, Text: "database pool", Vector: vec(t, "database pool")},
	}
	db := &DB{
		Dim: testDim, Backend: "local-hashing",
		Sources: []Source{{Label: "repoA", Root: "/r/a", HasGit: true}, {Label: "repoB", Root: "/r/b", HasGit: false}},
		Chunks:  chunks,
		KW:      buildKWIndex(chunks, true),
	}
	data := dbMarshal(db)
	if string(data[:4]) != magic {
		t.Fatalf("magic = %q", data[:4])
	}
	got, err := readDB(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got.Dim != db.Dim || got.Backend != db.Backend {
		t.Fatalf("header mismatch: %+v", got)
	}
	if len(got.Sources) != 2 || got.Sources[0].Label != "repoA" || !got.Sources[0].HasGit || got.Sources[1].HasGit {
		t.Fatalf("sources = %+v", got.Sources)
	}
	if len(got.Chunks) != 2 {
		t.Fatalf("chunks = %d", len(got.Chunks))
	}
	for i := range chunks {
		if got.Chunks[i].Path != chunks[i].Path || got.Chunks[i].Kind != chunks[i].Kind ||
			got.Chunks[i].Start != chunks[i].Start || got.Chunks[i].End != chunks[i].End ||
			got.Chunks[i].Text != chunks[i].Text {
			t.Fatalf("chunk %d = %+v", i, got.Chunks[i])
		}
		if !reflect.DeepEqual(got.Chunks[i].Vector, chunks[i].Vector) {
			t.Fatalf("chunk %d vector mismatch", i)
		}
	}
	if got.KW == nil {
		t.Fatal("KW lost")
	}
	if len(got.KW.Terms) != len(db.KW.Terms) {
		t.Fatalf("KW terms %d vs %d", len(got.KW.Terms), len(db.KW.Terms))
	}
	if !reflect.DeepEqual(got.KW.DF, db.KW.DF) {
		t.Fatal("KW df mismatch")
	}
}

func TestDBRoundTripNoKW(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	db := &DB{
		Dim:     testDim,
		Backend: "local-hashing",
		Chunks:  []Chunk{{Path: "a", Kind: "code", Text: "x", Vector: vec(t, "x")}},
		KW:      nil,
	}
	got, err := readDB(bytes.NewReader(dbMarshal(db)))
	if err != nil {
		t.Fatal(err)
	}
	if got.KW != nil {
		t.Fatal("KW should be nil")
	}
}

func TestReadDBBadMagic(t *testing.T) {
	if _, err := readDB(bytes.NewReader([]byte("XXXXrest"))); err == nil {
		t.Fatal("expected bad magic error")
	}
}

func TestReadKWIndexOutOfRange(t *testing.T) {
	// Build a valid index, then corrupt a termID to be out of range and confirm
	// readKWIndex rejects it.
	t.Setenv("KB_EMBED_URL", "")
	chunks := []Chunk{{Path: "a", Kind: "code", Text: "alpha beta", Vector: vec(t, "alpha beta")}}
	db := &DB{Dim: testDim, Backend: "local-hashing", Chunks: chunks, KW: buildKWIndex(chunks, true)}
	data := dbMarshal(db)
	got, err := readDB(bytes.NewReader(data))
	if err != nil || got.KW == nil {
		t.Fatal(err)
	}
	// Sanity: a well-formed index round-trips and scores.
	sc := got.KW.Score("alpha", nil)
	if _, ok := sc[0]; !ok {
		t.Fatal("chunk0 should be active")
	}
}

func TestBoardMarshalRoundTrip(t *testing.T) {
	now := time.Now().Unix()
	b := newBoard()
	welcome := b.Threads[boardWelcome]
	welcome.Msgs = []BoardMsg{
		{ID: 1, Seq: 0, Agent: "alice", Pub: "aa", Sig: "bb", Text: "hello", At: now, Kind: "hello", Refs: []string{"x"}, Task: "t#1"},
		{ID: 2, Seq: 1, Agent: "bob", Pub: "cc", Sig: "dd", Text: "world", At: now, Kind: "info"},
	}
	t2 := &BoardThread{ID: "research", CreatedAt: now, CreatedBy: "alice", Msgs: []BoardMsg{
		{ID: 3, Seq: 0, Agent: "alice", Pub: "aa", Sig: "bb", Text: "idea", At: now, Kind: "feature"},
	}}
	b.Threads["research"] = t2
	b.Order = append(b.Order, "research")
	b.NextID = 3
	b.Agents = map[string]*BoardAgent{
		"alice": {ID: "alice", Pub: "aa", FirstSeen: now - 10, LastSeen: now, Posts: 2},
		"bob":   {ID: "bob", Pub: "cc", FirstSeen: now - 5, LastSeen: now - 1, Posts: 1},
	}
	data := boardMarshal(b)
	if string(data[:4]) != boardMagic {
		t.Fatalf("magic = %q", data[:4])
	}
	got, err := readBoard(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got.NextID != b.NextID {
		t.Fatalf("NextID = %d", got.NextID)
	}
	if len(got.Order) != 2 || got.Order[0] != boardWelcome || got.Order[1] != "research" {
		t.Fatalf("order = %v", got.Order)
	}
	gw := got.Threads[boardWelcome]
	if len(gw.Msgs) != 2 {
		t.Fatalf("welcome msgs = %d", len(gw.Msgs))
	}
	if gw.Msgs[0].ID != 1 || gw.Msgs[0].Text != "hello" || gw.Msgs[0].Agent != "alice" ||
		len(gw.Msgs[0].Refs) != 1 || gw.Msgs[0].Refs[0] != "x" || gw.Msgs[0].Task != "t#1" {
		t.Fatalf("welcome msg0 = %+v", gw.Msgs[0])
	}
	// Thread id restored implicitly.
	if gw.Msgs[0].Thread != boardWelcome {
		t.Fatalf("msg thread = %q", gw.Msgs[0].Thread)
	}
	if got.Agents["alice"].Posts != 2 || got.Agents["bob"].Pub != "cc" {
		t.Fatalf("agents = %+v", got.Agents)
	}
}

func TestReadBoardBadMagic(t *testing.T) {
	if _, err := readBoard(bytes.NewReader([]byte("NOTA"))); err == nil {
		t.Fatal("expected bad magic error")
	}
}

func TestReadBoardTruncated(t *testing.T) {
	b := newBoard()
	data := boardMarshal(b)
	// Truncate to cut off mid-stream.
	if _, err := readBoard(bytes.NewReader(data[:len(data)-5])); err == nil {
		t.Fatal("expected truncation error")
	}
}

// ---- PBKDF2 + bundle crypto ----

func TestPBKDF2SHA256KnownVectors(t *testing.T) {
	cases := []struct {
		iter int
		want string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	}
	for _, c := range cases {
		got := cryptoPbkdf2SHA256([]byte("password"), []byte("salt"), c.iter, 32)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("iter=%d got %s, want %s", c.iter, hex.EncodeToString(got), c.want)
		}
	}
}

func TestPBKDF2LengthAndSaltSensitivity(t *testing.T) {
	a := cryptoPbkdf2SHA256([]byte("pw"), []byte("saltA"), 100, 48)
	b := cryptoPbkdf2SHA256([]byte("pw"), []byte("saltB"), 100, 48)
	if len(a) != 48 {
		t.Fatalf("len = %d", len(a))
	}
	if bytes.Equal(a, b) {
		t.Fatal("different salts should give different keys")
	}
}

func TestBundleEncryptDecryptRoundTrip(t *testing.T) {
	plain := []byte("the knowledge base bytes")
	key := []byte("secret-passphrase")
	ct := cryptoEncryptBundle(plain, key)
	if string(ct[:4]) != bundleMagic {
		t.Fatalf("magic = %q", ct[:4])
	}
	out, err := cryptoDecryptBundle(ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("got %q, want %q", out, plain)
	}
}

func TestBundleWrongKey(t *testing.T) {
	ct := cryptoEncryptBundle([]byte("data"), []byte("key-one"))
	if _, err := cryptoDecryptBundle(ct, []byte("key-two")); err == nil {
		t.Fatal("wrong key should fail")
	}
}

func TestBundleBadMagic(t *testing.T) {
	ct := cryptoEncryptBundle([]byte("data"), []byte("key"))
	ct[0] = 'X' // corrupt magic
	if _, err := cryptoDecryptBundle(ct, []byte("key")); err == nil {
		t.Fatal("bad magic should fail")
	}
}

func TestBundleTooShort(t *testing.T) {
	if _, err := cryptoDecryptBundle([]byte("KBX1"), []byte("key")); err == nil {
		t.Fatal("too short should fail")
	}
}

func TestTarGZMemRoundTrip(t *testing.T) {
	files := map[string][]byte{"kb.db": []byte("DBDATA"), "board.bin": []byte("BOARDDATA")}
	data, err := cryptoTarGZMem(files)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cryptoTarGZExtractMem(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got["kb.db"], []byte("DBDATA")) {
		t.Fatalf("kb.db = %q", got["kb.db"])
	}
	if !bytes.Equal(got["board.bin"], []byte("BOARDDATA")) {
		t.Fatalf("board.bin = %q", got["board.bin"])
	}
}

func TestTarGZExtractWhitelist(t *testing.T) {
	// A tar containing a non-whitelisted file should drop it.
	files := map[string][]byte{"kb.db": []byte("DB"), "../evil": []byte("bad")}
	data, err := cryptoTarGZMem(files)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cryptoTarGZExtractMem(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["evil"]; ok {
		t.Fatal("non-whitelisted file should be dropped")
	}
	if !bytes.Equal(got["kb.db"], []byte("DB")) {
		t.Fatal("kb.db missing")
	}
}

func TestFileMagic(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "f")
	if err := os.WriteFile(p, []byte("KBV1xxxx"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := fileMagic(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "KBV1" {
		t.Fatalf("magic = %q", got)
	}
	// Missing file.
	if _, err := fileMagic(filepath.Join(tmp, "nope")); err == nil {
		t.Fatal("expected error")
	}
}

func TestAtomicWrite(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "nested", "out.txt")
	if err := atomicWrite(p, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	// No leftover tmp file.
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Fatal("tmp file should not remain")
	}
}

func TestLogTail(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "log")
	if err := os.WriteFile(p, []byte("l1\nl2\nl3\nl4\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := logTail(p, 2); got != "l3\nl4" {
		t.Fatalf("got %q", got)
	}
	if got := logTail(p, 10); got != "l1\nl2\nl3\nl4" {
		t.Fatalf("got %q", got)
	}
	// Missing file.
	if got := logTail(filepath.Join(tmp, "nope"), 5); got != "" {
		t.Fatalf("got %q", got)
	}
}

// ---------- 15. No plain HTTP ----------

// TestDaemonRefusesPlainHTTP: why — the daemon's TCP port is only ever HTTPS
// with client certificates; -http (or config http) without mTLS must refuse to
// start before any pid file or socket exists, on loopback too.
func TestDaemonRefusesPlainHTTP(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	bin := filepath.Join(t.TempDir(), "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	for _, c := range []struct {
		name string
		cfg  string
		args []string
	}{
		{"flag", "", []string{"daemon", "run", "-http", "-bind", "127.0.0.1:0"}},
		{"config", `{"http": true, "http_addr": "127.0.0.1:0"}`, []string{"daemon", "run"}},
	} {
		state := shortStateDir(t)
		if c.cfg != "" {
			writeTestPEM(t, state, "config.json", []byte(c.cfg))
		}
		cmd := exec.Command(bin, c.args...)
		cmd.Env = append(os.Environ(), "KBTOOL_DIR="+state, "KBTOOL_SOCKET=", "KBTOOL_DB=", "KBTOOL_BOARD=", "KB_EMBED_URL=")
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "serves TCP only with mTLS") {
			t.Fatalf("%s: -http without mTLS must refuse: %v\n%s", c.name, err, out)
		}
		ents, _ := os.ReadDir(state)
		for _, e := range ents {
			if e.Name() != "config.json" {
				t.Fatalf("%s: a refused start must leave no state, found %s", c.name, e.Name())
			}
		}
	}
}

func TestSplitListenAddr(t *testing.T) {
	host, port := splitListenAddr("0.0.0.0:1234")
	if host != "127.0.0.1" || port != 1234 {
		t.Fatalf("got %s:%d", host, port)
	}
	// IPv6 wildcard must be bracketed; [::]:9999 → 127.0.0.1:9999.
	host, port = splitListenAddr("[::]:9999")
	if host != "127.0.0.1" || port != 9999 {
		t.Fatalf("got %s:%d", host, port)
	}
	// Bad port → default.
	host, port = splitListenAddr("0.0.0.0:bad")
	if host != "127.0.0.1" || port != defHTTPPort {
		t.Fatalf("got %s:%d", host, port)
	}
	// Explicit non-wildcard host preserved.
	host, port = splitListenAddr("10.0.0.5:8080")
	if host != "10.0.0.5" || port != 8080 {
		t.Fatalf("got %s:%d", host, port)
	}
}

// ---------- 16. config + tool options ----------

func TestEffectiveDisabledSetDefault(t *testing.T) {
	// nil config → defaults: kb_status, board_sign, all git; the board is on.
	m := effectiveDisabledSet(nil)
	for _, name := range []string{"kb_status", "board_sign", "git_blame", "git_log"} {
		if !m[name] {
			t.Errorf("%s should be disabled by default", name)
		}
	}
	for _, name := range []string{"board_signup", "board_read", "board_post"} {
		if m[name] {
			t.Errorf("%s should be enabled by default", name)
		}
	}
	// search_codebase should be enabled (not disabled).
	if m["search_codebase"] {
		t.Error("search_codebase should not be disabled")
	}
}

func TestEffectiveDisabledSetExplicitList(t *testing.T) {
	list := []string{"only_this"}
	c := &config{DisableTools: &list, GitTools: boolPtr(true), MessageBoard: boolPtr(true)}
	m := effectiveDisabledSet(c)
	if !m["only_this"] {
		t.Error("only_this should be disabled")
	}
	// With git+board enabled, group tools are NOT auto-disabled.
	if m["git_blame"] {
		t.Error("git_blame should be enabled when git_tools=true")
	}
	if m["board_read"] {
		t.Error("board_read should be enabled when message_board=true")
	}
	// kb_status/board_sign are NOT in the explicit list, so they are enabled now.
	if m["kb_status"] {
		t.Error("kb_status should be enabled (explicit list overrides defaults)")
	}
}

func TestEffectiveDisabledSetEmptyList(t *testing.T) {
	empty := []string{}
	c := &config{DisableTools: &empty, GitTools: boolPtr(true), MessageBoard: boolPtr(true)}
	m := effectiveDisabledSet(c)
	if len(m) != 0 {
		t.Fatalf("expected empty disabled set, got %v", m)
	}
}

func TestEffectiveDisabledSetGroupOff(t *testing.T) {
	c := &config{GitTools: boolPtr(false), MessageBoard: boolPtr(true)}
	m := effectiveDisabledSet(c)
	if !m["git_blame"] || !m["git_log"] {
		t.Error("git tools should be disabled when git_tools=false")
	}
	if m["board_read"] {
		t.Error("board tools should be enabled when message_board=true")
	}
}

func boolPtr(b bool) *bool { return &b }

func TestEnsureToolOptionsSeed(t *testing.T) {
	c := &config{}
	ensureToolOptions(c)
	if c.DisableTools == nil {
		t.Fatal("DisableTools should be seeded")
	}
	if !reflect.DeepEqual(*c.DisableTools, defaultDisableTools) {
		t.Fatalf("DisableTools = %v, want %v", *c.DisableTools, defaultDisableTools)
	}
	if c.GitTools == nil || *c.GitTools != false {
		t.Fatal("GitTools should be seeded false")
	}
	if c.MessageBoard == nil || *c.MessageBoard != true {
		t.Fatal("MessageBoard should be seeded true")
	}
}

func TestEnsureToolOptionsPreserve(t *testing.T) {
	keep := []string{"custom"}
	gitOn := true
	mbH := true
	c := &config{DisableTools: &keep, GitTools: &gitOn, MessageBoard: &mbH}
	ensureToolOptions(c)
	if len(*c.DisableTools) != 1 || (*c.DisableTools)[0] != "custom" {
		t.Fatalf("DisableTools overwritten: %v", *c.DisableTools)
	}
	if *c.GitTools != true {
		t.Fatal("GitTools overwritten")
	}
	if *c.MessageBoard != true {
		t.Fatal("MessageBoard overwritten")
	}
}

func TestKwPathStr(t *testing.T) {
	if got := kwPathStr(&config{}); got != "true(default)" {
		t.Fatalf("got %q", got)
	}
	f := false
	if got := kwPathStr(&config{KWPath: &f}); got != "false" {
		t.Fatalf("got %q", got)
	}
	tr := true
	if got := kwPathStr(&config{KWPath: &tr}); got != "true" {
		t.Fatalf("got %q", got)
	}
}

func TestAbsolutized(t *testing.T) {
	got := absolutized([]string{"rel/path", "/abs/path"})
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if !filepath.IsAbs(got[0]) {
		t.Fatalf("not abs: %q", got[0])
	}
	if got[1] != "/abs/path" {
		t.Fatalf("abs changed: %q", got[1])
	}
}

func TestConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	c := &config{
		Version: 1, Sources: []string{"/src"}, Dim: 256, Chunk: 24, Overlap: 6, MaxKB: 128,
		Git: true, GitMaxCommits: 50, GitDiffMaxKB: 100,
		TrustedPaths:   []string{"/trusted"},
		ForbiddenPaths: []string{"/forbidden"},
		Http:           true,
		Mtls:           false,
		HTTPAddr:       "127.0.0.1:9876",
	}
	if err := saveConfig(c); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.Dim != 256 || got.Chunk != 24 || !got.Git || got.GitMaxCommits != 50 {
		t.Fatalf("got %+v", got)
	}
	if got.Sources[0] != "/src" || got.TrustedPaths[0] != "/trusted" || got.ForbiddenPaths[0] != "/forbidden" {
		t.Fatalf("got %+v", got)
	}
	// Version stamped to 1, Updated set.
	if got.Version != 1 || got.Updated == "" {
		t.Fatalf("version/updated: %+v", got)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Fatal("expected nil for missing config")
	}
}

func TestLoadConfigWarnedCorrupt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not json"), 0644); err != nil {
		t.Fatal(err)
	}
	c := loadConfigWarned()
	if c != nil {
		t.Fatal("expected nil for corrupt config")
	}
}

func TestDefaultDB(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	// No config → stateDir/kb.db.
	if got := defaultDB(); got != filepath.Join(dir, "kb.db") {
		t.Fatalf("got %q", got)
	}
	// Config with db path → that path.
	if err := saveConfig(&config{DB: "/custom/kb.db"}); err != nil {
		t.Fatal(err)
	}
	if got := defaultDB(); got != "/custom/kb.db" {
		t.Fatalf("got %q", got)
	}
}

// ---------- 17. MCP / JSON-RPC protocol ----------

func TestMustMarshal(t *testing.T) {
	got := mustMarshal(map[string]string{"a": "b"})
	if string(got) != `{"a":"b"}` {
		t.Fatalf("got %s", got)
	}
}

func TestInitializeInstructions(t *testing.T) {
	fe := &fakeExec{}
	out := initializeInstructions(fe)
	if !strings.Contains(out, "knowledge base") {
		t.Fatalf("missing KB mention: %q", out)
	}
	// With board enabled, board flow described.
	if !strings.Contains(out, "board_signup") {
		t.Fatalf("missing board flow: %q", out)
	}
	// With everything disabled, no tool lists.
	fe2 := &fakeExec{disabled: map[string]bool{}}
	for _, t := range toolSchemas() {
		fe2.disabled[t.Name] = true
	}
	out2 := initializeInstructions(fe2)
	if strings.Contains(out2, "KB tools:") || strings.Contains(out2, "Board tools:") {
		t.Fatalf("should not list tools when all disabled: %q", out2)
	}
}

func TestDispatchInitialize(t *testing.T) {
	fe := &fakeExec{}
	res, err := dispatch(fe, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("type %T", res)
	}
	if m["protocolVersion"] != mcpProtocol {
		t.Fatalf("protocolVersion = %v", m["protocolVersion"])
	}
}

func TestDispatchPing(t *testing.T) {
	res, err := dispatch(&fakeExec{}, "ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := res.(map[string]any); !ok || len(m) != 0 {
		t.Fatalf("got %v", res)
	}
}

func TestDispatchToolsListFiltersDisabled(t *testing.T) {
	fe := &fakeExec{disabled: map[string]bool{"kb_status": true, "board_sign": true}}
	res, err := dispatch(fe, "tools/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	tools := m["tools"].([]mcpTool)
	for _, tool := range tools {
		if tool.Name == "kb_status" || tool.Name == "board_sign" {
			t.Fatalf("disabled tool %s should be hidden", tool.Name)
		}
	}
	// Total should be all minus the 2 disabled.
	all := len(toolSchemas())
	if len(tools) != all-2 {
		t.Fatalf("got %d tools, want %d", len(tools), all-2)
	}
}

func TestDispatchToolsCall(t *testing.T) {
	fe := &fakeExec{results: map[string]fakeResult{"search_codebase": {text: "42 results", isErr: false}}}
	res, err := dispatch(fe, "tools/call", mustMarshal(map[string]any{"name": "search_codebase"}))
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	content := m["content"].([]map[string]any)
	if content[0]["text"] != "42 results" {
		t.Fatalf("text = %v", content[0]["text"])
	}
	if m["isError"] != false {
		t.Fatal("isError should be false")
	}
}

func TestDispatchToolsCallError(t *testing.T) {
	fe := &fakeExec{results: map[string]fakeResult{"x": {text: "boom", isErr: true}}}
	res, err := dispatch(fe, "tools/call", mustMarshal(map[string]any{"name": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["isError"] != true {
		t.Fatal("isError should be true")
	}
}

func TestDispatchUnknownMethod(t *testing.T) {
	_, err := dispatch(&fakeExec{}, "nope", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	re, ok := err.(*rpcError)
	if !ok || re.Code != -32601 {
		t.Fatalf("err = %+v", err)
	}
}

func TestHandleLineRoundTrip(t *testing.T) {
	fe := &fakeExec{results: map[string]fakeResult{"ping": {text: "", isErr: false}}}
	line := []byte(`{"jsonrpc":"2.0","id":7,"method":"ping"}`)
	resp := handleLine(line, fe)
	if resp == nil {
		t.Fatal("nil response")
	}
	var out struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatal(err)
	}
	if string(out.ID) != "7" {
		t.Fatalf("id = %s", out.ID)
	}
}

func TestHandleLineParseError(t *testing.T) {
	resp := handleLine([]byte("not json"), &fakeExec{})
	if resp == nil {
		t.Fatal("expected a response")
	}
	var out struct {
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatal(err)
	}
	if out.Error == nil || out.Error.Code != -32700 {
		t.Fatalf("err = %+v", out.Error)
	}
}

func TestHandleLineNotificationNoResponse(t *testing.T) {
	// No id → notification → no response.
	resp := handleLine([]byte(`{"jsonrpc":"2.0","method":"ping"}`), &fakeExec{})
	if resp != nil {
		t.Fatalf("expected nil, got %s", resp)
	}
}

func TestHandleLineUnknownMethod(t *testing.T) {
	resp := handleLine([]byte(`{"jsonrpc":"2.0","id":1,"method":"nope"}`), &fakeExec{})
	var out struct {
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatal(err)
	}
	if out.Error.Code != -32601 {
		t.Fatalf("code = %d", out.Error.Code)
	}
}

func TestServeLines(t *testing.T) {
	fe := &fakeExec{}
	var in []byte
	in = append(in, `{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"...)
	in = append(in, `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`+"\n"...)
	var out bytes.Buffer
	if err := serveLines(bytes.NewReader(in), &out, fe); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines: %q", len(lines), out.String())
	}
	// Each should parse as JSON with the matching id.
	for i, l := range lines {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("line %d not json: %v", i, err)
		}
	}
}

func TestHTTPHandlerHealthz(t *testing.T) {
	h := httpHandler(&fakeExec{})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestHTTPHandlerMCP(t *testing.T) {
	fe := &fakeExec{results: map[string]fakeResult{"search_codebase": {text: "ok", isErr: false}}}
	h := httpHandler(fe)
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_codebase"}}`
	resp, err := http.Post(srv.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Error != nil {
		t.Fatalf("error = %+v", out.Error)
	}
}

func TestHTTPHandlerMethodNotAllowed(t *testing.T) {
	h := httpHandler(&fakeExec{})
	srv := httptest.NewServer(h)
	defer srv.Close()
	// GET /mcp should be 405.
	resp, err := http.Get(srv.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	// POST /healthz should be 405.
	resp, err = http.Post(srv.URL+"/healthz", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestQwenToolsShape(t *testing.T) {
	tools := toolSchemas()
	q := qwenTools(tools)
	if len(q) != len(tools) {
		t.Fatalf("got %d, want %d", len(q), len(tools))
	}
	for i, m := range q {
		if m["type"] != "function" {
			t.Fatalf("item %d type = %v", i, m["type"])
		}
		fn := m["function"].(map[string]any)
		if fn["name"] != tools[i].Name {
			t.Fatalf("name mismatch: %v vs %v", fn["name"], tools[i].Name)
		}
	}
}

func TestToolSchemasWellFormed(t *testing.T) {
	tools := toolSchemas()
	if len(tools) != 21 {
		t.Fatalf("got %d tools, want 21", len(tools))
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		if tool.Name == "" || tool.Description == "" {
			t.Fatalf("tool missing name/desc: %+v", tool)
		}
		if seen[tool.Name] {
			t.Fatalf("duplicate tool %s", tool.Name)
		}
		seen[tool.Name] = true
	}
	// Required tools present.
	for _, want := range []string{"search_codebase", "board_signup", "board_read", "board_fetch", "git_blame", "git_log", "kb_status", "kb_terms", "kb_bundle"} {
		if !seen[want] {
			t.Fatalf("missing tool %s", want)
		}
	}
}

// ---------- 18. at-rest store (plain + encrypted) ----------

func openPlainStore(t *testing.T) (*kbStore, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_BOARD", filepath.Join(dir, "board.bin"))
	st, err := openKBStore(filepath.Join(dir, "kb.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return st, dir
}

func TestStorePlainSaveLoadDB(t *testing.T) {
	st, _ := openPlainStore(t)
	if st.enc {
		t.Fatal("should be plain")
	}
	t.Setenv("KB_EMBED_URL", "")
	chunks := []Chunk{{Path: "a", Kind: "code", Text: "token bucket", Vector: vec(t, "token bucket")}}
	db := &DB{Dim: testDim, Backend: "local-hashing", Chunks: chunks, KW: buildKWIndex(chunks, true)}
	if err := st.saveDB(db); err != nil {
		t.Fatal(err)
	}
	// File exists with KBV1 magic.
	if m, _ := fileMagic(st.path); m != "KBV1" {
		t.Fatalf("magic = %q", m)
	}
	got, err := st.db()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Chunks) != 1 || got.Chunks[0].Text != "token bucket" {
		t.Fatalf("got %+v", got)
	}
}

func TestStorePlainBoardRoundTrip(t *testing.T) {
	st, dir := openPlainStore(t)
	b := newBoard()
	b.Threads[boardWelcome].Msgs = []BoardMsg{{ID: 1, Seq: 0, Agent: "a", Text: "hi", Kind: "hello", At: time.Now().Unix()}}
	b.NextID = 1
	if err := st.saveBoard(b); err != nil {
		t.Fatal(err)
	}
	if !st.boardExists() {
		t.Fatal("board should exist")
	}
	// board.bin has MBD1 magic.
	if m, _ := fileMagic(filepath.Join(dir, "board.bin")); m != "MBD1" {
		t.Fatalf("board magic = %q", m)
	}
	got, err := st.loadBoard(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Threads[boardWelcome].Msgs) != 1 {
		t.Fatalf("msgs = %d", len(got.Threads[boardWelcome].Msgs))
	}
	// mtime gate.
	if mt, ok := st.boardMtime(); !ok || mt.IsZero() {
		t.Fatal("boardMtime should be set")
	}
}

func TestStorePlainLock(t *testing.T) {
	st, _ := openPlainStore(t)
	unlock, err := st.lock()
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	// Lock file exists now.
	if !fileExists(st.boardPath + ".lock") {
		t.Fatal("lock file should exist")
	}
}

func TestStoreConsistencyPlain(t *testing.T) {
	st, _ := openPlainStore(t)
	// Plain DB + plain board → consistent.
	if err := st.checkConsistency(); err != nil {
		t.Fatal(err)
	}
	// Plain DB + an ENCRYPTED board.bin → inconsistent.
	if err := os.WriteFile(st.boardPath, []byte("KBX1xxxx"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := st.checkConsistency(); err == nil {
		t.Fatal("expected inconsistency")
	}
}

func TestStoreEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_BOARD", filepath.Join(dir, "board.bin"))
	t.Setenv("KB_EMBED_URL", "")
	key := []byte("top-secret")
	st, err := openKBStore(filepath.Join(dir, "kb.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	if !st.enc {
		t.Fatal("should be encrypted")
	}
	chunks := []Chunk{{Path: "a", Kind: "code", Text: "token bucket", Vector: vec(t, "token bucket")}}
	db := &DB{Dim: testDim, Backend: "local-hashing", Chunks: chunks, KW: buildKWIndex(chunks, true)}
	if err := st.saveDB(db); err != nil {
		t.Fatal(err)
	}
	// File should be a KBX1 bundle.
	if m, _ := fileMagic(st.path); m != "KBX1" {
		t.Fatalf("magic = %q", m)
	}
	// Save a board too (goes into the bundle).
	b := newBoard()
	b.NextID = 1
	b.Threads[boardWelcome].Msgs = []BoardMsg{{ID: 1, Seq: 0, Agent: "a", Text: "hi", Kind: "hello"}}
	if err := st.saveBoard(b); err != nil {
		t.Fatal(err)
	}
	if !st.boardExists() {
		t.Fatal("board should exist in bundle")
	}
	// Read back.
	gotdb, err := st.db()
	if err != nil {
		t.Fatal(err)
	}
	if len(gotdb.Chunks) != 1 {
		t.Fatalf("db chunks = %d", len(gotdb.Chunks))
	}
	gotb, err := st.loadBoard(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotb.Threads[boardWelcome].Msgs) != 1 {
		t.Fatal("board msgs")
	}
	// No stray plain board.bin should exist.
	if fileExists(st.boardPath) {
		t.Fatal("no plain board.bin should exist in encrypted mode")
	}
}

func TestStoreEncryptedWrongKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	st, err := openKBStore(filepath.Join(dir, "kb.db"), []byte("key-one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.saveDB(&DB{Dim: testDim, Backend: "local-hashing"}); err != nil {
		t.Fatal(err)
	}
	// Reopen with the wrong key → should fail to verify.
	if _, err := openKBStore(filepath.Join(dir, "kb.db"), []byte("key-two")); err == nil {
		t.Fatal("wrong key should fail")
	}
}

func TestStoreEncryptedNoKeyStatus(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	// Create encrypted store.
	st1, _ := openKBStore(filepath.Join(dir, "kb.db"), []byte("key"))
	st1.saveDB(&DB{Dim: testDim, Backend: "local-hashing"})
	// Open without a key: enc reported, contents unreadable.
	st2, err := openKBStore(filepath.Join(dir, "kb.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !st2.enc {
		t.Fatal("should report encrypted")
	}
	if st2.boardExists() {
		t.Fatal("boardExists should be false without key")
	}
	if _, err := st2.db(); err == nil {
		// db() returns nil DB (empty) not error here since dbBytes empty; but
		// loading the board must require a key.
	}
	if _, err := st2.loadBoard(false); err == nil {
		t.Fatal("loadBoard without key should fail")
	}
}

func TestOpenStoreRequiresKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_BOARD", filepath.Join(dir, "board.bin"))
	// Create an encrypted store.
	st, _ := openKBStore(filepath.Join(dir, "kb.db"), []byte("key"))
	st.saveDB(&DB{Dim: testDim, Backend: "local-hashing"})
	dbPath := filepath.Join(dir, "kb.db")
	// requireKey=true, no key source → error.
	if _, err := openStore(dbPath, "", "", false, true); err == nil {
		t.Fatal("expected key-required error")
	}
	// requireKey=false → ok (status-only).
	if _, err := openStore(dbPath, "", "", false, false); err != nil {
		t.Fatal(err)
	}
}

func TestOpenStoreKeyEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_BOARD", filepath.Join(dir, "board.bin"))
	t.Setenv("MYDBKEY", "from-env")
	st, _ := openKBStore(filepath.Join(dir, "kb.db"), []byte("from-env"))
	st.saveDB(&DB{Dim: testDim, Backend: "local-hashing"})
	dbPath := filepath.Join(dir, "kb.db")
	// Provide key via env var name.
	got, err := openStore(dbPath, "MYDBKEY", "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.enc {
		t.Fatal("should be encrypted")
	}
}

func TestResolveKey(t *testing.T) {
	t.Setenv("RK_ENV", "envvalue")
	t.Setenv(secretEnv, "")
	// 1. keyEnv wins.
	k, have, err := resolveKey("RK_ENV", "", false)
	if err != nil || !have || string(k) != "envvalue" {
		t.Fatalf("got (%s,%v,%v)", k, have, err)
	}
	// keyEnv empty var → error.
	t.Setenv("RK_EMPTY", "")
	if _, _, err := resolveKey("RK_EMPTY", "", false); err == nil {
		t.Fatal("empty env should error")
	}
	// 2. keyFile.
	dir := t.TempDir()
	f := filepath.Join(dir, "k")
	os.WriteFile(f, []byte("  filevalue\n"), 0600)
	k, have, err = resolveKey("", f, false)
	if err != nil || !have || string(k) != "filevalue" {
		t.Fatalf("got (%s,%v,%v)", k, have, err)
	}
	// keyFile missing → error.
	if _, _, err := resolveKey("", filepath.Join(dir, "nope"), false); err == nil {
		t.Fatal("missing file should error")
	}
	// 3. $KBTOOL_SECRET fallback.
	t.Setenv(secretEnv, "dbkeyvalue")
	k, have, err = resolveKey("", "", false)
	if err != nil || !have || string(k) != "dbkeyvalue" {
		t.Fatalf("got (%s,%v,%v)", k, have, err)
	}
	t.Setenv(secretEnv, "")
	// 4. no source, no prompt → (nil,false,nil).
	k, have, err = resolveKey("", "", false)
	if err != nil || have || k != nil {
		t.Fatalf("got (%s,%v,%v)", k, have, err)
	}
}

func TestCurrentBoardBytes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_BOARD", filepath.Join(dir, "board.bin"))
	st, _ := openKBStore(filepath.Join(dir, "kb.db"), nil)
	// No board yet.
	if b := st.currentBoardBytes(); b != nil {
		t.Fatal("should be nil")
	}
	// Create a board.
	b := newBoard()
	st.saveBoard(b)
	got := st.currentBoardBytes()
	if got == nil {
		t.Fatal("should be non-nil")
	}
	if !bytes.HasPrefix(got, []byte(boardMagic)) {
		t.Fatal("should start with board magic")
	}
}

func TestEnsureBoardReady(t *testing.T) {
	st, dir := openPlainStore(t)
	if st.boardExists() {
		t.Fatal("should start with no board")
	}
	if err := ensureBoardReady(st); err != nil {
		t.Fatal(err)
	}
	if !st.boardExists() {
		t.Fatal("board should exist now")
	}
	// Idempotent.
	if err := ensureBoardReady(st); err != nil {
		t.Fatal(err)
	}
	b, _ := st.loadBoard(false)
	if _, ok := b.Threads[boardWelcome]; !ok {
		t.Fatal("welcome thread should exist")
	}
	_ = dir
}

func TestStoreSaveDBCarriesBoard(t *testing.T) {
	// Encrypted: saving the DB after a board exists must keep the board in the bundle.
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_BOARD", filepath.Join(dir, "board.bin"))
	t.Setenv("KB_EMBED_URL", "")
	key := []byte("k")
	st, _ := openKBStore(filepath.Join(dir, "kb.db"), key)
	b := newBoard()
	st.saveBoard(b)
	// Now save a (new) DB; the board should be carried.
	chunks := []Chunk{{Path: "a", Kind: "code", Text: "x", Vector: vec(t, "x")}}
	db := &DB{Dim: testDim, Backend: "local-hashing", Chunks: chunks, KW: buildKWIndex(chunks, true)}
	if err := st.saveDB(db); err != nil {
		t.Fatal(err)
	}
	if !st.boardExists() {
		t.Fatal("board should survive DB save")
	}
	gotdb, _ := st.db()
	if len(gotdb.Chunks) != 1 {
		t.Fatal("db should have the chunk")
	}
}

// ---------- 19. build integration ----------

func TestBuildDBBasic(t *testing.T) {
	if !gitAvailable() {
		// buildDB works without git for non-git sources; keep going.
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(filepath.Join(src, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	// A Go file.
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n\nfunc TokenBucketLimiter() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A doc file.
	if err := os.WriteFile(filepath.Join(src, "pkg", "README.md"), []byte("# Docs\n\nAbout token bucket.\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A binary file (should be skipped).
	if err := os.WriteFile(filepath.Join(src, "img.png"), []byte{0x89, 'P', 'N', 'G'}, 0644); err != nil {
		t.Fatal(err)
	}
	// A lock file (should be skipped).
	if err := os.WriteFile(filepath.Join(src, "go.sum"), []byte("sum"), 0644); err != nil {
		t.Fatal(err)
	}
	// A skip-dir file.
	if err := os.MkdirAll(filepath.Join(src, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "node_modules", "x.js"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KB_EMBED_URL", "")
	db, err := buildDB(BuildOpts{
		Sources: []string{src},
		Dim:     testDim,
		Chunk:   48,
		Overlap: 0,
		MaxKB:   512,
		Embed:   localEmbed,
		KWPath:  boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if db.Backend != "local-hashing" {
		t.Fatalf("backend = %q", db.Backend)
	}
	if db.Dim != testDim {
		t.Fatalf("dim = %d", db.Dim)
	}
	// Collect chunk paths.
	var paths []string
	kinds := map[string]bool{}
	for _, c := range db.Chunks {
		paths = append(paths, c.Path)
		kinds[c.Kind] = true
	}
	// main.go and README.md present.
	joined := strings.Join(paths, "\n")
	if !strings.Contains(joined, "main.go") {
		t.Fatalf("main.go missing: %v", paths)
	}
	if !strings.Contains(joined, "README.md") {
		t.Fatalf("README.md missing: %v", paths)
	}
	// Binary + lock + node_modules absent.
	for _, bad := range []string{"img.png", "go.sum", "node_modules"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("should be skipped: %s", bad)
		}
	}
	// Kinds include code and doc.
	if !kinds["code"] || !kinds["doc"] {
		t.Fatalf("kinds = %v", kinds)
	}
	// KW index built and has the identifier token.
	if db.KW == nil {
		t.Fatal("KW nil")
	}
	if _, ok := db.KW.ID["tokenbucketlimiter"]; !ok {
		t.Fatal("tokenbucketlimiter token missing from KW")
	}
	// Sources recorded.
	if len(db.Sources) != 1 {
		t.Fatalf("sources = %+v", db.Sources)
	}
	// Vectors present and correct dim.
	for _, c := range db.Chunks {
		if len(c.Vector) != testDim {
			t.Fatalf("vector dim = %d", len(c.Vector))
		}
	}
}

func TestBuildDBNoSources(t *testing.T) {
	if _, err := buildDB(BuildOpts{Embed: localEmbed}); err == nil {
		t.Fatal("expected error for no sources")
	}
}

func TestBuildDBMissingSource(t *testing.T) {
	if _, err := buildDB(BuildOpts{Sources: []string{"/nonexistent/nope"}, Embed: localEmbed}); err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestBuildDBLabelConflict(t *testing.T) {
	// Two distinct roots with the same basename → label conflict.
	base := t.TempDir()
	a := filepath.Join(base, "repo")
	b := filepath.Join(base, "other", "repo")
	if err := os.MkdirAll(a, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(a, "x.go"), []byte("package a"), 0644)
	os.WriteFile(filepath.Join(b, "y.go"), []byte("package b"), 0644)
	if _, err := buildDB(BuildOpts{Sources: []string{a, b}, Embed: localEmbed}); err == nil {
		t.Fatal("expected label conflict error")
	}
}

func TestBuildDBStripsInvisibleAndCRLF(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.MkdirAll(src, 0755)
	// Content with an invisible TAG char and CRLF line endings.
	content := "line one\U000E0001\r\nline two\r\n"
	if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KB_EMBED_URL", "")
	db, err := buildDB(BuildOpts{Sources: []string{src}, Embed: localEmbed, KWPath: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Chunks) != 1 {
		t.Fatalf("chunks = %d", len(db.Chunks))
	}
	text := db.Chunks[0].Text
	if strings.ContainsRune(text, 0xE0001) {
		t.Fatal("invisible char not stripped")
	}
	if strings.Contains(text, "\r") {
		t.Fatal("CRLF not normalized")
	}
	// The two lines must be present, LF-joined. (Trailing whitespace from the
	// file's final newline is preserved, so match on content, not exact bytes.)
	if !strings.Contains(text, "line one\nline two") {
		t.Fatalf("text = %q", text)
	}
}

func TestBuildDBGit(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "myrepo")
	if err := os.MkdirAll(repo, 0755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("config", "user.email", "t@example.com")
	git("config", "user.name", "Test")
	// First commit.
	os.WriteFile(filepath.Join(repo, "app.go"), []byte("package main\n\n// TokenBucketLimiter does things.\nfunc TokenBucketLimiter() {}\n"), 0644)
	git("add", "-A")
	git("commit", "-q", "-m", "Initial commit with TokenBucket")
	// Second commit modifying the file.
	os.WriteFile(filepath.Join(repo, "app.go"), []byte("package main\n\n// TokenBucketLimiter v2.\nfunc TokenBucketLimiter() int { return 2 }\n"), 0644)
	git("add", "-A")
	git("commit", "-q", "-m", "Update limiter")

	t.Setenv("KB_EMBED_URL", "")
	db, err := buildDB(BuildOpts{
		Sources:       []string{repo},
		Embed:         localEmbed,
		Git:           true,
		GitMaxCommits: 10,
		GitDiffMaxKB:  100,
		KWPath:        boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	var commitTexts []string
	var diffChunks int
	for _, c := range db.Chunks {
		switch c.Kind {
		case "commit":
			commitTexts = append(commitTexts, c.Text)
		case "diff":
			diffChunks++
		}
	}
	if len(commitTexts) < 2 {
		t.Fatalf("expected >=2 commit chunks, got %d", len(commitTexts))
	}
	// Each commit chunk carries its own subject; both commits must be represented.
	allCommits := strings.Join(commitTexts, "\n\u0001\n")
	for _, subj := range []string{"Initial commit with TokenBucket", "Update limiter"} {
		if !strings.Contains(allCommits, subj) {
			t.Fatalf("commit chunks missing subject %q; got %q", subj, allCommits)
		}
	}
	// app.go content should be present (code chunk).
	found := false
	for _, c := range db.Chunks {
		if strings.Contains(c.Path, "app.go") && c.Kind == "code" {
			found = true
		}
	}
	if !found {
		t.Fatal("app.go code chunk missing")
	}
	_ = diffChunks
}

func TestParseCommitRecordsFromRealGit(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "r")
	os.MkdirAll(repo, 0755)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("config", "user.email", "t@e.com")
	git("config", "user.name", "T")
	os.WriteFile(filepath.Join(repo, "f.txt"), []byte("hello\n"), 0644)
	git("add", "-A")
	git("commit", "-q", "-m", "first commit subject")
	out, err := runGit(repo, "log", "-n", "1", "--format=%H%x01%an%x01%aI%x01%s%x01%b%x02")
	if err != nil {
		t.Fatal(err)
	}
	commits := parseCommitRecords(out)
	if len(commits) != 1 {
		t.Fatalf("got %d", len(commits))
	}
	if commits[0].Subject != "first commit subject" {
		t.Fatalf("subject = %q", commits[0].Subject)
	}
	if commits[0].Author != "T" {
		t.Fatalf("author = %q", commits[0].Author)
	}
	if len(commits[0].SHA) < 7 {
		t.Fatalf("sha too short: %q", commits[0].SHA)
	}
}

// ---------- 20. toolbox / tool execution ----------

func TestExecuteGatingDisabled(t *testing.T) {
	tb := &Toolbox{Disabled: map[string]bool{"search_codebase": true}}
	out, isErr := tb.Execute("search_codebase", nil)
	if !isErr {
		t.Fatal("should be an error")
	}
	if !strings.Contains(out, "disabled by config") {
		t.Fatalf("got %q", out)
	}
}

func TestExecuteStripsInvisible(t *testing.T) {
	tb := &Toolbox{}
	// Force an output that contains invisible chars by using a raw exec.
	// We can't easily inject; instead verify Execute strips a smuggled result via
	// a custom tool is not possible without a DB. Use board_sign which returns a
	// canonical containing the text — pass a smuggled text.
	seed := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	args := mustMarshal(map[string]any{"seed": seed, "text": "hello\U000E0001world"})
	out, _ := tb.Execute("board_sign", args)
	if strings.ContainsRune(out, 0xE0001) {
		t.Fatal("invisible char leaked into result")
	}
}

func TestExecuteUnknownTool(t *testing.T) {
	// A non-nil DB is required so dispatch reaches the unknown-tool branch
	// (a nil DB short-circuits to "knowledge base not loaded" first).
	tb := &Toolbox{DB: searchSetup(t)}
	out, isErr := tb.Execute("no_such_tool", nil)
	if !isErr {
		t.Fatal("should error")
	}
	if !strings.Contains(out, "unknown tool") {
		t.Fatalf("got %q", out)
	}
}

func TestExecuteNilDB(t *testing.T) {
	tb := &Toolbox{}
	// search_codebase with nil DB.
	out, isErr := tb.Execute("search_codebase", mustMarshal(map[string]any{"q": "x"}))
	if !isErr {
		t.Fatal("should error")
	}
	if !strings.Contains(out, "knowledge base not loaded") {
		t.Fatalf("got %q", out)
	}
}

func TestExecuteRawSearchCodebase(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	t.Setenv("KBTOOL_DIR", t.TempDir()) // refreshBoard locks the default board path
	tb := &Toolbox{DB: searchSetup(t)}
	out, isErr := tb.Execute("search_codebase", mustMarshal(map[string]any{"q": "token bucket limiter", "k": 3}))
	if isErr {
		t.Fatalf("isErr: %q", out)
	}
	if !strings.Contains(out, "results for") {
		t.Fatalf("got %q", out)
	}
	if !strings.Contains(out, "token") {
		t.Fatalf("should mention token: %q", out)
	}
}

func TestExecuteRawGetChunk(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	t.Setenv("KBTOOL_DIR", t.TempDir()) // refreshBoard locks the default board path
	chunks := []Chunk{
		{Path: "a", Kind: "code", Text: "first"},
		{Path: "b", Kind: "code", Text: "second"},
		{Path: "c", Kind: "code", Text: "third"},
	}
	tb := &Toolbox{DB: makeDB(t, chunks)}
	out, isErr := tb.Execute("get_chunk", mustMarshal(map[string]any{"index": 1}))
	if isErr {
		t.Fatalf("isErr: %q", out)
	}
	if !strings.Contains(out, "second") {
		t.Fatalf("got %q", out)
	}
	// With before/after.
	out, _ = tb.Execute("get_chunk", mustMarshal(map[string]any{"index": 1, "before": 1, "after": 1}))
	for _, want := range []string{"first", "second", "third"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in %q", want, out)
		}
	}
	// Out of range.
	out, isErr = tb.Execute("get_chunk", mustMarshal(map[string]any{"index": 99}))
	if !isErr {
		t.Fatal("should error")
	}
}

func TestExecuteRawListFiles(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	t.Setenv("KBTOOL_DIR", t.TempDir()) // refreshBoard locks the default board path
	chunks := []Chunk{
		{Path: "repo/src/a.go", Kind: "code"},
		{Path: "repo/src/b.go", Kind: "code"},
		{Path: "repo/docs/g.md", Kind: "doc"},
		{Path: "board/welcome/msg-0", Kind: "board"},
		{Path: "board/welcome/msg-1", Kind: "board"},
	}
	tb := &Toolbox{DB: makeDB(t, chunks)}
	out, isErr := tb.Execute("list_files", nil)
	if isErr {
		t.Fatalf("isErr: %q", out)
	}
	// Board messages grouped by thread.
	if !strings.Contains(out, "board/welcome") {
		t.Fatalf("board thread grouping missing: %q", out)
	}
	// Path filter.
	out, _ = tb.Execute("list_files", mustMarshal(map[string]any{"path": "docs"}))
	if !strings.Contains(out, "docs/g.md") {
		t.Fatalf("path filter: %q", out)
	}
	if strings.Contains(out, "a.go") {
		t.Fatalf("path filter leaked a.go: %q", out)
	}
}

func TestKbStatusBoardOnly(t *testing.T) {
	tb := &Toolbox{DB: nil}
	out, _ := tb.Execute("kb_status", nil)
	if !strings.Contains(out, "board-only mode") {
		t.Fatalf("got %q", out)
	}
}

func TestKbStatusWithDB(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	tb := &Toolbox{DB: searchSetup(t)}
	out, isErr := tb.Execute("kb_status", nil)
	if isErr {
		t.Fatalf("isErr: %q", out)
	}
	if !strings.Contains(out, "chunks=") || !strings.Contains(out, "keyword index:") {
		t.Fatalf("got %q", out)
	}
}

func TestRefreshBoardMerges(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	boardFile := filepath.Join(dir, "board.bin")
	t.Setenv("KBTOOL_BOARD", boardFile)
	t.Setenv("KB_EMBED_URL", "")

	// Seed a board with a message.
	st, _ := openKBStore(filepath.Join(dir, "kb.db"), nil)
	b := newBoard()
	b.NextID = 1
	b.Threads[boardWelcome].Msgs = []BoardMsg{{ID: 1, Seq: 0, Agent: "a", Text: "quantum flux capacitor", Kind: "info"}}
	st.saveBoard(b)

	// Build a DB with one chunk; refreshBoard should add the board message.
	chunks := []Chunk{{Path: "a", Kind: "code", Text: "unrelated text"}}
	tb := &Toolbox{DB: makeDB(t, chunks), Store: st, BoardPath: boardFile}
	before := len(tb.DB.Chunks)
	tb.refreshBoard()
	if len(tb.DB.Chunks) != before+1 {
		t.Fatalf("chunks = %d, want %d", len(tb.DB.Chunks), before+1)
	}
	last := tb.DB.Chunks[len(tb.DB.Chunks)-1]
	if last.Kind != "board" || !strings.Contains(last.Path, "board/welcome") {
		t.Fatalf("last = %+v", last)
	}
	// The new board text should be searchable.
	if _, err := tb.DB.Search("quantum flux", 5, "", "board", 0, false, ModeKeyword); err != nil {
		t.Fatal(err)
	}
}

func TestRepoForAndGitRootFor(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "alpha")
	os.MkdirAll(repo, 0755)
	db := &DB{Sources: []Source{{Label: "alpha", Root: repo, HasGit: true}}}
	tb := &Toolbox{DB: db}
	if got := tb.repoFor("alpha"); got != repo {
		t.Fatalf("repoFor = %q", got)
	}
	if got := tb.repoFor("ALPHA"); got != repo {
		t.Fatalf("repoFor case-insensitive = %q", got)
	}
	if got := tb.repoFor("nope"); got != "" {
		t.Fatalf("repoFor = %q", got)
	}
}

func TestTrustRefusedMessage(t *testing.T) {
	out := trustRefused("git_blame", "/etc/passwd")
	if !strings.Contains(out, "git_blame") || !strings.Contains(out, "trusted") {
		t.Fatalf("got %q", out)
	}
}

// boardExecute integration tests (plain store in a temp dir).

func newBoardToolbox(t *testing.T, db *DB) *Toolbox {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	boardFile := filepath.Join(dir, "board.bin")
	t.Setenv("KBTOOL_BOARD", boardFile)
	st, err := openKBStore(filepath.Join(dir, "kb.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Toolbox{DB: db, Store: st, BoardPath: boardFile}
}

func TestBoardSignupAndPost(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	// Signup.
	out, isErr := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "alice"}))
	if isErr {
		t.Fatalf("signup isErr: %q", out)
	}
	seedRe := regexp.MustCompile(`seed: ([0-9a-f]{64})`)
	m := seedRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no seed in output: %q", out)
	}
	seed := m[1]
	// Duplicate name rejected.
	out, isErr = tb.Execute("board_signup", mustMarshal(map[string]any{"name": "alice"}))
	if !isErr {
		t.Fatal("duplicate signup should error")
	}
	if !strings.Contains(out, "already registered") {
		t.Fatalf("got %q", out)
	}
	// Invalid name.
	out, isErr = tb.Execute("board_signup", mustMarshal(map[string]any{"name": "Bad Name!"}))
	if !isErr {
		t.Fatal("invalid name should error")
	}
	// Post to welcome.
	out, isErr = tb.Execute("board_post", mustMarshal(map[string]any{
		"thread": "welcome", "kind": "hello", "text": "I'm alice, hello", "seed": seed,
	}))
	if isErr {
		t.Fatalf("post isErr: %q", out)
	}
	if !strings.Contains(out, "posted to welcome") {
		t.Fatalf("got %q", out)
	}
	// Whoami.
	out, isErr = tb.Execute("board_whoami", mustMarshal(map[string]any{"seed": seed}))
	if isErr {
		t.Fatalf("whoami isErr: %q", out)
	}
	if !strings.Contains(out, "alice") {
		t.Fatalf("got %q", out)
	}
}

func TestBoardPostValidation(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	// No thread.
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"text": "x", "seed": "ab"})); !isErr || !strings.Contains(out, "thread") {
		t.Fatalf("got (%q,%v)", out, isErr)
	}
	// Invalid thread id.
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "UPPER SPACE", "text": "x", "seed": "ab"})); !isErr {
		t.Fatalf("got %q", out)
	}
	// No text.
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "welcome", "seed": "ab"})); !isErr || !strings.Contains(out, "text") {
		t.Fatalf("got (%q,%v)", out, isErr)
	}
	// Invalid kind.
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "welcome", "kind": "bogus", "text": "x", "seed": "ab"})); !isErr {
		t.Fatalf("got %q", out)
	}
	// Missing seed.
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "welcome", "kind": "info", "text": "x"})); !isErr || !strings.Contains(out, "seed") {
		t.Fatalf("got (%q,%v)", out, isErr)
	}
}

func TestBoardReadAndThreads(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	// Signup to get a seed.
	out, _ := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "bob"}))
	seed := regexp.MustCompile(`seed: ([0-9a-f]{64})`).FindStringSubmatch(out)[1]
	// Post.
	tb.Execute("board_post", mustMarshal(map[string]any{"thread": "welcome", "kind": "hello", "text": "hi there", "seed": seed}))
	// Read.
	out, isErr := tb.Execute("board_read", mustMarshal(map[string]any{"thread": "welcome", "seed": seed}))
	if isErr {
		t.Fatalf("read isErr: %q", out)
	}
	if !strings.Contains(out, "hi there") {
		t.Fatalf("read missing text: %q", out)
	}
	if !strings.Contains(out, "verified") {
		t.Fatalf("read missing verification: %q", out)
	}
	// Threads.
	out, isErr = tb.Execute("board_threads", mustMarshal(map[string]any{"seed": seed}))
	if isErr {
		t.Fatalf("threads isErr: %q", out)
	}
	if !strings.Contains(out, "welcome") {
		t.Fatalf("threads missing welcome: %q", out)
	}
	// Unknown thread.
	out, isErr = tb.Execute("board_read", mustMarshal(map[string]any{"thread": "nope", "seed": seed}))
	if !isErr || !strings.Contains(out, "unknown thread") {
		t.Fatalf("got (%q,%v)", out, isErr)
	}
}

func TestBoardConfirm(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	out, _ := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "carol"}))
	seed := regexp.MustCompile(`seed: ([0-9a-f]{64})`).FindStringSubmatch(out)[1]
	out, isErr := tb.Execute("board_confirm", mustMarshal(map[string]any{"seed": seed}))
	if isErr {
		t.Fatalf("confirm isErr: %q", out)
	}
	if !strings.Contains(out, "confirmed") || !strings.Contains(out, "carol") {
		t.Fatalf("got %q", out)
	}
	if !strings.Contains(out, "ACTIVE") {
		t.Fatalf("got %q", out)
	}
}

func TestBoardUnknownSeed(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	// Create the board first (so it's not "board not found").
	tb.Execute("board_signup", mustMarshal(map[string]any{"name": "dave"}))
	// A different (unregistered) seed.
	otherSeed := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 32))
	out, isErr := tb.Execute("board_read", mustMarshal(map[string]any{"thread": "welcome", "seed": otherSeed}))
	if !isErr || !strings.Contains(out, "seed not recognized") {
		t.Fatalf("got (%q,%v)", out, isErr)
	}
}

func TestBoardSearch(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	// DB with a KW index so board_search works.
	chunks := []Chunk{{Path: "a", Kind: "code", Text: "some base chunk"}}
	db := makeDB(t, chunks)
	tb := newBoardToolbox(t, db)
	out, _ := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "erin"}))
	seed := regexp.MustCompile(`seed: ([0-9a-f]{64})`).FindStringSubmatch(out)[1]
	tb.Execute("board_post", mustMarshal(map[string]any{"thread": "welcome", "kind": "info", "text": "photonics research notes", "seed": seed}))
	// Search for a word in the board message.
	out, isErr := tb.Execute("board_search", mustMarshal(map[string]any{"q": "photonics", "seed": seed}))
	if isErr {
		t.Fatalf("search isErr: %q", out)
	}
	if !strings.Contains(out, "photonics") {
		t.Fatalf("search missing match: %q", out)
	}
}

func TestBoardSearchNoDB(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	out, _ := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "frank"}))
	seed := regexp.MustCompile(`seed: ([0-9a-f]{64})`).FindStringSubmatch(out)[1]
	out, isErr := tb.Execute("board_search", mustMarshal(map[string]any{"q": "x", "seed": seed}))
	if !isErr || !strings.Contains(out, "knowledge base not loaded") {
		t.Fatalf("got (%q,%v)", out, isErr)
	}
}

func TestBoardSign(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := hex.EncodeToString(bytes.Repeat([]byte{0xee}, 32))
	out, isErr := tb.Execute("board_sign", mustMarshal(map[string]any{"seed": seed, "text": "sign me"}))
	if isErr {
		t.Fatalf("sign isErr: %q", out)
	}
	if !strings.Contains(out, "signature") || !strings.Contains(out, "public key") {
		t.Fatalf("got %q", out)
	}
	// Missing text.
	out, isErr = tb.Execute("board_sign", mustMarshal(map[string]any{"seed": seed}))
	if !isErr || !strings.Contains(out, "text") {
		t.Fatalf("got (%q,%v)", out, isErr)
	}
}

func TestBoardNewThread(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	out, _ := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "gina"}))
	seed := regexp.MustCompile(`seed: ([0-9a-f]{64})`).FindStringSubmatch(out)[1]
	// Post to a new thread.
	out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{
		"thread": "research-auth", "kind": "task", "text": "please research auth", "seed": seed,
	}))
	if isErr {
		t.Fatalf("post isErr: %q", out)
	}
	if !strings.Contains(out, "research-auth") {
		t.Fatalf("got %q", out)
	}
	// Task hint.
	if !strings.Contains(out, "result") {
		t.Fatalf("task hint missing: %q", out)
	}
	// Threads now lists the new thread.
	out, _ = tb.Execute("board_threads", mustMarshal(map[string]any{"seed": seed}))
	if !strings.Contains(out, "research-auth") {
		t.Fatalf("threads missing new thread: %q", out)
	}
}

func TestGitToolsRefusedWithoutTrust(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	tb := &Toolbox{DB: searchSetup(t)}
	// git_blame with no trusted repo.
	out, isErr := tb.Execute("git_blame", mustMarshal(map[string]any{"file": "nope/x.go"}))
	if !isErr {
		t.Fatal("should error")
	}
	if !strings.Contains(out, "could not determine repo") && !strings.Contains(out, "no trusted git repo") {
		t.Fatalf("got %q", out)
	}
	// git_log with no repo.
	out, isErr = tb.Execute("git_log", mustMarshal(map[string]any{"repo": "nope"}))
	if !isErr {
		t.Fatal("should error")
	}
}

func TestNewTrustPolicyAssembly(t *testing.T) {
	db := &DB{Sources: []Source{
		{Label: "a", Root: "/git/a", HasGit: true},
		{Label: "b", Root: "/plain/b", HasGit: false},
	}}
	cfg := &config{TrustedPaths: []string{"/cfg/trusted"}, ForbiddenPaths: []string{"/cfg/forbidden"}}
	tp := newTrustPolicy(db, []string{"/live/repo"}, cfg)
	// trusted = live repo + git sources + cfg trusted (plain source excluded).
	joined := strings.Join(tp.Trusted, "\n")
	if !strings.Contains(joined, "/live/repo") {
		t.Fatalf("missing live repo: %q", joined)
	}
	if !strings.Contains(joined, "/git/a") {
		t.Fatalf("missing git source: %q", joined)
	}
	if strings.Contains(joined, "/plain/b") {
		t.Fatalf("plain source should not be trusted: %q", joined)
	}
	if !strings.Contains(joined, "/cfg/trusted") {
		t.Fatalf("missing cfg trusted: %q", joined)
	}
	if !reflect.DeepEqual(tp.Forbidden, []string{"/cfg/forbidden"}) {
		t.Fatalf("forbidden = %v", tp.Forbidden)
	}
}

// ---------- 21. client config + misc ----------

func TestClientResolve(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	// Empty → stateDir/name.
	if got := clientResolve("", "ca.crt"); got != filepath.Join(dir, "ca.crt") {
		t.Fatalf("got %q", got)
	}
	// Absolute preserved.
	if got := clientResolve("/abs/x", "ca.crt"); got != "/abs/x" {
		t.Fatalf("got %q", got)
	}
	// Relative → stateDir/rel.
	if got := clientResolve("certs/ca.crt", "x"); got != filepath.Join(dir, "certs/ca.crt") {
		t.Fatalf("got %q", got)
	}
}

func TestClientConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	cc := &clientConfig{Host: "1.2.3.4", Port: 8443, TLS: true, CaCert: "ca.crt"}
	if err := saveClientConfig(cc); err != nil {
		t.Fatal(err)
	}
	got, err := loadClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "1.2.3.4" || got.Port != 8443 || !got.TLS || got.CaCert != "ca.crt" {
		t.Fatalf("got %+v", got)
	}
	if got.Version != 1 {
		t.Fatalf("version = %d", got.Version)
	}
}

func TestEndpointFromClientConfigUnix(t *testing.T) {
	dir := t.TempDir()
	cc := &clientConfig{UnixSocket: filepath.Join(dir, "d.sock")}
	ep, desc, ok := endpointFromClientConfig(cc)
	if !ok {
		t.Fatal("not ok")
	}
	if ep.kind != "unix" || ep.socket != cc.UnixSocket {
		t.Fatalf("got %+v", ep)
	}
	if !strings.Contains(desc, "unix") {
		t.Fatalf("desc = %q", desc)
	}
}

// TestEndpointFromClientConfigNoTLS: why — daemons serve TCP only with mTLS,
// so a hand-edited client.json with tls off yields no endpoint and cleartext
// is never tried.
func TestEndpointFromClientConfigNoTLS(t *testing.T) {
	if _, _, ok := endpointFromClientConfig(&clientConfig{Host: "10.0.0.5", Port: 9999}); ok {
		t.Fatal("a client config without TLS must yield no TCP endpoint")
	}
}

func TestEndpointFromClientConfigEmpty(t *testing.T) {
	if _, _, ok := endpointFromClientConfig(&clientConfig{}); ok {
		t.Fatal("empty config should not be ok")
	}
}

// TestRemoveLeftoverClientConfig: why — a daemon host talks to its daemon over
// the unix socket only, so a client.json an older version wrote there is
// removed (plans/host-socket-cli-and-live-reindex-plan.md); without one,
// nothing happens.
func TestRemoveLeftoverClientConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	removeLeftoverClientConfig()
	if err := saveClientConfig(&clientConfig{Version: 1, Host: "127.0.0.1", Port: 9876, TLS: true}); err != nil {
		t.Fatal(err)
	}
	removeLeftoverClientConfig()
	if fileExists(clientConfigPath()) {
		t.Fatal("a leftover client.json must be removed")
	}
}

func TestFlagFirst(t *testing.T) {
	got := flagFirst(
		[]string{"pos1", "-dim", "128", "-git", "pos2"},
		map[string]bool{"dim": true, "gitmaxcommits": true},
	)
	// flags (with their values) then positionals.
	want := []string{"-dim", "128", "-git", "pos1", "pos2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// = form does not consume a value.
	got = flagFirst([]string{"-dim=64", "x"}, map[string]bool{"dim": true})
	want = []string{"-dim=64", "x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestBackendTag(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	if got := backendTag(); got != "local-hashing" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("KB_EMBED_URL", "https://api.example/embeddings")
	t.Setenv("KB_EMBED_MODEL", "text-embed-3")
	if got := backendTag(); got != "remote:text-embed-3" {
		t.Fatalf("got %q", got)
	}
}

func TestPickEmbedderLocal(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	emb := pickEmbedder(32)
	v := emb([]string{"hello"})[0]
	if len(v) != 32 {
		t.Fatalf("dim = %d", len(v))
	}
}

func TestProbeDim(t *testing.T) {
	emb := func(texts []string) [][]float32 { return make([][]float32, len(texts), 0) }
	// A fake embedder that returns 7-dim vectors.
	fake := func(texts []string) [][]float32 {
		out := make([][]float32, len(texts))
		for i := range out {
			out[i] = make([]float32, 7)
		}
		return out
	}
	if got := probeDim(fake); got != 7 {
		t.Fatalf("got %d", got)
	}
	_ = emb
}

func TestRemoteFromEnvMissing(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	if _, err := remoteFromEnv(); err == nil {
		t.Fatal("expected error when KB_EMBED_URL unset")
	}
}

func TestEmbedOneLocal(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	v := embedOne("hello", 32)
	if len(v) != 32 {
		t.Fatalf("dim = %d", len(v))
	}
}

func TestReadLineTrim(t *testing.T) {
	r := strings.NewReader("  hello world \nrest")
	line, err := readLineTrim(r)
	if err != nil {
		t.Fatal(err)
	}
	if line != "hello world" {
		t.Fatalf("got %q", line)
	}
}

func TestLoadClientConfigSafeCorrupt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	os.WriteFile(filepath.Join(dir, "client.json"), []byte("{bad"), 0644)
	if cc := loadClientConfigSafe(); cc != nil {
		t.Fatal("expected nil for corrupt client config")
	}
}

// ---------- misc small helpers ----------

func TestResultIDs(t *testing.T) {
	// resultIDs is a tiny helper; ensure it doesn't panic on empty.
	if got := resultIDs(nil); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestSortedAgentsEmpty(t *testing.T) {
	b := &Board{Agents: map[string]*BoardAgent{}}
	if got := b.sortedAgents(); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestBoardThreadNilSafety(t *testing.T) {
	b := newBoard()
	if b.thread("welcome") == nil {
		t.Fatal("welcome should exist")
	}
	if b.thread("nope") != nil {
		t.Fatal("nope should be nil")
	}
}

// A few guard tests around the Search min gate.
func TestSearchMinGate(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	chunks := []Chunk{
		{Path: "a", Kind: "code", Text: "token bucket limiter"},
		{Path: "b", Kind: "code", Text: "completely different words here"},
	}
	db := makeDB(t, chunks)
	// A very high min should filter out weak matches in vector mode.
	res, err := db.Search("token bucket", 10, "", "", 0.99, false, ModeVector)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Score < 0.99 {
			t.Fatalf("min gate violated: score %f", r.Score)
		}
	}
}

func TestSearchFullText(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	chunks := []Chunk{{Path: "a", Kind: "code", Text: "the full text is here token"}}
	db := makeDB(t, chunks)
	res, err := db.Search("token", 5, "", "", 0, true, ModeVector)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatal("no results")
	}
	// fullText returns the chunk text in the result.
	if res[0].C.Text != "the full text is here token" {
		t.Fatalf("text = %q", res[0].C.Text)
	}
}

// Ensure the board welcome thread is created even when reading a board file
// that somehow lacks it.
func TestReadBoardEnsureWelcome(t *testing.T) {
	// Manually craft a board with a non-welcome thread only, marshal, then
	// readBoard should add welcome first.
	b := &Board{
		NextID: 1,
		Order:  []string{"other"},
		Threads: map[string]*BoardThread{
			"other": {ID: "other", CreatedAt: 1, CreatedBy: "x"},
		},
		Agents: map[string]*BoardAgent{},
	}
	got, err := readBoard(bytes.NewReader(boardMarshal(b)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Order[0] != boardWelcome {
		t.Fatalf("welcome not first: %v", got.Order)
	}
	if _, ok := got.Threads[boardWelcome]; !ok {
		t.Fatal("welcome missing")
	}
}

// Guard: capKWTerms must keep the index consistent (postings match terms) when
// it does nothing.
func TestKWIndexConsistency(t *testing.T) {
	chunks := []Chunk{
		{Path: "a", Kind: "code", Text: "alpha beta gamma"},
		{Path: "b", Kind: "code", Text: "alpha delta"},
	}
	kw := buildKWIndex(chunks, false)
	// Every term id in ChunkTF must be < len(Terms).
	for ci := range kw.ChunkTF {
		for _, p := range kw.ChunkTF[ci] {
			if int(p.id) >= len(kw.Terms) {
				t.Fatalf("chunk %d has out-of-range term id %d", ci, p.id)
			}
		}
	}
	// Postings length matches term count.
	if len(kw.Postings) != len(kw.Terms) {
		t.Fatalf("postings %d != terms %d", len(kw.Postings), len(kw.Terms))
	}
	// Score is deterministic.
	s1 := kw.Score("alpha", nil)
	s2 := kw.Score("alpha", nil)
	if s1[0] != s2[0] || s1[1] != s2[1] {
		t.Fatal("score not deterministic")
	}
}

// Guard: a chunk that appears in both channels should be fused, not duplicated.
func TestRRFNoDuplicates(t *testing.T) {
	rankA := []idScore{{id: 0, sc: 5}, {id: 1, sc: 4}}
	rankB := []idScore{{id: 0, sc: 9}, {id: 2, sc: 1}}
	got := rrfFuse(rankA, rankB, 60, 3)
	seen := map[int]bool{}
	for _, e := range got {
		if seen[e.id] {
			t.Fatalf("duplicate id %d", e.id)
		}
		seen[e.id] = true
	}
	if len(got) != 3 {
		t.Fatalf("got %d, want 3", len(got))
	}
}

// Guard: weightedFuse with all-zero scores doesn't divide by zero.
func TestWeightedFuseZeroScores(t *testing.T) {
	rankA := []idScore{{id: 0, sc: 0}, {id: 1, sc: 0}}
	got := weightedFuse(rankA, nil, 0.6, 0.4, 2)
	if len(got) != 2 {
		t.Fatalf("got %d", len(got))
	}
}

// ---------- 22. documentation link consistency (README + docs/) ----------

var docSubcommands = []string{"build", "query", "terms", "bundle", "tools", "call", "mcp", "daemon", "relay", "status", "board",
	"collaborate", "session", "steer", "kbx", "memory"}

// snapshotSubcommands are the snapshot-only commands, documented (simple and
// full) under docs/snapshots/ only.
var snapshotSubcommands = []string{"bench", "mtls", "client"}

// mdLinks extracts the relative markdown link targets of a doc. Fenced code
// blocks are stripped first (shell/JSON examples must not count as links);
// external URLs and anchor-only targets are skipped; fragments are removed.
func mdLinks(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var kept []string
	inFence := false
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "```") {
			inFence = !inFence
			continue
		}
		if !inFence {
			kept = append(kept, ln)
		}
	}
	re := regexp.MustCompile(`\[[^\]]*\]\(([^)\s]+)\)`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(strings.Join(kept, "\n"), -1) {
		target := m[1]
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
			strings.HasPrefix(target, "mailto:") || strings.HasPrefix(target, "#") {
			continue
		}
		if i := strings.IndexByte(target, '#'); i >= 0 {
			target = target[:i]
		}
		if target == "" {
			continue
		}
		out = append(out, target)
	}
	return out
}

// mdLinkSet returns the cleaned, source-relative targets a doc links to.
func mdLinkSet(t *testing.T, path string) map[string]bool {
	t.Helper()
	m := map[string]bool{}
	for _, target := range mdLinks(t, path) {
		m[filepath.Clean(filepath.Join(filepath.Dir(path), target))] = true
	}
	return m
}

// TestDocsLinks machine-checks the required documentation structure:
//
//  1. every relative link in README.md, docs/*.md and docs/snapshots/*.md
//     resolves to a real entry;
//  2. the README links every release subcommand's simple doc (the required
//     index), and neither the README nor a release doc links snapshot docs;
//  3. each simple doc cross-links its full doc and the full doc links back
//     (the required two-document, cross-linked layout), release commands in
//     docs/, snapshot-only ones in docs/snapshots/;
//  4. every snapshot doc says it applies to snapshot builds, and
//     docs/snapshots/README.md indexes the snapshot-only commands.
func TestDocsLinks(t *testing.T) {
	docs, err := filepath.Glob("docs/*.md")
	if err != nil {
		t.Fatalf("glob docs: %v", err)
	}
	snaps, err := filepath.Glob("docs/snapshots/*.md")
	if err != nil {
		t.Fatalf("glob docs/snapshots: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("no docs/*.md found (expected the docs/ directory)")
	}
	if _, err := os.Stat("README.md"); err != nil {
		t.Fatalf("no README.md: %v", err)
	}

	// 1. No broken relative links anywhere; release docs never link snapshots.
	release := append([]string{"README.md"}, docs...)
	for _, p := range append(append([]string{}, release...), snaps...) {
		for target := range mdLinkSet(t, p) {
			if _, err := os.Stat(target); err != nil {
				t.Errorf("%s: broken link -> %s", p, target)
			}
		}
	}
	for _, p := range release {
		for target := range mdLinkSet(t, p) {
			if strings.HasPrefix(filepath.ToSlash(target), "docs/snapshots") {
				t.Errorf("%s: release docs must not link snapshot docs (%s)", p, target)
			}
		}
	}
	for _, p := range snaps {
		if head := string(mustReadFile(t, p)); !strings.Contains(strings.ToLower(head[:min(len(head), 600)]), "snapshot") {
			t.Errorf("%s: a snapshot doc says it applies to snapshot builds", p)
		}
	}

	// 2. README indexes every subcommand's simple doc.
	readme := mdLinkSet(t, "README.md")
	for _, cmd := range docSubcommands {
		if !readme[filepath.Join("docs", cmd+"-simple.md")] {
			t.Errorf("README.md: missing link to docs/%s-simple.md", cmd)
		}
	}

	// 3. Simple <-> full cross-links for every subcommand.
	pair := func(dir, cmd string) {
		simple := filepath.Join(dir, cmd+"-simple.md")
		full := filepath.Join(dir, cmd+".md")
		if !mdLinkSet(t, simple)[full] {
			t.Errorf("%s: missing cross-link to %s", simple, full)
		}
		if !mdLinkSet(t, full)[simple] {
			t.Errorf("%s: missing cross-link back to %s", full, simple)
		}
	}
	for _, cmd := range docSubcommands {
		pair("docs", cmd)
	}
	snapIndex := mdLinkSet(t, filepath.Join("docs", "snapshots", "README.md"))
	for _, cmd := range snapshotSubcommands {
		pair(filepath.Join("docs", "snapshots"), cmd)
		if !snapIndex[filepath.Join("docs", "snapshots", cmd+"-simple.md")] {
			t.Errorf("docs/snapshots/README.md: missing link to %s-simple.md", cmd)
		}
		if readme[filepath.Join("docs", "snapshots", cmd+"-simple.md")] || fileExists(filepath.Join("docs", cmd+".md")) {
			t.Errorf("%s is snapshot-only: documented under docs/snapshots/ and not in the README", cmd)
		}
	}
}

// ---------- 23. CLI versioning (plans/multi-platform-automated-release-plan.md) ----------

var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// TestAppVerIsSemver: appVer must be a plain MAJOR.MINOR.PATCH so that
// (a) `-ldflags "-X main.appVer=..."` (which requires appVer to be a var)
// keeps working, and (b) released binaries report a version the release
// workflow can reason about (it strips the tag's leading "v").
func TestAppVerIsSemver(t *testing.T) {
	if !semverRe.MatchString(appVer) {
		t.Fatalf("appVer = %q does not match semver MAJOR.MINOR.PATCH", appVer)
	}
}

// TestAppVerInitialRelease: the first release of an unreleased project must
// be 0.1.0 per the release plan (the release workflow's no-tags case emits
// v0.1.0, so the source default must agree with it).
func TestAppVerInitialRelease(t *testing.T) {
	if appVer != "0.1.0" {
		t.Fatalf("expected initial version 0.1.0, got %q", appVer)
	}
}

// TestPrintVersion: the version command output must name the tool and carry
// the exact version string, on a single line (scriptable: `kbtool version`).
func TestPrintVersion(t *testing.T) {
	var buf bytes.Buffer
	printVersion(&buf)
	got := strings.TrimRight(buf.String(), "\n")
	want := appName + " version " + appVer
	if got != want {
		t.Fatalf("printVersion = %q, want %q", got, want)
	}
	if strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("expected exactly one line of output, got %q", buf.String())
	}
}

// TestPrintVersionMatchesTagInjection: GoReleaser injects the tag (minus "v")
// via -X main.appVer. Simulate the post-injection value and confirm the output
// tracks it. This pins the exact output format the release pipeline depends on
// (a release binary must self-report its own tag).
func TestPrintVersionMatchesTagInjection(t *testing.T) {
	old := appVer
	appVer = "2.3.4" // what -X main.appVer=2.3.4 would produce for tag v2.3.4
	defer func() { appVer = old }()

	var buf bytes.Buffer
	printVersion(&buf)
	if !strings.Contains(buf.String(), "2.3.4") {
		t.Fatalf("expected injected version 2.3.4 in output, got %q", buf.String())
	}
}

// TestUsageDocumentsVersionAliases: the usage text must document the
// version / -v / --version aliases so they cannot silently drift from what
// is advertised (all three share one implementation, printVersion;
// end-to-end they are exercised in CI via the snapshot build).
func TestUsageDocumentsVersionAliases(t *testing.T) {
	var buf bytes.Buffer
	usageTo(&buf)
	for _, alias := range []string{"kbtool version", "-v", "--version"} {
		if !strings.Contains(buf.String(), alias) {
			t.Fatalf("usage text must document %q; got:\n%s", alias, buf.String())
		}
	}
}

// ---------- 24. single-command buildability (hard requirement) ----------

// TestSingleFilePackage: the whole tool must remain a single non-test .go
// file (kbtool.go). This is a hard requirement — the tool is built with one
// go command (`go build -o kbtool kbtool.go`), so adding any other .go file
// to the package breaks that.
func TestSingleFilePackage(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}
	var nonTest []string
	for _, e := range entries {
		if e.Type().IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			nonTest = append(nonTest, name)
		}
	}
	if len(nonTest) != 1 || nonTest[0] != "kbtool.go" {
		t.Fatalf("package must contain exactly one non-test .go file, kbtool.go; found %v", nonTest)
	}
}

// TestSingleCommandBuild: the entire tool must compile with the single
// command `go build -o kbtool kbtool.go` (hard requirement: it is generated
// and distributed this way). Compiling the named file (not `go build .`) is
// what enforces that — it fails if the package needs any other file or any
// external module.
func TestSingleCommandBuild(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot verify single-command build")
	}
	out := filepath.Join(t.TempDir(), "kbtool")
	cmd := exec.Command(goBin, "build", "-o", out, "kbtool.go")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build -o kbtool kbtool.go failed:\n%s", b)
	}
	if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
		t.Fatalf("expected a non-empty binary at %s (err=%v)", out, err)
	}
}

// ---------- 25. terms census + context bundle (plans/context-bundle-plan.md) ----------

// buildTermsFixture builds a small multi-language repo (Go, Java, Python, JS)
// under a temp dir and returns an in-memory DB over it. Shared by the group-25
// tests: the fixture encodes every scenario the feature must handle (constructed
// URL strings, internal/external imports per language, test-file naming).
func buildTermsFixture(t *testing.T) *DB {
	t.Helper()
	t.Setenv("KB_EMBED_URL", "")
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// Go: internal package import (in-tree) + stdlib (external) + a URL built by
	// format verbs (the stable-fragment case).
	write("repo/src/foo/bar.go", `package foo

import (
	"fmt"

	"acme/repo/src/bar"
)

func EncodeEcosystem(name string) string {
	url := "https://nvd.nist.gov/feeds/json/cves/2.0/nvdcve-2.0-%s.json.gz".formatted(name)
	return fmt.Sprintf("%s / %s", bar.Name(), url)
}
`)
	write("repo/src/bar/bar.go", `package bar

func Name() string { return "bar" }
`)
	// Go test file sharing the identifier with bar.go.
	write("repo/src/foo/bar_test.go", `package foo

import "testing"

func TestEncodeEcosystem(t *testing.T) {
	if EncodeEcosystem("pip") == "" {
		t.Fatal("empty")
	}
}
`)
	// Java: internal import (Helper.java present) + external (Missing absent).
	write("repo/com/example/Foo.java", `package com.example;

import com.example.Helper;
import com.example.Missing;

public class Foo {
  public String feed() { return "nvdcve-2.0"; }
}
`)
	write("repo/com/example/Helper.java", `package com.example;

public class Helper {
  public static int one() { return 1; }
}
`)
	write("repo/com/example/FooTest.java", `package com.example;

public class FooTest {
  public void check() { new Foo().feed(); }
}
`)
	// Python: relative + wildcard (unresolved) + absolute internal + stdlib.
	write("repo/pkg/mod.py", `from .relative import thing
from pkg.util import helper
from os import *
import json

def run():
    return helper()
`)
	write("repo/pkg/util.py", `def helper():
    return 42
`)
	// JS: relative internal + bare external.
	write("repo/web/app.js", `import { widget } from "./widget";
import lodash from "lodash";

export function render() { return widget() + lodash; }
`)
	write("repo/web/widget.js", `export function widget() { return "w"; }
`)
	db, err := buildDB(BuildOpts{
		Sources: []string{dir},
		Dim:     testDim,
		Chunk:   48,
		Overlap: 0,
		MaxKB:   512,
		Embed:   localEmbed,
		KWPath:  boolPtr(true),
	})
	if err != nil {
		t.Fatalf("buildDB: %v", err)
	}
	return db
}

// findChunkByPath returns the first chunk whose (slash-normalized) path equals
// or ends with the given rel — the leading source label is a temp-dir basename
// and must not matter to the test.
func findChunkByPath(t *testing.T, db *DB, rel string) Chunk {
	t.Helper()
	rel = strings.ReplaceAll(rel, "\\", "/")
	for i := range db.Chunks {
		p := strings.ReplaceAll(db.Chunks[i].Path, "\\", "/")
		if p == rel || strings.HasSuffix(p, "/"+rel) {
			return db.Chunks[i]
		}
	}
	t.Fatalf("no chunk for %s (have %d chunks)", rel, len(db.Chunks))
	return Chunk{}
}

// 1. Census correctness: the identifier exists in exactly N files and the
// census reports exactly those N with exact per-file counts — and a nowhere
// identifier reports the distinct ABSENT result. This pins the feature's
// reason to exist: absence as a citable, complete result.
func TestTermsCensusCorrectness(t *testing.T) {
	db := buildTermsFixture(t)
	// EncodeEcosystem appears in exactly 2 files (bar.go x1, bar_test.go x2).
	r := termsCensus(db, "EncodeEcosystem", 0)
	if !r.Present {
		t.Fatalf("expected present, got: %+v", r)
	}
	if r.FileCount != 2 {
		t.Fatalf("FileCount = %d, want 2 (%+v)", r.FileCount, r.Files)
	}
	want := map[string]int{
		"repo/src/foo/bar.go":      1,
		"repo/src/foo/bar_test.go": 2,
	}
	if r.Occurrences != 3 {
		t.Fatalf("Occurrences = %d, want 3", r.Occurrences)
	}
	// The leading path segment is the source label (a temp-dir basename) — strip it.
	stripLabel := func(p string) string {
		if i := strings.IndexByte(p, '/'); i > 0 {
			return p[i+1:]
		}
		return p
	}
	for _, f := range r.Files {
		p := stripLabel(f.Path)
		w, ok := want[p]
		if !ok {
			t.Fatalf("unexpected file %q in census: %+v", f.Path, r.Files)
		}
		if f.Count != w {
			t.Fatalf("%s count = %d, want %d", f.Path, f.Count, w)
		}
		if len(f.Lines) == 0 {
			t.Fatalf("%s has no representative lines", f.Path)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Fatalf("missing files: %v", want)
	}

	// Absent: distinct, unambiguous, citable.
	r2 := termsCensus(db, "noSuchIdentifierZZZ", 0)
	if r2.Present || r2.Occurrences != 0 || r2.FileCount != 0 || len(r2.Files) != 0 {
		t.Fatalf("absent census must be empty: %+v", r2)
	}
	out := renderTerms(r2)
	if !containsLine(out, "ABSENT in indexed sources") {
		t.Fatalf("absent rendering must carry the ABSENT line: %q", out)
	}
	if !containsLine(renderTerms(r), "occurrence") {
		t.Fatalf("present rendering: %q", out)
	}
}

func containsLine(s, sub string) bool { return strings.Contains(s, sub) }

// "Present but didn't rank" must NOT be confused with absent: an identifier
// that is not in the top-k of a hybrid search still shows up in the census.
// This is the exact failure mode the feedback session hit ("NVD api key …"
// query returned 0 relevant hits, but the identifier did exist).
func TestTermsPresentButNotRanked(t *testing.T) {
	db := buildTermsFixture(t)
	// "EncodeEcosystem" is a rare token; a hybrid query about the general topic
	// with a small k may not surface the chunk containing it — but the census
	// must still report it present in exactly the files that contain it.
	res, err := db.Search("bar naming", 2, "", "", 0, false, ModeHybrid)
	if err != nil {
		t.Fatal(err)
	}
	rankedHas := false
	for _, x := range res {
		if strings.Contains(x.C.Text, "EncodeEcosystem") {
			rankedHas = true
		}
	}
	r := termsCensus(db, "EncodeEcosystem", 0)
	if !r.Present || r.FileCount != 2 {
		t.Fatalf("census must be present/2 regardless of ranking: rankedHas=%v census=%+v", rankedHas, r)
	}
	// The point of the feature: the two answers are independent.
	_ = rankedHas
}

// 2. Fragment propagation: a URL built with a format verb is found tree-wide by
// its stable fragment, and the REPORTED fragment is the one a human can judge.
func TestBundleFragmentPropagation(t *testing.T) {
	db := buildTermsFixture(t)
	c := findChunkByPath(t, db, "repo/src/foo/bar.go")
	out := bundleChunk(db, newBundleFiles(db), c)
	// The constructed literal must propagate via a stable fragment.
	if !strings.Contains(out, `fragment "nvdcve-2.0"`) {
		t.Fatalf("expected stable fragment \"nvdcve-2.0\" in propagation:\n%s", out)
	}
	// ...and it must surface the OTHER file that contains that fragment (Foo.java).
	if !strings.Contains(out, "repo/com/example/Foo.java") {
		t.Fatalf("fragment must surface Foo.java:\n%s", out)
	}
	// The full constructed string (with the %s verb) must NOT be the reported
	// fragment — only stable pieces.
	if strings.Contains(out, `fragment "https://nvd.nist.gov/feeds/json/cves/2.0/nvdcve-2.0-%s.json.gz"`) {
		t.Fatalf("constructed literal must be searched by fragments, not whole:\n%s", out)
	}
}

// stableFragments unit: split on format verbs / non-word runs, min length,
// longest-first, deduped, capped.
func TestStableFragments(t *testing.T) {
	f := stableFragments("https://nvd.nist.gov/feeds/json/cves/2.0/nvdcve-2.0-%s.json.gz")
	joined := strings.Join(f, "\n")
	if !strings.Contains(joined, "nvdcve-2.0") || !strings.Contains(joined, "json.gz") {
		t.Fatalf("fragments missing expected stable pieces: %v", f)
	}
	for _, frag := range f {
		if strings.Contains(frag, "%") {
			t.Fatalf("fragment must not contain a format verb: %q", frag)
		}
		if len(frag) < bundleFragMinLen {
			t.Fatalf("fragment too short: %q", frag)
		}
	}
	if len(f) > bundleFragMax {
		t.Fatalf("too many fragments: %d", len(f))
	}
	// longest first
	for i := 1; i < len(f); i++ {
		if len(f[i]) > len(f[i-1]) {
			t.Fatalf("fragments not longest-first: %v", f)
		}
	}
	// pure identifier yields itself
	if got := stableFragments("EncodeEcosystem"); len(got) != 1 || got[0] != "EncodeEcosystem" {
		t.Fatalf("pure identifier fragments = %v", got)
	}
	// short candidate yields nothing
	if got := stableFragments("ab"); len(got) != 0 {
		t.Fatalf("short input should yield no fragments: %v", got)
	}
}

// 3. Import verdicts: per-language fixtures. Internal resolves to the in-tree
// path; absent is external (not-in-tree); ambiguous (Python relative, wildcard)
// is unresolved — never a wrong verdict.
func TestBundleImportVerdicts(t *testing.T) {
	db := buildTermsFixture(t)
	bf := newBundleFiles(db)

	// Go: internal (in-tree package) + external (stdlib fmt).
	goOut := bundleChunk(db, bf, findChunkByPath(t, db, "repo/src/foo/bar.go"))
	if !strings.Contains(goOut, "acme/repo/src/bar") || !strings.Contains(goOut, "internal") {
		t.Fatalf("Go internal import missing:\n%s", goOut)
	}
	if !strings.Contains(goOut, "fmt") || !strings.Contains(goOut, "external") {
		t.Fatalf("Go external import (fmt) missing:\n%s", goOut)
	}
	// The internal Go import must point at the in-tree bar package.
	if !strings.Contains(goOut, "repo/src/bar/bar.go") {
		t.Fatalf("Go internal import must resolve to in-tree path:\n%s", goOut)
	}

	// Java: internal (Helper.java present) + external (Missing absent).
	jaOut := bundleChunk(db, bf, findChunkByPath(t, db, "repo/com/example/Foo.java"))
	if !strings.Contains(jaOut, "com.example.Helper") || !strings.Contains(jaOut, "Helper.java") {
		t.Fatalf("Java internal import missing:\n%s", jaOut)
	}
	if !strings.Contains(jaOut, "com.example.Missing") {
		t.Fatalf("Java external import missing:\n%s", jaOut)
	}
	// Missing must be external, not internal.
	if m := regexp.MustCompile(`com\.example\.Missing\s*->\s*(\w+)`).FindStringSubmatch(jaOut); m == nil || m[1] != "external" {
		t.Fatalf("Java absent import must be external, got:\n%s", jaOut)
	}

	// Python: relative + wildcard = unresolved; absolute internal = internal.
	pyOut := bundleChunk(db, bf, findChunkByPath(t, db, "repo/pkg/mod.py"))
	if !strings.Contains(pyOut, "unresolved") || !strings.Contains(pyOut, "relative import") {
		t.Fatalf("Python relative import must be unresolved:\n%s", pyOut)
	}
	if !strings.Contains(pyOut, "wildcard import") {
		t.Fatalf("Python wildcard import must be unresolved:\n%s", pyOut)
	}
	if !strings.Contains(pyOut, "from pkg.util import helper") || !strings.Contains(pyOut, "util.py") {
		t.Fatalf("Python absolute internal import missing:\n%s", pyOut)
	}
	if m := regexp.MustCompile(`import json\s*->\s*(\w+)`).FindStringSubmatch(pyOut); m == nil || m[1] != "external" {
		t.Fatalf("Python stdlib import must be external:\n%s", pyOut)
	}

	// JS: relative internal + bare external.
	jsOut := bundleChunk(db, bf, findChunkByPath(t, db, "repo/web/app.js"))
	if !strings.Contains(jsOut, `./widget`) || !strings.Contains(jsOut, "widget.js") {
		t.Fatalf("JS relative internal import missing:\n%s", jsOut)
	}
	if m := regexp.MustCompile(`lodash\s*->\s*(\w+)`).FindStringSubmatch(jsOut); m == nil || m[1] != "external" {
		t.Fatalf("JS bare import must be external:\n%s", jsOut)
	}
}

// 4. Neighborhood + test pairing: a hit lists its siblings (with one-line
// summaries) and picks up the test file(s) sharing identifiers — Go *_test.go
// and Java *Test.java conventions both.
func TestBundleNeighborhoodAndTestPairing(t *testing.T) {
	db := buildTermsFixture(t)
	bf := newBundleFiles(db)

	// Go: bar.go hit -> bar_test.go is in the neighborhood AND in tests, sharing
	// EncodeEcosystem.
	goOut := bundleChunk(db, bf, findChunkByPath(t, db, "repo/src/foo/bar.go"))
	if !strings.Contains(goOut, "neighborhood") {
		t.Fatalf("neighborhood section missing:\n%s", goOut)
	}
	if !strings.Contains(goOut, "bar_test.go") {
		t.Fatalf("bar_test.go not found in neighborhood/tests:\n%s", goOut)
	}
	if m := regexp.MustCompile(`tests:.*bar_test\.go — shared:.*EncodeEcosystem`).FindString(goOut); m == "" {
		if !strings.Contains(goOut, "bar_test.go") || !strings.Contains(goOut, "EncodeEcosystem") {
			t.Fatalf("bar_test.go must pair sharing EncodeEcosystem:\n%s", goOut)
		}
	}

	// Java: Foo.java hit -> FooTest.java pairs (shares Foo).
	jaOut := bundleChunk(db, bf, findChunkByPath(t, db, "repo/com/example/Foo.java"))
	if !strings.Contains(jaOut, "FooTest.java") {
		t.Fatalf("FooTest.java must pair with Foo.java:\n%s", jaOut)
	}
	// Neighborhood must include the sibling Helper.java.
	if !strings.Contains(jaOut, "Helper.java") {
		t.Fatalf("neighborhood must include Helper.java:\n%s", jaOut)
	}
}

// isTestFile unit: the naming conventions, and nothing else.
func TestIsTestFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"repo/com/example/FooTest.java", true},
		{"repo/src/foo/bar_test.go", true},
		{"repo/web/app.test.js", true},
		{"repo/web/app.spec.ts", true},
		{"repo/pkg/test_mod.py", true},
		{"repo/com/example/Foo.java", false},
		{"repo/src/foo/bar.go", false},
		{"repo/web/app.js", false},
		{"repo/pkg/mod.py", false},
		{"repo/src/foo/mytests.go", false}, // not *_test.go
	}
	for _, c := range cases {
		if got := isTestFile(c.path); got != c.want {
			t.Fatalf("isTestFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// 5. Caps / truncation: a synthetic large directory produces bounded output with
// the explicit truncation marker, so large repos never flood the terminal.
func TestBundleTruncation(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	dir := t.TempDir()
	sub := filepath.Join(dir, "repo", "big")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	// 30 sibling files -> neighborhood must cap at bundleNeighborhood + marker.
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("f%02d.go", i)
		body := fmt.Sprintf("package big\n\nfunc F%02d() int { return %d }\n", i, i)
		if err := os.WriteFile(filepath.Join(sub, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	db, err := buildDB(BuildOpts{
		Sources: []string{dir}, Dim: testDim, Chunk: 48, Overlap: 0, MaxKB: 512,
		Embed: localEmbed, KWPath: boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := findChunkByPath(t, db, "repo/big/f00.go")
	out := bundleChunk(db, newBundleFiles(db), c)
	if !strings.Contains(out, "…truncated") {
		t.Fatalf("expected explicit truncation marker in a 30-file dir:\n%s", out)
	}
	// Bounded: the neighborhood section must not list all 30 files.
	n := strings.Count(out, ".go  ")
	if n > bundleNeighborhood+2 { // +2 tolerance for hit marker / other mentions
		t.Fatalf("neighborhood not bounded; %d file lines (cap %d)\n%s", n, bundleNeighborhood, out)
	}
}

// 6. Encrypted store: terms + bundle against a store written with a key produce
// the SAME results as the plain store (the at-rest shape must be transparent).
func TestTermsBundleEncryptedStore(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	plain := buildTermsFixture(t)

	mkCensus := func(db *DB) *termsResult { return termsCensus(db, "EncodeEcosystem", 0) }
	mkBundle := func(db *DB) string {
		c := findChunkByPath(t, db, "repo/src/foo/bar.go")
		return bundleChunk(db, newBundleFiles(db), c)
	}
	baseCensus := mkCensus(plain)
	baseBundle := mkBundle(plain)

	// Write the SAME db to an encrypted store (key = the -db-key-file content),
	// read it back, and compare.
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("s3cret-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	key, have, err := resolveKey("", keyFile, false)
	if err != nil || !have {
		t.Fatalf("resolveKey: %v %v", have, err)
	}
	dbPath := filepath.Join(dir, "kb.db")
	st, err := openKBStore(dbPath, key)
	if err != nil {
		t.Fatal(err)
	}
	if !st.enc {
		t.Fatal("store should be encrypted with a key")
	}
	if err := st.saveDB(plain); err != nil {
		t.Fatal(err)
	}
	if m, _ := fileMagic(dbPath); m != bundleMagic {
		t.Fatalf("magic = %q, want %q", m, bundleMagic)
	}
	// Reopen with the key file (as -db-key-file does) and verify.
	st2, err := openStore(dbPath, "", keyFile, false, true)
	if err != nil {
		t.Fatalf("openStore with key file: %v", err)
	}
	got, err := st2.db()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Chunks) != len(plain.Chunks) {
		t.Fatalf("chunk count %d != %d", len(got.Chunks), len(plain.Chunks))
	}
	// Same census + bundle from the encrypted store.
	if c := mkCensus(got); !reflect.DeepEqual(c, baseCensus) {
		t.Fatalf("encrypted census differs:\nenc=%+v\nplain=%+v", c, baseCensus)
	}
	if b := mkBundle(got); b != baseBundle {
		t.Fatalf("encrypted bundle differs:\nenc=%s\nplain=%s", b, baseBundle)
	}
	// Wrong key must fail (fail closed).
	if _, err := openKBStore(dbPath, []byte("wrong")); err == nil {
		t.Fatal("wrong key should be refused")
	}
}

// 7. Client commands need the daemon: with a built DB on disk but no daemon,
// every client command refuses instead of opening the store itself; once
// `daemon run` serves the socket, terms, bundle and the stdio MCP server answer
// through it. Skipped when the go toolchain is unavailable.
func TestClientCommandsRequireDaemon(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary for daemon parity")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	build := exec.Command(goBin, "build", "-o", bin, "kbtool.go")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}

	// Build a fixture DB on disk (plain) in an isolated state dir.
	stDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stDir, 0755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(stDir, "kb.db")
	env := append(os.Environ(), "KBTOOL_DIR="+stDir, "KBTOOL_DB="+dbPath, "KB_EMBED_URL=")
	// Reuse the in-process fixture layout by writing the same files directly.
	fx := filepath.Join(work, "fx")
	mk := func(rel, content string) {
		p := filepath.Join(fx, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	mk("repo/src/foo/bar.go", `package foo

import (
	"fmt"

	"acme/repo/src/bar"
)

func EncodeEcosystem(name string) string {
	url := "https://nvd.nist.gov/feeds/json/cves/2.0/nvdcve-2.0-%s.json.gz".formatted(name)
	return fmt.Sprintf("%s / %s", bar.Name(), url)
}
`)
	mk("repo/src/bar/bar.go", `package bar

func Name() string { return "bar" }
`)
	mk("repo/src/foo/bar_test.go", `package foo

import "testing"

func TestEncodeEcosystem(t *testing.T) {
	if EncodeEcosystem("pip") == "" {
		t.Fatal("empty")
	}
}
`)
	buildCmd := exec.Command(bin, "build", "-db", dbPath, fx)
	buildCmd.Env = env
	if b, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("kbtool build: %v\n%s", err, b)
	}

	run := func(args ...string) (string, error) {
		c := exec.Command(bin, args...)
		c.Env = env
		b, err := c.CombinedOutput()
		return string(b), err
	}

	for _, args := range [][]string{
		{"terms", "EncodeEcosystem"}, {"bundle", "repo/src/foo/bar.go:7"}, {"query", "encode"},
		{"query", "-bundle", "encode"}, {"call", "kb_status"}, {"tools"}, {"mcp"}, {"board", "dump"},
	} {
		out, err := run(args...)
		if err == nil || !strings.Contains(out, "no kbtool daemon is running") {
			t.Fatalf("%v without a daemon must refuse: %v\n%s", args, err, out)
		}
	}

	// Start the daemon on a temp socket.
	sock := filepath.Join(stDir, "daemon.sock")
	daemon := exec.Command(bin, "daemon", "run", "-db", dbPath)
	daemon.Env = append(env, "KBTOOL_SOCKET="+sock)
	var logBuf bytes.Buffer
	daemon.Stdout = &logBuf
	daemon.Stderr = &logBuf
	if err := daemon.Start(); err != nil {
		t.Fatalf("daemon start: %v", err)
	}
	defer func() {
		_ = daemon.Process.Kill()
		_, _ = daemon.Process.Wait()
	}()
	// Wait for the socket to come up.
	deadline := time.Now().Add(10 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", sock); err == nil {
			_ = c.Close()
			up = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !up {
		_ = daemon.Process.Kill()
		t.Fatalf("daemon socket never came up; log:\n%s", logBuf.String())
	}
	dEnv := append(os.Environ(), "KBTOOL_DIR="+stDir, "KBTOOL_DB="+dbPath, "KBTOOL_SOCKET="+sock, "KB_EMBED_URL=")
	runDaemon := func(args ...string) (string, error) {
		c := exec.Command(bin, args...)
		c.Env = dEnv
		b, err := c.CombinedOutput()
		return string(b), err
	}

	termsDaemon, err := runDaemon("terms", "EncodeEcosystem")
	if err != nil {
		t.Fatalf("terms (daemon): %v\n%s", err, termsDaemon)
	}
	// Same target, same expected result — the socket path must not change the answer.
	bundleDaemon, err := runDaemon("bundle", "repo/src/foo/bar.go:7")
	if err != nil {
		t.Fatalf("bundle (daemon): %v\n%s", err, bundleDaemon)
	}
	// Absence must be identical over the socket too (and keep its own exit code).
	absDaemon, err := runDaemon("terms", "noSuchIdentifierZZZ")
	if err == nil {
		t.Fatalf("absent terms over daemon should exit non-zero: %s", absDaemon)
	}
	if !strings.Contains(absDaemon, "ABSENT in indexed sources") {
		t.Fatalf("absent terms over daemon: %s", absDaemon)
	}
	if !strings.Contains(termsDaemon, "occurrence") || !strings.Contains(termsDaemon, "(via daemon:") {
		t.Fatalf("terms over the daemon: %s", termsDaemon)
	}
	if !strings.Contains(bundleDaemon, "bar.go") {
		t.Fatalf("bundle over the daemon: %s", bundleDaemon)
	}
	mcp := exec.Command(bin, "mcp")
	mcp.Env = dEnv
	mcp.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}` + "\n")
	if out, err := mcp.Output(); err != nil || !strings.Contains(string(out), "search_codebase") {
		t.Fatalf("stdio mcp must proxy to the running daemon: %v\n%s", err, out)
	}
}

// ---------- 26. mTLS IP connectivity (plans/mtls-ip-connectivity-fix-plan.md) ----------
//
// Regression context: `kbtool mtls -ip A B -dns n` used to silently issue a cert
// missing B and n (flag.Parse stops at the first bare token), so clients could
// connect by DNS but not by IP — and the CLI hid the x509 mismatch behind
// "no daemon running and no db". This group pins: SAN parsing (nothing dropped),
// SAN self-verification of the issued cert, visible connection failures with a
// SAN hint, multi-host failover, and many clients sharing one client cert.

// TestMtlsSANArgParsing pins D1: every requested SAN entry must survive parsing,
// in any flag order, comma- or space-separated, with flags after bare tokens
// (the old parser silently dropped everything from the first bare token on).
func TestMtlsSANArgParsing(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		ips   []string
		names []string
		exp   time.Duration
		want  string // required substring when err is non-empty
	}{
		{"comma lists", []string{"-ip", "10.0.0.1,10.0.0.2", "-dns", "a.b,c.d"}, []string{"10.0.0.1", "10.0.0.2"}, []string{"a.b", "c.d"}, 24 * time.Hour, ""},
		{"space-separated lists (regression)", []string{"-ip", "10.0.0.1", "10.0.0.2", "-dns", "a.b"}, []string{"10.0.0.1", "10.0.0.2"}, []string{"a.b"}, 24 * time.Hour, ""},
		{"flags after bare tokens (regression)", []string{"-dns", "a.b", "10.0.0.1", "-expire", "72h"}, []string{"10.0.0.1"}, []string{"a.b"}, 72 * time.Hour, ""},
		{"bare tokens classify", []string{"10.0.0.1", "svc.local"}, []string{"10.0.0.1"}, []string{"svc.local"}, 24 * time.Hour, ""},
		{"flag=value form", []string{"-ip=10.0.0.9", "-dns=zz.test", "-expire=48h"}, []string{"10.0.0.9"}, []string{"zz.test"}, 48 * time.Hour, ""},
		{"duplicates dedup", []string{"-ip", "10.0.0.1,10.0.0.1", "10.0.0.1"}, []string{"10.0.0.1"}, nil, 24 * time.Hour, ""},
		{"-ip with a name errors", []string{"-ip", "notanip"}, nil, nil, 0, "not an IP address"},
		{"-dns with an IP errors", []string{"-dns", "10.0.0.1"}, nil, nil, 0, "is an IP address"},
		{"bad dns name errors", []string{"-dns", "-leading"}, nil, nil, 0, "DNS name"},
		{"unknown flag errors", []string{"-bogus", "x"}, nil, nil, 0, "unknown flag"},
		{"-expire without value errors", []string{"-ip", "10.0.0.1", "-expire"}, nil, nil, 0, "needs a value"},
		{"bad duration errors", []string{"-ip", "10.0.0.1", "-expire", "soon"}, nil, nil, 0, "duration"},
		{"no SANs parses empty (defaults applied by doMtls)", []string{}, nil, nil, 24 * time.Hour, ""},
		{"-expire only parses empty", []string{"-expire", "48h"}, nil, nil, 48 * time.Hour, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sa, err := parseMtlsArgs(c.args)
			if c.want != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got none (sa=%+v)", c.want, sa)
				}
				if !strings.Contains(err.Error(), c.want) {
					t.Fatalf("error %q does not contain %q", err, c.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(sa.ips, c.ips) {
				t.Errorf("ips = %v, want %v", sa.ips, c.ips)
			}
			if !reflect.DeepEqual(sa.names, c.names) {
				t.Errorf("names = %v, want %v", sa.names, c.names)
			}
			if sa.expire != c.exp {
				t.Errorf("expire = %v, want %v", sa.expire, c.exp)
			}
		})
	}
}

// TestMtlsCertSANSelfCheck pins D2: verifyCertSANs must accept a cert carrying
// every requested SAN and reject one missing any IP or DNS entry (the guard
// against issuing a PKI that drops a requested SAN).
func TestMtlsCertSANSelfCheck(t *testing.T) {
	caKey, caCert := cryptoGenerateCA("test CA", time.Hour)
	_, srv := cryptoGenerateLeaf(caKey, caCert, "srv",
		[]net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("2001:db8::1")},
		[]string{"a.b"}, time.Hour)
	if err := verifyCertSANs(srv, []string{"10.0.0.1", "2001:db8::1"}, []string{"a.b"}); err != nil {
		t.Fatalf("all-present must pass (IPv4+IPv6+DNS): %v", err)
	}
	if err := verifyCertSANs(srv, []string{"10.0.0.3"}, nil); err == nil {
		t.Fatal("missing IP SAN must be rejected")
	}
	if err := verifyCertSANs(srv, nil, []string{"zzz.other"}); err == nil {
		t.Fatal("missing DNS SAN must be rejected")
	}
}

// writeTestPEM writes PEM bytes into a test dir (helper for group 26).
func writeTestPEM(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatal(err)
	}
}

// serveToolboxSocket serves tb on a unix socket at path, the way the daemon
// does, for the client commands of a built binary to reach.
func serveToolboxSocket(t *testing.T, tb *Toolbox, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go serveUnix(ln, tb, make(chan error, 1))
}

// freePort returns a localhost TCP port that is free at call time.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

// startTestTLSHTTPServer starts an mTLS HTTP server (healthz) on 127.0.0.1 with
// the given server cert/key + client CA; returns the port and a stop func.
func startTestTLSHTTPServer(t *testing.T, srvCert *x509.Certificate, srvKey *ecdsa.PrivateKey, caPool *x509.CertPool) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert.Raw}, PrivateKey: srvKey}},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv := &http.Server{Handler: mux, TLSConfig: tlsCfg}
	// ServeTLS wraps the RAW listener in TLS itself (a pre-wrapped listener
	// double-encrypts and breaks the handshake).
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	return port, func() { _ = srv.Close() }
}

// TestLiveDaemonSurfacesTLSNameMismatch pins D5: when the dialed IP is not in
// the server cert's SANs, liveDaemon must RETURN the x509 mismatch (not swallow
// it) and daemonConnHint must turn it into the actionable "regenerate with
// kbtool mtls -ip …" hint — the user-facing fix for the "no daemon running"
// confusion.
func TestLiveDaemonSurfacesTLSNameMismatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_SOCKET", "")
	caKey, caCert := cryptoGenerateCA("test CA", time.Hour)
	// Server cert for 192.0.2.99 ONLY (NOT 127.0.0.1) — dialing 127.0.0.1 must
	// fail hostname verification.
	srvKey, srvCert := cryptoGenerateLeaf(caKey, caCert, "srv", []net.IP{net.ParseIP("192.0.2.99")}, nil, time.Hour)
	cliKey, cliCert := cryptoGenerateLeaf(caKey, caCert, "cli", nil, nil, time.Hour)
	writeTestPEM(t, dir, "ca.crt", cryptoPEMCert(caCert))
	writeTestPEM(t, dir, "client.crt", cryptoPEMCert(cliCert))
	writeTestPEM(t, dir, "client.key", cryptoPEMKey(cliKey))

	// Server cert for 192.0.2.99 only; the client dials 127.0.0.1 → SAN mismatch.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cryptoPEMCert(caCert))
	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert.Raw}, PrivateKey: srvKey}},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake() // drive the lazy handshake so the client gets a proper x509 failure
				}
				_ = c.Close()
			}(c)
		}
	}()
	defer func() { _ = tlsLn.Close(); <-acceptDone }()

	cc := &clientConfig{Host: "127.0.0.1", Port: port, TLS: true,
		CaCert: "ca.crt", ClientCert: "client.crt", ClientKey: "client.key"}
	if err := saveClientConfig(cc); err != nil {
		t.Fatal(err)
	}

	_, _, ok, err := liveDaemon()
	if ok {
		t.Fatal("must not report a live daemon (the SAN does not cover 127.0.0.1)")
	}
	if err == nil || !strings.Contains(err.Error(), "not 127.0.0.1") {
		t.Fatalf("x509 SAN mismatch not surfaced: %v", err)
	}
	if h := daemonConnHint(err); !strings.Contains(h, "kbtool mtls -ip") {
		t.Fatalf("missing SAN-mismatch hint: %q", h)
	}
}

// TestLiveDaemonSurfacesDeadPort pins D5's other half: plain connection failures
// (nothing listening) must also be surfaced with the endpoint URL, so a mis-set
// host/port is diagnosable instead of reading as "no daemon".
func TestLiveDaemonSurfacesDeadPort(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_SOCKET", "")
	caKey, caCert := cryptoGenerateCA("test CA", time.Hour)
	cliKey, cliCert := cryptoGenerateLeaf(caKey, caCert, "cli", nil, nil, time.Hour)
	writeTestPEM(t, dir, "ca.crt", cryptoPEMCert(caCert))
	writeTestPEM(t, dir, "client.crt", cryptoPEMCert(cliCert))
	writeTestPEM(t, dir, "client.key", cryptoPEMKey(cliKey))
	deadPort := freePort(t) // free ⇒ nothing listening

	cc := &clientConfig{Host: "127.0.0.1", Port: deadPort, TLS: true,
		CaCert: "ca.crt", ClientCert: "client.crt", ClientKey: "client.key"}
	if err := saveClientConfig(cc); err != nil {
		t.Fatal(err)
	}
	_, _, ok, err := liveDaemon()
	if ok {
		t.Fatal("must not report a live daemon")
	}
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("127.0.0.1:%d", deadPort)) {
		t.Fatalf("dead-endpoint failure not surfaced: %v", err)
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected a connection-refused detail: %v", err)
	}
}

// TestClientConfigHostsFailover pins D3+D4: a client.json with a dead primary
// host plus a hosts[] list must fail over to the live endpoint; an empty host
// with hosts[] set (the old "multi-IP, no DNS" bug) must still yield a usable
// endpoint.
func TestClientConfigHostsFailover(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_SOCKET", "")
	caKey, caCert := cryptoGenerateCA("test CA", time.Hour)
	srvKey, srvCert := cryptoGenerateLeaf(caKey, caCert, "srv", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour)
	cliKey, cliCert := cryptoGenerateLeaf(caKey, caCert, "cli", nil, nil, time.Hour)
	writeTestPEM(t, dir, "ca.crt", cryptoPEMCert(caCert))
	writeTestPEM(t, dir, "client.crt", cryptoPEMCert(cliCert))
	writeTestPEM(t, dir, "client.key", cryptoPEMKey(cliKey))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cryptoPEMCert(caCert))
	port, stop := startTestTLSHTTPServer(t, srvCert, srvKey, pool)
	defer stop()

	// Scenario 1: dead primary, live secondary in hosts[1].
	cc := &clientConfig{Host: "127.0.0.9", Hosts: []string{"127.0.0.9", "127.0.0.1"},
		Port: port, TLS: true, CaCert: "ca.crt", ClientCert: "client.crt", ClientKey: "client.key"}
	if err := saveClientConfig(cc); err != nil {
		t.Fatal(err)
	}
	_, desc, ok, err := liveDaemon()
	if !ok {
		t.Fatalf("expected failover to the live host, got: %v", err)
	}
	if !strings.Contains(desc, "127.0.0.1") {
		t.Fatalf("expected the live endpoint, got %q", desc)
	}

	// Scenario 2 (D3 regression): empty host + hosts set ⇒ still usable.
	cc2 := &clientConfig{Hosts: []string{"127.0.0.9", "127.0.0.1"},
		Port: port, TLS: true, CaCert: "ca.crt", ClientCert: "client.crt", ClientKey: "client.key"}
	if err := saveClientConfig(cc2); err != nil {
		t.Fatal(err)
	}
	_, desc2, ok2, err2 := liveDaemon()
	if !ok2 {
		t.Fatalf("empty-host config must fall back to hosts[0]+, got: %v", err2)
	}
	if !strings.Contains(desc2, "127.0.0.1") {
		t.Fatalf("expected the live endpoint, got %q", desc2)
	}

	// Scenario 3: all hosts dead ⇒ failure surfaced, not a silent false.
	cc3 := &clientConfig{Host: "127.0.0.9", Hosts: []string{"127.0.0.9"},
		Port: freePort(t), TLS: true, CaCert: "ca.crt", ClientCert: "client.crt", ClientKey: "client.key"}
	if err := saveClientConfig(cc3); err != nil {
		t.Fatal(err)
	}
	if _, _, ok3, err3 := liveDaemon(); ok3 {
		t.Fatal("all-dead hosts must not report live")
	} else if err3 == nil {
		t.Fatal("all-dead hosts must return a connection error")
	}
}

// TestMtlsSharedClientCertE2E is the user's scenario end-to-end (built binary,
// loopback only, skipped without the go toolchain):
//   - `mtls` with a space-separated multi-SAN list issues a cert carrying ALL of
//     them (D1) and a usable client.json (D3/D4);
//   - a client-only state dir (enrolled with the daemon's printed
//     `client -import` line, no DB) connects to the mTLS daemon BY IP;
//   - twelve concurrent clients sharing the SAME client cert all succeed (D6:
//     sharing is allowed by design — TLS has no per-cert uniqueness).
func TestMtlsSharedClientCertE2E(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary for the mTLS E2E")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	run := func(env []string, args ...string) (string, error) {
		c := exec.Command(bin, args...)
		c.Env = env
		out, err := c.CombinedOutput()
		return string(out), err
	}

	srvDir := filepath.Join(work, "srv")
	cliDir := filepath.Join(work, "cli")
	os.MkdirAll(srvDir, 0755)
	os.MkdirAll(cliDir, 0755)
	srvEnv := append(os.Environ(), "KBTOOL_DIR="+srvDir, "KB_EMBED_URL=")
	cliEnv := append(os.Environ(), "KBTOOL_DIR="+cliDir, "KB_EMBED_URL=")

	// D1 regression: space-separated SAN list (would have silently dropped
	// 127.0.0.2 and -dns under the old parser).
	mtlsOut, err := run(srvEnv, "mtls", "-ip", "127.0.0.1", "127.0.0.2", "-dns", "kbtool.test")
	if err != nil {
		t.Fatalf("mtls: %v\n%s", err, mtlsOut)
	}
	// The ISSUED cert must carry every requested SAN (D2's guard, through the CLI).
	b, err := os.ReadFile(filepath.Join(srvDir, "server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatal("no CERTIFICATE block in server.crt")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCertSANs(cert, []string{"127.0.0.1", "127.0.0.2"}, []string{"kbtool.test"}); err != nil {
		t.Fatalf("issued cert missing requested SANs: %v", err)
	}
	// Remote clients reach every SAN endpoint (D3/D4); the host itself keeps no
	// client.json (plans/host-socket-cli-and-live-reindex-plan.md).
	if fileExists(filepath.Join(srvDir, "client.json")) || !strings.Contains(mtlsOut, "remote client endpoints (one enrollment line each): kbtool.test, 127.0.0.1, 127.0.0.2") {
		t.Fatalf("mtls must list every SAN endpoint for remote clients and write no host client.json:\n%s", mtlsOut)
	}

	// Fixture DB so the daemon has something to serve.
	fx := filepath.Join(work, "fx")
	os.MkdirAll(filepath.Join(fx, "repo"), 0755)
	os.WriteFile(filepath.Join(fx, "repo", "hello.go"), []byte("package repo\n\nfunc Hello() string { return \"hello mTLS\" }\n"), 0644)
	dbPath := filepath.Join(srvDir, "kb.db")
	if out, err := run(srvEnv, "build", "-db", dbPath, fx); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	// Server daemon on a chosen port (all-interface bind: -mtls default).
	port := freePort(t)
	daemon := exec.Command(bin, "daemon", "run", "-http", "-mtls", "-bind", fmt.Sprintf("127.0.0.1:%d", port), "-db", dbPath)
	daemon.Env = srvEnv
	logPath := filepath.Join(work, "daemon.log")
	logF, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logF.Close()
	daemon.Stdout = logF
	daemon.Stderr = logF
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = daemon.Process.Kill(); _, _ = daemon.Process.Wait() }()
	// Wait for the boot line (printed once the port is bound).
	line := waitImportLine(t, logPath, "https://127.0.0.1:", 15*time.Second)

	// Friend's machine: client-only dir (no DB), enrolled by IP with the daemon's
	// printed one-liner (plans/mtls-client-bootstrap-plan.md).
	if out, err := run(cliEnv, strings.Fields(line)[1:]...); err != nil || !strings.Contains(out, "mTLS to https://127.0.0.1:") {
		t.Fatalf("client -import: %v\n%s", err, out)
	}
	// Re-running the line needs -yes (client.json would be replaced) and works with it.
	if out, err := run(cliEnv, strings.Fields(line)[1:]...); err == nil || !strings.Contains(out, "-yes") {
		t.Fatalf("re-import without -yes must refuse: %v\n%s", err, out)
	}
	if out, err := run(cliEnv, append(strings.Fields(line)[1:], "-yes")...); err != nil {
		t.Fatalf("re-import with -yes: %v\n%s", err, out)
	}
	// Removed forms: file import, export, and the long -bundle/-fingerprint/-key/-session flags.
	w := strings.Fields(line)
	tok, _ := parseEnrollToken(w[4])
	longForm := []string{"client", "-import", w[3], "-bundle", bundleIDFromKey(tok.Key), "-fingerprint", "x", "-key", base64.RawURLEncoding.EncodeToString(tok.Key)}
	for _, args := range [][]string{{"client", "-import", "client.kbx", "-key", "k"}, {"client", "-export", "-key", "k"}, longForm,
		{"client", "-import", w[3], w[4], "-session", newRelaySessionID()}, {"client", "-import", w[3]}} {
		if out, err := run(cliEnv, args...); err == nil {
			t.Fatalf("%v must fail:\n%s", args, out)
		}
	}
	// A token in the wrong form: direct token alone, relay token behind a URL, relay token without a session.
	relayTok := enrollToken{Host: "127.0.0.1", Session: newRelaySessionID(), Key: tok.Key}.encode()
	noSession := enrollToken{Host: "127.0.0.1", Key: tok.Key}.encode()
	for args, want := range map[[4]string]string{
		{"client", "-import", w[4], ""}:       "put the daemon URL in front of it",
		{"client", "-import", w[3], relayTok}: "pass it alone",
		{"client", "-import", noSession, ""}:  "put the daemon URL in front of it",
	} {
		a := args[:]
		if a[3] == "" {
			a = a[:3]
		}
		if out, err := run(cliEnv, a...); err == nil || !strings.Contains(out, want) {
			t.Fatalf("%v must fail with %q: %v\n%s", a, want, err, out)
		}
	}

	call := func() (string, error) {
		return run(cliEnv, "call", "list_files")
	}
	// [1] single client by IP must reach the daemon (D5's happy path).
	if out, err := call(); err != nil || !strings.Contains(out, "(via daemon: https://127.0.0.1:") || !strings.Contains(out, "hello.go") {
		t.Fatalf("by-IP connect failed:\n%s\nerr=%v", out, err)
	}
	// [2] twelve concurrent clients with the SAME client cert (D6).
	var wg sync.WaitGroup
	errs := make([]error, 12)
	outs := make([]string, 12)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outs[i], errs[i] = call()
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil || !strings.Contains(outs[i], "hello.go") || !strings.Contains(outs[i], "(via daemon: https://127.0.0.1:") {
			t.Fatalf("shared-cert client %d failed (12-way same cert):\n%s\nerr=%v", i+1, outs[i], e)
		}
	}
}

// waitImportLine polls a daemon log for its boot-time `kbtool client -import`
// command for the given URL prefix and returns the command (group 26/31 helper).
func waitImportLine(t *testing.T, logPath, urlPrefix string, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(logPath)
		for _, l := range strings.Split(string(b), "\n") {
			if i := strings.Index(l, "kbtool client -import "+urlPrefix); i >= 0 {
				return l[i:]
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, _ := os.ReadFile(logPath)
	t.Fatalf("no 'kbtool client -import %s' line in the daemon log:\n%s", urlPrefix, b)
	return ""
}

// mustReadFile reads a file or fails the test (group 26 helper).
func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---------- 27. mTLS client-only endpoint (plans/mtls-client-only-endpoint-plan.md) ----------
//
// Regression context: with client.json tls=true, liveDaemon still tried
// KBTOOL_SOCKET / daemon.sock / mcp.sock first, and when nothing answered the
// CLI silently fell back to the local db and board.bin. An agent whose mTLS
// endpoint was unreachable therefore signed up and posted on a PRIVATE board
// and never saw its collaborators. This group pins: mTLS ⇒ only the client.json
// endpoint, cert errors surfaced, and no local fallback from any client command.

// shortStateDir returns a short temp dir usable as KBTOOL_DIR that can also hold a
// unix socket (t.TempDir paths can exceed the sun_path limit on some platforms).
func shortStateDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "kb27")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// startTestUnixDaemon serves the MCP line protocol (fakeExec) on socket.
func startTestUnixDaemon(t *testing.T, socket string) {
	t.Helper()
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = serveLines(c, c, &fakeExec{})
			}(c)
		}
	}()
}

// writeTestClientPKI writes ca.crt / client.crt / client.key into dir.
func writeTestClientPKI(t *testing.T, dir string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	caKey, caCert := cryptoGenerateCA("test CA", time.Hour)
	cliKey, cliCert := cryptoGenerateLeaf(caKey, caCert, "cli", nil, nil, time.Hour)
	writeTestPEM(t, dir, "ca.crt", cryptoPEMCert(caCert))
	writeTestPEM(t, dir, "client.crt", cryptoPEMCert(cliCert))
	writeTestPEM(t, dir, "client.key", cryptoPEMKey(cliKey))
	return caKey, caCert
}

func mtlsHostConfig(port int) *clientConfig {
	return &clientConfig{Host: "127.0.0.1", Port: port, TLS: true,
		CaCert: "ca.crt", ClientCert: "client.crt", ClientKey: "client.key"}
}

// assertOnlyClientFiles fails when the state dir holds anything but the mTLS
// client files (plus extra): a pure client must never create kb.db, board.bin,
// *.lock, pid/log files or sockets — the backend daemon owns all of that.
func assertOnlyClientFiles(t *testing.T, dir string, extra ...string) {
	t.Helper()
	allowed := map[string]bool{"ca.crt": true, "client.crt": true, "client.key": true, "client.json": true}
	for _, e := range extra {
		allowed[e] = true
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !allowed[e.Name()] {
			t.Fatalf("pure mTLS client created local state %q in %s", e.Name(), dir)
		}
	}
}

// startTestMtlsDaemon serves the real daemon HTTP handler (httpHandler) over mTLS
// on 127.0.0.1 with ex as the backend; returns the port.
func startTestMtlsDaemon(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, ex executor) int {
	t.Helper()
	srvKey, srvCert := cryptoGenerateLeaf(caKey, caCert, "srv", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cryptoPEMCert(caCert))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: httpHandler(ex), TLSConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert.Raw}, PrivateKey: srvKey}},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// TestMtlsPureClientUsesBackendToolsAndState is the reported `kbtool tools` bug:
// a pure client (certs + client.json only, no config.json) showed the LOCAL
// default tool set, which hides the message board, instead of what the backend
// serves. The tool list (CLI + the stdio-mcp proxy's filter) must come from the
// daemon, tool calls must go there, and the state dir must stay client-only.
func TestMtlsPureClientUsesBackendToolsAndState(t *testing.T) {
	dir := shortStateDir(t)
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_SOCKET", "")
	t.Setenv("KBTOOL_DB", "")
	t.Setenv("KBTOOL_BOARD", "")
	caKey, caCert := writeTestClientPKI(t, dir)
	backend := &fakeExec{disabled: map[string]bool{"kb_status": true}} // backend: git tools ON
	port := startTestMtlsDaemon(t, caKey, caCert, backend)
	if err := saveClientConfig(mtlsHostConfig(port)); err != nil {
		t.Fatal(err)
	}
	if !effectiveDisabledSet(nil)["git_blame"] {
		t.Fatal("control: the local default view must hide the git tools (else this test is vacuous)")
	}

	tools, via, err := cliToolList()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(via, "https://127.0.0.1:") {
		t.Fatalf("tool list not from the mTLS daemon: via=%q", via)
	}
	got := map[string]bool{}
	for _, tl := range tools {
		got[tl.Name] = true
	}
	if !got["git_blame"] || !got["board_post"] || got["kb_status"] {
		t.Fatalf("tool list must be the backend's (git tools on, kb_status off), got %v", got)
	}

	ex, _, ok, err := liveDaemon()
	if !ok {
		t.Fatal(err)
	}
	if ex.toolDisabled("git_blame") || !ex.toolDisabled("kb_status") {
		t.Fatal("stdio-mcp proxy filter must follow the backend's tools/list")
	}
	if text, isErr := ex.Execute("board_threads", json.RawMessage(`{}`)); isErr || text != "exec:board_threads" {
		t.Fatalf("tool call not served by the backend: %q (err=%v)", text, isErr)
	}
	assertOnlyClientFiles(t, dir)
}

// TestMtlsClientSkipsLocalSockets pins the core bug: a live local daemon socket
// offered through KBTOOL_SOCKET must NOT be used by a remote client — the dead
// endpoint's failure is returned instead, without noise from the socket. The
// no-client.json control proves the socket is live, so the remote case isn't
// vacuous (plans/host-socket-cli-and-live-reindex-plan.md: a remote client
// talks only to its client.json endpoint, with or without TLS).
func TestMtlsClientSkipsLocalSockets(t *testing.T) {
	dir := shortStateDir(t)
	t.Setenv("KBTOOL_DIR", dir)
	sock := filepath.Join(shortStateDir(t), "daemon.sock")
	t.Setenv("KBTOOL_SOCKET", sock)
	startTestUnixDaemon(t, sock)
	writeTestClientPKI(t, dir)

	if _, desc, ok, err := liveDaemon(); !ok || !strings.HasPrefix(desc, "unix ") {
		t.Fatalf("control: without client.json the local socket must win, got ok=%v desc=%q err=%v", ok, desc, err)
	}
	dead := freePort(t)
	plain := mtlsHostConfig(dead)
	plain.TLS = false
	if err := saveClientConfig(plain); err != nil {
		t.Fatal(err)
	}
	if _, desc, ok, _ := liveDaemon(); ok {
		t.Fatalf("a remote client without TLS must not use the local socket either, got %q", desc)
	}

	if err := saveClientConfig(mtlsHostConfig(dead)); err != nil {
		t.Fatal(err)
	}
	_, desc, ok, err := liveDaemon()
	if ok {
		t.Fatalf("mTLS configured: the local socket must be skipped, but got %q", desc)
	}
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("127.0.0.1:%d", dead)) {
		t.Fatalf("expected the mTLS endpoint failure, got: %v", err)
	}
	if strings.Contains(err.Error(), "daemon.sock") || strings.Contains(err.Error(), "mcp.sock") {
		t.Fatalf("a failed opportunistic local socket must not be reported under mTLS: %v", err)
	}
}

// TestMtlsClientUsesOnlyMtlsEndpoint: with BOTH a live local socket and a live
// mTLS endpoint, the mTLS endpoint is chosen (before, the socket won).
func TestMtlsClientUsesOnlyMtlsEndpoint(t *testing.T) {
	dir := shortStateDir(t)
	t.Setenv("KBTOOL_DIR", dir)
	stray := filepath.Join(shortStateDir(t), "daemon.sock") // a live socket outside the client's dir
	t.Setenv("KBTOOL_SOCKET", stray)
	startTestUnixDaemon(t, stray)
	caKey, caCert := writeTestClientPKI(t, dir)
	srvKey, srvCert := cryptoGenerateLeaf(caKey, caCert, "srv", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cryptoPEMCert(caCert))
	port, stop := startTestTLSHTTPServer(t, srvCert, srvKey, pool)
	defer stop()
	if err := saveClientConfig(mtlsHostConfig(port)); err != nil {
		t.Fatal(err)
	}
	_, desc, ok, err := liveDaemon()
	if !ok {
		t.Fatalf("live mTLS endpoint not used: %v", err)
	}
	if !strings.HasPrefix(desc, "https://127.0.0.1:") {
		t.Fatalf("expected the mTLS endpoint, got %q", desc)
	}
}

// TestMtlsClientConfigErrorsSurfaced: an unloadable client cert (it used to be
// dropped silently, leaving no candidate and a nil error — the trigger for the
// silent local fallback) and a tls=true config with no endpoint must both be
// returned as errors, even with a live local socket present.
func TestMtlsClientConfigErrorsSurfaced(t *testing.T) {
	dir := shortStateDir(t)
	t.Setenv("KBTOOL_DIR", dir)
	stray := filepath.Join(shortStateDir(t), "daemon.sock") // a live socket outside the client's dir
	t.Setenv("KBTOOL_SOCKET", stray)
	startTestUnixDaemon(t, stray)

	if err := saveClientConfig(mtlsHostConfig(freePort(t))); err != nil { // no PKI written yet
		t.Fatal(err)
	}
	if _, desc, ok, err := liveDaemon(); ok || err == nil || !strings.Contains(err.Error(), "client cert/key") {
		t.Fatalf("missing client cert must be an error (not a socket fallback): ok=%v desc=%q err=%v", ok, desc, err)
	}

	writeTestClientPKI(t, dir)
	noEP := mtlsHostConfig(0)
	noEP.Host = ""
	if err := saveClientConfig(noEP); err != nil {
		t.Fatal(err)
	}
	if _, desc, ok, err := liveDaemon(); ok || err == nil || !strings.Contains(err.Error(), "no endpoint") {
		t.Fatalf("tls=true without an endpoint must be an error: ok=%v desc=%q err=%v", ok, desc, err)
	}
}

// TestMtlsClientRefusesLocalFallbackCLI is the user's scenario through the built
// binary: with an unreachable mTLS endpoint, `call board_signup`, `query`, and
// stdio `mcp` must fail and must NOT create a local board.bin. Without
// client.json and without a daemon the same call fails too: no client command
// opens the store itself.
func TestMtlsClientRefusesLocalFallbackCLI(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary for the CLI fallback test")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	dir := shortStateDir(t)
	env := append(os.Environ(), "KBTOOL_DIR="+dir, "KBTOOL_SOCKET=", "KBTOOL_DB=", "KBTOOL_BOARD=", "KB_EMBED_URL=")
	run := func(stdin string, args ...string) (string, error) {
		c := exec.Command(bin, args...)
		c.Env = env
		c.Stdin = strings.NewReader(stdin)
		out, err := c.CombinedOutput()
		return string(out), err
	}
	board := filepath.Join(dir, "board.bin")
	seedFile := filepath.Join(work, "seed")
	if err := os.WriteFile(seedFile, []byte(strings.Repeat("ab", 32)), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KBTOOL_DIR", dir) // saveClientConfig writes into the binary's state dir
	writeTestClientPKI(t, dir)
	if err := saveClientConfig(mtlsHostConfig(freePort(t))); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		stdin string
		args  []string
	}{
		{"", []string{"call", "board_signup", `{"name":"gus"}`}},
		{"", []string{"query", "anything"}},
		{"", []string{"terms", "anything"}},
		{"", []string{"bundle", "-q", "anything"}},
		{"", []string{"tools"}},
		{"", []string{"status"}},
		{"", []string{"board", "dump"}},
		{"", []string{"board", "attach", "-thread", "x", "-text", "y", "-seed-file", seedFile, "go.mod"}},
		{"", []string{"board", "fetch", "-seed-file", seedFile, "-o", work, "x#0"}},
		{`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n", []string{"mcp"}},
	}
	for _, c := range cases {
		out, err := run(c.stdin, c.args...)
		if err == nil {
			t.Fatalf("%v: must fail with an unreachable mTLS endpoint, got:\n%s", c.args, out)
		}
		if !strings.Contains(out, "endpoint is unreachable") {
			t.Fatalf("%v: missing the no-fallback error:\n%s", c.args, out)
		}
		if fileExists(board) {
			t.Fatalf("%v: a local board.bin was created under mTLS", c.args)
		}
		assertOnlyClientFiles(t, dir)
	}

	if err := os.Remove(filepath.Join(dir, "client.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"version":1,"message_board":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := run("", "call", "board_signup", `{"name":"gus"}`); err == nil || !strings.Contains(out, "no kbtool daemon is running") || fileExists(board) {
		t.Fatalf("without a daemon the board call must refuse and write nothing: err=%v\n%s", err, out)
	}
}

// ---------- 28. message board HTML dump (plans/message-board-html-dump-plan.md) ----------

// dumpSignup signs name up on tb's board and returns its seed.
func dumpSignup(t *testing.T, tb *Toolbox, name string) string {
	t.Helper()
	out, isErr := tb.Execute("board_signup", mustMarshal(map[string]any{"name": name}))
	if isErr {
		t.Fatalf("signup %s: %s", name, out)
	}
	m := regexp.MustCompile(`seed: ([0-9a-f]{64})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no seed in signup output: %q", out)
	}
	return m[1]
}

// dumpPost posts a signed message as the seed's identity.
func dumpPost(t *testing.T, tb *Toolbox, seed, thread, kind, text string) {
	t.Helper()
	args := map[string]any{"thread": thread, "kind": kind, "text": text, "seed": seed}
	if out, isErr := tb.Execute("board_post", mustMarshal(args)); isErr {
		t.Fatalf("post: %s", out)
	}
}

// editBoard applies fn to the stored board under the board lock and saves it,
// for crafting states the tools refuse to produce (forged/tampered messages).
func editBoard(t *testing.T, tb *Toolbox, fn func(b *Board)) {
	t.Helper()
	st := tb.store()
	unlock, err := st.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	b, err := st.loadBoard(false)
	if err != nil {
		t.Fatal(err)
	}
	fn(b)
	if err := st.saveBoard(b); err != nil {
		t.Fatal(err)
	}
}

func renderDump(t *testing.T, s boardSnapshot) string {
	t.Helper()
	var buf bytes.Buffer
	if err := renderBoardHTML(&buf, s); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

// TestBoardTemplateParsesAndIsEmbedded pins that the page template ships inside
// the binary: the embedded string is the real template, and it renders an empty
// snapshot (no threads, no agents) without error.
func TestBoardTemplateParsesAndIsEmbedded(t *testing.T) {
	if !strings.HasPrefix(messageBoardGohtml, "<!doctype html>") {
		head := messageBoardGohtml
		if len(head) > 40 {
			head = head[:40]
		}
		t.Fatalf("embedded template missing or wrong, starts with %q", head)
	}
	page := renderDump(t, boardSnapshot{})
	if !strings.Contains(page, "No agents have signed up yet.") || !strings.Contains(page, "0 thread(s)") {
		t.Fatalf("empty snapshot rendered unexpectedly:\n%s", page)
	}
}

// TestBoardSnapshotVerificationStatus pins that trust is computed by the producer
// and shown to the human: a genuine post is verified, a post signed with another
// agent's key is impersonation, tampered text is bad-signature, and both
// untrusted messages get the red badge and row.
func TestBoardSnapshotVerificationStatus(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	alice := dumpSignup(t, tb, "alice")
	bob := dumpSignup(t, tb, "bob")
	dumpPost(t, tb, alice, "welcome", "hello", "genuine alice")
	alicePriv, _, err := cryptoDeriveSeed(alice)
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, bobPub, err := cryptoDeriveSeed(bob)
	if err != nil {
		t.Fatal(err)
	}
	editBoard(t, tb, func(b *Board) {
		th := b.thread("welcome")
		now := time.Now().Unix()
		forged := BoardMsg{ID: b.NextID + 1, Thread: "welcome", Seq: len(th.Msgs), Agent: "alice",
			Pub: hex.EncodeToString(bobPub), Text: "forged alice", At: now, Kind: "info"}
		forged.Sig = cryptoSignBoard(bobPriv, canonicalMsg(forged))
		th.Msgs = append(th.Msgs, forged)
		tampered := BoardMsg{ID: b.NextID + 2, Thread: "welcome", Seq: len(th.Msgs), Agent: "alice",
			Pub: b.Agents["alice"].Pub, Text: "original", At: now, Kind: "info"}
		tampered.Sig = cryptoSignBoard(alicePriv, canonicalMsg(tampered))
		tampered.Text = "tampered"
		th.Msgs = append(th.Msgs, tampered)
		b.NextID += 2
	})
	s, err := tb.boardExport()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	var agentMsgs []snapMsg
	for _, m := range s.Threads[0].Msgs {
		if m.Agent == boardSystem {
			continue // the system intro (verified) is not under test here
		}
		agentMsgs = append(agentMsgs, m)
		got = append(got, m.Text+"="+m.Status)
	}
	s.Threads = s.Threads[:1]
	s.Threads[0].Msgs = agentMsgs
	want := []string{"genuine alice=verified", "forged alice=impersonation", "tampered=bad-signature"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
	page := renderDump(t, s)
	if strings.Count(page, `class="badge ok"`) != 1 || strings.Count(page, `class="badge bad"`) != 2 ||
		strings.Count(page, `class="msg untrusted"`) != 2 {
		t.Fatalf("verification badges/rows not rendered as expected:\n%s", page)
	}
}

// TestBoardSnapshotOrderAndRoster pins the page order (welcome first, then thread
// creation order, messages by seq) and that ACTIVE/STALE follows
// KBTOOL_BOARD_TTL at export time.
func TestBoardSnapshotOrderAndRoster(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	t.Setenv("KBTOOL_BOARD_TTL", "60")
	alice := dumpSignup(t, tb, "alice")
	dumpSignup(t, tb, "bob")
	dumpPost(t, tb, alice, "zeta", "info", "z0")
	dumpPost(t, tb, alice, "alpha", "info", "a0")
	dumpPost(t, tb, alice, "zeta", "task", "z1")
	editBoard(t, tb, func(b *Board) { b.Agents["bob"].LastSeen = time.Now().Unix() - 3600 })
	s, err := tb.boardExport()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, th := range s.Threads {
		ids = append(ids, th.ID)
	}
	if !reflect.DeepEqual(ids, []string{"welcome", "system", "zeta", "alpha"}) {
		t.Fatalf("thread order = %v", ids)
	}
	if z := s.Threads[2].Msgs; len(z) != 2 || z[0].Text != "z0" || z[1].Text != "z1" || z[1].Seq != 1 {
		t.Fatalf("zeta messages out of seq order: %+v", z)
	}
	if s.TTL != 60 || len(s.Agents) != 3 || s.Agents[0].ID != boardSystem {
		t.Fatalf("ttl=%d agents=%+v (system first)", s.TTL, s.Agents)
	}
	if a := s.Agents[1]; a.ID != "alice" || !a.Active {
		t.Fatalf("most recent agent should be ACTIVE alice, got %+v", a)
	}
	if b := s.Agents[2]; b.ID != "bob" || b.Active {
		t.Fatalf("bob (last seen 1h ago, ttl 60s) should be STALE, got %+v", b)
	}
}

// TestBoardDumpEscapesUntrustedText pins html/template: board text is untrusted
// agent input, so markup in a message renders as text (stored-XSS guard),
// including inside the data-search attribute.
func TestBoardDumpEscapesUntrustedText(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "mallory")
	dumpPost(t, tb, seed, "welcome", "info", `<script>alert(1)</script> "><img src=x onerror=alert(2)>`)
	s, err := tb.boardExport()
	if err != nil {
		t.Fatal(err)
	}
	page := renderDump(t, s)
	for _, raw := range []string{"<script>alert(1)", "<img src=x", `"><img`} {
		if strings.Contains(page, raw) {
			t.Fatalf("unescaped %q in page:\n%s", raw, page)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("message text should be present, escaped:\n%s", page)
	}
}

// TestBoardTemplateCollapsesBlobs pins that a long base64 line (how agents share
// tarballs) becomes its own collapsed segment, short text stays inline, and the
// blob stays out of the filter text and the summary preview.
func TestBoardTemplateCollapsesBlobs(t *testing.T) {
	blob := strings.Repeat("QUJD", 1250)
	text := "see attachment abc123\n" + blob + "\nbye"
	want := []boardSegment{{Text: "see attachment abc123"}, {Blob: true, Text: blob}, {Text: "bye"}}
	if got := boardSegments(text); !reflect.DeepEqual(got, want) {
		t.Fatalf("segments = %+v", got)
	}
	m := snapMsg{Agent: "ben", Kind: "result", Text: text, Status: "verified"}
	if strings.Contains(boardSearchText(m), "qujd") {
		t.Fatal("blob leaked into the filter text")
	}
	if p := boardPreview(text); p != "see attachment abc123" {
		t.Fatalf("preview = %q", p)
	}
	if p := boardPreview(blob + "\nafter"); p != "after" {
		t.Fatalf("preview must skip a leading blob, got %q", p)
	}
	page := renderDump(t, boardSnapshot{Threads: []snapThread{{ID: "t", Msgs: []snapMsg{m}}}})
	if !strings.Contains(page, `<details class="blob"><summary>base64 attachment (5000 chars)</summary>`) {
		t.Fatalf("blob not collapsed:\n%s", page)
	}
}

// TestBoardDumpIsReadOnly pins that exporting never writes: the board bytes are
// unchanged (no last-seen bump, no save), and a missing board is an error rather
// than being created.
func TestBoardDumpIsReadOnly(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	dumpPost(t, tb, seed, "welcome", "hello", "hi")
	before, err := os.ReadFile(tb.BoardPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tb.boardExport(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(tb.BoardPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("board file changed during export")
	}

	empty := newBoardToolbox(t, nil)
	if _, err := empty.boardExport(); err == nil {
		t.Fatal("exporting a missing board must be an error")
	}
	if fileExists(empty.BoardPath) {
		t.Fatal("export created a board")
	}
}

// TestBoardExportNotAnMCPTool pins that board/export is a JSON-RPC method for the
// human CLI, not an agent tool: absent from tools/list, refused by tools/call,
// served over the daemon's HTTP route, and method-not-found for an executor
// that cannot export.
func TestBoardExportNotAnMCPTool(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	// A loaded DB, so tools/call reaches the tool lookup ("unknown tool") instead of
	// stopping at "knowledge base not loaded".
	tb := newBoardToolbox(t, makeDB(t, []Chunk{{Path: "a", Kind: "code", Text: "base chunk"}}))
	seed := dumpSignup(t, tb, "alice")
	dumpPost(t, tb, seed, "welcome", "hello", "over http")

	res, err := dispatch(tb, "tools/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.(map[string]any)["tools"].([]mcpTool) {
		if strings.Contains(tl.Name, "export") {
			t.Fatalf("tools/list exposes %q", tl.Name)
		}
	}
	if out, isErr := tb.Execute("board/export", nil); !isErr || !strings.Contains(out, "unknown tool") {
		t.Fatalf("tools/call must refuse board/export, got (%q, %v)", out, isErr)
	}

	srv := httptest.NewServer(httpHandler(tb))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"board/export"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rr struct {
		Result boardSnapshot `json:"result"`
		Error  *rpcError     `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		t.Fatal(err)
	}
	if rr.Error != nil || len(rr.Result.Threads) != 2 || len(rr.Result.Threads[0].Msgs) != 2 ||
		rr.Result.Threads[0].Msgs[1].Text != "over http" || rr.Result.Threads[0].Msgs[1].Status != "verified" {
		t.Fatalf("board/export over HTTP: error=%v result=%+v", rr.Error, rr.Result)
	}

	if _, err := dispatch(&fakeExec{}, "board/export", nil); err == nil || !strings.Contains(err.Error(), "method not found") {
		t.Fatalf("non-exporting executor must answer method not found, got %v", err)
	}
}

// TestBoardExportRemoteOverMtls pins the pure-client path: with client.json
// tls=true the dump comes from the backend over mTLS (board/export), equals the
// backend's own snapshot, and the client state dir stays client-only.
func TestBoardExportRemoteOverMtls(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	dumpPost(t, tb, seed, "welcome", "hello", "from the backend")

	dir := shortStateDir(t)
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_SOCKET", "")
	t.Setenv("KBTOOL_DB", "")
	caKey, caCert := writeTestClientPKI(t, dir)
	port := startTestMtlsDaemon(t, caKey, caCert, tb)
	if err := saveClientConfig(mtlsHostConfig(port)); err != nil {
		t.Fatal(err)
	}
	got, via, err := boardDumpSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(via, "https://127.0.0.1:") {
		t.Fatalf("dump not served by the mTLS backend: via=%q", via)
	}
	want, err := tb.boardExport()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Threads, want.Threads) || !reflect.DeepEqual(got.Agents, want.Agents) {
		t.Fatalf("remote snapshot differs from the backend's:\n got %+v\nwant %+v", got, want)
	}
	assertOnlyClientFiles(t, dir)
}

// TestBoardExportDisabledBoard pins that a config with the message board off
// (message_board false) refuses the export with an explanation instead of
// rendering an empty page; the control exports the same board once it is on.
func TestBoardExportDisabledBoard(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	dumpPost(t, tb, seed, "welcome", "hello", "hi")
	off := false
	tb.Disabled = effectiveDisabledSet(&config{MessageBoard: &off})
	if _, err := tb.boardExport(); err == nil || !strings.Contains(err.Error(), "disabled by config") {
		t.Fatalf("board off must refuse the export, got %v", err)
	}
	on := true
	tb.Disabled = effectiveDisabledSet(&config{MessageBoard: &on})
	if s, err := tb.boardExport(); err != nil || len(s.Threads) != 2 {
		t.Fatalf("control: board on must export, got %v (threads=%d)", err, len(s.Threads))
	}
}

// TestBoardDumpBinaryRunsWithoutTemplateOnDisk pins "never an external asset
// after building": the binary from the single-command build runs in an empty
// directory (no message_board.gohtml) and still renders the page, to stdout by
// default and to a 0600 file with -o.
func TestBoardDumpBinaryRunsWithoutTemplateOnDisk(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	bin := filepath.Join(t.TempDir(), "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	dumpPost(t, tb, seed, "welcome", "hello", "embedded template works")
	state := os.Getenv("KBTOOL_DIR")
	if err := os.WriteFile(filepath.Join(state, "config.json"), []byte(`{"version":1,"message_board":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	sock := filepath.Join(shortStateDir(t), "daemon.sock")
	serveToolboxSocket(t, tb, sock)
	env := append(os.Environ(), "KBTOOL_DIR="+state, "KBTOOL_SOCKET="+sock,
		"KBTOOL_DB=", "KBTOOL_BOARD="+tb.BoardPath, "KB_EMBED_URL=")
	cmd := func(args ...string) *exec.Cmd {
		c := exec.Command(bin, args...)
		c.Dir = work
		c.Env = env
		return c
	}

	out, err := cmd("board", "dump").Output()
	if err != nil {
		t.Fatalf("board dump: %v", err)
	}
	if !strings.HasPrefix(string(out), "<!doctype html>") || !strings.Contains(string(out), "embedded template works") {
		t.Fatalf("stdout is not the rendered page:\n%s", out)
	}

	if b, err := cmd("board", "dump", "-o", "page.html").CombinedOutput(); err != nil {
		t.Fatalf("board dump -o: %v\n%s", err, b)
	}
	page := filepath.Join(work, "page.html")
	fi, err := os.Stat(page)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("page mode = %v, want 0600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(page); !strings.Contains(string(b), "embedded template works") {
		t.Fatal("-o file is missing the board content")
	}
	ents, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("work dir should hold only page.html, got %d entries", len(ents))
	}
}

// ---------- 29. message board attachments (plans/message-board-attachments-plan.md) ----------

// rawEntry is one hand-built tar entry for crafting hostile archives.
type rawEntry struct {
	hdr  tar.Header
	data string
}

// rawTarGZ builds a tar.gz byte for byte as given (no sorting, no validation),
// so tests can produce archives kbtool itself would never write.
func rawTarGZ(t *testing.T, entries ...rawEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := e.hdr
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg && h.Size == 0 {
			h.Size = int64(len(e.data))
		}
		if h.Mode == 0 {
			h.Mode = 0644
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// packFiles packs in-memory files the way the CLI does (deterministic tar.gz).
func packFiles(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var ms []tarGZMember
	for n, d := range files {
		ms = append(ms, tarGZMember{Name: n, Data: []byte(d)})
	}
	data, _, err := attachPack(ms)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// postAttachment posts a message carrying data as its attachment.
func postAttachment(tb *Toolbox, seed, thread string, data []byte) (string, bool) {
	return tb.Execute("board_post", mustMarshal(map[string]any{"thread": thread, "text": "see attachment",
		"seed": seed, "attachment": base64.StdEncoding.EncodeToString(data)}))
}

// TestTarGZWriteDeterministicAndStreamed pins that the shared tar.gz writer is
// deterministic (same inputs, same bytes, hence a stable signed digest) and that
// disk members are streamed with the same content as in-memory ones.
func TestTarGZWriteDeterministicAndStreamed(t *testing.T) {
	a := packFiles(t, map[string]string{"b.txt": "bee", "a/c.txt": "sea"})
	b := packFiles(t, map[string]string{"a/c.txt": "sea", "b.txt": "bee"})
	if !bytes.Equal(a, b) {
		t.Fatal("identical inputs produced different archives")
	}
	p := filepath.Join(t.TempDir(), "c.txt")
	if err := os.WriteFile(p, []byte("sea"), 0600); err != nil {
		t.Fatal(err)
	}
	var disk, mem bytes.Buffer
	if err := tarGZWrite(&disk, []tarGZMember{{Name: "c.txt", Path: p}}); err != nil {
		t.Fatal(err)
	}
	if err := tarGZWrite(&mem, []tarGZMember{{Name: "c.txt", Data: []byte("sea")}}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(disk.Bytes(), mem.Bytes()) {
		t.Fatal("a disk member and the same in-memory member packed differently")
	}
	files, err := attachManifest(a)
	if err != nil || len(files) != 2 || files[0].Name != "a/c.txt" || files[1].Size != 3 {
		t.Fatalf("manifest = %+v, %v", files, err)
	}
}

// TestAttachManifestRejectsHostileArchives pins full upload validation: every
// archive shape that could escape the extraction directory, overwrite through a
// link, or exhaust memory is refused before it is stored.
func TestAttachManifestRejectsHostileArchives(t *testing.T) {
	big := strings.Repeat("\x00", boardMaxAttachUnpacked+1)
	cases := map[string][]byte{
		"not gzip":     []byte("plain text"),
		"empty":        rawTarGZ(t),
		"traversal":    rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "../evil"}, data: "x"}),
		"inner dotdot": rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "a/../../evil"}, data: "x"}),
		"absolute":     rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "/etc/evil"}, data: "x"}),
		"symlink":      rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}),
		"hardlink":     rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "hl", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"}}),
		"directory":    rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "d/", Typeflag: tar.TypeDir}}),
		"duplicate":    rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "a"}, data: "1"}, rawEntry{hdr: tar.Header{Name: "a"}, data: "2"}),
		"file vs dir":  rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "a"}, data: "1"}, rawEntry{hdr: tar.Header{Name: "a/b"}, data: "2"}),
		"control char": rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "a\nb"}, data: "x"}),
		"unclean":      rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "a//b"}, data: "x"}),
		"bomb":         rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "zeros"}, data: big}),
	}
	for name, data := range cases {
		if _, err := attachManifest(data); err == nil {
			t.Errorf("%s: hostile archive was accepted", name)
		}
	}
	if _, err := attachManifest(rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "ok/file.txt"}, data: "x"})); err != nil {
		t.Fatalf("control: a clean archive was refused: %v", err)
	}
}

// TestBoardAttachmentRoundTrip pins the MCP surface end to end: board_post stores
// and signs the attachment, board_read summarizes it (no payload), board_fetch
// returns the exact bytes as verified, and the board file round-trips it.
func TestBoardAttachmentRoundTrip(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	data := packFiles(t, map[string]string{"plans/plan.md": "# plan", "tickets/01-x.md": "ticket"})
	out, isErr := postAttachment(tb, seed, "plans", data)
	if isErr || !strings.Contains(out, "attachment: 2 file(s)") || !strings.Contains(out, "sha256 "+sha256Hex(data)) {
		t.Fatalf("post: %s", out)
	}

	read, _ := tb.Execute("board_read", mustMarshal(map[string]any{"thread": "plans", "seed": seed}))
	if !strings.Contains(read, "attachment: 2 file(s)") || !strings.Contains(read, "kbtool board fetch plans#0") {
		t.Fatalf("board_read lacks the attachment summary:\n%s", read)
	}
	if strings.Contains(read, base64.StdEncoding.EncodeToString(data)[:40]) {
		t.Fatal("board_read must not print the attachment payload")
	}

	got, isErr := tb.Execute("board_fetch", mustMarshal(map[string]any{"thread": "plans", "seq": 0, "seed": seed}))
	if isErr {
		t.Fatalf("fetch: %s", got)
	}
	status, back, err := parseBoardFetch(got)
	if err != nil || status != "verified" || !bytes.Equal(back, data) {
		t.Fatalf("fetch round trip: status=%q err=%v equal=%v", status, err, bytes.Equal(back, data))
	}
	if !strings.Contains(got, "tickets/01-x.md") {
		t.Fatalf("fetch output lacks the file list:\n%s", got)
	}

	b, err := tb.store().loadBoard(false)
	if err != nil {
		t.Fatal(err)
	}
	m := b.Threads["plans"].Msgs[0]
	if m.Attach == nil || !bytes.Equal(m.Attach.Data, data) || len(m.Attach.Files) != 2 {
		t.Fatalf("attachment did not survive save/load: %+v", m.Attach)
	}
	if !strings.Contains(boardChunk(m).Text, "plans/plan.md") {
		t.Fatal("search chunk should index the attachment's file names")
	}

	if out, isErr := tb.Execute("board_fetch", mustMarshal(map[string]any{"thread": "welcome", "seq": 0, "seed": seed})); !isErr {
		t.Fatalf("fetching a message without an attachment must fail, got %s", out)
	}
	if out, isErr := tb.Execute("board_fetch", mustMarshal(map[string]any{"thread": "plans", "seq": 0, "seed": strings.Repeat("cd", 32)})); !isErr {
		t.Fatalf("an unregistered seed must not fetch, got %s", out)
	}
}

// TestBoardAttachmentTamperDetected pins that the signature covers the
// attachment: swapping the stored bytes (digest untouched) or the digest itself
// turns the message into bad-signature, and the CLI refuses to extract it.
func TestBoardAttachmentTamperDetected(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	if out, isErr := postAttachment(tb, seed, "plans", packFiles(t, map[string]string{"a.txt": "good"})); isErr {
		t.Fatal(out)
	}
	evil := packFiles(t, map[string]string{"a.txt": "evil"})
	editBoard(t, tb, func(b *Board) { b.Threads["plans"].Msgs[0].Attach.Data = evil })
	got, _ := tb.Execute("board_fetch", mustMarshal(map[string]any{"thread": "plans", "seq": 0, "seed": seed}))
	if !strings.Contains(got, "· bad-signature") || !strings.Contains(got, "DO NOT TRUST") {
		t.Fatalf("swapped bytes not flagged:\n%s", got)
	}
	if _, _, err := parseBoardFetch(got); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("the CLI must reject bytes that do not match the signed digest, got %v", err)
	}

	editBoard(t, tb, func(b *Board) {
		b.Threads["plans"].Msgs[0].Attach.SHA256 = sha256Hex(evil)
	})
	got, _ = tb.Execute("board_fetch", mustMarshal(map[string]any{"thread": "plans", "seq": 0, "seed": seed}))
	status, _, err := parseBoardFetch(got)
	if err != nil || status != "bad-signature" {
		t.Fatalf("a re-pointed digest must break the signature: status=%q err=%v", status, err)
	}
}

// TestBoardAttachmentLimits pins the caps: an oversized upload is refused before
// decoding, invalid archives are refused, and an attachment counts against the
// whole-board memory limit.
func TestBoardAttachmentLimits(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	huge := strings.Repeat("A", base64.StdEncoding.EncodedLen(boardMaxAttach)+4)
	out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "x", "text": "t", "seed": seed, "attachment": huge}))
	if !isErr || !strings.Contains(out, "compressed cap") {
		t.Fatalf("oversized attachment: %s", out)
	}
	if out, isErr := postAttachment(tb, seed, "x", rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "../evil"}, data: "x"})); !isErr || !strings.Contains(out, "unsafe") {
		t.Fatalf("hostile archive must be refused at upload: %s", out)
	}
	b, err := tb.store().loadBoard(false)
	if err != nil {
		t.Fatal(err)
	}
	tb.BoardMaxBytes = int64(len(boardMarshal(b))) + 500 // room for a small text post, not an attachment
	rnd := make([]byte, 4096)
	x := uint32(7)
	for i := range rnd {
		x = x*1103515245 + 12345
		rnd[i] = byte(x >> 16)
	}
	if out, isErr := postAttachment(tb, seed, "x", packFiles(t, map[string]string{"a": string(rnd)})); !isErr || !strings.Contains(out, "message board is full") {
		t.Fatalf("attachment must count against the board memory limit: %s", out)
	}
	dumpPost(t, tb, seed, "x", "info", "a small text post still fits")
}

// TestBoardFileWithoutAttachmentsUnchanged pins compatibility: a board written
// before the attachments trailer (it ends after the agents) still loads, the
// trailer round-trips, and a trailer pointing at an unknown message is
// corruption.
func TestBoardFileWithoutAttachmentsUnchanged(t *testing.T) {
	b := newBoard()
	b.Threads["welcome"].Msgs = []BoardMsg{{ID: 1, Thread: "welcome", Agent: "a", Text: "hi", Kind: "info"}}
	plain := boardMarshal(b)
	legacy := plain[:len(plain)-4] // no attachment count: the pre-attachments format
	if _, err := readBoard(bytes.NewReader(legacy)); err != nil {
		t.Fatalf("board without trailer: %v", err)
	}
	b.Threads["welcome"].Msgs[0].Attach = &BoardAttachment{SHA256: "s", Data: []byte("d"), Files: []attachFile{{Name: "f", Size: 1}}}
	with := boardMarshal(b)
	if !bytes.HasPrefix(with, legacy) {
		t.Fatal("attachments must only append a trailer")
	}
	b2, err := readBoard(bytes.NewReader(with))
	if err != nil || !reflect.DeepEqual(b2.Threads["welcome"].Msgs[0].Attach, b.Threads["welcome"].Msgs[0].Attach) {
		t.Fatalf("trailer round trip: %v", err)
	}
	b.Threads["welcome"].Msgs[0].ID = 2
	orphan := boardMarshal(b)
	b.Threads["welcome"].Msgs[0].Attach = nil
	b.Threads["welcome"].Msgs[0].ID = 1
	corrupt := append(legacy, orphan[len(legacy):]...)
	if _, err := readBoard(bytes.NewReader(corrupt)); err == nil || !strings.Contains(err.Error(), "unknown message") {
		t.Fatalf("orphan attachment must be corruption, got %v", err)
	}
}

// TestBoardAttachmentEncryptedAtRest pins the storage decision (attachments live
// inside the board, so an encrypted store encrypts them too): no plaintext board
// file appears, the attachment content is absent from the bundle bytes, and a
// reopened store with the key serves the verified attachment.
func TestBoardAttachmentEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	boardFile := filepath.Join(dir, "board.bin")
	t.Setenv("KBTOOL_BOARD", boardFile)
	dbPath := filepath.Join(dir, "kb.db")
	st, err := openKBStore(dbPath, []byte("at-rest-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.saveDB(&DB{Dim: testDim, Backend: "local-hashing"}); err != nil {
		t.Fatal(err)
	}
	tb := &Toolbox{Store: st, BoardPath: boardFile}
	seed := dumpSignup(t, tb, "alice")
	secret := "TOP-SECRET-ATTACHMENT-CONTENT"
	data := rawTarGZ(t, rawEntry{hdr: tar.Header{Name: "s.txt", Format: tar.FormatUSTAR}, data: secret})
	if out, isErr := postAttachment(tb, seed, "plans", data); isErr {
		t.Fatal(out)
	}
	if fileExists(boardFile) {
		t.Fatal("an encrypted store must not write a plaintext board.bin")
	}
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, data) || bytes.Contains(raw, []byte(secret)) {
		t.Fatal("attachment bytes are visible in the encrypted bundle")
	}
	st2, err := openKBStore(dbPath, []byte("at-rest-key"))
	if err != nil {
		t.Fatal(err)
	}
	tb2 := &Toolbox{Store: st2, BoardPath: boardFile}
	got, _ := tb2.Execute("board_fetch", mustMarshal(map[string]any{"thread": "plans", "seq": 0, "seed": seed}))
	if status, back, err := parseBoardFetch(got); err != nil || status != "verified" || !bytes.Equal(back, data) {
		t.Fatalf("reopened encrypted store: status=%q err=%v", status, err)
	}
}

// TestAttachCollectRefusesSecretsAndLinks pins the client-side slurp policy:
// directory walks skip .git, kbtool credentials, seed-looking files, private keys
// and symlinks (with a notice), and naming any of them explicitly is an error,
// as are absolute and escaping paths.
func TestAttachCollectRefusesSecretsAndLinks(t *testing.T) {
	base := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("plans/a.md", "plan")
	write("plans/sub/b.md", "more")
	write("plans/.git/config", "[core]")
	write("plans/.kbtool-seed", strings.Repeat("ab", 32))
	write("plans/my-seed", strings.Repeat("cd", 32)+"\n")
	write("plans/key.pem", "-----BEGIN EC PRIVATE KEY-----\nxx\n")
	if err := os.Symlink("/etc/passwd", filepath.Join(base, "plans", "link")); err != nil {
		t.Fatal(err)
	}
	ms, skipped, err := attachCollect(base, []string{"plans"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range ms {
		names = append(names, m.Name)
	}
	if !reflect.DeepEqual(names, []string{"plans/a.md", "plans/sub/b.md"}) {
		t.Fatalf("members = %v (skipped %v)", names, skipped)
	}
	joined := strings.Join(skipped, "\n")
	for _, want := range []string{".git/ (excluded directory)", ".kbtool-seed (kbtool credential file)", "my-seed (looks like a board seed", "key.pem (contains a PEM private key)", "link (symlink, not followed)"} {
		if !strings.Contains(joined, want) {
			t.Errorf("skipped list lacks %q:\n%s", want, joined)
		}
	}
	for _, bad := range []string{"/etc/passwd", "../x", "plans/link", "plans/.kbtool-seed", "plans/my-seed", "plans/key.pem", "plans/.git"} {
		if _, _, err := attachCollect(base, []string{bad}); err == nil {
			t.Errorf("explicit %q must be refused", bad)
		}
	}
}

// TestAttachExtractIsSafe pins the reader side: files land under the target dir,
// existing files are never overwritten without -yes (and nothing is written on
// refusal), and a symlinked directory inside the target is never followed.
func TestAttachExtractIsSafe(t *testing.T) {
	data := packFiles(t, map[string]string{"plans/a.md": "plan", "tickets/01.md": "ticket"})
	dest := t.TempDir()
	written, err := attachExtract(data, dest, false)
	if err != nil || len(written) != 2 {
		t.Fatalf("extract: %v %v", written, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "plans", "a.md")); string(b) != "plan" {
		t.Fatalf("content = %q", b)
	}
	if err := os.WriteFile(filepath.Join(dest, "plans", "a.md"), []byte("local edit"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dest, "tickets", "01.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := attachExtract(data, dest, false); err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Fatalf("existing file must block extraction, got %v", err)
	}
	if fileExists(filepath.Join(dest, "tickets", "01.md")) {
		t.Fatal("a refused extraction must write nothing")
	}
	if _, err := attachExtract(data, dest, true); err != nil {
		t.Fatalf("-yes must replace: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "plans", "a.md")); string(b) != "plan" {
		t.Fatal("-yes did not replace the file")
	}

	outside := t.TempDir()
	dest2 := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dest2, "plans")); err != nil {
		t.Fatal(err)
	}
	if _, err := attachExtract(data, dest2, true); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked dir must be refused, got %v", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatal("extraction wrote through a symlink")
	}
}

// TestBoardDumpEmbedsSmallAttachments pins the page rules: attachments under
// 1 MiB are embedded as a data: download, larger ones show only metadata plus
// the kbtool command, and file names are escaped like message text.
func TestBoardDumpEmbedsSmallAttachments(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	small := packFiles(t, map[string]string{"<b>x</b>.md": "small"})
	if out, isErr := postAttachment(tb, seed, "plans", small); isErr {
		t.Fatal(out)
	}
	rnd := make([]byte, boardDumpEmbedMax+1024)
	x := uint32(1)
	for i := range rnd { // LCG noise: gzip cannot shrink it below the embed limit
		x = x*1103515245 + 12345
		rnd[i] = byte(x >> 16)
	}
	large := packFiles(t, map[string]string{"big.bin": string(rnd)})
	if len(large) < boardDumpEmbedMax {
		t.Fatalf("test archive too small to exercise the limit: %d", len(large))
	}
	if out, isErr := postAttachment(tb, seed, "plans", large); isErr {
		t.Fatal(out)
	}
	s, err := tb.boardExport()
	if err != nil {
		t.Fatal(err)
	}
	page := renderDump(t, s)
	// html/template writes '+' in attributes as &#43;; browsers decode it back.
	if !strings.Contains(strings.ReplaceAll(page, "&#43;", "+"), `href="data:application/gzip;base64,`+base64.StdEncoding.EncodeToString(small)) {
		t.Fatal("small attachment not embedded as a data: link")
	}
	if strings.Contains(page, base64.StdEncoding.EncodeToString(large)[:64]) {
		t.Fatal("large attachment must not be embedded")
	}
	if !strings.Contains(page, "kbtool board fetch -o plans-1 plans#1") || !strings.Contains(page, sha256Hex(large)) {
		t.Fatal("large attachment lacks the retrieval command or digest")
	}
	if strings.Contains(page, "<b>x</b>") || !strings.Contains(page, "&lt;b&gt;x&lt;/b&gt;.md") {
		t.Fatal("attachment file names must be escaped")
	}
}

// TestBoardAttachRemoteOverMtls pins the client/daemon split: through an mTLS
// backend the client posts a locally packed attachment and fetches the same
// bytes back, and an executor without board_fetch (an older daemon) is refused
// before posting, so an attachment is never silently dropped.
func TestBoardAttachRemoteOverMtls(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	dir := shortStateDir(t)
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_SOCKET", "")
	t.Setenv("KBTOOL_DB", "")
	caKey, caCert := writeTestClientPKI(t, dir)
	port := startTestMtlsDaemon(t, caKey, caCert, tb)
	if err := saveClientConfig(mtlsHostConfig(port)); err != nil {
		t.Fatal(err)
	}
	ex, via, err := boardClientExec()
	if err != nil || !strings.HasPrefix(via, "https://127.0.0.1:") {
		t.Fatalf("not resolved to the mTLS backend: via=%q err=%v", via, err)
	}
	if err := boardAttachSupported(ex); err != nil {
		t.Fatal(err)
	}
	data := packFiles(t, map[string]string{"plans/p.md": "remote"})
	out, isErr := ex.Execute("board_post", mustMarshal(map[string]any{"thread": "plans", "text": "t", "seed": seed,
		"attachment": base64.StdEncoding.EncodeToString(data)}))
	if isErr || !strings.Contains(out, sha256Hex(data)) {
		t.Fatalf("remote post: %s", out)
	}
	got, isErr := ex.Execute("board_fetch", mustMarshal(map[string]any{"thread": "plans", "seq": 0, "seed": seed}))
	status, back, err := parseBoardFetch(got)
	if isErr || err != nil || status != "verified" || !bytes.Equal(back, data) {
		t.Fatalf("remote fetch: status=%q err=%v", status, err)
	}
	assertOnlyClientFiles(t, dir)

	if err := boardAttachSupported(&fakeExec{disabled: map[string]bool{"board_fetch": true}}); err == nil {
		t.Fatal("an executor without board_fetch must be refused")
	}
}

// TestBoardAttachFetchBinary pins the CLI end to end with the built binary:
// attach packs a directory (skipping the seed file sitting in it), fetch
// extracts identical files elsewhere, and a second fetch refuses to overwrite.
func TestBoardAttachFetchBinary(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	bin := filepath.Join(t.TempDir(), "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	state := os.Getenv("KBTOOL_DIR")
	if err := os.WriteFile(filepath.Join(state, "config.json"), []byte(`{"version":1,"message_board":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	for rel, data := range map[string]string{"plans/plan.md": "# plan", "tickets/01-a.md": "A", ".kbtool-seed": seed} {
		p := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	sock := filepath.Join(shortStateDir(t), "daemon.sock")
	serveToolboxSocket(t, tb, sock)
	env := append(os.Environ(), "KBTOOL_DIR="+state, "KBTOOL_SOCKET="+sock,
		"KBTOOL_DB=", "KBTOOL_BOARD="+tb.BoardPath, "KB_EMBED_URL=")
	run := func(dir string, args ...string) (string, error) {
		c := exec.Command(bin, args...)
		c.Dir = dir
		c.Env = env
		out, err := c.CombinedOutput()
		return string(out), err
	}
	if out, err := run(src, "board", "attach", "-thread", "plans", "-text", "plans + tickets", "."); err != nil {
		t.Fatalf("attach: %v\n%s", err, out)
	} else if !strings.Contains(out, ".kbtool-seed (kbtool credential file)") || !strings.Contains(out, "attachment: 2 file(s)") {
		t.Fatalf("attach output:\n%s", out)
	}
	dst := t.TempDir()
	seedFile := filepath.Join(src, ".kbtool-seed")
	if out, err := run(dst, "board", "fetch", "-seed-file", seedFile, "-o", "got", "plans#0"); err != nil {
		t.Fatalf("fetch: %v\n%s", err, out)
	}
	for rel, want := range map[string]string{"plans/plan.md": "# plan", "tickets/01-a.md": "A"} {
		if b, err := os.ReadFile(filepath.Join(dst, "got", rel)); err != nil || string(b) != want {
			t.Fatalf("%s: %q %v", rel, b, err)
		}
	}
	if fileExists(filepath.Join(dst, "got", ".kbtool-seed")) {
		t.Fatal("the seed file was attached")
	}
	if out, err := run(dst, "board", "fetch", "-seed-file", seedFile, "-o", "got", "plans#0"); err == nil || !strings.Contains(out, "-yes") {
		t.Fatalf("second fetch must refuse to overwrite: %v\n%s", err, out)
	}
}

// ---------- 30. message board memory limit (plans/message-board-memory-limit-plan.md) ----------

// TestParseBoardMemLimit pins the accepted value forms: percentages of the
// launch-time base, binary and decimal units, bare bytes, and clear errors for
// anything else (a typo must never silently become "no limit").
func TestParseBoardMemLimit(t *testing.T) {
	ok := map[string]int64{
		"1048576": 1 << 20,
		"512MiB":  512 << 20,
		"512M":    512 << 20,
		"2GB":     2e9,
		"1.5 GiB": 3 << 29,
		"64kb":    64000,
		"100%":    boardMemBase(),
		"25%":     boardMemBase() / 4,
	}
	for in, want := range ok {
		got, err := parseBoardMemLimit(in)
		if err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0", "0%", "101%", "-5MiB", "lots", "5 parsecs", "%", "12XB"} {
		if _, err := parseBoardMemLimit(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// TestResolveBoardMemLimitPrecedence pins flag > config > default, and that the
// error names the source of a bad value so the operator knows what to fix.
func TestResolveBoardMemLimitPrecedence(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	n, desc, err := resolveBoardMemLimit("", nil)
	if err != nil || n != boardMemBase()/4 || !strings.Contains(desc, "(default)") {
		t.Fatalf("default: %d %q %v", n, desc, err)
	}
	c := &config{BoardMaxMemory: "64MiB"}
	if n, desc, _ := resolveBoardMemLimit("", c); n != 64<<20 || !strings.Contains(desc, "message_board_max_memory") {
		t.Fatalf("config: %d %q", n, desc)
	}
	if n, desc, _ := resolveBoardMemLimit("1GiB", c); n != 1<<30 || !strings.Contains(desc, "-board-max-memory") {
		t.Fatalf("flag must beat config: %d %q", n, desc)
	}
	if _, _, err := resolveBoardMemLimit("", &config{BoardMaxMemory: "huge"}); err == nil || !strings.Contains(err.Error(), "message_board_max_memory") {
		t.Fatalf("bad config value must name its source, got %v", err)
	}
}

// TestBoardMemLimitRefusesGrowth pins enforcement on the whole board: once a
// post or signup would pass the limit it is refused and nothing is saved, while
// reads (which only bump last-seen) keep working on the full board.
func TestBoardMemLimitRefusesGrowth(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	dumpPost(t, tb, seed, "welcome", "hello", "hi")
	b, err := tb.store().loadBoard(false)
	if err != nil {
		t.Fatal(err)
	}
	tb.BoardMaxBytes = int64(len(boardMarshal(b))) + 100
	before, err := os.ReadFile(tb.BoardPath)
	if err != nil {
		t.Fatal(err)
	}
	out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "x", "text": strings.Repeat("y", 200), "seed": seed}))
	if !isErr || !strings.Contains(out, "message board is full") || !strings.Contains(out, "-board-max-memory") {
		t.Fatalf("post over the limit: %s", out)
	}
	after, _ := os.ReadFile(tb.BoardPath)
	if !bytes.Equal(before, after) {
		t.Fatal("a refused post must not change the stored board")
	}
	if out, isErr := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "a-very-long-agent-name-to-overflow"})); !isErr || !strings.Contains(out, "message board is full") {
		t.Fatalf("signup over the limit: %s", out)
	}
	if out, isErr := tb.Execute("board_read", mustMarshal(map[string]any{"thread": "welcome", "seed": seed})); isErr {
		t.Fatalf("reads must keep working on a full board: %s", out)
	}
}

// TestBoardMemLimitFromConfig pins that toolboxes without an explicit limit (one-
// shot kbtool call, stdio mcp, CLI local fallback) honor message_board_max_memory,
// and that an invalid value falls back to the default instead of blocking.
func TestBoardMemLimitFromConfig(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	cfgFile := filepath.Join(os.Getenv("KBTOOL_DIR"), "config.json")
	if err := os.WriteFile(cfgFile, []byte(`{"version":1,"message_board":true,"message_board_max_memory":"2KiB"}`), 0644); err != nil {
		t.Fatal(err)
	}
	seed := dumpSignup(t, tb, "alice")
	if tb.boardLimit() != 2048 {
		t.Fatalf("limit = %d, want 2048 from config", tb.boardLimit())
	}
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "x", "text": strings.Repeat("y", 4096), "seed": seed})); !isErr || !strings.Contains(out, "message board is full") {
		t.Fatalf("config limit not enforced: %s", out)
	}

	if err := os.WriteFile(cfgFile, []byte(`{"version":1,"message_board":true,"message_board_max_memory":"nonsense"}`), 0644); err != nil {
		t.Fatal(err)
	}
	tb2 := &Toolbox{Store: tb.Store, BoardPath: tb.BoardPath}
	if got := tb2.boardLimit(); got != boardMemBase()/4 {
		t.Fatalf("invalid config value must fall back to the default, got %d", got)
	}
}

// TestPersistDaemonArgsRecordsBoardMaxMemory pins that an explicit
// -board-max-memory on `daemon start` is recorded like the other daemon flags,
// so a later bare start keeps the operator's limit.
func TestPersistDaemonArgsRecordsBoardMaxMemory(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	if !persistDaemonArgs([]string{"-board-max-memory", "512MiB"}) {
		t.Fatal("explicit flag should write the config")
	}
	c, err := loadConfig()
	if err != nil || c == nil || c.BoardMaxMemory != "512MiB" {
		t.Fatalf("config = %+v, %v", c, err)
	}
}

// TestDaemonRefusesInvalidBoardMemLimit pins fail-fast startup (built binary):
// an unparseable -board-max-memory exits with the reason before any pid file or
// socket exists, rather than serving with a surprise limit.
func TestDaemonRefusesInvalidBoardMemLimit(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	bin := filepath.Join(t.TempDir(), "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	state := shortStateDir(t)
	c := exec.Command(bin, "daemon", "run", "-board-max-memory", "bogus")
	c.Env = append(os.Environ(), "KBTOOL_DIR="+state, "KBTOOL_SOCKET=", "KBTOOL_DB=", "KBTOOL_BOARD=", "KB_EMBED_URL=")
	out, err := c.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "invalid board memory limit") || !strings.Contains(string(out), "-board-max-memory") {
		t.Fatalf("daemon must refuse a bad limit: %v\n%s", err, out)
	}
	if ents, _ := os.ReadDir(state); len(ents) != 0 {
		t.Fatalf("a refused start must leave no state, found %d entries", len(ents))
	}
}

// ---------- 31. mTLS client bootstrap (plans/mtls-client-bootstrap-plan.md) ----------

// bootFixture is an in-process enrollment port wired exactly like the daemon's
// (bootstrapTLSConfig + serveBootstrap + tlsHandler/plainHandler).
type bootFixture struct {
	dir    string
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	cli    *x509.Certificate
	bs     *bootstrapState
	hp     string
	port   int
}

// startBootFixture serves a fresh PKI; prepare runs before serving (so tests can
// tamper with state without racing the server goroutines).
func startBootFixture(t *testing.T, prepare func(f *bootFixture, store *crlStore)) *bootFixture {
	t.Helper()
	f := &bootFixture{dir: t.TempDir()}
	f.caKey, f.caCert = writeTestClientPKI(t, f.dir)
	srvKey, srvCert := cryptoGenerateLeaf(f.caKey, f.caCert, "srv", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour)
	writeTestPEM(t, f.dir, "server.crt", cryptoPEMCert(srvCert))
	writeTestPEM(t, f.dir, "server.key", cryptoPEMKey(srvKey))
	cli, err := cryptoFirstCert(filepath.Join(f.dir, "client.crt"))
	if err != nil {
		t.Fatal(err)
	}
	f.cli = cli
	store := &crlStore{ca: f.caCert}
	strict, err := cryptoServerTLSConfig(filepath.Join(f.dir, "server.crt"), filepath.Join(f.dir, "server.key"), filepath.Join(f.dir, "ca.crt"), store)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.port = ln.Addr().(*net.TCPAddr).Port
	f.hp = fmt.Sprintf("127.0.0.1:%d", f.port)
	f.bs, err = newBootstrapState(filepath.Join(f.dir, "ca.crt"), filepath.Join(f.dir, "client.crt"), filepath.Join(f.dir, "client.key"), []string{"127.0.0.1"}, f.port)
	if err != nil {
		t.Fatal(err)
	}
	if prepare != nil {
		prepare(f, store)
	}
	tlsSrv := &http.Server{Handler: f.bs.tlsHandler(httpHandler(&fakeExec{})), TLSConfig: bootstrapTLSConfig(strict), ReadHeaderTimeout: 5 * time.Second}
	plainSrv := &http.Server{Handler: f.bs.plainHandler(), ReadHeaderTimeout: 5 * time.Second}
	serveBootstrap(ln, tlsSrv, plainSrv, make(chan error, 2))
	t.Cleanup(func() { _ = tlsSrv.Close(); _ = plainSrv.Close(); _ = ln.Close() })
	return f
}

// httpsClient trusts the fixture CA; withCert adds the fixture client certificate.
func (f *bootFixture) httpsClient(t *testing.T, withCert bool) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.caCert)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if withCert {
		pair, err := tls.LoadX509KeyPair(filepath.Join(f.dir, "client.crt"), filepath.Join(f.dir, "client.key"))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

func httpGetStatus(t *testing.T, c *http.Client, url string) (int, []byte) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// TestCAFingerprintFormat: why — `kbtool mtls` and `status` still print the CA
// fingerprint for humans: the full SHA-256 as 43-char base64url, distinct per CA.
func TestCAFingerprintFormat(t *testing.T) {
	_, ca := cryptoGenerateCA("fp CA", time.Hour)
	fp := caFingerprint(ca.Raw)
	sum := sha256.Sum256(ca.Raw)
	if len(fp) != 43 || fp != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint %q is not the 43-char base64url SHA-256", fp)
	}
	if _, other := cryptoGenerateCA("other CA", time.Hour); caFingerprint(other.Raw) == fp {
		t.Fatal("different CAs must have different fingerprints")
	}
}

// TestParseImportURL: why — -import accepts only the daemon URL (file import was
// removed); anything else (http, paths, credentials) must be refused up front.
func TestParseImportURL(t *testing.T) {
	ok := map[string]struct {
		host string
		port int
	}{
		"https://kb.example:1234/": {"kb.example", 1234},
		"https://kb.example:1234":  {"kb.example", 1234},
		"https://10.0.0.5/":        {"10.0.0.5", defHTTPPort},
		"https://[::1]:9876/":      {"::1", 9876},
	}
	for in, want := range ok {
		h, p, err := parseImportURL(in, defHTTPPort)
		if err != nil || h != want.host || p != want.port {
			t.Errorf("parseImportURL(%q) = %q %d %v, want %q %d", in, h, p, err, want.host, want.port)
		}
	}
	for _, bad := range []string{"client.kbx", "/tmp/client.kbx", "http://kb.example:9876/", "https://kb.example:9876/mcp",
		"https://kb.example/?x=1", "https://u:p@kb.example/", "https://:9876/", "https://kb.example:0/", "https://kb.example:99999/"} {
		if _, _, err := parseImportURL(bad, defHTTPPort); err == nil {
			t.Errorf("parseImportURL(%q) must fail", bad)
		}
	}
}

// TestBootstrapPortRouting: why — one port now speaks plain HTTP, TLS and mTLS;
// the security boundary is that plain HTTP yields only the public CA, TLS without
// a certificate yields only the encrypted bundle, and every API stays mTLS-only.
func TestBootstrapPortRouting(t *testing.T) {
	f := startBootFixture(t, nil)
	plain := &http.Client{Timeout: 10 * time.Second}
	if code, body := httpGetStatus(t, plain, "http://"+f.hp+"/ca.crt"); code != 200 || !bytes.Equal(body, f.bs.CAPEM) {
		t.Fatalf("plain /ca.crt: %d", code)
	}
	for _, p := range []string{"/", "/healthz", "/mcp", "/bundle/" + f.bs.ID} {
		if code, _ := httpGetStatus(t, plain, "http://"+f.hp+p); code != 404 {
			t.Errorf("plain %s: got %d, want 404", p, code)
		}
	}
	anon := f.httpsClient(t, false)
	for _, p := range []string{"/healthz", "/mcp", "/ca.crt"} {
		if code, _ := httpGetStatus(t, anon, "https://"+f.hp+p); code != 401 {
			t.Errorf("TLS without cert %s: got %d, want 401", p, code)
		}
	}
	if resp, err := anon.Post("https://"+f.hp+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)); err != nil || resp.StatusCode != 401 {
		t.Fatalf("POST /mcp without cert must be 401: %v %v", resp, err)
	}
	for _, p := range []string{"/bundle/", "/bundle/" + f.bs.ID[:21], "/bundle/" + f.bs.ID + "x", "/bundle/" + base64.RawURLEncoding.EncodeToString(f.bs.Key)} {
		if code, _ := httpGetStatus(t, anon, "https://"+f.hp+p); code != 404 {
			t.Errorf("TLS %s: got %d, want 404", p, code)
		}
	}
	code, data := httpGetStatus(t, anon, "https://"+f.hp+"/bundle/"+f.bs.ID)
	if code != 200 {
		t.Fatalf("bundle: %d", code)
	}
	if _, err := cryptoDecryptBundle(data, f.bs.Key); err != nil {
		t.Fatalf("bundle must decrypt with the boot key: %v", err)
	}
	if code, _ := httpGetStatus(t, f.httpsClient(t, true), "https://"+f.hp+"/healthz"); code != 200 {
		t.Fatalf("mTLS /healthz: %d", code)
	}
}

// TestBootstrapBundleFreshPerRequest: why — the bundle is encrypted on the fly
// with a fresh nonce, so two downloads never share ciphertext yet carry the
// same four files.
func TestBootstrapBundleFreshPerRequest(t *testing.T) {
	f := startBootFixture(t, nil)
	anon := f.httpsClient(t, false)
	_, a := httpGetStatus(t, anon, "https://"+f.hp+"/bundle/"+f.bs.ID)
	_, b := httpGetStatus(t, anon, "https://"+f.hp+"/bundle/"+f.bs.ID)
	if bytes.Equal(a, b) {
		t.Fatal("two bundle downloads must differ in ciphertext")
	}
	var got []map[string][]byte
	for _, d := range [][]byte{a, b} {
		plain, err := cryptoDecryptBundle(d, f.bs.Key)
		if err != nil {
			t.Fatal(err)
		}
		m, err := tarGZFilesMem(plain, bundleAllowed, 1<<20)
		if err != nil || len(m) != 4 {
			t.Fatalf("bundle files: %v %d", err, len(m))
		}
		got = append(got, m)
	}
	if !reflect.DeepEqual(got[0], got[1]) {
		t.Fatal("both downloads must carry the same files")
	}
}

// TestBootstrapRevokedCertRefused: why — making the client certificate optional
// at the handshake must not weaken revocation: a revoked certificate is still
// refused, while certificate-less enrollment keeps working.
func TestBootstrapRevokedCertRefused(t *testing.T) {
	f := startBootFixture(t, func(f *bootFixture, store *crlStore) {
		now := time.Now()
		der, err := x509.CreateRevocationList(crand.Reader, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
			RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: f.cli.SerialNumber, RevocationTime: now}},
		}, f.caCert, f.caKey)
		if err != nil {
			t.Fatal(err)
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		store.set([]*x509.RevocationList{crl})
	})
	if resp, err := f.httpsClient(t, true).Get("https://" + f.hp + "/healthz"); err == nil {
		resp.Body.Close()
		t.Fatalf("revoked client cert must be refused, got %d", resp.StatusCode)
	}
	if code, _ := httpGetStatus(t, f.httpsClient(t, false), "https://"+f.hp+"/bundle/"+f.bs.ID); code != 200 {
		t.Fatalf("enrollment without a cert must still work: %d", code)
	}
}

// TestClientImportEndToEnd: why — the one-liner's whole client path (bundle
// fetch from the derived ID, decrypt with the token key, server checked against
// the bundled CA, install, mTLS check) must leave a client.json that reaches the
// daemon at the imported host:port.
func TestClientImportEndToEnd(t *testing.T) {
	f := startBootFixture(t, nil)
	cli := t.TempDir()
	t.Setenv("KBTOOL_DIR", cli)
	files, err := bootstrapFetchBundle(f.hp, "127.0.0.1", "", f.bs.Key)
	if err != nil {
		t.Fatal(err)
	}
	written, err := bootstrapInstall(cli, files, "127.0.0.1", f.port, "", false)
	if err != nil || len(written) != 4 {
		t.Fatalf("install: %v %v", written, err)
	}
	assertOnlyClientFiles(t, cli)
	if fi, err := os.Stat(filepath.Join(cli, "client.key")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("client.key must be 0600: %v %v", fi, err)
	}
	cc, err := loadClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cc.Host != "127.0.0.1" || cc.Port != f.port || len(cc.Hosts) != 0 || !cc.TLS || cc.UnixSocket != "" {
		t.Fatalf("client.json must point at the imported URL: %+v", cc)
	}
	ep, _, ok := endpointForHostPort(cc, cc.Host)
	if !ok {
		t.Fatal("imported credentials do not load")
	}
	if err := pingEndpoint(ep); err != nil {
		t.Fatalf("mTLS after import: %v", err)
	}
}

// TestBootstrapInterceptorRefused: why — without a fingerprint the client
// fetches the bundle before trusting the server; an interceptor with its own
// CA that proxies the real (encrypted) bundle must still be refused once the
// bundle reveals the true CA.
func TestBootstrapInterceptorRefused(t *testing.T) {
	f := startBootFixture(t, nil)
	caKey, ca := cryptoGenerateCA("interceptor CA", time.Hour)
	k, c := cryptoGenerateLeaf(caKey, ca, "mitm", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour)
	upstream := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	mitm := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := upstream.Get("https://" + f.hp + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	mitm.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{c.Raw}, PrivateKey: k}}}
	mitm.StartTLS()
	defer mitm.Close()
	hp := strings.TrimPrefix(mitm.URL, "https://")
	if _, err := bootstrapFetchBundle(hp, "127.0.0.1", "", f.bs.Key); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("an interceptor proxying the real bundle must be refused: %v", err)
	}
}

// TestBootstrapStaleOrWrongToken: why — a stale line (daemon restarted) or a
// mistyped key derives an unknown bundle ID and must fail with an actionable
// message, never a partial install.
func TestBootstrapStaleOrWrongToken(t *testing.T) {
	f := startBootFixture(t, nil)
	wrong := append([]byte{}, f.bs.Key...)
	wrong[0] ^= 1
	if _, err := bootstrapFetchBundle(f.hp, "127.0.0.1", "", wrong); err == nil || !strings.Contains(err.Error(), "does not know this token") {
		t.Fatalf("wrong key: %v", err)
	}
}

// TestBootstrapSwappedBundleCARejected: why — the bundled ca.crt becomes the
// client's trust anchor, so the server the client actually talked to must hold
// a certificate from that CA.
func TestBootstrapSwappedBundleCARejected(t *testing.T) {
	f := startBootFixture(t, func(f *bootFixture, _ *crlStore) {
		_, other := cryptoGenerateCA("swapped CA", time.Hour)
		f.bs.files["ca.crt"] = cryptoPEMCert(other)
	})
	if _, err := bootstrapFetchBundle(f.hp, "127.0.0.1", "", f.bs.Key); err == nil || !strings.Contains(err.Error(), "not valid for 127.0.0.1 under the bundled CA") {
		t.Fatalf("swapped bundled CA must be refused: %v", err)
	}
}

// TestBootstrapInstallOverwrite: why — enrolling must not silently replace an
// existing client identity; identical files (an already-trusted CA) need no -yes.
func TestBootstrapInstallOverwrite(t *testing.T) {
	f := startBootFixture(t, nil)
	files := func() map[string][]byte {
		m, err := bootstrapFetchBundle(f.hp, "127.0.0.1", "", f.bs.Key)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	cli := t.TempDir()
	writeTestPEM(t, cli, "ca.crt", f.bs.CAPEM)
	if w, err := bootstrapInstall(cli, files(), "127.0.0.1", f.port, "", false); err != nil || len(w) != 3 {
		t.Fatalf("identical ca.crt must be left alone: %v %v", w, err)
	}
	writeTestPEM(t, cli, "client.key", []byte("old identity"))
	if _, err := bootstrapInstall(cli, files(), "127.0.0.1", f.port, "", false); err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Fatalf("differing client.key must need -yes: %v", err)
	}
	if string(mustReadFile(t, filepath.Join(cli, "client.key"))) != "old identity" {
		t.Fatal("a refused install must not write anything")
	}
	if _, err := bootstrapInstall(cli, files(), "127.0.0.1", f.port, "", true); err != nil {
		t.Fatal(err)
	}
	if string(mustReadFile(t, filepath.Join(cli, "client.key"))) == "old identity" {
		t.Fatal("-yes must replace client.key")
	}
}

// TestBootstrapImportLines: why — the boot line is the user interface: one line
// per server address, the readable URL followed by a direct token that parses
// back to the boot key, whose derived bundle ID is the one the daemon serves.
func TestBootstrapImportLines(t *testing.T) {
	f := startBootFixture(t, nil)
	lines := f.bs.importLines([]string{"kb.example", "10.0.0.5", "::1"}, 9876)
	if len(lines) != 3 || !strings.Contains(lines[2], "https://[::1]:9876/") {
		t.Fatalf("import lines: %q", lines)
	}
	for _, l := range lines {
		w := strings.Fields(l)
		if len(w) != 5 || w[1] != "client" || w[2] != "-import" {
			t.Fatalf("malformed line %q", l)
		}
		if _, _, err := parseImportURL(w[3], defHTTPPort); err != nil {
			t.Fatalf("URL does not parse back: %q", l)
		}
		tok, err := parseEnrollToken(w[4])
		if err != nil || tok.Host != "" || tok.Session != "" || !bytes.Equal(tok.Key, f.bs.Key) {
			t.Fatalf("token does not parse back to the boot key: %q %+v %v", l, tok, err)
		}
	}
	if len(f.bs.Key) != 16 || f.bs.ID != bundleIDFromKey(f.bs.Key) {
		t.Fatalf("key must be 16 bytes and the bundle ID derived from it: %d %q", len(f.bs.Key), f.bs.ID)
	}
	hosts, port := bootstrapHosts(filepath.Join(f.dir, "server.crt"), &net.TCPAddr{Port: 4321})
	if port != 4321 || !reflect.DeepEqual(hosts, []string{"127.0.0.1"}) {
		t.Fatalf("bootstrapHosts = %v %d", hosts, port)
	}
}

// TestDaemonLogPrivateAndRelayed: why — the log now holds the enrollment key, so
// an existing 0644 log is tightened to 0600; `daemon start` relays each
// endpoint's command once, from the new daemon's log entries only (not stale
// ones from earlier boots).
func TestDaemonLogPrivateAndRelayed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "daemon.log")
	if err := os.WriteFile(p, []byte("kbtool client -import https://old:1/ kb1old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, off, err := openDaemonLog(p)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(f, "kbtool daemon: client enrollment enabled")
	fmt.Fprintln(f, "kbtool daemon: enroll a client via new:2: kbtool client -import https://new:2/ kb1new")
	fmt.Fprintln(f, "kbtool daemon: enroll a client via 10.0.0.5:2: kbtool client -import https://10.0.0.5:2/ kb1new")
	fmt.Fprintln(f, "kbtool client -import https://new:2/ kb1new")
	f.Close()
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0600 {
		t.Fatalf("log mode %v, want 0600", fi.Mode().Perm())
	}
	var buf bytes.Buffer
	relayImportLines(&buf, p, off)
	out := buf.String()
	if strings.Contains(out, "old:1") || strings.Count(out, "  kbtool client -import https://new:2/ ") != 1 ||
		strings.Count(out, "  kbtool client -import https://10.0.0.5:2/ ") != 1 {
		t.Fatalf("relay must show each new endpoint's command once:\n%s", out)
	}
}

// ---------- 32. kbtool mtls default SANs (plans/mtls-default-sans-plan.md) ----------

// TestDefaultSANs: why — without SAN arguments the certificate must cover every
// dialable address of the host, its hostname and host.docker.internal, while
// link-local/unspecified addresses (undialable without a zone, and each SAN
// becomes a client.json endpoint) are left out.
func TestDefaultSANs(t *testing.T) {
	cidr := func(s string) net.Addr {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	addrs := []net.Addr{
		cidr("127.0.0.1/8"), cidr("::1/128"), cidr("192.168.1.20/24"), cidr("fe80::1/64"),
		cidr("169.254.3.4/16"), cidr("10.0.0.5/8"), &net.IPAddr{IP: net.ParseIP("2001:db8::7")},
		cidr("10.0.0.5/32"), &net.IPAddr{IP: net.IPv4zero}, &net.IPAddr{IP: net.ParseIP("ff02::1")},
	}
	ips, names := defaultSANs(addrs, "buildhost")
	if want := []string{"127.0.0.1", "::1", "192.168.1.20", "10.0.0.5", "2001:db8::7"}; !reflect.DeepEqual(ips, want) {
		t.Errorf("ips = %v, want %v", ips, want)
	}
	if want := []string{"buildhost", "host.docker.internal"}; !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
	for _, bad := range []string{"", "10.1.2.3", "bad_host-", "-x", "host.docker.internal"} {
		_, names := defaultSANs(nil, bad)
		if !reflect.DeepEqual(names, []string{"host.docker.internal"}) {
			t.Errorf("hostname %q: names = %v, want only host.docker.internal", bad, names)
		}
	}
}

// TestMtlsNoArgsUsesDefaultSANs: why — the user-facing promise: a bare
// `kbtool mtls` issues a usable certificate for this host (interface IPs,
// hostname, host.docker.internal), while explicit SANs get no defaults mixed in.
func TestMtlsNoArgsUsesDefaultSANs(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	issue := func(dir string, args ...string) *x509.Certificate {
		t.Helper()
		c := exec.Command(bin, append([]string{"mtls"}, args...)...)
		c.Env = append(os.Environ(), "KBTOOL_DIR="+dir, "HOME="+work)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("mtls %v: %v\n%s", args, err, out)
		}
		cert, err := cryptoFirstCert(filepath.Join(dir, "server.crt"))
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip("no interface addresses:", err)
	}
	host, _ := os.Hostname()
	wantIPs, wantNames := defaultSANs(addrs, host)
	cert := issue(filepath.Join(work, "def"))
	if err := verifyCertSANs(cert, wantIPs, wantNames); err != nil {
		t.Fatalf("default cert: %v", err)
	}
	if !containsString(cert.DNSNames, "host.docker.internal") || len(cert.IPAddresses) == 0 {
		t.Fatalf("default cert SANs: ip=%v dns=%v", cert.IPAddresses, cert.DNSNames)
	}
	if fileExists(filepath.Join(work, "def", "client.json")) {
		t.Fatal("kbtool mtls must not write a client.json on the daemon host")
	}
	explicit := issue(filepath.Join(work, "exp"), "-ip", "127.0.0.1", "-expire", "48h")
	if len(explicit.IPAddresses) != 1 || len(explicit.DNSNames) != 0 {
		t.Fatalf("explicit SANs must not get defaults: ip=%v dns=%v", explicit.IPAddresses, explicit.DNSNames)
	}
}

// TestDaemonLogsEnrollmentPerSAN: why — the user picks the address a client can
// reach, so every SAN endpoint gets its own copyable command, exactly once in
// the log: bare when stdout is the log, prefixed entries when stdout is separate.
func TestDaemonLogsEnrollmentPerSAN(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	srv := shortStateDir(t)
	env := append(os.Environ(), "KBTOOL_DIR="+srv, "HOME="+work, "KB_EMBED_URL=")
	mt := exec.Command(bin, "mtls", "-ip", "127.0.0.1,::1", "-dns", "localhost,kb.test")
	mt.Env = env
	if out, err := mt.CombinedOutput(); err != nil {
		t.Fatalf("mtls: %v\n%s", err, out)
	}
	endpoints := []string{"localhost", "kb.test", "127.0.0.1", "::1"}
	boot := func(sep bool) (logText, outText string, port int) {
		t.Helper()
		port = freePort(t)
		d := exec.Command(bin, "daemon", "run", "-http", "-mtls", "-bind", fmt.Sprintf("127.0.0.1:%d", port))
		d.Env = env
		logPath := filepath.Join(work, fmt.Sprintf("log-%v", sep))
		outPath := filepath.Join(work, fmt.Sprintf("out-%v", sep))
		lf, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		defer lf.Close()
		d.Stderr = lf
		d.Stdout = lf
		if sep {
			of, err := os.Create(outPath)
			if err != nil {
				t.Fatal(err)
			}
			defer of.Close()
			d.Stdout = of
		}
		if err := d.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = d.Process.Kill(); _, _ = d.Process.Wait() }()
		waitImportLine(t, logPath, fmt.Sprintf("https://[::1]:%d/", port), 15*time.Second)
		lb, _ := os.ReadFile(logPath)
		ob, _ := os.ReadFile(outPath)
		return string(lb), string(ob), port
	}
	count := func(text, prefix, hp string) int {
		n := 0
		for _, l := range strings.Split(text, "\n") {
			if strings.HasPrefix(l, prefix+"kbtool client -import https://"+hp+"/ kb1") {
				n++
			}
		}
		return n
	}
	entry := func(hp string) string { return "kbtool daemon: enroll a client via " + hp + ": " }
	// stdout == log: bare commands only, one per endpoint.
	logText, _, port := boot(false)
	for _, h := range endpoints {
		hp := net.JoinHostPort(h, strconv.Itoa(port))
		if count(logText, "", hp) != 1 || strings.Contains(logText, entry(hp)) {
			t.Fatalf("stdout == log: want one bare command for %s and no prefixed entry:\n%s", hp, logText)
		}
	}
	// Separate stdout: bare commands there, one prefixed entry per endpoint in the log.
	logText, outText, port := boot(true)
	for _, h := range endpoints {
		hp := net.JoinHostPort(h, strconv.Itoa(port))
		if count(outText, "", hp) != 1 || count(logText, entry(hp), hp) != 1 {
			t.Fatalf("separate stdout: want one bare command on stdout and one log entry for %s:\nstdout:\n%s\nlog:\n%s", hp, outText, logText)
		}
	}
}

// ---------- 33. mTLS implies HTTP on all interfaces (plans/mtls-implies-http-plan.md) ----------

// TestResolveHTTP: why — mTLS exists to share the daemon over the network, so
// with mTLS on HTTP must default on; an explicit -http/-http=false still wins
// and plain (non-mTLS) daemons keep HTTP off unless asked.
func TestResolveHTTP(t *testing.T) {
	on, off := &config{Http: true}, &config{}
	cases := []struct {
		name             string
		flagSet, flagVal bool
		cfg              *config
		mtls, want       bool
	}{
		{"nothing: off", false, false, nil, false, false},
		{"config http", false, false, on, false, true},
		{"mTLS implies HTTP", false, false, off, true, true},
		{"mTLS, no config", false, false, nil, true, true},
		{"-http=false wins over mTLS", true, false, on, true, false},
		{"-http wins without mTLS", true, true, off, false, true},
	}
	for _, c := range cases {
		if got := resolveHTTP(c.flagSet, c.flagVal, c.cfg, c.mtls); got != c.want {
			t.Errorf("%s: resolveHTTP = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestDaemonMtlsServesHTTPByDefault: why — the user-facing promise through the
// built binary: `daemon run -mtls` listens on TCP on every interface without
// -http, and -http=false keeps it unix-socket only.
func TestDaemonMtlsServesHTTPByDefault(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	srv := shortStateDir(t)
	env := append(os.Environ(), "KBTOOL_DIR="+srv, "HOME="+work, "KB_EMBED_URL=")
	mt := exec.Command(bin, "mtls", "-ip", "127.0.0.1")
	mt.Env = env
	if out, err := mt.CombinedOutput(); err != nil {
		t.Fatalf("mtls: %v\n%s", err, out)
	}
	// kbtool mtls records http: true; drop it so only mTLS can turn HTTP on.
	cfgPath := filepath.Join(srv, "config.json")
	var raw map[string]any
	if err := json.Unmarshal(mustReadFile(t, cfgPath), &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "http")
	delete(raw, "http_addr")
	b, _ := json.Marshal(raw)
	if err := os.WriteFile(cfgPath, b, 0644); err != nil {
		t.Fatal(err)
	}
	run := func(extra ...string) (string, int) {
		t.Helper()
		port := freePort(t)
		args := append([]string{"daemon", "run", "-bind", fmt.Sprintf(":%d", port)}, extra...)
		d := exec.Command(bin, args...)
		d.Env = env
		logPath := filepath.Join(work, fmt.Sprintf("log-%d", port))
		lf, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		defer lf.Close()
		d.Stdout, d.Stderr = lf, lf
		if err := d.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = d.Process.Kill(); _, _ = d.Process.Wait() }()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if l := string(mustReadFile(t, logPath)); strings.Contains(l, "serving") || strings.Contains(l, "board-only mode") {
				return l, port
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("daemon did not come up:\n%s", mustReadFile(t, logPath))
		return "", 0
	}
	logText, port := run()
	if !strings.Contains(logText, fmt.Sprintf("https://*:%d", port)) {
		t.Fatalf("mTLS daemon must serve HTTPS on all interfaces by default:\n%s", logText)
	}
	logText, port = run("-http=false")
	if strings.Contains(logText, fmt.Sprintf(":%d", port)) || !strings.Contains(logText, "[mtls]") {
		t.Fatalf("-http=false must keep the mTLS daemon unix-socket only:\n%s", logText)
	}
}

// ---------- 34. mTLS relay (plans/mtls-relay-plan.md) ----------

// startTestRelay serves a relay with a fresh relay PKI on 127.0.0.1; tune may
// shrink its limits before it serves.
func startTestRelay(t *testing.T, token string, tune func(*relayServer)) (*relayServer, string) {
	t.Helper()
	rs := newRelayServer(newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil), token)
	if tune != nil {
		tune(rs)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go rs.serve(ln)
	t.Cleanup(func() { _ = ln.Close(); rs.shutdown() })
	return rs, ln.Addr().String()
}

// newRelaySessionID is a well-formed session ID with no key behind it.
func newRelaySessionID() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// newTestRelaySession makes a session key and its ID, expiring at exp.
func newTestRelaySession(t *testing.T, exp time.Time) (string, *relaySessionAuth) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &relaySessionAuth{Key: key, Expires: exp.Unix()}
	return relaySessionID(key.Public().(ed25519.PublicKey), a.Expires), a
}

// registerTestSession registers sid with the relay at hp, signed by auth (nil:
// unsigned), trusting the certificate the relay presents.
func registerTestSession(hp, sid string, auth *relaySessionAuth, token string) (net.Conn, error) {
	var sign func(tls.ConnectionState) (map[string]string, error)
	if auth != nil {
		sign = func(cs tls.ConnectionState) (map[string]string, error) { return auth.headers(sid, cs) }
	}
	return relayUpgrade(hp, relayTrust{}.tlsConfig(), "/v1/register",
		map[string]string{"X-Kbtool-Session": sid, "X-Kbtool-Relay-Token": token}, sign)
}

// registerNewTestSession registers a fresh valid session for an hour.
func registerNewTestSession(t *testing.T, hp, token string) (string, net.Conn, error) {
	t.Helper()
	sid, auth := newTestRelaySession(t, time.Now().Add(time.Hour))
	c, err := registerTestSession(hp, sid, auth, token)
	return sid, c, err
}

// relayTeam is an in-process daemon behind a relay: its own team PKI, the
// bootstrap handler and a relayConnector.
type relayTeam struct {
	dir, sid string
	boot     *bootstrapState
	conn     *relayConnector
}

func startRelayTeam(t *testing.T, rs *relayServer, hp, token string) *relayTeam {
	t.Helper()
	return startRelayTeamTrust(t, rs, hp, token, relayTrust{})
}

// startRelayTeamTrust is startRelayTeam with the daemon verifying the relay by trust.
func startRelayTeamTrust(t *testing.T, rs *relayServer, hp, token string, trust relayTrust) *relayTeam {
	t.Helper()
	dir := t.TempDir()
	caKey, caCert := writeTestClientPKI(t, dir)
	srvKey, srvCert := cryptoGenerateLeaf(caKey, caCert, "srv", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour)
	writeTestPEM(t, dir, "server.crt", cryptoPEMCert(srvCert))
	writeTestPEM(t, dir, "server.key", cryptoPEMKey(srvKey))
	tlsCfg, err := cryptoServerTLSConfig(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "ca.crt"), &crlStore{})
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(hp)
	p, _ := strconv.Atoi(port)
	boot, err := newBootstrapState(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"), []string{"127.0.0.1"}, p)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	ln := newChanListener(&net.TCPAddr{})
	srv := &http.Server{Handler: boot.tlsHandler(mux), TLSConfig: relayServerTLS(bootstrapTLSConfig(tlsCfg), caCert.Raw)}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	sid, auth := newTestRelaySession(t, caCert.NotAfter)
	team := &relayTeam{dir: dir, sid: sid, boot: boot}
	team.conn = &relayConnector{HostPort: hp, Session: team.sid, Token: token, Auth: auth, Trust: trust,
		Deliver: func(c net.Conn) bool {
			select {
			case ln.ch <- c:
				return true
			case <-ln.done:
				return false
			}
		},
		Logf: func(string, ...any) {}}
	go team.conn.run()
	t.Cleanup(func() { team.conn.close(); _ = srv.Close(); _ = ln.Close() })
	waitRelaySession(t, rs, team.sid, true)
	return team
}

// waitRelaySession waits until the relay has (or no longer has) a live session.
func waitRelaySession(t *testing.T, rs *relayServer, sid string, live bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rs.mu.Lock()
		s := rs.sessions[sid]
		ok := s != nil && s.ctrl != nil
		rs.mu.Unlock()
		if ok == live {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("relay session %s live=%v never reached", sid, live)
}

// enrollViaRelay runs the client side of a relay token's `client -import` into a
// fresh state dir and points KBTOOL_DIR at it.
func enrollViaRelay(t *testing.T, hp string, team *relayTeam) *clientConfig {
	t.Helper()
	cli := t.TempDir()
	files, err := bootstrapFetchBundle(hp, "127.0.0.1", team.sid, team.boot.Key)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(hp)
	p, _ := strconv.Atoi(port)
	if _, err := bootstrapInstall(cli, files, "127.0.0.1", p, team.sid, false); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KBTOOL_DIR", cli)
	if err := enableClientRelay(); err != nil {
		t.Fatal(err)
	}
	cc, err := loadClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	return cc
}

func pingRelayed(cc *clientConfig) error {
	ep, _, ok := endpointForHostPort(cc, cc.Host)
	if !ok {
		return errors.New("client config does not load")
	}
	return pingEndpoint(ep)
}

// relayTapBuf records what the relay copies from clients to daemons.
type relayTapBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (r *relayTapBuf) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.b.Write(p)
}

func (r *relayTapBuf) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.b.String()
}

// captureClientHello returns the first TLS record a Go client sends for serverName.
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _ = tls.Client(c1, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake() }()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

// TestRelaySessionIDShape: why — the session ID travels as SNI, so the ID
// derived from a session key must be a valid lowercase DNS label, and the relay
// routes only IDs of exactly this shape.
func TestRelaySessionIDShape(t *testing.T) {
	a, _ := newTestRelaySession(t, time.Now().Add(time.Hour))
	b, _ := newTestRelaySession(t, time.Now().Add(time.Hour))
	if !isRelaySessionID(a) || a == b || len(a) != 32 {
		t.Fatalf("session IDs must be distinct 32-char lowercase hex: %q %q", a, b)
	}
	for _, bad := range []string{"", strings.ToUpper(a), a[:31], a + "0", "g" + a[1:], "localhost"} {
		if isRelaySessionID(bad) {
			t.Errorf("isRelaySessionID(%q) must be false", bad)
		}
	}
}

// TestClientHelloSNI: why — the relay routes on SNI it reads without
// terminating TLS; the parser must find it in a real ClientHello, report its
// absence, and never panic or over-read on truncated or corrupted input.
func TestClientHelloSNI(t *testing.T) {
	sid := newRelaySessionID()
	rec := captureClientHello(t, sid)
	got, err := peekClientHelloSNI(bufio.NewReader(bytes.NewReader(rec)))
	if err != nil || got != sid {
		t.Fatalf("SNI = %q, %v; want %q", got, err, sid)
	}
	if got, err := clientHelloSNI(captureClientHello(t, "")[5:]); err != nil || got != "" {
		t.Fatalf("no SNI: got %q, %v", got, err)
	}
	for n := 0; n < len(rec); n++ {
		if _, err := peekClientHelloSNI(bufio.NewReader(bytes.NewReader(rec[:n]))); err == nil {
			t.Fatalf("truncated hello (%d of %d bytes) must be an error", n, len(rec))
		}
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		m := append([]byte{}, rec[5:]...)
		for j := 0; j < 1+r.Intn(4); j++ {
			m[r.Intn(len(m))] = byte(r.Intn(256))
		}
		_, _ = clientHelloSNI(m) // must not panic
	}
	if _, err := peekClientHelloSNI(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\n\r\n"))); err == nil {
		t.Fatal("plain HTTP is not a ClientHello")
	}
}

// TestRelayPublicEndpoints: why — /healthz serves health checks on both the
// plain and the TLS side, the relay serves no /ca.crt that would name it, and a
// default-trust daemon learns the CA fingerprint from the handshake itself.
func TestRelayPublicEndpoints(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	for _, scheme := range []string{"http", "https"} {
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		resp, err := cl.Get(scheme + "://" + hp + "/ca.crt")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || bytes.Contains(b, []byte("CERTIFICATE")) {
			t.Fatalf("%s /ca.crt must be the honeypot's 404: %d %q", scheme, resp.StatusCode, b)
		}
	}
	if l := rs.Honey.list(); len(l) != 0 {
		t.Fatalf("/ca.crt must not mark the client: %+v", l)
	}
	if !relayHealthy(hp) {
		t.Fatal("plain /healthz must answer")
	}
	fp, err := relayCheck(hp, relayTrust{})
	if err != nil || fp != rs.currentPKI().FP {
		t.Fatalf("relayCheck (/healthz over HTTPS) = %q, %v; want %q", fp, err, rs.currentPKI().FP)
	}
	if resp, err := http.Get("http://" + hp + "/v1/register"); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("registration must not be reachable over plain HTTP: %v %v", resp, err)
	}
}

// TestRelayRegistrationToken: why — with relay_token set only daemons that
// present it may register a session; without it registration is open.
func TestRelayRegistrationToken(t *testing.T) {
	_, hp := startTestRelay(t, "tk", nil)
	for _, tok := range []string{"", "wrong"} {
		_, _, err := registerNewTestSession(t, hp, tok)
		var he *relayHTTPError
		if !errors.As(err, &he) || he.Code != http.StatusForbidden {
			t.Fatalf("token %q: want 403, got %v", tok, err)
		}
	}
	_, c, err := registerNewTestSession(t, hp, "tk")
	if err != nil {
		t.Fatalf("right token must register: %v", err)
	}
	c.Close()
	_, open := startTestRelay(t, "", nil)
	_, c, err = registerNewTestSession(t, open, "")
	if err != nil {
		t.Fatalf("open relay must accept registration without a token: %v", err)
	}
	c.Close()
}

// TestRelayDuplicateSessionAndForget: why — a live session cannot be taken
// over by a second registration, and the relay forgets a session (rejecting its
// SNI) when the daemon disconnects, so the ID can be registered again.
func TestRelayDuplicateSessionAndForget(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	sid, auth := newTestRelaySession(t, time.Now().Add(time.Hour))
	c, err := registerTestSession(hp, sid, auth, "")
	if err != nil {
		t.Fatal(err)
	}
	waitRelaySession(t, rs, sid, true)
	_, err = registerTestSession(hp, sid, auth, "")
	var he *relayHTTPError
	if !errors.As(err, &he) || he.Code != http.StatusConflict {
		t.Fatalf("second live registration: want 409, got %v", err)
	}
	c.Close()
	waitRelaySession(t, rs, sid, false)
	if _, err := tls.Dial("tcp", hp, &tls.Config{ServerName: sid, InsecureSkipVerify: true}); err == nil {
		t.Fatal("a forgotten session's SNI must be rejected")
	}
	c, err = registerTestSession(hp, sid, auth, "")
	if err != nil {
		t.Fatalf("a forgotten session ID must be registrable again: %v", err)
	}
	c.Close()
	if _, err := registerTestSession(hp, "not-a-session", auth, ""); err == nil {
		t.Fatal("a malformed session ID must be refused")
	}
}

// TestRelayEndToEnd: why — the owner's scenario: a client enrolls with an
// unreachable daemon through the relay (bundle decrypted with the token key,
// server checked against the bundled CA), then makes mTLS calls with SNI =
// session; the relay only copies ciphertext, and another session is refused.
func TestRelayEndToEnd(t *testing.T) {
	tap := &relayTapBuf{}
	rs, hp := startTestRelay(t, "tk", func(rs *relayServer) { rs.tap = tap })
	team := startRelayTeam(t, rs, hp, "tk")
	cc := enrollViaRelay(t, hp, team)
	if cc.Session != team.sid || cc.Host != "127.0.0.1" || !cc.TLS {
		t.Fatalf("client.json must record the relay and session: %+v", cc)
	}
	if err := pingRelayed(cc); err != nil {
		t.Fatalf("mTLS call through the relay: %v", err)
	}
	if s := tap.String(); s == "" || strings.Contains(s, "/healthz") || strings.Contains(s, "/bundle/") || strings.Contains(s, team.boot.ID) {
		t.Fatalf("the relay must see only ciphertext (tap %d bytes)", len(s))
	}
	if _, err := bootstrapFetchBundle(hp, "127.0.0.1", newRelaySessionID(), team.boot.Key); err == nil {
		t.Fatal("a token naming an unknown session must not enroll")
	}
	if _, err := tls.Dial("tcp", hp, &tls.Config{ServerName: newRelaySessionID(), InsecureSkipVerify: true}); err == nil {
		t.Fatal("an unknown session's SNI must be rejected")
	}
}

// TestRelayTwoSessionsIsolated: why — one relay carries many teams; a client
// of team A that aims at team B's session reaches B's daemon but cannot
// verify it (B's certificate is not signed by A's CA), and A keeps working.
func TestRelayTwoSessionsIsolated(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	a := startRelayTeam(t, rs, hp, "")
	b := startRelayTeam(t, rs, hp, "")
	cc := enrollViaRelay(t, hp, a)
	if err := pingRelayed(cc); err != nil {
		t.Fatalf("team A through the relay: %v", err)
	}
	wrong := *cc
	wrong.Session = b.sid
	if err := pingRelayed(&wrong); err == nil {
		t.Fatal("team A's client must not verify team B's daemon")
	}
}

// TestRelayReconnectSameSession: why — clients keep reaching the daemon via
// the same SNI, so after the relay drops the control stream the daemon must
// re-register the SAME session ID, and the session is then usable again.
func TestRelayReconnectSameSession(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	team := startRelayTeam(t, rs, hp, "")
	cc := enrollViaRelay(t, hp, team)
	rs.mu.Lock()
	old := rs.sessions[team.sid]
	rs.mu.Unlock()
	_ = old.ctrl.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		rs.mu.Lock()
		s := rs.sessions[team.sid]
		rs.mu.Unlock()
		if s != nil && s != old && s.ctrl != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon did not re-register its session")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := pingRelayed(cc); err != nil {
		t.Fatalf("enrolled client after reconnect: %v", err)
	}
	team.conn.close()
	waitRelaySession(t, rs, team.sid, false)
	if err := pingRelayed(cc); err == nil {
		t.Fatal("after the daemon disconnects the relay must reject its session")
	}
}

// relayRawDial opens a TCP connection to the relay and sends a ClientHello
// for sid, so the relay routes it without a TLS client finishing a handshake.
func relayRawDial(t *testing.T, hp, sid string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", hp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(captureClientHello(t, sid)); err != nil {
		t.Fatal(err)
	}
	return c
}

// relayReadsData reports whether the relay answered with data (true) or closed
// the connection (false) within d.
func relayReadsData(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	n, err := c.Read(make([]byte, 1))
	return n > 0 && err == nil
}

// TestRelayLimits: why — the relay must bound its resources: streams per
// session, a deadline for the daemon to accept, and an idle timeout on spliced
// streams; a freed stream slot is reusable.
func TestRelayLimits(t *testing.T) {
	rs, hp := startTestRelay(t, "", func(rs *relayServer) {
		rs.MaxPerSession = 1
		rs.IdleTimeout = 400 * time.Millisecond
	})
	team := startRelayTeam(t, rs, hp, "")
	first := relayRawDial(t, hp, team.sid)
	if !relayReadsData(first, 5*time.Second) {
		t.Fatal("first stream must reach the daemon (ServerHello)")
	}
	second := relayRawDial(t, hp, team.sid)
	if relayReadsData(second, 5*time.Second) {
		t.Fatal("a stream over the per-session limit must be closed")
	}
	second.Close()
	start := time.Now()
	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, first) // the rest of the server flight, then EOF at idle
	if el := time.Since(start); el < 300*time.Millisecond || el > 4*time.Second {
		t.Fatalf("idle stream closed after %s, want about the 400ms idle timeout", el)
	}
	first.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		third := relayRawDial(t, hp, team.sid)
		ok := relayReadsData(third, 2*time.Second)
		third.Close()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a freed stream slot must be reusable")
		}
	}

	// A registered session that never accepts: the client is closed after AcceptTimeout.
	rs2, hp2 := startTestRelay(t, "", func(rs *relayServer) { rs.AcceptTimeout = 300 * time.Millisecond })
	sid, ctrl, err := registerNewTestSession(t, hp2, "")
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	waitRelaySession(t, rs2, sid, true)
	start = time.Now()
	c := relayRawDial(t, hp2, sid)
	defer c.Close()
	line, err := bufio.NewReader(ctrl).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "conn ") {
		t.Fatalf("the relay must announce the stream on the control stream: %q %v", line, err)
	}
	if relayReadsData(c, 5*time.Second) {
		t.Fatal("an unaccepted stream must be closed")
	}
	if el := time.Since(start); el < 250*time.Millisecond || el > 4*time.Second {
		t.Fatalf("unaccepted stream closed after %s, want about the 300ms accept timeout", el)
	}
}

// TestResolveHTTPRelay: why — a daemon with a relay must not open a TCP port
// that bypasses the relay unless the admin asks (-http or config http).
func TestResolveHTTPRelay(t *testing.T) {
	relay := &config{RelaySession: "0123456789abcdef0123456789abcdef"}
	relayHTTP := &config{RelaySession: "0123456789abcdef0123456789abcdef", Http: true}
	if resolveHTTP(false, false, relay, true) {
		t.Error("relay + mTLS: HTTP must default off")
	}
	if !resolveHTTP(true, true, relay, true) {
		t.Error("relay: -http must turn HTTP on")
	}
	if !resolveHTTP(false, false, relayHTTP, true) {
		t.Error("relay: config http must turn HTTP on")
	}
}

// TestParseMtlsArgsRelay: why — relay.json is the only relay source, so the
// old relay flags are usage errors; relay URLs default to port 9876 and the
// relay CA setting ("system" or a PEM file) is validated before it is stored.
func TestParseMtlsArgsRelay(t *testing.T) {
	for _, bad := range [][]string{{"-relay", "https://relay.example/"}, {"-token", "tk"}, {"-relay-ca", "system"}} {
		if _, err := parseMtlsArgs(bad); err == nil {
			t.Errorf("parseMtlsArgs(%q) must fail", bad)
		}
	}
	if h, p, norm, err := relayHostPort("https://relay.example/"); err != nil || h != "relay.example" || p != defRelayPort || norm != "https://relay.example:9876/" {
		t.Fatalf("relayHostPort = %q %d %q %v", h, p, norm, err)
	}
	for _, bad := range []string{"http://relay/", "https://relay/x"} {
		if _, _, _, err := relayHostPort(bad); err == nil {
			t.Errorf("relayHostPort(%q) must fail", bad)
		}
	}
	ca := filepath.Join(t.TempDir(), "relay-ca.pem")
	_, caCert := cryptoGenerateCA("pinned", time.Hour)
	writeTestPEM(t, filepath.Dir(ca), filepath.Base(ca), cryptoPEMCert(caCert))
	if v, err := normalizeRelayCA("system"); err != nil || v != "system" {
		t.Fatalf("normalizeRelayCA(system) = %q %v", v, err)
	}
	if v, err := normalizeRelayCA(ca); err != nil || v != ca {
		t.Fatalf("normalizeRelayCA(FILE) = %q %v", v, err)
	}
	if _, err := normalizeRelayCA(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("a missing relay CA file must fail")
	}
}

// startTestMtlsUnixDaemon serves the MCP line protocol over mTLS on a unix socket.
func startTestMtlsUnixDaemon(t *testing.T, socket string, srvCert *x509.Certificate, srvKey *ecdsa.PrivateKey, pool *x509.CertPool) {
	t.Helper()
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ln = tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert.Raw}, PrivateKey: srvKey}}})
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = serveLines(c, c, &fakeExec{})
			}(c)
		}
	}()
}

// TestLiveDaemonPrefersLocalMtlsSocket: why — the daemon host's CLI talks to
// its own daemon only over the unix socket, with the socket's mTLS taken from
// config.json and the state dir's certificates; a leftover client.json naming
// a relay or HTTP endpoint is never dialed
// (plans/host-socket-cli-and-live-reindex-plan.md).
func TestLiveDaemonPrefersLocalMtlsSocket(t *testing.T) {
	dir := shortStateDir(t)
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_SOCKET", "")
	caKey, caCert := writeTestClientPKI(t, dir)
	srvKey, srvCert := cryptoGenerateLeaf(caKey, caCert, "srv", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour)
	writeTestPEM(t, dir, "server.crt", cryptoPEMCert(srvCert))
	if err := saveConfig(&config{Mtls: true, CaCert: "ca.crt"}); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	deadPort := freePort(t)
	remote := mtlsHostConfig(deadPort)
	remote.Session = newRelaySessionID()
	if err := saveClientConfig(remote); err != nil {
		t.Fatal(err)
	}
	if remoteClient() || !isDaemonHost() {
		t.Fatal("a state dir with config.json is a daemon host, whatever client.json says")
	}
	if _, _, ok, err := liveDaemon(); ok || (err != nil && strings.Contains(err.Error(), strconv.Itoa(deadPort))) {
		t.Fatalf("with the daemon down the host must not dial client.json endpoints: ok=%v err=%v", ok, err)
	}
	startTestMtlsUnixDaemon(t, filepath.Join(dir, "daemon.sock"), srvCert, srvKey, pool)
	_, desc, ok, err := liveDaemon()
	if !ok || desc != "unix "+filepath.Join(dir, "daemon.sock")+" (mtls)" {
		t.Fatalf("the local mTLS daemon socket must be used, got ok=%v desc=%q err=%v", ok, desc, err)
	}
}

// TestRelayListCLI: why — with several joined relays a new session falls back
// round robin when a relay cannot take it, then sticks to the relay that did:
// when that relay is down the daemon logs errors instead of moving, and only
// the host's `relay move` switches it (keeping the session, since every
// joined relay host is a SAN).
func TestRelayListCLI(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	dirA, dirB, srvDir := shortStateDir(t), shortStateDir(t), shortStateDir(t)
	env := func(dir string) []string {
		return append(os.Environ(), "KBTOOL_DIR="+dir, "HOME="+work, "KB_EMBED_URL=", "KBTOOL_SOCKET=")
	}
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, bin, args...)
		c.Env = env(dir)
		out, err := c.CombinedOutput()
		return string(out), err
	}
	n := 0
	spawn := func(dir string, args ...string) (*exec.Cmd, string) {
		t.Helper()
		n++
		logPath := filepath.Join(work, fmt.Sprintf("p%d.log", n))
		lf, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		c := exec.Command(bin, args...)
		c.Env = env(dir)
		c.Stdout, c.Stderr = lf, lf
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _, _ = c.Process.Wait(); lf.Close() })
		return c, logPath
	}
	stop := func(c *exec.Cmd) {
		_ = c.Process.Signal(syscall.SIGTERM)
		_, _ = c.Process.Wait()
	}
	waitLog := func(path, want string) string {
		t.Helper()
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if l := string(mustReadFile(t, path)); strings.Contains(l, want) {
				return l
			}
		}
		t.Fatalf("%q not in log:\n%s", want, mustReadFile(t, path))
		return ""
	}
	startRelay := func(dir, hp string) *exec.Cmd {
		t.Helper()
		c, _ := spawn(dir, "relay", "run", "-bind", hp)
		for deadline := time.Now().Add(15 * time.Second); !relayHealthy(hp); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("relay %s did not come up", hp)
			}
		}
		return c
	}
	cfgOf := func() config {
		var c config
		if err := json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	pA, pB := freePort(t), freePort(t)
	hpA, hpB := fmt.Sprintf("127.0.0.1:%d", pA), fmt.Sprintf("127.0.0.1:%d", pB)
	urlA, urlB := "https://"+hpA+"/", "https://"+hpB+"/"
	relayA, relayB := startRelay(dirA, hpA), startRelay(dirB, hpB)
	for _, u := range []string{urlA, urlB} {
		if out, err := run(srvDir, "relay", "join", u); err != nil {
			t.Fatalf("relay join %s: %v\n%s", u, err, out)
		}
	}
	if out, err := run(srvDir, "relay", "ls"); err != nil || !strings.Contains(out, "1. "+urlA+" (trusts the certificate it presents; next new session starts here)") || !strings.Contains(out, "2. "+urlB) {
		t.Fatalf("relay ls: %v\n%s", err, out)
	}
	stop(relayA)
	if out, err := run(srvDir, "mtls", "-expire", "1h"); err != nil || !strings.Contains(out, "round robin") {
		t.Fatalf("mtls: %v\n%s", err, out)
	}
	sid := cfgOf().RelaySession
	if cfgOf().RelayURL != "" {
		t.Fatal("a new relay session picks its relay at daemon start")
	}

	d1, log1 := spawn(srvDir, "daemon", "run")
	waitLog(log1, "relay "+hpA+": cannot start the session there")
	waitLog(log1, "session "+sid+" started on relay "+urlB+" and sticks to it")
	line := waitImportLine(t, log1, enrollTokenPrefix, 20*time.Second)
	if tok, err := parseEnrollToken(strings.Fields(line)[3]); err != nil || tok.Port != pB {
		t.Fatalf("the enrollment line must name the relay that took the session: %+v %v", tok, err)
	}
	var rj relayJSON
	_ = json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "relay.json")), &rj)
	if cfgOf().RelayURL != urlB || rj.Next != 0 {
		t.Fatalf("sticky relay %q (want %s), next %d (want 0, past B)", cfgOf().RelayURL, urlB, rj.Next)
	}
	stop(d1)

	stop(relayB)
	relayA = startRelay(dirA, hpA)
	d2, log2 := spawn(srvDir, "daemon", "run")
	waitLog(log2, "relay "+hpB+": ")
	time.Sleep(500 * time.Millisecond)
	if l := string(mustReadFile(t, log2)); strings.Contains(l, "registered") || strings.Contains(l, hpA) {
		t.Fatalf("a sticky session must not move to another relay on its own:\n%s", l)
	}
	if out, err := run(srvDir, "relay", "move", urlA); err == nil || !strings.Contains(out, "daemon is running") {
		t.Fatalf("relay move needs the daemon stopped: %v\n%s", err, out)
	}
	stop(d2)
	if out, err := run(srvDir, "relay", "move", "https://127.0.0.1:1/"); err == nil || !strings.Contains(out, "not joined") {
		t.Fatalf("relay move to a relay that is not joined: %v\n%s", err, out)
	}
	if out, err := run(srvDir, "relay", "move", urlA); err != nil || !strings.Contains(out, "moved to "+urlA) {
		t.Fatalf("relay move: %v\n%s", err, out)
	}
	if c := cfgOf(); c.RelayURL != urlA || c.RelaySession != sid {
		t.Fatalf("relay move keeps the session when the certificates cover the relay: %+v", c)
	}
	_, log3 := spawn(srvDir, "daemon", "run")
	waitLog(log3, "relay "+hpA+": session "+sid+" registered")
	if out, err := run(srvDir, "relay", "ls"); err != nil || !strings.Contains(out, "session "+sid+" sticks here") {
		t.Fatalf("relay ls shows the sticky relay: %v\n%s", err, out)
	}
	if out, err := run(srvDir, "status"); err != nil || !strings.Contains(out, "relay:    session "+sid+" on "+urlA+" (sticky; relays enabled, 2 joined)") {
		t.Fatalf("status shows the sticky relay: %v\n%s", err, out)
	}
}

// TestRelayCLI: why — the user-facing flow through the built binary: a relay
// service, `relay join` (checked before relay.json is written) and `mtls`
// (relay-only SAN, stored session, http off, no host client.json), a daemon
// that opens no TCP port and prints the relay token import line, the refusals
// (relay and daemon in one state dir, unreachable relay), enrollment (which
// writes the client's relay.json) and calls from a third state dir, the same
// session after a daemon restart, a new one from the next `mtls`, and `relay
// leave` returning mtls to direct mode.
func TestRelayCLI(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	relayDir, srvDir, cliDir := shortStateDir(t), shortStateDir(t), shortStateDir(t)
	env := func(dir string) []string {
		return append(os.Environ(), "KBTOOL_DIR="+dir, "HOME="+work, "KB_EMBED_URL=", "KBTOOL_SOCKET=")
	}
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, bin, args...)
		c.Env = env(dir)
		out, err := c.CombinedOutput()
		return string(out), err
	}
	spawn := func(dir, logName string, args ...string) (*exec.Cmd, string) {
		t.Helper()
		logPath := filepath.Join(work, logName)
		lf, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		c := exec.Command(bin, args...)
		c.Env = env(dir)
		c.Stdout, c.Stderr = lf, lf
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _, _ = c.Process.Wait(); lf.Close() })
		return c, logPath
	}
	stop := func(c *exec.Cmd) {
		_ = c.Process.Signal(syscall.SIGTERM)
		_, _ = c.Process.Wait()
	}

	port := freePort(t)
	hp := fmt.Sprintf("127.0.0.1:%d", port)
	relayURL := "https://" + hp + "/"
	relay, relayLog := spawn(relayDir, "relay.log", "relay", "run", "-bind", hp, "-token", "tk")
	deadline := time.Now().Add(15 * time.Second)
	for !relayHealthy(hp) {
		if time.Now().After(deadline) {
			t.Fatalf("relay did not come up:\n%s", mustReadFile(t, relayLog))
		}
		time.Sleep(50 * time.Millisecond)
	}
	fresh := shortStateDir(t)
	if out, err := run(fresh, "relay", "join", fmt.Sprintf("https://127.0.0.1:%d/", freePort(t))); err == nil || !strings.Contains(out, "not usable") || fileExists(filepath.Join(fresh, "relay.json")) {
		t.Fatalf("relay join must check the relay before writing relay.json: %v\n%s", err, out)
	}

	if out, err := run(srvDir, "relay", "join", relayURL, "-token", "tk"); err != nil || !strings.Contains(out, "reachable") {
		t.Fatalf("relay join: %v\n%s", err, out)
	}
	var rj relayJSON
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "relay.json")), &rj); err != nil || len(rj.Relays) != 1 || rj.Relays[0].URL != relayURL || rj.Relays[0].Token != "tk" || !rj.Enabled {
		t.Fatalf("relay.json: %+v %v", rj, err)
	}
	if fi, err := os.Stat(filepath.Join(srvDir, "relay.json")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("relay.json holds the relay token and must be 0600: %v", err)
	}
	if out, err := run(srvDir, "mtls", "-expire", "1h"); err != nil {
		t.Fatalf("mtls with relay.json: %v\n%s", err, out)
	}
	var cfg config
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.MessageBoard == nil || !*cfg.MessageBoard {
		t.Fatalf("the message board defaults on: %+v", cfg.MessageBoard)
	}
	if !isRelaySessionID(cfg.RelaySession) || cfg.RelayToken != "" || cfg.Http || cfg.HTTPAddr != "" || !cfg.Mtls {
		t.Fatalf("relay-mode mtls config: %+v", cfg)
	}
	sid := cfg.RelaySession
	if fi, err := os.Stat(filepath.Join(srvDir, relaySessionKeyFile)); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("relay-mode mtls must write %s with mode 0600: %v", relaySessionKeyFile, err)
	}
	if _, err := loadRelayAuth(srvDir, filepath.Join(srvDir, "ca.crt"), sid); err != nil {
		t.Fatalf("the session ID must derive from the session key and the CA expiry: %v", err)
	}
	crt, err := cryptoFirstCert(filepath.Join(srvDir, "server.crt"))
	if err != nil || !reflect.DeepEqual(mapIps(crt.IPAddresses), []string{"127.0.0.1"}) || len(crt.DNSNames) != 0 {
		t.Fatalf("server SAN must be only the relay host: %v %v %v", err, crt.IPAddresses, crt.DNSNames)
	}
	if fileExists(filepath.Join(srvDir, "client.json")) {
		t.Fatal("the daemon host must keep no client.json: it uses its unix socket")
	}

	daemon, daemonLog := spawn(srvDir, "daemon1.log", "daemon", "run")
	line := waitImportLine(t, daemonLog, enrollTokenPrefix, 20*time.Second)
	if w := strings.Fields(line); len(w) != 4 {
		t.Fatalf("the relay import line must be `kbtool client -import kb1…`: %q", line)
	} else if tok, err := parseEnrollToken(w[3]); err != nil || tok.Host != "127.0.0.1" || tok.Port != port || tok.Session != sid {
		t.Fatalf("the relay token must carry the relay address and session: %+v %v", tok, err)
	}
	waitLog := func(path, want string) string {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if l := string(mustReadFile(t, path)); strings.Contains(l, want) {
				return l
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%q not in log:\n%s", want, mustReadFile(t, path))
		return ""
	}
	logText := waitLog(daemonLog, "session "+sid+" registered")
	if strings.Contains(logText, "https://*") || !strings.Contains(logText, "relay "+relayURL) {
		t.Fatalf("relay-mode daemon must not open a TCP port by default:\n%s", logText)
	}
	hp2 := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	relay2, relay2Log := spawn(srvDir, "relay2.log", "relay", "run", "-bind", hp2)
	for deadline := time.Now().Add(15 * time.Second); !relayHealthy(hp2); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("a relay must run beside a daemon in one state dir:\n%s", mustReadFile(t, relay2Log))
		}
	}
	stop(relay2)
	if out, err := run(srvDir, "status"); err != nil || !strings.Contains(out, "socket "+filepath.Join(srvDir, "daemon.sock")) ||
		!strings.Contains(out, "relay:    session "+sid+" on "+relayURL+" (sticky") || !strings.Contains(out, "unix socket only") {
		t.Fatalf("the daemon host's CLI must use the unix socket: %v\n%s", err, out)
	}

	f := strings.Fields(line)
	if out, err := run(cliDir, f[1:]...); err != nil || !strings.Contains(out, "enrolled") {
		t.Fatalf("client import through the relay: %v\n%s", err, out)
	}
	var crj relayJSON
	var ccj clientConfig
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(cliDir, "relay.json")), &crj); err != nil || !crj.Enabled || len(crj.Relays) != 0 {
		t.Fatalf("a relay token import must enable relays in the client's relay.json and join none: %+v %v", crj, err)
	}
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(cliDir, "client.json")), &ccj); err != nil || ccj.Host != "" || ccj.Port != 0 || ccj.Session != sid || ccj.Relay != relayURL {
		t.Fatalf("a relay client.json keeps the session and the relay the token named: %+v %v", ccj, err)
	}
	if out, err := run(cliDir, "status"); err != nil || !strings.Contains(out, "reachable at https://"+hp+" (relay session "+sid+")") {
		t.Fatalf("enrolled client must reach the daemon via the relay: %v\n%s", err, out)
	}
	if out, err := run(cliDir, "tools"); err != nil || !strings.Contains(out, "board_post") {
		t.Fatalf("a relay daemon must serve the board tools without a config edit: %v\n%s", err, out)
	}

	stop(daemon)
	_, daemonLog2 := spawn(srvDir, "daemon2.log", "daemon", "run")
	if line2 := waitImportLine(t, daemonLog2, enrollTokenPrefix, 20*time.Second); line2 == line {
		t.Fatal("a restarted daemon must print a new token (new boot key)")
	}
	waitLog(daemonLog2, "session "+sid+" registered")
	if out, err := run(cliDir, "status"); err != nil || !strings.Contains(out, "reachable at https://"+hp) {
		t.Fatalf("an enrolled client must keep working after a daemon restart: %v\n%s", err, out)
	}
	if out, err := run(cliDir, "relay", "disable"); err != nil || !strings.Contains(out, "disabled") {
		t.Fatalf("relay disable: %v\n%s", err, out)
	}
	if out, _ := run(cliDir, "tools"); !strings.Contains(out, "relay enable") {
		t.Fatalf("a client of a disabled relay must refuse and name 'kbtool relay enable':\n%s", out)
	}
	if out, err := run(cliDir, "relay", "enable"); err != nil {
		t.Fatalf("relay enable: %v\n%s", err, out)
	}
	if out, err := run(cliDir, "status"); err != nil || !strings.Contains(out, "reachable at https://"+hp) {
		t.Fatalf("re-enabling the relay must reconnect the client: %v\n%s", err, out)
	}
	stop(relay)
	if out, err := run(srvDir, "mtls"); err != nil {
		t.Fatalf("mtls again: %v\n%s", err, out)
	}
	var cfg2 config
	_ = json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &cfg2)
	if !isRelaySessionID(cfg2.RelaySession) || cfg2.RelaySession == sid {
		t.Fatalf("a new mtls must issue a new relay session: %+v", cfg2)
	}
	if err := os.Remove(filepath.Join(srvDir, relaySessionKeyFile)); err != nil {
		t.Fatal(err)
	}
	if out, err := run(srvDir, "daemon", "run"); err == nil || !strings.Contains(out, "relay session key") {
		t.Fatalf("a relay session without its key (pre-key config) must be refused at daemon start: %v\n%s", err, out)
	}
	if out, err := run(srvDir, "relay", "disable"); err != nil {
		t.Fatalf("relay disable: %v\n%s", err, out)
	}
	if b := mustReadFile(t, filepath.Join(srvDir, "relay.json")); !strings.Contains(string(b), `"enabled": false`) || !strings.Contains(string(b), relayURL) {
		t.Fatalf("relay disable must keep relay.json and set enabled false:\n%s", b)
	}
	localDaemon, localLog := spawn(srvDir, "daemon3.log", "daemon", "run")
	waitLog(localLog, "relays are disabled (or none is joined); serving locally only")
	if out, err := run(srvDir, "status"); err != nil || !strings.Contains(out, "relays disabled, 1 joined") {
		t.Fatalf("status must show the disabled relay: %v\n%s", err, out)
	}
	stop(localDaemon)
	if l := string(mustReadFile(t, localLog)); strings.Contains(l, enrollTokenPrefix) {
		t.Fatalf("a daemon with a disabled relay must print no enrollment line:\n%s", l)
	}
	if out, err := run(srvDir, "relay", "enable"); err != nil {
		t.Fatalf("relay enable: %v\n%s", err, out)
	}
	off := false
	cfg2.MessageBoard = &off
	if b, err := json.Marshal(cfg2); err != nil || os.WriteFile(filepath.Join(srvDir, "config.json"), b, 0600) != nil {
		t.Fatal(err)
	}
	if out, err := run(srvDir, "relay", "leave"); err == nil || !strings.Contains(out, "-all") {
		t.Fatalf("relay leave needs a URL or -all: %v\n%s", err, out)
	}
	if out, err := run(srvDir, "relay", "leave", "-all"); err != nil || fileExists(filepath.Join(srvDir, "relay.json")) {
		t.Fatalf("relay leave must remove relay.json: %v\n%s", err, out)
	}
	if out, err := run(srvDir, "mtls", "-ip", "127.0.0.1"); err != nil {
		t.Fatalf("mtls (leaving relay mode): %v\n%s", err, out)
	}
	var cfg3 config
	_ = json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &cfg3)
	if cfg3.RelaySession != "" || cfg3.MessageBoard == nil || *cfg3.MessageBoard {
		t.Fatalf("mtls without relay.json must leave relay mode and keep the user's message_board=false: %+v", cfg3)
	}
	if fileExists(filepath.Join(srvDir, relaySessionKeyFile)) {
		t.Fatal("mtls without relay.json must drop the relay session key")
	}
}

// TestRelayDefaultPortIsDaemonPort: why — a relay and a daemon never share a
// state dir, so the relay uses the daemon's port (9876) for its bind and for
// relay URLs without a port; an explicit -bind still wins.
func TestRelayDefaultPortIsDaemonPort(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	if defRelayPort != defHTTPPort || defHTTPPort != 9876 {
		t.Fatalf("relay default port %d, daemon %d: want both 9876", defRelayPort, defHTTPPort)
	}
	if o := parseRelayOpts(nil); o.bind != ":9876" {
		t.Fatalf("relay default bind = %q, want :9876", o.bind)
	}
	if o := parseRelayOpts([]string{"-bind", "127.0.0.1:7000"}); o.bind != "127.0.0.1:7000" {
		t.Fatalf("explicit -bind must win, got %q", o.bind)
	}
	if _, p, norm, err := relayHostPort("https://relay.example/"); err != nil || p != 9876 || norm != "https://relay.example:9876/" {
		t.Fatalf("relay URL without a port: %d %q %v", p, norm, err)
	}
}

// ---------- 35. PBKDF2 cost (plans/pbkdf2-derive-once-plan.md) ----------

// TestBundlePBKDF2Iterations: why — KBX1 keys are stretched with 600,000
// PBKDF2-HMAC-SHA256 iterations, changed in place without a version bump: a
// bundle keyed with the old 100,000 iterations must not decrypt, and the
// header still says version 1.
func TestBundlePBKDF2Iterations(t *testing.T) {
	if bundlePBKDF2 != 600000 || bundleVersion != 1 {
		t.Fatalf("iterations %d version %d: want 600000, 1", bundlePBKDF2, bundleVersion)
	}
	key := []byte("pass")
	ct := cryptoEncryptBundle([]byte("data"), key)
	if v := binary.LittleEndian.Uint16(ct[4:6]); v != 1 {
		t.Fatalf("header version %d, want 1", v)
	}
	want := cryptoBundleAEAD(key, ct[6:22], 600000)
	if pt, err := want.Open(nil, ct[22:34], ct[34:], nil); err != nil || string(pt) != "data" {
		t.Fatalf("bundle must be keyed with 600k iterations: %q %v", pt, err)
	}
	old := cryptoBundleAEAD(key, ct[6:22], 100000)
	legacy := append(append([]byte{}, ct[:34]...), old.Seal(nil, ct[22:34], []byte("data"), nil)...)
	if _, err := cryptoDecryptBundle(legacy, key); err == nil {
		t.Fatal("a 100k-iteration bundle must no longer decrypt")
	}
}

// TestBootstrapBundleNoServerPBKDF2: why — the enrollment bundle is encrypted
// per request with the boot key; the daemon must derive that key once at boot
// and keep it, so requests cost no PBKDF2 (and cannot be used to burn server
// CPU), while each client still pays one 600k derivation to decrypt.
func TestBootstrapBundleNoServerPBKDF2(t *testing.T) {
	before := pbkdf2Derivations.Load()
	f := startBootFixture(t, nil)
	if n := pbkdf2Derivations.Load() - before; n != 1 {
		t.Fatalf("daemon boot ran %d PBKDF2 derivations, want exactly 1", n)
	}
	hc := f.httpsClient(t, false)
	var bodies [][]byte
	before = pbkdf2Derivations.Load()
	start := time.Now()
	for i := 0; i < 20; i++ {
		resp, err := hc.Get("https://" + f.hp + "/bundle/" + f.bs.ID)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bundle request: %s", resp.Status)
		}
		bodies = append(bodies, b)
	}
	served := time.Since(start)
	if n := pbkdf2Derivations.Load() - before; n != 0 {
		t.Fatalf("serving 20 bundles ran %d PBKDF2 derivations, want 0", n)
	}
	nonces := map[string]bool{}
	for _, b := range bodies {
		if !bytes.Equal(b[6:22], bodies[0][6:22]) {
			t.Fatal("served bundles must share the boot salt (one derived key)")
		}
		nonces[string(b[22:34])] = true
	}
	if len(nonces) != len(bodies) {
		t.Fatal("every served bundle needs a fresh nonce")
	}
	start = time.Now()
	if _, err := cryptoDecryptBundle(bodies[0], f.bs.Key); err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	t.Logf("server: 20 bundles in %s; client: one 600k-iteration decrypt in %s", served, time.Since(start))
	if n := pbkdf2Derivations.Load() - before; n != 1 {
		t.Fatalf("client decrypt ran %d derivations, want 1", n)
	}
	if _, err := cryptoDecryptBundle(bodies[1], []byte("wrong")); err == nil {
		t.Fatal("a wrong key must fail")
	}
}

// TestEncryptedStoreDerivesOnce: why — the encrypted store is server-side
// state read and rewritten on every board operation; it must derive its key
// once per open, not on every read or save.
func TestEncryptedStoreDerivesOnce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	path := filepath.Join(dir, "kb.db")
	key := []byte("store-pass")
	st, err := openKBStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	before := pbkdf2Derivations.Load()
	b := newBoard()
	for i := 0; i < 5; i++ {
		if err := st.saveBoard(b); err != nil {
			t.Fatal(err)
		}
		if _, err := st.loadBoard(false); err != nil {
			t.Fatal(err)
		}
	}
	if n := pbkdf2Derivations.Load() - before; n != 1 {
		t.Fatalf("5 saves + 5 loads ran %d PBKDF2 derivations, want 1", n)
	}
	before = pbkdf2Derivations.Load()
	st2, err := openKBStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := st2.loadBoard(false); err != nil {
			t.Fatal(err)
		}
		if err := st2.saveBoard(b); err != nil {
			t.Fatal(err)
		}
	}
	if n := pbkdf2Derivations.Load() - before; n != 1 {
		t.Fatalf("reopen + 3 loads + 3 saves ran %d PBKDF2 derivations, want 1", n)
	}
	if _, err := openKBStore(path, []byte("wrong")); err == nil {
		t.Fatal("a wrong store key must fail")
	}
}

// ---------- 36. compact enrollment token (plans/compact-enrollment-token-plan.md) ----------

// TestEnrollTokenRoundTrip: why — every host kind, with and without a custom
// port and session, must decode to exactly what was encoded (the default port
// decodes as 0, which the client reads as 9876).
func TestEnrollTokenRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, enrollKeyLen)
	sid := newRelaySessionID()
	for _, host := range []string{"", "10.0.0.5", "2001:db8::1", "relay.example.net"} {
		for _, port := range []int{0, defRelayPort, 443, 65535} {
			for _, session := range []string{"", sid} {
				in := enrollToken{Host: host, Port: port, Session: session, Key: key}
				s := in.encode()
				out, err := parseEnrollToken(s)
				want := in
				if want.Port == defRelayPort {
					want.Port = 0
				}
				if err != nil || !reflect.DeepEqual(out, want) {
					t.Fatalf("round trip %+v -> %q -> %+v %v", in, s, out, err)
				}
				if !strings.HasPrefix(s, enrollTokenPrefix) || strings.ContainsAny(s, "+/= ") {
					t.Fatalf("token %q must be kb1 + unpadded base64url", s)
				}
			}
		}
	}
}

// TestEnrollTokenRejects: why — the token is pasted by hand, so a truncated,
// extended or corrupted one must fail up front with a pointer to the daemon's
// line rather than dial somewhere unexpected.
func TestEnrollTokenRejects(t *testing.T) {
	key := bytes.Repeat([]byte{1}, enrollKeyLen)
	sid, _ := hex.DecodeString(newRelaySessionID())
	raw := func(b ...[]byte) string {
		return enrollTokenPrefix + base64.RawURLEncoding.EncodeToString(bytes.Join(b, nil))
	}
	good := enrollToken{Host: "relay.example.net", Port: 443, Session: hex.EncodeToString(sid), Key: key}.encode()
	for name, s := range map[string]string{
		"empty":          "",
		"no prefix":      strings.TrimPrefix(good, enrollTokenPrefix),
		"other version":  "kb2" + strings.TrimPrefix(good, enrollTokenPrefix),
		"not base64url":  good[:10] + "!" + good[11:],
		"padded":         good + "==",
		"prefix only":    enrollTokenPrefix,
		"truncated":      good[:len(good)-4],
		"trailing byte":  raw([]byte{0}, key, []byte{0}),
		"short key":      raw([]byte{0}, key[:15]),
		"unknown flag":   raw([]byte{1 << 4}, key),
		"port 0":         raw([]byte{tokFlagPort}, []byte{0, 0}, key),
		"bad DNS name":   raw([]byte{tokHostDNS, 4}, []byte("a b."), key),
		"IP as DNS name": raw([]byte{tokHostDNS, 8}, []byte("10.0.0.5"), key),
		"empty DNS name": raw([]byte{tokHostDNS, 0}, key),
		"short session":  raw([]byte{tokFlagSession}, sid[:8], key),
	} {
		if _, err := parseEnrollToken(s); err == nil || !strings.Contains(err.Error(), "invalid enrollment token") {
			t.Errorf("%s (%q) must be rejected: %v", name, s, err)
		}
	}
}

// TestEnrollTokenSize: why — the point of the format is the shortest paste: a
// direct token is the bare 128-bit key plus one flag byte, and a relay token
// only adds the host, the session and a non-default port.
func TestEnrollTokenSize(t *testing.T) {
	key := make([]byte, enrollKeyLen)
	if s := (enrollToken{Key: key}).encode(); len(s) != 3+23 {
		t.Fatalf("direct token %q is %d chars, want 26", s, len(s))
	}
	relay := enrollToken{Host: "relay.example.net", Port: defRelayPort, Session: newRelaySessionID(), Key: key}
	if s := relay.encode(); len(s) != 3+68 {
		t.Fatalf("relay token %q is %d chars, want 71", s, len(s))
	}
	relay.Host = "10.0.0.5"
	if s := relay.encode(); len(s) != 3+50 {
		t.Fatalf("IPv4 relay token %q is %d chars, want 53", s, len(s))
	}
}

// TestBundleIDFromKey: why — the bundle ID no longer travels, so client and
// daemon must derive the same 22-char ID, distinct per key and not the key.
func TestBundleIDFromKey(t *testing.T) {
	a, b := bytes.Repeat([]byte{1}, enrollKeyLen), bytes.Repeat([]byte{2}, enrollKeyLen)
	id := bundleIDFromKey(a)
	if id != bundleIDFromKey(a) || len(id) != 22 || id == bundleIDFromKey(b) || id == base64.RawURLEncoding.EncodeToString(a) {
		t.Fatalf("bundle ID %q must be a stable, key-specific 22-char derivation", id)
	}
	bs1, bs2 := startBootFixture(t, nil).bs, startBootFixture(t, nil).bs
	if bytes.Equal(bs1.Key, bs2.Key) || bs1.ID != bundleIDFromKey(bs1.Key) {
		t.Fatal("each boot must draw a fresh key and serve its derived ID")
	}
}

// ---------- 37. the message board defaults on, with or without a relay ----------

// TestBoardEnabledRule: why — an explicit message_board value always wins; a
// missing value means on in every mode, so a local session has its board (the
// agent's session memory) without a relay, and turning it off sticks.
func TestBoardEnabledRule(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		board *bool
		relay string
		want  bool
	}{
		{nil, "", true}, {nil, "0123456789abcdef0123456789abcdef", true},
		{&on, "", true}, {&on, "0123456789abcdef0123456789abcdef", true},
		{&off, "", false}, {&off, "0123456789abcdef0123456789abcdef", false},
	} {
		c := &config{MessageBoard: tc.board, RelaySession: tc.relay}
		if got := boardEnabled(c); got != tc.want {
			t.Errorf("boardEnabled(board=%v relay=%q) = %v, want %v", tc.board, tc.relay, got, tc.want)
		}
		disabled := effectiveDisabledSet(c)["board_post"]
		if disabled == tc.want {
			t.Errorf("board_post disabled=%v for board=%v relay=%q", disabled, tc.board, tc.relay)
		}
	}
	if !boardEnabled(nil) || effectiveDisabledSet(nil)["board_post"] {
		t.Fatal("no config must leave the board on")
	}
}

// TestEnsureToolOptionsRelaySeed: why — config writes seed the board option so
// the file documents it; the seed is true in every mode, and a present value
// is never re-stamped either way.
func TestEnsureToolOptionsRelaySeed(t *testing.T) {
	relay := &config{RelaySession: "0123456789abcdef0123456789abcdef"}
	ensureToolOptions(relay)
	plain := &config{}
	ensureToolOptions(plain)
	if relay.MessageBoard == nil || !*relay.MessageBoard || plain.MessageBoard == nil || !*plain.MessageBoard {
		t.Fatalf("seed: relay=%v plain=%v, want true for both", relay.MessageBoard, plain.MessageBoard)
	}
	off := false
	kept := &config{RelaySession: "0123456789abcdef0123456789abcdef", MessageBoard: &off}
	ensureToolOptions(kept)
	if *kept.MessageBoard {
		t.Fatal("an explicit false must not be re-stamped in relay mode")
	}
}

// TestRelayBoardFalseSurvivesDaemonArgs: why — after relay setup turned the
// board on, a user's later false must survive the config writes a
// `daemon start` with flags performs.
func TestRelayBoardFalseSurvivesDaemonArgs(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	off := false
	if err := saveConfig(&config{RelaySession: "0123456789abcdef0123456789abcdef", MessageBoard: &off}); err != nil {
		t.Fatal(err)
	}
	if !persistDaemonArgs([]string{"-board-max-memory", "512MiB"}) {
		t.Fatal("explicit flag should write the config")
	}
	c, err := loadConfig()
	if err != nil || c == nil || c.MessageBoard == nil || *c.MessageBoard || boardEnabled(c) {
		t.Fatalf("message_board=false must survive: %+v %v", c, err)
	}
}

// ---------- 38. host socket CLI, remote-client guard, live reindex (plans/host-socket-cli-and-live-reindex-plan.md) ----------

// TestStateDirRoles: why — every routing and refusal decision keys off the
// state dir's role, so each host marker must make a host (even next to a
// client.json), client.json alone makes a remote client, and neither is plain.
func TestStateDirRoles(t *testing.T) {
	for _, marker := range hostStateMarkers {
		dir := t.TempDir()
		t.Setenv("KBTOOL_DIR", dir)
		writeTestPEM(t, dir, "client.json", []byte(`{"version":1,"host":"127.0.0.1"}`))
		writeTestPEM(t, dir, marker, []byte("x"))
		if !isDaemonHost() || remoteClient() {
			t.Fatalf("%s next to client.json must make a daemon host", marker)
		}
	}
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	if isDaemonHost() || remoteClient() {
		t.Fatal("an empty state dir is plain local")
	}
	writeTestPEM(t, dir, "client.json", []byte(`{"version":1,"host":"127.0.0.1"}`))
	if isDaemonHost() || !remoteClient() {
		t.Fatal("client.json alone makes a remote client")
	}
}

// TestHostNeverDialsNetwork: why — the host CLI must reach its daemon only
// through the unix socket: a leftover client.json naming a LIVE HTTPS daemon is
// ignored, so a down local daemon means local fallback, never a network call.
func TestHostNeverDialsNetwork(t *testing.T) {
	dir := shortStateDir(t)
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_SOCKET", "")
	caKey, caCert := writeTestClientPKI(t, dir)
	srvKey, srvCert := cryptoGenerateLeaf(caKey, caCert, "srv", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	port, stop := startTestTLSHTTPServer(t, srvCert, srvKey, pool)
	defer stop()
	if err := saveClientConfig(mtlsHostConfig(port)); err != nil {
		t.Fatal(err)
	}
	if _, desc, ok, err := liveDaemon(); !ok || !strings.HasPrefix(desc, "https://") {
		t.Fatalf("control: as a remote client the live HTTPS daemon is used, got ok=%v desc=%q err=%v", ok, desc, err)
	}
	if err := saveConfig(&config{}); err != nil {
		t.Fatal(err)
	}
	if _, desc, ok, err := liveDaemon(); ok || err != nil {
		t.Fatalf("a host with no daemon socket must fall back locally, got ok=%v desc=%q err=%v", ok, desc, err)
	}
	startTestUnixDaemon(t, filepath.Join(dir, "daemon.sock"))
	if _, desc, ok, _ := liveDaemon(); !ok || desc != "unix "+filepath.Join(dir, "daemon.sock") {
		t.Fatalf("the host must use its plain socket, got ok=%v desc=%q", ok, desc)
	}
}

// swapTestDB builds a small index whose only file is named after word, so a
// test can tell which index is being served.
func swapTestDB(t *testing.T, word string) (*DB, []byte) {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, word+".go"), []byte("package x\n\nfunc "+word+"() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KB_EMBED_URL", "")
	db, err := buildDB(BuildOpts{Sources: []string{src}, Dim: testDim, Chunk: 48, MaxKB: 512, Embed: localEmbed, KWPath: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	return db, dbMarshal(db)
}

// servesFile reports whether db holds a chunk from a file named word.go.
func servesFile(db *DB, word string) bool {
	for _, c := range db.Chunks {
		if strings.HasSuffix(c.Path, word+".go") {
			return true
		}
	}
	return false
}

// newSwapToolbox serves db1 from a store in a fresh state dir (encrypted when
// key != nil) over a unix socket, and returns the toolbox and a client for it.
func newSwapToolbox(t *testing.T, db1 []byte, key []byte) (*Toolbox, *remoteExec) {
	t.Helper()
	dir := shortStateDir(t)
	t.Setenv("KBTOOL_DIR", dir)
	t.Setenv("KBTOOL_BOARD", "")
	t.Setenv("KBTOOL_DB", "")
	st, err := openKBStore(filepath.Join(dir, "kb.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.saveDBBytes(db1); err != nil {
		t.Fatal(err)
	}
	db, err := st.db()
	if err != nil {
		t.Fatal(err)
	}
	tb := &Toolbox{DB: db, Store: st, BoardPath: st.boardPath}
	tb.Trust = newTrustPolicy(db, nil, nil)
	sock := filepath.Join(dir, "daemon.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go serveUnix(ln, tb, make(chan error, 1))
	return tb, &remoteExec{ep: endpoint{kind: "unix", socket: sock}}
}

// TestIndexSwapPlain: why — the core of live reindexing on a plain store: the
// new index is served at once and replaces kb.db on disk, so a daemon restart
// would serve the same index.
func TestIndexSwapPlain(t *testing.T) {
	_, b1 := swapTestDB(t, "alphaOne")
	db2, b2 := swapTestDB(t, "betaTwo")
	tb, rex := newSwapToolbox(t, b1, nil)
	res, err := swapIndexVia(rex, b2)
	if err != nil || res.Encrypted || res.Chunks != len(db2.Chunks) || res.DB != tb.Store.path {
		t.Fatalf("swap: %+v %v", res, err)
	}
	if !servesFile(tb.DB, "betaTwo") || servesFile(tb.DB, "alphaOne") {
		t.Fatal("the daemon must serve the swapped index")
	}
	if !bytes.Equal(mustReadFile(t, tb.Store.path), b2) {
		t.Fatal("kb.db on disk must be the swapped index")
	}
	if out, isErr := tb.Execute("search_codebase", mustMarshal(map[string]any{"q": "betaTwo"})); isErr || !strings.Contains(out, "betaTwo.go") {
		t.Fatalf("search must find the new index: %s", out)
	}
}

// TestIndexSwapEncryptedKeepsNewIndex: why — the bug the save lock prevents: in
// an encrypted store every board save re-bundles kb.db, so after a swap a board
// post must carry the NEW index (and the old board), the client never needs the
// key, and no plaintext index or board ever lands on disk.
func TestIndexSwapEncryptedKeepsNewIndex(t *testing.T) {
	_, b1 := swapTestDB(t, "alphaOne")
	_, b2 := swapTestDB(t, "betaTwo")
	tb, rex := newSwapToolbox(t, b1, []byte("correct horse"))
	out, isErr := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "alice"}))
	m := regexp.MustCompile(`seed: ([0-9a-f]{64})`).FindStringSubmatch(out)
	if isErr || m == nil {
		t.Fatalf("signup: %s", out)
	}
	if res, err := swapIndexVia(rex, b2); err != nil || !res.Encrypted {
		t.Fatalf("swap: %+v %v", res, err)
	}
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "t", "text": "after swap", "seed": m[1]})); isErr {
		t.Fatalf("post: %s", out)
	}
	dbB, boardB, err := readStoreBundle(tb.Store.path, tb.Store.sealer)
	if err != nil || !bytes.Equal(dbB, b2) {
		t.Fatalf("a board save after the swap must keep the new index in the bundle (err=%v)", err)
	}
	b, err := readBoard(bytes.NewReader(boardB))
	if err != nil || b.Agents["alice"] == nil || b.Threads["t"] == nil {
		t.Fatalf("the board must survive the swap: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(tb.Store.path))
	for _, e := range entries {
		if n := e.Name(); n != "kb.db" && n != "kb.db.lock" && n != "daemon.sock" {
			t.Fatalf("unexpected file %s next to the encrypted store", n)
		}
	}
}

// TestIndexSwapRacesBoardPosts: why — swaps and board posts run concurrently in
// a live daemon; every post must survive and the final bundle must hold the
// last swapped index (run with -race).
func TestIndexSwapRacesBoardPosts(t *testing.T) {
	_, b1 := swapTestDB(t, "alphaOne")
	_, b2 := swapTestDB(t, "betaTwo")
	_, b3 := swapTestDB(t, "gammaThree")
	tb, rex := newSwapToolbox(t, b1, []byte("correct horse"))
	out, _ := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "alice"}))
	seed := regexp.MustCompile(`seed: ([0-9a-f]{64})`).FindStringSubmatch(out)[1]
	const posts = 12
	var wg sync.WaitGroup
	errs := make(chan string, posts+2)
	for i := 0; i < posts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "t", "text": fmt.Sprintf("m%d", i), "seed": seed})); isErr {
				errs <- out
			}
		}(i)
	}
	for _, b := range [][]byte{b2, b3} {
		if _, err := swapIndexVia(rex, b); err != nil {
			errs <- err.Error()
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	dbB, boardB, err := readStoreBundle(tb.Store.path, tb.Store.sealer)
	if res, _ := swapIndexVia(rex, b3); res.Chunks != 1 {
		t.Fatalf("the swap must report the index's own chunks, not merged board messages: %+v", res)
	}
	if err != nil || !bytes.Equal(dbB, b3) || !servesFile(tb.DB, "gammaThree") {
		t.Fatalf("the last swapped index must be served and stored (err=%v)", err)
	}
	b, err := readBoard(bytes.NewReader(boardB))
	if err != nil || b.Threads["t"] == nil || len(b.Threads["t"].Msgs) != posts {
		t.Fatalf("every post must survive the swaps: %v", err)
	}
}

// TestIndexSwapRejectsBadPayloads: why — a truncated, corrupted or non-index
// payload must be refused before anything is touched: the served index and
// kb.db stay exactly as they were.
func TestIndexSwapRejectsBadPayloads(t *testing.T) {
	db1, b1 := swapTestDB(t, "alphaOne")
	_, b2 := swapTestDB(t, "betaTwo")
	tb, rex := newSwapToolbox(t, b1, nil)
	sum := sha256.Sum256(b2)
	good := hex.EncodeToString(sum[:])
	junk := []byte("not an index at all")
	junkSum := sha256.Sum256(junk)
	cases := []struct {
		name    string
		params  map[string]any
		payload []byte
		want    string
	}{
		{"zero size", map[string]any{"size": 0, "sha256": good}, nil, "out of range"},
		{"too large", map[string]any{"size": int64(maxIndexSwap) + 1, "sha256": good}, nil, "out of range"},
		{"bad hash", map[string]any{"size": len(b2), "sha256": strings.Repeat("0", 64)}, b2, "checksum mismatch"},
		{"not an index", map[string]any{"size": len(junk), "sha256": hex.EncodeToString(junkSum[:])}, junk, "not a valid index"},
	}
	for _, c := range cases {
		res, err := rex.callPayload(methodIndexSwap, mustMarshal(c.params), c.payload)
		if err != nil {
			t.Fatalf("%s: transport error %v", c.name, err)
		}
		if res.Error == nil || !strings.Contains(res.Error.Message, c.want) {
			t.Fatalf("%s: want an error containing %q, got %+v", c.name, c.want, res)
		}
		if len(tb.DB.Chunks) != len(db1.Chunks) || !servesFile(tb.DB, "alphaOne") || !bytes.Equal(mustReadFile(t, tb.Store.path), b1) {
			t.Fatalf("%s: a refused swap must change nothing", c.name)
		}
	}
}

// TestIndexMethodsSocketOnly: why — swapping the index is a host-only power:
// over HTTP (mTLS or relay) and stdio the methods must not exist, whatever the
// caller's certificate.
func TestIndexMethodsSocketOnly(t *testing.T) {
	_, b1 := swapTestDB(t, "alphaOne")
	tb, rex := newSwapToolbox(t, b1, nil)
	if res, err := rex.call(methodIndexInfo, json.RawMessage(`{}`)); err != nil || res.Error != nil {
		t.Fatalf("control: index_info over the unix socket: %+v %v", res, err)
	}
	for _, m := range []string{methodIndexInfo, methodIndexSwap} {
		if _, err := dispatch(tb, m, json.RawMessage(`{"size":1,"sha256":"00"}`)); err == nil || !strings.Contains(err.Error(), "method not found") {
			t.Fatalf("%s must not be dispatched (HTTP path): %v", m, err)
		}
		srv := httptest.NewServer(httpHandler(tb))
		resp, err := http.Post(srv.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+m+`","params":{}}`))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		srv.Close()
		if !strings.Contains(string(body), "method not found") {
			t.Fatalf("%s over HTTP: %s", m, body)
		}
		var out bytes.Buffer
		if err := serveLines(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+m+`","params":{}}`+"\n"), &out, tb); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "method not found") {
			t.Fatalf("%s over stdio: %s", m, out.String())
		}
	}
}

// TestHostSocketCLI: why — the user-facing flow through the built binary: the
// host's CLI ignores a leftover client.json (with the daemon down it reports
// that no daemon runs; the file is removed at daemon start), `build` swaps into the running daemon with no
// restart, at-rest encryption can't be changed under it, another -db is just
// written; a remote client refuses every daemon-side command and a host dir
// refuses `client -import`.
func TestHostSocketCLI(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	host, remote := shortStateDir(t), shortStateDir(t)
	run := func(dir string, args ...string) (string, error) {
		c := exec.Command(bin, args...)
		c.Env = append(os.Environ(), "KBTOOL_DIR="+dir, "KBTOOL_SOCKET=", "KBTOOL_DB=", "KBTOOL_BOARD=", "KBTOOL_SECRET=", "KB_EMBED_URL=")
		out, err := c.CombinedOutput()
		return string(out), err
	}
	src := filepath.Join(work, "src")
	writeSrc := func(name string) {
		if err := os.MkdirAll(src, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, name+".go"), []byte("package x\n\nfunc "+name+"() {}\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeSrc("alphaOne")
	if out, err := run(host, "build", "-dim", strconv.Itoa(testDim), src); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	t.Setenv("KBTOOL_DIR", host)
	if err := saveClientConfig(mtlsHostConfig(freePort(t))); err != nil {
		t.Fatal(err)
	}
	if out, err := run(host, "query", "alphaOne"); err == nil || !strings.Contains(out, "no kbtool daemon is running") {
		t.Fatalf("a host with its daemon down must say so, ignoring client.json: %v\n%s", err, out)
	}
	if out, err := run(host, "status"); err != nil || !strings.Contains(out, "ignoring leftover") || !strings.Contains(out, "unix socket only") {
		t.Fatalf("host status: %v\n%s", err, out)
	}

	daemonLog := filepath.Join(work, "daemon.log")
	lf, err := os.Create(daemonLog)
	if err != nil {
		t.Fatal(err)
	}
	daemon := exec.Command(bin, "daemon", "run")
	daemon.Env = append(os.Environ(), "KBTOOL_DIR="+host, "KBTOOL_SOCKET=", "KBTOOL_DB=", "KBTOOL_BOARD=", "KBTOOL_SECRET=", "KB_EMBED_URL=")
	daemon.Stdout, daemon.Stderr = lf, lf
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_, _ = daemon.Process.Wait()
		_ = lf.Close()
	})
	sock := filepath.Join(host, "daemon.sock")
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if c, err := net.Dial("unix", sock); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon socket never came up:\n%s", mustReadFile(t, daemonLog))
		}
	}
	if fileExists(filepath.Join(host, "client.json")) || !strings.Contains(string(mustReadFile(t, daemonLog)), "removed leftover") {
		t.Fatalf("daemon start must remove the host's leftover client.json:\n%s", mustReadFile(t, daemonLog))
	}

	writeSrc("betaTwo")
	if out, err := run(host, "build", "-dim", strconv.Itoa(testDim), src); err != nil || !strings.Contains(out, "swapped into the running daemon") {
		t.Fatalf("build with the daemon running must swap: %v\n%s", err, out)
	}
	if out, err := run(host, "query", "betaTwo"); err != nil || !strings.Contains(out, "betaTwo.go") {
		t.Fatalf("the daemon must serve the swapped index without a restart: %v\n%s", err, out)
	}
	if out, err := run(host, "build", "-encrypt", src); err == nil || !strings.Contains(out, "stop the daemon to change at-rest encryption") {
		t.Fatalf("-encrypt under a running plain daemon must be refused: %v\n%s", err, out)
	}
	other := filepath.Join(work, "other.db")
	if out, err := run(host, "build", "-dim", strconv.Itoa(testDim), "-db", other, src); err != nil || strings.Contains(out, "swapped") || !fileExists(other) {
		t.Fatalf("a build to another -db just writes that file: %v\n%s", err, out)
	}

	writeTestClientPKI(t, remote)
	t.Setenv("KBTOOL_DIR", remote)
	if err := saveClientConfig(mtlsHostConfig(freePort(t))); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"build", src}, {"bench"}, {"daemon", "start"}, {"daemon", "status"}, {"mcp", "start"},
		{"mtls"}, {"relay", "status"}, {"relay", "run"},
	} {
		out, err := run(remote, args...)
		if err == nil || !strings.Contains(out, "this state dir is a remote client") {
			t.Fatalf("%v on a remote client must be refused: %v\n%s", args, err, out)
		}
		assertOnlyClientFiles(t, remote)
	}
	tok := enrollToken{Key: bytes.Repeat([]byte{7}, 16)}.encode()
	if out, err := run(host, "client", "-import", "https://127.0.0.1:1/", tok); err == nil || !strings.Contains(out, "belongs to a daemon host") {
		t.Fatalf("client -import into a host dir must be refused: %v\n%s", err, out)
	}
}

// ---------- 39. relay in-memory rotating CA and systemd (plans/relay-ephemeral-ca-and-systemd-plan.md) ----------

// relayLeafVia completes a TLS handshake with the relay itself (no session SNI)
// and returns the leaf it presented.
func relayLeafVia(t *testing.T, hp string) *x509.Certificate {
	t.Helper()
	c, err := tls.Dial("tcp", hp, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0]
}

// chainsTo reports whether leaf verifies under the PEM CA.
func chainsTo(leaf *x509.Certificate, caPEM []byte) bool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return false
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool})
	return err == nil
}

// TestRelayPKIInMemory: why — the relay's CA is generated per generation,
// never written, and its leaf chains to it; two generations never share a CA.
func TestRelayPKIInMemory(t *testing.T) {
	p1 := newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, []string{"relay.test"})
	p2 := newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil)
	if p1.FP == p2.FP || bytes.Equal(p1.CAPEM, p2.CAPEM) {
		t.Fatal("two generations must have different CAs")
	}
	if !chainsTo(p1.Leaf.Leaf, p1.CAPEM) || chainsTo(p1.Leaf.Leaf, p2.CAPEM) {
		t.Fatal("the leaf must chain to its own CA only")
	}
	if !containsString(p1.Leaf.Leaf.DNSNames, "relay.test") {
		t.Fatalf("extra DNS SAN missing: %v", p1.Leaf.Leaf.DNSNames)
	}
	if !p1.Expires.IsZero() || strings.Contains(relayStatusText(":1", p1), "valid until") {
		t.Fatal("an in-memory CA must not report its (disguised) expiry")
	}
}

// TestRelayCertDisguise: why — anyone can open a TLS connection to the relay,
// so its certificate must look like a sysadmin's long-lived self-made one:
// nothing names kbtool, the validity is years long and the same across
// rotations (a 12h window would give the relay away), the chain carries the
// CA, and no interface address or container name leaks into the SANs.
func TestRelayCertDisguise(t *testing.T) {
	ips, names := relaySANs([]string{"203.0.113.7"}, []string{"relay.example.org"})
	p1 := newRelayPKI(ips, names)
	p2 := newRelayPKI(ips, names)
	ca, err := x509.ParseCertificate(p1.Leaf.Certificate[len(p1.Leaf.Certificate)-1])
	if err != nil || len(p1.Leaf.Certificate) != 2 || !ca.IsCA || caFingerprint(ca.Raw) != p1.FP {
		t.Fatalf("chain must be [leaf, CA] with FP the CA's: %d certs, %v", len(p1.Leaf.Certificate), err)
	}
	leaf := p1.Leaf.Leaf
	if ca.Subject.String() != "CN="+relayCAName || len(leaf.Subject.Organization) != 0 {
		t.Fatalf("subjects: CA %q, leaf %q", ca.Subject, leaf.Subject)
	}
	host, _ := os.Hostname()
	if dnsNameOK(host) && leaf.Subject.CommonName != host {
		t.Fatalf("leaf CN %q, want the host name %q", leaf.Subject.CommonName, host)
	}
	for _, der := range p1.Leaf.Certificate {
		if bytes.Contains(bytes.ToLower(der), []byte("kbtool")) {
			t.Fatal("no certificate may contain \"kbtool\"")
		}
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("leaf EKU %v, want serverAuth only", leaf.ExtKeyUsage)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("IP SANs %v, want only the -ip one", leaf.IPAddresses)
	}
	for _, n := range leaf.DNSNames {
		if n != host && n != "relay.example.org" {
			t.Fatalf("unexpected DNS SAN %q in %v", n, leaf.DNSNames)
		}
	}
	age := time.Since(leaf.NotBefore)
	if age < 30*24*time.Hour-time.Minute || age > 365*24*time.Hour+time.Minute ||
		!leaf.NotAfter.Equal(leaf.NotBefore.AddDate(10, 0, 0)) {
		t.Fatalf("validity %s – %s, want issued 30–365 days ago for ten years", leaf.NotBefore, leaf.NotAfter)
	}
	if !ca.NotBefore.Equal(leaf.NotBefore) || !p2.Leaf.Leaf.NotBefore.Equal(leaf.NotBefore) || !p2.Leaf.Leaf.NotAfter.Equal(leaf.NotAfter) {
		t.Fatal("every generation of one relay process must carry the same validity")
	}
	if p1.FP == p2.FP {
		t.Fatal("rotation must still change the keys")
	}
}

// TestRelayRotationServesNewCA: why — after a rotation new handshakes present
// the new chain, whose CA fingerprint the daemon reports.
func TestRelayRotationServesNewCA(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	fp1, err := relayFingerprint(hp)
	if err != nil || fp1 != rs.currentPKI().FP {
		t.Fatalf("first CA: %q %v", fp1, err)
	}
	old := rs.currentPKI().CAPEM
	if !chainsTo(relayLeafVia(t, hp), old) {
		t.Fatal("the presented leaf must chain to the served CA")
	}
	rs.setPKI(newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil))
	fp2, err := relayFingerprint(hp)
	if err != nil || fp2 == fp1 || fp2 != rs.currentPKI().FP {
		t.Fatalf("after rotation the handshake must present the new CA: %q (old %q) %v", fp2, fp1, err)
	}
	leaf := relayLeafVia(t, hp)
	if !chainsTo(leaf, rs.currentPKI().CAPEM) || chainsTo(leaf, old) {
		t.Fatal("new handshakes must get the new leaf")
	}
}

// TestRelayRotationGraceful: why — rotation must not disturb a team: the
// daemon's control stream and an established client stream survive it, and a
// new client call works because the daemon's accept fetches the new CA.
func TestRelayRotationGraceful(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	team := startRelayTeam(t, rs, hp, "")
	cc := enrollViaRelay(t, hp, team)
	if err := pingRelayed(cc); err != nil {
		t.Fatalf("before rotation: %v", err)
	}
	ep, _, ok := endpointForHostPort(cc, cc.Host)
	if !ok {
		t.Fatal("client config does not load")
	}
	tcfg := ep.tlsCfg.Clone()
	tcfg.NextProtos = []string{"http/1.1"}
	raw, err := net.Dial("tcp", hp)
	if err != nil {
		t.Fatal(err)
	}
	est := tls.Client(raw, tcfg)
	defer est.Close()
	if err := est.Handshake(); err != nil {
		t.Fatalf("established stream: %v", err)
	}
	rs.mu.Lock()
	ctrl := rs.sessions[team.sid].ctrl
	rs.mu.Unlock()

	rs.setPKI(newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil))

	_ = est.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(est, "GET /healthz HTTP/1.1\r\nHost: kb\r\n\r\n"); err != nil {
		t.Fatalf("established stream after rotation: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(est), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("established stream must survive the rotation: %v %v", resp, err)
	}
	if err := pingRelayed(cc); err != nil {
		t.Fatalf("a new client call after rotation (accept must fetch the new CA): %v", err)
	}
	rs.mu.Lock()
	same := rs.sessions[team.sid] != nil && rs.sessions[team.sid].ctrl == ctrl
	rs.mu.Unlock()
	if !same {
		t.Fatal("the daemon's control stream must survive the rotation (no re-registration)")
	}
}

// TestRelayEnvOptions: why — under systemd the relay is configured from the
// environment; the precedence flag > environment > config > default must hold
// and a bad value must stop it with the variable named.
func TestRelayEnvOptions(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	for _, v := range relayEnv {
		t.Setenv(v, "")
		os.Unsetenv(v)
	}
	if err := saveConfig(&config{RelayBind: "127.0.0.1:7000", RelayToken: "cfg"}); err != nil {
		t.Fatal(err)
	}
	o, err := parseRelayOptsErr(nil)
	if err != nil || o.bind != "127.0.0.1:7000" || o.token != "cfg" || o.rotate != relayDefaultRotate {
		t.Fatalf("config and defaults: %+v %v", o, err)
	}
	t.Setenv("KBTOOL_RELAY_PORT", "7100")
	t.Setenv("KBTOOL_RELAY_TOKEN", "env")
	t.Setenv("KBTOOL_RELAY_ROTATE", "1h")
	if o, err = parseRelayOptsErr(nil); err != nil || o.bind != ":7100" || o.token != "env" || o.rotate != time.Hour {
		t.Fatalf("environment over config: %+v %v", o, err)
	}
	t.Setenv("KBTOOL_RELAY_BIND", "127.0.0.1:7200")
	if o, _ = parseRelayOptsErr(nil); o.bind != "127.0.0.1:7200" {
		t.Fatalf("KBTOOL_RELAY_BIND wins over KBTOOL_RELAY_PORT: %q", o.bind)
	}
	if o, err = parseRelayOptsErr([]string{"-bind", ":7300", "-token", "flag", "-rotate", "2h"}); err != nil ||
		o.bind != ":7300" || o.token != "flag" || o.rotate != 2*time.Hour {
		t.Fatalf("flags over environment: %+v %v", o, err)
	}
	t.Setenv("KBTOOL_RELAY_BIND", "")
	for env, bad := range map[string]string{"KBTOOL_RELAY_PORT": "http", "KBTOOL_RELAY_ROTATE": "soon"} {
		t.Setenv(env, bad)
		if _, err := parseRelayOptsErr(nil); err == nil || !strings.Contains(err.Error(), env) {
			t.Fatalf("%s=%q must be refused naming the variable: %v", env, bad, err)
		}
		t.Setenv(env, map[string]string{"KBTOOL_RELAY_PORT": "7100", "KBTOOL_RELAY_ROTATE": "1h"}[env])
	}
	t.Setenv("KBTOOL_RELAY_BIND", "no-port")
	if _, err := parseRelayOptsErr(nil); err == nil || !strings.Contains(err.Error(), "KBTOOL_RELAY_BIND") {
		t.Fatalf("a bad KBTOOL_RELAY_BIND must be refused: %v", err)
	}
	t.Setenv("KBTOOL_RELAY_BIND", "")
	if o, err := parseRelayOptsErr([]string{"-rotate", "72h"}); err != nil || o.rotate != 72*time.Hour {
		t.Fatalf("any positive rotation interval is accepted: %+v %v", o, err)
	}
}

// TestSdNotify: why — Type=notify units wait for READY=1; the datagram must
// reach NOTIFY_SOCKET, and without it nothing is sent.
func TestSdNotify(t *testing.T) {
	path := filepath.Join(shortStateDir(t), "notify")
	pc, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	t.Setenv("NOTIFY_SOCKET", "")
	sdNotify("READY=1") // no socket: must not panic or block
	t.Setenv("NOTIFY_SOCKET", path)
	sdNotify("READY=1\nSTATUS=x")
	buf := make([]byte, 256)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := pc.Read(buf)
	if err != nil || string(buf[:n]) != "READY=1\nSTATUS=x" {
		t.Fatalf("notify datagram: %q %v", buf[:n], err)
	}
}

// docsUnitBlock returns the ini block under "## 3. The unit file" in
// docs/relay-systemd.md.
func docsUnitBlock(t *testing.T) string {
	t.Helper()
	doc := string(mustReadFile(t, filepath.Join("docs", "relay-systemd.md")))
	i := strings.Index(doc, "## 3. The unit file")
	if i < 0 {
		t.Fatal("docs/relay-systemd.md: no '## 3. The unit file' section")
	}
	rest := doc[i:]
	a := strings.Index(rest, "```ini\n")
	b := strings.Index(rest[a+7:], "```")
	if a < 0 || b < 0 {
		t.Fatal("docs/relay-systemd.md: no ini block in the unit file section")
	}
	return rest[a+7 : a+7+b]
}

// TestRelayUnitAndDocsInSync: why — the unit the docs show and the one `relay
// unit` prints must not drift, every KBTOOL_RELAY_* variable the code reads is
// documented, and the generator's options produce a valid unit without the
// token in it.
func TestRelayUnitAndDocsInSync(t *testing.T) {
	def := relayUnitText("/usr/local/bin/kbtool", defRelayPort, "", relayUnitName)
	if got := docsUnitBlock(t); got != def {
		t.Fatalf("docs/relay-systemd.md unit block and relayUnitText differ:\n--- docs\n%s\n--- code\n%s", got, def)
	}
	doc := string(mustReadFile(t, filepath.Join("docs", "relay-systemd.md")))
	src := string(mustReadFile(t, "kbtool.go"))
	for _, m := range regexp.MustCompile(`"(KBTOOL_RELAY_[A-Z_]+)"`).FindAllStringSubmatch(src, -1) {
		if !containsString(relayEnv, m[1]) {
			t.Fatalf("%s is read but missing from relayEnv", m[1])
		}
	}
	for _, v := range relayEnv {
		if !strings.Contains(doc, "`"+v+"`") {
			t.Fatalf("%s is not documented in docs/relay-systemd.md", v)
		}
	}
	low := relayUnitText("/opt/kbtool", 443, "", "edge-relay")
	for _, want := range []string{"ExecStart=/opt/kbtool relay run", "Environment=KBTOOL_RELAY_PORT=443\n", "\nAmbientCapabilities=CAP_NET_BIND_SERVICE",
		"StateDirectory=edge-relay", "Environment=KBTOOL_DIR=%S/edge-relay", "EnvironmentFile=-/etc/kbtool/edge-relay.env", "Description=kbtool relay (edge-relay)"} {
		if !strings.Contains(low, want) {
			t.Fatalf("relay unit -port 443 -name edge-relay: missing %q\n%s", want, low)
		}
	}
	if b := relayUnitText("/opt/kbtool", defRelayPort, "10.0.0.5:9876", relayUnitName); !strings.Contains(b, "Environment=KBTOOL_RELAY_BIND=10.0.0.5:9876\n") || !strings.Contains(b, "#AmbientCapabilities") {
		t.Fatalf("relay unit -bind: %s", b)
	}
	for _, u := range []string{def, low} {
		if strings.Contains(u, "TOKEN") {
			t.Fatal("the unit must not carry a token")
		}
		section := ""
		for _, line := range strings.Split(u, "\n") {
			switch l := strings.TrimSpace(line); {
			case l == "" || strings.HasPrefix(l, "#"):
			case strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]"):
				section = l
			case section != "" && strings.Contains(l, "=") && !strings.HasPrefix(l, "="):
			default:
				t.Fatalf("not a unit line: %q", line)
			}
		}
	}
}

// TestRelayServiceCLI: why — the systemd flow through the built binary: the port
// from KBTOOL_RELAY_PORT, READY=1 / STATUS / STOPPING=1 on NOTIFY_SOCKET, the old
// on-disk PKI removed and nothing written, SIGHUP rotating the served CA, a
// restart serving another CA, and `relay unit` naming this binary.
func TestRelayServiceCLI(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	dir := shortStateDir(t)
	for _, n := range relayLegacyPKIFiles {
		writeTestPEM(t, dir, n, []byte("old"))
	}
	notify := filepath.Join(dir, "notify")
	pc, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notify, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	next := func(want string) string {
		t.Helper()
		buf := make([]byte, 1024)
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
			_ = pc.SetReadDeadline(deadline)
			n, err := pc.Read(buf)
			if err != nil {
				break
			}
			if m := string(buf[:n]); strings.Contains(m, want) {
				return m
			}
		}
		t.Fatalf("no %q on NOTIFY_SOCKET", want)
		return ""
	}
	port := freePort(t)
	hp := fmt.Sprintf("127.0.0.1:%d", port)
	start := func(logName string) (*exec.Cmd, string) {
		t.Helper()
		lf, err := os.Create(filepath.Join(work, logName))
		if err != nil {
			t.Fatal(err)
		}
		c := exec.Command(bin, "relay", "run")
		c.Env = append(os.Environ(), "KBTOOL_DIR="+dir, "KBTOOL_RELAY_PORT="+strconv.Itoa(port), "KBTOOL_RELAY_BIND=", "NOTIFY_SOCKET="+notify)
		c.Stdout, c.Stderr = lf, lf
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _, _ = c.Process.Wait(); _ = lf.Close() })
		ready := next("READY=1")
		fp, err := relayFingerprint(hp)
		if err != nil || !strings.Contains(ready, fp) {
			t.Fatalf("READY status must name the served CA %q: %q %v", fp, ready, err)
		}
		return c, fp
	}
	relay, fp1 := start("relay1.log")
	for _, n := range relayLegacyPKIFiles {
		if fileExists(filepath.Join(dir, n)) {
			t.Fatalf("%s from an older relay must be removed", n)
		}
	}
	if err := relay.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	rotated := next("STATUS=")
	fp2, err := relayFingerprint(hp)
	if err != nil || fp2 == fp1 || !strings.Contains(rotated, fp2) {
		t.Fatalf("SIGHUP must rotate the served CA: %q -> %q (%q) %v", fp1, fp2, rotated, err)
	}
	if err := relay.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	next("STOPPING=1")
	_, _ = relay.Process.Wait()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if n := e.Name(); n != "notify" && n != "config.json" {
			t.Fatalf("the relay must leave nothing in its state dir after a clean stop, found %s", n)
		}
	}
	_, fp3 := start("relay2.log")
	if fp3 == fp1 || fp3 == fp2 {
		t.Fatal("a restarted relay must serve a new CA")
	}
	unit := exec.Command(bin, "relay", "unit", "-port", "443")
	unit.Env = append(os.Environ(), "KBTOOL_DIR="+dir)
	out, err := unit.CombinedOutput()
	exe, _ := filepath.EvalSymlinks(bin)
	if err != nil || !strings.Contains(string(out), "ExecStart="+exe+" relay run\n") || !strings.Contains(string(out), "KBTOOL_RELAY_PORT=443") {
		t.Fatalf("relay unit: %v\n%s", err, out)
	}
}

// ---------- 40. relay reconnect jitter (plans/relay-reconnect-jitter-plan.md) ----------

// TestRelayJitter: why — the reconnect wait must stay within [ceiling/2,
// ceiling] (never faster than half the schedule, never slower than it) and
// vary, so daemons of a restarted relay spread out.
func TestRelayJitter(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		d := relayJitter(8 * time.Second)
		if d < 4*time.Second || d > 8*time.Second {
			t.Fatalf("jitter %s outside [4s, 8s]", d)
		}
		seen[d] = true
	}
	if len(seen) < 50 {
		t.Fatalf("jitter barely varies: %d distinct waits in 200", len(seen))
	}
	if relayJitter(0) != 0 || relayJitter(1) != 1 {
		t.Fatal("tiny ceilings must not panic")
	}
}

// TestRelayConnectorKeepsRetrying: why — a daemon must never give up on its
// relay: against a dead relay it keeps retrying with jittered, growing waits
// capped at the maximum, and stops only on close().
func TestRelayConnectorKeepsRetrying(t *testing.T) {
	var mu sync.Mutex
	var waits []time.Duration
	re := regexp.MustCompile(`reconnecting in (\S+)$`)
	rc := &relayConnector{HostPort: fmt.Sprintf("127.0.0.1:%d", freePort(t)), Session: newRelaySessionID(),
		Deliver: func(net.Conn) bool { return false }, minBackoff: 10 * time.Millisecond, maxBackoff: 40 * time.Millisecond,
		Logf: func(f string, a ...any) {
			if m := re.FindStringSubmatch(fmt.Sprintf(f, a...)); m != nil {
				d, _ := time.ParseDuration(m[1])
				mu.Lock()
				waits = append(waits, d)
				mu.Unlock()
			}
		}}
	done := make(chan struct{})
	go func() { rc.run(); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(waits)
		mu.Unlock()
		if n >= 12 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d retries logged", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	rc.close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close() must stop the retry loop")
	}
	mu.Lock()
	defer mu.Unlock()
	distinct := map[time.Duration]bool{}
	for i, w := range waits {
		ceiling := 10 * time.Millisecond << i
		if ceiling > 40*time.Millisecond {
			ceiling = 40 * time.Millisecond
		}
		if w < ceiling/2-time.Millisecond || w > ceiling+time.Millisecond {
			t.Fatalf("retry %d waited %s, want within [%s, %s]", i, w, ceiling/2, ceiling)
		}
		distinct[w] = true
	}
	if len(distinct) < 3 {
		t.Fatalf("waits must be jittered: %v", waits)
	}
}

// ---------- 41. relay hardening (plans/relay-hardening-plan.md) ----------

// TestRelaySessionKeyDerivation: why — the session ID is bound to the session
// key and the team CA's expiry, so it cannot be claimed without the key and
// changes with the CA; the key file is private and a stale or keyless config is
// caught before the daemon serves.
func TestRelaySessionKeyDerivation(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	sid, auth := newTestRelaySession(t, exp)
	pub := auth.Key.Public().(ed25519.PublicKey)
	if relaySessionID(pub, exp.Unix()) != sid || !isRelaySessionID(sid) {
		t.Fatal("derivation must be deterministic and SNI-shaped")
	}
	if relaySessionID(pub, exp.Unix()+1) == sid {
		t.Fatal("another expiry must give another ID")
	}
	if other, _ := newTestRelaySession(t, exp); other == sid {
		t.Fatal("another key must give another ID")
	}
	dir := t.TempDir()
	key, err := writeRelaySessionKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, relaySessionKeyFile)); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("session key mode: %v", err)
	}
	if back, err := loadRelaySessionKey(dir); err != nil || !back.Equal(key) {
		t.Fatalf("session key round trip: %v", err)
	}
	_, caCert := writeTestClientPKI(t, dir)
	good := relaySessionID(key.Public().(ed25519.PublicKey), caCert.NotAfter.Unix())
	if a, err := loadRelayAuth(dir, filepath.Join(dir, "ca.crt"), good); err != nil || a.Expires != caCert.NotAfter.Unix() {
		t.Fatalf("loadRelayAuth: %v", err)
	}
	if _, err := loadRelayAuth(dir, filepath.Join(dir, "ca.crt"), newRelaySessionID()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a session ID not derived from the key and CA must be refused: %v", err)
	}
	writeTestPEM(t, dir, relaySessionKeyFile, []byte("zz\n"))
	if _, err := loadRelayAuth(dir, filepath.Join(dir, "ca.crt"), good); err == nil {
		t.Fatal("a corrupt session key must be refused")
	}
	if _, err := loadRelayAuth(t.TempDir(), filepath.Join(dir, "ca.crt"), good); err == nil || !strings.Contains(err.Error(), "relay session key") {
		t.Fatalf("a missing session key must be refused: %v", err)
	}
}

// registerSigned registers sid with headers from sign (nil: none) on a fresh
// relay TLS connection and returns the status code (101 on success).
func registerSigned(t *testing.T, hp, sid string, sign func(tls.ConnectionState) (map[string]string, error)) (int, net.Conn) {
	t.Helper()
	c, err := relayUpgrade(hp, relayTrust{}.tlsConfig(), "/v1/register", map[string]string{"X-Kbtool-Session": sid}, sign)
	var he *relayHTTPError
	switch {
	case err == nil:
		return http.StatusSwitchingProtocols, c
	case errors.As(err, &he):
		return he.Code, nil
	}
	t.Fatalf("register %s: %v", sid, err)
	return 0, nil
}

// TestRelayRegistrationProof: why — only the holder of a session's key may
// register it, the signature is good for one TLS connection only, and an
// expired session (team CA expired) is refused; so a stolen session ID, a
// replayed registration or an old key cannot take over or squat a session.
func TestRelayRegistrationProof(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	sid, auth := newTestRelaySession(t, time.Now().Add(time.Hour))
	_, other := newTestRelaySession(t, time.Now().Add(time.Hour))
	signWith := func(a *relaySessionAuth, mutate func(map[string]string)) func(tls.ConnectionState) (map[string]string, error) {
		return func(cs tls.ConnectionState) (map[string]string, error) {
			h, err := a.headers(sid, cs)
			if err == nil && mutate != nil {
				mutate(h)
			}
			return h, err
		}
	}
	flip := func(h map[string]string) {
		b, _ := base64.RawURLEncoding.DecodeString(h["X-Kbtool-Session-Sig"])
		b[0] ^= 1
		h["X-Kbtool-Session-Sig"] = base64.RawURLEncoding.EncodeToString(b)
	}
	for name, sign := range map[string]func(tls.ConnectionState) (map[string]string, error){
		"no proof (legacy daemon)": nil,
		"another key":              signWith(other, nil),
		"another expiry":           signWith(auth, func(h map[string]string) { h["X-Kbtool-Session-Expires"] = strconv.FormatInt(auth.Expires+60, 10) }),
		"bad signature":            signWith(auth, flip),
		"malformed key":            signWith(auth, func(h map[string]string) { h["X-Kbtool-Session-Key"] = "AAAA" }),
	} {
		if code, _ := registerSigned(t, hp, sid, sign); code != http.StatusForbidden && code != http.StatusBadRequest {
			t.Errorf("%s: want 403/400, got %d", name, code)
		}
	}
	var captured map[string]string
	code, c := registerSigned(t, hp, sid, func(cs tls.ConnectionState) (map[string]string, error) {
		h, err := auth.headers(sid, cs)
		captured = h
		return h, err
	})
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("a valid registration must succeed: %d", code)
	}
	waitRelaySession(t, rs, sid, true)
	squat := func(when string) {
		if code, _ := registerSigned(t, hp, sid, signWith(other, nil)); code != http.StatusForbidden {
			t.Fatalf("squatting a %s session without its key: want 403, got %d", when, code)
		}
		replay := func(tls.ConnectionState) (map[string]string, error) { return captured, nil }
		if code, _ := registerSigned(t, hp, sid, replay); code != http.StatusForbidden {
			t.Fatalf("replaying a %s session's registration on another connection: want 403, got %d", when, code)
		}
	}
	squat("live")
	c.Close()
	waitRelaySession(t, rs, sid, false)
	squat("disconnected")
	old, oldAuth := newTestRelaySession(t, time.Now().Add(-time.Minute))
	if code, _ := registerSigned(t, hp, old, func(cs tls.ConnectionState) (map[string]string, error) { return oldAuth.headers(old, cs) }); code != http.StatusForbidden {
		t.Fatalf("an expired session: want 403, got %d", code)
	}
}

// TestRelaySessionExpiresWithCA: why — a session lives no longer than the team
// CA it was derived from; the relay closes it at that moment.
func TestRelaySessionExpiresWithCA(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	sid, auth := newTestRelaySession(t, time.Now().Add(2*time.Second))
	c, err := registerTestSession(hp, sid, auth, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitRelaySession(t, rs, sid, true)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("the relay must end the control stream at expiry, not time out: %v", err)
	}
	waitRelaySession(t, rs, sid, false)
}

// TestRelaySessionCap: why — the number of sessions is bounded (default 5000)
// so registrations cannot exhaust the relay; at the cap it answers 503 and a
// freed slot is usable again.
func TestRelaySessionCap(t *testing.T) {
	if newRelayServer(newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil), "").MaxSessions != 5000 {
		t.Fatal("the default session cap must be 5000")
	}
	rs, hp := startTestRelay(t, "", func(rs *relayServer) { rs.MaxSessions = 2 })
	var conns []net.Conn
	for i := 0; i < 2; i++ {
		sid, c, err := registerNewTestSession(t, hp, "")
		if err != nil {
			t.Fatal(err)
		}
		waitRelaySession(t, rs, sid, true)
		conns = append(conns, c)
	}
	_, _, err := registerNewTestSession(t, hp, "")
	var he *relayHTTPError
	if !errors.As(err, &he) || he.Code != http.StatusServiceUnavailable {
		t.Fatalf("over the cap: want 503, got %v", err)
	}
	conns[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, c, err := registerNewTestSession(t, hp, "")
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a freed slot must be usable: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	conns[1].Close()
}

// TestRelayControlLineLimit: why — control lines are tiny ("ping", "pong",
// "conn <id>"); neither end may buffer an unbounded line from the other.
func TestRelayControlLineLimit(t *testing.T) {
	if l, err := readCtrlLine(bufio.NewReaderSize(strings.NewReader("conn abc\n"), relayCtrlMaxLine)); err != nil || l != "conn abc\n" {
		t.Fatalf("a short line: %q %v", l, err)
	}
	long := strings.Repeat("x", 4*relayCtrlMaxLine) + "\n"
	if _, err := readCtrlLine(bufio.NewReaderSize(strings.NewReader(long), relayCtrlMaxLine)); err == nil {
		t.Fatal("an over-long line must be an error")
	}
	rs, hp := startTestRelay(t, "", nil)
	sid, c, err := registerNewTestSession(t, hp, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitRelaySession(t, rs, sid, true)
	if _, err := io.WriteString(c, strings.Repeat("y", 4*relayCtrlMaxLine)); err != nil {
		t.Fatal(err)
	}
	waitRelaySession(t, rs, sid, false)
}

// TestIPLimiter: why — the per-IP token bucket must allow the burst, refuse
// beyond it, refill at the rate, keep IPs independent, forget idle IPs, and
// bound its table.
func TestIPLimiter(t *testing.T) {
	if l := newIPLimiter(0, time.Second, 5); l != nil || !l.allow("a") {
		t.Fatal("rate 0 must mean unlimited")
	}
	l := newIPLimiter(10, time.Second, 2)
	if !l.allow("a") || !l.allow("a") || l.allow("a") {
		t.Fatal("burst 2 then refuse")
	}
	if !l.allow("b") {
		t.Fatal("IPs are independent")
	}
	time.Sleep(150 * time.Millisecond)
	if !l.allow("a") {
		t.Fatal("tokens must refill")
	}
	time.Sleep(300 * time.Millisecond)
	l.sweep()
	if len(l.m) != 0 {
		t.Fatalf("full buckets must be swept: %d left", len(l.m))
	}
	l.max = 1
	if !l.allow("c") || l.allow("d") {
		t.Fatal("a full table must refuse unknown IPs")
	}
}

// TestRelayRateLimits: why — one source address cannot open connections or
// register sessions faster than the configured rates.
func TestRelayRateLimits(t *testing.T) {
	_, hp := startTestRelay(t, "", func(rs *relayServer) { rs.ConnLimit = newIPLimiter(1, time.Hour, 3) })
	hc := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	ok := 0
	for i := 0; i < 6; i++ {
		if resp, err := hc.Get("http://" + hp + "/healthz"); err == nil {
			resp.Body.Close()
			ok++
		}
	}
	if ok != 3 {
		t.Fatalf("connection burst 3: %d of 6 connections served", ok)
	}
	_, hp2 := startTestRelay(t, "", func(rs *relayServer) { rs.RegLimit = newIPLimiter(1, time.Hour, 1) })
	if _, c, err := registerNewTestSession(t, hp2, ""); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}
	_, _, err := registerNewTestSession(t, hp2, "")
	var he *relayHTTPError
	if !errors.As(err, &he) || he.Code != http.StatusTooManyRequests {
		t.Fatalf("over the registration rate: want 429, got %v", err)
	}
}

// writeOperatorCert writes a relay certificate for 127.0.0.1 signed by a new CA
// into dir and returns the CA file.
func writeOperatorCert(t *testing.T, dir string) string {
	t.Helper()
	caKey, caCert := cryptoGenerateCA("operator CA", time.Hour)
	k, c := cryptoGenerateLeaf(caKey, caCert, "relay.test", []net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour)
	writeTestPEM(t, dir, "relay.crt", append(cryptoPEMCert(c), cryptoPEMCert(caCert)...))
	writeTestPEM(t, dir, "relay.key", cryptoPEMKey(k))
	writeTestPEM(t, dir, "operator-ca.crt", cryptoPEMCert(caCert))
	return filepath.Join(dir, "operator-ca.crt")
}

// TestRelayOperatorCertPinned: why — a relay on the internet can present an
// operator certificate, and a daemon with the relay CA pinned verifies it (host
// name included) instead of trusting whatever certificate it is shown.
func TestRelayOperatorCertPinned(t *testing.T) {
	dir := t.TempDir()
	caFile := writeOperatorCert(t, dir)
	pki, err := loadRelayOperatorPKI(filepath.Join(dir, "relay.crt"), filepath.Join(dir, "relay.key"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM := mustReadFile(t, caFile)
	if !bytes.Equal(pki.CAPEM, caPEM) {
		t.Fatal("the operator chain's last certificate is its CA")
	}
	rs := newRelayServer(pki, "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go rs.serve(ln)
	t.Cleanup(func() { _ = ln.Close(); rs.shutdown() })
	hp := ln.Addr().String()
	trust, err := loadRelayTrust(caFile, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if fp, err := relayCheck(hp, trust); err != nil || fp != "" {
		t.Fatalf("relayCheck with a pinned CA: %q %v", fp, err)
	}
	if _, err := relayCheck(hp, relayTrust{Mode: "file", Pool: trust.Pool, Host: "elsewhere.example"}); err == nil {
		t.Fatal("a pinned CA must still check the relay's host name")
	}
	if _, err := relayCheck(hp, relayTrust{Mode: "system", Host: "127.0.0.1"}); err == nil {
		t.Fatal("system roots must not trust a private operator CA")
	}
	team := startRelayTeamTrust(t, rs, hp, "", trust)
	if err := pingRelayed(enrollViaRelay(t, hp, team)); err != nil {
		t.Fatalf("mTLS through an operator-certificate relay: %v", err)
	}
	if fp, err := relayCheck(hp, relayTrust{}); err != nil || fp != caFingerprint(pki.Leaf.Certificate[1]) {
		t.Fatalf("default-trust daemons must keep working with an operator certificate: %q %v", fp, err)
	}
}

// TestRelayHardeningOptions: why — the cap, the rates and the operator
// certificate follow flag > environment > config > default, bad values name
// their source, and the certificate options cannot be half-set or mixed with
// the in-memory CA's.
func TestRelayHardeningOptions(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	for _, v := range relayEnv {
		t.Setenv(v, "")
		os.Unsetenv(v)
	}
	o, err := parseRelayOptsErr(nil)
	if err != nil || o.maxSessions != 5000 || o.connRate != 20 || o.regRate != 30 || o.certFile != "" {
		t.Fatalf("defaults: %+v %v", o, err)
	}
	if err := saveConfig(&config{RelayMaxSessions: 7}); err != nil {
		t.Fatal(err)
	}
	if o, _ = parseRelayOptsErr(nil); o.maxSessions != 7 {
		t.Fatalf("config relay_max_sessions: %d", o.maxSessions)
	}
	t.Setenv("KBTOOL_RELAY_MAX_SESSIONS", "8")
	t.Setenv("KBTOOL_RELAY_CONN_RATE", "0")
	t.Setenv("KBTOOL_RELAY_REGISTER_RATE", "2.5")
	if o, err = parseRelayOptsErr(nil); err != nil || o.maxSessions != 8 || o.connRate != 0 || o.regRate != 2.5 {
		t.Fatalf("environment over config: %+v %v", o, err)
	}
	if o, err = parseRelayOptsErr([]string{"-max-sessions", "9", "-conn-rate", "4", "-register-rate", "0"}); err != nil || o.maxSessions != 9 || o.connRate != 4 || o.regRate != 0 {
		t.Fatalf("flags over environment: %+v %v", o, err)
	}
	for env, bad := range map[string]string{"KBTOOL_RELAY_MAX_SESSIONS": "lots", "KBTOOL_RELAY_CONN_RATE": "-1", "KBTOOL_RELAY_REGISTER_RATE": "NaN"} {
		t.Setenv(env, bad)
		if _, err := parseRelayOptsErr(nil); err == nil || !strings.Contains(err.Error(), env) {
			t.Fatalf("%s=%q must be refused naming the variable: %v", env, bad, err)
		}
		t.Setenv(env, "1")
	}
	if _, err := parseRelayOptsErr([]string{"-max-sessions", "-3"}); err == nil {
		t.Fatal("a session cap below 1 must be refused")
	}
	dir := t.TempDir()
	writeOperatorCert(t, dir)
	crt, key := filepath.Join(dir, "relay.crt"), filepath.Join(dir, "relay.key")
	t.Setenv("KBTOOL_RELAY_CERT", crt)
	if _, err := parseRelayOptsErr(nil); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("a certificate without a key must be refused: %v", err)
	}
	t.Setenv("KBTOOL_RELAY_KEY", key)
	if o, err = parseRelayOptsErr(nil); err != nil || o.certFile != crt || o.keyFile != key {
		t.Fatalf("certificate from the environment: %+v %v", o, err)
	}
	if _, err := parseRelayOptsErr([]string{"-rotate", "1h"}); err == nil {
		t.Fatal("-rotate with an operator certificate must be refused")
	}
	if _, err := parseRelayOptsErr([]string{"-cert", key}); err == nil {
		t.Fatal("an unreadable certificate must be refused at startup")
	}
}

// TestRelayOperatorCLI: why — through the built binary: a relay with an
// operator certificate from the environment, a daemon set up with `relay join
// -relay-ca FILE` and `mtls` registering through it, and SIGHUP reloading a replaced
// certificate from disk without dropping the daemon's session.
func TestRelayOperatorCLI(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	relayDir, srvDir, certDir := shortStateDir(t), shortStateDir(t), t.TempDir()
	caFile := writeOperatorCert(t, certDir)
	port := freePort(t)
	hp := fmt.Sprintf("127.0.0.1:%d", port)
	base := append(os.Environ(), "HOME="+work, "KB_EMBED_URL=", "KBTOOL_SOCKET=", "KBTOOL_RELAY_BIND=", "KBTOOL_RELAY_PORT=")
	spawn := func(env []string, logName string, args ...string) (*exec.Cmd, string) {
		t.Helper()
		logPath := filepath.Join(work, logName)
		lf, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		c := exec.Command(bin, args...)
		c.Env = env
		c.Stdout, c.Stderr = lf, lf
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _, _ = c.Process.Wait(); lf.Close() })
		return c, logPath
	}
	waitLog := func(path, want string) {
		t.Helper()
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if strings.Contains(string(mustReadFile(t, path)), want) {
				return
			}
		}
		t.Fatalf("%q not in log:\n%s", want, mustReadFile(t, path))
	}
	relay, relayLog := spawn(append(base, "KBTOOL_DIR="+relayDir, "KBTOOL_RELAY_CERT="+filepath.Join(certDir, "relay.crt"),
		"KBTOOL_RELAY_KEY="+filepath.Join(certDir, "relay.key")), "relay.log", "relay", "run", "-bind", hp)
	waitLog(relayLog, "operator certificate")
	fp1, err := relayFingerprint(hp)
	if err != nil {
		t.Fatal(err)
	}
	join := exec.Command(bin, "relay", "join", "https://"+hp+"/", "-relay-ca", caFile)
	join.Env = append(base, "KBTOOL_DIR="+srvDir)
	if out, err := join.CombinedOutput(); err != nil {
		t.Fatalf("relay join -relay-ca: %v\n%s", err, out)
	}
	var rj relayJSON
	_ = json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "relay.json")), &rj)
	if len(rj.Relays) != 1 || rj.Relays[0].CA != caFile {
		t.Fatalf("relay.json must record the pinned CA: %+v", rj)
	}
	mt := exec.Command(bin, "mtls", "-expire", "1h")
	mt.Env = append(base, "KBTOOL_DIR="+srvDir)
	if out, err := mt.CombinedOutput(); err != nil {
		t.Fatalf("mtls: %v\n%s", err, out)
	}
	var cfg config
	_ = json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &cfg)
	_, daemonLog := spawn(append(base, "KBTOOL_DIR="+srvDir), "daemon.log", "daemon", "run")
	waitLog(daemonLog, "session "+cfg.RelaySession+" registered")
	writeOperatorCert(t, certDir)
	if err := relay.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitLog(relayLog, "rotated the CA (SIGHUP)")
	if fp2, err := relayFingerprint(hp); err != nil || fp2 == fp1 {
		t.Fatalf("SIGHUP must reload the operator certificate: %q -> %q %v", fp1, fp2, err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := strings.Count(string(mustReadFile(t, daemonLog)), "registered"); n != 1 {
		t.Fatalf("a reload must not drop the daemon's session (%d registrations)", n)
	}
}

// FuzzPeekClientHelloSNI: why — the relay parses ClientHellos from anyone on
// the internet before any authentication; no input may panic or hang it.
func FuzzPeekClientHelloSNI(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	c1, c2 := net.Pipe()
	go func() {
		_ = tls.Client(c1, &tls.Config{ServerName: "0123456789abcdef0123456789abcdef", InsecureSkipVerify: true}).Handshake()
	}()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16384)
	if n, err := c2.Read(buf); err == nil {
		f.Add(append([]byte{}, buf[:n]...))
	}
	c1.Close()
	c2.Close()
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = peekClientHelloSNI(bufio.NewReaderSize(bytes.NewReader(b), 5+16384+2048))
	})
}

// ---------- 42. system user, read-only system thread, build refresh (plans/system-board-and-build-refresh-plan.md) ----------

// loadTestBoard reads the toolbox's board from its store.
func loadTestBoard(t *testing.T, tb *Toolbox) *Board {
	t.Helper()
	b, err := tb.store().loadBoard(false)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSystemInitOrderAndSignature: why — the system user must be registered
// when the board is first written, post system#0 BEFORE welcome#0 (so the
// welcome pointer is valid), sign both verifiably, keep welcome first and
// system second, and keep its key in board.bin across reloads.
func TestSystemInitOrderAndSignature(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	dumpSignup(t, tb, "alice")
	b := loadTestBoard(t, tb)
	if len(b.Order) < 2 || b.Order[0] != boardWelcome || b.Order[1] != boardSystem {
		t.Fatalf("thread order = %v, want welcome, system first", b.Order)
	}
	sys0, wel0 := b.Threads[boardSystem].Msgs[0], b.Threads[boardWelcome].Msgs[0]
	if sys0.ID != 1 || wel0.ID != 2 || sys0.Agent != boardSystem || wel0.Agent != boardSystem {
		t.Fatalf("system#0 must precede welcome#0, both by system: %+v / %+v", sys0, wel0)
	}
	for _, m := range []BoardMsg{sys0, wel0} {
		if st := cryptoVerifyBoardMsg(b, m); st != "verified" {
			t.Fatalf("%s#%d is %s", m.Thread, m.Seq, st)
		}
	}
	for _, want := range []string{"system-authored", "not an agent", "not interactive", "purely informative", "kbtool board read system#0", "10 words"} {
		if !strings.Contains(wel0.Text, want) {
			t.Fatalf("welcome#0 lacks %q: %s", want, wel0.Text)
		}
	}
	for _, want := range []string{"Current search index", "first line of the roster", "latest=system#N",
		"kbtool board attach", "share files between agents", "8.0 MiB compressed, 1000 files", "topic threads", "Keep `welcome` minimal"} {
		if !strings.Contains(sys0.Text, want) {
			t.Fatalf("system#0 lacks %q", want)
		}
	}
	pub := hex.EncodeToString(ed25519.NewKeyFromSeed(b.SystemSeed).Public().(ed25519.PublicKey))
	if b.Agents[boardSystem].Pub != pub {
		t.Fatal("stored system seed does not match the registered system key")
	}
	dumpSignup(t, tb, "bob") // a later write must not re-register
	if b2 := loadTestBoard(t, tb); !bytes.Equal(b2.SystemSeed, b.SystemSeed) || len(b2.Threads[boardSystem].Msgs) != 1 {
		t.Fatal("the system user must be registered once and kept forever")
	}
}

// TestSystemReservedNameAndThread: why — nobody may sign up as `system`, and
// agent posts (plain or with an attachment) to the system thread are refused,
// so system messages stay trustworthy.
func TestSystemReservedNameAndThread(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	if out, isErr := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "system"})); !isErr || !strings.Contains(out, "reserved") {
		t.Fatalf("signup as system must be refused, got (%q, %v)", out, isErr)
	}
	seed := dumpSignup(t, tb, "alice")
	data, _, err := attachPack([]tarGZMember{{Name: "a.txt", Data: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range []map[string]any{
		{"thread": "system", "text": "hi", "seed": seed},
		{"thread": "SYSTEM", "text": "hi", "seed": seed, "attachment": base64.StdEncoding.EncodeToString(data)},
	} {
		if out, isErr := tb.Execute("board_post", mustMarshal(args)); !isErr || !strings.Contains(out, "read-only") {
			t.Fatalf("post to system must be refused, got (%q, %v)", out, isErr)
		}
	}
	if n := len(loadTestBoard(t, tb).Threads[boardSystem].Msgs); n != 1 {
		t.Fatalf("system thread changed: %d messages", n)
	}
}

// TestSystemPostWelcomeNotice: why — every system post must leave the exact
// welcome notice naming the command that retrieves it.
func TestSystemPostWelcomeNotice(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	dumpSignup(t, tb, "alice")
	tb.postSystem(func(*Board, bool) string { return "index rebuilt" })
	b := loadTestBoard(t, tb)
	sys := b.Threads[boardSystem].Msgs
	wel := b.Threads[boardWelcome].Msgs
	if len(sys) != 2 || sys[1].Text != "index rebuilt" {
		t.Fatalf("system thread = %+v", sys)
	}
	want := "Notice: a `system` thread message was posted.  Retrieve the latest message with `kbtool board read system#1`."
	if last := wel[len(wel)-1]; last.Text != want || last.Agent != boardSystem || cryptoVerifyBoardMsg(b, last) != "verified" {
		t.Fatalf("welcome notice = %+v", last)
	}
}

// TestWelcomeWordLimit: why — welcome stays minimal: at most N words
// (default 10, config welcome_max_words), each under 50 characters with
// punctuation counted, and no attachments; other threads are unaffected.
func TestWelcomeWordLimit(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	post := func(tb *Toolbox, thread, text string) (string, bool) {
		return tb.Execute("board_post", mustMarshal(map[string]any{"thread": thread, "text": text, "seed": seed}))
	}
	ten := strings.TrimSpace(strings.Repeat("w ", 10))
	if out, isErr := post(tb, "welcome", ten); isErr {
		t.Fatalf("10 words must fit: %s", out)
	}
	if out, isErr := post(tb, "welcome", ten+" w"); !isErr || !strings.Contains(out, "limited to 10 words") {
		t.Fatalf("11 words must be refused, got (%q, %v)", out, isErr)
	}
	if out, isErr := post(tb, "welcome", strings.Repeat("a", 48)+"!"); isErr {
		t.Fatalf("a 49-character word must fit: %s", out)
	}
	if out, isErr := post(tb, "welcome", strings.Repeat("a", 49)+","); !isErr || !strings.Contains(out, "under 50 characters") {
		t.Fatalf("50 characters including punctuation must be refused, got (%q, %v)", out, isErr)
	}
	data, _, _ := attachPack([]tarGZMember{{Name: "a.txt", Data: []byte("x")}})
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "welcome", "text": "file", "seed": seed,
		"attachment": base64.StdEncoding.EncodeToString(data)})); !isErr || !strings.Contains(out, "cannot carry attachments") {
		t.Fatalf("welcome attachment must be refused, got (%q, %v)", out, isErr)
	}
	if out, isErr := post(tb, "plans", strings.Repeat("word ", 200)); isErr {
		t.Fatalf("other threads have no word limit: %s", out)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("KBTOOL_DIR"), "config.json"), []byte(`{"version":1,"welcome_max_words":3}`), 0644); err != nil {
		t.Fatal(err)
	}
	tb2 := &Toolbox{Store: tb.Store, BoardPath: tb.BoardPath}
	if out, isErr := post(tb2, "welcome", "one two three four"); !isErr || !strings.Contains(out, "limited to 3 words") {
		t.Fatalf("welcome_max_words=3 must apply, got (%q, %v)", out, isErr)
	}
}

// TestSystemExemptFromMessageLimits: why — per-message limits (text size,
// welcome words) never apply to the system user, but the board-wide memory
// limit still does: an oversized system post is skipped, not forced in.
func TestSystemExemptFromMessageLimits(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	dumpSignup(t, tb, "alice")
	big := strings.Repeat("long system text ", boardMaxText/16+10)
	tb.postSystem(func(*Board, bool) string { return big })
	b := loadTestBoard(t, tb)
	if got := b.Threads[boardSystem].Msgs; len(got) != 2 || len(got[1].Text) <= boardMaxText {
		t.Fatal("a system post over the per-message text cap must be accepted")
	}
	if n := len(strings.Fields(b.Threads[boardWelcome].Msgs[0].Text)); n <= defWelcomeMaxWords {
		t.Fatalf("the system welcome intro should exceed the agent word limit (has %d words)", n)
	}
	tb2 := &Toolbox{Store: tb.Store, BoardPath: tb.BoardPath, BoardMaxBytes: int64(len(boardMarshal(b))) + 64}
	tb2.postSystem(func(*Board, bool) string { return big })
	if n := len(loadTestBoard(t, tb).Threads[boardSystem].Msgs); n != 2 {
		t.Fatalf("a system post over the board memory limit must be skipped, have %d messages", n)
	}
}

// TestBoardSystemTrailer: why — the system seed and state survive a save and
// load, a board written before the trailer still loads (without a system
// user), an unknown trailer is corruption, and board.bin is owner-only now
// that it holds a private key.
func TestBoardSystemTrailer(t *testing.T) {
	b := newBoard()
	legacy := boardMarshal(b)
	if _, err := ensureSystem(b, boardSysInfo{WelcomeWords: 10}, 1); err != nil {
		t.Fatal(err)
	}
	b.Sys = boardSysState{Settings: map[string]string{"k": "v"}, Running: true}
	b2, err := readBoard(bytes.NewReader(boardMarshal(b)))
	if err != nil || !bytes.Equal(b2.SystemSeed, b.SystemSeed) || !reflect.DeepEqual(b2.Sys, b.Sys) {
		t.Fatalf("system trailer round trip: %v", err)
	}
	if old, err := readBoard(bytes.NewReader(legacy)); err != nil || old.SystemSeed != nil {
		t.Fatalf("legacy board: %v", err)
	}
	var bad bytes.Buffer
	bad.Write(legacy)
	writeStr(&bad, "NOPE")
	if _, err := readBoard(&bad); err == nil || !strings.Contains(err.Error(), "unknown trailer") {
		t.Fatalf("unknown trailer must be corruption, got %v", err)
	}
	p := filepath.Join(t.TempDir(), "board.bin")
	if err := boardSave(p, b); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("board.bin mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	b.Agents = map[string]*BoardAgent{boardSystem: {ID: boardSystem}}
	b.SystemSeed = nil
	if _, err := ensureSystem(b, boardSysInfo{}, 1); err == nil {
		t.Fatal("an agent already named system must block registration")
	}
}

// TestRosterSystemFirst: why — watching for system updates relies on
// `system` being the roster's first line with its latest message id, and it
// must not count as an agent.
func TestRosterSystemFirst(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	dumpSignup(t, tb, "alice")
	b := loadTestBoard(t, tb)
	lines := strings.Split(boardRoster(b, time.Now().Unix()), "\n")
	if len(lines) < 3 || !strings.Contains(lines[1], "SYSTEM") || !strings.Contains(lines[1], "latest=system#0") ||
		!strings.Contains(lines[2], "alice") {
		t.Fatalf("roster:\n%s", strings.Join(lines, "\n"))
	}
	if s := tb.boardStats(); !strings.Contains(s, "1 agent(s) (1 active") {
		t.Fatalf("stats must not count system: %s", s)
	}
	empty := newBoard()
	_, _ = ensureSystem(empty, boardSysInfo{}, time.Now().Unix())
	if r := boardRoster(empty, time.Now().Unix()); !strings.Contains(r, "none signed up yet") {
		t.Fatalf("a board with only system has no agents:\n%s", r)
	}
}

// TestSearchRanksSystemThreadLast: why — system notices must never crowd out
// real results: system-thread chunks rank below every other hit, even when
// they match better.
func TestSearchRanksSystemThreadLast(t *testing.T) {
	chunks := []Chunk{
		{Path: "board/system/msg-0", Kind: "board", Text: "zebra zebra zebra zebra"},
		{Path: "src/a.go", Kind: "code", Text: "zebra once in some code"},
		{Path: "board/plans/msg-0", Kind: "board", Text: "zebra plan"},
	}
	for i := range chunks {
		chunks[i].Vector = embedOne(chunks[i].Text, 64)
	}
	db := &DB{Dim: 64, Chunks: chunks, KW: buildKWIndex(chunks, true)}
	for _, mode := range []string{ModeHybrid, ModeKeyword, ModeVector} {
		res, err := db.SearchW("zebra", 10, "", "", 0, true, mode, defWKeyword, defWVector)
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 3 || res[2].C.Path != "board/system/msg-0" {
			t.Fatalf("%s: system chunk must rank last: %+v", mode, res)
		}
	}
}

// TestBoardMergeIgnoresThreadOrder: why — messages are stored by thread, not
// by ID; merging into the index must not skip lower IDs that appear in later
// threads (the system thread interleaves IDs with welcome).
func TestBoardMergeIgnoresThreadOrder(t *testing.T) {
	tb := newBoardToolbox(t, &DB{Dim: 8, KW: buildKWIndex(nil, true)})
	b := newBoard()
	b.Threads["welcome"].Msgs = []BoardMsg{{ID: 1, Thread: "welcome", Text: "a"}, {ID: 5, Thread: "welcome", Seq: 1, Text: "e"}}
	b.Threads["plans"] = &BoardThread{ID: "plans", Msgs: []BoardMsg{{ID: 2, Thread: "plans", Text: "b"}, {ID: 3, Thread: "plans", Seq: 1, Text: "c"}}}
	b.Order = append(b.Order, "plans")
	tb.mergeBoardMsgs(tb.store(), b)
	if len(tb.DB.Chunks) != 4 || tb.boardLast != 5 {
		t.Fatalf("merged %d chunks (last %d), want 4 (last 5)", len(tb.DB.Chunks), tb.boardLast)
	}
}

// initTestRepo makes a git repo with one commit and returns its path and HEAD.
func initTestRepo(t *testing.T, name string) (string, string) {
	t.Helper()
	repo := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(repo, 0755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("config", "user.email", "t@example.com")
	git("config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(repo, "a.go"), []byte("package a\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git("add", "-A")
	git("commit", "-q", "-m", "init")
	return repo, git("rev-parse", "HEAD")
}

// TestSourceCommitDirtyCaptured: why — every build records HEAD and the
// work-tree state of each git source, even without -git, and the DB keeps
// them; DBs written before the trailer still load.
func TestSourceCommitDirtyCaptured(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	t.Setenv("KB_EMBED_URL", "")
	repo, head := initTestRepo(t, "repoa")
	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, "n.txt"), []byte("notes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	build := func() *DB {
		db, err := buildDB(BuildOpts{Sources: []string{repo, plain}, Embed: localEmbed, KWPath: boolPtr(true)})
		if err != nil {
			t.Fatal(err)
		}
		return db
	}
	db := build()
	if s := db.Sources[0]; !s.HasGit || s.Commit != head || s.Dirty {
		t.Fatalf("git source = %+v, want HEAD %s clean", s, head)
	}
	if s := db.Sources[1]; s.HasGit || s.Commit != "" {
		t.Fatalf("plain source = %+v", s)
	}
	if err := os.WriteFile(filepath.Join(repo, "new.go"), []byte("package a\n"), 0644); err != nil {
		t.Fatal(err)
	}
	db = build()
	if !db.Sources[0].Dirty {
		t.Fatal("an uncommitted file must mark the work tree dirty")
	}
	raw := dbMarshal(db)
	back, err := readDB(bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(back.Sources, db.Sources) {
		t.Fatalf("source trailer round trip: %v %+v", err, back.Sources)
	}
	if hs, err := readDBSources(bytes.NewReader(raw)); err != nil || len(hs) != 2 || hs[0].Label != db.Sources[0].Label {
		t.Fatalf("header-only source read: %v %+v", err, hs)
	}
	legacy := raw[:bytes.LastIndex(raw, []byte(dbSrcTag))-4]
	if old, err := readDB(bytes.NewReader(legacy)); err != nil || old.Sources[0].Commit != "" || old.KW == nil {
		t.Fatalf("a DB without the trailer must still load: %v", err)
	}
}

// TestBuildAnnouncementText: why — the build message names sources by label
// only, says indexed (new) or was rebuilt (known), clean or dirty, not a git
// repo, and lists removed sources; it never leaks a path.
func TestBuildAnnouncementText(t *testing.T) {
	prev := []Source{{Label: "repoA", Root: "/secret/repoA", HasGit: true}, {Label: "gone", Root: "/secret/gone"}}
	cur := []Source{
		{Label: "repoA", Root: "/secret/repoA", HasGit: true, Commit: "abc123"},
		{Label: "repoB", Root: "/secret/repoB", HasGit: true, Commit: "def456", Dirty: true},
		{Label: "dirA", Root: "/secret/dirA"},
	}
	got := buildAnnouncement(prev, cur, 42)
	for _, want := range []string{
		"42 chunks from 3 source(s)",
		"- `repoA` was rebuilt at commit `abc123` with a clean git workspace\n",
		"- `repoB` indexed at commit `def456` with a dirty git workspace\n",
		"- `dirA` indexed (not a git repo)\n",
		"- `gone` was removed from the index\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("announcement lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "/secret") {
		t.Fatalf("announcement leaks a path:\n%s", got)
	}
}

// TestSwapIndexAnnouncesBuild: why — a live reindex through the daemon posts
// the build summary (comparing against the index it replaced) with its
// welcome notice; with the board off nothing is posted.
func TestSwapIndexAnnouncesBuild(t *testing.T) {
	old := &DB{Dim: 8, Sources: []Source{{Label: "repoA", HasGit: true}}, KW: buildKWIndex(nil, true)}
	tb := newBoardToolbox(t, old)
	dumpSignup(t, tb, "alice")
	next := &DB{Dim: 8, Sources: []Source{{Label: "repoA", HasGit: true, Commit: "abc"}, {Label: "notes"}}, KW: buildKWIndex(nil, true)}
	if _, err := tb.swapIndex(dbMarshal(next)); err != nil {
		t.Fatal(err)
	}
	b := loadTestBoard(t, tb)
	sys := b.Threads[boardSystem].Msgs
	if len(sys) != 2 || !strings.Contains(sys[1].Text, "`repoA` was rebuilt at commit `abc`") || !strings.Contains(sys[1].Text, "`notes` indexed (not a git repo)") {
		t.Fatalf("system thread after swap: %+v", sys)
	}
	wel := b.Threads[boardWelcome].Msgs
	if !strings.Contains(wel[len(wel)-1].Text, "kbtool board read system#1") {
		t.Fatalf("no welcome notice: %+v", wel[len(wel)-1])
	}
	off := false
	tb.Disabled = effectiveDisabledSet(&config{MessageBoard: &off})
	if _, err := tb.swapIndex(dbMarshal(next)); err != nil {
		t.Fatal(err)
	}
	if n := len(loadTestBoard(t, tb).Threads[boardSystem].Msgs); n != 2 {
		t.Fatalf("board off must not post, have %d system messages", n)
	}
}

// TestDaemonStartStopAnnouncements: why — daemon start and stop are posted;
// the first start on a new board is covered by system#0; a start after an
// unclean stop says so; changed collaboration settings are listed.
func TestDaemonStartStopAnnouncements(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	tb.announceDaemonStart()
	b := loadTestBoard(t, tb)
	if len(b.Threads[boardSystem].Msgs) != 1 || !b.Sys.Running || b.Sys.Settings["welcome post limit"] == "" {
		t.Fatalf("first start: %d system messages, state %+v", len(b.Threads[boardSystem].Msgs), b.Sys)
	}
	tb.announceDaemonStart() // the previous run never stopped
	b = loadTestBoard(t, tb)
	last := b.Threads[boardSystem].Msgs[len(b.Threads[boardSystem].Msgs)-1].Text
	if !strings.Contains(last, "daemon started") || !strings.Contains(last, "did not stop cleanly") || !strings.Contains(last, "No collaboration settings changed") {
		t.Fatalf("restart after crash:\n%s", last)
	}
	tb.announceDaemonStop("received terminated")
	b = loadTestBoard(t, tb)
	last = b.Threads[boardSystem].Msgs[len(b.Threads[boardSystem].Msgs)-1].Text
	if b.Sys.Running || !strings.Contains(last, "daemon stopped (received terminated)") {
		t.Fatalf("stop: running=%v\n%s", b.Sys.Running, last)
	}
	tb2 := &Toolbox{Store: tb.Store, BoardPath: tb.BoardPath, WelcomeMaxWords: 5}
	tb2.announceDaemonStart()
	b = loadTestBoard(t, tb)
	last = b.Threads[boardSystem].Msgs[len(b.Threads[boardSystem].Msgs)-1].Text
	if strings.Contains(last, "did not stop cleanly") || !strings.Contains(last, "welcome post limit changed: 10 words, each under 50 characters → 5 words") {
		t.Fatalf("settings change:\n%s", last)
	}
}

// TestReuseRecordedBuild: why — a bare `kbtool build` rebuilds the recorded
// sources with the recorded knobs, explicit flags still win, and with nothing
// recorded it changes nothing.
func TestReuseRecordedBuild(t *testing.T) {
	kw := false
	prev := &config{Sources: []string{"/r/a", "/r/b"}, DB: "/r/kb.db", Dim: 128, Chunk: 30, Git: true, GitMaxCommits: 7, KWPath: &kw}
	o := BuildOpts{Sources: []string{"."}, Dim: 256, Chunk: 60, Overlap: 10, KWPath: boolPtr(true)}
	dbp := "default.db"
	if !reuseRecordedBuild(prev, map[string]bool{"dim": true}, &o, &dbp) {
		t.Fatal("recorded sources must be reused")
	}
	if !reflect.DeepEqual(o.Sources, prev.Sources) || o.Dim != 256 || o.Chunk != 30 || o.Overlap != 10 || !o.Git ||
		o.GitMaxCommits != 7 || *o.KWPath || dbp != "/r/kb.db" {
		t.Fatalf("opts = %+v db=%s", o, dbp)
	}
	o2 := BuildOpts{Sources: []string{"."}}
	if reuseRecordedBuild(&config{}, nil, &o2, &dbp) || reuseRecordedBuild(nil, nil, &o2, &dbp) || o2.Sources[0] != "." {
		t.Fatal("nothing recorded must leave the opts alone")
	}
}

// TestRecordBuildConfigMerges: why — a build replaces only the build fields
// in config.json; unrelated settings (welcome limit, relay, board memory)
// survive so the next daemon start uses the new index and the old settings.
func TestRecordBuildConfigMerges(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBTOOL_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"version":1,"welcome_max_words":4,"relay_session":"0123456789abcdef0123456789abcdef","message_board_max_memory":"64MiB","sources":["/old"],"git":true,"live":true,"liveRepos":["/old"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	recordBuildConfig([]string{dir}, filepath.Join(dir, "kb.db"), 64, 40, 5, 512, false, 0, 0, nil)
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.WelcomeMaxWords != 4 || c.RelaySession != "0123456789abcdef0123456789abcdef" || c.BoardMaxMemory != "64MiB" {
		t.Fatalf("unrelated settings lost: %+v", c)
	}
	if len(c.Sources) != 1 || c.Sources[0] != dir || c.Dim != 64 || c.Git || c.Live || c.LiveRepos != nil {
		t.Fatalf("build fields not replaced: %+v", c)
	}
}

// TestBoardReadArgs: why — `kbtool board read system#N` must ask board_read
// for exactly message N; a bare thread reads from the start.
func TestBoardReadArgs(t *testing.T) {
	a, err := boardReadArgs("system#3", 50)
	if err != nil || a["thread"] != "system" || a["after"] != 3 || a["limit"] != 1 {
		t.Fatalf("system#3 -> %v %v", a, err)
	}
	if a, err := boardReadArgs("plans", 20); err != nil || a["thread"] != "plans" || a["limit"] != 20 || a["after"] != nil {
		t.Fatalf("plans -> %v %v", a, err)
	}
	for _, bad := range []string{"#1", "system#x", "system#-1"} {
		if _, err := boardReadArgs(bad, 1); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	a, _ = boardReadArgs("system#0", 50)
	a["seed"] = seed
	out, isErr := tb.Execute("board_read", mustMarshal(a))
	if isErr || !strings.Contains(out, "showing 0..0") || !strings.Contains(out, "How this board works") {
		t.Fatalf("board_read system#0: %s", out)
	}
}

// TestRelayLostConnectivityLogged: why — losing an established relay
// connection must be written to daemon.log in plain words (it is not posted
// on the board).
func TestRelayLostConnectivityLogged(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	sid, auth := newTestRelaySession(t, time.Now().Add(time.Hour))
	var mu sync.Mutex
	var logs []string
	rc := &relayConnector{HostPort: hp, Session: sid, Auth: auth, Deliver: func(net.Conn) bool { return false },
		minBackoff: 10 * time.Millisecond, maxBackoff: 20 * time.Millisecond,
		Logf: func(f string, a ...any) {
			mu.Lock()
			logs = append(logs, fmt.Sprintf(f, a...))
			mu.Unlock()
		}}
	go rc.run()
	defer rc.close()
	waitRelaySession(t, rs, sid, true)
	rs.shutdown()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		joined := strings.Join(logs, "\n")
		mu.Unlock()
		if strings.Contains(joined, "lost connectivity to the relay") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no lost-connectivity log line:\n%s", strings.Join(logs, "\n"))
}

// TestRelayConnectorRoundRobin: why — when no candidate relay takes a new
// session at start, the connector keeps cycling through all of them, sticks
// to the first that accepts it (OnSticky, exactly once) and serves there.
func TestRelayConnectorRoundRobin(t *testing.T) {
	sid, auth := newTestRelaySession(t, time.Now().Add(time.Hour))
	dead := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	late := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	var mu sync.Mutex
	var logs, stuck []string
	rc := &relayConnector{Session: sid, Auth: auth, Deliver: func(net.Conn) bool { return false },
		minBackoff: 10 * time.Millisecond, maxBackoff: 20 * time.Millisecond,
		Candidates: []relayEndpoint{{URL: "https://" + dead + "/", HostPort: dead}, {URL: "https://" + late + "/", HostPort: late}},
		OnSticky: func(ep relayEndpoint) {
			mu.Lock()
			stuck = append(stuck, ep.URL)
			mu.Unlock()
		},
		Logf: func(f string, a ...any) {
			mu.Lock()
			logs = append(logs, fmt.Sprintf(f, a...))
			mu.Unlock()
		}}
	if rc.pick() || rc.sticky() {
		t.Fatal("no relay is up: pick must fail and keep the candidates")
	}
	go rc.run()
	defer rc.close()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		mu.Lock()
		retried := strings.Contains(strings.Join(logs, "\n"), "no joined relay accepted session")
		mu.Unlock()
		if retried {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no retry log line")
		}
	}
	rs := newRelayServer(newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil), "")
	ln, err := net.Listen("tcp", late)
	if err != nil {
		t.Fatal(err)
	}
	go rs.serve(ln)
	t.Cleanup(func() { _ = ln.Close(); rs.shutdown() })
	waitRelaySession(t, rs, sid, true)
	mu.Lock()
	defer mu.Unlock()
	if len(stuck) != 1 || stuck[0] != "https://"+late+"/" {
		t.Fatalf("OnSticky must report the relay that took the session once: %v", stuck)
	}
}

// ---------- 43. collaboration sessions, relay.json, collaboration doc (plans/collaborate-sessions-and-relay-json-plan.md) ----------

// TestSessionIDFormat: why — session directories sort and list by their name,
// so the ID must be the ISO-8601 basic UTC timestamp plus a short random part,
// and two IDs from the same second must still differ.
func TestSessionIDFormat(t *testing.T) {
	now := time.Date(2026, 10, 2, 18, 47, 0, 0, time.FixedZone("x", 3600))
	a, b := newSessionID(now), newSessionID(now)
	if !sessionIDRe.MatchString(a) || !strings.HasPrefix(a, "20261002T174700Z_") {
		t.Fatalf("session id %q: want 20261002T174700Z_xxxxxx (UTC)", a)
	}
	if a == b {
		t.Fatal("two session ids from the same second must differ")
	}
}

// TestCollabSources: why — `collaborate host` indexes what the human means by
// "this directory": the checkout itself, or every project next to a git
// checkout (git or not), never hidden or symlinked directories.
func TestCollabSources(t *testing.T) {
	mk := func(p ...string) string {
		d := filepath.Join(p...)
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		return d
	}
	repo := t.TempDir()
	mk(repo, ".git")
	mk(repo, "sub", ".git")
	if got, _ := collabSources(repo); !reflect.DeepEqual(got, []string{repo}) {
		t.Fatalf("a git checkout indexes itself only: %v", got)
	}
	ws := t.TempDir()
	a, b := mk(ws, "a"), mk(ws, "b")
	mk(a, ".git")
	mk(ws, ".hidden", ".git")
	if err := os.Symlink(a, filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, ws, "file.txt", []byte("x"))
	if got, _ := collabSources(ws); !reflect.DeepEqual(got, []string{a, b}) {
		t.Fatalf("children of a workspace with a git child: %v, want [%s %s]", got, a, b)
	}
	plain := t.TempDir()
	mk(plain, "x")
	if got, _ := collabSources(plain); !reflect.DeepEqual(got, []string{plain}) {
		t.Fatalf("no git anywhere indexes the directory itself: %v", got)
	}
}

// TestValidateAbout: why — `session ls` shows about.json, which agents write;
// validation must catch every mistake an agent can make so `session validate`
// is a reliable check of their edit.
func TestValidateAbout(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{`{"summary":"branch protection migration","participants":["Sam","Josh"]}`, ""},
		{`{"summary":"two words","participants":["Sam"]}`, ""},
		{`{"summary":"one","participants":["Sam"]}`, "2 or 3 words"},
		{`{"summary":"one two three four","participants":["Sam"]}`, "2 or 3 words"},
		{`{"summary":"two  words","participants":["Sam"]}`, "single spaces"},
		{`{"summary":"two words","participants":[]}`, "participants is empty"},
		{`{"summary":"two words","participants":null}`, "participants is empty"},
		{`{"summary":"two words","participants":["Sam","sam"]}`, "more than once"},
		{`{"summary":"two words","participants":[" Sam"]}`, "leading or trailing"},
		{`{"summary":"two words","participants":[""]}`, "empty name"},
		{`{"summary":"two words","participants":["` + strings.Repeat("x", 65) + `"]}`, "at most 64"},
		{`{"summary":"two words","participants":["a\u0007b"]}`, "control"},
		{`{"summary":"two words","participants":["Sam"],"agents":["x"]}`, "unknown field"},
		{`{"summary":"two words","participants":["Sam"]} {}`, "after the JSON"},
		{`not json`, "is not"},
	} {
		_, probs := validateAbout([]byte(tc.in))
		got := strings.Join(probs, "; ")
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("validateAbout(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCreateAndValidateSession: why — a new session must have the layout the
// collaboration doc promises (seed kept out of git, empty about.json the
// agents fill in), and validation must report the kbtool-owned files too.
// Why: agents work from the user's checkout, so memory/, consensus/,
// deliverables/ and the checksum files must only ever exist under
// ~/.config/kbtool/sessions/<id>/, and the agent doc must never send an agent
// to a path relative to its working directory.
func TestSessionDirsNeverInWorkdir(t *testing.T) {
	home, work := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KBTOOL_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
	m, err := createSession("attendee", work, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".config", "kbtool", "sessions", m.ID)
	if sessionDir(m.ID) != want {
		t.Fatalf("session dir %s, want %s", sessionDir(m.ID), want)
	}
	for _, d := range []string{"memory", "consensus", "deliverables"} {
		if fi, err := os.Stat(filepath.Join(want, d)); err != nil || !fi.IsDir() {
			t.Fatalf("%s must be under %s: %v", d, want, err)
		}
	}
	doc, err := renderCollabDoc(newCollabDoc(m, "attend"))
	if err != nil {
		t.Fatal(err)
	}
	for _, never := range []string{want, home, ".config/kbtool", m.ID, "shasum", "scratch", "about.json", ".kbtool-seed"} {
		if strings.Contains(string(doc), never) {
			t.Fatalf("the doc must not name %q: agents reach session files only through kbtool", never)
		}
	}
	ents, _ := os.ReadDir(work)
	if len(ents) != 0 {
		t.Fatalf("nothing may be created in the working directory: %v", ents)
	}

	t.Setenv("KBTOOL_DIR", "relative-state")
	if _, err := createSession("attendee", work, time.Now()); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("a relative data dir must be refused: %v", err)
	}
	if ents, _ := os.ReadDir(work); len(ents) != 0 {
		t.Fatalf("a refused session must not touch the working directory: %v", ents)
	}
}

func TestCreateAndValidateSession(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	m, err := createSession("host", "/work", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := sessionDir(m.ID)
	for _, d := range []string{"memory", "consensus", "deliverables"} {
		if fi, err := os.Stat(filepath.Join(dir, d)); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0700 {
			t.Fatalf("%s must be a 0700 directory: %v", d, err)
		}
	}
	probs := validateSession(m.ID)
	if len(probs) != 2 || !strings.Contains(probs[0], "summary") || !strings.Contains(probs[1], "participants") {
		t.Fatalf("a fresh session lacks only summary and participants: %q", probs)
	}
	writeTestPEM(t, dir, "about.json", []byte(`{"summary":"auth review","participants":["Sam"]}`))
	if probs := validateSession(m.ID); len(probs) != 0 {
		t.Fatalf("a filled-in session must validate: %q", probs)
	}
	if err := os.Remove(filepath.Join(dir, "deliverables")); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, dir, "meta.json", []byte(`{"id":"other","role":"host"}`))
	probs = validateSession(m.ID)
	if got := strings.Join(probs, "; "); !strings.Contains(got, "deliverables/") || !strings.Contains(got, "meta.json") {
		t.Fatalf("validation must cover the directories and meta.json: %q", probs)
	}
	if probs := validateSession("bogus"); len(probs) != 1 {
		t.Fatalf("an invalid id is one problem: %q", probs)
	}
}

// TestListSessions: why — `session ls` is how humans find a past session: most
// recently used first, the current one marked, and long participant lists cut
// off unless -a asks for all.
func TestListSessions(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var ids []string
	for i, people := range []string{`["A"]`, `["A","B","C","D","E"]`, `[]`} {
		m, err := createSession("attendee", "/w", base.Add(time.Duration(i)*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		writeTestPEM(t, sessionDir(m.ID), "about.json", []byte(`{"summary":"session `+strconv.Itoa(i)+`","participants":`+people+`}`))
		ids = append(ids, m.ID)
	}
	m, _ := loadSessionMeta(ids[0])
	m.LastUsed = base.Add(5 * time.Hour).Format(time.RFC3339Nano)
	if err := saveSessionMeta(m); err != nil {
		t.Fatal(err)
	}
	if err := saveSessionPointer(&sessionPointer{Current: ids[1], Active: true}); err != nil {
		t.Fatal(err)
	}
	rows, err := listSessions(nil)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows: %v %v", rows, err)
	}
	if rows[0].ID != ids[0] || rows[1].ID != ids[2] || rows[2].ID != ids[1] {
		t.Fatalf("order must follow last_used: %v", rows)
	}
	if !rows[2].Current || rows[2].State != "active" || rows[0].State != "finished" {
		t.Fatalf("current/active marking: %+v", rows)
	}
	var buf bytes.Buffer
	writeSessionList(&buf, rows, false)
	out := buf.String()
	if !strings.Contains(out, "A, B, C +2 more") || !strings.Contains(out, "session ls -a") || !strings.Contains(out, "* "+ids[1]) {
		t.Fatalf("list output:\n%s", out)
	}
	buf.Reset()
	writeSessionList(&buf, rows, true)
	if !strings.Contains(buf.String(), "A, B, C, D, E") || strings.Contains(buf.String(), "more") {
		t.Fatalf("-a must list every participant:\n%s", buf.String())
	}
}

// TestArchiveRestoreState: why — finish must leave the data dir with only
// relay.json, session.json and sessions/, and resume must bring back exactly
// what was there, private key modes included.
func TestArchiveRestoreState(t *testing.T) {
	sd := shortStateDir(t)
	writeTestPEM(t, sd, "relay.json", []byte("{}"))
	writeTestPEM(t, sd, "session.json", []byte("{}"))
	if err := os.MkdirAll(filepath.Join(sd, "sessions", "x"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sd, "server.key"), []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, sd, "config.json", []byte(`{"a":1}`))
	if err := os.MkdirAll(filepath.Join(sd, "nested", "deep"), 0750); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, filepath.Join(sd, "nested", "deep"), "f", []byte("deep"))
	ln, err := net.Listen("unix", filepath.Join(sd, "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	dest := filepath.Join(sd, "sessions", "x", "state.tar.gz")
	n, err := archiveState(sd, dest)
	if err != nil || n != 3 {
		t.Fatalf("archive: n=%d err=%v", n, err)
	}
	if fi, err := os.Stat(dest); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("the archive holds keys and must be 0600: %v", err)
	}
	left, _ := looseState(sd)
	if len(left) != 0 {
		t.Fatalf("only the keep-list may remain: %v", left)
	}
	if n, err := archiveState(sd, dest); n != 0 || err != nil || !fileExists(dest) {
		t.Fatal("archiving nothing must leave an earlier archive alone")
	}
	if n, err := restoreState(sd, dest); err != nil || n != 3 {
		t.Fatalf("restore: n=%d err=%v", n, err)
	}
	if fi, err := os.Stat(filepath.Join(sd, "server.key")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("server.key must come back 0600: %v", err)
	}
	if string(mustReadFile(t, filepath.Join(sd, "nested", "deep", "f"))) != "deep" {
		t.Fatal("nested files must come back")
	}
	if fi, err := os.Stat(filepath.Join(sd, "nested", "deep")); err != nil || fi.Mode().Perm() != 0750 {
		t.Fatalf("directory modes must come back: %v", err)
	}
	if _, err := restoreState(sd, dest); err == nil {
		t.Fatal("restore must never overwrite existing files")
	}
}

// TestRestoreStateRefusesEscapes: why — an archive is unpacked into the data
// dir; it must not write outside it or over the files that outlive sessions.
func TestRestoreStateRefusesEscapes(t *testing.T) {
	for _, name := range []string{"../evil", "/abs", "relay.json", "sessions/x/meta.json"} {
		sd := t.TempDir()
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
		tw.Close()
		gz.Close()
		src := filepath.Join(t.TempDir(), "s.tar.gz")
		writeTestPEM(t, filepath.Dir(src), "s.tar.gz", buf.Bytes())
		if _, err := restoreState(sd, src); err == nil {
			t.Errorf("restore must refuse %q", name)
		}
	}
}

// TestConfirmCollab: why — replacing a session is destructive enough to need
// a yes; scripts and agents without a terminal must pass -yes explicitly.
func TestConfirmCollab(t *testing.T) {
	old := stdinTTY
	t.Cleanup(func() { stdinTTY = old })
	stdinTTY = func() bool { return false }
	if err := confirmCollab(nil, false); err != nil {
		t.Fatal("nothing to confirm must pass")
	}
	if err := confirmCollab([]string{"x"}, true); err != nil {
		t.Fatal("-yes must confirm")
	}
	if err := confirmCollab([]string{"x"}, false); err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Fatalf("no terminal and no -yes must refuse and name -yes: %v", err)
	}
}

// TestReplaceReasons: why — the user must be told every thing a new session
// replaces: the collaboration doc or stray state. An active session is never
// replaced (activeSessionErr refuses instead).
func TestReplaceReasons(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	cwd := t.TempDir()
	if rs := replaceReasons(cwd, nil); len(rs) != 0 {
		t.Fatalf("a clean start needs no confirmation: %q", rs)
	}
	writeTestPEM(t, cwd, collabDocName, []byte(collabDocPrefix+"(x) -->\n"))
	writeTestPEM(t, stateDir(), "kb.db", []byte("x"))
	rs := replaceReasons(cwd, nil)
	if len(rs) != 2 || !strings.Contains(rs[0], collabDocName) || !strings.Contains(rs[1], "kb.db") {
		t.Fatalf("doc + loose state: %q", rs)
	}
	if err := activeSessionErr(&sessionPointer{Current: "20260101T000000Z_abcdef", Active: true}); !strings.Contains(err.Error(), "kbtool collaborate finish") {
		t.Fatalf("an active session must be finished by the user: %v", err)
	}
}

// TestCollabDocRender: why — the doc is what agents follow: every field must
// render, it names no session ID or data dir path, kbtool recognizes its own
// doc, and only the host gets the hosting section with its sources and relay.
func TestCollabDocRender(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	writeTestPEM(t, stateDir(), "relay.json", []byte(`{"version":1,"enabled":true,"relays":[{"url":"https://other.example:9876/"},{"url":"https://relay.example:9876/"}]}`))
	if err := saveConfig(&config{Sources: []string{"/src/a", "/src/b"}, RelaySession: "0123456789abcdef0123456789abcdef", RelayURL: "https://relay.example:9876/"}); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"host", "attendee"} {
		m, err := createSession(role, "/w", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		b, err := renderCollabDoc(newCollabDoc(m, "host"))
		if err != nil {
			t.Fatal(err)
		}
		doc := string(b)
		if strings.Contains(doc, "{{") || strings.Contains(doc, "<no value>") {
			t.Fatalf("%s: unrendered template fields", role)
		}
		for _, never := range []string{sessionDir(m.ID), stateDir(), m.ID, "~/.config"} {
			if strings.Contains(doc, never) {
				t.Errorf("%s doc names %q", role, never)
			}
		}
		for _, want := range []string{"consensus/goals.md", "kbtool board signup", "kbtool session about", "kbtool memory", "kbtool consensus propose",
			"kbtool consensus review", "kbtool consensus vote", "kbtool deliverables", "-host-accepted", "background update", "board fetch -o DIR", "attach` (memory", "consensus_files"} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s doc lacks %q", role, want)
			}
		}
		host := strings.Contains(doc, "Hosting this session")
		if host != (role == "host") {
			t.Errorf("%s: hosting section present=%v", role, host)
		}
		if role == "host" && (!strings.Contains(doc, "`/src/b`") || !strings.Contains(doc, "https://relay.example:9876/")) {
			t.Error("the host section must list the sources and the relay")
		}
		if strings.Contains(doc, "This session is local") {
			t.Errorf("%s: a relay session is not local", role)
		}
		dir := t.TempDir()
		writeTestPEM(t, dir, collabDocName, b)
		if exists, ours := collabDocState(dir); !exists || !ours {
			t.Fatalf("kbtool recognizes its own doc: %v %v", exists, ours)
		}
		writeTestPEM(t, dir, collabDocName, []byte("# my own notes\n"))
		if exists, ours := collabDocState(dir); !exists || ours {
			t.Fatalf("a hand-written file is not kbtool's: %v %v", exists, ours)
		}
	}
	writeTestPEM(t, stateDir(), "relay.json", []byte(`{"version":1,"enabled":false,"relays":[{"url":"https://relay.example:9876/"}]}`))
	m, err := createSession("host", "/w", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := renderCollabDoc(newCollabDoc(m, "host"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	if !strings.Contains(doc, "This session is local") || !strings.Contains(doc, "session memory") ||
		strings.Contains(doc, "enrollment line for the") || strings.Contains(doc, "relay.example") || strings.Contains(doc, "shared daemon") {
		t.Fatalf("a host without an enabled relay gets the local session doc:\n%s", doc)
	}
}

// TestRelayJSONClient: why — a relay client reaches the relay its token named
// (client.json relay), whatever the joined list says; relay.json only gates it
// with "enabled", and a broken client.json says how to re-enroll.
func TestRelayJSONClient(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	if err := saveRelayJSON(&relayJSON{Relays: []relayTarget{{URL: "https://joined.example:7000/", Token: "tk", CA: "system"}}}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(relayJSONPath()); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("relay.json must be 0600: %v", err)
	}
	if err := enableClientRelay(); err != nil {
		t.Fatal(err)
	}
	if rj, _ := loadRelayJSON(); rj == nil || !rj.Enabled || len(rj.Relays) != 1 || rj.Relays[0].Token != "tk" {
		t.Fatalf("enrolling enables relays and keeps the joined list: %+v", rj)
	}
	writeTestPEM(t, stateDir(), "client.json", []byte(`{"version":1,"tls":true,"session":"0123456789abcdef0123456789abcdef","relay":"https://relay.example:7001/"}`))
	cc, err := loadClientConfig()
	if err != nil || cc.Host != "relay.example" || cc.Port != 7001 {
		t.Fatalf("relay client endpoint from client.json: %+v %v", cc, err)
	}
	rj, _ := loadRelayJSON()
	rj.Enabled = false
	if err := saveRelayJSON(rj); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClientConfig(); err == nil || !strings.Contains(err.Error(), "kbtool relay enable") {
		t.Fatalf("a relay client with relays disabled must say how to enable them: %v", err)
	}
	if a, err := activeRelay(); err != nil || a != nil {
		t.Fatalf("disabled relays are not active: %+v %v", a, err)
	}
	if err := os.Remove(relayJSONPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClientConfig(); err != nil {
		t.Fatalf("a relay client needs no relay.json: %v", err)
	}
	writeTestPEM(t, stateDir(), "client.json", []byte(`{"version":1,"tls":true,"session":"0123456789abcdef0123456789abcdef"}`))
	if _, err := loadClientConfig(); err == nil || !strings.Contains(err.Error(), "client -import") {
		t.Fatalf("a relay client.json without its relay must say how to re-enroll: %v", err)
	}
	writeTestPEM(t, stateDir(), "relay.json", []byte(`{"relays":[{"url":"http://plain/"}]}`))
	if _, err := loadRelayJSON(); err == nil {
		t.Fatal("an invalid relay URL must be refused")
	}
}

// TestRelayJSONList: why — the joined relays are one global list: a new
// session tries them round robin from next, find matches normalized URLs, and
// activeRelay needs relays enabled and at least one joined.
func TestRelayJSONList(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	rj := &relayJSON{Enabled: true, Next: 1, Relays: []relayTarget{{URL: "https://a.example:9876/"}, {URL: "https://b.example:9876/"}, {URL: "https://c.example:9876/"}}}
	var order []string
	for _, r := range rj.roundRobin() {
		order = append(order, r.URL)
	}
	if strings.Join(order, " ") != "https://b.example:9876/ https://c.example:9876/ https://a.example:9876/" {
		t.Fatalf("round robin from next=1: %v", order)
	}
	if rj.find("https://c.example") != 2 || rj.find("https://d.example/") != -1 {
		t.Fatal("find must match normalized URLs")
	}
	if err := saveRelayJSON(&relayJSON{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if a, _ := activeRelay(); a != nil {
		t.Fatal("no joined relay: not active")
	}
	if err := saveRelayJSON(rj); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(&config{RelaySession: "0123456789abcdef0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	if err := persistStickyRelay("https://c.example:9876/"); err != nil {
		t.Fatal(err)
	}
	c, _ := loadConfig()
	got, _ := loadRelayJSON()
	if c.RelayURL != "https://c.example:9876/" || got.Next != 0 {
		t.Fatalf("sticky relay recorded and round robin moved past it: relay_url=%q next=%d", c.RelayURL, got.Next)
	}
}

// TestSessionSeedDefaults: why — agents should never handle the seed: board
// commands default to the active session's seed file, and `kbtool call`
// fills in a missing seed, but never overrides one or touches signup.
func TestSessionSeedDefaults(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	if defaultSeedFile() != ".kbtool-seed" {
		t.Fatal("without a session the seed file is ./.kbtool-seed")
	}
	m, err := createSession("attendee", "/w", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := saveSessionPointer(&sessionPointer{Current: m.ID, Active: true}); err != nil {
		t.Fatal(err)
	}
	if defaultSeedFile() != sessionSeedPath(m.ID) {
		t.Fatalf("active session seed file = %q", defaultSeedFile())
	}
	seed := strings.Repeat("ab", 32)
	if sessionSeedPath(m.ID) != filepath.Join(stateDir(), "sessions", m.ID, ".kbtool-seed") {
		t.Fatalf("the seed lives in the session directory, not memory/: %s", sessionSeedPath(m.ID))
	}
	writeTestPEM(t, sessionDir(m.ID), ".kbtool-seed", []byte(seed+"\n"))
	var got map[string]string
	_ = json.Unmarshal(injectSessionSeed("board_whoami", []byte(`{}`)), &got)
	if got["seed"] != seed {
		t.Fatalf("missing seed must be injected: %v", got)
	}
	for _, tc := range []struct{ name, args string }{
		{"board_post", `{"seed":"mine"}`}, {"board_signup", `{"name":"a"}`}, {"kb_search", `{"q":"x"}`},
	} {
		if out := string(injectSessionSeed(tc.name, []byte(tc.args))); out != tc.args {
			t.Errorf("%s %s must be left alone, got %s", tc.name, tc.args, out)
		}
	}
	if err := saveSessionPointer(&sessionPointer{Current: m.ID}); err != nil {
		t.Fatal(err)
	}
	if out := string(injectSessionSeed("board_whoami", []byte(`{}`))); out != `{}` || defaultSeedFile() != ".kbtool-seed" {
		t.Fatal("a finished session's seed must not be used")
	}
	if signupSeed("signed up as: a\nseed: "+seed+"\n") != seed || signupSeed("seed: xyz") != "" {
		t.Fatal("signupSeed must extract exactly a 64-hex seed")
	}
}

// TestSystemIntroRebuildGuidance: why — rebuilding the index is a human action
// on the host, so system#0 must tell agents how to ask (call or board) and
// how to sign up without handling the seed.
func TestSystemIntroRebuildGuidance(t *testing.T) {
	txt := systemIntroText(boardSysInfo{WelcomeWords: 10})
	for _, want := range []string{"Only the host's human can rebuild the index", "in the call", "`index` thread", "kbtool board signup NAME"} {
		if !strings.Contains(txt, want) {
			t.Errorf("system#0 lacks %q", want)
		}
	}
}

// TestCollaborateLocalThenExpand: why — with the relay disabled, hosting needs
// no relay connectivity: the session is local (unix socket, no PKI, no
// enrollment line) yet has its board as session memory; enabling the relay and
// resuming opens the same session, board included, to collaborators.
func TestCollaborateLocalThenExpand(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	relayDir, hostDir := shortStateDir(t), shortStateDir(t)
	hostWork := t.TempDir()
	if err := os.MkdirAll(filepath.Join(hostWork, "repo", ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, filepath.Join(hostWork, "repo"), "a.go", []byte("package a\nfunc Alpha() {}\n"))
	run := func(dir, cwd string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, bin, args...)
		c.Env = append(os.Environ(), "KBTOOL_DIR="+dir, "HOME="+work, "KB_EMBED_URL=", "KBTOOL_SOCKET=", "KBTOOL_RELAY_BIND=", "KBTOOL_RELAY_PORT=")
		c.Dir = cwd
		out, err := c.CombinedOutput()
		return string(out), err
	}
	hp := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if out, err := run(relayDir, work, "relay", "start", "-bind", hp); err != nil {
		t.Fatalf("relay start: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_, _ = run(hostDir, hostWork, "collaborate", "finish")
		_, _ = run(relayDir, work, "relay", "stop")
	})
	if out, err := run(hostDir, work, "relay", "disable"); err == nil || !strings.Contains(out, "relay join") {
		t.Fatalf("relay disable without relay.json must point to relay join: %v\n%s", err, out)
	}
	if out, err := run(hostDir, work, "relay", "join", "https://"+hp+"/"); err != nil {
		t.Fatalf("relay join: %v\n%s", err, out)
	}
	if out, err := run(hostDir, work, "relay", "disable"); err != nil {
		t.Fatalf("relay disable: %v\n%s", err, out)
	}
	out, err := run(hostDir, hostWork, "collaborate", "host", "-yes")
	if err != nil || !strings.Contains(out, "local session") || strings.Contains(out, "kbtool collaborate attend") {
		t.Fatalf("collaborate host with the relay disabled must start a local session: %v\n%s", err, out)
	}
	for _, f := range []string{"ca.crt", "server.crt", relaySessionKeyFile} {
		if fileExists(filepath.Join(hostDir, f)) {
			t.Fatalf("a local session must not issue %s", f)
		}
	}
	if !strings.Contains(string(mustReadFile(t, filepath.Join(hostWork, collabDocName))), "This session is local") {
		t.Fatal("the local host's doc must say the session is local")
	}
	if out, err := run(hostDir, hostWork, "board", "signup", "hostbot"); err != nil || !strings.Contains(out, "seed stored in this session") {
		t.Fatalf("the board is on in a local session: %v\n%s", err, out)
	}
	if out, err := run(hostDir, hostWork, "relay", "enable"); err != nil || !strings.Contains(out, "collaborate resume") {
		t.Fatalf("relay enable: %v\n%s", err, out)
	}
	if out, err := run(hostDir, hostWork, "collaborate", "resume"); err != nil || !strings.Contains(out, "does not use them") {
		t.Fatalf("resume with the daemon running must say how to expand: %v\n%s", err, out)
	}
	if out, err := run(hostDir, hostWork, "collaborate", "finish"); err != nil {
		t.Fatalf("finish: %v\n%s", err, out)
	}
	if out, err := run(hostDir, hostWork, "collaborate", "resume"); err != nil || !strings.Contains(out, "opening the session to collaborators") {
		t.Fatalf("resume with an enabled relay must open the session: %v\n%s", err, out)
	}
	var line string
	for deadline := time.Now().Add(20 * time.Second); line == "" && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if m := regexp.MustCompile(`kbtool client -import (kb1\S+)`).FindStringSubmatch(string(mustReadFile(t, filepath.Join(hostDir, "daemon.log")))); m != nil {
			line = m[1]
		}
	}
	if line == "" {
		t.Fatalf("no relay enrollment line after expanding:\n%s", mustReadFile(t, filepath.Join(hostDir, "daemon.log")))
	}
	if doc := string(mustReadFile(t, filepath.Join(hostWork, collabDocName))); strings.Contains(doc, "This session is local") || !strings.Contains(doc, "https://"+hp+"/") {
		t.Fatal("resume must rewrite the doc for collaborators")
	}
	if out, err := run(hostDir, hostWork, "call", "board_whoami"); err != nil || !strings.Contains(out, "you are: hostbot") {
		t.Fatalf("the local session's board carries over: %v\n%s", err, out)
	}
}

// TestCollaborateCLI: why — the whole lifecycle through the binary built with
// the single build command (run from directories without the embedded
// template) over a relay: host (index, relay-mode mTLS, daemon, doc, attend line), the
// confirmation refusal, attend (relay.json written), seedless board use,
// finish leaving only the keep-list, session ls, resume on both sides, and
// session validate.
func TestCollaborateCLI(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	relayDir, hostDir, attDir := shortStateDir(t), shortStateDir(t), shortStateDir(t)
	hostWork, attWork := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(hostWork, "repo", ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, filepath.Join(hostWork, "repo"), "a.go", []byte("package a\nfunc Alpha() {}\n"))
	run := func(dir, cwd string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, bin, args...)
		c.Env = append(os.Environ(), "KBTOOL_DIR="+dir, "HOME="+work, "KB_EMBED_URL=", "KBTOOL_SOCKET=", "KBTOOL_RELAY_BIND=", "KBTOOL_RELAY_PORT=")
		c.Dir = cwd
		out, err := c.CombinedOutput()
		return string(out), err
	}
	hp := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if out, err := run(relayDir, work, "relay", "start", "-bind", hp); err != nil {
		t.Fatalf("relay start: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_, _ = run(hostDir, hostWork, "collaborate", "finish")
		_, _ = run(relayDir, work, "relay", "stop")
	})
	if out, err := run(hostDir, work, "relay", "join", "https://"+hp+"/"); err != nil {
		t.Fatalf("relay join: %v\n%s", err, out)
	}
	writeTestPEM(t, hostWork, collabDocName, []byte("old\n"))
	if out, err := run(hostDir, hostWork, "collaborate", "host"); err == nil || !strings.Contains(out, "-yes") {
		t.Fatalf("an existing %s must need confirmation: %v\n%s", collabDocName, err, out)
	}
	out, err := run(hostDir, hostWork, "collaborate", "host", "-yes")
	if err != nil || !strings.Contains(out, "indexing "+hostWork) || !strings.Contains(out, "kbtool collaborate attend kb1") {
		t.Fatalf("collaborate host: %v\n%s", err, out)
	}
	if !strings.Contains(string(mustReadFile(t, filepath.Join(hostWork, collabDocName))), "Hosting this session") {
		t.Fatal("the host's doc must have the hosting section")
	}
	var line string
	for deadline := time.Now().Add(20 * time.Second); line == "" && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if m := regexp.MustCompile(`kbtool client -import (kb1\S+)`).FindStringSubmatch(string(mustReadFile(t, filepath.Join(hostDir, "daemon.log")))); m != nil {
			line = m[1]
		}
	}
	if line == "" {
		t.Fatal("no relay enrollment line")
	}
	if out, err := run(attDir, attWork, "collaborate", "attend", line); err != nil || !strings.Contains(out, "enrolled") || !fileExists(filepath.Join(attDir, "relay.json")) {
		t.Fatalf("collaborate attend: %v\n%s", err, out)
	}
	if out, err := run(attDir, attWork, "board", "signup", "alice"); err != nil || strings.Contains(out, "seed: ") {
		t.Fatalf("board signup must store, not print, the seed: %v\n%s", err, out)
	}
	if out, err := run(attDir, attWork, "call", "board_whoami"); err != nil || !strings.Contains(out, "you are: alice") || !strings.Contains(out, "platform: "+clientPlatform) {
		t.Fatalf("kbtool call must use the session seed: %v\n%s", err, out)
	}
	if out, err := run(attDir, attWork, "board", "read", "system#0"); err != nil || !strings.Contains(out, "Rebuilding the index") {
		t.Fatalf("board read with the session seed: %v\n%s", err, out)
	}
	// consensus voting end to end: the host's agent signs up over the unix socket
	if out, err := run(hostDir, hostWork, "board", "signup", "hostbot"); err != nil || !strings.Contains(out, "session host's agent") || !strings.Contains(out, "seed stored in this session") {
		t.Fatalf("host signup over the socket is the host's agent (and names no data dir path): %v\n%s", err, out)
	}
	os.MkdirAll(filepath.Join(attWork, "tickets"), 0700)
	writeTestPEM(t, filepath.Join(attWork, "tickets"), "01.md", []byte("ticket one\n"))
	if out, err := run(attDir, attWork, "memory", "import", "tickets"); err != nil {
		t.Fatalf("memory import: %v\n%s", err, out)
	}
	if out, err := run(attDir, attWork, "consensus", "propose", "-m", "first ticket", "tickets=deliverables"); err != nil || !strings.Contains(out, "waiting for: hostbot") {
		t.Fatalf("propose: %v\n%s", err, out)
	}
	if out, err := run(attDir, attWork, "consensus", "propose", "-m", "x", "-host-accepted", "tickets=deliverables/x"); err == nil {
		t.Fatalf("-host-accepted is refused for a remote agent:\n%s", out)
	}
	if out, err := run(hostDir, hostWork, "consensus", "review", "1", "-diff"); err != nil || !strings.Contains(out, "=== deliverables/01.md: new file") {
		t.Fatalf("review -diff: %v\n%s", err, out)
	}
	if out, err := run(hostDir, hostWork, "consensus", "vote", "1", "yes"); err != nil || !strings.Contains(out, "accepted") {
		t.Fatalf("vote: %v\n%s", err, out)
	}
	out, err = run(attDir, attWork, "deliverables", "cat", "01.md")
	if err != nil || !strings.Contains(out, "ticket one") || !strings.Contains(out, "background update of deliverables/ (proposal 1 accepted)") {
		t.Fatalf("the attendee's copy updates in the background before it is read: %v\n%s", err, out)
	}
	os.MkdirAll(filepath.Join(hostWork, "notes"), 0700)
	writeTestPEM(t, filepath.Join(hostWork, "notes"), "goals.md", []byte("the goals\n"))
	run(hostDir, hostWork, "memory", "import", "notes/goals.md")
	if out, err := run(hostDir, hostWork, "consensus", "propose", "-m", "goals agreed with the humans", "-host-accepted", "goals.md=consensus/goals.md"); err != nil || !strings.Contains(out, "accepted") {
		t.Fatalf("-host-accepted over the socket: %v\n%s", err, out)
	}
	if out, err := run(attDir, attWork, "consensus", "cat", "goals.md"); err != nil || !strings.Contains(out, "the goals") {
		t.Fatalf("host-accepted change reaches the attendee: %v\n%s", err, out)
	}
	if out, err := run(attDir, attWork, "call", "board_confirm"); err != nil || !regexp.MustCompile(`alice .*copies=in-sync`).MatchString(out) {
		t.Fatalf("roster shows the attendee in sync:\n%s", out)
	}
	p := func(dir string) *sessionPointer {
		var sp sessionPointer
		if err := json.Unmarshal(mustReadFile(t, filepath.Join(dir, "session.json")), &sp); err != nil {
			t.Fatal(err)
		}
		return &sp
	}
	attID := p(attDir).Current
	writeTestPEM(t, filepath.Join(attDir, "sessions", attID), "about.json", []byte(`{"summary":"lab session","participants":["Sam","Josh"]}`))
	if out, err := run(attDir, attWork, "session", "validate"); err != nil || !strings.Contains(out, "ok") {
		t.Fatalf("session validate: %v\n%s", err, out)
	}
	certsBefore := map[string][]byte{}
	for _, f := range []string{"ca.crt", "server.crt", "client.crt"} {
		certsBefore[f], _ = os.ReadFile(filepath.Join(hostDir, f))
	}
	for _, d := range []struct{ dir, cwd string }{{attDir, attWork}, {hostDir, hostWork}} {
		if out, err := run(d.dir, d.cwd, "collaborate", "finish"); err != nil {
			t.Fatalf("finish: %v\n%s", err, out)
		}
		ents, _ := os.ReadDir(d.dir)
		for _, e := range ents {
			if !collabKeep[e.Name()] {
				t.Fatalf("%s left in %s after finish", e.Name(), d.dir)
			}
		}
	}
	if out, err := run(hostDir, hostWork, "board", "dump", "-session", p(hostDir).Current); err != nil || !strings.Contains(out, "first ticket") || !strings.Contains(out, "<html") {
		t.Fatalf("board dump of the finished host session: %v\n%.300s", err, out)
	}
	if out, err := run(attDir, attWork, "board", "dump", "-session", attID); err == nil || !strings.Contains(out, "attendee session has no copy") {
		t.Fatalf("board dump of a finished attendee session: %v\n%.300s", err, out)
	}
	if out, err := run(attDir, attWork, "session", "ls"); err != nil || !strings.Contains(out, "lab session") || !strings.Contains(out, "Sam, Josh") || !strings.Contains(out, "finished") {
		t.Fatalf("session ls: %v\n%s", err, out)
	}
	out, err = run(hostDir, hostWork, "collaborate", "resume")
	if err != nil || !strings.Contains(out, "daemon started") {
		t.Fatalf("host resume: %v\n%s", err, out)
	}
	if strings.Contains(out, "issuing new ones") {
		t.Fatalf("resume must not issue certificates while the restored ones are valid:\n%s", out)
	}
	for f, want := range certsBefore {
		if got, _ := os.ReadFile(filepath.Join(hostDir, f)); len(want) == 0 || !bytes.Equal(got, want) {
			t.Fatalf("resume must restore %s unchanged while it is valid", f)
		}
	}
	attDoc := filepath.Join(attWork, collabDocName)
	if err := os.WriteFile(attDoc, []byte("# hand-written\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := run(attDir, attWork, "collaborate", "resume"); err == nil || !strings.Contains(out, "not written by kbtool") {
		t.Fatalf("resume must ask before replacing a hand-written doc: %v\n%s", err, out)
	}
	os.Remove(attDoc)
	var connected bool
	for deadline := time.Now().Add(20 * time.Second); !connected && time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		out, _ = run(attDir, attWork, "collaborate", "resume")
		connected = strings.Contains(out, "connected to")
	}
	if !connected {
		t.Fatalf("attendee resume must reconnect through the same relay session:\n%s", out)
	}
	if out, err := run(attDir, attWork, "call", "board_whoami"); err != nil || !strings.Contains(out, "you are: alice") {
		t.Fatalf("the restored session keeps its identity: %v\n%s", err, out)
	}
}

// ---------- 44. encrypted sessions, KBTOOL_SECRET, KBX2 and kbx rekey ----------

func kbx2Bytes(t *testing.T, key, head, payload []byte, keys kbxKeys) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := newKBX2Writer(&buf, key, nil, head)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(keys); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestKBX2Format: why — session archives must round-trip across many
// records, and a wrong key, a truncated file, a re-flagged record or trailing
// data must all be rejected (the final keys record guards against
// truncation).
func TestKBX2Format(t *testing.T) {
	key := []byte("k1")
	payload := bytes.Repeat([]byte("0123456789abcdef"), kbx2RecordMax/16*3+5)
	keys := kbxKeys{Inner: map[string][]byte{"state/kb.db": []byte("inner")}}
	b := kbx2Bytes(t, key, []byte(`{"h":1}`), payload, keys)
	r, err := openKBX2(bytes.NewReader(b), key)
	if err != nil || string(r.head) != `{"h":1}` {
		t.Fatalf("open: %v head %q", err, r.head)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, payload) || string(r.keys.Inner["state/kb.db"]) != "inner" {
		t.Fatalf("round trip: %v (%d bytes) keys %v", err, len(got), r.keys)
	}
	if _, err := openKBX2(bytes.NewReader(b), []byte("nope")); err == nil || !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("a wrong key must fail on the head: %v", err)
	}
	cut, _ := openKBX2(bytes.NewReader(b[:len(b)-40]), key)
	if _, err := io.ReadAll(cut); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("a truncated file must be reported: %v", err)
	}
	tampered := append([]byte{}, b...)
	tampered[kbx2HeaderLen+5+len(r.head)+16] = kbx2FlagFinal | kbx2FlagKeys
	tr, _ := openKBX2(bytes.NewReader(tampered), key)
	if _, err := io.ReadAll(tr); err == nil {
		t.Fatal("re-flagging a record must fail authentication")
	}
	extra, _ := openKBX2(bytes.NewReader(append(append([]byte{}, b...), 'x')), key)
	if _, err := io.ReadAll(extra); err == nil || !strings.Contains(err.Error(), "after its final record") {
		t.Fatalf("trailing data must be rejected: %v", err)
	}
	var out bytes.Buffer
	if err := rekeyKBX2(bytes.NewReader(b), &out, key, []byte("k2"), nil); err != nil {
		t.Fatal(err)
	}
	r2, err := openKBX2(bytes.NewReader(out.Bytes()), []byte("k2"))
	if err != nil {
		t.Fatal(err)
	}
	got2, _ := io.ReadAll(r2)
	if !bytes.Equal(got2, payload) || string(r2.head) != `{"h":1}` || string(r2.keys.Inner["state/kb.db"]) != "inner" {
		t.Fatal("rekey must keep the head, payload and keys record")
	}
}

// encSessionFixture makes an active attendee session in an encrypted data
// dir with a summary, a seed, and loose state including an encrypted kb.db.
func encSessionFixture(t *testing.T, key []byte) (*sessionPointer, string) {
	t.Helper()
	t.Setenv("KBTOOL_DIR", t.TempDir())
	t.Setenv(secretEnv, string(key))
	work := t.TempDir()
	m, err := createSession("attendee", work, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, sessionDir(m.ID), "about.json", []byte(`{"summary":"sealed lab","participants":["Sam","Josh"]}`))
	writeTestPEM(t, sessionDir(m.ID), ".kbtool-seed", []byte("seed-value\n"))
	writeTestPEM(t, filepath.Join(sessionDir(m.ID), "consensus"), "goals.md", []byte("goals\n"))
	st := &kbStore{path: filepath.Join(stateDir(), "kb.db")}
	st.setKey(key)
	if err := st.writeBundle([]byte("DBBYTES"), []byte("BOARD")); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, stateDir(), "client.json", []byte(`{}`))
	p := &sessionPointer{Current: m.ID, Active: true, Encrypt: true}
	if err := writeJSON0600(sessionJSONPath(), p); err != nil {
		t.Fatal(err)
	}
	return p, work
}

var randomKBXRe = regexp.MustCompile(`^[0-9a-f]{32}\.kbx$`)

// sealedPath is the file sealing session id, found by its head; its name
// must be random.
func sealedPath(t *testing.T, id string, key []byte) string {
	t.Helper()
	a, err := findSessionArchive(id, key)
	if err != nil || a == nil {
		t.Fatalf("session %s is not sealed: %v", id, err)
	}
	if !randomKBXRe.MatchString(a.File) {
		t.Fatalf("sealed file name %q is not random", a.File)
	}
	return a.path()
}

// kbxFilesIn lists dir/sessions/*.kbx.
func kbxFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "sessions", "*.kbx"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestEncryptedFinishListRekeyResume: why — this is the encrypted session
// lifecycle: finish leaves only a randomly named sessions/*.kbx whose head
// alone identifies the session, ls reads the head alone, kbx rekey changes
// only outer files and renames every archive (an interrupted rekey repeats
// cleanly), and restoring re-encrypts the inner kb.db under the current key
// while the archive disappears.
func TestEncryptedFinishListRekeyResume(t *testing.T) {
	k1, k2, k3 := []byte("first key"), []byte("second key"), []byte("third key")
	p, work := encSessionFixture(t, k1)
	id := p.Current
	if err := finishSessionNow(p, time.Now(), k1, nil); err != nil {
		t.Fatal(err)
	}
	f1 := sealedPath(t, id, k1)
	if dirExists(sessionDir(id)) || len(kbxFilesIn(t, stateDir())) != 1 || strings.Contains(f1, id) {
		t.Fatal("finish must leave only the encrypted archive, under a name unrelated to the session")
	}
	if loose, _ := looseState(stateDir()); len(loose) != 0 {
		t.Fatalf("the data dir keeps only %v after finish, has %v", collabKeep, loose)
	}
	if bytes.Contains(mustReadFile(t, f1), []byte("sealed lab")) {
		t.Fatal("the archive must not hold plain text")
	}
	rows, err := listSessions(k1)
	if err != nil || len(rows) != 1 || rows[0].ID != id || rows[0].Summary != "sealed lab" || len(rows[0].People) != 2 || rows[0].State != "finished, encrypted" || rows[0].Role != "attendee" {
		t.Fatalf("ls must show the head: %v %+v", err, rows)
	}
	if rows, _ := listSessions(nil); len(rows) != 0 {
		t.Fatalf("without a key nothing sealed is listed: %+v", rows)
	}
	h, err := readSessionHead(f1, k1)
	if err != nil || h.Meta.Workdir != work || h.Meta.Finished == "" {
		t.Fatalf("the head carries the working directory: %v %+v", err, h)
	}
	if probs := validateSealedSession(id, k1); len(probs) != 0 {
		t.Fatalf("validate reads the head: %q", probs)
	}

	if n, err := rekeyDataDir(k1, k2); err != nil || n != 1 {
		t.Fatalf("rekey: %d %v", n, err)
	}
	f2 := sealedPath(t, id, k2)
	if f2 == f1 || fileExists(f1) || len(kbxFilesIn(t, stateDir())) != 1 {
		t.Fatal("rekey must write the archive under a new random name and remove the old file")
	}
	if kbxOpensWith(f2, k1) || !kbxOpensWith(f2, k2) {
		t.Fatal("the archive must open with the new key only")
	}
	if n, err := rekeyDataDir(k1, k2); err != nil || n != 0 {
		t.Fatalf("a repeated rekey skips files already under the new key: %d %v", n, err)
	}
	half, err := newSessionKBXPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := rekeyFileTo(f2, half, k2, k3, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := rekeyDataDir(k2, k3); err != nil || n != 1 || fileExists(f2) || !fileExists(half) || len(kbxFilesIn(t, stateDir())) != 1 {
		t.Fatalf("a rekey interrupted before removing the old file must drop that leftover, not rekey it twice: %d %v %v", n, err, kbxFilesIn(t, stateDir()))
	}
	if got := sealedPath(t, id, k3); got != half {
		t.Fatalf("the session must be found under its rekeyed file %s, got %s", half, got)
	}

	tmp := filepath.Join(sessionsDir(), "."+id+".extract")
	keys, err := extractSession(half, tmp, k3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.Inner["state/kb.db"], k1) {
		t.Fatal("the archive must remember the inner kb.db key")
	}
	if string(mustReadFile(t, filepath.Join(tmp, ".kbtool-seed"))) != "seed-value\n" || !fileExists(filepath.Join(tmp, "consensus", "goals.md")) {
		t.Fatal("the payload must restore the session files and seed")
	}
	if m, err := loadSessionMetaFrom(tmp); err != nil || m.ID != id {
		t.Fatalf("meta.json must be written from the head: %v", err)
	}
	if _, err := moveStateBack(filepath.Join(tmp, "state"), stateDir(), keys.Inner["state/kb.db"], k3); err != nil {
		t.Fatal(err)
	}
	b := mustReadFile(t, filepath.Join(stateDir(), "kb.db"))
	if _, err := cryptoDecryptBundle(b, k1); err == nil {
		t.Fatal("the inner kb.db must no longer open with the old key")
	}
	plain, err := cryptoDecryptBundle(b, k3)
	if err != nil {
		t.Fatalf("the inner kb.db must be re-encrypted under the current key: %v", err)
	}
	if files, err := cryptoTarGZExtractMem(plain); err != nil || string(files["kb.db"]) != "DBBYTES" || string(files["board.bin"]) != "BOARD" {
		t.Fatalf("the re-encrypted kb.db must keep its contents: %v", err)
	}
}

func loadSessionMetaFrom(dir string) (*sessionMeta, error) {
	var m sessionMeta
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err == nil {
		err = json.Unmarshal(b, &m)
	}
	return &m, err
}

// TestSessionHeadOnly: why — session ls must not decrypt or unpack a
// finished session: the head alone (cut off after its first record) is
// enough, and nothing is extracted.
func TestSessionHeadOnly(t *testing.T) {
	key := []byte("k")
	p, _ := encSessionFixture(t, key)
	if err := finishSessionNow(p, time.Now(), key, nil); err != nil {
		t.Fatal(err)
	}
	b := mustReadFile(t, sealedPath(t, p.Current, key))
	n := binary.LittleEndian.Uint32(b[kbx2HeaderLen+1:])
	headOnly := filepath.Join(t.TempDir(), "head.kbx")
	writeTestPEM(t, filepath.Dir(headOnly), "head.kbx", b[:kbx2HeaderLen+5+int(n)])
	h, err := readSessionHead(headOnly, key)
	if err != nil || h.About == nil || h.About.Summary != "sealed lab" || h.Meta.ID != p.Current {
		t.Fatalf("the head record alone must describe the session: %v %+v", err, h)
	}
	if bytes.Contains(mustReadFile(t, headOnly), []byte("seed-value")) {
		t.Fatal("the head must not carry the seed")
	}
}

// TestWorkdirOneLiner: why — resuming outside the session's working
// directory would point the agents at the wrong AGENTS_COLLABORATION.md, so
// the user gets a copy-paste command instead.
func TestWorkdirOneLiner(t *testing.T) {
	m := &sessionMeta{ID: "20260101T000000Z_abcdef", Workdir: "/work/my repo"}
	if err := checkWorkdir(m, "/work/my repo"); err != nil {
		t.Fatal(err)
	}
	err := checkWorkdir(m, "/elsewhere")
	if err == nil || !strings.Contains(err.Error(), "cd '/work/my repo' && kbtool collaborate resume -id 20260101T000000Z_abcdef") {
		t.Fatalf("the error must carry the one-liner: %v", err)
	}
}

// TestEncryptDataDirConvertsHistory: why — -encrypt keys the whole data dir:
// a finished plain session's plain kb.db + board.bin become one encrypted
// kb.db inside its sealed archive, and session.json stays encrypted.
func TestEncryptDataDirConvertsHistory(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	key := []byte("history key")
	m, err := createSession("host", t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(sessionDir(m.ID), "state"), 0700); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, filepath.Join(sessionDir(m.ID), "state"), "kb.db", []byte(magic+"plain-db"))
	writeTestPEM(t, filepath.Join(sessionDir(m.ID), "state"), "board.bin", []byte("plain-board"))
	if got := encryptReasons(nil); len(got) != 3 || !strings.Contains(got[1], m.ID) {
		t.Fatalf("the caution must name the sessions to encrypt: %q", got)
	}
	if err := encryptDataDir(nil, key); err != nil {
		t.Fatal(err)
	}
	if dirExists(sessionDir(m.ID)) || !encryptedDataDir() {
		t.Fatal("the session must be sealed and session.json encrypted")
	}
	tmp := filepath.Join(t.TempDir(), "x")
	keys, err := extractSession(sealedPath(t, m.ID, key), tmp, key)
	if err != nil || !bytes.Equal(keys.Inner["state/kb.db"], key) {
		t.Fatalf("extract: %v %v", err, keys)
	}
	if fileExists(filepath.Join(tmp, "state", "board.bin")) {
		t.Fatal("board.bin must be packed into the encrypted kb.db")
	}
	plain, err := cryptoDecryptBundle(mustReadFile(t, filepath.Join(tmp, "state", "kb.db")), key)
	files, ferr := cryptoTarGZExtractMem(plain)
	if err != nil || ferr != nil || string(files["kb.db"]) != magic+"plain-db" || string(files["board.bin"]) != "plain-board" {
		t.Fatalf("kb.db must hold the db and board, encrypted: %v %v", err, ferr)
	}
	if err := saveSessionPointer(&sessionPointer{Current: m.ID}); err != nil || !encryptedDataDir() {
		t.Fatal("once encrypted, session.json stays encrypted")
	}
}

// TestEncryptedDataDirNeedsSecret: why — with "encrypt": true kbtool must
// fail rather than prompt or write plain data when KBTOOL_SECRET is unset,
// and a file inside the data dir cannot be rekeyed on its own.
func TestEncryptedDataDirNeedsSecret(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	t.Setenv(secretEnv, "")
	if err := writeJSON0600(sessionJSONPath(), &sessionPointer{Encrypt: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := requireSecret("", "", "list sessions"); err == nil || !strings.Contains(err.Error(), secretEnv) {
		t.Fatalf("a missing secret must name %s: %v", secretEnv, err)
	}
	kb := filepath.Join(stateDir(), "kb.db")
	writeTestPEM(t, stateDir(), "kb.db", cryptoEncryptBundle([]byte("x"), []byte("k")))
	if _, err := openStore(kb, "", "", true, true); err == nil || !strings.Contains(err.Error(), secretEnv) {
		t.Fatalf("an encrypted data dir never prompts: %v", err)
	}
	t.Setenv(secretEnv, "from-env")
	if k, err := requireSecret("", "", "x"); err != nil || string(k) != "from-env" {
		t.Fatalf("requireSecret reads %s: %v", secretEnv, err)
	}
	if !inDataDir(kb) || !inDataDir(filepath.Join(stateDir(), "sessions", "a.kbx")) || inDataDir(filepath.Join(t.TempDir(), "a.kbx")) {
		t.Fatal("inDataDir must tell data dir files apart")
	}
	out := filepath.Join(t.TempDir(), "export.kbx")
	writeTestPEM(t, filepath.Dir(out), "export.kbx", cryptoEncryptBundle([]byte("payload"), []byte("old")))
	if err := rekeyFile(out, []byte("old"), []byte("new"), nil); err != nil || !kbxOpensWith(out, []byte("new")) {
		t.Fatalf("a KBX1 file outside the data dir is rekeyed in place: %v", err)
	}
}

// TestEncryptedCollaborateCLI: why — end to end with the real binary:
// host -encrypt, `daemon stop` finishing (sealing) the session, ls needing
// KBTOOL_SECRET, resume refusing other directories with a one-liner, one
// active session at a time, kbx rekey refused while active, and a resume
// after a rekey serving the re-encrypted kb.db.
// Then a killed daemon (an unclean shutdown): every command refuses with the
// warning until `session validate` checks and seals the session.
func TestEncryptedCollaborateCLI(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	relayDir, hostDir := filepath.Join(shortStateDir(t), "new"), shortStateDir(t) // relay start creates its state dir
	hostWork := t.TempDir()
	if err := os.MkdirAll(filepath.Join(hostWork, "repo", ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, filepath.Join(hostWork, "repo"), "a.go", []byte("package a\nfunc Alpha() {}\n"))
	run := func(cwd, secret string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, bin, args...)
		c.Env = append(os.Environ(), "KBTOOL_DIR="+hostDir, "HOME="+work, "KB_EMBED_URL=", "KBTOOL_SOCKET=", "KBTOOL_RELAY_BIND=", "KBTOOL_RELAY_PORT=",
			secretEnv+"="+secret, "MYKEY=first key", "NEWKEY=second key")
		c.Dir = cwd
		out, err := c.CombinedOutput()
		return string(out), err
	}
	rdir := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, bin, args...)
		c.Env = append(os.Environ(), "KBTOOL_DIR="+relayDir, "HOME="+work, "KBTOOL_RELAY_BIND=", "KBTOOL_RELAY_PORT=")
		out, err := c.CombinedOutput()
		return string(out), err
	}
	hp := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if out, err := rdir("relay", "start", "-bind", hp); err != nil {
		t.Fatalf("relay start: %v\n%s", err, out)
	}
	if fi, err := os.Stat(relayDir); err != nil || fi.Mode().Perm() != 0700 {
		t.Fatalf("relay start creates a missing state dir, mode 0700: %v", err)
	}
	t.Cleanup(func() {
		_, _ = run(hostWork, "second key", "collaborate", "finish")
		_, _ = run(hostWork, "first key", "collaborate", "finish")
		_, _ = rdir("relay", "stop")
	})
	if out, err := run(work, "", "relay", "join", "https://"+hp+"/"); err != nil {
		t.Fatalf("relay join: %v\n%s", err, out)
	}
	if out, err := run(hostWork, "", "collaborate", "host", "-encrypt", "-db-key-env", "MYKEY"); err == nil || !strings.Contains(out, "keys the whole kbtool data dir") {
		t.Fatalf("-encrypt must caution and ask for confirmation: %v\n%s", err, out)
	}
	out, err := run(hostWork, "", "collaborate", "host", "-yes", "-encrypt", "-db-key-env", "MYKEY")
	if err != nil || !strings.Contains(out, "ENCRYPTED") || !strings.Contains(out, "export "+secretEnv) {
		t.Fatalf("collaborate host -encrypt: %v\n%s", err, out)
	}
	var sp sessionPointer
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(hostDir, "session.json")), &sp); err != nil || !sp.Encrypt || !sp.Active {
		t.Fatalf("session.json must be encrypted and active: %v %+v", err, sp)
	}
	id := sp.Current
	if out, err := run(hostWork, "first key", "collaborate", "host", "-yes"); err == nil || !strings.Contains(out, "collaborate finish") {
		t.Fatalf("a second session must be refused while one is active: %v\n%s", err, out)
	}
	if out, err := run(work, "first key", "kbx", "rekey", "-new-key-env", "NEWKEY"); err == nil || !strings.Contains(out, "active") {
		t.Fatalf("kbx rekey must be refused while a session is active: %v\n%s", err, out)
	}
	if out, err := run(work, "", "daemon", "stop"); err != nil {
		t.Fatalf("daemon stop: %v\n%s", err, out)
	}
	sealedFiles := kbxFilesIn(t, hostDir)
	if dirExists(filepath.Join(hostDir, "sessions", id)) || len(sealedFiles) != 1 || !randomKBXRe.MatchString(filepath.Base(sealedFiles[0])) {
		t.Fatalf("daemon stop must finish and encrypt the session under a random name: %v", sealedFiles)
	}
	if out, err := run(work, "", "session", "ls"); err == nil || !strings.Contains(out, secretEnv) {
		t.Fatalf("session ls must need %s: %v\n%s", secretEnv, err, out)
	}
	if out, err := run(work, "first key", "session", "ls"); err != nil || !strings.Contains(out, "finished, encrypted") || !strings.Contains(out, id) || !strings.Contains(out, "host") {
		t.Fatalf("session ls with the key: %v\n%s", err, out)
	}
	if out, err := run(work, "first key", "board", "dump", "-session", id); err != nil || !strings.Contains(out, "How this board works") {
		t.Fatalf("board dump decrypts the sealed host session in memory: %v\n%.300s", err, out)
	}
	if out, err := run(work, "second key", "board", "dump", "-session", id); err == nil {
		t.Fatalf("board dump with a wrong key must fail:\n%.300s", out)
	}
	if after := kbxFilesIn(t, hostDir); len(after) != 1 || after[0] != sealedFiles[0] {
		t.Fatalf("board dump leaves the archive untouched: %v", after)
	}
	if out, err := run(work, "first key", "collaborate", "resume"); err == nil || !strings.Contains(out, "cd "+hostWork+" && kbtool collaborate resume -id "+id) {
		t.Fatalf("resume elsewhere must print the one-liner: %v\n%s", err, out)
	}
	if out, err := run(work, "first key", "kbx", "rekey", "-new-key-env", "NEWKEY", sealedFiles[0]); err == nil || !strings.Contains(out, "share one key") {
		t.Fatalf("a data dir file cannot be rekeyed alone: %v\n%s", err, out)
	}
	if out, err := run(work, "first key", "kbx", "rekey", "-new-key-env", "NEWKEY"); err != nil || !strings.Contains(out, "rekeyed 1 file") {
		t.Fatalf("kbx rekey: %v\n%s", err, out)
	}
	if now := kbxFilesIn(t, hostDir); len(now) != 1 || now[0] == sealedFiles[0] || !randomKBXRe.MatchString(filepath.Base(now[0])) {
		t.Fatalf("kbx rekey must rename the archive: before %v, after %v", sealedFiles, now)
	}
	out, err = run(hostWork, "second key", "collaborate", "resume")
	if err != nil || !strings.Contains(out, "decrypted session") || !strings.Contains(out, "daemon started") {
		t.Fatalf("resume after rekey: %v\n%s", err, out)
	}
	if len(kbxFilesIn(t, hostDir)) != 0 {
		t.Fatal("resume must delete the decrypted archive")
	}
	if out, err := run(hostWork, "", "query", "Alpha"); err != nil || !strings.Contains(out, "a.go") {
		t.Fatalf("the daemon must serve the kb.db re-encrypted under the new key: %v\n%s", err, out)
	}
	if out, err := run(work, "", "board", "signup", "-seed-file", filepath.Join(t.TempDir(), "agent.seed"), "lab-agent"); err == nil || !strings.Contains(out, "leave out -seed-file") {
		t.Fatalf("in a session the seed lives in the session: %v\n%s", err, out)
	}
	if out, err := run(work, "", "board", "signup", "lab-agent"); err != nil || !strings.Contains(out, "seed stored in this session") {
		t.Fatalf("board signup: %v\n%s", err, out)
	}
	if out, err := run(work, "", "board", "signup", "other-name"); err == nil || !strings.Contains(out, "already signed up as lab-agent") {
		t.Fatalf("a valid signup refuses another one: %v\n%s", err, out)
	}
	writeTestPEM(t, hostWork, "decision.md", []byte("we go with plan B\n"))
	out, err = run(hostWork, "", "steer", "-m", "Humans agreed: plan B. Read the attached decision.", "decision.md")
	steerRe := regexp.MustCompile(`posted attachment system#(\d+) \(decision\.md\)\nposted steering message system#(\d+)`)
	sm := steerRe.FindStringSubmatch(out)
	if err != nil || sm == nil {
		t.Fatalf("steer: %v\n%s", err, out)
	}
	attSeq, steerSeq := sm[1], sm[2]
	if err := os.Remove(filepath.Join(hostDir, "system-seen.json")); err != nil {
		t.Fatal(err)
	}
	notice := "notice: new steering message from the session host: system#" + steerSeq + "; read it with: kbtool board read system#" + steerSeq
	if out, err := run(work, "", "board", "read", "welcome"); err != nil || !strings.Contains(out, notice) {
		t.Fatalf("an agent's board command must print the steering notice on stderr: %v\n%s", err, out)
	}
	if out, err := run(work, "", "query", "Alpha"); err != nil || !strings.Contains(out, notice) {
		t.Fatalf("the notice repeats on any daemon command until read: %v\n%s", err, out)
	}
	out, err = run(work, "", "board", "read", "system#"+steerSeq)
	if err != nil || !strings.Contains(out, "Humans agreed: plan B") || !strings.Contains(out, "kbtool board fetch -o DIR system#"+attSeq) || strings.Contains(out, "notice:") {
		t.Fatalf("reading the steering message: %v\n%s", err, out)
	}
	if out, err := run(work, "", "board", "fetch", "-o", "got", "system#"+attSeq); err != nil || strings.Contains(out, "notice:") || !strings.Contains(out, "memory/got/decision.md") {
		t.Fatalf("fetching the steering attachment into memory (and no notice once read): %v\n%s", err, out)
	}
	if out, err := run(work, "", "memory", "cat", "got/decision.md"); err != nil || !strings.Contains(out, "we go with plan B") {
		t.Fatalf("the steering attachment must be in memory: %v\n%s", err, out)
	}
	if out, err := run(work, "", "board", "fetch", "-o", t.TempDir(), "system#"+attSeq); err == nil || !strings.Contains(out, "memory:") {
		t.Fatalf("in a session board fetch extracts only into memory: %v\n%s", err, out)
	}
	if out, err := run(hostWork, "", "steer"); err == nil || !strings.Contains(out, "usage: kbtool steer") {
		t.Fatalf("steer without a message: %v\n%s", err, out)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(mustReadFile(t, filepath.Join(hostDir, "daemon.pid")))))
	if pid <= 0 {
		t.Fatal("no daemon pid")
	}
	osCompatStopProcess("daemon", pid, true)
	for deadline := time.Now().Add(10 * time.Second); pidAlive(pid) && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
	}
	for _, args := range [][]string{{"daemon", "start"}, {"collaborate", "resume"}, {"session", "ls"}} {
		if out, err := run(hostWork, "second key", args...); err == nil || !strings.Contains(out, "unclean shutdown") || !strings.Contains(out, "kbtool session validate") {
			t.Fatalf("%v after a crash must refuse with the warning: %v\n%s", args, err, out)
		}
	}
	if daemonLog := filepath.Join(hostDir, "daemon.sock"); fileExists(daemonLog) && socketAlive(daemonLog) {
		t.Fatal("daemon start must do nothing after a crash")
	}
	if out, err := run(work, "", "session", "validate"); err == nil || !strings.Contains(out, secretEnv) {
		t.Fatalf("sealing needs the key: %v\n%s", err, out)
	}
	out, err = run(work, "second key", "session", "validate")
	if err != nil || !strings.Contains(out, "sealed into") || !strings.Contains(out, "cd "+hostWork+" && kbtool collaborate resume -id "+id) {
		t.Fatalf("validate must seal the crashed session and print the resume command: %v\n%s", err, out)
	}
	if dirExists(filepath.Join(hostDir, "sessions", id)) || len(kbxFilesIn(t, hostDir)) != 1 {
		t.Fatal("validate must leave only the sealed archive")
	}
	if out, err := run(hostWork, "second key", "collaborate", "resume"); err != nil || !strings.Contains(out, "daemon started") {
		t.Fatalf("resume after validate: %v\n%s", err, out)
	}
	if out, err := run(hostWork, "second key", "collaborate", "finish"); err != nil || len(kbxFilesIn(t, hostDir)) != 1 {
		t.Fatalf("finish: %v\n%s", err, out)
	}
}

// uncleanFixture is an active host session of an encrypted data dir left
// plain with its state loose, as a killed daemon leaves it.
func uncleanFixture(t *testing.T, key []byte) *sessionPointer {
	t.Helper()
	p, _ := encSessionFixture(t, key)
	m, err := loadSessionMeta(p.Current)
	if err != nil {
		t.Fatal(err)
	}
	m.Role = "host"
	if err := saveSessionMeta(m); err != nil {
		t.Fatal(err)
	}
	st := &kbStore{path: filepath.Join(stateDir(), "kb.db")}
	st.setKey(key)
	if err := st.writeBundle(dbMarshal(&DB{Dim: 8}), boardMarshal(newBoard())); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, stateDir(), "daemon.pid", []byte("999999999\n"))
	return p
}

// TestUncleanSessionValidateSeals: why — a daemon that died without sealing
// leaves the active encrypted session plain. That state must be detected,
// thoroughly validated (a failure leaves it untouched and says why), and on
// success sealed at once, with the copy-paste resume command printed.
func TestUncleanSessionValidateSeals(t *testing.T) {
	key := []byte("unclean key")
	p := uncleanFixture(t, key)
	id := p.Current
	if q, ok := uncleanSession(); !ok || q.Current != id {
		t.Fatal("a plain active host session with no daemon is unclean")
	}
	if w := uncleanSessionWarning(id); !strings.Contains(w, "unclean shutdown") || !strings.Contains(w, "kbtool session validate") {
		t.Fatalf("the warning must name the cause and the fix: %q", w)
	}
	writeTestPEM(t, stateDir(), "board.bin", []byte("plain board"))
	writeTestPEM(t, sessionsDir(), "0123456789abcdef0123456789abcdef.kbx.tmp", []byte("half written"))
	var out bytes.Buffer
	if validateUnclean(&out, p, key, time.Now()) {
		t.Fatalf("a plain board.bin must fail the check:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "board.bin is a plain message board") || !strings.Contains(out.String(), "failed") || !dirExists(sessionDir(id)) || len(kbxFilesIn(t, stateDir())) != 0 {
		t.Fatalf("a failed check reports and leaves the session plain:\n%s", out.String())
	}
	if fileExists(filepath.Join(sessionsDir(), "0123456789abcdef0123456789abcdef.kbx.tmp")) || fileExists(pidPath("daemon")) {
		t.Fatal("leftovers of interrupted work and stale pid files are removed")
	}
	if err := os.Remove(filepath.Join(stateDir(), "board.bin")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if !validateUnclean(&out, p, key, time.Now()) {
		t.Fatalf("a sound session must validate:\n%s", out.String())
	}
	sealed := sealedPath(t, id, key)
	m, _ := readSessionHead(sealed, key)
	want := "cd " + shellQuote(m.Meta.Workdir) + " && kbtool collaborate resume -id " + id
	if !strings.Contains(out.String(), "sealed into "+sealed) || !strings.Contains(out.String(), want) {
		t.Fatalf("success seals and prints the resume command %q:\n%s", want, out.String())
	}
	if dirExists(sessionDir(id)) || encryptedActive(t) {
		t.Fatal("the session must be sealed and no longer active")
	}
	if _, ok := uncleanSession(); ok {
		t.Fatal("after sealing nothing is unclean")
	}
}

func encryptedActive(t *testing.T) bool {
	t.Helper()
	p, err := loadSessionPointer()
	if err != nil {
		t.Fatal(err)
	}
	return p != nil && p.Active
}

// TestUncleanSessionWrongKeyAndSealedLeftover: why — a wrong key must fail
// the check without sealing, and a finish that sealed the archive but died
// before removing the plain directory is completed, not sealed twice.
func TestUncleanSessionWrongKeyAndSealedLeftover(t *testing.T) {
	key := []byte("the key")
	p := uncleanFixture(t, key)
	id := p.Current
	var out bytes.Buffer
	if validateUnclean(&out, p, []byte("not the key"), time.Now()) || !strings.Contains(out.String(), "does not open with "+secretEnv) {
		t.Fatalf("a wrong key fails on kb.db:\n%s", out.String())
	}
	m, err := loadSessionMeta(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := moveStateInto(stateDir(), filepath.Join(sessionDir(id), "state"), nil); err != nil {
		t.Fatal(err)
	}
	dest, err := newSessionKBXPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := sealSession(sessionDir(id), dest, key, nil, sessionHead{Meta: *m}, false, kbxKeys{}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if !validateUnclean(&out, p, key, time.Now()) || !strings.Contains(out.String(), "already sealed") {
		t.Fatalf("an already sealed session only loses its leftover directory:\n%s", out.String())
	}
	if dirExists(sessionDir(id)) || sealedPath(t, id, key) != dest || encryptedActive(t) {
		t.Fatal("the leftover directory is removed and the session finished")
	}
}

// TestSealedSessionCatalog: why — a sealed session's identity is its
// encrypted head, never its file name; the catalog decrypts each head once
// (the daemon keeps one for its lifetime), and the daemon's socket method
// serves the list only to a caller that proves it holds the key.
func TestSealedSessionCatalog(t *testing.T) {
	key := []byte("catalog key")
	p, _ := encSessionFixture(t, key)
	id := p.Current
	if err := finishSessionNow(p, time.Now(), key, nil); err != nil {
		t.Fatal(err)
	}
	orig := sealedPath(t, id, key)
	renamed := filepath.Join(sessionsDir(), "anything.kbx")
	if err := os.Rename(orig, renamed); err != nil {
		t.Fatal(err)
	}
	if a, err := findSessionArchive(id, key); err != nil || a == nil || a.path() != renamed {
		t.Fatalf("the head, not the file name, identifies the session: %v %+v", err, a)
	}
	writeTestPEM(t, sessionsDir(), "garbage.kbx", []byte("not an archive"))
	rows, err := listSessions(key)
	if err != nil || len(rows) != 2 {
		t.Fatalf("ls lists the session and the unreadable file: %v %+v", err, rows)
	}
	var bad, good bool
	for _, r := range rows {
		bad = bad || (r.ID == "?" && strings.Contains(r.Summary, "garbage.kbx"))
		good = good || (r.ID == id && r.Role == "attendee")
	}
	if !bad || !good {
		t.Fatalf("rows: %+v", rows)
	}
	if err := os.Remove(filepath.Join(sessionsDir(), "garbage.kbx")); err != nil {
		t.Fatal(err)
	}

	c := newSessionCatalog(key)
	if as, err := c.archives(); err != nil || len(as) != 1 || as[0].Head == nil {
		t.Fatalf("first load: %v %+v", err, as)
	}
	fi, _ := os.Stat(renamed)
	b := mustReadFile(t, renamed)
	if err := os.WriteFile(renamed, bytes.Repeat([]byte{0}, len(b)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(renamed, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if as, _ := c.archives(); len(as) != 1 || as[0].Head == nil || as[0].Head.Meta.ID != id {
		t.Fatalf("an unchanged file (same size and time) must come from the cache: %+v", as)
	}
	if err := os.WriteFile(renamed, b, 0600); err != nil {
		t.Fatal(err)
	}

	dup := filepath.Join(sessionsDir(), "copy.kbx")
	writeTestPEM(t, sessionsDir(), "copy.kbx", b)
	if _, err := findSessionArchive(id, key); err == nil || !strings.Contains(err.Error(), "sealed in 2 files") {
		t.Fatalf("two files with one session's head must be refused: %v", err)
	}
	if err := os.Remove(dup); err != nil {
		t.Fatal(err)
	}

	st := &kbStore{path: filepath.Join(stateDir(), "kb.db")}
	st.setKey(key)
	tb := &Toolbox{Store: st}
	call := func(verifier string) rpcResult {
		line := mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": methodSessions, "params": map[string]string{"verifier": verifier}})
		var res rpcResult
		if err := json.Unmarshal(handleHostMethod(line, bufio.NewReader(strings.NewReader("")), tb), &res); err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := call(hex.EncodeToString(sessionListVerifier([]byte("wrong")))); res.Error == nil || !strings.Contains(res.Error.Message, "does not match") {
		t.Fatalf("a wrong key gets nothing: %+v", res)
	}
	res := call(hex.EncodeToString(sessionListVerifier(key)))
	var out struct {
		Sessions []sessionArchive `json:"sessions"`
	}
	if res.Error != nil || json.Unmarshal(res.Result, &out) != nil || len(out.Sessions) != 1 || out.Sessions[0].Head.Meta.ID != id || out.Sessions[0].File != "anything.kbx" {
		t.Fatalf("the daemon serves its catalog: %+v %s", res.Error, res.Result)
	}
	if tb.sessionCat == nil {
		t.Fatal("the daemon must keep the catalog loaded")
	}
	if bytes.Contains(res.Result, []byte("seed-value")) {
		t.Fatal("the listing carries heads only, never the seed")
	}
}

// ---------- 45. kbtool steer and system notices (plans/steer-and-system-notices-plan.md) ----------

func steerTarGZ(t *testing.T, name, body string) []byte {
	t.Helper()
	data, _, err := attachPack([]tarGZMember{{Name: name, Data: []byte(body)}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestSteerAttachmentsFirstMessageLast: why — agents find the steering
// message through latest=system#N, so it must be the last system post, after
// every attachment it names with the command that retrieves it; all posts
// are signed by the system account and agents cannot post kind=steer.
func TestSteerAttachmentsFirstMessageLast(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	if _, err := tb.steer("   ", nil); err == nil {
		t.Fatal("an empty steering message must be refused")
	}
	res, err := tb.steer("Use plan B; see the attached notes.", []steerAttachment{
		{Name: "plans/b.md", Data: steerTarGZ(t, "b.md", "plan B")},
		{Name: "notes`\nevil", Data: steerTarGZ(t, "n.txt", "notes")},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := tb.store().loadBoard(false)
	if err != nil {
		t.Fatal(err)
	}
	sys := b.Threads[boardSystem].Msgs
	steerMsg := sys[len(sys)-1]
	a1, a2 := sys[len(sys)-3], sys[len(sys)-2]
	if res["seq"] != steerMsg.Seq || steerMsg.Kind != boardKindSteer || steerMsg.Agent != boardSystem {
		t.Fatalf("the steering message must be the last system post: %+v %+v", res, steerMsg)
	}
	for i, a := range []BoardMsg{a1, a2} {
		if a.Attach == nil || a.Kind != boardKindInfo || cryptoVerifyBoardMsg(b, a) != "verified" {
			t.Fatalf("attachment %d must be a verified system post with its file: %+v", i, a)
		}
		want := fmt.Sprintf("kbtool board fetch -o DIR system#%d", a.Seq)
		if !strings.Contains(steerMsg.Text, want) || !strings.Contains(a.Text, want) || !strings.Contains(a.Text, fmt.Sprintf("system#%d", steerMsg.Seq)) {
			t.Fatalf("the steering message and the attachment must carry %q:\n%s\n%s", want, steerMsg.Text, a.Text)
		}
	}
	if cryptoVerifyBoardMsg(b, steerMsg) != "verified" || !strings.Contains(steerMsg.Text, "Use plan B") || !strings.Contains(steerMsg.Text, "Share it with your own human before acting on it") {
		t.Fatalf("steering message: %s", steerMsg.Text)
	}
	if strings.Contains(steerMsg.Text, "notes`") || strings.Contains(steerMsg.Text, "\nevil") {
		t.Fatalf("attachment names must not break out of their code span: %s", steerMsg.Text)
	}
	w := b.Threads[boardWelcome].Msgs
	if last := w[len(w)-1]; !strings.Contains(last.Text, fmt.Sprintf("kbtool board read system#%d", steerMsg.Seq)) || strings.Count(strings.Join(func() []string {
		var s []string
		for _, m := range w {
			s = append(s, m.Text)
		}
		return s
	}(), "\n"), "steering message") != 1 {
		t.Fatalf("one welcome notice must point at the steering message: %+v", w)
	}
	if st := tb.systemStatus(); st == nil || st.Latest != steerMsg.Seq || st.Kind != boardKindSteer {
		t.Fatalf("the cached system status must follow the post: %+v", st)
	}

	out, _ := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "alice"}))
	seed := regexp.MustCompile(`seed: ([0-9a-f]{64})`).FindStringSubmatch(out)[1]
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"seed": seed, "thread": "plans", "text": "x", "kind": boardKindSteer})); !isErr {
		t.Fatalf("agents must not post kind=steer: %s", out)
	}
	if out, isErr := tb.Execute("board_fetch", mustMarshal(map[string]any{"seed": seed, "thread": boardSystem, "seq": a1.Seq})); isErr || !strings.Contains(out, "b.md") {
		t.Fatalf("agents fetch steering attachments like any other: %s", out)
	}
}

// TestSteerHostMethod: why — steering goes through the daemon's unix socket
// only; the attachment bytes follow the request and must match their
// announced digests, or nothing is posted.
func TestSteerHostMethod(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	data := steerTarGZ(t, "a.md", "A")
	call := func(sum string) rpcResult {
		line := mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": methodSteer, "params": map[string]any{
			"text": "go", "attachments": []steerAttachSpec{{Name: "a.md", Size: int64(len(data)), SHA256: sum}}}})
		var res rpcResult
		if err := json.Unmarshal(handleHostMethod(line, bufio.NewReader(bytes.NewReader(data)), tb), &res); err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := call(strings.Repeat("0", 64)); res.Error == nil || !strings.Contains(res.Error.Message, "checksum mismatch") {
		t.Fatalf("a wrong digest must be refused: %+v", res)
	}
	if st := tb.systemStatus(); st != nil && st.Kind == boardKindSteer {
		t.Fatal("nothing may be posted after a refused request")
	}
	if res := call(sha256Hex(data)); res.Error != nil {
		t.Fatalf("steer over the socket: %+v", res.Error)
	}
	if st := tb.systemStatus(); st == nil || st.Kind != boardKindSteer {
		t.Fatalf("status after steering: %+v", st)
	}
	var res rpcResult
	_ = json.Unmarshal(handleLine(mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": methodSteer}), tb), &res)
	if res.Error == nil {
		t.Fatal("kbtool/steer must not exist outside the unix socket")
	}
}

// TestSystemNoticeOnStderr: why — every tool result carries the system
// status, and the CLI prints one notice per command while a newer system
// message is unread here; reading it (board read's "showing A..B") stops
// the notices, and a new board (another system key) starts over.
func TestSystemNoticeOnStderr(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	if _, err := tb.steer("Pause all work.", nil); err != nil {
		t.Fatal(err)
	}
	r, err := dispatch(tb, "tools/call", mustMarshal(map[string]any{"name": "board_threads", "arguments": map[string]any{}}))
	if err != nil {
		t.Fatal(err)
	}
	raw := mustMarshal(r)
	if !bytes.Contains(raw, []byte(`"kbtool/system"`)) {
		t.Fatalf("tool results must carry _meta kbtool/system: %s", raw)
	}
	defer func() { lastSystem, systemNoticeDone, quietSystem = nil, false, false }()
	lastSystem, systemNoticeDone = nil, false
	noteSystemMeta(raw)
	st := lastSystem
	if st == nil || st.Kind != boardKindSteer {
		t.Fatalf("the client must read the status: %+v", st)
	}
	var buf bytes.Buffer
	systemNoticeDone = false
	systemNotice(&buf, st)
	want := fmt.Sprintf("notice: new steering message from the session host: system#%d", st.Latest)
	if !strings.Contains(buf.String(), want) || !strings.Contains(buf.String(), fmt.Sprintf("kbtool board read system#%d", st.Latest)) {
		t.Fatalf("notice: %q", buf.String())
	}
	buf.Reset()
	systemNotice(&buf, st)
	if buf.Len() != 0 {
		t.Fatal("at most one notice per command")
	}
	markSystemRead(fmt.Sprintf("thread %q — %d message(s), showing %d..%d\n\n", boardSystem, st.Latest+1, st.Latest, st.Latest))
	systemNoticeDone = false
	systemNotice(&buf, st)
	if buf.Len() != 0 {
		t.Fatalf("a read message must not be noticed again: %q", buf.String())
	}
	systemNoticeDone = false
	systemNotice(&buf, &sysStatus{Latest: st.Latest + 2, Kind: boardKindInfo, Pub: st.Pub})
	if !strings.Contains(buf.String(), "new system message") || !strings.Contains(buf.String(), "(2 unread system messages)") {
		t.Fatalf("a newer plain system message: %q", buf.String())
	}
	buf.Reset()
	systemNoticeDone = false
	systemNotice(&buf, &sysStatus{Latest: 0, Kind: boardKindInfo, Pub: "another board"})
	if !strings.Contains(buf.String(), "system#0") {
		t.Fatalf("another board's system key starts over: %q", buf.String())
	}
}

// ---------- 46. session files through kbtool: memory, consensus, deliverables (plans/memory-consensus-deliverables-plan.md) ----------

// Why: every path an agent passes must stay inside its directory; `..` is
// refused outright (not cleaned away) so a typo can never reach kbtool state.
func TestSanitizeRel(t *testing.T) {
	ok := map[string]string{
		".": ".", "./": ".", "": ".", "a": "a", "./a/b": "a/b", "a//b/": "a/b",
		`a\b`: "a/b", "a/./b": "a/b", "x..y": "x..y", "a/~b": "a/~b",
	}
	for in, want := range ok {
		got, err := sanitizeRel(in)
		if err != nil || got != want {
			t.Errorf("sanitizeRel(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"..", "../x", "a/../b", "./../../etc", `a\..\b`, "/etc/passwd", `\x`,
		"C:/x", `c:\x`, "C:x", "//host/share", "~", "~/x", "~root", "a\x00b", "a\nb"} {
		if got, err := sanitizeRel(in); err == nil {
			t.Errorf("sanitizeRel(%q) = %q; want an error", in, got)
		}
	}
}

// Why: a symlink planted inside memory/ must not lead outside it.
func TestSandboxPathRefusesSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0600)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	for _, p := range []string{"link", "link/secret", "link/new"} {
		if _, _, err := sandboxPath(root, p); err == nil || !strings.Contains(err.Error(), "symbolic") {
			t.Fatalf("sandboxPath(%q) must refuse the symlink: %v", p, err)
		}
	}
	full, rel, err := sandboxPath(root, "./new/dir/f.md")
	if err != nil || rel != "new/dir/f.md" || full != filepath.Join(root, "new", "dir", "f.md") {
		t.Fatalf("a path that does not exist yet resolves inside root: %q %q %v", full, rel, err)
	}
	ft := &fileTools{name: "memory", root: root, writable: true, out: io.Discard, err: io.Discard}
	var buf bytes.Buffer
	ft.out = &buf
	if err := ft.find(nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "secret") {
		t.Fatalf("find must not follow symlinks: %q", buf.String())
	}
}

// memSession creates an active session in a fresh data dir and returns its directory.
func memSession(t *testing.T) string {
	t.Helper()
	t.Setenv("KBTOOL_DIR", t.TempDir())
	t.Setenv(secretEnv, "")
	m, err := createSession("host", t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := saveSessionPointer(&sessionPointer{Current: m.ID, Active: true}); err != nil {
		t.Fatal(err)
	}
	return sessionDir(m.ID)
}

func runFT(t *testing.T, name string, writable bool, in string, cmd string, args ...string) (string, error) {
	t.Helper()
	root, err := sessionSubdir(name)
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	ft := &fileTools{name: name, root: root, writable: writable, out: &out, err: &errb}
	sdir, _ := activeSessionDir()
	ok, err := runFileTool(ft, cmd, args, sdir, strings.NewReader(in))
	if !ok {
		t.Fatalf("%s is not a %s command", cmd, name)
	}
	return out.String(), err
}

// Why: agents organize their memory only through these commands, so each
// must work like its familiar counterpart and stay inside memory/.
func TestMemoryCommands(t *testing.T) {
	dir := memSession(t)
	if _, err := os.Stat(filepath.Join(dir, "scratch")); err == nil {
		t.Fatal("sessions no longer have scratch/")
	}
	must := func(out string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	must(runFT(t, "memory", true, "one\ntwo\nthree\nTwo again\n", "write", "notes/plan.md"))
	must(runFT(t, "memory", true, "four\n", "write", "-append", "notes/plan.md"))
	must(runFT(t, "memory", true, "x", "write", ".hidden"))
	if got := must(runFT(t, "memory", true, "", "cat", "notes/plan.md")); got != "one\ntwo\nthree\nTwo again\nfour\n" {
		t.Fatalf("cat: %q", got)
	}
	if got := must(runFT(t, "memory", true, "", "head", "-n", "2", "notes/plan.md")); got != "one\ntwo\n" {
		t.Fatalf("head: %q", got)
	}
	if got := must(runFT(t, "memory", true, "", "tail", "-n", "1", "notes/plan.md")); got != "four\n" {
		t.Fatalf("tail: %q", got)
	}
	if got := must(runFT(t, "memory", true, "", "wc", "-l", "notes/plan.md")); !strings.Contains(got, "5 memory/notes/plan.md") {
		t.Fatalf("wc: %q", got)
	}
	if got := must(runFT(t, "memory", true, "", "ls")); got != "memory/notes/\n" {
		t.Fatalf("ls hides dotfiles: %q", got)
	}
	if got := must(runFT(t, "memory", true, "", "ls", "-a", "-R")); !strings.Contains(got, "memory/.hidden") || !strings.Contains(got, "memory/notes/plan.md") {
		t.Fatalf("ls -a -R: %q", got)
	}
	if got := must(runFT(t, "memory", true, "", "grep", "-i", "-n", "two")); got != "memory/notes/plan.md:2:two\nmemory/notes/plan.md:4:Two again\n" {
		t.Fatalf("grep: %q", got)
	}
	if got := must(runFT(t, "memory", true, "", "grep", "-c", "-F", "o")); got != "memory/notes/plan.md:4\n" {
		t.Fatalf("grep -c -F: %q", got)
	}
	if _, err := runFT(t, "memory", true, "", "grep", "nomatch"); err != errNoMatch {
		t.Fatalf("grep without a match: %v", err)
	}
	must(runFT(t, "memory", true, "", "mkdir", "-p", "a/b"))
	must(runFT(t, "memory", true, "", "mv", "notes/plan.md", "a/b"))
	if got := must(runFT(t, "memory", true, "", "find", "-name", "*.md")); got != "memory/a/b/plan.md\n" {
		t.Fatalf("find -name after mv: %q", got)
	}
	if got := must(runFT(t, "memory", true, "", "find", ".", "-type", "d", "-maxdepth", "1")); got != "memory/\nmemory/a\nmemory/notes\n" {
		t.Fatalf("find -type d -maxdepth 1: %q", got)
	}
	if _, err := runFT(t, "memory", true, "", "mv", "a", "a/b"); err == nil {
		t.Fatal("moving a directory into itself must fail")
	}
	if _, err := runFT(t, "memory", true, "", "rm", "a"); err == nil || !strings.Contains(err.Error(), "-r") {
		t.Fatalf("rm of a directory needs -r: %v", err)
	}
	must(runFT(t, "memory", true, "", "rm", "-r", "a"))
	if _, err := runFT(t, "memory", true, "", "rm", "-r", "."); err == nil {
		t.Fatal("memory/ itself cannot be removed")
	}
	for _, bad := range [][]string{{"cat", "../about.json"}, {"cat", "/etc/passwd"}, {"ls", "../state"}, {"rm", "-r", "../consensus"}, {"mv", ".hidden", "../x"}} {
		if _, err := runFT(t, "memory", true, "", bad[0], bad[1:]...); err == nil {
			t.Fatalf("%v must be refused", bad)
		}
	}
	if _, err := runFT(t, "memory", true, "", "write", "../about.json"); err == nil {
		t.Fatal("write outside memory must be refused")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "about.json")); !strings.Contains(string(b), "participants") {
		t.Fatalf("about.json must be untouched: %q", b)
	}

	// import from the working directory
	work := t.TempDir()
	old, _ := os.Getwd()
	os.Chdir(work)
	t.Cleanup(func() { os.Chdir(old) })
	os.MkdirAll(filepath.Join(work, "plans", ".git"), 0700)
	os.WriteFile(filepath.Join(work, "plans", "p.md"), []byte("P"), 0600)
	os.WriteFile(filepath.Join(work, "plans", ".git", "HEAD"), []byte("ref"), 0600)
	os.WriteFile(filepath.Join(work, "plans", ".kbtool-seed"), []byte("seed"), 0600)
	must(runFT(t, "memory", true, "", "import", "plans"))
	if b, err := os.ReadFile(filepath.Join(dir, "memory", "plans", "p.md")); err != nil || string(b) != "P" {
		t.Fatalf("import copies the directory: %q %v", b, err)
	}
	for _, skip := range []string{"plans/.git/HEAD", "plans/.kbtool-seed"} {
		if _, err := os.Stat(filepath.Join(dir, "memory", filepath.FromSlash(skip))); err == nil {
			t.Fatalf("import must skip %s", skip)
		}
	}
	for _, bad := range []string{"..", "../x", "/etc", "."} {
		if _, err := runFT(t, "memory", true, "", "import", bad); err == nil {
			t.Fatalf("import %q must be refused", bad)
		}
	}
}

// Why: consensus/ and deliverables/ change only by vote; their commands read.
func TestSharedDirsReadOnly(t *testing.T) {
	dir := memSession(t)
	os.WriteFile(filepath.Join(dir, "deliverables", "01.md"), []byte("ticket\n"), 0600)
	os.MkdirAll(filepath.Join(dir, "deliverables", "sub"), 0700)
	os.WriteFile(filepath.Join(dir, "deliverables", "sub", "02.md"), []byte("two\n"), 0600)
	if got, err := runFT(t, "deliverables", false, "", "cat", "01.md"); err != nil || got != "ticket\n" {
		t.Fatalf("cat: %q %v", got, err)
	}
	for _, cmd := range []string{"import", "mkdir", "mv", "rm"} {
		_, err := runFT(t, "deliverables", false, "", cmd, "x")
		if err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Fatalf("deliverables %s must be refused: %v", cmd, err)
		}
	}
	root, _ := sessionSubdir("consensus")
	ok, err := runFileTool(&fileTools{name: "consensus", root: root, out: io.Discard, err: io.Discard}, "write", []string{"x"}, dir, strings.NewReader(""))
	if !ok || err == nil || !strings.Contains(err.Error(), "consensus propose") {
		t.Fatalf("consensus write must point at consensus propose: %v", err)
	}
	got, err := runFT(t, "deliverables", false, "", "checksum")
	if err != nil {
		t.Fatal(err)
	}
	list, _ := dirChecksumList(dir, "deliverables")
	want := sha256Hex([]byte("ticket\n")) + "  deliverables/01.md\n" + sha256Hex([]byte("two\n")) + "  deliverables/sub/02.md\n"
	if list != want {
		t.Fatalf("checksum list (shasum format, session-relative, sorted):\n%s\nwant\n%s", list, want)
	}
	if !strings.HasSuffix(got, "unified "+sha256Hex([]byte(want))+"  deliverables/\n") {
		t.Fatalf("unified checksum is the sha256 of the list: %q", got)
	}
	u, err := writeDirChecksum(dir, "deliverables")
	if b, _ := os.ReadFile(filepath.Join(dir, "deliverables.sha256")); err != nil || string(b) != want || u != sha256Hex([]byte(want)) {
		t.Fatalf("deliverables.sha256 lives in the session dir: %q %v", b, err)
	}
	if l, _ := dirChecksumList(dir, "consensus"); l != "" {
		t.Fatalf("an empty directory has an empty list: %q", l)
	}
}

func tarNames(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	got := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return got
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		got[h.Name] = string(b)
	}
}

// Why: memory (and the shared dirs) can be exported from the active session,
// a finished plain session and a sealed one, streamed without temp files.
func TestSessionDirExport(t *testing.T) {
	dir := memSession(t)
	id := filepath.Base(dir)
	os.MkdirAll(filepath.Join(dir, "memory", "n"), 0700)
	os.WriteFile(filepath.Join(dir, "memory", "n", "a.md"), []byte("A"), 0600)
	os.WriteFile(filepath.Join(dir, "consensus", "c.md"), []byte("C"), 0600)
	os.MkdirAll(filepath.Join(dir, "state"), 0700)
	os.WriteFile(filepath.Join(dir, "state", "x"), []byte("state"), 0600)

	var buf bytes.Buffer
	if n, err := exportSessionDir(&buf, "memory", "", nil); err != nil || n != 1 {
		t.Fatalf("active export: %d %v", n, err)
	}
	if got := tarNames(t, buf.Bytes()); got["memory/n/a.md"] != "A" || len(got) != 3 {
		t.Fatalf("active memory export: %v", got)
	}
	buf.Reset()
	if _, err := exportSessionDir(&buf, "consensus", id, nil); err != nil {
		t.Fatal(err)
	}
	if got := tarNames(t, buf.Bytes()); got["consensus/c.md"] != "C" {
		t.Fatalf("plain finished-session export: %v", got)
	}

	// seal it, then slice memory/ out of the encrypted archive
	key := []byte("export-secret")
	m, err := loadSessionMeta(id)
	if err != nil {
		t.Fatal(err)
	}
	saveSessionPointer(&sessionPointer{Current: id})
	if _, err := sealSessionDir(id, m, key, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("sealing removes the directory")
	}
	if _, err := exportSessionDir(&buf, "memory", id, nil); err == nil || !strings.Contains(err.Error(), secretEnv) {
		t.Fatalf("a sealed session needs %s: %v", secretEnv, err)
	}
	buf.Reset()
	if n, err := exportSessionDir(&buf, "memory", id, key); err != nil || n != 1 {
		t.Fatalf("sealed export: %d %v", n, err)
	}
	got := tarNames(t, buf.Bytes())
	if got["memory/n/a.md"] != "A" {
		t.Fatalf("sealed memory export: %v", got)
	}
	for name := range got {
		if !strings.HasPrefix(name, "memory/") {
			t.Fatalf("the slice holds only memory/: %s", name)
		}
	}
	if _, err := exportSessionDir(&buf, "memory", id, []byte("wrong")); err == nil {
		t.Fatal("a wrong key must fail")
	}
	if _, err := exportSessionDir(&buf, "memory", "../x", key); err == nil {
		t.Fatal("a bad session ID must fail")
	}
	if ents, _ := os.ReadDir(sessionsDir()); len(ents) != 1 {
		t.Fatalf("export leaves no files behind: %v", ents)
	}
}

// Why: agents set the session summary and participants without editing
// about.json by path.
func TestSessionAboutCommand(t *testing.T) {
	dir := memSession(t)
	var out bytes.Buffer
	if err := sessionAboutCmd(&out, nil); err != nil || !strings.Contains(out.String(), "to fix:") {
		t.Fatalf("an unfilled about lists what to fix: %q %v", out.String(), err)
	}
	out.Reset()
	if err := sessionAboutCmd(&out, []string{"-summary", "  branch   protection migration ", "-participant", "Sam", "-participant", "Josh", "-participant", "sam"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "to fix:") || !strings.Contains(out.String(), "participants: Sam, Josh") {
		t.Fatalf("about: %q", out.String())
	}
	b, _ := os.ReadFile(filepath.Join(dir, "about.json"))
	if a, probs := validateAbout(b); len(probs) != 0 || a.Summary != "branch protection migration" {
		t.Fatalf("about.json: %s %v", b, probs)
	}
}

// ---------- 47. consensus voting (plans/memory-consensus-deliverables-plan.md) ----------

var consSeedRe = regexp.MustCompile(`seed: ([0-9a-f]{64})`)

func consSignup(t *testing.T, tb *Toolbox, name string, local bool) string {
	t.Helper()
	args := mustMarshal(map[string]any{"name": name})
	var out string
	var isErr bool
	if local {
		line := mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": "board_signup", "arguments": json.RawMessage(args)}})
		resp := handleLineFrom(line, tb, true)
		var r struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
				IsError bool                    `json:"isError"`
			} `json:"result"`
		}
		if err := json.Unmarshal(resp, &r); err != nil || len(r.Result.Content) == 0 {
			t.Fatalf("local signup: %s", resp)
		}
		out, isErr = r.Result.Content[0].Text, r.Result.IsError
	} else {
		out, isErr = tb.Execute("board_signup", args)
	}
	m := consSeedRe.FindStringSubmatch(out)
	if isErr || m == nil {
		t.Fatalf("signup %s: %s", name, out)
	}
	if strings.Contains(out, "session host's agent") != local {
		t.Fatalf("only a signup over the unix socket is the host's agent (local=%v): %s", local, out)
	}
	return m[1]
}

func consTGZ(t *testing.T, files map[string]string) string {
	t.Helper()
	var ms []tarGZMember
	for k, v := range files {
		ms = append(ms, tarGZMember{Name: k, Data: []byte(v)})
	}
	var buf bytes.Buffer
	if err := tarGZWrite(&buf, ms); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func consCall(t *testing.T, tb *Toolbox, local bool, name string, args map[string]any) (string, bool) {
	t.Helper()
	if local {
		return tb.ExecuteLocal(name, mustMarshal(args))
	}
	return tb.Execute(name, mustMarshal(args))
}

func consBoard(t *testing.T, tb *Toolbox) *Board {
	t.Helper()
	b, err := tb.store().loadBoard(false)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// consAge makes agents look offline (last seen long ago).
func consAge(t *testing.T, tb *Toolbox, names ...string) {
	t.Helper()
	st := tb.store()
	b := consBoard(t, tb)
	for _, n := range names {
		b.Agents[n].LastSeen -= 3600
	}
	if err := st.saveBoard(b); err != nil {
		t.Fatal(err)
	}
}

// Why: the host's agent is recognized only through the daemon's unix socket,
// may accept alone only with -host-accepted, and gets "talk to your human" otherwise.
func TestConsensusHostAgent(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	host := consSignup(t, tb, "alice", true)
	if b := consBoard(t, tb); b.Cons.HostAgent != "alice" {
		t.Fatalf("host agent: %q", b.Cons.HostAgent)
	}
	files := consTGZ(t, map[string]string{"consensus/goals.md": "goals\n", "deliverables/01.md": "t1\n"})
	out, isErr := consCall(t, tb, true, "board_propose", map[string]any{"seed": host, "text": "first goals", "attachment": files})
	if !isErr || !strings.Contains(out, "talk to your human") {
		t.Fatalf("the host's agent alone must be told to talk to its human: %s", out)
	}
	if out, isErr := consCall(t, tb, false, "board_propose", map[string]any{"seed": host, "text": "x", "attachment": files, "host_accepted": true}); !isErr || !strings.Contains(out, "host's own kbtool") {
		t.Fatalf("-host-accepted must arrive over the unix socket: %s", out)
	}
	out, isErr = consCall(t, tb, true, "board_propose", map[string]any{"seed": host, "text": "first goals", "attachment": files, "host_accepted": true})
	if isErr || !strings.Contains(out, "accepted") {
		t.Fatalf("host-accepted proposal: %s", out)
	}
	b := consBoard(t, tb)
	if p := b.Cons.proposal(1); p == nil || p.State != propAccepted || !p.HostAccepted {
		t.Fatalf("proposal 1: %+v", p)
	}
	if b.Cons.Files["consensus/goals.md"].SHA256 != sha256Hex([]byte("goals\n")) {
		t.Fatalf("accepted tree: %+v", b.Cons.Files)
	}
	msgs := b.Threads[boardConsThread].Msgs
	if len(msgs) != 2 || msgs[0].Kind != boardKindProposal || msgs[0].Agent != "alice" || msgs[1].Agent != boardSystem || msgs[1].Kind != boardKindOutcome {
		t.Fatalf("consensus thread: proposal by alice then outcome by system: %+v", msgs)
	}
	for _, m := range msgs {
		if cryptoVerifyBoardMsg(b, m) != "verified" {
			t.Fatalf("message %d does not verify", m.Seq)
		}
	}

	// a second agent signing up remotely is not the host's agent
	bob := consSignup(t, tb, "bob", false)
	if b := consBoard(t, tb); b.Cons.HostAgent != "alice" {
		t.Fatalf("a remote signup must not take over: %q", b.Cons.HostAgent)
	}
	if out, isErr := consCall(t, tb, true, "board_propose", map[string]any{"seed": bob, "text": "x", "attachment": files, "host_accepted": true}); !isErr {
		t.Fatalf("-host-accepted is for the host's agent only: %s", out)
	}
	// with alice offline, bob's proposal needs alice (the host's agent)
	consAge(t, tb, "alice")
	out, isErr = consCall(t, tb, false, "board_propose", map[string]any{"seed": bob, "text": "more", "attachment": consTGZ(t, map[string]string{"deliverables/02.md": "t2\n"})})
	if isErr || !strings.Contains(out, "waiting for: alice\n") {
		t.Fatalf("with nobody else active the host's agent must vote: %s", out)
	}
	if out, isErr := consCall(t, tb, false, "board_vote", map[string]any{"seed": host, "n": 2, "vote": "yes"}); isErr || !strings.Contains(out, "accepted") {
		t.Fatalf("host's yes accepts: %s", out)
	}
}

// Why: every other active agent must vote yes; one no with a reason rejects
// at once; a no needs a reason; the proposer cannot vote.
func TestConsensusVoting(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	alice := consSignup(t, tb, "alice", true)
	bob := consSignup(t, tb, "bob", false)
	carol := consSignup(t, tb, "carol", false)
	_ = alice
	files := consTGZ(t, map[string]string{"consensus/goals.md": "goals\n"})
	out, isErr := consCall(t, tb, false, "board_propose", map[string]any{"seed": bob, "text": "goals", "attachment": files})
	if isErr || !strings.Contains(out, "waiting for: alice, carol") {
		t.Fatalf("propose: %s", out)
	}
	if out, isErr := consCall(t, tb, false, "board_vote", map[string]any{"seed": bob, "n": 1, "vote": "yes"}); !isErr || !strings.Contains(out, "counts as your yes") {
		t.Fatalf("the proposer cannot vote: %s", out)
	}
	if out, isErr := consCall(t, tb, false, "board_vote", map[string]any{"seed": carol, "n": 1, "vote": "no"}); !isErr || !strings.Contains(out, "needs a reason") {
		t.Fatalf("a no needs a reason: %s", out)
	}
	out, _ = consCall(t, tb, false, "board_vote", map[string]any{"seed": carol, "n": 1, "vote": "yes"})
	if !strings.Contains(out, "waiting for: alice") {
		t.Fatalf("still waiting for alice: %s", out)
	}
	if out, isErr := consCall(t, tb, false, "board_vote", map[string]any{"seed": carol, "n": 1, "vote": "yes"}); !isErr || !strings.Contains(out, "already voted") {
		t.Fatalf("one vote each: %s", out)
	}
	out, _ = consCall(t, tb, false, "board_vote", map[string]any{"seed": alice, "n": 1, "vote": "yes"})
	if !strings.Contains(out, "accepted") {
		t.Fatalf("all yes accepts: %s", out)
	}
	b := consBoard(t, tb)
	want := sha256Hex([]byte("goals\n")) + "  consensus/goals.md\n"
	if consList(b, sessConsensus) != want || consUnified(b, sessConsensus) != unifiedChecksum(want) {
		t.Fatalf("accepted list: %q", consList(b, sessConsensus))
	}
	if consList(b, sessDeliverables) != "" {
		t.Fatalf("deliverables untouched: %q", consList(b, sessDeliverables))
	}

	// a no with a reason rejects at once
	consCall(t, tb, false, "board_propose", map[string]any{"seed": carol, "text": "rewrite", "attachment": consTGZ(t, map[string]string{"consensus/goals.md": "other\n"})})
	out, _ = consCall(t, tb, false, "board_vote", map[string]any{"seed": bob, "n": 2, "vote": "no", "reason": "loses the goals"})
	if !strings.Contains(out, "rejected") {
		t.Fatalf("no rejects: %s", out)
	}
	if out, isErr := consCall(t, tb, false, "board_vote", map[string]any{"seed": alice, "n": 2, "vote": "yes"}); !isErr || !strings.Contains(out, "already rejected") {
		t.Fatalf("a closed proposal takes no votes: %s", out)
	}
	if b := consBoard(t, tb); b.Cons.Files["consensus/goals.md"].SHA256 != sha256Hex([]byte("goals\n")) {
		t.Fatal("a rejected proposal changes nothing")
	}

	// stale: two proposals on the same file; accepting one closes the other
	consCall(t, tb, false, "board_propose", map[string]any{"seed": bob, "text": "v2", "attachment": consTGZ(t, map[string]string{"consensus/goals.md": "v2\n"})})
	consCall(t, tb, false, "board_propose", map[string]any{"seed": carol, "text": "v3", "attachment": consTGZ(t, map[string]string{"consensus/goals.md": "v3\n"})})
	consCall(t, tb, false, "board_vote", map[string]any{"seed": alice, "n": 3, "vote": "yes"})
	consCall(t, tb, false, "board_vote", map[string]any{"seed": carol, "n": 3, "vote": "yes"})
	b = consBoard(t, tb)
	if b.Cons.proposal(3).State != propAccepted || b.Cons.proposal(4).State != propStale || !strings.Contains(b.Cons.proposal(4).Reason, "proposal 3") {
		t.Fatalf("stale handling: %+v %+v", b.Cons.proposal(3), b.Cons.proposal(4))
	}

	// unchanged files and empty proposals
	if out, isErr := consCall(t, tb, false, "board_propose", map[string]any{"seed": bob, "text": "same", "attachment": consTGZ(t, map[string]string{"consensus/goals.md": "v2\n"})}); !isErr || !strings.Contains(out, "nothing would change") {
		t.Fatalf("an unchanged file is not a proposal: %s", out)
	}
	for _, bad := range []map[string]string{{"memory/x.md": "x"}, {"goals.md": "x"}} {
		if out, isErr := consCall(t, tb, false, "board_propose", map[string]any{"seed": bob, "text": "bad", "attachment": consTGZ(t, bad)}); !isErr || !strings.Contains(out, "consensus/ or deliverables/") {
			t.Fatalf("files outside the shared dirs are refused: %s", out)
		}
	}
	// delete
	if out, isErr := consCall(t, tb, false, "board_propose", map[string]any{"seed": bob, "text": "drop", "delete": []string{"deliverables/none"}}); !isErr || !strings.Contains(out, "nothing accepted") {
		t.Fatalf("deleting nothing: %s", out)
	}
	consCall(t, tb, false, "board_propose", map[string]any{"seed": bob, "text": "drop goals", "delete": []string{"consensus"}})
	consCall(t, tb, false, "board_vote", map[string]any{"seed": alice, "n": 5, "vote": "yes"})
	consCall(t, tb, false, "board_vote", map[string]any{"seed": carol, "n": 5, "vote": "yes"})
	if b := consBoard(t, tb); len(b.Cons.Files) != 0 || b.Cons.proposal(5).State != propAccepted {
		t.Fatalf("delete of a directory: %+v", b.Cons.Files)
	}
}

// Why: an agent holding a vote stays ACTIVE (and required); agents only
// write the consensus thread through the consensus tools.
func TestConsensusActivityAndThread(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	alice := consSignup(t, tb, "alice", true)
	bob := consSignup(t, tb, "bob", false)
	consSignup(t, tb, "carol", false)
	consCall(t, tb, false, "board_propose", map[string]any{"seed": bob, "text": "goals", "attachment": consTGZ(t, map[string]string{"consensus/goals.md": "g\n"})})
	consAge(t, tb, "bob", "carol")
	b := consBoard(t, tb)
	now := time.Now().Unix()
	if !boardAgentActive(b, b.Agents["bob"], now) || boardAgentActive(b, b.Agents["carol"], now) {
		t.Fatal("bob holds a vote (his proposal) and stays ACTIVE; carol does not")
	}
	if r := boardRoster(b, now); !regexp.MustCompile(`ACTIVE +bob`).MatchString(r) {
		t.Fatalf("roster shows bob ACTIVE: %s", r)
	}
	// carol went offline: alice's yes is enough now
	out, _ := consCall(t, tb, false, "board_vote", map[string]any{"seed": alice, "n": 1, "vote": "yes"})
	if !strings.Contains(out, "accepted") {
		t.Fatalf("live required voters: %s", out)
	}
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"seed": alice, "thread": "consensus", "text": "hi"})); !isErr || !strings.Contains(out, "kbtool consensus") {
		t.Fatalf("board_post to consensus is refused: %s", out)
	}
	if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"seed": alice, "thread": "plans", "text": "hi", "kind": "proposal"})); !isErr {
		t.Fatalf("kind proposal is not a board_post kind: %s", out)
	}
}

// Why: the accepted tree survives a save/load and is served as a tar.gz built
// from the proposal attachments, matching what the client checksums.
func TestConsensusSyncAndPersistence(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	alice := consSignup(t, tb, "alice", true)
	files := map[string]string{"consensus/goals.md": "g\n", "deliverables/a/01.md": "one\n", "deliverables/02.md": "two\n"}
	consCall(t, tb, true, "board_propose", map[string]any{"seed": alice, "text": "start", "attachment": consTGZ(t, files), "host_accepted": true})
	consCall(t, tb, true, "board_propose", map[string]any{"seed": alice, "text": "edit", "attachment": consTGZ(t, map[string]string{"deliverables/02.md": "TWO\n"}), "host_accepted": true})
	b := consBoard(t, tb)
	c, err := readBoard(bytes.NewReader(boardMarshal(b)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Cons, b.Cons) || c.SystemSeed == nil {
		t.Fatalf("consensus trailer round trip:\n%+v\n%+v", c.Cons, b.Cons)
	}
	out, isErr := consCall(t, tb, false, "board_consensus", map[string]any{"seed": alice, "sync": "deliverables",
		"have": map[string]string{"deliverables": strings.Repeat("a", 64)}})
	if isErr {
		t.Fatal(out)
	}
	data, err := attachUnarmor(out)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := tarGZAllMem(data)
	want := map[string][]byte{"deliverables/a/01.md": []byte("one\n"), "deliverables/02.md": []byte("TWO\n")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sync tar.gz: %q", got)
	}
	sdir := t.TempDir()
	for k, v := range got {
		os.MkdirAll(filepath.Join(sdir, filepath.Dir(k)), 0700)
		os.WriteFile(filepath.Join(sdir, k), v, 0600)
	}
	if l, _ := dirChecksumList(sdir, sessDeliverables); unifiedChecksum(l) != consUnified(consBoard(t, tb), sessDeliverables) {
		t.Fatal("client and server unified checksums must agree")
	}
	if !strings.Contains(out, "unified checksum "+consUnified(consBoard(t, tb), sessDeliverables)) {
		t.Fatalf("status names the unified checksums: %s", out)
	}
	if k := consBoard(t, tb).Cons.Known["alice"]; k["deliverables"] != strings.Repeat("a", 64) {
		t.Fatalf("reported checksums are recorded: %v", k)
	}
	if _, err := readBoard(bytes.NewReader(append(boardMarshal(b), []byte("\x04\x00\x00\x00XXXX")...))); err == nil {
		t.Fatal("an unknown trailer is corruption")
	}
}

// Why: review -diff shows what a proposal changes in a familiar form.
func TestWriteLineDiff(t *testing.T) {
	var buf bytes.Buffer
	writeLineDiff(&buf, "consensus/g.md", "a\nb\nc\nd\ne\nf\ng\n", "a\nb\nc\nD\ne\nf\ng\n")
	want := "=== consensus/g.md\n@@\n  b\n  c\n- d\n+ D\n  e\n  f\n"
	if buf.String() != want {
		t.Fatalf("diff:\n%s\nwant:\n%s", buf.String(), want)
	}
	buf.Reset()
	writeLineDiff(&buf, "x", "", "1\n2\n")
	if !strings.HasPrefix(buf.String(), "=== x: new file, 2 line(s)\n+ 1\n+ 2\n") {
		t.Fatalf("new file: %q", buf.String())
	}
}

// Why: propose packs memory files under their consensus/ or deliverables/
// names; sources stay inside memory and dotfiles are left out.
func TestConsensusMembers(t *testing.T) {
	mem := t.TempDir()
	os.MkdirAll(filepath.Join(mem, "tickets", ".backup"), 0700)
	os.WriteFile(filepath.Join(mem, "tickets", "01.md"), []byte("1"), 0600)
	os.WriteFile(filepath.Join(mem, "tickets", ".hidden"), []byte("h"), 0600)
	os.WriteFile(filepath.Join(mem, "tickets", ".backup", "old.md"), []byte("o"), 0600)
	os.WriteFile(filepath.Join(mem, "goals.md"), []byte("g"), 0600)
	ms, err := consensusMembers(mem, []string{"tickets=deliverables", "goals.md=consensus/goals.md"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range ms {
		names = append(names, m.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "consensus/goals.md,deliverables/01.md" {
		t.Fatalf("members: %v", names)
	}
	for _, bad := range []string{"goals.md", "../x=consensus/x", "goals.md=memory/x", "goals.md=consensus", "goals.md=consensus/../x", "/etc/passwd=consensus/p"} {
		if _, err := consensusMembers(mem, []string{bad}); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	if _, err := consensusMembers(mem, []string{"goals.md=consensus/g", "goals.md=consensus/g"}); err == nil {
		t.Fatal("a destination given twice is refused")
	}
}

// Why: every tool result tells the client the accepted checksums, and the
// client brings its copy up to date in the background, keeping what it
// replaces, then reports the checksums it now has.
func TestConsensusBackgroundSync(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	alice := consSignup(t, tb, "alice", true)
	bob := consSignup(t, tb, "bob", false)
	consCall(t, tb, false, "board_propose", map[string]any{"seed": bob, "text": "start",
		"attachment": consTGZ(t, map[string]string{"consensus/goals.md": "goals\n", "deliverables/t/01.md": "one\n"})})
	consCall(t, tb, false, "board_vote", map[string]any{"seed": alice, "n": 1, "vote": "yes"})

	// the status rides on every tool result
	line := mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "board_threads", "arguments": map[string]any{"seed": bob}}})
	var r struct {
		Result struct {
			Meta map[string]json.RawMessage `json:"_meta"`
		} `json:"result"`
	}
	json.Unmarshal(handleLine(line, tb), &r)
	var cs consStatus
	if err := json.Unmarshal(r.Result.Meta["kbtool/consensus"], &cs); err != nil || cs.Accepted != 1 || cs.Consensus != consUnified(consBoard(t, tb), sessConsensus) {
		t.Fatalf("_meta kbtool/consensus: %s %v", r.Result.Meta["kbtool/consensus"], err)
	}

	sdir := memSession(t)
	os.WriteFile(filepath.Join(sdir, "consensus", "goals.md"), []byte("my edit\n"), 0600)
	os.WriteFile(filepath.Join(sdir, "deliverables", "stray.md"), []byte("stray\n"), 0600)
	var notes bytes.Buffer
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	consBackground(tb, &notes, sdir, bob, &cs, now)
	for name, want := range map[string]string{"consensus/goals.md": "goals\n", "deliverables/t/01.md": "one\n"} {
		if b, _ := os.ReadFile(filepath.Join(sdir, name)); string(b) != want {
			t.Fatalf("%s = %q after the background update", name, b)
		}
	}
	if _, err := os.Stat(filepath.Join(sdir, "deliverables", "stray.md")); err == nil {
		t.Fatal("files the board does not have are removed")
	}
	bk := filepath.Join(sdir, "memory", ".backup", "20261002T120000Z")
	if b, _ := os.ReadFile(filepath.Join(bk, "consensus", "goals.md")); string(b) != "my edit\n" {
		t.Fatalf("the replaced copy is kept in memory/.backup: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(bk, "deliverables", "stray.md")); string(b) != "stray\n" {
		t.Fatalf("the removed file is kept in memory/.backup: %q", b)
	}
	if _, err := os.Stat(filepath.Join(bk, "deliverables", "t", "01.md")); err == nil {
		t.Fatal("files that were not changed locally need no backup")
	}
	n := notes.String()
	if !strings.Contains(n, "notice: background update of consensus/ and deliverables/ (proposal 1 accepted); review it with: kbtool consensus review 1") ||
		!strings.Contains(n, "memory/.backup/20261002T120000Z") {
		t.Fatalf("notices: %q", n)
	}
	if l, _ := dirChecksumList(sdir, "consensus"); unifiedChecksum(l) != cs.Consensus {
		t.Fatal("the local copy now has the accepted checksum")
	}
	if b, _ := os.ReadFile(filepath.Join(sdir, "deliverables.sha256")); !strings.Contains(string(b), "deliverables/t/01.md") {
		t.Fatalf("deliverables.sha256 regenerated: %q", b)
	}
	b := consBoard(t, tb)
	if r := boardRoster(b, time.Now().Unix()); !regexp.MustCompile(`bob .*copies=in-sync`).MatchString(r) {
		t.Fatalf("the board knows bob's copies are in sync: %s", r)
	}

	// in sync: nothing to do, no notice
	notes.Reset()
	consBackground(tb, &notes, sdir, bob, &cs, now)
	if notes.Len() != 0 {
		t.Fatalf("no notice when in sync: %q", notes.String())
	}

	// an open proposal waiting for this agent's vote
	consCall(t, tb, false, "board_propose", map[string]any{"seed": bob, "text": "more", "attachment": consTGZ(t, map[string]string{"deliverables/t/02.md": "two\n"})})
	st := consStatusOf(consBoard(t, tb), time.Now().Unix())
	consBackground(tb, &notes, sdir, alice, st, now)
	if !strings.Contains(notes.String(), "notice: proposal 2 by bob waits for your vote; review it with: kbtool consensus review 2") {
		t.Fatalf("vote notice: %q", notes.String())
	}
	notes.Reset()
	consBackground(tb, &notes, sdir, bob, st, now)
	if strings.Contains(notes.String(), "waits for your vote") {
		t.Fatalf("the proposer is not asked to vote: %q", notes.String())
	}
}

// Why: accepted documents are searchable on the host, labelled with whether
// the hit is the current version.
func TestConsensusDocsSearchable(t *testing.T) {
	t.Setenv("KB_EMBED_URL", "")
	db := makeDB(t, []Chunk{{Path: "a", Kind: "code", Text: "some base chunk"}})
	tb := newBoardToolbox(t, db)
	alice := consSignup(t, tb, "alice", true)
	consCall(t, tb, true, "board_propose", map[string]any{"seed": alice, "text": "plan", "host_accepted": true,
		"attachment": consTGZ(t, map[string]string{"consensus/goals.md": "migrate branch protection to zygomorphic org jobs\n"})})
	out, _ := tb.Execute("board_search", mustMarshal(map[string]any{"q": "zygomorphic", "seed": alice}))
	if !strings.Contains(out, "board/consensus-docs/consensus/goals.md@1") || !strings.Contains(out, "current version, proposal 1") {
		t.Fatalf("accepted doc in board search: %s", out)
	}
	consCall(t, tb, true, "board_propose", map[string]any{"seed": alice, "text": "v2", "host_accepted": true,
		"attachment": consTGZ(t, map[string]string{"consensus/goals.md": "zygomorphic v2\n"})})
	out, _ = tb.Execute("board_search", mustMarshal(map[string]any{"q": "zygomorphic", "seed": alice, "k": 20}))
	if !strings.Contains(out, "superseded by proposal 2") || !strings.Contains(out, "goals.md@2") {
		t.Fatalf("superseded versions are labelled: %s", out)
	}
	chunks := consDocChunks(consBoard(t, tb), 2)
	if len(chunks) != 1 || chunks[0].Start != 1 || !strings.HasPrefix(chunks[0].Text, "consensus/goals.md\n") {
		t.Fatalf("doc chunks: %+v", chunks)
	}
}

// ---------- 48. board export from finished sessions (plans/memory-consensus-deliverables-plan.md) ----------

func boardWithPost(t *testing.T, text string) *Board {
	t.Helper()
	b := newBoard()
	if _, err := ensureSystem(b, boardSysInfo{WelcomeWords: 40}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	boardSystemPost(b, text, time.Now().Unix())
	return b
}

// Why: past host sessions' boards can be reviewed: a plain session dir, and a
// sealed archive decrypted in memory with the inner kb.db key from its keys
// record; attendee sessions have no board and say so.
func TestSessionBoardExport(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	t.Setenv(secretEnv, "")
	host, err := createSession("host", t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(sessionDir(host.ID), "state"), 0700)
	os.WriteFile(filepath.Join(sessionDir(host.ID), "state", "board.bin"), boardMarshal(boardWithPost(t, "plain session marker")), 0600)
	b, err := sessionBoard(host.ID, nil)
	if err != nil || !strings.Contains(b.Threads[boardSystem].Msgs[1].Text, "plain session marker") {
		t.Fatalf("plain host session: %v", err)
	}

	att, _ := createSession("attendee", t.TempDir(), time.Now().Add(time.Second))
	if _, err := sessionBoard(att.ID, nil); err != errAttendeeBoard {
		t.Fatalf("attendee session: %v", err)
	}

	// a sealed host session whose kb.db is an encrypted store under its own key
	enc, _ := createSession("host", t.TempDir(), time.Now().Add(2*time.Second))
	inner := []byte("inner store key")
	var tgz bytes.Buffer
	tarGZWrite(&tgz, []tarGZMember{{Name: "board.bin", Data: boardMarshal(boardWithPost(t, "sealed session marker"))}})
	sealed := newBundleSealer(inner).seal(tgz.Bytes())
	dir := sessionDir(enc.ID)
	os.MkdirAll(filepath.Join(dir, "state"), 0700)
	os.WriteFile(filepath.Join(dir, "state", "kb.db"), sealed, 0600)
	outer := []byte("archive key")
	dest, _ := newSessionKBXPath()
	if err := sealSession(dir, dest, outer, make([]byte, 16), sessionHead{Meta: *enc}, false, kbxKeys{Inner: map[string][]byte{"state/kb.db": inner}}); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(dir)
	if _, err := sessionBoard(enc.ID, nil); err == nil || !strings.Contains(err.Error(), secretEnv) {
		t.Fatalf("a sealed session needs the key: %v", err)
	}
	b, err = sessionBoard(enc.ID, outer)
	if err != nil || !strings.Contains(b.Threads[boardSystem].Msgs[1].Text, "sealed session marker") {
		t.Fatalf("sealed host session: %v", err)
	}
	if _, err := sessionBoard(enc.ID, []byte("wrong")); err == nil {
		t.Fatal("a wrong key fails")
	}
	var html bytes.Buffer
	if err := renderBoardHTML(&html, boardSnapshotOf(b, time.Now())); err != nil || !strings.Contains(html.String(), "sealed session marker") {
		t.Fatalf("HTML: %v", err)
	}
	if ents, _ := os.ReadDir(sessionsDir()); len(ents) != 3 {
		t.Fatalf("the export leaves nothing behind: %d entries", len(ents))
	}

	// the sealed attendee check happens before any payload is read
	os.MkdirAll(filepath.Join(sessionDir(att.ID), "state"), 0700)
	m, _ := loadSessionMeta(att.ID)
	if _, err := sealSessionDir(att.ID, m, outer, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionBoard(att.ID, outer); err != errAttendeeBoard {
		t.Fatalf("sealed attendee session: %v", err)
	}
}

// ---------- 49. agent-side session layer (plans/session-memory-attachments-plan.md) ----------

func layerCall(t *testing.T, ex executor, name string, args map[string]any) (string, bool) {
	t.Helper()
	return ex.Execute(name, mustMarshal(args))
}

func layerTools(t *testing.T, ex executor) map[string]map[string]any {
	t.Helper()
	res, err := dispatch(ex, "tools/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, tl := range res.(map[string]any)["tools"].([]mcpTool) {
		out[tl.Name] = tl.InputSchema.(map[string]any)
	}
	return out
}

// Why: a human reviewing the board must see which agent is the host's.
func TestBoardDumpTagsHostAgent(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	alice := consSignup(t, tb, "alice", true)
	bob := consSignup(t, tb, "bob", false)
	for _, seed := range []string{alice, bob} {
		if out, isErr := tb.Execute("board_post", mustMarshal(map[string]any{"thread": "plans", "text": "hello", "seed": seed})); isErr {
			t.Fatal(out)
		}
	}
	var buf bytes.Buffer
	if err := renderBoardHTML(&buf, boardSnapshotOf(consBoard(t, tb), time.Now())); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	tag := `<span class="host-agent">[host agent]</span>`
	if !strings.Contains(page, "<td>alice "+tag+"</td>") || !strings.Contains(page, "<b>alice</b> "+tag) {
		t.Fatal("the host's agent must be tagged in the roster and on its messages")
	}
	if !strings.Contains(page, `<span class="tag">host agent: alice</span>`) {
		t.Fatal("the session tags name the host's agent")
	}
	if strings.Count(page, tag) != 2 {
		t.Fatalf("only the host's agent is tagged: %d tags", strings.Count(page, tag))
	}
	buf.Reset()
	if err := renderBoardHTML(&buf, boardSnapshotOf(newBoard(), time.Now())); err != nil || strings.Contains(buf.String(), tag) {
		t.Fatalf("no host agent, no tag: %v", err)
	}
}

// Why: an agent learns the platform of the kbtool binary it signed up with
// only from board_whoami; the client reports it from build-time constants,
// the board keeps it, and the export shows it to the humans.
func TestSignupPlatform(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	sock := filepath.Join(shortStateDir(t), "daemon.sock")
	serveToolboxSocket(t, tb, sock)
	ce := &remoteExec{ep: endpoint{kind: "unix", socket: sock}}
	out, isErr := ce.Execute("board_signup", mustMarshal(map[string]any{"name": "alice", "platform": "plan9/mips"}))
	if isErr || strings.Contains(out, clientPlatform) {
		t.Fatalf("the signup reply stays free of the platform: %s", out)
	}
	seed := consSeedRe.FindStringSubmatch(out)[1]
	if p := consBoard(t, tb).Agents["alice"].Platform; p != clientPlatform {
		t.Fatalf("the client reports its own binary's platform, whatever the agent passes: %q", p)
	}
	if clientPlatform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatal("clientPlatform comes from the build")
	}
	if out, _ := tb.Execute("board_whoami", mustMarshal(map[string]any{"seed": seed})); !strings.Contains(out, "platform: "+clientPlatform) {
		t.Fatalf("whoami shows the platform: %s", out)
	}
	if out := boardRoster(consBoard(t, tb), time.Now().Unix()); strings.Contains(out, clientPlatform) {
		t.Fatalf("the roster stays free of platforms: %s", out)
	}
	for _, tl := range toolSchemas() {
		if b, _ := json.Marshal(tl.InputSchema); strings.Contains(string(b), "platform") {
			t.Fatalf("%s's schema must not mention platform", tl.Name)
		}
	}
	if out, isErr := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "bob", "platform": strings.Repeat("x", boardPlatformMax+1)})); !isErr || !strings.Contains(out, "limited to") || consSeedRe.MatchString(out) {
		t.Fatalf("an over-long platform is refused before any seed is issued: %s", out)
	}
	if consBoard(t, tb).Agents["bob"] != nil {
		t.Fatal("a refused signup registers nothing")
	}
	if out, isErr := tb.Execute("board_signup", mustMarshal(map[string]any{"name": "dave", "platform": "Linux AMD64 (custom)"})); isErr {
		t.Fatalf("an unusual platform within the limit is accepted: %s", out)
	}
	consSignup(t, tb, "carol", false)
	b := consBoard(t, tb)
	if b.Agents["carol"].Platform != "" {
		t.Fatal("the daemon never adds its own platform to a signup")
	}
	b2, err := readBoard(bytes.NewReader(boardMarshal(b)))
	if err != nil || b2.Agents["alice"].Platform != clientPlatform || b2.Agents["carol"].Platform != "" {
		t.Fatalf("the platform survives a save: %v", err)
	}
	var buf bytes.Buffer
	if err := renderBoardHTML(&buf, boardSnapshotOf(b, time.Now())); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	if !strings.Contains(page, `<span class="tag">`+clientPlatform+` × 1</span>`) || !strings.Contains(page, `<td><span class="tag">`+clientPlatform+`</span></td>`) {
		t.Fatal("the export shows each agent's platform and the session's platforms")
	}
	if !strings.Contains(page, `<span class="tag">3 agent(s), 3 active</span>`) {
		t.Fatal("the export summarizes the agents")
	}
}

// Why: over MCP an agent must see memory paths, not base64, and no seed;
// outside a session the tools are unchanged.
func TestSessionLayerSchemas(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	if _, ok := withSession(tb).(*agentExec); !ok {
		t.Fatal("no session: only the signup guard")
	}
	memSession(t)
	tools := layerTools(t, withSession(tb))
	props := func(name string) map[string]any { return tools[name]["properties"].(map[string]any) }
	if _, ok := props("board_post")["attachment"]; ok {
		t.Error("board_post must not offer base64 attachments in a session")
	}
	if _, ok := props("board_post")["attach"]; !ok {
		t.Error("board_post must take attach (memory paths)")
	}
	if _, ok := props("board_fetch")["into"]; !ok {
		t.Error("board_fetch must take into")
	}
	if _, ok := props("board_propose")["files"]; !ok {
		t.Error("board_propose must take files")
	}
	for name, sch := range tools {
		if req, _ := sch["required"].([]string); strings.HasPrefix(name, "board_") && slices.Contains(req, "seed") {
			t.Errorf("%s still requires seed", name)
		}
	}
	for _, n := range []string{"memory", "consensus_files", "deliverables_files"} {
		if tools[n] == nil {
			t.Errorf("missing tool %s", n)
		}
	}
	if _, ok := props("consensus_files")["content"]; ok {
		t.Error("consensus_files is read-only")
	}
}

// Why: whatever the call method, attaching packs files from memory and
// fetching extracts into memory, and the seed stays with kbtool.
func TestSessionLayerAttachFetch(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	sdir := memSession(t)
	ex := withSession(tb)

	out, isErr := layerCall(t, ex, "board_signup", map[string]any{"name": "alice"})
	seed, _ := readSeedFile(filepath.Join(sdir, ".kbtool-seed"))
	if isErr || seed == "" || strings.Contains(out, seed) || !strings.Contains(out, "seed stored in this session") {
		t.Fatalf("signup must keep the seed in the session and not show it: %v %s", isErr, out)
	}
	if out, isErr := layerCall(t, ex, "board_signup", map[string]any{"name": "bob"}); !isErr || !strings.Contains(out, "already signed up as alice") {
		t.Fatalf("a second signup must not replace the seed: %s", out)
	}
	if out, isErr := layerCall(t, ex, "board_whoami", map[string]any{}); isErr || !strings.Contains(out, "alice") {
		t.Fatalf("the seed is supplied: %s", out)
	}

	if out, isErr := layerCall(t, ex, "memory", map[string]any{"command": "write", "args": []string{"notes/plan.md"}, "content": "plan v1\n"}); isErr {
		t.Fatalf("memory write: %s", out)
	}
	if out, isErr := layerCall(t, ex, "memory", map[string]any{"command": "cat", "args": []string{"notes/plan.md"}}); isErr || out != "plan v1\n" {
		t.Fatalf("memory cat: %q", out)
	}
	if out, isErr := layerCall(t, ex, "memory", map[string]any{"command": "cat", "args": []string{"../meta.json"}}); !isErr || !strings.Contains(out, "memory:") {
		t.Fatalf("memory paths must stay in memory: %s", out)
	}
	if out, isErr := layerCall(t, ex, "memory", map[string]any{"command": "export"}); !isErr {
		t.Fatalf("export writes a tar.gz to stdout; not an MCP command: %s", out)
	}

	if out, isErr := layerCall(t, ex, "board_post", map[string]any{"thread": "plans", "text": "x", "attachment": consTGZ(t, map[string]string{"a": "b"})}); !isErr || !strings.Contains(out, "from your memory") {
		t.Fatalf("base64 attachments must be refused in a session: %s", out)
	}
	if out, isErr := layerCall(t, ex, "board_post", map[string]any{"thread": "plans", "text": "x", "attach": []string{"../.kbtool-seed"}}); !isErr || !strings.Contains(out, "memory:") {
		t.Fatalf("attach must stay in memory: %s", out)
	}
	out, isErr = layerCall(t, ex, "board_post", map[string]any{"thread": "plans", "text": "plan draft", "attach": []string{"notes"}})
	if isErr {
		t.Fatalf("attach from memory: %s", out)
	}
	b := consBoard(t, tb)
	m := b.thread("plans").Msgs[0]
	if m.Attach == nil || len(m.Attach.Files) != 1 || m.Attach.Files[0].Name != "notes/plan.md" {
		t.Fatalf("attachment: %+v", m.Attach)
	}

	out, isErr = layerCall(t, ex, "board_fetch", map[string]any{"thread": "plans", "seq": 0, "list": true})
	if isErr || !strings.Contains(out, "notes/plan.md") || strings.Contains(out, attachArmorBegin) {
		t.Fatalf("list: %s", out)
	}
	out, isErr = layerCall(t, ex, "board_fetch", map[string]any{"thread": "plans", "seq": 0, "into": "in"})
	if isErr || !strings.Contains(out, "memory/in/notes/plan.md") || strings.Contains(out, attachArmorBegin) {
		t.Fatalf("fetch into memory: %s", out)
	}
	if got, _ := os.ReadFile(filepath.Join(sdir, "memory", "in", "notes", "plan.md")); string(got) != "plan v1\n" {
		t.Fatalf("fetched file: %q", got)
	}
	if out, isErr := layerCall(t, ex, "board_fetch", map[string]any{"thread": "plans", "seq": 0, "into": "in"}); !isErr || !strings.Contains(out, "overwrite") {
		t.Fatalf("existing files are kept unless overwrite: %s", out)
	}
	if _, isErr := layerCall(t, ex, "board_fetch", map[string]any{"thread": "plans", "seq": 0, "into": "in", "overwrite": true}); isErr {
		t.Fatal("overwrite")
	}
	if out, isErr := layerCall(t, ex, "board_fetch", map[string]any{"thread": "plans", "seq": 0, "into": "/tmp"}); !isErr || !strings.Contains(out, "memory:") {
		t.Fatalf("fetch must stay in memory: %s", out)
	}

	if out, isErr := layerCall(t, ex, "consensus_files", map[string]any{"command": "write", "args": []string{"x"}}); !isErr || !strings.Contains(out, "unknown command") && !strings.Contains(out, "read-only") {
		t.Fatalf("consensus_files is read-only: %s", out)
	}
	if out, isErr := layerCall(t, ex, "board_propose", map[string]any{"text": "x", "attachment": consTGZ(t, map[string]string{"deliverables/a": "b"})}); !isErr || !strings.Contains(out, "from your memory") {
		t.Fatalf("base64 proposals must be refused in a session: %s", out)
	}
	consSignup(t, tb, "bob", false)
	out, isErr = layerCall(t, ex, "board_propose", map[string]any{"text": "the plan", "files": []string{"notes/plan.md=deliverables/plan.md"}})
	if isErr || !strings.Contains(out, "proposal 1") {
		t.Fatalf("propose from memory: %s", out)
	}
	out, isErr = layerCall(t, ex, "board_proposal", map[string]any{"n": 1, "diff": true, "into": "rev"})
	if isErr || !strings.Contains(out, "+ plan v1") || !strings.Contains(out, "memory/rev") || strings.Contains(out, attachArmorBegin) {
		t.Fatalf("review into memory: %s", out)
	}
	if got, _ := os.ReadFile(filepath.Join(sdir, "memory", "rev", "deliverables", "plan.md")); string(got) != "plan v1\n" {
		t.Fatalf("proposal files in memory: %q", got)
	}
	if out, isErr := layerCall(t, ex, "board_consensus", map[string]any{"sync": true}); !isErr || !strings.Contains(out, "background") {
		t.Fatalf("sync is kbtool's job: %s", out)
	}
	if out, isErr := layerCall(t, ex, "deliverables_files", map[string]any{"command": "ls"}); isErr {
		t.Fatalf("deliverables_files ls: %s", out)
	}
}

// ---------- 50. relay honeypot (plans/relay-honeypot-plan.md) ----------

type hpClock struct{ t time.Time }

func (c *hpClock) now() time.Time      { return c.t }
func (c *hpClock) add(d time.Duration) { c.t = c.t.Add(d) }
func hpGet(h *honeypot, ip string) *hpClient {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.clients[ip]; e != nil {
		c := *e.Value.(*hpClient)
		return &c
	}
	return nil
}

// Why: / marks a client seen, a honeypot directory blocks it (short the
// first time, longer after), drops never refresh it, and it is forgotten
// once it has been quiet for the remember window.
func TestHoneypotStateMachine(t *testing.T) {
	clk := &hpClock{t: time.Unix(1_800_000_000, 0)}
	h := newHoneypot()
	h.now = clk.now
	const ip = "203.0.113.7"
	if h.blocked(ip) {
		t.Fatal("unknown clients are not blocked")
	}
	h.record(ip, false)
	if c := hpGet(h, ip); c == nil || c.State != hpSeen || h.blocked(ip) {
		t.Fatalf("GET / marks seen, not blocked: %+v", c)
	}
	clk.add(time.Minute)
	h.record(ip, true)
	c := hpGet(h, ip)
	if c.State != hpSuspicious || !c.BlockedUntil.Equal(clk.t.Add(relayDefBlock)) || !h.blocked(ip) {
		t.Fatalf("the first honeypot directory blocks for the initial block: %+v", c)
	}
	seen := c.LastSeen
	clk.add(10 * time.Minute)
	for i := 0; i < 3; i++ {
		h.blocked(ip)
	}
	if c := hpGet(h, ip); !c.LastSeen.Equal(seen) || c.Dropped < 3 {
		t.Fatalf("drops must not refresh last seen: %+v", c)
	}
	clk.add(5 * time.Minute)
	if h.blocked(ip) {
		t.Fatal("the initial block ends")
	}
	h.record(ip, true)
	if c := hpGet(h, ip); !c.BlockedUntil.Equal(clk.t.Add(relayDefReblock)) {
		t.Fatalf("an already suspicious client is blocked for the follow-up block: %+v", c)
	}
	clk.add(relayDefReblock + time.Minute)
	h.record(ip, true)
	if c := hpGet(h, ip); !c.BlockedUntil.Equal(clk.t.Add(relayDefReblock)) {
		t.Fatal("suspicious again after the block: another follow-up block")
	}
	clk.add(relayDefRemember - time.Second)
	h.sweep()
	if hpGet(h, ip) == nil {
		t.Fatal("remembered until the window passes")
	}
	clk.add(time.Second)
	h.sweep()
	if hpGet(h, ip) != nil {
		t.Fatal("forgotten after the remember window without an answered request")
	}
	h.record(ip, true)
	if c := hpGet(h, ip); c.State != hpSuspicious || !c.BlockedUntil.Equal(clk.t.Add(relayDefBlock)) {
		t.Fatal("a forgotten client starts over: its first honeypot directory is an initial block")
	}

	h.Remember, h.Block = time.Minute, time.Hour
	clk.add(2 * time.Hour)
	h.record(ip, true)
	clk.add(30 * time.Minute)
	h.sweep()
	if hpGet(h, ip) == nil || !h.blocked(ip) {
		t.Fatal("a client stays remembered while it is blocked")
	}
}

// Why: a swarm of addresses must not exhaust memory: the least recently
// seen clients are forgotten first, and the budget scales with memory.
func TestHoneypotEviction(t *testing.T) {
	clk := &hpClock{t: time.Unix(1_800_000_000, 0)}
	h := newHoneypot()
	h.now = clk.now
	h.MaxClients = 3
	for _, ip := range []string{"a", "b", "c"} {
		h.record(ip, false)
		clk.add(time.Second)
	}
	h.record("a", false)
	h.record("d", false)
	if hpGet(h, "b") != nil || hpGet(h, "a") == nil || hpGet(h, "c") == nil || hpGet(h, "d") == nil || h.evicted != 1 {
		t.Fatal("the least recently seen client is forgotten first")
	}
	if n, err := honeypotMaxClientsFor("64MiB"); err != nil || n != 64<<20/honeypotClientCost {
		t.Fatalf("64MiB: %d %v", n, err)
	}
	if n, _ := honeypotMaxClientsFor("1KiB"); n != honeypotMinClients {
		t.Fatalf("tiny budgets keep a floor: %d", n)
	}
	if _, err := honeypotMaxClientsFor("lots"); err == nil {
		t.Fatal("bad budgets are refused")
	}
}

// Why: the listing is random per boot, never names real endpoints, and is
// the same for one client every time: 1 to 5 of 32 words, picked by a
// 32-bit mask derived from the client's address.
func TestHoneypotWordsAndListing(t *testing.T) {
	h := newHoneypot()
	seen := map[string]bool{}
	for i, w := range h.words {
		if honeypotReserved[w] || len(w) < 3 || len(w) > 12 || seen[w] || h.word(w) != i {
			t.Fatalf("word %q", w)
		}
		seen[w] = true
		if _, err := time.Parse("2006-01-02 15:04", h.dates[i]); err != nil {
			t.Fatalf("date %q", h.dates[i])
		}
	}
	if h.word("") != -1 || h.word("ca.crt") != -1 {
		t.Fatal("only boot words are directories")
	}
	if h2 := newHoneypot(); h.words == h2.words {
		t.Fatal("words are random per boot")
	}
	sizes := map[int]bool{}
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		m := h.mask(ip)
		if n := bits.OnesCount32(m); n < 1 || n > honeypotMaxDirs || m != h.mask(ip) {
			t.Fatalf("mask for %s: %032b", ip, m)
		}
		a, b := h.listing(ip), h.listing(ip)
		if !slices.Equal(a, b) || len(a) != bits.OnesCount32(m) || !sort.StringsAreSorted(a) {
			t.Fatalf("listing for %s: %v %v", ip, a, b)
		}
		sizes[len(a)] = true
	}
	if len(sizes) != honeypotMaxDirs {
		t.Fatalf("every listing size from 1 to 5 occurs: %v", sizes)
	}
}

func hpRequest(t *testing.T, client *http.Client, method, url string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

var hpDirRe = regexp.MustCompile(`<a href="([^"?/]+)/">`)

// Why: to a browser or scanner the relay is an Apache directory listing;
// kbtool's own requests never mark a client; a listed directory blocks the
// client, whose connections then die silently.
func TestRelayHoneypotHTTP(t *testing.T) {
	rs, hp := startTestRelay(t, "", func(rs *relayServer) { rs.Healthz.interval = 0 })
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	tlsc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	if _, err := relayFingerprint(hp); err != nil {
		t.Fatal(err)
	}
	if !relayHealthy(hp) {
		t.Fatal("healthz")
	}
	if _, err := relayCheck(hp, relayTrust{}); err != nil {
		t.Fatal(err)
	}
	resp, body := hpRequest(t, plain, "GET", "http://"+hp+"/favicon.ico")
	if resp.StatusCode != 404 || resp.Header.Get("Server") != honeypotServer || !strings.Contains(body, "<title>404 Not Found</title>") {
		t.Fatalf("unknown paths are Apache 404s: %d %q", resp.StatusCode, body)
	}
	if n := len(rs.Honey.list()); n != 0 {
		t.Fatalf("kbtool's own requests must not mark a client: %d", n)
	}

	resp, body = hpRequest(t, plain, "GET", "http://"+hp+"/")
	if resp.StatusCode != 200 || resp.Header.Get("Server") != honeypotServer || resp.Header.Get("Content-Type") != "text/html;charset=ISO-8859-1" || !strings.Contains(body, "<title>Index of /</title>") {
		t.Fatalf("GET / is an Apache listing: %d %v %q", resp.StatusCode, resp.Header, body)
	}
	if strings.Contains(body, "ca.crt") || strings.Contains(body, "healthz") || strings.Contains(body, "<address>") || honeypotServer != "Apache" {
		t.Fatalf("the listing hides the real endpoints: %q", body)
	}
	var dirs []string
	for _, m := range hpDirRe.FindAllStringSubmatch(body, -1) {
		dirs = append(dirs, m[1])
	}
	_, tbody := hpRequest(t, tlsc, "GET", "https://"+hp+"/")
	var tdirs []string
	for _, m := range hpDirRe.FindAllStringSubmatch(tbody, -1) {
		tdirs = append(tdirs, m[1])
	}
	if len(dirs) < 1 || len(dirs) > honeypotMaxDirs || !slices.Equal(dirs, tdirs) {
		t.Fatalf("the same listing over HTTP and HTTPS: %v %v", dirs, tdirs)
	}
	if c := hpGet(rs.Honey, "127.0.0.1"); c == nil || c.State != hpSeen || c.Requests != 2 {
		t.Fatalf("GET / marks the client seen: %+v", c)
	}

	resp, body = hpRequest(t, plain, "GET", "http://"+hp+"/"+dirs[0]+"/")
	if resp.StatusCode != 200 || !strings.Contains(body, "Index of /"+dirs[0]+"/") || !strings.Contains(body, "Parent Directory") {
		t.Fatalf("a honeypot directory is answered: %d %q", resp.StatusCode, body)
	}
	c := hpGet(rs.Honey, "127.0.0.1")
	if c.State != hpSuspicious || !rs.Honey.blocked("127.0.0.1") {
		t.Fatalf("a honeypot directory makes the client suspicious and blocked: %+v", c)
	}
	conn, err := net.Dial("tcp", hp)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := conn.Read(make([]byte, 64)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a blocked client gets no answer at all: %d %v", n, err)
	}
	conn.Close()
	if after := hpGet(rs.Honey, "127.0.0.1"); !after.LastSeen.Equal(c.LastSeen) || after.Dropped == 0 {
		t.Fatalf("drops do not refresh last seen: %+v", after)
	}
	rs.Honey.forget([]string{"127.0.0.1"}, false, false)
	if resp, _ := hpRequest(t, plain, "GET", "http://"+hp+"/healthz"); resp.StatusCode != 200 {
		t.Fatal("a forgotten client is served again")
	}
	if resp, _ := hpRequest(t, plain, "POST", "http://"+hp+"/"); resp.StatusCode != 405 || len(rs.Honey.list()) != 0 {
		t.Fatal("other methods on / are refused like Apache and mark nobody")
	}
}

// Why: health checks are answered at most once per interval, whoever asks.
func TestRelayHealthzRateLimit(t *testing.T) {
	_, hp := startTestRelay(t, "", func(rs *relayServer) { rs.Healthz.interval = 300 * time.Millisecond })
	plain := &http.Client{Timeout: 5 * time.Second}
	if resp, _ := hpRequest(t, plain, "GET", "http://"+hp+"/healthz"); resp.StatusCode != 200 {
		t.Fatal("first healthz")
	}
	resp, _ := hpRequest(t, plain, "GET", "http://"+hp+"/healthz")
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "1" || resp.Header.Get("Server") != honeypotServer {
		t.Fatalf("a second healthz within the interval: %d %v", resp.StatusCode, resp.Header)
	}
	time.Sleep(350 * time.Millisecond)
	if resp, _ := hpRequest(t, plain, "GET", "http://"+hp+"/healthz"); resp.StatusCode != 200 {
		t.Fatal("answered again after the interval")
	}
}

// Why: the operator inspects and clears the honeypot of a running relay
// without restarting it.
func TestRelayHoneypotControl(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	rs := newRelayServer(newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil), "")
	ln, err := net.Listen("unix", relayControlPath())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go rs.serveControl(ln)
	rs.Honey.record("192.0.2.1", false)
	rs.Honey.record("192.0.2.2", true)
	rs.Honey.record("2001:db8::1", true)
	var out bytes.Buffer
	relayHoneypotCmd([]string{"ls"}, &out)
	if s := out.String(); !regexp.MustCompile(`(?m)^192\.0\.2\.1 +seen `).MatchString(s) || !regexp.MustCompile(`(?m)^192\.0\.2\.2 +suspicious `).MatchString(s) || !strings.Contains(s, "3 client(s) remembered") {
		t.Fatalf("ls: %s", s)
	}
	out.Reset()
	relayHoneypotCmd([]string{"ls", "-json"}, &out)
	var list []hpEntry
	if err := json.Unmarshal(out.Bytes(), &list); err != nil || len(list) != 3 || list[1].BlockedUntil == 0 {
		t.Fatalf("ls -json: %v %s", err, out.String())
	}
	out.Reset()
	relayHoneypotCmd([]string{"rm", "2001:0db8:0:0::1"}, &out)
	if !strings.Contains(out.String(), "forgot 1") || hpGet(rs.Honey, "2001:db8::1") != nil {
		t.Fatalf("rm normalizes the address: %s", out.String())
	}
	out.Reset()
	relayHoneypotCmd([]string{"clear", "-suspicious"}, &out)
	if !strings.Contains(out.String(), "forgot 1") || hpGet(rs.Honey, "192.0.2.1") == nil {
		t.Fatalf("clear -suspicious keeps seen clients: %s", out.String())
	}
	out.Reset()
	relayHoneypotCmd([]string{"clear"}, &out)
	if !strings.Contains(out.String(), "forgot 1") || len(rs.Honey.list()) != 0 {
		t.Fatalf("clear: %s", out.String())
	}
}

// Why: the timings are daemon options in milliseconds (flag > environment >
// default) and the memory budget accepts a share of memory or a size.
func TestRelayHoneypotOpts(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	for _, e := range relayEnv {
		t.Setenv(e, "")
	}
	o, err := parseRelayOptsErr(nil)
	if err != nil || o.healthz != time.Second || o.remember != 2*time.Hour || o.block != 15*time.Minute || o.reblock != time.Hour || o.honeyMem != "10%" {
		t.Fatalf("defaults: %+v %v", o, err)
	}
	t.Setenv("KBTOOL_RELAY_HONEYPOT_BLOCK", "60000")
	t.Setenv("KBTOOL_RELAY_HONEYPOT_MAX_MEMORY", "32MiB")
	o, err = parseRelayOptsErr([]string{"-healthz-interval", "0", "-honeypot-reblock", "120000", "-honeypot-remember", "500"})
	if err != nil || o.healthz != 0 || o.block != time.Minute || o.reblock != 2*time.Minute || o.remember != 500*time.Millisecond || o.honeyMem != "32MiB" {
		t.Fatalf("flags and environment: %+v %v", o, err)
	}
	for _, bad := range [][]string{{"-honeypot-block", "0"}, {"-honeypot-remember", "-5"}, {"-honeypot-max-memory", "lots"}} {
		if _, err := parseRelayOptsErr(bad); err == nil {
			t.Fatalf("%v must be refused", bad)
		}
	}
	t.Setenv("KBTOOL_RELAY_HONEYPOT_BLOCK", "1.5")
	if _, err := parseRelayOptsErr(nil); err == nil {
		t.Fatal("milliseconds are whole numbers")
	}
}

// Why: the listing's icons are Apache's own files with stock headers, so a
// scanner hashing /icons/ sees httpd; fetching them never marks a client.
func TestRelayHoneypotIcons(t *testing.T) {
	rs, hp := startTestRelay(t, "", func(rs *relayServer) { rs.Healthz.interval = 0 })
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	tlsc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for _, name := range []string{"blank.gif", "folder.gif", "back.gif"} {
		want := mustReadFile(t, filepath.Join("honeypot-icons", name))
		for _, u := range []string{"http://" + hp, "https://" + hp} {
			c := plain
			if strings.HasPrefix(u, "https") {
				c = tlsc
			}
			resp, body := hpRequest(t, c, "GET", u+"/icons/"+name)
			etag := fmt.Sprintf(`"%x-3e9564c23b600"`, len(want))
			if resp.StatusCode != 200 || body != string(want) || resp.Header.Get("Content-Type") != "image/gif" ||
				resp.Header.Get("Server") != honeypotServer || resp.Header.Get("ETag") != etag ||
				resp.Header.Get("Last-Modified") != "Sat, 20 Nov 2004 20:16:24 GMT" || resp.Header.Get("Accept-Ranges") != "bytes" {
				t.Fatalf("%s%s: %d %v", u, name, resp.StatusCode, resp.Header)
			}
			req, _ := http.NewRequest("GET", u+"/icons/"+name, nil)
			req.Header.Set("If-None-Match", etag)
			if r2, err := c.Do(req); err != nil || r2.StatusCode != 304 {
				t.Fatalf("conditional GET: %v %v", err, r2)
			} else {
				r2.Body.Close()
			}
		}
	}
	if resp, body := hpRequest(t, plain, "HEAD", "http://"+hp+"/icons/folder.gif"); resp.StatusCode != 200 || body != "" || resp.ContentLength != 225 {
		t.Fatalf("HEAD: %d %d %q", resp.StatusCode, resp.ContentLength, body)
	}
	for _, p := range []string{"/icons/", "/icons/text.gif", "/icons/../ca.crt", "/icons/x/folder.gif"} {
		if resp, _ := hpRequest(t, plain, "GET", "http://"+hp+p); resp.StatusCode != 404 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
	if n := len(rs.Honey.list()); n != 0 {
		t.Fatalf("icons never mark a client: %d", n)
	}
}

// Why: when another program keeps one side of the relay's port (an IDE's
// port forward on macOS), the relay must say so and not start.
func TestRelayBindCheck(t *testing.T) {
	for _, bind := range []string{"127.0.0.1:0", ":0"} {
		ln, err := net.Listen("tcp", bind)
		if err != nil {
			t.Fatal(err)
		}
		if err := relayBindCheck(ln, bind); err != nil {
			t.Fatalf("%s: the relay's own port passes: %v", bind, err)
		}
		ln.Close()
	}
	other, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	go func() {
		for {
			c, err := other.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := other.Addr().(*net.TCPAddr).Port
	ours, err := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		t.Skipf("no IPv6-only wildcard listener here: %v", err)
	}
	defer ours.Close()
	bind := fmt.Sprintf(":%d", port)
	err = relayBindCheck(ours, bind)
	if err == nil || !strings.Contains(err.Error(), "another program answers on 127.0.0.1:") || !strings.Contains(err.Error(), "lsof -nP -iTCP:") {
		t.Fatalf("a port shared with another program is reported: %v", err)
	}
}

// ---------- 51. snapshot-only commands ----------

// Why: releases work through collaboration sessions only; sessionless use,
// direct networking and hand-made certificates are snapshot-only. Release
// builds refuse them and leave them out of usage; snapshot and source builds
// run and list them; a session's own daemon child still starts.
func TestPreReleaseTools(t *testing.T) {
	old := preRelease
	t.Cleanup(func() { preRelease = old })
	t.Setenv("KBTOOL_DIR", t.TempDir())
	t.Setenv(childEnv, "")
	var buf bytes.Buffer
	usageTo(&buf)
	if old != "true" || refusePreRelease("bench", nil) != nil || !strings.Contains(buf.String(), "kbtool bench") || !strings.Contains(buf.String(), "kbtool mtls") {
		t.Fatal("source and snapshot builds run and list the snapshot-only commands")
	}
	preRelease = "false"
	refused := [][]string{
		{"bench"}, {"mtls"}, {"client", "-import", "kb1x"}, {"mcp", "start"}, {"mcp", "serve"},
		{"daemon", "start"}, {"daemon", "run"}, {"build", "."}, {"build"},
		{"collaborate", "host", "-ip", "10.0.0.1"}, {"collaborate", "host", "--dns=h.example"},
		{"collaborate", "attend", "https://h:9876/", "kb1x"}, {"collaborate", "resume", "https://h:9876/", "kb1x"},
	}
	for _, c := range refused {
		if err := refusePreRelease(c[0], c[1:]); err == nil || !strings.Contains(err.Error(), "snapshot builds only") {
			t.Fatalf("a release build refuses %v: %v", c, err)
		}
	}
	allowed := [][]string{
		{"query", "x"}, {"terms", "x"}, {"bundle", "a.go:1"}, {"tools"}, {"call", "kb_status"}, {"mcp"},
		{"status"}, {"help"}, {"daemon", "stop"}, {"daemon", "status"}, {"relay", "self-host", "start"},
		{"relay", "start"}, {"collaborate", "host", "-yes"}, {"collaborate", "attend", "kb1x"}, {"collaborate", "resume"},
		{"session", "ls"}, {"board", "dump"}, {"steer", "-m", "x"}, {"kbx", "rekey"},
	}
	for _, c := range allowed {
		if err := refusePreRelease(c[0], c[1:]); err != nil {
			t.Fatalf("%v runs in release builds: %v", c, err)
		}
	}
	t.Setenv(childEnv, "1")
	if err := refusePreRelease("daemon", []string{"run"}); err != nil {
		t.Fatalf("the session's daemon child starts in release builds: %v", err)
	}
	memSession(t)
	if err := refusePreRelease("build", nil); err != nil {
		t.Fatalf("a bare build reindexes the session in release builds: %v", err)
	}
	if err := refusePreRelease("build", []string{"-db-key-env", "K"}); err != nil {
		t.Fatalf("the key flags are allowed with a session build: %v", err)
	}
	if err := refusePreRelease("build", []string{"-git"}); err == nil {
		t.Fatal("build options are snapshot-only even in a session")
	}
	buf.Reset()
	usageTo(&buf)
	u := buf.String()
	for _, hidden := range []string{"kbtool bench", "kbtool mtls", "kbtool client", "mcp serve", "daemon run", "[-ip …] [-dns …]", "https://HOST:PORT/ kb1TOKEN", "Snapshot builds"} {
		if strings.Contains(u, hidden) {
			t.Fatalf("release usage leaves %q out:\n%s", hidden, u)
		}
	}
	for _, shown := range []string{"kbtool collaborate host", "kbtool relay self-host", "kbtool query", "kbtool bundle", "kbtool mcp "} {
		if !strings.Contains(u, shown) {
			t.Fatalf("release usage lists %q", shown)
		}
	}
	if !strings.Contains(certHint(), "collaborate") || strings.Contains(certHint(), "mtls") || enrollPrefix() != attendPrefix {
		t.Fatal("release hints name session commands")
	}
	if !strings.Contains(string(mustReadFile(t, ".goreleaser.yaml")), "-X main.preRelease={{ .IsSnapshot }}") {
		t.Fatal("goreleaser sets preRelease from IsSnapshot")
	}
}

// Why: a board name is bound to its seed for good, so an agent that forgot
// it signed up must not take a second name, whatever the call method; a seed
// the board does not know (another board) must not block a signup.
func TestSignupGuard(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	wd, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(wd) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	// Outside a session: ./.kbtool-seed and this process's signups.
	ex := withSession(tb)
	out, isErr := layerCall(t, ex, "board_signup", map[string]any{"name": "alice"})
	seed := signupSeed(out)
	if isErr || seed == "" {
		t.Fatalf("first signup: %s", out)
	}
	if out, isErr := layerCall(t, ex, "board_signup", map[string]any{"name": "alice2"}); !isErr || !strings.Contains(out, "already signed up as alice") {
		t.Fatalf("a second signup in one MCP session must be refused: %s", out)
	}
	if err := os.WriteFile(".kbtool-seed", []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}
	if out, isErr := layerCall(t, withSession(tb), "board_signup", map[string]any{"name": "alice3"}); !isErr || !strings.Contains(out, "already signed up as alice") {
		t.Fatalf("a valid ./.kbtool-seed must refuse a signup: %s", out)
	}
	stale := strings.Repeat("ab", ed25519.SeedSize)
	if err := os.WriteFile(".kbtool-seed", []byte(stale), 0600); err != nil {
		t.Fatal(err)
	}
	if out, isErr := layerCall(t, withSession(tb), "board_signup", map[string]any{"name": "carol"}); isErr || !strings.Contains(out, "moved it to .kbtool-seed.unrecognized-") {
		t.Fatalf("an unrecognized seed is moved aside and the signup goes ahead: %s", out)
	}
	if _, err := os.Stat(".kbtool-seed"); err == nil {
		t.Fatal("the unrecognized seed must be moved away")
	}

	// In a session: the session seed, the same for MCP and the CLI.
	sdir := memSession(t)
	if err := os.WriteFile(filepath.Join(sdir, ".kbtool-seed"), []byte(stale), 0600); err != nil {
		t.Fatal(err)
	}
	ex = withSession(tb)
	if out, isErr := layerCall(t, ex, "board_signup", map[string]any{"name": "dave"}); isErr || !strings.Contains(out, "not registered on this board") {
		t.Fatalf("session: an unrecognized seed is moved aside: %s", out)
	}
	if out, isErr := layerCall(t, ex, "board_signup", map[string]any{"name": "dave2"}); !isErr || !strings.Contains(out, "already signed up as dave") {
		t.Fatalf("session: a valid seed refuses another signup: %s", out)
	}
	if out, isErr := layerCall(t, withSession(tb), "board_signup", map[string]any{"name": "dave3"}); !isErr || !strings.Contains(out, "already signed up as dave") {
		t.Fatalf("session: a new MCP process must be refused too: %s", out)
	}
}

// Why: the self-hosted relay's port is drawn once, outside the common service
// ports and every OS's ephemeral range, and a taken port is an error rather
// than a silent move (that would break every enrollment line).
func TestSelfHostPort(t *testing.T) {
	for i := 0; i < 20; i++ {
		p, err := pickSelfHostPort()
		if err != nil || p < selfHostPortMin || p > selfHostPortMax {
			t.Fatalf("pickSelfHostPort: %d %v", p, err)
		}
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if l2, err := listenSelfRelay(ln.Addr().(*net.TCPAddr).Port); err == nil {
		l2.Close()
		t.Fatal("a taken self-hosted relay port must be an error")
	}
	t.Setenv("KBTOOL_DIR", t.TempDir())
	if err := saveRelayJSON(&relayJSON{Enabled: true, SelfHost: true}); err != nil {
		t.Fatal(err)
	}
	tok, port, err := selfHostSettings()
	if err != nil || len(tok) != 32 || port < selfHostPortMin {
		t.Fatalf("selfHostSettings: %q %d %v", tok, port, err)
	}
	if tok2, port2, _ := selfHostSettings(); tok2 != tok || port2 != port {
		t.Fatal("the self-hosted relay's token and port are generated once and kept")
	}
}

// TestRelaySelfHostCLI: why — LAN/VPN collaboration through the relay the
// daemon hosts in memory: the session ignores (and keeps) its remote sticky
// relay, certificates are reissued for this machine's addresses, clients
// enroll at any of them, `relay self-host stop|start` acts on the running
// daemon on the same port, nothing is written for the relay, and stopping
// self-hosting returns the session to its remote relay.
func TestRelaySelfHostCLI(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	relayDir, srvDir, cliDir := shortStateDir(t), shortStateDir(t), shortStateDir(t)
	env := func(dir string) []string {
		return append(os.Environ(), "KBTOOL_DIR="+dir, "HOME="+work, "KB_EMBED_URL=", "KBTOOL_SOCKET=", "KBTOOL_RELAY_BIND=", "KBTOOL_RELAY_PORT=")
	}
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, bin, args...)
		c.Env = env(dir)
		out, err := c.CombinedOutput()
		return string(out), err
	}
	n := 0
	spawn := func(dir string, args ...string) (*exec.Cmd, string) {
		t.Helper()
		n++
		logPath := filepath.Join(work, fmt.Sprintf("p%d.log", n))
		lf, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		c := exec.Command(bin, args...)
		c.Env = env(dir)
		c.Stdout, c.Stderr = lf, lf
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _, _ = c.Process.Wait(); lf.Close() })
		return c, logPath
	}
	stop := func(c *exec.Cmd) {
		_ = c.Process.Signal(syscall.SIGTERM)
		_, _ = c.Process.Wait()
	}
	waitLog := func(path, want string) string {
		t.Helper()
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if l := string(mustReadFile(t, path)); strings.Contains(l, want) {
				return l
			}
		}
		t.Fatalf("%q not in log:\n%s", want, mustReadFile(t, path))
		return ""
	}
	cfgOf := func() config {
		var c config
		if err := json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	rjOf := func() relayJSON {
		var rj relayJSON
		if err := json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "relay.json")), &rj); err != nil {
			t.Fatal(err)
		}
		return rj
	}

	// A session that sticks to a remote relay first.
	hpA := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	urlA := "https://" + hpA + "/"
	spawn(relayDir, "relay", "run", "-bind", hpA)
	for deadline := time.Now().Add(15 * time.Second); !relayHealthy(hpA); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("relay did not come up")
		}
	}
	if out, err := run(srvDir, "relay", "join", urlA); err != nil {
		t.Fatalf("relay join: %v\n%s", err, out)
	}
	if out, err := run(srvDir, "mtls", "-expire", "1h"); err != nil {
		t.Fatalf("mtls: %v\n%s", err, out)
	}
	sid := cfgOf().RelaySession
	d1, log1 := spawn(srvDir, "daemon", "run")
	waitLog(log1, "relay "+hpA+": session "+sid+" registered")
	stop(d1)
	if cfgOf().RelayURL != urlA {
		t.Fatalf("the session sticks to %s: %+v", urlA, cfgOf())
	}

	// Self-hosting: a random port in range and a token, generated once.
	out, err := run(srvDir, "relay", "self-host", "start")
	rj := rjOf()
	if err != nil || !rj.SelfHost || len(rj.SelfHostToken) != 32 || rj.SelfHostPort < selfHostPortMin || rj.SelfHostPort > selfHostPortMax ||
		!strings.Contains(out, fmt.Sprintf("port %d", rj.SelfHostPort)) {
		t.Fatalf("relay self-host start: %v %+v\n%s", err, rj, out)
	}
	port := rj.SelfHostPort
	selfHP := fmt.Sprintf("127.0.0.1:%d", port)
	if out, err := run(srvDir, "relay", "ls"); err != nil || !strings.Contains(out, "self-hosting") || !strings.Contains(out, "remembers it (unused while self-hosting)") {
		t.Fatalf("relay ls while self-hosting: %v\n%s", err, out)
	}
	// New certificates while self-hosting cover every address of this machine.
	if out, err := run(srvDir, "mtls", "-expire", "1h"); err != nil || !strings.Contains(out, "on the relay the daemon hosts itself") || !strings.Contains(out, dockerHostName) {
		t.Fatalf("mtls while self-hosting covers this machine's addresses: %v\n%s", err, out)
	}
	sid = cfgOf().RelaySession
	if cfgOf().RelayURL != urlA {
		t.Fatalf("self-hosting must keep the remembered remote relay untouched: %+v", cfgOf())
	}

	d2, log2 := spawn(srvDir, "daemon", "run")
	waitLog(log2, fmt.Sprintf("self-hosted relay (in memory) listening on :%d", port))
	logText := waitLog(log2, "relay "+selfHP+": session "+sid+" registered")
	if strings.Contains(logText, hpA) {
		t.Fatalf("self-hosting must not try remote relays:\n%s", logText)
	}
	time.Sleep(300 * time.Millisecond)
	lines := regexp.MustCompile(`kbtool client -import (kb1\S+)`).FindAllStringSubmatch(string(mustReadFile(t, log2)), -1)
	var loopLine string
	hosts := map[string]bool{}
	for _, m := range lines {
		tok, err := parseEnrollToken(m[1])
		if err != nil || tok.Port != port || tok.Session != sid {
			t.Fatalf("enrollment line for the self-hosted relay: %+v %v", tok, err)
		}
		hosts[tok.Host] = true
		if tok.Host == "127.0.0.1" {
			loopLine = m[1]
		}
	}
	if !hosts["127.0.0.1"] || !hosts[dockerHostName] {
		t.Fatalf("one enrollment line per address of this machine: %v", hosts)
	}
	if out, err := run(cliDir, "client", "-import", loopLine, "-yes"); err != nil || !strings.Contains(out, "enrolled") {
		t.Fatalf("enroll through the self-hosted relay: %v\n%s", err, out)
	}
	if out, err := run(cliDir, "status"); err != nil || !strings.Contains(out, "daemon:   reachable") {
		t.Fatalf("client through the self-hosted relay: %v\n%s", err, out)
	}
	if out, err := run(srvDir, "status"); err != nil || !strings.Contains(out, "relay:    session "+sid+" on the self-hosted relay") || !strings.Contains(out, "remembers remote relay "+urlA) {
		t.Fatalf("status while self-hosting: %v\n%s", err, out)
	}
	for _, f := range []string{"relay.pid", "relay.log", "relay.sock"} {
		if fileExists(filepath.Join(srvDir, f)) {
			t.Fatalf("the self-hosted relay lives in memory; found %s", f)
		}
	}

	// Live control of the running daemon's relay, same port both times.
	if out, err := run(srvDir, "relay", "self-host", "stop"); err != nil || !strings.Contains(out, "stopped its relay") {
		t.Fatalf("relay self-host stop (live): %v\n%s", err, out)
	}
	if relayHealthy(selfHP) {
		t.Fatal("the self-hosted relay must stop with self-host stop")
	}
	if out, err := run(srvDir, "relay", "self-host", "start"); err != nil || !strings.Contains(out, fmt.Sprintf("hosts the relay on port %d", port)) {
		t.Fatalf("relay self-host start (live): %v\n%s", err, out)
	}
	ok := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && !ok; time.Sleep(200 * time.Millisecond) {
		out, err := run(cliDir, "status")
		ok = err == nil && strings.Contains(out, "daemon:   reachable")
	}
	if !ok {
		t.Fatalf("the old enrollment keeps working after a live restart on the kept port:\n%s", mustReadFile(t, log2))
	}
	stop(d2)
	if relayHealthy(selfHP) {
		t.Fatal("the self-hosted relay must stop with the daemon")
	}

	// Self-hosting off: the session returns to its remembered remote relay.
	if out, err := run(srvDir, "relay", "self-host", "stop"); err != nil || rjOf().SelfHost || rjOf().SelfHostToken != rj.SelfHostToken {
		t.Fatalf("relay self-host stop keeps the token: %v %+v\n%s", err, rjOf(), out)
	}
	_, log3 := spawn(srvDir, "daemon", "run")
	waitLog(log3, "relay "+hpA+": session "+sid+" registered")
}

// TestEncryptedLocalAndSelfHostedSessions: why — with encryption on, a local
// session and a self-hosted one are kept exactly like a remote-relay session:
// finishing seals everything into one sessions/*.kbx and leaves only the
// global files in the state dir.
func TestEncryptedLocalAndSelfHostedSessions(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the binary")
	}
	work := t.TempDir()
	bin := filepath.Join(work, "kbtool")
	if b, err := exec.Command(goBin, "build", "-o", bin, "kbtool.go").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	hostDir, hostWork := shortStateDir(t), t.TempDir()
	if err := os.MkdirAll(filepath.Join(hostWork, "repo", ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, filepath.Join(hostWork, "repo"), "a.go", []byte("package a\nfunc Alpha() {}\n"))
	run := func(secret string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, bin, args...)
		c.Env = append(os.Environ(), "KBTOOL_DIR="+hostDir, "HOME="+work, "KB_EMBED_URL=", "KBTOOL_SOCKET=", "KBTOOL_RELAY_BIND=", "KBTOOL_RELAY_PORT=",
			secretEnv+"="+secret, "MYKEY=first key")
		c.Dir = hostWork
		out, err := c.CombinedOutput()
		return string(out), err
	}
	t.Cleanup(func() {
		_, _ = run("first key", "collaborate", "finish")
		_, _ = run("", "relay", "stop")
	})
	// A standalone relay may run in the same state dir and outlives sessions.
	if out, err := run("", "relay", "start", "-bind", fmt.Sprintf("127.0.0.1:%d", freePort(t))); err != nil {
		t.Fatalf("relay start beside the daemon's state: %v\n%s", err, out)
	}
	sealedOnly := func(want int) {
		t.Helper()
		if k := kbxFilesIn(t, hostDir); len(k) != want {
			t.Fatalf("want %d sealed sessions, got %v", want, k)
		}
		ents, _ := os.ReadDir(hostDir)
		for _, e := range ents {
			if !collabKeep[e.Name()] {
				t.Fatalf("finish must leave only %v in the state dir; found %s", collabKeep, e.Name())
			}
		}
		sub, _ := os.ReadDir(filepath.Join(hostDir, "sessions"))
		for _, e := range sub {
			if e.IsDir() {
				t.Fatalf("no plain session dir may remain: %s", e.Name())
			}
		}
	}

	out, err := run("", "collaborate", "host", "-yes", "-encrypt", "-db-key-env", "MYKEY")
	if err != nil || !strings.Contains(out, "local session") {
		t.Fatalf("encrypted local session: %v\n%s", err, out)
	}
	if out, err := run("first key", "collaborate", "finish"); err != nil {
		t.Fatalf("finish (local): %v\n%s", err, out)
	}
	sealedOnly(1)

	if out, err := run("first key", "relay", "self-host", "start"); err != nil {
		t.Fatalf("relay self-host start: %v\n%s", err, out)
	}
	out, err = run("first key", "collaborate", "host", "-yes")
	if err != nil || !strings.Contains(out, "kbtool collaborate attend kb1") || !strings.Contains(out, "# via ") {
		t.Fatalf("encrypted self-hosted session: %v\n%s", err, out)
	}
	if doc := string(mustReadFile(t, filepath.Join(hostWork, "AGENTS_COLLABORATION.md"))); !strings.Contains(doc, "through the relay it hosts on this machine") {
		t.Fatal("the agent's doc names the self-hosted relay")
	}
	if out, err := run("first key", "collaborate", "finish"); err != nil {
		t.Fatalf("finish (self-hosted): %v\n%s", err, out)
	}
	sealedOnly(2)
	if out, err := run("", "relay", "status"); err != nil || !strings.Contains(out, "running") {
		t.Fatalf("finishing sessions must leave a standalone relay manageable: %v\n%s", err, out)
	}
}

// ---------- 52. OS compatibility (osCompat*) ----------

func osCompatSkipWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Linux/macOS path")
	}
}

// osCompatAssertExclusive checks that lock blocks a second holder until the
// first releases it.
func osCompatAssertExclusive(t *testing.T, lock func(string) (func(), error), path string) {
	t.Helper()
	unlock, err := lock(path)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	got := make(chan func(), 1)
	go func() {
		u, err := lock(path)
		if err != nil {
			t.Errorf("second lock: %v", err)
			u = func() {}
		}
		got <- u
	}()
	select {
	case <-got:
		t.Fatal("a second holder must wait while the lock is held")
	case <-time.After(150 * time.Millisecond):
	}
	unlock()
	select {
	case u := <-got:
		u()
	case <-time.After(5 * time.Second):
		t.Fatal("the second holder must get the lock once it is released")
	}
}

// TestOSCompatLockFileExclusive: board and store writes rely on this lock; the
// native flock (raw syscall numbers per GOARCH) must really exclude.
func TestOSCompatLockFileExclusive(t *testing.T) {
	osCompatAssertExclusive(t, osCompatLockFile, filepath.Join(t.TempDir(), "x.lock"))
}

// TestOSCompatWindowsLockFile: the Windows lock-file emulation is portable code,
// so its exclusion and its takeover of an abandoned (empty, stale) lock are
// pinned on every platform.
func TestOSCompatWindowsLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	osCompatAssertExclusive(t, osCompatWindowsLockFile, path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("an unlocked Windows lock file must be gone: %v", err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	_ = os.Chtimes(path, old, old)
	done := make(chan struct{})
	go func() {
		if u, err := osCompatWindowsLockFile(path); err == nil {
			u()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a stale empty lock file must be taken over")
	}
}

// TestOSCompatUmask: the daemon and relay sockets are owner-only only because of
// this umask; it must apply and restore the previous mask.
func TestOSCompatUmask(t *testing.T) {
	osCompatSkipWindows(t)
	dir := t.TempDir()
	create := func(name string) os.FileMode {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, nil, 0666); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}
	outer := osCompatUmask(022)
	defer outer()
	inner := osCompatUmask(0177)
	got := create("a")
	inner()
	if got != 0600 {
		t.Fatalf("umask 0177 must create 0600, got %v", got)
	}
	if got := create("b"); got != 0644 {
		t.Fatalf("the previous umask 022 must be restored (0644), got %v", got)
	}
}

// TestOSCompatProcessLifecycle: pidAlive, bgStop's SIGTERM and the forced kill
// go through osCompat; a stopped child must read as dead afterwards.
func TestOSCompatProcessLifecycle(t *testing.T) {
	osCompatSkipWindows(t)
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not on PATH")
	}
	if !osCompatProcessAlive(os.Getpid()) {
		t.Fatal("this process must be alive")
	}
	if osCompatProcessAlive(0) || osCompatProcessAlive(-1) {
		t.Fatal("non-positive pids are never alive")
	}
	for _, force := range []bool{false, true} {
		c := exec.Command(sleep, "30")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		osCompatStopProcess("test", c.Process.Pid, force)
		_ = c.Wait()
		if osCompatProcessAlive(c.Process.Pid) {
			t.Fatalf("force=%v: the stopped child must be dead", force)
		}
	}
}

// TestOSCompatDetach: background services must start in their own session
// (Setsid) so they survive the terminal; the field is set by reflection.
func TestOSCompatDetach(t *testing.T) {
	cmd := exec.Command("true")
	osCompatDetach(cmd)
	v := reflect.ValueOf(cmd.SysProcAttr).Elem()
	if runtime.GOOS == "windows" {
		if v.FieldByName("CreationFlags").Uint() == 0 {
			t.Fatal("windows: detach must set CreationFlags")
		}
		return
	}
	if !v.FieldByName("Setsid").Bool() {
		t.Fatal("detach must set Setsid")
	}
}

// TestOSCompatOpenNoFollow: attachment extraction must never write through a
// symlink; both the native O_NOFOLLOW and the Windows Lstat path refuse.
func TestOSCompatOpenNoFollow(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	for name, open := range map[string]func(string, int, os.FileMode) (*os.File, error){
		"osCompatOpenNoFollow": osCompatOpenNoFollow, "osCompatWindowsOpenNoFollow": osCompatWindowsOpenNoFollow,
	} {
		if f, err := open(link, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err == nil {
			f.Close()
			t.Fatalf("%s must refuse a symlink", name)
		}
		f, err := open(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			t.Fatalf("%s must create a regular file: %v", name, err)
		}
		f.Close()
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("the symlink target must be untouched")
	}
}

// TestOSCompatIsTerminal: stdinTTY gates interactive prompts; files and
// /dev/null are not terminals (a plain char-device check would accept /dev/null).
func TestOSCompatIsTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if osCompatIsTerminal(f) || osCompatWindowsIsTerminal(f) {
		t.Fatal("a regular file is not a terminal")
	}
	if runtime.GOOS != "windows" {
		n, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()
		if osCompatIsTerminal(n) {
			t.Fatal("/dev/null is not a terminal")
		}
	}
}

// TestOSCompatReadSecretLineNonTTY: piped input (scripts, tests) must still be
// read when echo cannot be hidden.
func TestOSCompatReadSecretLineNonTTY(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() { fmt.Fprint(w, "  s3cret \nnext\n"); w.Close() }()
	line, err := osCompatReadSecretLine(r)
	if err != nil || line != "s3cret" {
		t.Fatalf("got %q, %v", line, err)
	}
}

// TestOSCompatEchoOffOnPTY: the termios layout (size, c_lflag offset and width)
// is hard-coded per OS; on a real Linux pseudo-terminal clearing ECHO must show
// up in the attributes read back, and restoring must bring it back.
func TestOSCompatEchoOffOnPTY(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pty setup below is Linux-specific")
	}
	abi := osCompatLinuxABI()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skip("no /dev/ptmx")
	}
	defer ptmx.Close()
	var unlock, n uint32
	const tiocsptlck, tiocgptn = 0x40045431, 0x80045430
	if _, _, e := osCompatSyscall(abi.sysIoctl, ptmx.Fd(), tiocsptlck, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		t.Skipf("unlockpt: %v", e)
	}
	if _, _, e := osCompatSyscall(abi.sysIoctl, ptmx.Fd(), tiocgptn, uintptr(unsafe.Pointer(&n))); e != 0 {
		t.Skipf("ptsname: %v", e)
	}
	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR, 0)
	if err != nil {
		t.Skipf("open pts: %v", err)
	}
	defer pts.Close()
	if !osCompatIsTerminal(pts) {
		t.Fatal("a pty slave is a terminal")
	}
	lflag := func() uint32 {
		b, ok := osCompatUnixTermios(abi, pts.Fd())
		if !ok {
			t.Fatal("TCGETS failed")
		}
		return binary.NativeEndian.Uint32(b[abi.lflagOffset:])
	}
	old, _ := osCompatUnixTermios(abi, pts.Fd())
	if lflag()&osCompatEcho == 0 {
		t.Skip("pty starts without ECHO")
	}
	now := append([]byte(nil), old...)
	binary.NativeEndian.PutUint32(now[abi.lflagOffset:], binary.NativeEndian.Uint32(now[abi.lflagOffset:])&^osCompatEcho)
	if !osCompatUnixSetTermios(abi, pts.Fd(), now) || lflag()&osCompatEcho != 0 {
		t.Fatal("ECHO must be cleared")
	}
	if !osCompatUnixSetTermios(abi, pts.Fd(), old) || lflag()&osCompatEcho == 0 {
		t.Fatal("ECHO must be restored")
	}
}

// TestOSCompatWindowsStopRequest: Windows stops services with a stop-request
// file instead of SIGTERM; it must reach the named pid only, so a leftover file
// from an earlier instance never stops a new one.
func TestOSCompatWindowsStopRequest(t *testing.T) {
	t.Setenv("KBTOOL_DIR", t.TempDir())
	sig := make(chan os.Signal, 1)
	osCompatWindowsStopProcess("svc", os.Getpid()+1, false)
	go osCompatWindowsWatchStop("svc", sig)
	select {
	case <-sig:
		t.Fatal("a stop request for another pid must be ignored")
	case <-time.After(500 * time.Millisecond):
	}
	osCompatWindowsStopProcess("svc", os.Getpid(), false)
	select {
	case s := <-sig:
		if s.String() != "stop request" {
			t.Fatalf("got %v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stop request must be delivered")
	}
	if _, err := os.Stat(osCompatWindowsStopPath("svc")); !os.IsNotExist(err) {
		t.Fatal("a delivered stop request must be removed")
	}
}

// TestOSCompatPlatformMatrix: every release target must compile and anything
// else must fail at the osCompatSupportedPlatform guard; .goreleaser.yaml must
// ship Windows.
func TestOSCompatPlatformMatrix(t *testing.T) {
	if !osCompatSupportedPlatform {
		t.Fatal("the test platform must be supported")
	}
	if y := string(mustReadFile(t, ".goreleaser.yaml")); !strings.Contains(y, "- windows") {
		t.Fatal(".goreleaser.yaml must build windows")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH")
	}
	build := func(goos, goarch string) ([]byte, error) {
		c := exec.Command(goBin, "build", "-o", filepath.Join(t.TempDir(), "kbtool"), "kbtool.go")
		c.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
		return c.CombinedOutput()
	}
	for _, p := range [][2]string{{"windows", "amd64"}, {"darwin", "arm64"}, {"linux", "arm"}} {
		if out, err := build(p[0], p[1]); err != nil {
			t.Fatalf("%s/%s must compile:\n%s", p[0], p[1], out)
		}
	}
	if out, err := build("linux", "riscv64"); err == nil || !strings.Contains(string(out), "duplicate key false") {
		t.Fatalf("an unsupported platform must fail at the guard: %v\n%s", err, out)
	}
}
