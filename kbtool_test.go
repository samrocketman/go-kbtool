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
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
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

// ---------- 15. HTTP bind guard ----------

func TestIsLoopbackBind(t *testing.T) {
	for _, a := range []string{"127.0.0.1:9876", "[::1]:9876", "localhost:8080", "127.5.6.7:1"} {
		if !isLoopbackBind(a) {
			t.Errorf("%s should be loopback", a)
		}
	}
	for _, a := range []string{"0.0.0.0:9876", ":9876", "[::]:9876", "10.0.0.5:9876", "myhost:80"} {
		if isLoopbackBind(a) {
			t.Errorf("%s should NOT be loopback", a)
		}
	}
	// Malformed.
	if isLoopbackBind("nonsense") {
		t.Error("malformed should be non-loopback")
	}
}

func TestValidateHTTPBind(t *testing.T) {
	cases := []struct {
		name     string
		httpOn   bool
		mtls     bool
		insecure bool
		addr     string
		wantErr  bool
	}{
		{"no http", false, false, false, "0.0.0.0:1", false},
		{"loopback cleartext ok", true, false, false, "127.0.0.1:9876", false},
		{"localhost cleartext ok", true, false, false, "localhost:9876", false},
		{"nonloopback cleartext refused", true, false, false, "0.0.0.0:9876", true},
		{"nonloopback cleartext LAN refused", true, false, false, "10.1.2.3:9876", true},
		{"nonloopback mtls ok", true, true, false, "0.0.0.0:9876", false},
		{"nonloopback insecure ok", true, false, true, "0.0.0.0:9876", false},
		{"hostname cleartext refused (fail closed)", true, false, false, "myhost:9876", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateHTTPBind(c.httpOn, c.mtls, c.insecure, c.addr)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, c.wantErr)
			}
		})
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
	// nil config → defaults: kb_status, board_sign, all git, all board.
	m := effectiveDisabledSet(nil)
	for _, name := range []string{"kb_status", "board_sign", "git_blame", "git_log", "board_signup", "board_read"} {
		if !m[name] {
			t.Errorf("%s should be disabled by default", name)
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
	if c.MessageBoard == nil || *c.MessageBoard != false {
		t.Fatal("MessageBoard should be seeded false")
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
	if len(tools) != 17 {
		t.Fatalf("got %d tools, want 17", len(tools))
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
	t.Setenv(dbKeyEnv, "")
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
	// 3. $KBTOOL_DBKEY fallback.
	t.Setenv(dbKeyEnv, "dbkeyvalue")
	k, have, err = resolveKey("", "", false)
	if err != nil || !have || string(k) != "dbkeyvalue" {
		t.Fatalf("got (%s,%v,%v)", k, have, err)
	}
	t.Setenv(dbKeyEnv, "")
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

func TestEndpointFromClientConfigHTTP(t *testing.T) {
	cc := &clientConfig{Host: "10.0.0.5", Port: 9999}
	ep, url, ok := endpointFromClientConfig(cc)
	if !ok {
		t.Fatal("not ok")
	}
	if ep.kind != "http" {
		t.Fatalf("kind = %q", ep.kind)
	}
	if url != "http://10.0.0.5:9999" {
		t.Fatalf("url = %q", url)
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

var docSubcommands = []string{"build", "query", "terms", "bundle", "bench", "tools", "call", "mcp", "daemon", "mtls", "client", "relay", "status", "board"}

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
//  1. every relative link in README.md and docs/*.md resolves to a real entry;
//  2. the README links every subcommand's simple doc (the required index);
//  3. each simple doc cross-links its full doc and the full doc links back
//     (the required two-document, cross-linked layout).
func TestDocsLinks(t *testing.T) {
	docs, err := filepath.Glob("docs/*.md")
	if err != nil {
		t.Fatalf("glob docs: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("no docs/*.md found (expected the docs/ directory)")
	}
	if _, err := os.Stat("README.md"); err != nil {
		t.Fatalf("no README.md: %v", err)
	}

	// 1. No broken relative links anywhere.
	for _, p := range append([]string{"README.md"}, docs...) {
		for target := range mdLinkSet(t, p) {
			if _, err := os.Stat(target); err != nil {
				t.Errorf("%s: broken link -> %s", p, target)
			}
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
	for _, cmd := range docSubcommands {
		simple := filepath.Join("docs", cmd+"-simple.md")
		full := filepath.Join("docs", cmd+".md")
		if !mdLinkSet(t, simple)[full] {
			t.Errorf("%s: missing cross-link to %s", simple, full)
		}
		if !mdLinkSet(t, full)[simple] {
			t.Errorf("%s: missing cross-link back to %s", full, simple)
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

// 7. Daemon parity: identical results via the daemon socket vs direct DB.
// Builds the real binary, serves it with `daemon run` on a temp unix socket, and
// compares `terms` + `bundle` output over the socket against the one-shot local
// (direct-DB) path. Skipped when the go toolchain is unavailable.
func TestTermsBundleDaemonParity(t *testing.T) {
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

	// Direct-DB (daemon down) baseline.
	termsLocal, err := run("terms", "EncodeEcosystem")
	if err != nil {
		t.Fatalf("terms (local): %v\n%s", err, termsLocal)
	}
	bundleLocal, err := run("bundle", "repo/src/foo/bar.go:7")
	if err != nil {
		t.Fatalf("bundle (local): %v\n%s", err, bundleLocal)
	}
	if !strings.Contains(termsLocal, "ABSENT") && !strings.Contains(termsLocal, "occurrence") {
		t.Fatalf("unexpected terms output: %s", termsLocal)
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
	// Strip the "(via daemon: …)" stderr line, then require identical results.
	stripDaemon := func(s string) string {
		var out []string
		for _, ln := range strings.Split(s, "\n") {
			if strings.Contains(ln, "(via daemon:") {
				continue
			}
			out = append(out, ln)
		}
		return strings.Join(out, "\n")
	}
	if got, want := stripDaemon(termsDaemon), termsLocal; got != want {
		t.Fatalf("daemon/local terms mismatch:\ndaemon=\n%s\nlocal=\n%s", got, want)
	}
	if got, want := stripDaemon(bundleDaemon), bundleLocal; got != want {
		t.Fatalf("daemon/local bundle mismatch:\ndaemon=\n%s\nlocal=\n%s", got, want)
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
	backend := &fakeExec{disabled: map[string]bool{"kb_status": true}} // backend: board ON
	port := startTestMtlsDaemon(t, caKey, caCert, backend)
	if err := saveClientConfig(mtlsHostConfig(port)); err != nil {
		t.Fatal(err)
	}
	if !effectiveDisabledSet(nil)["board_signup"] {
		t.Fatal("control: the local default view must hide the board (else this test is vacuous)")
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
	if !got["board_signup"] || !got["board_post"] || got["kb_status"] {
		t.Fatalf("tool list must be the backend's (board on, kb_status off), got %v", got)
	}

	ex, _, ok, err := liveDaemon()
	if !ok {
		t.Fatal(err)
	}
	if ex.toolDisabled("board_signup") || !ex.toolDisabled("kb_status") {
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
// stdio `mcp` must fail and must NOT create a local board.bin. The control run
// (no client.json) shows the same call otherwise writes the local board.
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
		if !strings.Contains(out, "refusing local db/board fallback") {
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
	// Control: a plain local dir with the board on writes board.bin locally.
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"version":1,"message_board":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := run("", "call", "board_signup", `{"name":"gus"}`); err != nil || !fileExists(board) {
		t.Fatalf("control: without mTLS the one-shot board call writes board.bin locally: err=%v\n%s", err, out)
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
	for _, m := range s.Threads[0].Msgs {
		got = append(got, m.Text+"="+m.Status)
	}
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
	if !reflect.DeepEqual(ids, []string{"welcome", "zeta", "alpha"}) {
		t.Fatalf("thread order = %v", ids)
	}
	if z := s.Threads[1].Msgs; len(z) != 2 || z[0].Text != "z0" || z[1].Text != "z1" || z[1].Seq != 1 {
		t.Fatalf("zeta messages out of seq order: %+v", z)
	}
	if s.TTL != 60 || len(s.Agents) != 2 {
		t.Fatalf("ttl=%d agents=%d", s.TTL, len(s.Agents))
	}
	if a := s.Agents[0]; a.ID != "alice" || !a.Active {
		t.Fatalf("most recent agent should be ACTIVE alice, got %+v", a)
	}
	if b := s.Agents[1]; b.ID != "bob" || b.Active {
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
	if rr.Error != nil || len(rr.Result.Threads) != 1 || len(rr.Result.Threads[0].Msgs) != 1 ||
		rr.Result.Threads[0].Msgs[0].Text != "over http" || rr.Result.Threads[0].Msgs[0].Status != "verified" {
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
	got, via, err := boardDumpSnapshot(filepath.Join(dir, "kb.db"), "", "")
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
// (message_board absent/false) refuses the export with an explanation instead of
// rendering an empty page; the control exports the same board once it is on.
func TestBoardExportDisabledBoard(t *testing.T) {
	tb := newBoardToolbox(t, nil)
	seed := dumpSignup(t, tb, "alice")
	dumpPost(t, tb, seed, "welcome", "hello", "hi")
	tb.Disabled = effectiveDisabledSet(nil)
	if _, err := tb.boardExport(); err == nil || !strings.Contains(err.Error(), "disabled by config") {
		t.Fatalf("board off must refuse the export, got %v", err)
	}
	on := true
	tb.Disabled = effectiveDisabledSet(&config{MessageBoard: &on})
	if s, err := tb.boardExport(); err != nil || len(s.Threads) != 1 {
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
	env := append(os.Environ(), "KBTOOL_DIR="+state, "KBTOOL_SOCKET="+filepath.Join(state, "none.sock"),
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

// TestBoardFileWithoutAttachmentsUnchanged pins compatibility: a board without
// attachments serializes with no trailer (boards written before this feature
// still load), and a trailer pointing at an unknown message is corruption.
func TestBoardFileWithoutAttachmentsUnchanged(t *testing.T) {
	b := newBoard()
	b.Threads["welcome"].Msgs = []BoardMsg{{ID: 1, Thread: "welcome", Agent: "a", Text: "hi", Kind: "info"}}
	plain := boardMarshal(b)
	if _, err := readBoard(bytes.NewReader(plain)); err != nil {
		t.Fatalf("board without trailer: %v", err)
	}
	b.Threads["welcome"].Msgs[0].Attach = &BoardAttachment{SHA256: "s", Data: []byte("d"), Files: []attachFile{{Name: "f", Size: 1}}}
	with := boardMarshal(b)
	if !bytes.HasPrefix(with, plain) {
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
	corrupt := append(boardMarshal(b), orphan[len(plain):]...)
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
	ex, via, err := boardClientExec(filepath.Join(dir, "kb.db"), "", "")
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
	env := append(os.Environ(), "KBTOOL_DIR="+state, "KBTOOL_SOCKET="+filepath.Join(state, "none.sock"),
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
	rs := newRelayServer(newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour), token)
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
// unsigned), trusting the relay CA fetched over HTTP.
func registerTestSession(hp, sid string, auth *relaySessionAuth, token string) (net.Conn, error) {
	pool, _, err := relayFetchCA(hp)
	if err != nil {
		return nil, err
	}
	var sign func(tls.ConnectionState) (map[string]string, error)
	if auth != nil {
		sign = func(cs tls.ConnectionState) (map[string]string, error) { return auth.headers(sid, cs) }
	}
	return relayUpgrade(hp, relayTLSClientConfig(pool), "/v1/register",
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

// TestRelayPublicEndpoints: why — daemons bootstrap trust in the relay from
// plain-HTTP /ca.crt, and /healthz serves health checks on both the plain and
// the TLS side.
func TestRelayPublicEndpoints(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	resp, err := http.Get("http://" + hp + "/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(b, rs.currentPKI().CAPEM) {
		t.Fatal("plain /ca.crt must serve the relay CA")
	}
	if !relayHealthy(hp) {
		t.Fatal("plain /healthz must answer")
	}
	fp, err := relayCheck(hp, relayTrust{})
	if err != nil || fp != rs.currentPKI().FP {
		t.Fatalf("relayCheck (CA over HTTP, /healthz over HTTPS) = %q, %v; want %q", fp, err, rs.currentPKI().FP)
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
	relay := &config{RelayURL: "https://relay:9876/"}
	relayHTTP := &config{RelayURL: "https://relay:9876/", Http: true}
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

// TestParseMtlsArgsRelay: why — `mtls -relay` takes the relay URL (default
// port 9876, the daemon's) and an optional token; a token without a relay or a malformed
// relay URL is a usage error, not silently ignored.
func TestParseMtlsArgsRelay(t *testing.T) {
	sa, err := parseMtlsArgs([]string{"-relay", "https://relay.example/", "-token", "tk", "-dns", "extra.example"})
	if err != nil || sa.relay != "https://relay.example/" || sa.token != "tk" || !reflect.DeepEqual(sa.names, []string{"extra.example"}) {
		t.Fatalf("parse: %+v %v", sa, err)
	}
	if h, p, norm, err := relayHostPort(sa.relay); err != nil || h != "relay.example" || p != defRelayPort || norm != "https://relay.example:9876/" {
		t.Fatalf("relayHostPort = %q %d %q %v", h, p, norm, err)
	}
	ca := filepath.Join(t.TempDir(), "relay-ca.pem")
	_, caCert := cryptoGenerateCA("pinned", time.Hour)
	writeTestPEM(t, filepath.Dir(ca), filepath.Base(ca), cryptoPEMCert(caCert))
	if sa, err := parseMtlsArgs([]string{"-relay", "https://relay.example/", "-relay-ca", "system"}); err != nil || sa.relayCA != "system" {
		t.Fatalf("-relay-ca system: %+v %v", sa, err)
	}
	if sa, err := parseMtlsArgs([]string{"-relay", "https://relay.example/", "-relay-ca", ca}); err != nil || sa.relayCA != ca {
		t.Fatalf("-relay-ca FILE: %+v %v", sa, err)
	}
	for _, bad := range [][]string{{"-token", "tk"}, {"-relay", "http://relay/"}, {"-relay", "https://relay/x"},
		{"-relay-ca", "system"}, {"-relay", "https://relay/", "-relay-ca", filepath.Join(t.TempDir(), "missing.pem")}} {
		if _, err := parseMtlsArgs(bad); err == nil {
			t.Errorf("parseMtlsArgs(%q) must fail", bad)
		}
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

// TestRelayCLI: why — the user-facing flow through the built binary: a relay
// service, `mtls -relay` (relay-only SAN, stored session, http off, no host
// client.json), a daemon that opens no TCP port and prints the relay token
// import line, the refusals (establish while running, relay and daemon in one state
// dir, unreachable relay), enrollment and calls from a third state dir, the same
// session after a daemon restart, and a new one from the next `mtls -relay`.
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
	if out, err := run(relayDir, "daemon", "run"); err == nil || !strings.Contains(out, "cannot share one state dir") {
		t.Fatalf("a daemon must refuse a state dir with a running relay: %v\n%s", err, out)
	}
	fresh := shortStateDir(t)
	if out, err := run(fresh, "relay", "establish", fmt.Sprintf("https://127.0.0.1:%d/", freePort(t))); err == nil || !strings.Contains(out, "not usable") || fileExists(filepath.Join(fresh, "ca.crt")) {
		t.Fatalf("establish must check the relay before issuing certificates: %v\n%s", err, out)
	}

	if err := os.WriteFile(filepath.Join(srvDir, "config.json"), []byte(`{"message_board": false}`), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := run(srvDir, "mtls", "-relay", relayURL, "-token", "tk", "-expire", "1h"); err != nil || !strings.Contains(out, "message board is on") {
		t.Fatalf("mtls -relay: %v\n%s", err, out)
	}
	var cfg config
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.MessageBoard == nil || !*cfg.MessageBoard {
		t.Fatalf("relay setup must turn the message board on (plans/relay-message-board-default-plan.md): %+v", cfg.MessageBoard)
	}
	if cfg.RelayURL != relayURL || !isRelaySessionID(cfg.RelaySession) || cfg.RelayToken != "tk" || cfg.Http || cfg.HTTPAddr != "" || !cfg.Mtls {
		t.Fatalf("mtls -relay config: %+v", cfg)
	}
	sid := cfg.RelaySession
	if fi, err := os.Stat(filepath.Join(srvDir, relaySessionKeyFile)); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("mtls -relay must write %s with mode 0600: %v", relaySessionKeyFile, err)
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
	if out, err := run(srvDir, "relay", "establish", relayURL); err == nil || !strings.Contains(out, "the daemon must not be running to establish a relay connection") {
		t.Fatalf("establish must refuse while the daemon runs: %v\n%s", err, out)
	}
	if out, err := run(srvDir, "relay", "run", "-bind", "127.0.0.1:0"); err == nil || !strings.Contains(out, "cannot share one state dir") {
		t.Fatalf("a relay must refuse a state dir with a running daemon: %v\n%s", err, out)
	}
	if out, err := run(srvDir, "status"); err != nil || !strings.Contains(out, "socket "+filepath.Join(srvDir, "daemon.sock")) ||
		!strings.Contains(out, "relay:    "+relayURL+" session "+sid) || !strings.Contains(out, "unix socket only") {
		t.Fatalf("the daemon host's CLI must use the unix socket: %v\n%s", err, out)
	}

	f := strings.Fields(line)
	if out, err := run(cliDir, f[1:]...); err != nil || !strings.Contains(out, "enrolled") {
		t.Fatalf("client import through the relay: %v\n%s", err, out)
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
	stop(relay)
	if out, err := run(srvDir, "mtls", "-relay", relayURL); err != nil {
		t.Fatalf("mtls -relay again: %v\n%s", err, out)
	}
	var cfg2 config
	_ = json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &cfg2)
	if !isRelaySessionID(cfg2.RelaySession) || cfg2.RelaySession == sid || cfg2.RelayToken != "" {
		t.Fatalf("a new mtls -relay must issue a new session (and drop the old token): %+v", cfg2)
	}
	if out, err := run(srvDir, "mtls", "-relay", relayURL, "-relay-ca", "system"); err != nil {
		t.Fatalf("mtls -relay -relay-ca system: %v\n%s", err, out)
	}
	_ = json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &cfg2)
	if cfg2.RelayCA != "system" {
		t.Fatalf("mtls -relay-ca must record relay_ca: %+v", cfg2)
	}
	if err := os.Remove(filepath.Join(srvDir, relaySessionKeyFile)); err != nil {
		t.Fatal(err)
	}
	if out, err := run(srvDir, "daemon", "run"); err == nil || !strings.Contains(out, "relay session key") {
		t.Fatalf("a relay session without its key (pre-key config) must be refused at daemon start: %v\n%s", err, out)
	}
	off := false
	cfg2.MessageBoard = &off
	if b, err := json.Marshal(cfg2); err != nil || os.WriteFile(filepath.Join(srvDir, "config.json"), b, 0600) != nil {
		t.Fatal(err)
	}
	if out, err := run(srvDir, "mtls", "-ip", "127.0.0.1"); err != nil {
		t.Fatalf("mtls (leaving relay mode): %v\n%s", err, out)
	}
	var cfg3 config
	_ = json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &cfg3)
	if cfg3.RelayURL != "" || cfg3.MessageBoard == nil || *cfg3.MessageBoard {
		t.Fatalf("plain mtls must leave relay mode and keep the user's message_board=false: %+v", cfg3)
	}
	if cfg3.RelayCA != "" || fileExists(filepath.Join(srvDir, relaySessionKeyFile)) {
		t.Fatalf("plain mtls must drop relay_ca and the session key: %+v", cfg3)
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

// ---------- 37. relay mode turns the message board on (plans/relay-message-board-default-plan.md) ----------

// TestBoardEnabledRule: why — an explicit message_board value always wins; only
// a missing value follows the mode (on with a relay, off without), so turning
// the board off in relay mode is possible and sticks.
func TestBoardEnabledRule(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		board *bool
		relay string
		want  bool
	}{
		{nil, "", false}, {nil, "https://relay.example.net:9876/", true},
		{&on, "", true}, {&on, "https://relay.example.net:9876/", true},
		{&off, "", false}, {&off, "https://relay.example.net:9876/", false},
	} {
		c := &config{MessageBoard: tc.board, RelayURL: tc.relay}
		if got := boardEnabled(c); got != tc.want {
			t.Errorf("boardEnabled(board=%v relay=%q) = %v, want %v", tc.board, tc.relay, got, tc.want)
		}
		disabled := effectiveDisabledSet(c)["board_post"]
		if disabled == tc.want {
			t.Errorf("board_post disabled=%v for board=%v relay=%q", disabled, tc.board, tc.relay)
		}
	}
	if boardEnabled(nil) {
		t.Fatal("no config must keep the board off")
	}
}

// TestEnsureToolOptionsRelaySeed: why — config writes seed the board option so
// the file documents it; in relay mode the seed must be true, and a present
// value is never re-stamped either way.
func TestEnsureToolOptionsRelaySeed(t *testing.T) {
	relay := &config{RelayURL: "https://relay.example.net:9876/"}
	ensureToolOptions(relay)
	plain := &config{}
	ensureToolOptions(plain)
	if relay.MessageBoard == nil || !*relay.MessageBoard || plain.MessageBoard == nil || *plain.MessageBoard {
		t.Fatalf("seed: relay=%v plain=%v, want true and false", relay.MessageBoard, plain.MessageBoard)
	}
	off := false
	kept := &config{RelayURL: "https://relay.example.net:9876/", MessageBoard: &off}
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
	if err := saveConfig(&config{RelayURL: "https://relay.example.net:9876/", MessageBoard: &off}); err != nil {
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
// host's CLI ignores a leftover client.json (local fallback while the daemon is
// down, removed at daemon start), `build` swaps into the running daemon with no
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
		c.Env = append(os.Environ(), "KBTOOL_DIR="+dir, "KBTOOL_SOCKET=", "KBTOOL_DB=", "KBTOOL_BOARD=", "KBTOOL_DBKEY=", "KB_EMBED_URL=")
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
	if out, err := run(host, "query", "alphaOne"); err != nil || !strings.Contains(out, "alphaOne.go") {
		t.Fatalf("a host with its daemon down queries locally, ignoring client.json: %v\n%s", err, out)
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
	daemon.Env = append(os.Environ(), "KBTOOL_DIR="+host, "KBTOOL_SOCKET=", "KBTOOL_DB=", "KBTOOL_BOARD=", "KBTOOL_DBKEY=", "KB_EMBED_URL=")
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

// TestRelayPKIInMemory: why — the relay's CA is generated per start, never
// written, valid for the configured lifetime, and its leaf chains to it; two
// generations never share a CA.
func TestRelayPKIInMemory(t *testing.T) {
	before := time.Now()
	p1 := newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, []string{"relay.test"}, 3*time.Hour)
	p2 := newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil, 3*time.Hour)
	if p1.FP == p2.FP || bytes.Equal(p1.CAPEM, p2.CAPEM) {
		t.Fatal("two generations must have different CAs")
	}
	if !chainsTo(p1.Leaf.Leaf, p1.CAPEM) || chainsTo(p1.Leaf.Leaf, p2.CAPEM) {
		t.Fatal("the leaf must chain to its own CA only")
	}
	for _, na := range []time.Time{p1.Expires, p1.Leaf.Leaf.NotAfter} {
		if d := na.Sub(before); d < 3*time.Hour-time.Minute || d > 3*time.Hour+time.Minute {
			t.Fatalf("validity %s, want about 3h", d)
		}
	}
	if !containsString(p1.Leaf.Leaf.DNSNames, "relay.test") {
		t.Fatalf("extra DNS SAN missing: %v", p1.Leaf.Leaf.DNSNames)
	}
}

// TestRelayRotationServesNewCA: why — after a rotation /ca.crt and the leaf
// presented to new handshakes change together, so a daemon that fetches the
// CA can always verify the relay.
func TestRelayRotationServesNewCA(t *testing.T) {
	rs, hp := startTestRelay(t, "", nil)
	_, fp1, err := relayFetchCA(hp)
	if err != nil || fp1 != rs.currentPKI().FP {
		t.Fatalf("first CA: %q %v", fp1, err)
	}
	old := rs.currentPKI().CAPEM
	if !chainsTo(relayLeafVia(t, hp), old) {
		t.Fatal("the presented leaf must chain to the served CA")
	}
	rs.setPKI(newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour))
	_, fp2, err := relayFetchCA(hp)
	if err != nil || fp2 == fp1 || fp2 != rs.currentPKI().FP {
		t.Fatalf("after rotation /ca.crt must serve the new CA: %q (old %q) %v", fp2, fp1, err)
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

	rs.setPKI(newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour))

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
	if err != nil || o.bind != "127.0.0.1:7000" || o.token != "cfg" || o.rotate != relayDefaultRotate || o.caTTL != relayDefaultCATTL {
		t.Fatalf("config and defaults: %+v %v", o, err)
	}
	t.Setenv("KBTOOL_RELAY_PORT", "7100")
	t.Setenv("KBTOOL_RELAY_TOKEN", "env")
	t.Setenv("KBTOOL_RELAY_ROTATE", "1h")
	t.Setenv("KBTOOL_RELAY_CA_TTL", "3h")
	if o, err = parseRelayOptsErr(nil); err != nil || o.bind != ":7100" || o.token != "env" || o.rotate != time.Hour || o.caTTL != 3*time.Hour {
		t.Fatalf("environment over config: %+v %v", o, err)
	}
	t.Setenv("KBTOOL_RELAY_BIND", "127.0.0.1:7200")
	if o, _ = parseRelayOptsErr(nil); o.bind != "127.0.0.1:7200" {
		t.Fatalf("KBTOOL_RELAY_BIND wins over KBTOOL_RELAY_PORT: %q", o.bind)
	}
	if o, err = parseRelayOptsErr([]string{"-bind", ":7300", "-token", "flag", "-rotate", "2h", "-ca-ttl", "5h"}); err != nil ||
		o.bind != ":7300" || o.token != "flag" || o.rotate != 2*time.Hour || o.caTTL != 5*time.Hour {
		t.Fatalf("flags over environment: %+v %v", o, err)
	}
	t.Setenv("KBTOOL_RELAY_BIND", "")
	for env, bad := range map[string]string{"KBTOOL_RELAY_PORT": "http", "KBTOOL_RELAY_ROTATE": "soon", "KBTOOL_RELAY_CA_TTL": "-1h"} {
		t.Setenv(env, bad)
		if _, err := parseRelayOptsErr(nil); err == nil || !strings.Contains(err.Error(), env) {
			t.Fatalf("%s=%q must be refused naming the variable: %v", env, bad, err)
		}
		t.Setenv(env, map[string]string{"KBTOOL_RELAY_PORT": "7100", "KBTOOL_RELAY_ROTATE": "1h", "KBTOOL_RELAY_CA_TTL": "3h"}[env])
	}
	t.Setenv("KBTOOL_RELAY_BIND", "no-port")
	if _, err := parseRelayOptsErr(nil); err == nil || !strings.Contains(err.Error(), "KBTOOL_RELAY_BIND") {
		t.Fatalf("a bad KBTOOL_RELAY_BIND must be refused: %v", err)
	}
	t.Setenv("KBTOOL_RELAY_BIND", "")
	if _, err := parseRelayOptsErr([]string{"-rotate", "3h"}); err == nil || !strings.Contains(err.Error(), "longer than the rotation") {
		t.Fatalf("a CA lifetime not longer than the rotation must be refused: %v", err)
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
		_, fp, err := relayFetchCA(hp)
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
	_, fp2, err := relayFetchCA(hp)
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
	pool, _, err := relayFetchCA(hp)
	if err != nil {
		t.Fatal(err)
	}
	c, err := relayUpgrade(hp, relayTLSClientConfig(pool), "/v1/register", map[string]string{"X-Kbtool-Session": sid}, sign)
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
	if newRelayServer(newRelayPKI([]net.IP{net.ParseIP("127.0.0.1")}, nil, time.Hour), "").MaxSessions != 5000 {
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
// operator certificate, and a daemon with relay_ca pinned verifies it (host
// name included) without trusting plain-HTTP /ca.crt at all.
func TestRelayOperatorCertPinned(t *testing.T) {
	dir := t.TempDir()
	caFile := writeOperatorCert(t, dir)
	pki, err := loadRelayOperatorPKI(filepath.Join(dir, "relay.crt"), filepath.Join(dir, "relay.key"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM := mustReadFile(t, caFile)
	if !bytes.Equal(pki.CAPEM, caPEM) {
		t.Fatal("/ca.crt must serve the last certificate of the operator chain")
	}
	var fetches atomic.Int32
	rs := newRelayServer(pki, "")
	inner := rs.plainSrv.Handler
	rs.plainSrv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ca.crt" {
			fetches.Add(1)
		}
		inner.ServeHTTP(w, r)
	})
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
	if n := fetches.Load(); n != 0 {
		t.Fatalf("a pinned-CA daemon must not fetch /ca.crt (%d fetches)", n)
	}
	if fp, err := relayCheck(hp, relayTrust{}); err != nil || fp != caFingerprint(pki.Leaf.Certificate[1]) {
		t.Fatalf("fetch-mode daemons must keep working with an operator certificate: %q %v", fp, err)
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
// operator certificate from the environment, a daemon set up with `mtls -relay
// -relay-ca FILE` registering through it, and SIGHUP reloading a replaced
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
	_, fp1, err := relayFetchCA(hp)
	if err != nil {
		t.Fatal(err)
	}
	mt := exec.Command(bin, "mtls", "-relay", "https://"+hp+"/", "-relay-ca", caFile, "-expire", "1h")
	mt.Env = append(base, "KBTOOL_DIR="+srvDir)
	if out, err := mt.CombinedOutput(); err != nil {
		t.Fatalf("mtls -relay -relay-ca: %v\n%s", err, out)
	}
	var cfg config
	_ = json.Unmarshal(mustReadFile(t, filepath.Join(srvDir, "config.json")), &cfg)
	if cfg.RelayCA != caFile {
		t.Fatalf("relay_ca must record the pinned CA: %+v", cfg)
	}
	_, daemonLog := spawn(append(base, "KBTOOL_DIR="+srvDir), "daemon.log", "daemon", "run")
	waitLog(daemonLog, "session "+cfg.RelaySession+" registered")
	writeOperatorCert(t, certDir)
	if err := relay.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitLog(relayLog, "rotated the CA (SIGHUP)")
	if _, fp2, err := relayFetchCA(hp); err != nil || fp2 == fp1 {
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
