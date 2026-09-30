// kbtool - a single-file code & documentation knowledge base with local embeddings,
// hybrid search (BM25 keyword + dense vector, rank-fused), a RAM-resident daemon,
// a signed multi-agent message board (topical threads, task delegation, confirmations),
// and an MCP server (Qwen 3.8 / OpenAI-compatible tool calling). Standard library only.
//
// Commands:
//
//	kbtool build [dir]                build the DB (vectors + keyword index) from a codebase / docs
//	kbtool query "text"               search; uses the daemon when it is up, else loads the DB locally
//	kbtool query "text" -bundle       …and expand each top hit into a context bundle (see `kbtool bundle`)
//	kbtool terms <identifier>         exact identifier/string census (presence/ABSENCE evidence): exit 0=present, 3=absent
//	kbtool bundle <file:line>         context-bundle expansion of a known location (or -q "query" for its top hits)
//	kbtool tools                      print MCP tool schemas (or -qwen for an OpenAI/Qwen "tools" array)
//	kbtool call <tool> '<json>'       invoke one tool directly (daemon when up, else local)
//	kbtool bench -db PATH             in-process query benchmark (min/p50/p95/max)
//	kbtool mcp                        run the MCP server over stdio (for an agent to spawn)
//	kbtool mcp serve                  run the MCP server over a unix socket in the foreground
//	kbtool mcp start|stop|status      manage the background MCP service
//	kbtool daemon run|start|stop|status
//	                                  manage the background RAM-resident vector DB service
//	kbtool mtls -ip … | -dns …        generate the local mTLS PKI (CA + server + client certs)
//	kbtool client -export/-import     move the client setup between machines (encrypted bundle)
//	kbtool status                     show db + board + daemon/mcp service state
//
// Networking (plans/http-support-with-mtls-auth-plan.md): the daemon always serves its
// unix socket; -http adds a TCP listener (GET /healthz, POST /mcp; IPv4/IPv6,
// HTTP/2 over TLS); -mtls requires and verifies client certificates (CRL:
// crl.pem, enforced at the handshake; refresh gated by crl_refresh). client.json
// points the local CLI at the daemon (unix socket or host:port, tls flag).
//
// Cleartext-HTTP guard (plans/guard-against-plain-http-plan.md): a non-loopback -http
// bind requires -mtls or the explicit -http-allow-insecure; without -mtls the
// default bind is loopback (127.0.0.1:9876) so unauthenticated cleartext HTTP
// never leaks to the network by accident.
//
// Options persist (plans/kbtool-config-plan.md): `kbtool build` records its options in
// <stateDir>/config.json (JSON, e.g. ~/.config/kbtool/config.json) — a -git build
// records live=true + the repo list — so a bare `kbtool daemon start` serves with
// the same options the build used. Explicit flags always beat the config.
//
// At-rest encryption (plans/encrypt-at-rest-db-and-message-board-plan.md): with a key
// (build -encrypt prompt / -db-key-env / -db-key-file / $KBTOOL_DBKEY), kb.db is
// a KBX1 bundle (PBKDF2-HMAC-SHA256 + AES-256-GCM over a tar.gz — the same
// format as `kbtool client -export`) holding BOTH the KBV1 database and the MBD1
// message board; without a key the store is plain (kb.db + board.bin). The two
// are always both encrypted or both plain (mixed state is refused), the key
// lives only in process memory, every board/db save re-encrypts with it, and
// the key is never written to config.json, argv, or any file kbtool owns.
//
// MCP tools (plans/new-tool-options-plan.md, supersedes the gating defaults in
// plans/kbtool-preserve-config-plan.md): tool endpoints are enabled/disabled by config.json:
//   - git_tools    (bool, default false) — enables the git tools (git_blame, git_log)
//   - message_board (bool, default false) — enables the message board tools (board_*)
//   - disable_tools (list, default ["kb_status", "board_sign"]) — per-tool kill switch, always
//     honored, even over the group options
//
// Enabled by default: search_codebase, get_chunk, list_files. A tool in the list is
// hidden from all tools lists and refused at tools/call. Once present in the file,
// none of the three are ever overwritten by kbtool writes (seed-or-preserve).
//
// Path trust (plans/constrain-file-ops-to-trusted-paths-plan.md): the git tools
// (git_blame/git_log) may read only inside the trusted set: -live repo roots
// (auto) + indexed git source roots + config trusted_paths. Config
// forbidden_paths ALWAYS wins over trusted (it can forbid a default-trusted
// repo or a subpath of one). The trust model is op-parameterized (today:
// OpRead only) so future capabilities can be added without redesign.
//
// Message board tools (invoke via `kbtool call` or MCP tools/call; see
// plans/message-board-plan.md + plans/new-message-board-initilization.md):
// board_signup, board_whoami, board_sign, board_post, board_read, board_threads,
// board_search, board_confirm. The board is signed (per-agent private seed ->
// ed25519), append-only, multi-thread (welcome first), auto-initialized at daemon
// start when message_board=true, and is continuously indexed into the KB for
// cross-thread semantic search. Identity: board_signup binds a name to a seed
// (permanent); every other board call takes the seed as the credential.
//
// Search modes (query -mode, search_codebase "mode"):
//
//	hybrid   (default) Reciprocal Rank Fusion of BM25 keyword + dense-vector cosine
//	vector           dense-vector cosine only (Tier 1 behavior)
//	keyword          BM25 keyword only
//	weighted         min-max normalized weighted fusion (-kw-w / -vec-w weights)
//
// Embeddings default to a fast, offline hashing embedding (no model download). To use a
// remote OpenAI-compatible endpoint instead, set:
//
//	KB_EMBED_URL    e.g. https://api.openai.com/v1/embeddings
//	KB_EMBED_KEY    e.g. sk-...
//	KB_EMBED_MODEL  e.g. text-embedding-3-small
//
// The embedding backend must stay fixed between build and query (dims must match).
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	appName = "kbtool"

	magic      = "KBV1" // file magic
	defDim     = 1024   // embedding dim (local hashing default)
	defChunk   = 48     // chunk size in lines
	defOverlap = 12     // overlap in lines
	defMaxKB   = 512    // skip files larger than this (KB)

	defGitMaxCommits = 200  // per-repo commit cap for -git history
	defGitDiffMaxKB  = 8000 // global byte safety cap on baked diff content (KB)

	mcpProtocol = "2024-11-05" // MCP protocol version we answer with

	// Tier 2 (hybrid retrieval) defaults — see plans/tier-2-hybrid-plan.md §9.
	maxKWTerms  = 2000000 // vocabulary cap (keeps highest-df + all df=1 terms)
	bm25K1      = 1.2     // BM25 term-frequency saturation
	bm25B       = 0.75    // BM25 length normalization
	rrfK        = 60      // Reciprocal Rank Fusion constant
	defWKeyword = 0.6     // default keyword weight (mode=weighted)
	defWVector  = 0.4     // default vector weight (mode=weighted)

	ModeHybrid   = "hybrid"   // RRF fusion of keyword (BM25) + vector (default)
	ModeVector   = "vector"   // dense-vector cosine only (Tier 1 behavior)
	ModeKeyword  = "keyword"  // BM25 keyword only
	ModeWeighted = "weighted" // min-max weighted fusion (wKW/wVec)

	// Message board defaults — see plans/message-board-plan.md.
	boardMagic    = "MBD1"     // board file magic
	boardWelcome  = "welcome"  // the first thread is always the welcome thread
	defBoardTTL   = 120        // seconds: agent is ACTIVE within this last-seen window
	boardMaxText  = 256 * 1024 // per-message text cap (bytes)
	boardKindInfo = "info"     // default message kind

	// Network / mTLS (plans/http-support-with-mtls-auth-plan.md).
	defHTTPPort  = 9876             // default TCP port for -http
	maxHTTPBody  = 16 * 1024 * 1024 // POST /mcp body cap (bytes)
	crlPoll      = 2 * time.Second  // CRL file-watch poll (when crl_refresh=false)
	defCrlPeriod = 60               // seconds: CRL reload period (when crl_refresh=true)

	// Client bundle (`kbtool client -export`, plans/http-support-with-mtls-auth-plan.md §3.3):
	// magic "KBX1" | version u16 LE | salt 16B | nonce 12B | AES-256-GCM ciphertext+tag,
	// plaintext = tar.gz of the client setup files.
	bundleMagic   = "KBX1"
	bundleVersion = 1
	bundlePBKDF2  = 100000 // PBKDF2-HMAC-SHA256 iterations
)

// appVer is the CLI-reported version. It is a var (not const) so release
// builds can override it: -ldflags "-X main.appVer=<tag>" (GoReleaser injects
// the git tag). Default keeps plain `go build` binaries sane.
var appVer = "0.1.0"

// ---------- core data ----------

type Chunk struct {
	Path   string
	Kind   string // code|doc|text
	Start  int    // 1-based line
	End    int
	Text   string
	Vector []float32
}

// Source records one indexed root: a git repo (label = repo basename) or a plain dir
// (label = dir basename). It is persisted so kb_status can report it and the daemon can
// resolve a live git repo by label.
type Source struct {
	Label  string
	Root   string // resolved root: git toplevel, or the source dir (for non-git)
	HasGit bool
}

type DB struct {
	Dim     int
	Backend string // "local-hashing" or "remote:<model>"
	Sources []Source
	Chunks  []Chunk
	KW      *KWIndex // Tier 2 keyword (BM25) index; nil = not built (pre-Tier-2 file)
}

type Result struct {
	C     Chunk   `json:"chunk"`
	Score float64 `json:"score"`
}

// ---------- security: invisible-character sanitization (see plans/security-filter-plan.md) ----------
//
// Threat: "ASCII smuggling" prompt injection. Invisible Unicode TAG characters
// (U+E0000..U+E007F) render as nothing in virtually every UI and model, but they are
// real codepoints sitting between visible characters — an attacker can hide a word in
// plain text:  "ev\uE0001al" looks like ""+junk to a human and like "eval" (or like
// nothing) to a model, while a security filter seeing the raw bytes matches neither.
// The classic invisible format characters (zero-width, bidi, C1 controls, BOM, soft
// hyphen, …) are used in the same attacks and are stripped with them.
//
// Policy: strip (not replace) these characters at every boundary where text crosses
// between kbtool and (a) the AI — tool results, search queries, embedding endpoints —
// and (b) the DB — indexing. Idempotent, stdlib only, no DB format change.

// isInvisibleRune reports whether r is stripped before text reaches an AI model, a
// security filter, or the DB. Primary target: the TAG block U+E0000..U+E007F.
// Extended set: the classic invisible format / bidi / C1 control characters used in
// the same smuggling attacks. C0 whitespace (tab, LF, CR, VT, FF) is preserved so
// text structure survives.
func isInvisibleRune(r rune) bool {
	if r >= 0xE0000 && r <= 0xE007F { // TAG block — the primary smuggling vector
		return true
	}
	if r >= 0x0080 && r <= 0x009F { // C1 control block (incl. NEL U+0085, LS U+0084, PS U+0083)
		return true
	}
	switch r {
	case 0x00AD, // soft hyphen
		0x034F,         // combining grapheme joiner
		0x061C,         // Arabic letter mark
		0x115F, 0x1160, // Hangul filler
		0x17B4, 0x17B5, // Javanese filler
		0x180E,         // Mongolian vowel separator
		0x200B,         // zero-width space
		0x200C,         // zero-width non-joiner
		0x200D,         // zero-width joiner
		0x200E, 0x200F, // LRM / RLM
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // bidi embed controls
		0x2060,                 // word joiner
		0x2061,                 // function application
		0x2062, 0x2063, 0x2064, // invisible times / plus / times
		0x2066, 0x2067, 0x2068, 0x2069, // isolate controls
		0xFEFF,                 // BOM / zero-width no-break space
		0xFFF9, 0xFFFA, 0xFFFB: // interlinear annotation anchors
		return true
	}
	return false
}

// stripInvisible removes the characters flagged by isInvisibleRune. It returns the
// input unchanged when nothing is stripped (no allocation). Idempotent.
func stripInvisible(s string) string {
	if s == "" {
		return s
	}
	out, changed := make([]rune, 0, len(s)), false
	for _, r := range s {
		if isInvisibleRune(r) {
			changed = true
			continue
		}
		out = append(out, r)
	}
	if !changed {
		return s
	}
	return string(out)
}

// ---------- keyword index (Tier 2, BM25) ----------

// tfPair is an (id, count) pair: (termID, tf) in KWIndex.ChunkTF and
// (chunkID, tf) in KWIndex.Postings.
type tfPair struct {
	id    int32
	count int32
}

// KWIndex is an in-memory Okapi BM25 index over the chunk texts (plus, when built
// with kwPath, the path-leaf and kind tokens — tier-2 plan §4/§8). The term
// dictionary, df vector and avgdl are derived; idf is computed at score time.
type KWIndex struct {
	N        int      // number of chunks
	Terms    []string // term dictionary; termID = index
	ID       map[string]int32
	DF       []uint32   // doc frequency per termID
	AvgDL    float64    // average chunk length in tokens
	Lens     []int32    // per-chunk token length
	ChunkTF  [][]tfPair // per chunk: (termID, tf) sorted by termID — this is what is serialized
	Postings [][]tfPair // per termID: (chunkID, tf) sorted by chunkID — inverted, for scoring
}

// buildKWIndex constructs the keyword index from chunk texts. It is called on every
// build (tier-2 plan §4: built unconditionally). kwPath includes each chunk's path-leaf
// tokens and kind in the indexed terms (§8, default ON).
func buildKWIndex(chunks []Chunk, kwPath bool) *KWIndex {
	n := len(chunks)
	id := make(map[string]int32)
	var terms []string
	var df []uint32
	ensure := func(t string) int32 {
		if v, ok := id[t]; ok {
			return v
		}
		v := int32(len(terms))
		id[t] = v
		terms = append(terms, t)
		df = append(df, 0)
		return v
	}
	chunkTF := make([][]tfPair, n)
	lens := make([]int32, n)
	for ci, c := range chunks {
		toks := tokenize(c.Text)
		if kwPath {
			// §8: index the path's LEAF tokens (not the whole path) + the kind, to help
			// "find files about X" and disambiguate same-name symbols across packages.
			toks = append(toks, tokenize(filepath.Base(c.Path))...)
			if c.Kind != "" {
				toks = append(toks, strings.ToLower(c.Kind))
			}
		}
		lens[ci] = int32(len(toks))
		counts := map[int32]uint32{}
		for _, t := range toks {
			if t == "" {
				continue
			}
			counts[ensure(t)]++
		}
		tf := make([]tfPair, 0, len(counts))
		for tid, cnt := range counts {
			tf = append(tf, tfPair{id: tid, count: int32(cnt)})
			df[tid]++
		}
		sort.Slice(tf, func(a, b int) bool { return tf[a].id < tf[b].id })
		chunkTF[ci] = tf
	}
	var total float64
	for _, l := range lens {
		total += float64(l)
	}
	avg := float64(0)
	if n > 0 {
		avg = total / float64(n)
	}
	kw := &KWIndex{
		N: n, Terms: terms, ID: id, DF: df,
		AvgDL: avg, Lens: lens, ChunkTF: chunkTF,
		Postings: buildPostings(n, chunkTF),
	}
	capKWTerms(kw)
	return kw
}

// buildPostings inverts per-chunk tf into per-term (chunkID, tf) lists for scoring.
func buildPostings(nChunks int, chunkTF [][]tfPair) [][]tfPair {
	nTerms := 0
	for _, tf := range chunkTF {
		for _, p := range tf {
			if int(p.id)+1 > nTerms {
				nTerms = int(p.id) + 1
			}
		}
	}
	post := make([][]tfPair, nTerms)
	for ci, tf := range chunkTF {
		for _, p := range tf {
			post[p.id] = append(post[p.id], tfPair{id: int32(ci), count: p.count})
		}
	}
	for t := range post {
		sort.Slice(post[t], func(a, b int) bool { return post[t][a].id < post[t][b].id })
	}
	return post
}

func computeLens(chunkTF [][]tfPair) []int32 {
	lens := make([]int32, len(chunkTF))
	for ci, tf := range chunkTF {
		var l int32
		for _, p := range tf {
			l += p.count
		}
		lens[ci] = l
	}
	return lens
}

// capKWTerms bounds the vocabulary at maxKWTerms: keep the highest-df terms plus ALL
// df=1 terms (df=1 = rare identifiers, the most valuable for exact recall — tier-2
// plan §4.2). Deterministic; logs a warning when it fires.
func capKWTerms(kw *KWIndex) {
	if len(kw.Terms) <= maxKWTerms {
		return
	}
	keep := make([]bool, len(kw.Terms))
	kept := 0
	budget := maxKWTerms
	for i, d := range kw.DF {
		if kept >= budget {
			break
		}
		if d == 1 {
			keep[i] = true
			kept++
		}
	}
	budget -= kept
	type cand struct {
		i int32
		d uint32
	}
	var cands []cand
	for i, d := range kw.DF {
		if !keep[i] {
			cands = append(cands, cand{int32(i), d})
		}
	}
	sort.Slice(cands, func(a, b int) bool {
		if cands[a].d != cands[b].d {
			return cands[a].d > cands[b].d
		}
		return cands[a].i < cands[b].i
	})
	for j := 0; j < len(cands) && j < budget; j++ {
		keep[cands[j].i] = true
	}
	newID := make(map[string]int32, budget+kept)
	var newTerms []string
	var newDF []uint32
	for i := range kw.DF {
		if keep[i] {
			newID[kw.Terms[i]] = int32(len(newTerms))
			newTerms = append(newTerms, kw.Terms[i])
			newDF = append(newDF, kw.DF[i])
		}
	}
	newChunkTF := make([][]tfPair, len(kw.ChunkTF))
	for ci, tf := range kw.ChunkTF {
		ntf := make([]tfPair, 0, len(tf))
		for _, p := range tf {
			if ni, ok := newID[kw.Terms[p.id]]; ok {
				ntf = append(ntf, tfPair{id: ni, count: p.count})
			}
		}
		newChunkTF[ci] = ntf
	}
	kw.Terms, kw.DF, kw.ID, kw.ChunkTF = newTerms, newDF, newID, newChunkTF
	kw.Lens = computeLens(newChunkTF)
	kw.Postings = buildPostings(kw.N, newChunkTF)
	fmt.Fprintf(os.Stderr, "kbtool: warning: keyword vocabulary exceeded %d terms; capped at %d\n", maxKWTerms, len(newTerms))
}

// Score runs Okapi BM25 (k1=1.2, b=0.75, non-negative idf) for the query over the
// candidate chunks (cand==nil means all chunks) and returns their scores. Only chunks
// containing at least one query term appear; scoring touches only the postings of the
// query terms (inverted index), so it is O(occurrences), not O(N·|q|).
func (kw *KWIndex) Score(query string, cand map[int]bool) map[int]float64 {
	if kw == nil {
		return map[int]float64{}
	}
	sc := make([]float64, kw.N)
	active := kw.ScoreInto(query, cand, sc)
	out := make(map[int]float64, len(active))
	for _, id := range active {
		out[id] = sc[id]
	}
	return out
}

// ScoreInto is the fast path used by Search: it writes BM25 scores into the caller's
// fresh (all-zero) buffer sc, indexed by chunk ID, and returns the active chunk IDs
// (those containing at least one query term, restricted to cand when non-nil).
func (kw *KWIndex) ScoreInto(query string, cand map[int]bool, sc []float64) []int {
	if kw == nil || kw.N == 0 {
		return nil
	}
	avg := kw.AvgDL
	if avg <= 0 {
		avg = 1
	}
	var active []int
	seen := map[int32]bool{}
	for _, t := range tokenize(query) {
		id, ok := kw.ID[t]
		if !ok || seen[id] {
			continue
		}
		seen[id] = true
		idf := math.Log(1 + (float64(kw.N)-float64(kw.DF[id])+0.5)/(float64(kw.DF[id])+0.5))
		for _, p := range kw.Postings[id] {
			ci := int(p.id)
			if cand != nil && !cand[ci] {
				continue
			}
			dl := float64(kw.Lens[ci])
			denom := float64(p.count) + bm25K1*(1-bm25B+bm25B*dl/avg)
			if denom <= 0 {
				continue
			}
			if sc[ci] == 0 { // contributions are strictly positive: first touch = new active chunk
				active = append(active, ci)
			}
			sc[ci] += idf * float64(p.count) * (bm25K1 + 1) / denom
		}
	}
	return active
}

// kwAddChunk appends one chunk (id = current N) to an existing KWIndex WITHOUT
// rebuilding it (plans/message-board-plan.md §4): new terms are added to the dictionary,
// df/lens/postings are extended, and avgdl is updated in closed form. The chunk id
// must equal kw.N before the call (i.e. this chunk is the newest one).
func kwAddChunk(kw *KWIndex, c Chunk) {
	if kw == nil {
		return
	}
	n := kw.N // this chunk's id
	toks := tokenize(c.Text)
	// Consistent with buildKWIndex(kwPath=true): include path-leaf + kind tokens.
	toks = append(toks, tokenize(filepath.Base(c.Path))...)
	if c.Kind != "" {
		toks = append(toks, strings.ToLower(c.Kind))
	}
	counts := map[int32]uint32{}
	for _, t := range toks {
		if t == "" {
			continue
		}
		id, ok := kw.ID[t]
		if !ok {
			id = int32(len(kw.Terms))
			kw.ID[t] = id
			kw.Terms = append(kw.Terms, t)
			kw.DF = append(kw.DF, 0)
			if len(kw.Postings) <= int(id) {
				kw.Postings = append(kw.Postings, make([][]tfPair, int(id)+1-len(kw.Postings))...)
			}
		}
		counts[id]++
	}
	tf := make([]tfPair, 0, len(counts))
	var l int32
	for id, cnt := range counts {
		tf = append(tf, tfPair{id: id, count: int32(cnt)})
		kw.DF[id]++
		l += int32(cnt)
	}
	sort.Slice(tf, func(a, b int) bool { return tf[a].id < tf[b].id })
	kw.ChunkTF = append(kw.ChunkTF, tf)
	kw.Lens = append(kw.Lens, l)
	// avgdl in closed form: (oldAvg*oldN + newLen) / (oldN + 1)
	if n > 0 {
		kw.AvgDL = (kw.AvgDL*float64(n) + float64(l)) / float64(n+1)
	} else {
		kw.AvgDL = float64(l)
	}
	for _, p := range tf {
		kw.Postings[p.id] = append(kw.Postings[p.id], tfPair{id: int32(n), count: p.count})
	}
	kw.N = n + 1
	if len(kw.Terms) > maxKWTerms {
		capKWTerms(kw)
	}
}

// ---------- embedding ----------

// ---------- tokenizer (shared by the BM25 index AND the hashing embedder) ----------
//
// The SAME rich tokenizer feeds both retrieval channels (tier-2 plan §3), so a query
// "token bucket" and a chunk containing TokenBucketLimiter share the token, bucket
// terms in both channels. Identifiers are split on case boundaries, underscores and
// letter/digit boundaries — and the WHOLE identifier is kept so exact full-name
// queries still match:
//
//	TokenBucketLimiter -> token bucket limiter tokenbucketlimiter
//	foo_bar_baz        -> foo bar baz foobarbaz
//	HTTPClient         -> http client httpclient
//
// Code symbols stay as tokens (informative for code: method calls, operators), with
// common multi-char symbols recognized before single-char fallback:
//
//	=>, ::, ==, !=, <=, >=, &&, ||, +=, -=, *=, /=, ++, --, ->, =>
//	and single: - . ( ) { } < > = + / * & | ; : # @ $

var kwSymbols = func() []struct {
	s string
	r []rune
} {
	var out []struct {
		s string
		r []rune
	}
	for _, s := range []string{"=>", "::", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=", "++", "--", "->", "->"} {
		out = append(out, struct {
			s string
			r []rune
		}{s, []rune(s)})
	}
	return out
}()

func isAlnumRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// tokenize produces a deterministic token stream for code text (see the block above).
func tokenize(s string) []string {
	runes := []rune(s)
	var out []string
	i := 0
	for i < len(runes) {
		if isAlnumRune(runes[i]) || runes[i] == '_' {
			j := i
			for j < len(runes) && (isAlnumRune(runes[j]) || runes[j] == '_') {
				j++
			}
			out = append(out, identTokens(runes[i:j])...)
			i = j
			continue
		}
		matched := false
		for _, sym := range kwSymbols {
			if i+len(sym.r) <= len(runes) && runesEqual(runes[i:i+len(sym.r)], sym.r) {
				out = append(out, sym.s)
				i += len(sym.r)
				matched = true
				break
			}
		}
		if !matched {
			r := runes[i]
			if r < 128 && strings.IndexByte("-.(){}<>+=/*&|;:#@$", byte(r)) >= 0 {
				out = append(out, string(r))
			}
			i++
		}
	}
	return out
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// identTokens expands one identifier run ([A-Za-z0-9_]*) into its lowercase word
// parts (split on case boundaries, underscores, letter/digit boundaries) PLUS the
// whole identifier (underscores removed). Deduped, order-stable.
func identTokens(seg []rune) []string {
	isUpper := func(r rune) bool { return r >= 'A' && r <= 'Z' }
	isLower := func(r rune) bool { return r >= 'a' && r <= 'z' }
	isDigit := func(r rune) bool { return r >= '0' && r <= '9' }
	isLetter := func(r rune) bool { return isUpper(r) || isLower(r) }
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i := 0; i < len(seg); i++ {
		r := seg[i]
		if r == '_' {
			flush()
			continue
		}
		if i > 0 {
			prev := seg[i-1]
			boundary :=
				(isUpper(r) && isLower(prev)) || // fooBar -> foo | Bar
					(isUpper(r) && isUpper(prev) && i+1 < len(seg) && isLower(seg[i+1])) || // HTTPClient -> HTTP | Client
					(isDigit(r) && isLetter(prev)) || // foo2 -> foo | 2
					(isLetter(r) && isDigit(prev)) // 2foo -> 2 | foo
			if boundary {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	whole := strings.ToLower(strings.ReplaceAll(string(seg), "_", ""))
	seen := map[string]bool{}
	var out []string
	for _, w := range words {
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	if whole != "" && !seen[whole] {
		out = append(out, whole)
	}
	return out
}

// hashDim returns a deterministic token hash in [0,dim).
func hashDim(tok string, dim int) int {
	var h uint32 = 2166136261
	for i := 0; i < len(tok); i++ {
		h ^= uint32(tok[i])
		h *= 16777619
	}
	return int(h % uint32(dim))
}

// embedLocal produces a normalized "hashing trick" bag-of-words vector. No model,
// fully offline. Quality is coarse but works well enough for code search and needs
// zero setup.
func embedLocal(texts []string, dim int) [][]float32 {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		v := make([]float32, dim)
		for _, tok := range tokenize(t) {
			v[hashDim(tok, dim)] += 1
		}
		out[i] = normalize(v) // L2-normalize so dot == cosine
	}
	return out
}

func normalize(v []float32) []float32 {
	var ss float64
	for _, x := range v {
		ss += float64(x) * float64(x)
	}
	if ss == 0 {
		return v
	}
	n := float32(1 / math.Sqrt(ss)) // divide by the L2 norm, so dot(a,a) == 1
	for i := range v {
		v[i] *= n
	}
	return v
}

// dot is a cosine proxy (both vectors are L2-normalized). Accumulating in float32
// keeps the inner loop fast (no per-element conversion) — ranking precision is
// unaffected at these magnitudes.
func dot(a, b []float32) float64 {
	var s float32
	for i, x := range a {
		s += x * b[i]
	}
	return float64(s)
}

// remoteEmbedder hits an OpenAI-compatible /embeddings endpoint.
type remoteEmbedder func([]string) [][]float32

func remoteFromEnv() (remoteEmbedder, error) {
	url := os.Getenv("KB_EMBED_URL")
	if url == "" {
		return nil, fmt.Errorf("KB_EMBED_URL not set")
	}
	key := os.Getenv("KB_EMBED_KEY")
	model := os.Getenv("KB_EMBED_MODEL")
	client := &http.Client{Timeout: 120 * time.Second}
	return func(texts []string) [][]float32 {
		body, _ := json.Marshal(map[string]any{"model": model, "input": texts})
		req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()
		var parsed struct {
			Data []struct {
				Embedding []float32 `json:"embedding"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
			panic(err)
		}
		out := make([][]float32, len(parsed.Data))
		for i, d := range parsed.Data {
			out[i] = d.Embedding
		}
		return out
	}, nil
}

// ---------- active embedding backend ----------

// backendTag identifies the active embedding backend so build and query can be
// checked for consistency (the two must match, or scores are meaningless).
func backendTag() string {
	if os.Getenv("KB_EMBED_URL") != "" {
		return "remote:" + os.Getenv("KB_EMBED_MODEL")
	}
	return "local-hashing"
}

// pickEmbedder returns the embedding function for the active backend. Local is the
// offline default; remote uses KB_EMBED_URL/KEY/MODEL. wantDim applies to local only.
func pickEmbedder(wantDim int) func([]string) [][]float32 {
	if os.Getenv("KB_EMBED_URL") != "" {
		if emb, err := remoteFromEnv(); err == nil {
			return emb
		}
		fmt.Fprintln(os.Stderr, "kbtool: remote embedder unavailable, falling back to local")
	}
	d := wantDim
	if d <= 0 {
		d = defDim
	}
	return func(texts []string) [][]float32 { return embedLocal(texts, d) }
}

// probeDim returns the dimension a backend actually produces (one small probe call).
func probeDim(emb func([]string) [][]float32) int {
	v := emb([]string{"kbtool dimension probe"})[0]
	return len(v)
}

// embedOne embeds a single string with the active backend (used for queries).
func embedOne(q string, dim int) []float32 {
	if os.Getenv("KB_EMBED_URL") != "" {
		if emb, err := remoteFromEnv(); err == nil {
			return emb([]string{q})[0]
		}
	}
	return embedLocal([]string{q}, dim)[0]
}

// ---------- chunking ----------

// chunkText splits lines into overlapping chunks.
func chunkText(path, kind string, lines []string, chunk, overlap int) []Chunk {
	if chunk <= 0 {
		chunk = defChunk
	}
	if overlap < 0 {
		overlap = 0
	}
	if overlap >= chunk {
		overlap = chunk / 2
	}
	var chunks []Chunk
	start := 0
	for start < len(lines) {
		end := start + chunk
		if end > len(lines) {
			end = len(lines)
		}
		text := strings.Join(lines[start:end], "\n")
		if strings.TrimSpace(text) != "" {
			chunks = append(chunks, Chunk{
				Path: path, Kind: kind,
				Start: start + 1, End: end,
				Text: text,
			})
		}
		if end == len(lines) {
			break
		}
		start = end - overlap
	}
	return chunks
}

// ---------- file walking ----------

func kindOfPath(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".go", ".py", ".js", ".ts", ".tsx", ".jsx", ".rs", ".c", ".h", ".cpp", ".cc", ".cxx",
		".java", ".kt", ".rb", ".php", ".cs", ".swift", ".scala", ".sh", ".bash", ".zsh",
		".sql", ".proto", ".toml", ".ini", ".cfg", ".conf", ".yml", ".yaml", ".json", ".xml",
		".html", ".css", ".vue", ".svelte":
		return "code"
	case ".md", ".rst", ".txt", ".adoc", ".tex", ".org":
		return "doc"
	}
	switch strings.ToLower(name) {
	case "makefile", "dockerfile", "jenkinsfile", "cmakelists.txt", ".gitignore", ".env", ".gitattributes":
		return "code"
	}
	return "text"
}

func isTextExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf",
		".zip", ".gz", ".tar", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib",
		".bin", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav",
		".wasm", ".pyc", ".class", ".o", ".a", ".lock":
		return false
	}
	return true
}

// ---------- build ----------

type BuildOpts struct {
	Sources       []string // one or more source dirs (each may be a git repo or a subdir of one)
	Dim           int
	Chunk         int
	Overlap       int
	MaxKB         int
	Git           bool // bake git history (commit messages + diffs) + provenance summary
	GitMaxCommits int
	GitDiffMaxKB  int
	Embed         func([]string) [][]float32 // nil => pick active backend
	KWPath        *bool                      // nil/true => include path-leaf + kind tokens in the keyword index (tier-2 §8, default ON)
}

func buildDB(opts BuildOpts) (*DB, error) {
	if opts.Dim <= 0 {
		opts.Dim = defDim
	}
	if opts.Chunk <= 0 {
		opts.Chunk = defChunk
	}
	if opts.Overlap < 0 {
		opts.Overlap = defOverlap
	}
	if opts.MaxKB <= 0 {
		opts.MaxKB = defMaxKB
	}
	if opts.GitMaxCommits <= 0 {
		opts.GitMaxCommits = defGitMaxCommits
	}
	if opts.GitDiffMaxKB <= 0 {
		opts.GitDiffMaxKB = defGitDiffMaxKB
	}
	if len(opts.Sources) == 0 {
		return nil, fmt.Errorf("no source directory given")
	}
	embed := opts.Embed
	if embed == nil {
		embed = pickEmbedder(opts.Dim)
	}
	// The dimension must reflect what the backend actually produces (local = wantDim;
	// remote = the model's dim, via a one-shot probe).
	opts.Dim = probeDim(embed)
	backend := backendTag()

	// ---- resolve each source into (src, root, rel, label) ----
	type srcInfo struct {
		Src, Root, Rel, Label string
		HasGit                bool
	}
	var srcs []srcInfo
	for _, s := range opts.Sources {
		// Absolutize FIRST: git toplevels are absolute, and filepath.Rel between an
		// absolute root and a relative walk path fails (silently dropping the file's
		// rel path from chunk paths).
		if a, err := filepath.Abs(s); err == nil {
			s = a
		}
		s = filepath.Clean(s)
		if fi, err := os.Stat(s); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("source not found (not a directory): %s", s)
		}
		root := s
		hasGit := false
		if top, ok := gitToplevel(s); ok {
			root, hasGit = top, true
		}
		rel, _ := filepath.Rel(root, s)
		if rel == "." {
			rel = ""
		}
		// Label is persisted (Sources) and used in chunk paths: keep it clean too.
		srcs = append(srcs, srcInfo{Src: s, Root: root, Rel: rel, Label: stripInvisible(filepath.Base(root)), HasGit: hasGit})
	}
	// label conflict: the same label mapped to more than one distinct root
	labelRoots := map[string][]string{}
	for _, r := range srcs {
		if !contains(labelRoots[r.Label], r.Root) {
			labelRoots[r.Label] = append(labelRoots[r.Label], r.Root)
		}
	}
	for _, label := range sortedStringKeys(labelRoots) {
		if len(labelRoots[label]) > 1 {
			return nil, fmt.Errorf("label conflict: %q is used by both %s — rename one repo/dir to a unique name",
				label, strings.Join(labelRoots[label], " and "))
		}
	}

	// ---- Sources list (deduped by root) ----
	seenRoot := map[string]bool{}
	var sources []Source
	for _, r := range srcs {
		if seenRoot[r.Root] {
			continue
		}
		seenRoot[r.Root] = true
		sources = append(sources, Source{Label: r.Label, Root: r.Root, HasGit: r.HasGit})
	}

	// ---- walk + chunk files across all sources (dedupe by absolute path) ----
	var all []Chunk
	seenFile := map[string]bool{}
	fileCount := 0
	for _, r := range srcs {
		err := filepath.Walk(r.Src, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // skip unreadable
			}
			if info.IsDir() {
				if isSkipDir(info.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if info.Size() > int64(opts.MaxKB)*1024 {
				return nil
			}
			name := info.Name()
			if !isTextExt(name) || isSkipFile(name) {
				return nil
			}
			if seenFile[path] {
				return nil
			}
			seenFile[path] = true
			data, err := os.ReadFile(path)
			if err != nil || !isUTF8(data) {
				return nil
			}
			relPath, _ := filepath.Rel(r.Root, path)
			kind := kindOfPath(name)
			// Security (plans/security-filter-plan.md §3.2): strip invisible tag/format chars
			// so they never reach the DB, the tokenizer, or an embedding model.
			content := stripInvisible(string(data))
			lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
			for _, ch := range chunkText(r.Label+"/"+stripInvisible(relPath), kind, lines, opts.Chunk, opts.Overlap) {
				if r.HasGit && opts.Git {
					if prov := provenanceFor(r.Root, relPath, ch.Start, ch.End); prov != "" {
						ch.Text = prov + "\n" + ch.Text
					}
				}
				all = append(all, ch)
			}
			fileCount++
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// ---- optional git history (per distinct repo, deduped, capped) ----
	if opts.Git {
		repoPathspecs := map[string][]string{}
		repoLabel := map[string]string{}
		for _, r := range srcs {
			if !r.HasGit {
				continue
			}
			repoLabel[r.Root] = r.Label
			if !contains(repoPathspecs[r.Root], r.Rel) {
				repoPathspecs[r.Root] = append(repoPathspecs[r.Root], r.Rel)
			}
		}
		diffBudget := opts.GitDiffMaxKB * 1024
		diffBytes := 0
		for _, root := range sortedStringKeys(repoLabel) {
			label := repoLabel[root]
			commits, err := gitLogCommits(root, opts.GitMaxCommits, repoPathspecs[root])
			if err != nil {
				fmt.Fprintf(os.Stderr, "kbtool: git history for %s: %v\n", label, err)
				continue
			}
			for _, c := range commits {
				sha7 := c.SHA
				if len(sha7) > 7 {
					sha7 = sha7[:7]
				}
				msg := c.Subject
				if c.Body != "" {
					msg += "\n\n" + c.Body
				}
				all = append(all, Chunk{Path: label + "/git/" + sha7, Kind: "commit", Text: msg})
				if diffBytes < diffBudget {
					if patch, err := gitCommitDiff(root, c.SHA, repoPathspecs[root]); err == nil {
						for _, fd := range parsePatch(patch) {
							if diffBytes >= diffBudget {
								break
							}
							text := c.Subject + "\n\n--- " + fd.File + " ---\n" + fd.Hunk
							all = append(all, Chunk{Path: label + "/git/" + sha7 + "/" + fd.File, Kind: "diff", Text: text})
							diffBytes += len(text)
						}
					}
				}
			}
		}
	}

	// ---- embed in batches ----
	const batch = 64
	for i := 0; i < len(all); i += batch {
		j := i + batch
		if j > len(all) {
			j = len(all)
		}
		texts := make([]string, j-i)
		for k := i; k < j; k++ {
			texts[k-i] = all[k].Text
		}
		vecs := embed(texts)
		for k := i; k < j; k++ {
			all[k].Vector = vecs[k-i]
		}
		fmt.Fprintf(os.Stderr, "embedded %d/%d chunks (%d files)\n", j, len(all), fileCount)
	}
	db := &DB{Dim: opts.Dim, Backend: backend, Sources: sources, Chunks: all}
	// Tier 2 (§4): the keyword (BM25) index is built unconditionally on every build,
	// so hybrid/keyword search works out of the box on any freshly built DB.
	kwPath := opts.KWPath == nil || *opts.KWPath
	db.KW = buildKWIndex(all, kwPath)
	return db, nil
}

// contains reports whether v is in list.
func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func sortedStringKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------- skip rules ----------

func isSkipDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", "node_modules", "vendor", "dist", "build", "target", "out",
		".venv", "venv", "__pycache__", ".idea", ".vscode", ".next", "coverage",
		".tox", ".mypy_cache", "bower_components", ".cache", "tmp", "temp":
		return true
	}
	return false
}

// isSkipFile flags generated/lock/minified files that are useless (or harmful) to index.
func isSkipFile(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "gopkg.lock",
		"pipfile.lock", "poetry.lock", "cargo.lock", "composer.lock":
		return true
	}
	if strings.HasSuffix(n, ".min.js") || strings.HasSuffix(n, ".min.css") {
		return true
	}
	// Single-dot extensions match on the final extension; multi-dot
	// (e.g. .pb.go, .generated.go) must match by suffix because
	// filepath.Ext only returns the last dot.
	switch filepath.Ext(n) {
	case ".lock", ".map", ".sum", ".snap":
		return true
	}
	for _, suf := range []string{".min.js", ".min.css", ".pb.go", ".pb.cc", ".pb.h", ".generated.go"} {
		if strings.HasSuffix(n, suf) {
			return true
		}
	}
	return false
}

// ---------- git plumbing (stdlib os/exec; never panics on git failure) ----------

type gitCommit struct {
	SHA, Author, Date, Subject, Body string
}

type gitFileDiff struct {
	File   string
	Hunk   string
	Binary bool
}

type blameLine struct {
	SHA, Author, Date string
}

func runGit(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	return cmd.CombinedOutput()
}

// gitToplevel returns the repo working-tree root containing dir ("" ,false if not a repo).
func gitToplevel(dir string) (string, bool) {
	out, err := runGit(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "", false
	}
	return s, true
}

func filterNonEmpty(ps []string) []string {
	var out []string
	for _, p := range ps {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// gitLogCommits lists up to n newest commits, optionally scoped to the given pathspecs.
func gitLogCommits(root string, n int, pathspecs []string) ([]gitCommit, error) {
	args := []string{"log", "-n", strconv.Itoa(n), "--format=%H%x01%an%x01%aI%x01%s%x01%b%x02"}
	if ps := filterNonEmpty(pathspecs); len(ps) > 0 {
		args = append(append(args, "--"), ps...)
	}
	out, err := runGit(root, args...)
	if err != nil {
		return nil, err
	}
	return parseCommitRecords(out), nil
}

func parseCommitRecords(out []byte) []gitCommit {
	out = []byte(stripInvisible(string(out))) // security: clean commit messages before indexing
	var commits []gitCommit
	for _, rec := range bytes.Split(out, []byte{0x02}) {
		rec = bytes.TrimSpace(rec)
		if len(rec) == 0 {
			continue
		}
		parts := bytes.SplitN(rec, []byte{0x01}, 6)
		if len(parts) < 5 || len(parts[0]) == 0 {
			continue
		}
		c := gitCommit{SHA: string(parts[0]), Author: string(parts[1]), Date: string(parts[2]), Subject: string(parts[3])}
		// A well-formed record has 5 fields (SHA, author, date, subject, body)
		// → SplitN(...,6) yields 5 parts; the body is the 5th (index 4).
		if len(parts) >= 5 {
			c.Body = strings.TrimSpace(string(parts[4]))
		}
		commits = append(commits, c)
	}
	return commits
}

// gitCommitDiff returns the patch for one commit, optionally scoped to pathspecs.
func gitCommitDiff(root, sha string, pathspecs []string) (string, error) {
	args := []string{"show", "--format=", sha}
	if ps := filterNonEmpty(pathspecs); len(ps) > 0 {
		args = append(append(args, "--"), ps...)
	}
	out, err := runGit(root, args...)
	if err != nil {
		return "", err
	}
	return stripInvisible(string(out)), nil // security: clean diff content before indexing
}

// parsePatch splits a unified diff into per-file {added lines + hunk headers}.
func parsePatch(patch string) []gitFileDiff {
	var files []gitFileDiff
	var cur *gitFileDiff
	for _, ln := range strings.Split(patch, "\n") {
		if strings.HasPrefix(ln, "diff --git ") {
			if cur != nil && !cur.Binary {
				files = append(files, *cur)
			}
			cur = &gitFileDiff{File: patchPath(ln)}
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(ln, "Binary files"):
			cur.Binary = true
			cur.Hunk = ""
		case strings.HasPrefix(ln, "@@"):
			cur.Hunk += ln + "\n"
		case strings.HasPrefix(ln, "+") && !strings.HasPrefix(ln, "+++"):
			cur.Hunk += ln + "\n"
		}
	}
	if cur != nil && !cur.Binary {
		files = append(files, *cur)
	}
	var out []gitFileDiff
	for _, f := range files {
		if !f.Binary && strings.TrimSpace(f.Hunk) != "" {
			out = append(out, f)
		}
	}
	return out
}

// patchPath extracts the target path from a "diff --git a/X b/Y" line.
func patchPath(ln string) string {
	fields := strings.Fields(strings.TrimPrefix(ln, "diff --git "))
	for i := len(fields) - 1; i >= 0; i-- {
		f := fields[i]
		if strings.HasPrefix(f, "b/") {
			return f[2:]
		}
	}
	if len(fields) >= 1 && strings.HasPrefix(fields[0], "a/") {
		return fields[0][2:]
	}
	if len(fields) >= 1 {
		return fields[0]
	}
	return strings.TrimSpace(ln)
}

// gitBlameMap maps each final line number to its originating commit/author/date.
func gitBlameMap(root, file string) (map[int]blameLine, error) {
	out, err := runGit(root, "blame", "--", file)
	if err != nil {
		return nil, err
	}
	out = []byte(stripInvisible(string(out))) // security: clean authors/dates before parsing
	m := map[int]blameLine{}
	for _, ln := range strings.Split(string(out), "\n") {
		if ln == "" {
			continue
		}
		if b, ok := parseBlameLine(ln); ok {
			m[b.Line] = blameLine{SHA: b.SHA, Author: b.Author, Date: b.Date}
		}
	}
	return m, nil
}

type parsedBlame struct {
	Line              int
	SHA, Author, Date string
}

// parseBlameLine parses a git blame line. Handles both:
//
//	<sha> (<author> <date> <tz> <line>) <content>
//	<sha> <orig> (<author> <date> <tz> <line>) <content>
//
// A leading '^' on the sha (boundary/root commit) is stripped.
func parseBlameLine(ln string) (parsedBlame, bool) {
	i := strings.IndexByte(ln, ' ')
	if i < 0 {
		return parsedBlame{}, false
	}
	sha := strings.TrimPrefix(ln[:i], "^")
	rest := ln[i+1:]
	open := strings.IndexByte(rest, '(')
	if open < 0 {
		return parsedBlame{}, false
	}
	closeIdx := strings.IndexByte(rest, ')')
	if closeIdx < 0 || closeIdx <= open {
		return parsedBlame{}, false
	}
	inner := strings.Fields(rest[open+1 : closeIdx]) // author date tz line
	var author, date string
	if len(inner) >= 1 {
		author = inner[0]
	}
	if len(inner) >= 2 {
		date = inner[1]
	}
	lineN := 0
	if len(inner) > 0 {
		if n, err := strconv.Atoi(inner[len(inner)-1]); err == nil {
			lineN = n
		}
	}
	if lineN == 0 {
		return parsedBlame{}, false
	}
	return parsedBlame{Line: lineN, SHA: sha, Author: author, Date: date}, true
}

// provenanceFor builds the one-line summary baked into a chunk's text.
func provenanceFor(root, file string, start, end int) string {
	m, err := gitBlameMap(root, file)
	if err != nil || len(m) == 0 {
		return ""
	}
	type agg struct {
		author, year string
		count        int
	}
	per := map[string]*agg{}
	latest := ""
	for ln, b := range m {
		if ln < start || ln > end {
			continue
		}
		year := b.Date
		if len(year) >= 4 {
			year = year[:4]
		}
		a, ok := per[b.SHA]
		if !ok {
			a = &agg{}
			per[b.SHA] = a
		}
		a.count++
		a.author, a.year = b.Author, year
		if b.Date > latest {
			latest = b.Date
		}
	}
	if len(per) == 0 {
		return ""
	}
	topSHA, topCount := "", -1
	for sha, a := range per {
		if a.count > topCount {
			topCount, topSHA = a.count, sha
		}
	}
	top := per[topSHA]
	sha7 := topSHA
	if len(sha7) > 7 {
		sha7 = sha7[:7]
	}
	last := latest
	if len(last) >= 7 {
		last = last[:7]
	}
	return fmt.Sprintf("[provenance: %s %s %s · churn=%d · last=%s]", sha7, top.author, top.year, len(per), last)
}

// gitBlameRange runs a live `git blame` (optionally scoped to a line range) for the tools.
func gitBlameRange(root, file string, start, end, limit int) (string, error) {
	args := []string{"blame"}
	if start > 0 && end > 0 {
		args = append(args, "-L", fmt.Sprintf("%d,%d", start, end))
	}
	args = append(args, "--", file)
	out, err := runGit(root, args...)
	if err != nil {
		return "", err
	}
	s := stripInvisible(strings.TrimSpace(string(out))) // security: never return invisible chars to the AI
	if limit > 0 {
		lines := strings.Split(s, "\n")
		if len(lines) > limit {
			lines = append(lines[:limit], fmt.Sprintf("… (%d more lines)", len(lines)-limit))
			s = strings.Join(lines, "\n")
		}
	}
	return s, nil
}

// gitLogPath runs a live `git log` for the tools.
func gitLogPath(root, path string, n int, author string) (string, error) {
	if n <= 0 {
		n = 20
	}
	if n > 200 {
		n = 200
	}
	args := []string{"log", "-n", strconv.Itoa(n), "--pretty=format:%h %ad %an %s", "--date=short"}
	if author != "" {
		args = append(args, "--author="+author)
	}
	if path != "" {
		args = append(args, "--", path)
	}
	out, err := runGit(root, args...)
	if err != nil {
		return "", err
	}
	return stripInvisible(strings.TrimSpace(string(out))), nil // security: never return invisible chars to the AI
}

// splitLabel splits a labeled chunk path "label/rel" into (label, rel).
func splitLabel(p string) (label, rel string) {
	i := strings.IndexByte(p, '/')
	if i <= 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}

func isUTF8(b []byte) bool {
	for i := 0; i < len(b); {
		c := b[i]
		var w int
		switch {
		case c < 0x80:
			w = 1
		case c >= 0xC2 && c < 0xE0:
			w = 2
		case c >= 0xE0 && c < 0xF0:
			w = 3
		case c >= 0xF0 && c < 0xF8:
			w = 4
		default:
			return false
		}
		if i+w > len(b) {
			return false
		}
		for k := 1; k < w; k++ {
			if b[i+k]&0xC0 != 0x80 {
				return false
			}
		}
		i += w
	}
	return true
}

// ---------- (de)serialization ----------

// The on-disk format is a simple binary blob so one-shot loading is fast and has no
// external index to manage. Layout:
//
//	[4s magic][u32 dim][str backend]
//	[u32 nsources]  per source: [str label][str root][u8 hasGit]
//	[u32 nchunks]   per chunk:  [u32 len][path][u32 len][kind][u32 start][u32 end]
//	                 [u32 len][text][f32*dim vector]
//	[u8 hasKW]                                   // Tier 2: 1 = keyword index present
//	[u32 nTerms][per term: u32 len, bytes]       // term dictionary
//	[u32 dfCount][per term: u32 df]              // doc frequencies (idf derived at load)
//	[f32 avgdl]
//	[u32 nChunkTF]  per chunk: [u32 ntf][ntf × (u32 termID, u32 count)]
//
// Pre-Tier-2 files simply end after the chunk block (no hasKW byte); readDB treats
// EOF there as hasKW=0 and hybrid/keyword modes degrade cleanly.

func writeU32(b *bytes.Buffer, v uint32) { binary.Write(b, binary.LittleEndian, v) }
func writeStr(b *bytes.Buffer, s string) {
	writeU32(b, uint32(len(s)))
	b.WriteString(s)
}

func (db *DB) WriteTo(path string) error {
	return os.WriteFile(path, dbMarshal(db), 0644)
}

// dbMarshal serializes the DB to the KBV1 binary format (the body of WriteTo,
// factored out so the identical bytes can be packed into the at-rest encrypted
// bundle — see plans/encrypt-at-rest-db-and-message-board-plan.md).
func dbMarshal(db *DB) []byte {
	var buf bytes.Buffer
	buf.WriteString(magic)
	writeU32(&buf, uint32(db.Dim))
	writeStr(&buf, db.Backend)
	writeU32(&buf, uint32(len(db.Sources)))
	for _, s := range db.Sources {
		writeStr(&buf, s.Label)
		writeStr(&buf, s.Root)
		if s.HasGit {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
	}
	writeU32(&buf, uint32(len(db.Chunks)))
	for _, c := range db.Chunks {
		writeStr(&buf, c.Path)
		writeStr(&buf, c.Kind)
		writeU32(&buf, uint32(c.Start))
		writeU32(&buf, uint32(c.End))
		writeStr(&buf, c.Text)
		for _, f := range c.Vector {
			binary.Write(&buf, binary.LittleEndian, f)
		}
	}
	if db.KW != nil {
		buf.WriteByte(1)
		writeU32(&buf, uint32(len(db.KW.Terms)))
		for _, t := range db.KW.Terms {
			writeStr(&buf, t)
		}
		writeU32(&buf, uint32(len(db.KW.DF)))
		for _, d := range db.KW.DF {
			writeU32(&buf, d)
		}
		binary.Write(&buf, binary.LittleEndian, float32(db.KW.AvgDL))
		writeU32(&buf, uint32(len(db.KW.ChunkTF)))
		for _, tf := range db.KW.ChunkTF {
			writeU32(&buf, uint32(len(tf)))
			for _, p := range tf {
				writeU32(&buf, uint32(p.id))
				writeU32(&buf, uint32(p.count))
			}
		}
	} else {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func readU32(r io.Reader) (uint32, error) {
	var v uint32
	err := binary.Read(r, binary.LittleEndian, &v)
	return v, err
}
func readStr(r io.Reader) (string, error) {
	n, err := readU32(r)
	if err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readDB(r io.Reader) (*DB, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	if string(head) != magic {
		return nil, fmt.Errorf("bad magic %q", head)
	}
	dim, _ := readU32(r)
	backend, _ := readStr(r)
	nsrc, _ := readU32(r)
	var sources []Source
	for i := uint32(0); i < nsrc; i++ {
		label, _ := readStr(r)
		root, _ := readStr(r)
		var hg byte
		_ = binary.Read(r, binary.LittleEndian, &hg)
		sources = append(sources, Source{Label: label, Root: root, HasGit: hg == 1})
	}
	n, _ := readU32(r)
	db := &DB{Dim: int(dim), Backend: backend, Sources: sources, Chunks: make([]Chunk, 0, n)}
	for i := uint32(0); i < n; i++ {
		var c Chunk
		var err error
		if c.Path, err = readStr(r); err != nil {
			return nil, err
		}
		if c.Kind, err = readStr(r); err != nil {
			return nil, err
		}
		start, err := readU32(r)
		if err != nil {
			return nil, err
		}
		c.Start = int(start)
		end, err := readU32(r)
		if err != nil {
			return nil, err
		}
		c.End = int(end)
		if c.Text, err = readStr(r); err != nil {
			return nil, err
		}
		c.Vector = make([]float32, dim)
		for j := uint32(0); j < dim; j++ {
			if err := binary.Read(r, binary.LittleEndian, &c.Vector[j]); err != nil {
				return nil, err
			}
		}
		db.Chunks = append(db.Chunks, c)
	}
	// Tier 2 keyword block (optional; pre-Tier-2 files end here).
	var has byte
	err := binary.Read(r, binary.LittleEndian, &has)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if has == 1 {
		kw, err := readKWIndex(r)
		if err != nil {
			return nil, fmt.Errorf("corrupt keyword index: %v", err)
		}
		db.KW = kw
	}
	return db, nil
}

// readKWIndex decodes the Tier 2 keyword block and reconstructs the in-memory
// structures (term->id, postings, lens) from the serialized per-chunk tf.
func readKWIndex(r io.Reader) (*KWIndex, error) {
	nTerms, err := readU32(r)
	if err != nil {
		return nil, err
	}
	terms := make([]string, nTerms)
	for i := 0; i < int(nTerms); i++ {
		terms[i], err = readStr(r)
		if err != nil {
			return nil, err
		}
	}
	nDF, err := readU32(r)
	if err != nil {
		return nil, err
	}
	if nDF != nTerms {
		return nil, fmt.Errorf("df count %d != term count %d", nDF, nTerms)
	}
	df := make([]uint32, nTerms)
	for i := 0; i < int(nTerms); i++ {
		df[i], err = readU32(r)
		if err != nil {
			return nil, err
		}
	}
	var avg float32
	if err := binary.Read(r, binary.LittleEndian, &avg); err != nil {
		return nil, err
	}
	nChunks, err := readU32(r)
	if err != nil {
		return nil, err
	}
	chunkTF := make([][]tfPair, nChunks)
	for ci := 0; ci < int(nChunks); ci++ {
		ntf, err := readU32(r)
		if err != nil {
			return nil, err
		}
		tf := make([]tfPair, ntf)
		for j := 0; j < int(ntf); j++ {
			id, err := readU32(r)
			if err != nil {
				return nil, err
			}
			cnt, err := readU32(r)
			if err != nil {
				return nil, err
			}
			if id >= uint32(nTerms) {
				return nil, fmt.Errorf("termID %d out of range (nTerms=%d)", id, nTerms)
			}
			tf[j] = tfPair{id: int32(id), count: int32(cnt)}
		}
		chunkTF[ci] = tf
	}
	id := make(map[string]int32, nTerms)
	for i, t := range terms {
		id[t] = int32(i)
	}
	return &KWIndex{
		N: int(nChunks), Terms: terms, ID: id, DF: df,
		AvgDL: float64(avg), Lens: computeLens(chunkTF),
		ChunkTF: chunkTF, Postings: buildPostings(int(nChunks), chunkTF),
	}, nil
}

// ---------- search ----------

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// embedQuery embeds a single query with the active backend (local by default, or the
// remote endpoint when KB_EMBED_URL is set). The backend must match the one used at
// build time or scores are meaningless — Search enforces the dimension match.
func (db *DB) embedQuery(q string) []float32 {
	return embedOne(q, db.Dim)
}

// Search runs a query in the given mode ("" = hybrid, the Tier 2 default):
//
//	hybrid   RRF (K=60) fusion of channel A (BM25 keyword) + channel B (vector cosine)
//	vector   channel B only (== Tier 1 behavior; the regression baseline)
//	keyword  channel A only (pure BM25)
//	weighted wKW·minmax(A) + wVec·minmax(B), default weights 0.6/0.4 (see SearchW)
//
// Filters: path (substring) and kind are applied FIRST to build the candidate set;
// both channels score only that set. min (when > 0) is a semantic-confidence gate on
// the dense-vector score only — it never gates BM25; 0 = off. Ties break by lower
// original chunk index, so results are fully deterministic.
func (db *DB) Search(query string, k int, pathSub, kind string, min float64, fullText bool, mode string) ([]Result, error) {
	return db.SearchW(query, k, pathSub, kind, min, fullText, mode, defWKeyword, defWVector)
}

// SearchW is Search with explicit fusion weights for mode=weighted.
func (db *DB) SearchW(query string, k int, pathSub, kind string, min float64, fullText bool, mode string, wKW, wVec float64) ([]Result, error) {
	// Security (plans/security-filter-plan.md §3.3): canonicalize the query so smuggled
	// invisible chars can't reach the tokenizer, the hashing embedder, or a remote
	// embedding model (KB_EMBED_URL is a model endpoint).
	query = stripInvisible(query)
	if k <= 0 {
		k = 10
	}
	switch mode {
	case "", ModeHybrid, ModeVector, ModeKeyword, ModeWeighted:
	default:
		return nil, fmt.Errorf("unknown mode %q (want hybrid|vector|keyword|weighted)", mode)
	}
	if db.KW == nil && mode != ModeVector {
		if mode == ModeKeyword || mode == ModeWeighted {
			return nil, fmt.Errorf("keyword index not built; rebuild to enable %s mode", mode)
		}
		mode = ModeVector // pre-Tier-2 DB: hybrid degrades to vector (tier-2 plan §8)
	}
	if len(db.Chunks) == 0 {
		return nil, nil
	}

	// ---- candidate set: path/kind filters applied first; both channels score only it ----
	var cand []int
	for i := range db.Chunks {
		c := &db.Chunks[i]
		if pathSub != "" && !strings.Contains(strings.ToLower(c.Path), strings.ToLower(pathSub)) {
			continue
		}
		if kind != "" && c.Kind != kind {
			continue
		}
		cand = append(cand, i)
	}
	if len(cand) == 0 {
		return nil, nil
	}
	var candSet map[int]bool
	if len(cand) < len(db.Chunks) {
		candSet = make(map[int]bool, len(cand))
		for _, i := range cand {
			candSet[i] = true
		}
	}

	// Per-query scratch score buffers. Chunk IDs are dense (0..N-1), so a []float64
	// indexed by chunk ID is O(1) to fill, read and merge — much cheaper than map
	// lookups (this is what keeps p95 under 100 ms at N=50k, tier-2 plan §10).
	n := len(db.Chunks)
	scA := make([]float64, n)
	scB := make([]float64, n)
	var activeA, activeB []int

	// ---- channel B: dense-vector cosine (mechanism unchanged from Tier 1) ----
	if mode != ModeKeyword {
		if want := backendTag(); db.Backend != "" && want != db.Backend {
			return nil, fmt.Errorf("embedding backend mismatch: db was built with %q but the active backend is %q; use the same embedding backend (KB_EMBED_*) for build and query, or rebuild",
				db.Backend, want)
		}
		qv := db.embedQuery(query)
		if len(qv) != db.Dim {
			return nil, fmt.Errorf("embedding dimension mismatch: db was built with dim %d (%s) but the query produced dim %d; use the same embedding backend for build and query, or rebuild",
				db.Dim, db.Backend, len(qv))
		}
		for _, i := range cand {
			s := dot(qv, db.Chunks[i].Vector)
			if mode == ModeVector {
				if s < min { // Tier 1 semantics: min gates the only channel
					continue
				}
			} else if min > 0 && s < min { // hybrid/weighted: min is a pre-filter on B only
				continue
			}
			scB[i] = s
			activeB = append(activeB, i)
		}
	}

	// ---- channel A: BM25 keyword (never gated by min) ----
	if mode != ModeVector {
		activeA = db.KW.ScoreInto(query, candSet, scA)
	}

	// ---- rank + fuse ----
	var fused []idScore
	switch mode {
	case ModeVector:
		fused = rankIDs(activeB, scB)
	case ModeKeyword:
		fused = rankIDs(activeA, scA)
	case ModeWeighted:
		fused = weightedFuse(rankIDs(activeA, scA), rankIDs(activeB, scB), wKW, wVec, n)
	default: // "" or hybrid
		fused = rrfFuse(rankIDs(activeA, scA), rankIDs(activeB, scB), rrfK, n)
	}
	if len(fused) > k {
		fused = fused[:k]
	}
	res := make([]Result, len(fused))
	for i, e := range fused {
		res[i] = Result{C: db.Chunks[e.id], Score: e.sc}
	}
	return res, nil
}

// idScore is a chunk ID with its (channel or fused) score.
type idScore struct {
	id int
	sc float64
}

// rankIDs sorts active chunk IDs by sc[id] descending; ties break by lower chunk
// index first (deterministic). No map lookups in the comparator (scores are copied
// into the slice first) — this keeps sorting 50k entries in single-digit ms.
func rankIDs(active []int, sc []float64) []idScore {
	out := make([]idScore, len(active))
	for i, id := range active {
		out[i] = idScore{id: id, sc: sc[id]}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].sc != out[b].sc {
			return out[a].sc > out[b].sc
		}
		return out[a].id < out[b].id
	})
	return out
}

// rrfFuse applies Reciprocal Rank Fusion: RRF(d) = Σ_c 1/(K + rank_c(d)), 1-based
// rank within channel c; a chunk absent from a channel contributes 0 from it. Rank-based,
// so no score normalization is needed across the two channels' different scales.
func rrfFuse(rankA, rankB []idScore, K int, n int) []idScore {
	sc := make([]float64, n)
	seen := make([]bool, n)
	var ids []int
	for _, e := range rankA {
		if !seen[e.id] {
			seen[e.id] = true
			ids = append(ids, e.id)
		}
	}
	for _, e := range rankB {
		if !seen[e.id] {
			seen[e.id] = true
			ids = append(ids, e.id)
		}
	}
	for r, e := range rankA {
		sc[e.id] += 1.0 / float64(K+r+1)
	}
	for r, e := range rankB {
		sc[e.id] += 1.0 / float64(K+r+1)
	}
	out := make([]idScore, len(ids))
	for i, id := range ids {
		out[i] = idScore{id: id, sc: sc[id]}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].sc != out[b].sc {
			return out[a].sc > out[b].sc
		}
		return out[a].id < out[b].id
	})
	return out
}

// weightedFuse computes wA·minmax(A) + wB·minmax(B); a chunk absent from a channel
// contributes 0 from that channel (its min-max value is not imputed). Input rankings
// are sorted descending, so hi/lo are the endpoints.
func weightedFuse(rankA, rankB []idScore, wA, wB float64, n int) []idScore {
	sc := make([]float64, n)
	apply := func(rank []idScore, w float64) {
		if len(rank) == 0 {
			return
		}
		hi, lo := rank[0].sc, rank[len(rank)-1].sc
		for _, e := range rank {
			if hi > lo {
				sc[e.id] += w * (e.sc - lo) / (hi - lo)
			} else {
				sc[e.id] += w // all-equal (or single) chunk: everyone is "best"
			}
		}
	}
	apply(rankA, wA)
	apply(rankB, wB)
	seen := make([]bool, n)
	var ids []int
	for _, e := range rankA {
		if !seen[e.id] {
			seen[e.id] = true
			ids = append(ids, e.id)
		}
	}
	for _, e := range rankB {
		if !seen[e.id] {
			seen[e.id] = true
			ids = append(ids, e.id)
		}
	}
	out := make([]idScore, len(ids))
	for i, id := range ids {
		out[i] = idScore{id: id, sc: sc[id]}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].sc != out[b].sc {
			return out[a].sc > out[b].sc
		}
		return out[a].id < out[b].id
	})
	return out
}

// ---------- terms census + context bundle (plans/context-bundle-plan.md) ----------
//
// Two lexical, read-only tools over the existing chunk store — no new index
// artifact, no AST, no type inference:
//
//   kb_terms — a COMPLETE occurrence census of one exact identifier/string over
//       every indexed chunk (substring match). Absence is a citable result:
//       present = the text occurs in at least one indexed chunk, independent of
//       any ranking (an identifier that "exists but didn't rank" in a hybrid
//       query is still censused as present).
//
//   kb_bundle — context-bundle expansion: for a location (file:line) or the top
//       hits of a query, one consolidated read pack per hit following the
//       code's own written pointers: (1) package neighborhood (sibling files +
//       one-line summary), (2) literal/identifier propagation (stable fragments
//       searched tree-wide), (3) import verdicts (internal / external /
//       unresolved — never a wrong verdict), (4) test-file pairing.

// bundle limits (plan §Design): hard caps keep large repos from flooding the
// terminal; every cap that fires renders an explicit "…truncated" marker.
const (
	termsDefaultMaxFiles = 20 // default census files shown (k)
	termsMaxLinesPerFile = 3  // representative lines per census file

	bundleDefaultHits   = 3  // top hits bundled for a query
	bundleMaxHits       = 8  // cap on hits bundled for a query
	bundleNeighborhood  = 20 // sibling files per neighborhood section
	bundleSummaryLimit  = 80 // one-line summary length (rune clip)
	bundleCandMax       = 8  // propagation candidates per hit
	bundleFragMax       = 6  // fragments per candidate
	bundleFragFilesMax  = 10 // files per fragment
	bundleFragMinLen    = 6  // min fragment length
	bundleImportsMax    = 20 // import statements per hit
	bundleTestMax       = 10 // paired test files per hit
	bundleTestSharedMax = 3  // shared identifiers shown per test file
	bundleSymbolLimit   = 3  // exported symbols in a neighborhood summary
)

// ---------- kb_terms: occurrence census ----------

type termsFile struct {
	Path  string   `json:"path"`
	Count int      `json:"count"`
	Lines []string `json:"lines,omitempty"`
}

type termsResult struct {
	Identifier  string      `json:"identifier"`
	Present     bool        `json:"present"`
	Occurrences int         `json:"occurrences"`
	FileCount   int         `json:"fileCount"`
	Files       []termsFile `json:"files"`
	Truncated   bool        `json:"truncated"`
}

// termsCensus scans every non-board chunk once and aggregates exact (case-
// sensitive) substring occurrences of term per file, with up to
// termsMaxLinesPerFile representative lines per file. k caps the file list (the
// true total stays in FileCount). Ranking is deliberately NOT involved: the
// result is a complete census of the indexed source, so absence is citable.
func termsCensus(db *DB, term string, k int) *termsResult {
	term = stripInvisible(term)
	if k <= 0 {
		k = termsDefaultMaxFiles
	}
	type acc struct {
		count int
		lines []string
	}
	res := &termsResult{Identifier: term, Files: []termsFile{}}
	if term == "" {
		return res
	}
	byFile := map[string]*acc{}
	total := 0
	for i := range db.Chunks {
		c := &db.Chunks[i]
		if c.Kind == "board" {
			continue // census is over indexed sources, not conversation
		}
		n := strings.Count(c.Text, term)
		if n == 0 {
			continue
		}
		total += n
		a, ok := byFile[c.Path]
		if !ok {
			a = &acc{}
			byFile[c.Path] = a
		}
		a.count += n
		if len(a.lines) < termsMaxLinesPerFile {
			for li, ln := range strings.Split(c.Text, "\n") {
				if strings.Contains(ln, term) {
					a.lines = append(a.lines, fmt.Sprintf(":%d  %s", c.Start+li, clip(strings.TrimSpace(ln), 120)))
					if len(a.lines) >= termsMaxLinesPerFile {
						break
					}
				}
			}
		}
	}
	res.Occurrences = total
	res.Present = total > 0
	res.FileCount = len(byFile)
	names := make([]string, 0, len(byFile))
	for p := range byFile {
		names = append(names, p)
	}
	sort.Slice(names, func(i, j int) bool {
		if byFile[names[i]].count != byFile[names[j]].count {
			return byFile[names[i]].count > byFile[names[j]].count
		}
		return names[i] < names[j]
	})
	if len(names) > k {
		names = names[:k]
		res.Truncated = true
	}
	for _, p := range names {
		res.Files = append(res.Files, termsFile{Path: p, Count: byFile[p].count, Lines: byFile[p].lines})
	}
	return res
}

// renderTerms is the human-readable census (kbtool terms without -json).
func renderTerms(r *termsResult) string {
	var b strings.Builder
	if !r.Present {
		// The feature's reason to exist: a DISTINCT, unambiguous absence result
		// that is citable as evidence (plans/context-bundle-plan.md).
		fmt.Fprintf(&b, "ABSENT in indexed sources: %q (0 occurrences in 0 files)\n", r.Identifier)
		return b.String()
	}
	fmt.Fprintf(&b, "%d occurrence(s) in %d file(s) for %q:\n", r.Occurrences, r.FileCount, r.Identifier)
	for _, f := range r.Files {
		fmt.Fprintf(&b, "  %s  (%d)\n", f.Path, f.Count)
		for _, ln := range f.Lines {
			fmt.Fprintf(&b, "      %s\n", ln)
		}
	}
	if r.Truncated {
		fmt.Fprintf(&b, "  …truncated (showing first %d of %d files)\n", len(r.Files), r.FileCount)
	}
	return b.String()
}

// ---------- kb_bundle: shared primitives ----------

// bundleFiles precomputes the per-file chunk map for one bundle call (board
// chunks excluded — the pack follows the code's pointers, not the board).
type bundleFiles struct {
	names  []string         // distinct chunk paths, in first-seen order
	set    map[string]bool  // membership
	chunks map[string][]int // path -> chunk indexes
}

func newBundleFiles(db *DB) *bundleFiles {
	bf := &bundleFiles{set: map[string]bool{}, chunks: map[string][]int{}}
	for i := range db.Chunks {
		c := &db.Chunks[i]
		if c.Kind == "board" {
			continue
		}
		if !bf.set[c.Path] {
			bf.set[c.Path] = true
			bf.names = append(bf.names, c.Path)
		}
		bf.chunks[c.Path] = append(bf.chunks[c.Path], i)
	}
	return bf
}

// dirOf returns the directory prefix of a chunk path ("a/b/c.go" -> "a/b/").
func dirOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return ""
	}
	return p[:i+1]
}

// baseOf returns the final path element ("a/b/c.go" -> "c.go").
func baseOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return p
	}
	return p[i+1:]
}

// pathSegs splits a slash path into non-empty segments.
func pathSegs(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// segsSuffix reports whether segs is a suffix of dir (segment-wise).
func segsSuffix(dir, segs []string) bool {
	if len(segs) > len(dir) {
		return false
	}
	off := len(dir) - len(segs)
	for i, s := range segs {
		if dir[off+i] != s {
			return false
		}
	}
	return true
}

// fileSummary produces the one-line neighborhood summary for a file: the first
// top-of-file doc-comment line (Go //, Java /**, #, """/”'), else up to
// bundleSymbolLimit exported symbol names (func/class/interface/struct/def/
// export), else the first non-empty line.
func fileSummary(db *DB, bf *bundleFiles, path string) string {
	idxs := bf.chunks[path]
	if len(idxs) == 0 {
		return "(no chunks)"
	}
	first := idxs[0]
	for _, i := range idxs[1:] {
		if db.Chunks[i].Start < db.Chunks[first].Start {
			first = i
		}
	}
	lines := strings.Split(db.Chunks[first].Text, "\n")
	if len(lines) > 20 {
		lines = lines[:20]
	}
	commentRe := regexp.MustCompile(`^(?:/\*\*\?|//+|#|"""|'')\s*(.*)$`)
	symRe := regexp.MustCompile(`(?:\bfunc\s+|\bclass\s+|\binterface\s+|\bstruct\s+|\bdef\s+|\bexport\s+(?:default\s+)?(?:async\s+)?)` +
		`([A-Za-z_$][A-Za-z0-9_$]*)`)
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if t == "" {
			continue
		}
		if m := commentRe.FindStringSubmatch(t); m != nil && strings.TrimSpace(m[1]) != "" {
			return clip(strings.TrimSpace(m[1]), bundleSummaryLimit)
		}
		break // only comment lines at the very top of the file count
	}
	var syms []string
	seen := map[string]bool{}
	for _, ln := range lines {
		for _, m := range symRe.FindAllStringSubmatch(ln, -1) {
			if !seen[m[1]] && !identStopword[m[1]] {
				seen[m[1]] = true
				syms = append(syms, m[1])
				if len(syms) >= bundleSymbolLimit {
					break
				}
			}
		}
		if len(syms) >= bundleSymbolLimit {
			break
		}
	}
	if len(syms) > 0 {
		return clip(strings.Join(syms, ", "), bundleSummaryLimit)
	}
	for _, ln := range lines {
		if t := strings.TrimSpace(ln); t != "" {
			return clip(t, bundleSummaryLimit)
		}
	}
	return "(empty)"
}

// ---------- propagation: candidate extraction + stable fragments ----------

// identStopword filters language keywords and ubiquitous generic names out of
// the propagation candidates and test-pairing identifiers (a hit mentioning
// "class" or "String" is not a pointer worth a tree-wide scan).
var identStopword = map[string]bool{
	// Go
	"package": true, "import": true, "return": true, "func": true, "type": true,
	"var": true, "const": true, "nil": true, "new": true, "make": true,
	"string": true, "int": true, "int32": true, "int64": true, "uint32": true,
	"uint64": true, "byte": true, "rune": true, "bool": true, "error": true,
	"errors": true, "context": true, "json": true, "http": true, "bytes": true,
	"fmt": true, "io": true, "os": true, "sync": true, "time": true,
	"println": true, "print": true,
	// Java / C-like
	"class": true, "interface": true, "public": true, "private": true,
	"protected": true, "static": true, "final": true, "void": true, "this": true,
	"super": true, "extends": true, "implements": true, "true": true, "false": true,
	"null": true, "boolean": true, "integer": true, "double": true, "float": true,
	"char": true, "long": true, "short": true, "enum": true, "case": true,
	"switch": true, "break": true, "continue": true, "else": true, "for": true,
	"while": true, "if": true, "in": true, "throw": true, "try": true,
	"catch": true, "finally": true, "assert": true, "String": true,
	"Integer": true, "Boolean": true, "Double": true, "Float": true, "Object": true,
	"Number": true, "System": true, "equals": true, "toString": true, "valueOf": true,
	"parseInt": true, "parseLong": true, "format": true, "formatted": true,
	"StringBuilder": true, "append": true, "trim": true, "split": true, "join": true,
	"length": true, "size": true, "isEmpty": true, "builder": true, "buffer": true,
	"buffers": true, "stream": true, "streams": true, "Optional": true,
	"List": true, "Map": true, "Set": true, "Collection": true, "Iterable": true,
	// JS / TS
	"export": true, "default": true, "module": true, "require": true,
	"from": true, "await": true, "async": true, "yield": true, "typeof": true,
	"console": true, "undefined": true, "Promise": true, "Array": true,
	"math": true, "JSON": true, "then": true,
	// Python
	"def": true, "self": true, "None": true, "True": true, "False": true, "with": true,
	"raise": true, "except": true, "lambda": true, "pass": true, "global": true,
	"nonlocal": true, "del": true, "is": true, "not": true, "and": true, "or": true,
	"str": true, "dict": true, "list": true, "tuple": true,
	"range": true, "len": true,
	// ubiquitous generics (all languages)
	"value": true, "values": true, "name": true, "names": true, "key": true,
	"keys": true, "data": true, "result": true, "results": true, "response": true,
	"request": true, "message": true, "messages": true, "info": true, "log": true,
	"logger": true, "logging": true, "warn": true, "warning": true, "debug": true,
	"trace": true, "level": true, "levels": true, "config": true, "configuration": true,
	"option": true, "options": true, "setting": true, "settings": true, "property": true,
	"properties": true, "attribute": true, "attributes": true, "field": true,
	"fields": true, "column": true, "columns": true, "table": true, "tables": true,
	"row": true, "rows": true, "record": true, "records": true, "entity": true,
	"entities": true, "document": true, "documents": true, "item": true, "items": true,
	"entry": true, "entries": true, "element": true, "elements": true, "node": true,
	"nodes": true, "child": true, "children": true, "parent": true, "root": true,
	"index": true, "indices": true, "offset": true, "limit": true, "count": true,
	"total": true, "sum": true, "average": true, "max": true, "min": true,
	"step": true, "steps": true, "interval": true, "duration": true, "timeout": true,
	"retries": true, "retry": true, "poll": true, "polling": true, "batch": true,
	"batches": true, "chunk": true, "chunks": true, "page": true, "pages": true,
	"slice": true, "stack": true, "queue": true, "map": true, "set": true,
	"channel": true, "channels": true, "pipe": true, "pipes": true, "socket": true,
	"sockets": true, "server": true, "servers": true, "client": true, "clients": true,
	"connection": true, "connections": true, "session": true, "sessions": true,
	"token": true, "tokens": true, "secret": true, "secrets": true, "password": true,
	"credential": true, "credentials": true, "certificate": true, "certificates": true,
	"sign": true, "signing": true, "signature": true, "verify": true,
	"verification": true, "auth": true, "authentication": true, "authorization": true,
	"permission": true, "permissions": true, "role": true, "roles": true, "user": true,
	"users": true, "account": true, "accounts": true, "team": true, "teams": true,
	"project": true, "projects": true, "policy": true, "policies": true, "rule": true,
	"rules": true, "filter": true, "filters": true, "matcher": true, "matchers": true,
	"handler": true, "handlers": true, "listener": true, "listeners": true,
	"callback": true, "callbacks": true, "hook": true, "hooks": true, "plugin": true,
	"plugins": true, "provider": true, "providers": true, "adapter": true,
	"adapters": true, "wrapper": true, "wrappers": true, "proxy": true, "proxies": true,
	"cache": true, "caches": true, "pool": true, "pools": true, "store": true,
	"stores": true, "repository": true, "repositories": true, "registry": true,
	"registries": true, "catalog": true, "catalogs": true, "source": true,
	"sources": true, "target": true, "targets": true, "input": true, "inputs": true,
	"output": true, "outputs": true, "payload": true, "payloads": true, "body": true,
	"header": true, "headers": true, "query": true, "queries": true, "param": true,
	"params": true, "argument": true, "arguments": true, "flag": true, "flags": true,
	"mode": true, "modes": true, "state": true, "states": true, "status": true,
	"phase": true, "phases": true, "stage": true, "stages": true, "task": true,
	"tasks": true, "job": true, "jobs": true, "worker": true, "workers": true,
	"agent": true, "agents": true, "process": true, "processes": true, "thread": true,
	"threads": true, "service": true, "services": true, "endpoint": true,
	"endpoints": true, "route": true, "routes": true, "path": true, "paths": true,
	"url": true, "urls": true, "uri": true, "uris": true, "link": true, "links": true,
	"ref": true, "refs": true, "id": true, "ids": true, "uuid": true, "uuids": true,
	"timestamp": true, "timestamps": true, "date": true, "dates": true, "day": true,
	"days": true, "month": true, "months": true, "year": true, "years": true,
	"hour": true, "hours": true, "minute": true, "minutes": true, "second": true,
	"seconds": true, "week": true, "weeks": true, "quarter": true, "quarters": true,
	"epoch": true, "utc": true, "gmt": true, "zone": true, "zones": true,
	"local": true, "remote": true, "internal": true, "external": true, "shared": true,
	"open": true, "closed": true, "active": true, "inactive": true, "enabled": true,
	"disabled": true, "valid": true, "invalid": true, "ready": true, "pending": true,
	"completed": true, "failed": true, "failure": true, "failures": true,
	"success": true, "succeeded": true, "running": true, "stopped": true,
	"started": true, "starting": true, "killed": true, "expired": true,
	"expiring": true, "deleted": true, "removed": true, "cleared": true, "purged": true,
	"archived": true, "stored": true, "saved": true, "loaded": true, "loading": true,
	"parse": true, "encode": true, "decode": true, "read": true, "write": true,
	"create": true, "update": true, "insert": true, "select": true, "fetch": true,
	"get": true, "put": true, "empty": true,
}

var (
	// string literals: double-quoted, single-quoted (min 2 inner chars), or
	// backtick-quoted (min 1 char) — escapes allowed in the first two.
	propLitRe   = regexp.MustCompile("\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`\n]*`")
	propIdentRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]{4,}`)
	propVerbRe  = regexp.MustCompile(`%[-#0 +]*[a-zA-Z]`)
	propRunRe   = regexp.MustCompile(`[A-Za-z0-9._-]{6,}`)
	propAlphaRe = regexp.MustCompile(`[A-Za-z0-9]`)
)

// stripCommentLines drops comment-only lines (//, #, * block-continuation, """/
// ”' docstring openers, /* openers) so doc text doesn't pollute the propagation
// candidates — the code's own pointers are in code, not prose.
func stripCommentLines(text string) string {
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") ||
			strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") ||
			strings.HasPrefix(t, "\"\"\"") || strings.HasPrefix(t, "'''") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// extractCandidates pulls the propagation candidates out of the hit text (comment
// lines stripped): string literals first, then identifiers — longest first,
// deduped, stopword-filtered, capped at bundleCandMax. (plan §Design.2)
func extractCandidates(text string) []string {
	text = stripCommentLines(text)
	var literals, idents []string
	seen := map[string]bool{}
	for _, m := range propLitRe.FindAllString(text, -1) {
		inner := strings.Trim(m, "\"'`")
		if inner == "" || seen[inner] {
			continue
		}
		if len(inner) < 4 || len(inner) > 200 {
			continue
		}
		if !propAlphaRe.MatchString(inner) {
			continue
		}
		seen[inner] = true
		literals = append(literals, inner)
	}
	for _, m := range propIdentRe.FindAllString(text, -1) {
		if seen[m] || identStopword[m] {
			continue
		}
		seen[m] = true
		idents = append(idents, m)
	}
	byLen := func(s []string) {
		sort.Slice(s, func(a, b int) bool {
			if len(s[a]) != len(s[b]) {
				return len(s[a]) > len(s[b])
			}
			return s[a] < s[b]
		})
	}
	byLen(literals)
	byLen(idents)
	out := append(literals, idents...)
	if len(out) > bundleCandMax {
		out = out[:bundleCandMax]
	}
	return out
}

// stableFragments derives the search fragments of one candidate (plan
// §Design.2): split on format verbs (%s, %d, …), then keep every run of
// ≥ bundleFragMinLen word chars ([A-Za-z0-9._-], edges trimmed). A pure
// identifier yields itself;
// "...nvdcve-2.0-%s.json.gz" -> ["nvdcve-2.0", "nvd.nist.gov", "json.gz", …].
// Longest first, capped at bundleFragMax, deduped.
func stableFragments(s string) []string {
	if len(s) < bundleFragMinLen {
		return nil
	}
	seen := map[string]bool{}
	var frags []string
	add := func(f string) {
		f = strings.TrimLeft(f, "-.")
		f = strings.TrimRight(f, "-.")
		if len(f) >= bundleFragMinLen && !seen[f] {
			seen[f] = true
			frags = append(frags, f)
		}
	}
	for _, piece := range propVerbRe.Split(s, -1) {
		for _, run := range propRunRe.FindAllString(piece, -1) {
			add(run)
		}
	}
	sort.Slice(frags, func(a, b int) bool {
		if len(frags[a]) != len(frags[b]) {
			return len(frags[a]) > len(frags[b])
		}
		return frags[a] < frags[b]
	})
	if len(frags) > bundleFragMax {
		frags = frags[:bundleFragMax]
	}
	return frags
}

// fragHit is one file's occurrence count for a fragment.
type fragHit struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// fragmentSearch finds one exact fragment tree-wide (substring scan over the
// chunk texts — the BM25 postings cannot express "this exact fragment", and no
// new index is wanted). Returns per-file counts, top bundleFragFilesMax files.
func fragmentSearch(db *DB, frag string) []fragHit {
	byFile := map[string]int{}
	for i := range db.Chunks {
		c := &db.Chunks[i]
		if c.Kind == "board" {
			continue
		}
		if n := strings.Count(c.Text, frag); n > 0 {
			byFile[c.Path] += n
		}
	}
	out := make([]fragHit, 0, len(byFile))
	for p, n := range byFile {
		out = append(out, fragHit{Path: p, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > bundleFragFilesMax {
		out = out[:bundleFragFilesMax]
	}
	return out
}

// ---------- import verdicts (per-language line patterns, NOT an AST) ----------

type importVerdict struct {
	Line    int    `json:"line"`
	Stmt    string `json:"stmt"`
	Verdict string `json:"verdict"` // internal | external | unresolved
	Detail  string `json:"detail,omitempty"`
}

var (
	goImportLineRe  = regexp.MustCompile(`^\s*import\s+(?:([A-Za-z_][\w.]*|\.\|\*)\s+)?"([^"]+)"\s*(//.*)?$`)
	goImportOpenRe  = regexp.MustCompile(`^\s*import\s*\(`)
	goBlockImportRe = regexp.MustCompile(`^\s*(?:([A-Za-z_][\w.]*|\.\|\*)\s+)?"([^"]+)"\s*(//.*)?$`)
	javaImportRe    = regexp.MustCompile(`^\s*import\s+(static\s+)?([A-Za-z_][\w.]*)\s*;`)
	jsFromImportRe  = regexp.MustCompile(`^\s*(?:import|export)\b.*?\bfrom\s+["']([^"']+)["']`)
	jsRequireRe     = regexp.MustCompile(`\brequire\s*\(\s*["']([^"']+)["']\s*\)`)
	pyImportRe      = regexp.MustCompile(`^\s*import\s+([\w.]+(?:\s*,\s*[\w.]+)*)`)
	pyFromImportRe  = regexp.MustCompile(`^\s*from\s+([.\w*]+)\s+import\s+(.+)$`)
)

// importVerdicts scans the hit chunk's lines with the language's import pattern
// (keyed by extension: Go, Java/Kotlin, JS/TS, Python) and resolves each
// against the indexed file set. The verdict ladder is deliberately fail-closed
// (plan §Design.3): internal requires a matching indexed file (shown, with the
// matched suffix for module-style imports); external means "no indexed file
// matches this deterministic mapping"; anything ambiguous (Python relative or
// wildcard imports) is unresolved. Never a wrong verdict.
func importVerdicts(db *DB, bf *bundleFiles, c Chunk) []importVerdict {
	ext := strings.ToLower(filepath.Ext(baseOf(c.Path)))
	lines := strings.Split(c.Text, "\n")
	var out []importVerdict
	add := func(lineIdx int, stmt, verdict, detail string) {
		if len(out) >= bundleImportsMax {
			return
		}
		out = append(out, importVerdict{Line: c.Start + lineIdx, Stmt: clip(stmt, 100), Verdict: verdict, Detail: detail})
	}

	// dirSuffixMatch: the longest suffix of the import's path segments that is a
	// suffix of some indexed file's directory segments (Go module imports carry
	// a module prefix the indexed paths do not, so suffix matching is the
	// honest lexical rule; the matched suffix is reported for human judgment).
	dirSuffixMatch := func(impSegs []string) (path, matched string) {
		for n := len(impSegs); n >= 1; n-- {
			suffix := impSegs[len(impSegs)-n:]
			for _, f := range bf.names {
				if segsSuffix(pathSegs(dirOf(f)), suffix) {
					return f, strings.Join(suffix, "/")
				}
			}
		}
		return "", ""
	}

	switch ext {
	case ".go":
		inBlock := false
		for li, raw := range lines {
			t := strings.TrimSpace(raw)
			if inBlock {
				if t == ")" {
					inBlock = false
					continue
				}
				if strings.HasPrefix(t, "//") {
					continue
				}
				if m := goBlockImportRe.FindStringSubmatch(t); m != nil && m[2] != "" {
					if p, suf := dirSuffixMatch(pathSegs(m[2])); p != "" {
						add(li, m[2], "internal", p+" (matched suffix \""+suf+"\")")
					} else {
						add(li, m[2], "external", "not-in-tree")
					}
				}
				continue
			}
			if goImportOpenRe.MatchString(t) {
				inBlock = true
				continue
			}
			if m := goImportLineRe.FindStringSubmatch(raw); m != nil && m[2] != "" {
				if p, suf := dirSuffixMatch(pathSegs(m[2])); p != "" {
					add(li, m[2], "internal", p+" (matched suffix \""+suf+"\")")
				} else {
					add(li, m[2], "external", "not-in-tree")
				}
			}
		}
	case ".java", ".kt":
		for li, raw := range lines {
			m := javaImportRe.FindStringSubmatch(raw)
			if m == nil || m[2] == "" {
				continue
			}
			dotted := m[2]
			segs := pathSegs(strings.ReplaceAll(dotted, ".", "/"))
			if len(segs) == 0 {
				add(li, dotted, "unresolved", "empty import path")
				continue
			}
			base := segs[len(segs)-1]
			dirPart := segs[:len(segs)-1]
			var found string
			for _, f := range bf.names {
				fsegs := pathSegs(f)
				if len(fsegs) < 2 {
					continue
				}
				fdir, fbase := fsegs[:len(fsegs)-1], fsegs[len(fsegs)-1]
				// class file in a directory whose tail matches the package part
				if strings.EqualFold(fbase, base+".java") && segsSuffix(fdir, dirPart) {
					found = f
					break
				}
				// nested-class layout: the package directory includes the base
				if segsSuffix(fdir, segs) && strings.HasSuffix(fbase, ".java") {
					found = f
					break
				}
			}
			if found != "" {
				add(li, dotted, "internal", found)
			} else {
				add(li, dotted, "external", "not-in-tree")
			}
		}
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		for li, raw := range lines {
			var specs []string
			if m := jsFromImportRe.FindStringSubmatch(raw); m != nil {
				specs = append(specs, m[1])
			}
			for _, m := range jsRequireRe.FindAllStringSubmatch(raw, -1) {
				specs = append(specs, m[1])
			}
			for _, spec := range specs {
				if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") {
					target := dirOf(c.Path) + strings.TrimPrefix(strings.TrimPrefix(spec, "./"), "../")
					cand := []string{target}
					for _, e := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"} {
						cand = append(cand, target+e, target+"/index"+e)
					}
					var found string
					for _, cc := range cand {
						if bf.set[cc] {
							found = cc
							break
						}
					}
					if found != "" {
						add(li, spec, "internal", found)
					} else {
						add(li, spec, "external", "not-in-tree")
					}
				} else {
					if p, suf := dirSuffixMatch(pathSegs(spec)); p != "" {
						add(li, spec, "internal", p+" (matched suffix \""+suf+"\")")
					} else {
						add(li, spec, "external", "not-in-tree")
					}
				}
			}
		}
	case ".py":
		for li, raw := range lines {
			if m := pyFromImportRe.FindStringSubmatch(raw); m != nil {
				module, imports := m[1], m[2]
				if strings.Contains(imports, "*") {
					add(li, "from "+module+" import "+clip(imports, 40), "unresolved", "wildcard import")
					continue
				}
				if strings.HasPrefix(module, ".") {
					add(li, "from "+module+" import "+clip(imports, 40), "unresolved", "relative import")
					continue
				}
				ms := pathSegs(strings.ReplaceAll(module, ".", "/")) // dotted module -> path segments
				var names []string
				for _, nm := range strings.Split(imports, ",") {
					if f := strings.Fields(strings.TrimSpace(nm)); len(f) > 0 {
						names = append(names, f[0]) // "x as y" -> x
					}
				}
				var found string
				for _, f := range bf.names {
					fsegs := pathSegs(f)
					if len(fsegs) < 2 {
						continue
					}
					fdir, fbase := fsegs[:len(fsegs)-1], fsegs[len(fsegs)-1]
					if (fbase == ms[len(ms)-1]+".py" && segsSuffix(fdir, ms[:len(ms)-1])) ||
						(fbase == "__init__.py" && segsSuffix(fdir, ms)) {
						found = f
						break
					}
					for _, nm := range names {
						if nm == "" {
							continue
						}
						if (fbase == nm+".py" && segsSuffix(fdir, ms)) ||
							(fbase == "__init__.py" && segsSuffix(fdir, append(append([]string{}, ms...), nm))) {
							found = f
							break
						}
					}
					if found != "" {
						break
					}
				}
				stmt := "from " + module + " import " + clip(imports, 40)
				if found != "" {
					add(li, stmt, "internal", found)
				} else {
					add(li, stmt, "external", "not-in-tree")
				}
				continue
			}
			if m := pyImportRe.FindStringSubmatch(raw); m != nil {
				for _, mod := range strings.Split(m[1], ",") {
					mod = strings.TrimSpace(mod)
					if mod == "" {
						continue
					}
					ms := pathSegs(strings.ReplaceAll(mod, ".", "/")) // dotted module -> path segments
					var found string
					for _, f := range bf.names {
						fsegs := pathSegs(f)
						if len(fsegs) < 2 {
							continue
						}
						fdir, fbase := fsegs[:len(fsegs)-1], fsegs[len(fsegs)-1]
						if (fbase == ms[len(ms)-1]+".py" && segsSuffix(fdir, ms[:len(ms)-1])) ||
							(fbase == "__init__.py" && segsSuffix(fdir, ms)) {
							found = f
							break
						}
					}
					if found != "" {
						add(li, "import "+mod, "internal", found)
					} else {
						add(li, "import "+mod, "external", "not-in-tree")
					}
				}
			}
		}
	}
	return out
}

// ---------- test-file pairing ----------

// isTestFile applies the test naming conventions (plan §Design.4):
// *Test.java, *_test.go, *.test.* / *.spec.*, test_*.py.
func isTestFile(path string) bool {
	base := baseOf(path)
	switch {
	case strings.HasSuffix(base, "Test.java"):
		return true
	case strings.HasSuffix(base, "_test.go"):
		return true
	case strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"):
		return true
	}
	ext := filepath.Ext(base)
	if ext == "" {
		return false
	}
	rest := strings.TrimSuffix(base, ext)
	return strings.HasSuffix(rest, ".test") || strings.HasSuffix(rest, ".spec")
}

// testPairs finds indexed test files sharing identifiers with the hit (its
// extracted identifiers plus the hit file's name stem — how bar.go finds
// bar_test.go and X.java finds XTest.java).
func testPairs(db *DB, bf *bundleFiles, c Chunk) []struct {
	Path   string
	Shared []string
} {
	var hitIdents []string
	seen := map[string]bool{}
	addIdent := func(s string) {
		if !seen[s] && !identStopword[s] {
			seen[s] = true
			hitIdents = append(hitIdents, s)
		}
	}
	if stem := strings.TrimSuffix(baseOf(c.Path), filepath.Ext(baseOf(c.Path))); len(stem) >= 3 {
		addIdent(stem)
	}
	for _, id := range extractCandidates(c.Text) {
		if len(id) >= 4 {
			addIdent(id)
		}
	}
	var out []struct {
		Path   string
		Shared []string
	}
	for _, p := range bf.names {
		if !isTestFile(p) || p == c.Path {
			continue
		}
		var shared []string
		for _, id := range hitIdents {
			ok := false
			for _, ci := range bf.chunks[p] {
				if strings.Contains(db.Chunks[ci].Text, id) {
					ok = true
					break
				}
			}
			if ok {
				shared = append(shared, id)
			}
		}
		if len(shared) == 0 {
			continue
		}
		if len(shared) > bundleTestSharedMax {
			shared = shared[:bundleTestSharedMax]
		}
		out = append(out, struct {
			Path   string
			Shared []string
		}{p, shared})
		if len(out) >= bundleTestMax {
			break
		}
	}
	return out
}

// ---------- bundle rendering ----------

// bundleChunk renders ONE hit's consolidated read pack (the four components,
// each capped with an explicit truncation marker).
func bundleChunk(db *DB, bf *bundleFiles, c Chunk) string {
	var b strings.Builder
	fmt.Fprintf(&b, "== %s:%d-%d [%s] ==\n\n", c.Path, c.Start, c.End, c.Kind)

	// 1) package neighborhood
	hitDir := dirOf(c.Path)
	var sibs []string
	for _, p := range bf.names {
		if dirOf(p) == hitDir {
			sibs = append(sibs, p)
		}
	}
	sort.Strings(sibs)
	shown := sibs
	if len(shown) > bundleNeighborhood {
		shown = shown[:bundleNeighborhood]
	}
	b.WriteString("neighborhood (" + strconv.Itoa(len(sibs)) + " file(s) in " + hitDir + "):\n")
	for _, p := range shown {
		marker := "  "
		if p == c.Path {
			marker = "* "
		}
		fmt.Fprintf(&b, "%s%s  %s\n", marker, p, fileSummary(db, bf, p))
	}
	if len(sibs) > bundleNeighborhood {
		fmt.Fprintf(&b, "  …truncated (showing %d of %d files)\n", bundleNeighborhood, len(sibs))
	}
	b.WriteString("\n")

	// 2) propagation (stable-fragment search of the hit's literals/identifiers)
	cands := extractCandidates(c.Text)
	b.WriteString("propagation (literals/identifiers searched tree-wide):\n")
	if len(cands) == 0 {
		b.WriteString("  (no candidates)\n")
	}
	for _, cand := range cands {
		frags := stableFragments(cand)
		label := "  candidate " + strconv.Quote(cand)
		if len(frags) == 0 {
			fmt.Fprintf(&b, "%s — too short to propagate\n", label)
			continue
		}
		fmt.Fprintf(&b, "%s:\n", label)
		hitAny := false
		for _, frag := range frags {
			files := fragmentSearch(db, frag)
			if len(files) == 0 {
				continue
			}
			hitAny = true
			fmt.Fprintf(&b, "    fragment %q — %d file(s):\n", frag, len(files))
			for _, f := range files {
				fmt.Fprintf(&b, "      %s (%d)\n", f.Path, f.Count)
			}
		}
		if !hitAny {
			fmt.Fprintf(&b, "    — no occurrences anywhere (tried fragment(s): %s)\n", strings.Join(frags, ", "))
		}
	}
	b.WriteString("\n")

	// 3) import verdicts
	imps := importVerdicts(db, bf, c)
	b.WriteString("imports: " + strconv.Itoa(len(imps)) + " statement(s)\n")
	for _, iv := range imps {
		fmt.Fprintf(&b, "  L%d  %s  ->  %s", iv.Line, iv.Stmt, iv.Verdict)
		if iv.Detail != "" {
			fmt.Fprintf(&b, "  (%s)", iv.Detail)
		}
		b.WriteString("\n")
	}
	if len(imps) == 0 {
		b.WriteString("  (none detected, or no supported import syntax in this file)\n")
	}
	b.WriteString("\n")

	// 4) test pairing
	pairs := testPairs(db, bf, c)
	b.WriteString("tests: " + strconv.Itoa(len(pairs)) + " paired test file(s)\n")
	for _, p := range pairs {
		fmt.Fprintf(&b, "  %s — shared: %s\n", p.Path, strings.Join(p.Shared, ", "))
	}
	if len(pairs) == 0 {
		b.WriteString("  (none found sharing identifiers with the hit)\n")
	}
	return b.String()
}

// bundleForQuery searches (hybrid, k hits) and renders each hit's pack.
func bundleForQuery(db *DB, q string, k int) string {
	if k <= 0 {
		k = bundleDefaultHits
	}
	if k > bundleMaxHits {
		k = bundleMaxHits
	}
	res, err := db.Search(q, k, "", "", 0, false, ModeHybrid)
	if err != nil {
		// Backend mismatch (e.g. remote embedder configured at build time):
		// degrade to keyword-only so the bundle is still useful lexically.
		res, err = db.Search(q, k, "", "", 0, false, ModeKeyword)
		if err != nil {
			return "bundle: search failed: " + err.Error() + "\n"
		}
	}
	bf := newBundleFiles(db)
	var b strings.Builder
	fmt.Fprintf(&b, "bundle for query %q: %d hit(s)\n\n", q, len(res))
	if len(res) == 0 {
		b.WriteString("(no hits — try kb_terms to check whether the identifier exists at all)\n")
		return b.String()
	}
	for i, r := range res {
		fmt.Fprintf(&b, "-- hit %d/%d (score %.4f) --\n", i+1, len(res), r.Score)
		b.WriteString(bundleChunk(db, bf, r.C))
		b.WriteString("\n")
	}
	return b.String()
}

// parseTarget splits "file:line" (line optional: the last colon before digits).
func parseTarget(target string) (file string, line int) {
	i := strings.LastIndexByte(target, ':')
	if i > 0 {
		if n, err := strconv.Atoi(target[i+1:]); err == nil && n > 0 {
			return target[:i], n
		}
	}
	return target, 0
}

// findChunkForTarget locates the chunk for a file:line reference: exact path
// first, then suffix match (either direction), then basename; among candidates,
// the chunk whose [Start,End] contains the line (else the nearest).
func findChunkForTarget(db *DB, file string, line int) (*Chunk, bool) {
	type cand struct {
		idx  int
		dist int
	}
	var cands []cand
	add := func(i int) {
		c := &db.Chunks[i]
		d := 0
		if line > 0 {
			if c.Start <= line && line <= c.End {
				d = 0
			} else if line < c.Start {
				d = c.Start - line
			} else {
				d = line - c.End
			}
		}
		cands = append(cands, cand{i, d})
	}
	for i := range db.Chunks {
		if db.Chunks[i].Path == file {
			add(i)
		}
	}
	if len(cands) == 0 {
		for i := range db.Chunks {
			p := db.Chunks[i].Path
			if strings.HasSuffix(p, "/"+file) || strings.HasSuffix(file, "/"+p) ||
				baseOf(p) == file || baseOf(file) == baseOf(p) {
				add(i)
			}
		}
	}
	if len(cands) == 0 {
		return nil, false
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if c.dist < best.dist {
			best = c
		}
	}
	return &db.Chunks[best.idx], true
}

// bundleForTarget renders the pack for a known file:line location (the first
// form of the feature — no query involved).
func bundleForTarget(db *DB, target string) (string, bool) {
	file, line := parseTarget(target)
	c, ok := findChunkForTarget(db, file, line)
	if !ok {
		return "bundle: no indexed file matches " + file + " — use search_codebase or list_files first", false
	}
	bf := newBundleFiles(db)
	var b strings.Builder
	if line > 0 {
		fmt.Fprintf(&b, "bundle for location %s:%d\n\n", c.Path, line)
	} else {
		fmt.Fprintf(&b, "bundle for location %s\n\n", c.Path)
	}
	b.WriteString(bundleChunk(db, bf, *c))
	return b.String(), true
}

// ---------- message board (see plans/message-board-plan.md) ----------
//
// A signed, append-only, multi-thread collaboration board for AI agents. It is
// agent-managed (no human in the loop), persists in its own binary file (board.bin,
// magic MBD1) so `kbtool build` never wipes it, and is continuously merged into the
// in-memory KB index (vector + BM25) for cross-thread semantic discovery.
//
// Security model (signup-bound identity; plans/new-message-board-initilization.md):
//   - board_signup binds a NAME to a fresh random 32-byte ed25519 seed. The pubkey
//     is stored in the board; the seed is returned once and NEVER stored by kbtool
//     (the agent keeps it on its own disk; it can never be retrieved — losing it
//     means a new signup under a new name). Names are permanent.
//   - Every message is signed (ed25519) over its canonical field string and
//     attributed to the name bound to the signer's key: the seed IS the identity,
//     and an agent cannot post as anyone else.
//   - Every board endpoint requires the seed; unregistered seeds are steered to
//     board_signup. The welcome thread (signed kind=hello intro) is the first step
//     after signup, before browsing.
//   - Append-only: the only content mutation is board_post (append). No edit/delete.

var boardThreadIDRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
var boardAgentIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

var boardKinds = map[string]bool{
	"hello":   true, // welcome-thread introduction
	"info":    true, // default: general message
	"task":    true, // delegate work (research, etc.)
	"result":  true, // report back (link via Task = "<thread>#<seq>")
	"feature": true, // capture a feature idea
}

type BoardMsg struct {
	ID     int64    // global monotonic id (header counter)
	Thread string   // thread id
	Seq    int      // per-thread 0-based sequence (append position)
	Agent  string   // claimed author id
	Pub    string   // hex ed25519 pubkey of the actual signer (derived from the seed)
	Sig    string   // hex ed25519 signature over canonicalMsg(...)
	Text   string   // immutable message text
	At     int64    // unix seconds
	Kind   string   // hello|info|task|result|feature
	Refs   []string // cross-referenced thread ids
	Task   string   // e.g. "research-x#2" — the task a result answers
}

type BoardThread struct {
	ID        string
	CreatedAt int64
	CreatedBy string
	Msgs      []BoardMsg // serial, append-only
}

type BoardAgent struct {
	ID        string
	Pub       string // registered hex ed25519 pubkey (identity binding)
	FirstSeen int64
	LastSeen  int64 // confirmation timestamp (recency)
	Posts     int64
}

type Board struct {
	NextID  int64
	Order   []string // thread creation order
	Threads map[string]*BoardThread
	Agents  map[string]*BoardAgent
}

// boardPath locates the board file: KBTOOL_BOARD override, else next to the DB file.
func boardPath() string {
	if b := os.Getenv("KBTOOL_BOARD"); b != "" {
		return b
	}
	return filepath.Join(filepath.Dir(dbPath()), "board.bin")
}

// boardTTL is the activity window for ACTIVE/STALE (KBTOOL_BOARD_TTL seconds).
func boardTTL() time.Duration {
	if s := os.Getenv("KBTOOL_BOARD_TTL"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defBoardTTL * time.Second
}

// boardLock serializes read-modify-write board operations across processes using an
// exclusive flock on a STABLE lock file (the board file itself is atomically replaced
// via tmp+rename, so locking it directly would race on inodes — see plan §5).
func boardLock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		lf.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
		lf.Close()
	}, nil
}

func newBoard() *Board {
	b := &Board{
		NextID:  0,
		Order:   []string{},
		Threads: map[string]*BoardThread{},
		Agents:  map[string]*BoardAgent{},
	}
	ensureWelcome(b)
	return b
}

// ensureWelcome guarantees the welcome thread exists and is FIRST (plan §2.7).
func ensureWelcome(b *Board) {
	if _, ok := b.Threads[boardWelcome]; ok {
		return
	}
	now := time.Now().Unix()
	b.Threads[boardWelcome] = &BoardThread{ID: boardWelcome, CreatedAt: now, CreatedBy: "system"}
	b.Order = append([]string{boardWelcome}, b.Order...)
}

func (b *Board) thread(id string) *BoardThread { return b.Threads[id] }

func (b *Board) sortedAgents() []*BoardAgent {
	agents := make([]*BoardAgent, 0, len(b.Agents))
	for _, a := range b.Agents {
		agents = append(agents, a)
	}
	sort.Slice(agents, func(i, j int) bool {
		if agents[i].LastSeen != agents[j].LastSeen {
			return agents[i].LastSeen > agents[j].LastSeen
		}
		return agents[i].ID < agents[j].ID
	})
	return agents
}

func (b *Board) msgCount() int {
	total := 0
	for _, t := range b.Threads {
		total += len(t.Msgs)
	}
	return total
}

// boardAllMsgs returns every message in (thread order, seq order) — used for index
// merging and file (de)serialization iteration.
func (b *Board) allMsgs() []BoardMsg {
	var out []BoardMsg
	for _, id := range b.Order {
		t := b.Threads[id]
		if t != nil {
			out = append(out, t.Msgs...)
		}
	}
	return out
}

// canonicalMsg is the exact string a signature covers (NUL-joined so fields cannot be
// re-split; refs are sorted for determinism) — plan §2.13.
func canonicalMsg(m BoardMsg) string {
	refs := append([]string{}, m.Refs...)
	sort.Strings(refs)
	return strings.Join([]string{
		m.Agent, m.Thread, strconv.Itoa(m.Seq), m.Kind, m.Task, strings.Join(refs, ","), m.Text,
	}, "\x00")
}

// cryptoDeriveSeed validates a hex seed (must decode to exactly ed25519.SeedSize bytes) and
// derives the deterministic keypair. The seed itself is never retained.
func cryptoDeriveSeed(seedHex string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	seedHex = strings.TrimSpace(seedHex)
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, nil, fmt.Errorf("seed is not valid hex: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("seed must be %d bytes (%d hex chars), got %d bytes", ed25519.SeedSize, ed25519.SeedSize*2, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey), nil
}

func cryptoSignBoard(priv ed25519.PrivateKey, canonical string) string {
	return hex.EncodeToString(ed25519.Sign(priv, []byte(canonical)))
}

// cryptoVerifyBoardMsg reports a message's verification status against the board's identity
// registry (plan §2.14): verified | impersonation | bad-signature | unknown-agent.
func cryptoVerifyBoardMsg(b *Board, m BoardMsg) string {
	agent, ok := b.Agents[m.Agent]
	if !ok {
		return "unknown-agent"
	}
	if agent.Pub != m.Pub {
		return "impersonation" // signed with a different key than the author's registered one
	}
	pub, err := hex.DecodeString(m.Pub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "bad-signature"
	}
	sig, err := hex.DecodeString(m.Sig)
	if err != nil {
		return "bad-signature"
	}
	if !ed25519.Verify(pub, []byte(canonicalMsg(m)), sig) {
		return "bad-signature"
	}
	return "verified"
}

// agentByPub finds the identity registered for a pubkey (board_signup bound
// name<->pubkey permanently; plans/new-message-board-initilization.md §2.3).
func agentByPub(b *Board, pub string) *BoardAgent {
	for _, a := range b.Agents {
		if a.Pub == pub {
			return a
		}
	}
	return nil
}

// boardChunk converts a board message into an indexable KB chunk (plan §2.4):
// Path = board/<thread>/msg-<seq>, Kind = "board".
func boardChunk(m BoardMsg) Chunk {
	return Chunk{
		Path:  "board/" + m.Thread + "/msg-" + strconv.Itoa(m.Seq),
		Kind:  "board",
		Start: 1, End: 1,
		Text: m.Text,
	}
}

// fmtAgo renders a unix timestamp as a short human offset ("3s ago", "4m ago", ...).
func fmtAgo(ts int64) string {
	d := time.Since(time.Unix(ts, 0))
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// boardSave writes the board to a temp file and atomically renames it over the
// target (plan §5: readers never observe a partial file).
func boardSave(path string, b *Board) error {
	data := boardMarshal(b)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// boardMarshal serializes the board to the MBD1 binary format (the body of boardSave,
// factored out so the identical bytes can be packed into the at-rest encrypted bundle —
// see plans/encrypt-at-rest-db-and-message-board-plan.md).
func boardMarshal(b *Board) []byte {
	var buf bytes.Buffer
	buf.WriteString(boardMagic)
	writeU64b(&buf, uint64(b.NextID))
	writeU32(&buf, uint32(len(b.Order)))
	for _, id := range b.Order {
		t := b.Threads[id]
		if t == nil {
			continue
		}
		writeStr(&buf, t.ID)
		writeU64b(&buf, uint64(t.CreatedAt))
		writeStr(&buf, t.CreatedBy)
		writeU32(&buf, uint32(len(t.Msgs)))
		for _, m := range t.Msgs {
			writeU64b(&buf, uint64(m.ID))
			writeU32(&buf, uint32(m.Seq))
			writeStr(&buf, m.Agent)
			writeStr(&buf, m.Pub)
			writeStr(&buf, m.Sig)
			writeStr(&buf, m.Text)
			writeU64b(&buf, uint64(m.At))
			writeStr(&buf, m.Kind)
			writeU32(&buf, uint32(len(m.Refs)))
			for _, r := range m.Refs {
				writeStr(&buf, r)
			}
			writeStr(&buf, m.Task)
		}
	}
	// agents in a deterministic order (by ID) for stable files
	agentIDs := make([]string, 0, len(b.Agents))
	for id := range b.Agents {
		agentIDs = append(agentIDs, id)
	}
	sort.Strings(agentIDs)
	writeU32(&buf, uint32(len(agentIDs)))
	for _, id := range agentIDs {
		a := b.Agents[id]
		writeStr(&buf, a.ID)
		writeStr(&buf, a.Pub)
		writeU64b(&buf, uint64(a.FirstSeen))
		writeU64b(&buf, uint64(a.LastSeen))
		writeU64b(&buf, uint64(a.Posts))
	}
	return buf.Bytes()
}

// ensureBoardReady creates the board (welcome thread included) when it is absent —
// called at daemon start when message_board=true (plans/new-message-board-initilization.md
// §2.1). It works through the at-rest store so the board is created inside the
// encrypted bundle (when enc) or as a plain board.bin (when plain). Idempotent: an
// existing board is left untouched; the double-check under the lock makes racing
// daemons safe.
func ensureBoardReady(st *kbStore) error {
	if st.boardExists() {
		return nil
	}
	unlock, err := st.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if st.boardExists() { // a racing process created it while we waited for the lock
		return nil
	}
	return st.saveBoard(newBoard())
}

func readU64b(r io.Reader) (uint64, error) {
	var v uint64
	err := binary.Read(r, binary.LittleEndian, &v)
	return v, err
}

func writeU64b(b *bytes.Buffer, v uint64) { binary.Write(b, binary.LittleEndian, v) }

func loadBoardFile(path string) (*Board, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readBoard(f)
}

// readBoard deserializes a board from the given reader (the body of loadBoardFile,
// factored out so the MBD1 byte stream inside the at-rest encrypted bundle can be
// decoded without a file — see plans/encrypt-at-rest-db-and-message-board-plan.md).
func readBoard(f io.Reader) (*Board, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(f, head); err != nil {
		return nil, err
	}
	if string(head) != boardMagic {
		return nil, fmt.Errorf("bad board magic %q (not a message board file)", head)
	}
	nextID, err := readU64b(f)
	if err != nil {
		return nil, err
	}
	nThreads, err := readU32(f)
	if err != nil {
		return nil, err
	}
	b := &Board{
		NextID:  int64(nextID),
		Order:   make([]string, 0, nThreads),
		Threads: map[string]*BoardThread{},
		Agents:  map[string]*BoardAgent{},
	}
	for i := uint32(0); i < nThreads; i++ {
		id, err := readStr(f)
		if err != nil {
			return nil, err
		}
		createdAt, err := readU64b(f)
		if err != nil {
			return nil, err
		}
		createdBy, err := readStr(f)
		if err != nil {
			return nil, err
		}
		nMsgs, err := readU32(f)
		if err != nil {
			return nil, err
		}
		t := &BoardThread{ID: id, CreatedAt: int64(createdAt), CreatedBy: createdBy, Msgs: make([]BoardMsg, 0, nMsgs)}
		for j := uint32(0); j < nMsgs; j++ {
			var m BoardMsg
			idv, err := readU64b(f)
			if err != nil {
				return nil, err
			}
			m.ID = int64(idv)
			seq, err := readU32(f)
			if err != nil {
				return nil, err
			}
			m.Seq = int(seq)
			m.Thread = id // stored implicitly per-thread in the file; restore for canonical/signature
			if m.Agent, err = readStr(f); err != nil {
				return nil, err
			}
			if m.Pub, err = readStr(f); err != nil {
				return nil, err
			}
			if m.Sig, err = readStr(f); err != nil {
				return nil, err
			}
			if m.Text, err = readStr(f); err != nil {
				return nil, err
			}
			at, err := readU64b(f)
			if err != nil {
				return nil, err
			}
			m.At = int64(at)
			if m.Kind, err = readStr(f); err != nil {
				return nil, err
			}
			nRefs, err := readU32(f)
			if err != nil {
				return nil, err
			}
			for k := uint32(0); k < nRefs; k++ {
				ref, err := readStr(f)
				if err != nil {
					return nil, err
				}
				m.Refs = append(m.Refs, ref)
			}
			if m.Task, err = readStr(f); err != nil {
				return nil, err
			}
			t.Msgs = append(t.Msgs, m)
		}
		b.Order = append(b.Order, id)
		b.Threads[id] = t
	}
	nAgents, err := readU32(f)
	if err != nil {
		return nil, err
	}
	for i := uint32(0); i < nAgents; i++ {
		id, err := readStr(f)
		if err != nil {
			return nil, err
		}
		pub, err := readStr(f)
		if err != nil {
			return nil, err
		}
		first, err := readU64b(f)
		if err != nil {
			return nil, err
		}
		last, err := readU64b(f)
		if err != nil {
			return nil, err
		}
		posts, err := readU64b(f)
		if err != nil {
			return nil, err
		}
		b.Agents[id] = &BoardAgent{ID: id, Pub: pub, FirstSeen: int64(first), LastSeen: int64(last), Posts: int64(posts)}
	}
	ensureWelcome(b)
	return b, nil
}

// boardSignupTeaching is the steering message for missing/bad/unregistered seeds:
// it points the agent at board_signup and explains seed custody
// (plans/new-message-board-initilization.md §2.5).
const boardSignupTeaching = `this board requires a signed-up identity, and this seed is not one.
  1. Sign up: call board_signup with a name — it returns your private 64-hex seed.
     Names are permanent: once a name is taken it can never be reused, so if your
     previous seed is lost, choose a NEW name.
  2. STORE THE SEED ON DISK in your own workspace with a shell command, e.g.:
       printf '%s' '<seed>' > .kbtool-seed
     Keep it PRIVATE: never post it, share it, or write it into the board. kbtool
     never stores the seed and it can NEVER be retrieved — lose it and your identity
     is gone (a new board_signup under a new name is the only remedy).
  3. Use the SAME seed in every board call (board_post, board_read, board_threads,
     board_search, board_confirm) — it identifies you. After signing up, introduce
     yourself in the 'welcome' thread (board_post kind=hello) BEFORE browsing.`

// ---------- MCP tool schemas ----------

type mcpTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

func toolSchemas() []mcpTool {
	return []mcpTool{
		{
			Name: "search_codebase",
			Description: "Hybrid search (BM25 keyword + dense vector, rank-fused) over indexed code and documentation. " +
				"Strong for exact identifiers AND conceptual queries. Returns ranked chunks with file path, line range, and text.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"q":    map[string]any{"type": "string", "description": "Natural-language, conceptual, or exact-identifier query."},
					"k":    map[string]any{"type": "integer", "description": "Max results (default 8)."},
					"path": map[string]any{"type": "string", "description": "Filter by path substring."},
					"kind": map[string]any{"type": "string", "description": "Filter by kind: code|doc|text|commit|diff."},
					"min":  map[string]any{"type": "number", "description": "Minimum dense-vector score, 0 = off (default 0). Gates the vector channel only, never keyword."},
					"full": map[string]any{"type": "boolean", "description": "Return full chunk text instead of a snippet (default false)."},
					"mode": map[string]any{"type": "string", "description": "hybrid (default) = BM25+vector rank fusion; vector = dense only; keyword = BM25 only; weighted = weighted fusion with 'weights'."},
					"weights": map[string]any{
						"type":        "object",
						"description": "Fusion weights for mode=weighted: {\"keyword\": 0.6, \"vector\": 0.4} (defaults).",
						"properties": map[string]any{
							"keyword": map[string]any{"type": "number"},
							"vector":  map[string]any{"type": "number"},
						},
					},
				},
				"required": []string{"q"},
			},
		},
		{
			Name: "get_chunk",
			Description: "Fetch one chunk by 1-based chunk index (as reported by search_codebase). " +
				"Use it to read the full context of a hit.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"index":  map[string]any{"type": "integer", "description": "0-based chunk index."},
					"before": map[string]any{"type": "integer", "description": "Chunks to include before (default 0)."},
					"after":  map[string]any{"type": "integer", "description": "Chunks to include after (default 0)."},
				},
				"required": []string{"index"},
			},
		},
		{
			Name:        "list_files",
			Description: "List indexed files (path + kind + chunk count). Optionally filter by path substring.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":  map[string]any{"type": "string", "description": "Filter by path substring."},
					"kind":  map[string]any{"type": "string", "description": "Filter by kind: code|doc|text|commit|diff."},
					"limit": map[string]any{"type": "integer", "description": "Max files (default 200)."},
				},
			},
		},
		{
			Name: "kb_terms",
			Description: "COMPLETE occurrence census of one exact identifier or string across ALL indexed sources: per-file " +
				"occurrence counts plus representative lines. Use it for presence/ABSENCE checks — 'X does not exist in the " +
				"tree' is a citable result, not an inference: a zero-hit census is distinct from 'present but didn't rank' " +
				"in a search. Required: term. Optional: k (max files shown, default 20), json (machine-readable result).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"term": map[string]any{"type": "string", "description": "Exact identifier or string to census (case-sensitive substring match)."},
					"k":    map[string]any{"type": "integer", "description": "Max files to show (default 20; the true total is always reported)."},
					"json": map[string]any{"type": "boolean", "description": "Return the machine-readable JSON result instead of text."},
				},
				"required": []string{"term"},
			},
		},
		{
			Name: "kb_bundle",
			Description: "Context-bundle expansion: for a known location (target 'file:line', as reported by search_codebase) " +
				"or the top hits of a query (q), emit one consolidated read pack per hit following the code's own written " +
				"pointers: package neighborhood (sibling files + one-line summary), tree-wide literal/identifier propagation " +
				"(stable-fragment match, so constructed strings surface), import verdicts (internal / external not-in-tree / " +
				"unresolved — never a wrong verdict), and paired test files. Provide target OR q. Optional: k (hits to bundle, " +
				"default 3).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{"type": "string", "description": "Location to expand: 'file:line' (file path as from search_codebase, 1-based line)."},
					"q":      map[string]any{"type": "string", "description": "Query text: expand the top hits of this search instead of a fixed location."},
					"k":      map[string]any{"type": "integer", "description": "Hits to bundle when q is used (default 3, max 8)."},
				},
			},
		},
		{
			Name:        "kb_status",
			Description: "Report knowledge-base stats: sources, chunk count, file count, embedding dim/backend, and keyword-index presence/size.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			Name: "git_blame",
			Description: "Run `git blame` on a file in a live git repo (post-build state). " +
				"Use to see who/when each line of the current code came from.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"file":  map[string]any{"type": "string", "description": "Labeled file path (label/rel, as from search_codebase) or a repo-relative path."},
					"start": map[string]any{"type": "integer", "description": "Optional first line to blame."},
					"end":   map[string]any{"type": "integer", "description": "Optional last line to blame."},
					"repo":  map[string]any{"type": "string", "description": "Source label to pick the repo (inferred from file if labeled)."},
					"limit": map[string]any{"type": "integer", "description": "Max blame lines to return (default 200)."},
				},
				"required": []string{"file"},
			},
		},
		{
			Name: "git_log",
			Description: "Run `git log` in a live git repo (post-build state). " +
				"Optionally scoped to a path, author, or commit count.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"repo":   map[string]any{"type": "string", "description": "Source label or repo path (defaults to the single source if unambiguous)."},
					"path":   map[string]any{"type": "string", "description": "Optional pathspec to scope the log."},
					"n":      map[string]any{"type": "integer", "description": "Max commits (default 20, cap 200)."},
					"author": map[string]any{"type": "string", "description": "Optional author substring filter."},
				},
			},
		},
		// ---------- message board (agent collaboration; see plans/message-board-plan.md +
		// plans/new-message-board-initilization.md) ----------
		{
			Name: "board_signup",
			Description: "Sign up on the message board: choose your name and receive a private 64-hex seed. " +
				"The seed is YOUR IDENTITY: every other board call takes it, and kbtool never stores it — it can NEVER be " +
				"retrieved, so store it on disk in your own workspace NOW (e.g. shell: printf '%s' '<seed>' > .kbtool-seed) " +
				"and keep it private (never post or share it). Names are permanent: once taken, a name can never be reused. " +
				"After signing up, introduce yourself in the 'welcome' thread (board_post kind=hello) BEFORE browsing. " +
				"Required: name.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string", "description": "Your identity name (lowercase alphanumerics, optional '-'/'_', max 64 chars, e.g. \"alice\"). Permanent once registered."},
				},
				"required": []string{"name"},
			},
		},
		{
			Name: "board_whoami",
			Description: "Resolve a seed to its board identity: returns the signup name bound to the public key derived " +
				"from your seed. Use it to verify that the seed you stored on disk still corresponds to the identity you " +
				"expect. If the seed is not registered, you must board_signup again (a new seed means a new name). " +
				"Required: seed.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"seed": map[string]any{"type": "string", "description": "Your private 64-hex-char seed (from board_signup, stored on your own disk)."},
				},
				"required": []string{"seed"},
			},
		},
		{
			Name: "board_sign",
			Description: "The sign API: sign arbitrary text with your seed (ed25519). Returns the public key derived from " +
				"your seed, the exact canonical string signed, and the hex signature. Use it to validate your key material or to " +
				"sign out-of-band text; board_post signs messages internally the same way.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"seed": map[string]any{"type": "string", "description": "Your private 64-hex-char seed."},
					"text": map[string]any{"type": "string", "description": "Text to sign."},
				},
				"required": []string{"seed", "text"},
			},
		},
		{
			Name: "board_post",
			Description: "Post a SIGNED message to a thread (append-only: history can never be altered). Your identity comes " +
				"from your seed (board_signup): the post is attributed to the name you signed up with, and you cannot post as " +
				"anyone else. Introduce yourself in the 'welcome' thread (kind=hello) before browsing. Posting to a new thread id " +
				"creates the thread (topic ids: lowercase alphanumerics + hyphens). " +
				"Required: thread, text, seed. Optional: kind (hello|info|task|result|feature), refs (thread ids this relates to), " +
				"task ('<thread>#<seq>' of the task a result answers, e.g. 'research-x#2').",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"thread": map[string]any{"type": "string", "description": "Thread id, e.g. 'welcome' or a new topical id like 'research-auth'."},
					"text":   map[string]any{"type": "string", "description": "Message text (max 256 KiB)."},
					"seed":   map[string]any{"type": "string", "description": "Your private 64-hex-char seed — it identifies you (never stored by kbtool)."},
					"kind":   map[string]any{"type": "string", "enum": []string{"hello", "info", "task", "result", "feature"}, "description": "Message kind (default info). task = delegate work; result = report back; feature = capture a feature."},
					"refs":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Thread ids this message cross-references."},
					"task":   map[string]any{"type": "string", "description": "For kind=result: the '<thread>#<seq>' of the task being answered."},
				},
				"required": []string{"thread", "text", "seed"},
			},
		},
		{
			Name: "board_read",
			Description: "Read a thread's messages in serial order (oldest first). Each message shows author, kind, task/refs, " +
				"timestamp and VERIFICATION status: 'verified' = signature matches the author's registered key (trust it); " +
				"'impersonation'/'bad-signature' = DO NOT TRUST (wrong key or invalid signature). When expecting a research " +
				"report, confirm the reporting message's author is the agent you asked AND its status is verified. " +
				"Required: thread, seed (every board call is authenticated). Optional after/limit to page.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"thread": map[string]any{"type": "string", "description": "Thread id to read."},
					"after":  map[string]any{"type": "integer", "description": "First message seq to show (default 0)."},
					"limit":  map[string]any{"type": "integer", "description": "Max messages (default 50, cap 500)."},
					"seed":   map[string]any{"type": "string", "description": "Your private 64-hex-char seed — it identifies you (board_signup)."},
				},
				"required": []string{"thread", "seed"},
			},
		},
		{
			Name: "board_threads",
			Description: "List all board threads (id, message count, creator, participants, last activity) and the agent " +
				"roster with last-seen times and ACTIVE/STALE status. Use it to find related (cross-referenced) threads, " +
				"see who is around, or check whether a collaborator dropped off. Required: seed (your board_signup seed).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"seed": map[string]any{"type": "string", "description": "Your private 64-hex-char seed — it identifies you (board_signup)."},
				},
				"required": []string{"seed"},
			},
		},
		{
			Name: "board_search",
			Description: "Semantic search (BM25 keyword + vector, rank-fused) across ALL board messages — discovers relevant " +
				"conversation in OTHER threads even while you work in one. Returns matching messages with thread, author, and " +
				"verification status. Every posted message is indexed into the KB continuously. " +
				"Required: q, seed (your board_signup seed).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"q":      map[string]any{"type": "string", "description": "Query text (natural language or keywords)."},
					"k":      map[string]any{"type": "integer", "description": "Max results (default 8)."},
					"thread": map[string]any{"type": "string", "description": "Optional: restrict to one thread."},
					"seed":   map[string]any{"type": "string", "description": "Your private 64-hex-char seed — it identifies you (board_signup)."},
				},
				"required": []string{"q", "seed"},
			},
		},
		{
			Name: "board_confirm",
			Description: "Confirmations endpoint: assert you are active NOW (updates your last-seen timestamp) and returns the " +
				"full roster with ACTIVE/STALE status (TTL default 120s; KBTOOL_BOARD_TTL). Last-seen also updates on every " +
				"board interaction. Use before delegating a task, or when waiting for a report: a STALE author is likely offline " +
				"and may never report back — delegate to an ACTIVE agent instead (note the swap in the thread). " +
				"Required: seed (your board_signup seed).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"seed": map[string]any{"type": "string", "description": "Your private 64-hex-char seed — it identifies you (board_signup)."},
				},
				"required": []string{"seed"},
			},
		},
	}
}

// qwenTools renders the tools as an OpenAI/Qwen function-calling "tools" array so the
// exact same schemas can be dropped into a chat/completions request.
func qwenTools(tools []mcpTool) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  t.InputSchema,
			},
		})
	}
	return out
}

// ---------- path trust model (plans/constrain-file-ops-to-trusted-paths-plan.md) ----------
//
// The git MCP tools take attacker-influenced paths (git_blame's `file`;
// git_log's `repo`/`path`). Before this model, `git_log`'s repo argument fell
// back to ANY existing directory on the machine (its "direct path" case), and
// neither tool checked its path arguments against a trusted set — an agent
// could read the commit history of any git repo on disk.
//
// Decision table (plan decisions 2-6):
//
//	trusted   = -live repo roots (auto) + indexed git source roots + trusted_paths
//	forbidden = forbidden_paths — ALWAYS wins over trusted (can forbid a
//	            default-trusted -live repo, or a subpath of any trusted path)
//	default   = DENY
//
// Containment is verified twice: lexically, and on the symlink-resolved
// (real) locations, so a link inside a trusted root cannot reach a forbidden
// or untrusted location. Fail closed at every step.
//
// The decision is op-parameterized: today only OpRead is granted (the git
// tools are read-only). A future capability (OpWrite, OpExec, …) is declared
// as a TrustOp and granted in Allows() when a tool needs it — until then it
// is denied by default.

// TrustOp is a filesystem capability the trust model can grant or deny.
type TrustOp string

// OpRead is the only capability granted today: reading file content / git
// history under a trusted path (git_blame, git_log).
const OpRead TrustOp = "read"

// TrustPolicy is the per-process path-trust decision table. Roots are stored
// cleaned+absolute (lexical) and re-checked against their real locations.
type TrustPolicy struct {
	Trusted   []string // trusted roots: -live + git sources + trusted_paths
	Forbidden []string // forbidden roots: forbidden_paths — always win
}

// NewTrustPolicy normalizes the root sets (absolutize with error tolerance,
// clean, de-dupe, drop empties) and stores them. An empty trusted set yields
// a deny-all policy (fail closed).
func NewTrustPolicy(trustedRoots, forbiddenRoots []string) *TrustPolicy {
	clean := func(ps []string) []string {
		seen := map[string]bool{}
		var out []string
		for _, p := range ps {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if a, err := filepath.Abs(p); err == nil {
				p = a
			}
			p = filepath.Clean(p)
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		return out
	}
	return &TrustPolicy{Trusted: clean(trustedRoots), Forbidden: clean(forbiddenRoots)}
}

// AllowRead reports whether path may be read under this policy — the git
// tools' surface (decision 5: the read-grant interface of today).
func (tp *TrustPolicy) AllowRead(path string) bool { return tp.Allows(OpRead, path) }

// Allows reports whether path may be accessed for op. Fail-closed order:
//
//  1. op other than OpRead            → deny (a future op must be granted
//     here, deliberately — until then it is denied)
//  2. relative path                   → deny (callers always pass absolute)
//  3. path inside a forbidden root    → deny (precedence, lexical)
//  4. no trusted root contains path   → deny (default deny)
//  5. real path escapes the trusted   → deny (a symlink out of the trusted set)
//     root's real location
//  6. real path inside any forbidden  → deny (a symlink into a forbidden set)
//     root's real location
func (tp *TrustPolicy) Allows(op TrustOp, path string) bool {
	switch op {
	case OpRead:
		// granted below
	default:
		return false // unknown / future ops are denied until granted here
	}
	p := filepath.Clean(path)
	if !filepath.IsAbs(p) {
		return false
	}
	if withinAny(p, tp.Forbidden) {
		return false // forbidden always wins over trusted (lexical)
	}
	root, ok := rootWithin(p, tp.Trusted)
	if !ok {
		return false // not inside any trusted root: default deny
	}
	rp, ok := realPath(p)
	if !ok {
		return false // fail closed on resolution error
	}
	rt, ok := realPath(root)
	if !ok {
		rt = root // the root is a trusted directory; fall back to lexical
	}
	if !withinOrEqual(rt, rp) {
		return false // real location escapes the trusted root (symlink out)
	}
	for _, f := range tp.Forbidden {
		if rf, ok := realPath(f); ok && withinOrEqual(rf, rp) {
			return false // real location lands in a forbidden root (symlink)
		}
	}
	return true
}

// withinOrEqual reports whether p is dir itself or under it (separator-safe:
// "/ab" is NOT under "/a").
func withinOrEqual(dir, p string) bool {
	dir = filepath.Clean(dir)
	if p == dir {
		return true
	}
	return strings.HasPrefix(p, dir+string(filepath.Separator))
}

// withinAny reports whether p is inside (or equal to) any of dirs.
func withinAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if withinOrEqual(d, p) {
			return true
		}
	}
	return false
}

// rootWithin returns the most specific (longest) trusted root containing p.
func rootWithin(p string, roots []string) (string, bool) {
	best := ""
	for _, r := range roots {
		if withinOrEqual(r, p) && len(r) > len(best) {
			best = r
		}
	}
	return best, best != ""
}

// realPath resolves the symlinks in p as far as the filesystem allows: the
// longest existing prefix is EvalSymlinks'd and any missing tail is reattached
// (cleaned). When no component exists, p is its own real identity. ok=false
// only on an unexpected resolution failure (callers fail closed).
func realPath(p string) (string, bool) {
	p = filepath.Clean(p)
	cur := p
	var tail []string
	for {
		if _, err := os.Lstat(cur); err == nil {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, true // nothing exists anywhere: lexical identity
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
	real, err := filepath.EvalSymlinks(cur)
	if err != nil {
		return "", false
	}
	out := real
	for i := len(tail) - 1; i >= 0; i-- {
		out = filepath.Join(out, tail[i])
	}
	return out, true
}

// ---------- tool execution ----------

// Toolbox executes tools against an in-memory DB. It is the shared executor used by
// the stdio MCP server, the socket MCP server, and the daemon.
//
// Message-board fields (plans/message-board-plan.md §4): BoardPath is the board file
// (default boardPath()); refreshBoard() merges new board messages into DB (chunks +
// BM25) so search sees them. boardMu serializes merges in-process; boardSeen is the
// board-file mtime last merged; boardLast is the highest merged message ID.
type Toolbox struct {
	DB        *DB
	Live      []string        // live git repo root paths (from -live); empty for one-shot
	BoardPath string          // board file; "" => boardPath()
	Disabled  map[string]bool // config-disabled tools (plans/kbtool-preserve-config-plan.md); nil = none
	Trust     *TrustPolicy    // path trust (plans/constrain-file-ops-to-trusted-paths-plan.md); nil = deny all
	Store     *kbStore        // at-rest persistence (db + board, plain or encrypted); nil => plain default

	boardMu   sync.Mutex
	boardSeen time.Time // board file mtime last merged (zero = never)
	boardLast int64     // highest board message ID merged into DB
}

// store returns the at-rest store, falling back to a plain default store at the default
// db path so internal machinery (zero-value Toolbox) still works. Commands that touch an
// encrypted store attach their own (keyed) store explicitly (encrypt-at-rest plan §Design).
func (tb *Toolbox) store() *kbStore {
	if tb.Store != nil {
		return tb.Store
	}
	st, _ := openKBStore(defaultDB(), nil) // plain fallback; never errors for a missing file
	return st
}

// newToolbox builds a serving Toolbox with the config's disabled-tool set and
// the path-trust policy resolved once per process (see
// plans/kbtool-preserve-config-plan.md §4.2; plans/constrain-file-ops-to-trusted-paths-plan.md §3.2). Internal
// machinery (refreshBoard in doQuery, boardStats in doStatus) does not need
// them and may use a zero-value Toolbox (a nil TrustPolicy denies all reads —
// fail closed).
func newToolbox(db *DB, live []string) *Toolbox {
	cfg := loadConfigWarned()
	return &Toolbox{
		DB:        db,
		Live:      live,
		BoardPath: boardPath(),
		Disabled:  effectiveDisabledSet(cfg),
		Trust:     newTrustPolicy(db, live, cfg),
	}
}

// toolDisabled reports whether the tool is disabled by config (nil-map safe).
func (tb *Toolbox) toolDisabled(name string) bool { return tb.Disabled[name] }

// allowRead is the Toolbox's read grant for a path (see
// plans/constrain-file-ops-to-trusted-paths-plan.md §3.2); a nil policy denies everything (fail closed).
func (tb *Toolbox) allowRead(path string) bool {
	return tb.Trust != nil && tb.Trust.AllowRead(path)
}

// newTrustPolicy assembles the root sets for a serving Toolbox
// (plans/constrain-file-ops-to-trusted-paths-plan.md §3.2, decision 2):
//
//	trusted   = -live repo roots (auto; subdir checkouts resolve to their git
//	            toplevel — the toplevel is where git runs and where repoFor
//	            label-matching works)
//	            + the DB's git source roots (where the KB is indexed from —
//	            keeps the one-shot/stdio flows working, where Live is nil)
//	            + config trusted_paths
//	forbidden = config forbidden_paths (always wins over trusted)
func newTrustPolicy(db *DB, live []string, cfg *config) *TrustPolicy {
	var trusted []string
	for _, r := range live {
		trusted = append(trusted, liveRepoPath(r))
	}
	if db != nil {
		for _, s := range db.Sources {
			if s.HasGit {
				trusted = append(trusted, s.Root)
			}
		}
	}
	if cfg != nil {
		trusted = append(trusted, cfg.TrustedPaths...)
	}
	var forbidden []string
	if cfg != nil {
		forbidden = cfg.ForbiddenPaths
	}
	return NewTrustPolicy(trusted, forbidden)
}

// repoFor resolves a source label to a live git repo root: a -live path whose basename
// matches the label first, else the DB's recorded source root.
func (tb *Toolbox) repoFor(label string) string {
	for _, p := range tb.Live {
		if strings.EqualFold(stripInvisible(filepath.Base(filepath.Clean(p))), label) {
			return p
		}
	}
	if tb.DB != nil {
		for _, s := range tb.DB.Sources {
			if strings.EqualFold(s.Label, label) && s.HasGit {
				return s.Root
			}
		}
	}
	return ""
}

// gitRootFor resolves a git tool's repo reference (label OR path) to a root
// directory: repoFor first, then the trusted read set — so a trusted_paths
// repo is reachable by BOTH git tools even when it is neither -live nor
// indexed (plans/constrain-file-ops-to-trusted-paths-plan.md §3.3, decisions 7-8).
func (tb *Toolbox) gitRootFor(label string) string {
	if r := tb.repoFor(label); r != "" {
		return r
	}
	if tb.Trust != nil {
		// 1) the label is itself an existing, trusted directory (exact match
		//    wins over the basename heuristic below)
		if fi, err := os.Stat(label); err == nil && fi.IsDir() && tb.allowRead(label) {
			return label
		}
		// 2) basename match against the trusted roots (label style: "repoB")
		want := strings.ToLower(stripInvisible(filepath.Base(filepath.Clean(label))))
		for _, r := range tb.Trust.Trusted {
			if strings.ToLower(filepath.Base(r)) == want {
				return r
			}
		}
	}
	return ""
}

// trustRefused renders the standard refusal for a git-tool path outside the
// trusted read set (plans/constrain-file-ops-to-trusted-paths-plan.md §3.3): names
// the offending argument, the rule, and where to change it.
func trustRefused(tool, what string) string {
	return fmt.Sprintf("%s refused: %q is outside the trusted read set (trusted = -live repos + indexed git sources + trusted_paths; forbidden_paths always wins) — to allow it, add the path to trusted_paths in %s", tool, what, configPath())
}

// pathHasTraversal reports whether p contains a ".." path element (git_log
// pathspec defense — plan decision 11).
func pathHasTraversal(p string) bool {
	for _, e := range strings.Split(filepath.ToSlash(p), "/") {
		if e == ".." {
			return true
		}
	}
	return false
}

// boardFile returns the effective board file path for this toolbox.
func (tb *Toolbox) boardFile() string {
	if tb.BoardPath != "" {
		return tb.BoardPath
	}
	return boardPath()
}

// refreshBoard merges NEW board messages (ID > boardLast) into the in-memory DB:
// appends board chunks to DB.Chunks and extends the BM25 index (kwAddChunk), so
// search_codebase / board_search see cross-thread board content (plan §4).
// Best-effort: errors are swallowed (board is an enhancement, not a requirement);
// one-shot processes load a fresh board anyway.
func (tb *Toolbox) refreshBoard() {
	if tb.DB == nil || tb.DB.KW == nil {
		return
	}
	st := tb.store()
	tb.boardMu.Lock()
	defer tb.boardMu.Unlock()
	// mtime gate (cheap stat of the board carrier — bundle or board.bin): skip when
	// nothing changed since the last merge (ext4 has ns resolution).
	if mt, ok := st.boardMtime(); ok && !tb.boardSeen.IsZero() && !mt.After(tb.boardSeen) {
		return
	}
	unlock, err := st.lock()
	if err != nil {
		return
	}
	defer unlock()
	b, err := st.loadBoard(false)
	if err != nil {
		return // no board yet (or unreadable) — nothing to merge
	}
	for _, m := range b.allMsgs() {
		if m.ID <= tb.boardLast {
			continue
		}
		c := boardChunk(m)
		c.Text = stripInvisible(c.Text) // ingest sanitization (security-filter-plan §3.2)
		c.Vector = embedOne(c.Text, tb.DB.Dim)
		tb.DB.Chunks = append(tb.DB.Chunks, c)
		kwAddChunk(tb.DB.KW, c)
		tb.boardLast = m.ID
	}
	if mt, ok := st.boardMtime(); ok {
		tb.boardSeen = mt
	}
}

// Execute runs a named tool and returns its (sanitized) text result.
//
// Tool gating (plans/kbtool-preserve-config-plan.md §4.2): tools named in the
// config's disable_tools list are refused here — the single enforcement point
// for the socket daemon, the stdio MCP server, and one-shot `kbtool call`.
// No other runtime behavior changes: indexing, board merging, and git baking
// all proceed exactly as before.
//
// Security (plans/security-filter-plan.md §3.4): last-mile guarantee that no invisible
// tag/format character ever reaches the AI — even for DBs built before sanitization
// existed, or from paths we did not anticipate. Idempotent, so it is safe to apply on
// top of the per-source stripping done in buildDB and the git plumbing.
func (tb *Toolbox) Execute(name string, args json.RawMessage) (string, bool) {
	if tb.toolDisabled(name) {
		return fmt.Sprintf("tool %q is disabled by config (disable_tools in %s; remove it from that list to enable)", name, configPath()), true
	}
	text, isErr := tb.executeRaw(name, args)
	return stripInvisible(text), isErr
}

// kbStatus reports KB + message-board stats; tolerates a nil DB (board-only mode).
func (tb *Toolbox) kbStatus() (string, bool) {
	db := tb.DB
	if db == nil {
		return "knowledge base not loaded (board-only mode)\n" + tb.boardStats(), true
	}
	files := map[string]bool{}
	kinds := map[string]int{}
	for _, c := range db.Chunks {
		files[c.Path] = true
		kinds[c.Kind]++
	}
	b := db.Backend
	if b == "" {
		b = "unknown"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "chunks=%d files=%d dim=%d backend=%s", len(db.Chunks), len(files), db.Dim, b)
	for _, k := range []string{"code", "doc", "text", "commit", "diff", "board"} {
		if n, ok := kinds[k]; ok {
			fmt.Fprintf(&sb, " %s=%d", k, n)
		}
	}
	if db.KW != nil {
		fmt.Fprintf(&sb, "\nkeyword index: %d terms, avg chunk %.1f tokens (hybrid/keyword modes ready)", len(db.KW.Terms), db.KW.AvgDL)
	} else {
		sb.WriteString("\nkeyword index: not built (vector mode only; rebuild to enable hybrid/keyword)")
	}
	if len(db.Sources) > 0 {
		sb.WriteString("\nsources:")
		for _, s := range db.Sources {
			g := "dir"
			if s.HasGit {
				g = "git"
			}
			fmt.Fprintf(&sb, "\n  %-20s %s  %s", s.Label, g, s.Root)
		}
	}
	if len(tb.Live) > 0 {
		sb.WriteString("\nlive repos (git_blame/git_log):")
		for _, p := range tb.Live {
			fmt.Fprintf(&sb, "\n  %s", p)
		}
	}
	// Effective path trust (plans/constrain-file-ops-to-trusted-paths-plan.md §3.6):
	// what the git tools may read, and what always wins.
	if tb.Trust != nil {
		sb.WriteString("\ntrusted read roots (git tools):")
		for _, p := range tb.Trust.Trusted {
			fmt.Fprintf(&sb, "\n  trusted:   %s", p)
		}
		for _, p := range tb.Trust.Forbidden {
			fmt.Fprintf(&sb, "\n  FORBIDDEN: %s (always wins)", p)
		}
	}
	sb.WriteString("\n")
	sb.WriteString(tb.boardStats())
	return sb.String(), false
}

// kwPathStr renders a config's *bool kwPath (absent → the default "true").
func kwPathStr(c *config) string {
	if c.KWPath == nil {
		return "true(default)"
	}
	return strconv.FormatBool(*c.KWPath)
}

// boardStats renders the message-board summary (file, threads, messages, agents,
// active count). Read-only: the board file is atomically replaced, so no lock needed.
func (tb *Toolbox) boardStats() string {
	st := tb.store()
	if st.enc && st.key == nil {
		return "message board: encrypted in " + st.path + " (provide a key to read it)"
	}
	loc := st.boardCarrier() // display location (board.bin in plain mode; the bundle in enc)
	if !st.boardExists() {
		return "message board: not initialized (created at daemon start when message_board=true, or on first board_signup)"
	}
	b, err := st.loadBoard(false)
	if err != nil {
		return "message board: present at " + loc + " (unreadable: " + err.Error() + ")"
	}
	now := time.Now().Unix()
	active := 0
	for _, ag := range b.Agents {
		if now-ag.LastSeen <= int64(boardTTL().Seconds()) {
			active++
		}
	}
	return fmt.Sprintf("message board: %s · %d thread(s) [%s] · %d message(s) · %d agent(s) (%d active in last %s)",
		loc, len(b.Order), strings.Join(b.Order, ", "), b.msgCount(), len(b.Agents), active, boardTTL())
}

// boardFindMsg resolves a board chunk path ("board/<thread>/msg-<seq>") to the
// message in the board (nil when absent).
func boardFindMsg(b *Board, path string) *BoardMsg {
	rest := strings.TrimPrefix(path, "board/")
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return nil
	}
	threadID := rest[:i]
	seq, err := strconv.Atoi(strings.TrimPrefix(rest[i+1:], "msg-"))
	if err != nil {
		return nil
	}
	t := b.Threads[threadID]
	if t == nil || seq < 0 || seq >= len(t.Msgs) {
		return nil
	}
	return &t.Msgs[seq]
}

// boardRoster renders the agent activity roster (most recent first) with
// ACTIVE/STALE computed against boardTTL().
func boardRoster(b *Board, now int64) string {
	var sb strings.Builder
	sb.WriteString("agents (most recent first; ACTIVE = last seen within " + boardTTL().String() + "):\n")
	if len(b.Agents) == 0 {
		sb.WriteString("  (none signed up yet — be the first: board_signup, then post a signed hello in the welcome thread)\n")
		return sb.String()
	}
	for _, ag := range b.sortedAgents() {
		active := now-ag.LastSeen <= int64(boardTTL().Seconds())
		state := "STALE "
		if active {
			state = "ACTIVE"
		}
		fmt.Fprintf(&sb, "  %-7s %-16s posts=%-3d last=%s (%s)", state, ag.ID, ag.Posts,
			time.Unix(ag.LastSeen, 0).UTC().Format("2006-01-02 15:04:05Z"), fmtAgo(ag.LastSeen))
		if !active {
			sb.WriteString(" — likely offline; may not report back")
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// boardExecute implements the eight message-board tools (plans/message-board-plan.md §5 +
// plans/new-message-board-initilization.md). It runs BEFORE the db==nil check in
// executeRaw, so the board works standalone (board-only mode) even when no
// codebase DB has been built.
func (tb *Toolbox) boardExecute(name string, args json.RawMessage) (string, bool) {
	var a struct {
		Name   string   `json:"name"` // board_signup: the agent's chosen identity name
		Thread string   `json:"thread"`
		Seed   string   `json:"seed"`
		Text   string   `json:"text"`
		Kind   string   `json:"kind"`
		Refs   []string `json:"refs"`
		Task   string   `json:"task"`
		After  int      `json:"after"`
		Limit  int      `json:"limit"`
		Q      string   `json:"q"`
		K      int      `json:"k"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &a); err != nil {
			return "invalid arguments: " + err.Error(), true
		}
	}
	now := time.Now().Unix()
	st := tb.store()
	p := st.boardCarrier() // display location (board.bin in plain mode; the bundle in enc)

	// loadOrNew loads the board (creating it when create=true and absent), via the
	// at-rest store so it works for both the plain board.bin and the encrypted bundle.
	loadOrNew := func(create bool) (*Board, error) {
		return st.loadBoard(create)
	}

	// requireIdentity resolves the caller's seed to its registered identity
	// (board_signup bound name<->pubkey permanently) and bumps last-seen: every
	// board interaction is authenticated activity (makes board_confirm recency
	// reliable). Missing / malformed / unregistered seeds are steered to
	// board_signup. Returns the agent and the private key (for signing).
	requireIdentity := func(b *Board) (*BoardAgent, ed25519.PrivateKey, error) {
		if a.Seed == "" {
			return nil, nil, fmt.Errorf("missing required argument 'seed' (your private seed from board_signup — it identifies you on this board)\n%s", boardSignupTeaching)
		}
		priv, pub, err := cryptoDeriveSeed(a.Seed)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot derive key from seed: %v\n%s", err, boardSignupTeaching)
		}
		ag := agentByPub(b, hex.EncodeToString(pub))
		if ag == nil {
			return nil, nil, fmt.Errorf("seed not recognized: no identity is registered for this seed\n%s", boardSignupTeaching)
		}
		ag.LastSeen = now
		return ag, priv, nil
	}

	switch name {
	case "board_signup":
		idn := strings.TrimSpace(a.Name)
		if idn == "" {
			return "missing required argument 'name' (choose your identity name, e.g. \"alice\")", true
		}
		if !boardAgentIDRe.MatchString(idn) {
			return fmt.Sprintf("invalid name %q (want lowercase alphanumerics, optional '-'/'_', max 64 chars, e.g. \"alice\")", idn), true
		}
		seed := make([]byte, ed25519.SeedSize)
		if _, err := crand.Read(seed); err != nil {
			return "cannot generate seed: " + err.Error(), true
		}
		h := hex.EncodeToString(seed)
		_, pub, err := cryptoDeriveSeed(h)
		if err != nil {
			return "cannot derive key from seed: " + err.Error(), true
		}
		pubHex := hex.EncodeToString(pub)
		unlock, err := st.lock()
		if err != nil {
			return "cannot lock board: " + err.Error(), true
		}
		defer unlock()
		b, err := loadOrNew(true) // the first signup creates the board (welcome thread included)
		if err != nil {
			return err.Error(), true
		}
		if _, taken := b.Agents[idn]; taken {
			return fmt.Sprintf("name %q is already registered on this board — names are permanent and cannot be reused; choose a different name", idn), true
		}
		b.Agents[idn] = &BoardAgent{ID: idn, Pub: pubHex, FirstSeen: now, LastSeen: now, Posts: 0}
		if err := st.saveBoard(b); err != nil {
			return "cannot save board: " + err.Error(), true
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "signed up as: %s\n", idn)
		fmt.Fprintf(&sb, "seed: %s\n\n", h)
		sb.WriteString("STORE THIS SEED NOW — it identifies you on the board and can never be retrieved:\n")
		sb.WriteString("  use your shell tool to persist it in your own workspace, e.g.:\n")
		fmt.Fprintf(&sb, "    printf '%%s' '%s' > .kbtool-seed\n", h)
		sb.WriteString("Keep it PRIVATE: never post it, share it, or write it into the board. kbtool never stores\n")
		sb.WriteString("the seed. Lose it and this identity is gone — a new board_signup (with a NEW name) is the\n")
		sb.WriteString("only remedy.\n\n")
		sb.WriteString("Next steps (in order):\n")
		fmt.Fprintf(&sb, "  1. introduce yourself BEFORE browsing: board_post {\"thread\":\"welcome\",\"kind\":\"hello\",\"text\":\"I'm %s, …\",\"seed\":\"<your seed>\"}\n", idn)
		sb.WriteString("  2. then browse: board_threads / board_read / board_search (every board call takes your \"seed\")\n")
		return sb.String(), false

	case "board_whoami":
		if a.Seed == "" {
			return "missing required argument 'seed' (your private seed from board_signup)\n" + boardSignupTeaching, true
		}
		_, pub, err := cryptoDeriveSeed(a.Seed)
		if err != nil {
			return "cannot derive key from seed: " + err.Error() + "\n" + boardSignupTeaching, true
		}
		pubHex := hex.EncodeToString(pub)
		if !st.boardExists() {
			return fmt.Sprintf("board not found at %s — no one has signed up yet (or the daemon has not started); call board_signup to create your identity", p), true
		}
		b, err := st.loadBoard(false) // read-only; the board carrier is atomically replaced, so no lock needed
		if err != nil {
			return err.Error(), true
		}
		if ag := agentByPub(b, pubHex); ag != nil {
			return fmt.Sprintf("you are: %s\npublic key: %s\nsignup: %s\nposts: %d\n", ag.ID, pubHex,
				time.Unix(ag.FirstSeen, 0).UTC().Format("2006-01-02 15:04:05Z"), ag.Posts), false
		}
		return fmt.Sprintf("seed not recognized: no identity is registered for this seed\n%s", boardSignupTeaching), true

	case "board_sign":
		if a.Seed == "" {
			return "missing required argument 'seed' (your private signing seed; obtain one with board_signup and store it on disk)", true
		}
		if strings.TrimSpace(a.Text) == "" {
			return "missing required argument 'text'", true
		}
		priv, pub, err := cryptoDeriveSeed(a.Seed)
		if err != nil {
			return "cannot derive key from seed: " + err.Error() + "\n" + boardSignupTeaching, true
		}
		canonical := "board-sign\x00" + a.Text
		sig := cryptoSignBoard(priv, canonical)
		var sb strings.Builder
		fmt.Fprintf(&sb, "public key: %s\n", hex.EncodeToString(pub))
		fmt.Fprintf(&sb, "canonical:  %q\n", canonical)
		fmt.Fprintf(&sb, "signature:  %s\n", sig)
		sb.WriteString("check: ed25519.Verify(pubkey, canonical, signature) == true\n")
		return sb.String(), false

	case "board_post":
		if a.Thread == "" {
			return "missing required argument 'thread' (e.g. \"welcome\", or a new topical id like \"research-auth\")", true
		}
		threadID := strings.ToLower(a.Thread)
		if !boardThreadIDRe.MatchString(threadID) {
			return fmt.Sprintf("invalid thread id %q (want simple lowercase alphanumeric with hyphens, e.g. \"research-auth\")", a.Thread), true
		}
		text := strings.TrimSpace(a.Text)
		if text == "" {
			return "missing required argument 'text'", true
		}
		if len(text) > boardMaxText {
			return fmt.Sprintf("message too large (%d bytes; cap %d)", len(text), boardMaxText), true
		}
		kind := a.Kind
		if kind == "" {
			kind = boardKindInfo
		}
		if !boardKinds[kind] {
			return fmt.Sprintf("invalid kind %q (want hello|info|task|result|feature)", a.Kind), true
		}
		unlock, err := st.lock()
		if err != nil {
			return "cannot lock board: " + err.Error(), true
		}
		defer unlock()
		b, err := loadOrNew(true) // posting auto-creates the board (welcome thread included)
		if err != nil {
			return err.Error(), true
		}
		// identity: the author is ALWAYS the name bound to the signer's seed
		// (board_signup) — there is no caller-supplied agent id to spoof.
		ag, priv, err := requireIdentity(b)
		if err != nil {
			return err.Error(), true
		}
		t := b.thread(threadID)
		if t == nil {
			t = &BoardThread{ID: threadID, CreatedAt: now, CreatedBy: ag.ID}
			b.Threads[threadID] = t
			b.Order = append(b.Order, threadID)
		}
		m := BoardMsg{
			ID: b.NextID + 1, Thread: threadID, Seq: len(t.Msgs),
			Agent: ag.ID, Pub: ag.Pub, Text: text, At: now, Kind: kind,
			Refs: a.Refs, Task: a.Task,
		}
		m.Sig = cryptoSignBoard(priv, canonicalMsg(m))
		b.NextID = m.ID
		t.Msgs = append(t.Msgs, m)
		ag.Posts++ // LastSeen was already bumped by requireIdentity
		if err := st.saveBoard(b); err != nil {
			return "cannot save board: " + err.Error(), true
		}
		// merge into the in-memory index so this process's searches see the message
		tb.boardMu.Lock()
		if tb.DB != nil && tb.DB.KW != nil {
			c := boardChunk(m)
			c.Text = stripInvisible(c.Text) // ingest sanitization (security-filter-plan §3.2)
			c.Vector = embedOne(c.Text, tb.DB.Dim)
			tb.DB.Chunks = append(tb.DB.Chunks, c)
			kwAddChunk(tb.DB.KW, c)
			tb.boardLast = m.ID
			if mt, ok := st.boardMtime(); ok {
				tb.boardSeen = mt
			}
		}
		tb.boardMu.Unlock()
		var sb strings.Builder
		fmt.Fprintf(&sb, "posted to %s#%d (message id %d) as %s [%s] — signed and stored (append-only)\n", threadID, m.Seq, m.ID, ag.ID, kind)
		fmt.Fprintf(&sb, "public key: %s\n", ag.Pub)
		if a.Task != "" {
			fmt.Fprintf(&sb, "linked task: %s\n", a.Task)
		}
		if len(a.Refs) > 0 {
			fmt.Fprintf(&sb, "refs: %s\n", strings.Join(a.Refs, ", "))
		}
		if kind == "task" {
			fmt.Fprintf(&sb, "the delegate should reply with kind=\"result\" and task=\"%s#%d\"\n", threadID, m.Seq)
		}
		return sb.String(), false

	case "board_read":
		if a.Thread == "" {
			return "missing required argument 'thread' — see board_threads for the list", true
		}
		threadID := strings.ToLower(a.Thread)
		limit := a.Limit
		if limit <= 0 {
			limit = 50
		}
		if limit > 500 {
			limit = 500
		}
		after := a.After
		if after < 0 {
			after = 0
		}
		unlock, err := st.lock()
		if err != nil {
			return "cannot lock board: " + err.Error(), true
		}
		defer unlock()
		b, err := loadOrNew(false)
		if err != nil {
			return err.Error(), true
		}
		if _, _, err := requireIdentity(b); err != nil {
			return err.Error(), true
		}
		if err := st.saveBoard(b); err != nil { // persist the last-seen bump
			return "cannot save board: " + err.Error(), true
		}
		t := b.thread(threadID)
		if t == nil {
			return fmt.Sprintf("unknown thread %q — available: %s", a.Thread, strings.Join(b.Order, ", ")), true
		}
		start := after
		if start > len(t.Msgs) {
			start = len(t.Msgs)
		}
		end := start + limit
		if end > len(t.Msgs) {
			end = len(t.Msgs)
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "thread %q — %d message(s), showing %d..%d\n\n", t.ID, len(t.Msgs), start, end-1)
		for i := start; i < end; i++ {
			m := t.Msgs[i]
			status := cryptoVerifyBoardMsg(b, m)
			marker := "OK   "
			if status != "verified" {
				marker = "WARN "
			}
			fmt.Fprintf(&sb, "%s#%d [%s] %s · %s · %s\n", marker, m.Seq,
				time.Unix(m.At, 0).UTC().Format("2006-01-02 15:04:05"), m.Agent, m.Kind, status)
			if m.Task != "" || len(m.Refs) > 0 {
				if m.Task != "" {
					fmt.Fprintf(&sb, "      task: %s", m.Task)
				}
				if len(m.Refs) > 0 {
					fmt.Fprintf(&sb, "  refs: %s", strings.Join(m.Refs, ", "))
				}
				sb.WriteString("\n")
			}
			for _, ln := range strings.Split(m.Text, "\n") {
				fmt.Fprintf(&sb, "      %s\n", ln)
			}
			sb.WriteString("\n")
		}
		return sb.String(), false

	case "board_threads":
		unlock, err := st.lock()
		if err != nil {
			return "cannot lock board: " + err.Error(), true
		}
		defer unlock()
		b, err := loadOrNew(false)
		if err != nil {
			return err.Error(), true
		}
		if _, _, err := requireIdentity(b); err != nil {
			return err.Error(), true
		}
		if err := st.saveBoard(b); err != nil { // persist the last-seen bump
			return "cannot save board: " + err.Error(), true
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "board: %s\nthreads: %d · messages: %d · agents: %d\n\n", p, len(b.Order), b.msgCount(), len(b.Agents))
		for _, id := range b.Order {
			t := b.Threads[id]
			if t == nil {
				continue
			}
			participants := map[string]bool{}
			var lastAt int64
			var lastBy string
			for _, m := range t.Msgs {
				participants[m.Agent] = true
				lastAt = m.At
				lastBy = m.Agent
			}
			parts := make([]string, 0, len(participants))
			for x := range participants {
				parts = append(parts, x)
			}
			sort.Strings(parts)
			if len(t.Msgs) == 0 {
				fmt.Fprintf(&sb, "  %-24s (empty — created by %s)\n", id, t.CreatedBy)
				continue
			}
			fmt.Fprintf(&sb, "  %-24s %d msg(s) · by %s · last %s by %s · participants: %s\n",
				id, len(t.Msgs), t.CreatedBy, fmtAgo(lastAt), lastBy, strings.Join(parts, ", "))
		}
		sb.WriteString("\n")
		sb.WriteString(boardRoster(b, now))
		return sb.String(), false

	case "board_confirm":
		unlock, err := st.lock()
		if err != nil {
			return "cannot lock board: " + err.Error(), true
		}
		defer unlock()
		b, err := loadOrNew(false)
		if err != nil {
			return err.Error(), true
		}
		ag, _, err := requireIdentity(b) // confirmations = recency endpoint (plan §2.10)
		if err != nil {
			return err.Error(), true
		}
		if err := st.saveBoard(b); err != nil {
			return "cannot save board: " + err.Error(), true
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "confirmed: %s is active @ %s\n\n", ag.ID, time.Unix(now, 0).UTC().Format("2006-01-02 15:04:05Z"))
		sb.WriteString(boardRoster(b, now))
		sb.WriteString("\nif an agent you expect to report back is STALE, assume it may be offline — delegate the task to an ACTIVE agent instead (note the swap in the thread).\n")
		return sb.String(), false

	case "board_search":
		if tb.DB == nil || tb.DB.KW == nil {
			return "knowledge base not loaded (no db at " + dbPath() + "); run 'kbtool build .' first — board messages are indexed into the KB for search", true
		}
		if strings.TrimSpace(a.Q) == "" {
			return "missing required argument 'q'", true
		}
		// Verify identity and persist the last-seen bump under a SHORT-LIVED lock:
		// refreshBoard below takes the same board lock internally, and flock is not
		// reentrant — holding it across refreshBoard would deadlock this process.
		{
			unlock, lerr := st.lock()
			if lerr != nil {
				return "cannot lock board: " + lerr.Error(), true
			}
			b, lerr := loadOrNew(false)
			if lerr != nil {
				unlock()
				return lerr.Error(), true
			}
			if _, _, ierr := requireIdentity(b); ierr != nil {
				unlock()
				return ierr.Error(), true
			}
			if serr := st.saveBoard(b); serr != nil {
				unlock()
				return "cannot save board: " + serr.Error(), true
			}
			unlock()
		}
		tb.refreshBoard()
		k := a.K
		if k <= 0 {
			k = 8
		}
		pathSub := ""
		if a.Thread != "" {
			pathSub = "board/" + strings.ToLower(a.Thread) + "/"
		}
		res, err := tb.DB.SearchW(a.Q, k, pathSub, "board", 0, true, ModeHybrid, defWKeyword, defWVector)
		if err != nil {
			return err.Error(), true
		}
		if len(res) == 0 {
			return fmt.Sprintf("no board messages match %q — check board_threads / board_read (the board may be empty)", a.Q), false
		}
		// enrich with author + verification (atomic board carrier; read-only here)
		b, berr := st.loadBoard(false)
		var sb strings.Builder
		fmt.Fprintf(&sb, "%d board message(s) for %q:\n\n", len(res), a.Q)
		for i, r := range res {
			c := r.C
			fmt.Fprintf(&sb, "%d. %s [board] score=%.4f\n", i, c.Path, r.Score)
			if berr == nil {
				if m := boardFindMsg(b, c.Path); m != nil {
					fmt.Fprintf(&sb, "      by %s · %s · %s\n", m.Agent, m.Kind, cryptoVerifyBoardMsg(b, *m))
				}
			}
			fmt.Fprintf(&sb, "      %s\n\n", clip(strings.ReplaceAll(c.Text, "\n", " "), 300))
		}
		return sb.String(), false
	}
	return "unknown board tool: " + name, true
}

func (tb *Toolbox) executeRaw(name string, args json.RawMessage) (string, bool) {
	// Message board (plans/message-board-plan.md): routed FIRST so it works standalone
	// (board-only mode) even when no codebase DB is loaded.
	if strings.HasPrefix(name, "board_") {
		return tb.boardExecute(name, args)
	}
	if name == "search_codebase" || name == "get_chunk" || name == "list_files" {
		tb.refreshBoard() // merge any new board messages so KB reads see them
	}
	if name == "kb_status" {
		return tb.kbStatus()
	}
	var a struct {
		Q       string             `json:"q"`
		K       int                `json:"k"`
		Path    string             `json:"path"`
		Kind    string             `json:"kind"`
		Min     float64            `json:"min"`
		Full    bool               `json:"full"`
		Mode    string             `json:"mode"`
		Weights map[string]float64 `json:"weights"`
		Index   int                `json:"index"`
		Before  int                `json:"before"`
		After   int                `json:"after"`
		Limit   int                `json:"limit"`
		File    string             `json:"file"`
		Start   int                `json:"start"`
		End     int                `json:"end"`
		Repo    string             `json:"repo"`
		N       int                `json:"n"`
		Author  string             `json:"author"`
		// kb_terms / kb_bundle (plans/context-bundle-plan.md)
		Term   string `json:"term"`
		Target string `json:"target"`
		Json   bool   `json:"json"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &a); err != nil {
			return "invalid arguments: " + err.Error(), true
		}
	}
	db := tb.DB
	if db == nil {
		return "knowledge base not loaded", true
	}
	switch name {
	case "kb_terms":
		if a.Term == "" {
			return "missing required argument 'term'", true
		}
		r := termsCensus(db, a.Term, a.K)
		if a.Json {
			return string(mustMarshal(r)), false
		}
		return renderTerms(r), false
	case "kb_bundle":
		if a.Target == "" && a.Q == "" {
			return "provide 'target' (file:line) or 'q' (query text)", true
		}
		if a.Target != "" {
			out, ok := bundleForTarget(db, a.Target)
			if !ok {
				return out, true
			}
			return out, false
		}
		return bundleForQuery(db, a.Q, a.K), false
	case "search_codebase":
		if a.Q == "" {
			return "missing required argument 'q'", true
		}
		wKW, wVec := defWKeyword, defWVector
		if a.Weights != nil {
			if v, ok := a.Weights["keyword"]; ok {
				wKW = v
			}
			if v, ok := a.Weights["vector"]; ok {
				wVec = v
			}
		}
		res, err := db.SearchW(a.Q, a.K, a.Path, a.Kind, a.Min, a.Full, a.Mode, wKW, wVec)
		if err != nil {
			return err.Error(), true
		}
		if len(res) == 0 {
			return "no matches", false
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%d results for %q:\n\n", len(res), a.Q)
		for i, r := range res {
			c := r.C
			fmt.Fprintf(&b, "%d. %s:%d-%d [%s] score=%.4f\n", i, c.Path, c.Start, c.End, c.Kind, r.Score)
			if a.Full {
				fmt.Fprintf(&b, "%s\n", c.Text)
			} else {
				fmt.Fprintf(&b, "%s\n", clip(strings.ReplaceAll(c.Text, "\n", " "), 300))
			}
			b.WriteString("\n")
		}
		return b.String(), false
	case "get_chunk":
		i := a.Index
		if i < 0 {
			i = 0
		}
		if i >= len(db.Chunks) {
			return fmt.Sprintf("index %d out of range (0..%d)", i, len(db.Chunks)-1), true
		}
		lo := i - a.Before
		if lo < 0 {
			lo = 0
		}
		hi := i + a.After + 1
		if hi > len(db.Chunks) {
			hi = len(db.Chunks)
		}
		var b strings.Builder
		for j := lo; j < hi; j++ {
			c := db.Chunks[j]
			marker := "  "
			if j == i {
				marker = "> "
			}
			fmt.Fprintf(&b, "%s[%d] %s:%d-%d [%s]\n%s\n\n", marker, j, c.Path, c.Start, c.End, c.Kind, c.Text)
		}
		return b.String(), false
	case "list_files":
		if a.Limit <= 0 {
			a.Limit = 200
		}
		type agg struct {
			kind  string
			count int
		}
		m := map[string]*agg{}
		var order []string
		for _, c := range db.Chunks {
			if a.Path != "" && !strings.Contains(strings.ToLower(c.Path), strings.ToLower(a.Path)) {
				continue
			}
			if a.Kind != "" && c.Kind != a.Kind {
				continue
			}
			// Board messages each have a unique path (board/<thread>/msg-N);
			// group them by thread so a thread reads as one logical file.
			p := c.Path
			if c.Kind == "board" {
				if i := strings.LastIndex(c.Path, "/"); i > 0 {
					p = c.Path[:i]
				}
			}
			g, ok := m[p]
			if !ok {
				g = &agg{kind: c.Kind}
				m[p] = g
				order = append(order, p)
			}
			g.count++
		}
		sort.Strings(order)
		if len(order) > a.Limit {
			order = order[:a.Limit]
		}
		var b strings.Builder
		for _, p := range order {
			fmt.Fprintf(&b, "%s [%s] %d chunks\n", p, m[p].kind, m[p].count)
		}
		if len(order) == 0 {
			return "no files", false
		}
		return fmt.Sprintf("%d files\n%s", len(order), b.String()), false
	case "git_blame":
		if a.File == "" {
			return "missing required argument 'file'", true
		}
		label, rel := splitLabel(a.File)
		root := tb.gitRootFor(label) // -live/indexed first, then the trusted read set
		if root == "" && a.Repo != "" {
			// No label in the file (or it did not resolve): the path is
			// repo-relative to the explicit repo (schema: "label/rel … or a
			// repo-relative path").
			label, rel = a.Repo, a.File
			root = tb.gitRootFor(label)
		}
		if label == "" {
			return "could not determine repo: pass 'repo' (label) or a labeled file path", true
		}
		if root == "" {
			return fmt.Sprintf("no trusted git repo for %q — start the daemon with -live <repo>, rebuild with -git, or add the repo to trusted_paths", label), true
		}
		// Security (plans/constrain-file-ops-to-trusted-paths-plan.md §3.4): the blame
		// target must stay inside the trusted read set — rel may try to climb
		// out (../, absolute) or follow a link out; forbidden roots always win.
		if !tb.allowRead(filepath.Join(root, rel)) {
			return trustRefused("git_blame", a.File), true
		}
		out, err := gitBlameRange(root, rel, a.Start, a.End, a.Limit)
		if err != nil {
			return "git blame failed: " + err.Error(), true
		}
		if out == "" {
			return "no blame output (empty file or bad range?)", false
		}
		return out, false
	case "git_log":
		label := a.Repo
		if label == "" && len(db.Sources) == 1 {
			label = db.Sources[0].Label
		}
		if label == "" {
			return "could not determine repo: pass 'repo' (label or path) or have a single source", true
		}
		// The root (label or direct path) must be trusted — this replaces the
		// old "allow a direct path in repo" fallback, which accepted ANY
		// existing directory (plans/constrain-file-ops-to-trusted-paths-plan.md §3.4).
		root := tb.gitRootFor(label)
		if root == "" {
			return fmt.Sprintf("no trusted git repo for %q — start the daemon with -live <repo>, rebuild with -git, or add the repo to trusted_paths", label), true
		}
		if !tb.allowRead(root) {
			return trustRefused("git_log", label), true
		}
		// The pathspec is repo-relative (the repo is already identified by
		// `repo`). Tolerate a leading "<this repo's label>/" prefix — agents
		// echo labeled paths from search results — and strip it; the trust
		// check below always applies to the pathspec git will actually use,
		// never to a mis-split segment (see
		// plans/constrain-file-ops-to-trusted-paths-plan.md §3.4).
		pathRel := a.Path
		if pathRel != "" {
			if lbl, rel := splitLabel(pathRel); rel != "" &&
				strings.EqualFold(stripInvisible(lbl), stripInvisible(filepath.Base(root))) {
				pathRel = rel
			}
		}
		// …and a pathspec must not climb out of the (trusted) root: no ".."
		// elements, and literal (non-glob) pathspecs must pass the same read
		// check (glob pathspecs stay inside the already-checked root).
		if pathRel != "" &&
			(pathHasTraversal(pathRel) ||
				(!strings.ContainsAny(pathRel, "*?[") && !tb.allowRead(filepath.Join(root, pathRel)))) {
			return trustRefused("git_log", a.Path), true
		}
		out, err := gitLogPath(root, pathRel, a.N, a.Author)
		if err != nil {
			return "git log failed: " + err.Error(), true
		}
		if out == "" {
			return "no commits", false
		}
		return out, false
	}
	return "unknown tool: " + name, true
}

// ---------- JSON-RPC / MCP protocol ----------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return e.Message }

type rpcResult struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// executor is implemented by *Toolbox (local) and *remoteExec (daemon proxy).
type executor interface {
	Execute(name string, args json.RawMessage) (string, bool)
	// toolDisabled reports whether the executor refuses this tool (config's
	// disable_tools); dispatch uses it to filter tools/list + initialize
	// (plans/kbtool-preserve-config-plan.md §4.3).
	toolDisabled(name string) bool
}

func mustMarshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// initializeInstructions builds the MCP "initialize" instructions from the tools
// this executor actually serves (plans/kbtool-preserve-config-plan.md §4.3): config-
// disabled tools are not advertised.
func initializeInstructions(exec executor) string {
	var kb, board []string
	for _, t := range toolSchemas() {
		if exec.toolDisabled(t.Name) {
			continue
		}
		if strings.HasPrefix(t.Name, "board_") {
			board = append(board, t.Name)
		} else {
			kb = append(kb, t.Name)
		}
	}
	var sb strings.Builder
	sb.WriteString("Code & documentation knowledge base")
	if len(board) > 0 {
		sb.WriteString(" + signed multi-agent message board")
	}
	sb.WriteString(".\n")
	if len(kb) > 0 {
		sb.WriteString("KB tools: " + strings.Join(kb, ", ") + ".\n")
	}
	if len(board) > 0 {
		sb.WriteString("Board tools: " + strings.Join(board, ", ") + ".\n")
		sb.WriteString("Board flow: board_signup (choose a name; it returns your seed — store it on disk with a shell command, keep it private, it can never be retrieved) → " +
			"introduce yourself in the 'welcome' thread (board_post kind=hello) → " +
			"delegate tasks (kind=task) and collect results (kind=result, task='<thread>#<seq>'). " +
			"Every board call takes your seed as the credential; trust only messages whose verification is 'verified' AND whose author you expect; " +
			"check board_confirm for who is ACTIVE before delegating or when a report is overdue.")
	}
	return sb.String()
}

// dispatch implements the MCP methods against an executor.
func dispatch(exec executor, method string, params json.RawMessage) (any, error) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": mcpProtocol,
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    appName,
				"version": appVer,
			},
			"instructions": initializeInstructions(exec),
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		// Hide config-disabled tools (plans/kbtool-preserve-config-plan.md §4.3).
		tools := toolSchemas()
		if exec != nil {
			kept := tools[:0]
			for _, t := range tools {
				if !exec.toolDisabled(t.Name) {
					kept = append(kept, t)
				}
			}
			tools = kept
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if len(params) > 0 {
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
			}
		}
		text, isErr := exec.Execute(p.Name, p.Arguments)
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": isErr,
		}, nil
	}
	return nil, &rpcError{Code: -32601, Message: "method not found: " + method}
}

// handleLine processes one newline-delimited JSON-RPC message and returns the encoded
// response (or nil for notifications / parse errors with no id).
func handleLine(line []byte, exec executor) []byte {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		resp := rpcResult{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &rpcError{Code: -32700, Message: "parse error: " + err.Error()},
		}
		b, _ := json.Marshal(resp)
		return b
	}
	if req.ID == nil || len(req.ID) == 0 {
		return nil // notification: no response
	}
	result, err := dispatch(exec, req.Method, req.Params)
	if err != nil {
		resp := rpcResult{JSONRPC: "2.0", ID: req.ID}
		if re, ok := err.(*rpcError); ok {
			resp.Error = re
		} else {
			resp.Error = &rpcError{Code: -32603, Message: err.Error()}
		}
		b, _ := json.Marshal(resp)
		return b
	}
	rb, _ := json.Marshal(result)
	resp := rpcResult{JSONRPC: "2.0", ID: req.ID, Result: rb}
	b, _ := json.Marshal(resp)
	return b
}

// serveLines reads newline-delimited JSON-RPC requests from r and writes responses to w.
func serveLines(r io.Reader, w io.Writer, exec executor) error {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		// Skip blank lines and the empty read returned at EOF; still process a
		// final line that lacks a trailing newline (err==EOF but data present).
		if t := bytes.TrimSpace(line); len(t) > 0 {
			if resp := handleLine(t, exec); len(resp) > 0 {
				resp = append(resp, '\n') // newline-delimited framing
				if _, werr := w.Write(resp); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// serveStdio runs the MCP server over stdin/stdout.
func serveStdio(exec executor) error {
	return serveLines(os.Stdin, os.Stdout, exec)
}

// serveUnix serves newline-delimited JSON-RPC on l, one goroutine per
// connection. The listener is created (and optionally TLS-wrapped) by the
// caller — see daemonRun (plans/http-support-with-mtls-auth-plan.md §4.1).
func serveUnix(l net.Listener, exec executor, errc chan<- error) {
	for {
		c, err := l.Accept()
		if err != nil {
			errc <- err
			return
		}
		go func() {
			defer c.Close()
			_ = serveLines(c, c, exec)
		}()
	}
}

// httpHandler exposes the same MCP JSON-RPC over HTTP — one JSON-RPC message per
// request (plans/http-support-with-mtls-auth-plan.md §4.1): POST /mcp + GET /healthz.
// TLS (mTLS) is handled by the http.Server; over TLS the protocol negotiates to
// HTTP/2 via ALPN, over cleartext TCP it is HTTP/1.1 (h2c needs x/net — forbidden).
func httpHandler(exec executor) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed (use GET)", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed (use POST)", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBody))
		if err != nil {
			http.Error(w, "read error: "+err.Error(), http.StatusBadRequest)
			return
		}
		var req rpcRequest
		if err := json.Unmarshal(body, &req); err != nil {
			b, _ := json.Marshal(rpcResult{JSONRPC: "2.0", ID: json.RawMessage("null"),
				Error: &rpcError{Code: -32700, Message: "parse error: " + err.Error()}})
			_, _ = w.Write(b)
			return
		}
		if req.ID == nil || len(req.ID) == 0 {
			http.Error(w, "missing JSON-RPC id", http.StatusBadRequest)
			return
		}
		result, err := dispatch(exec, req.Method, req.Params)
		resp := rpcResult{JSONRPC: "2.0", ID: req.ID}
		if err != nil {
			if re, ok := err.(*rpcError); ok {
				resp.Error = re
			} else {
				resp.Error = &rpcError{Code: -32603, Message: err.Error()}
			}
		} else {
			resp.Result = mustMarshal(result)
		}
		b, _ := json.Marshal(resp)
		_, _ = w.Write(b)
	})
	return mux
}

// ---------- client-server network: CRL + mTLS (plans/http-support-with-mtls-auth-plan.md) ----------
//
// The daemon always serves the unix socket (default method); -http adds a TCP
// listener (POST /mcp, GET /healthz; HTTP/2 over TLS, HTTP/1.1 cleartext).
// -mtls wraps whatever is served with TLS + RequireAndVerifyClientCert. The
// server-side CRL store rejects revoked client certificates at handshake;
// cryptoMonitorCRL keeps it in sync with the CRL file (periodic refresh when
// crl_refresh=true, file-watch otherwise; missing file = no revocation data).
// Clients connect through client.json (unix or http endpoint, TLS when marked).

// crlStore is the daemon's in-memory revocation lists (thread-safe).
type crlStore struct {
	mu       sync.RWMutex
	crls     []*x509.RevocationList
	ca       *x509.Certificate // CA that signs the CRLs (set by the daemon before the monitor starts)
	lastStat time.Time         // CRL file mtime at last load (file-watch mode)
	lastSize int64             // CRL file size at last load (file-watch mode)
}

// caCert returns the CRL-signing CA (nil = no verification was configured).
func (s *crlStore) caCert() *x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ca
}

func (s *crlStore) set(crls []*x509.RevocationList) {
	s.mu.Lock()
	s.crls = crls
	s.mu.Unlock()
}

func (s *crlStore) noteFile(fi os.FileInfo) {
	s.mu.Lock()
	s.lastStat = fi.ModTime()
	s.lastSize = fi.Size()
	s.mu.Unlock()
}

func (s *crlStore) fileChanged(fi os.FileInfo) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !fi.ModTime().Equal(s.lastStat) || fi.Size() != s.lastSize
}

// cryptoLoadCRLs parses a PEM file containing one or more "X509 CRL" blocks.
func cryptoLoadCRLs(path string) ([]*x509.RevocationList, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.RevocationList
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			break
		}
		b = rest
		if block.Type != "X509 CRL" && block.Type != "CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		out = append(out, crl)
	}
	return out, nil
}

// cryptoVerifyCRLs drops CRLs whose signature does not verify against ca. When
// ca is nil (no CRL-signing CA configured) all lists are kept — the daemon
// still enforces issuer/expiry/serial matching.
func cryptoVerifyCRLs(crls []*x509.RevocationList, ca *x509.Certificate) []*x509.RevocationList {
	if ca == nil {
		return crls
	}
	out := make([]*x509.RevocationList, 0, len(crls))
	for _, crl := range crls {
		if crl.CheckSignatureFrom(ca) == nil {
			out = append(out, crl)
		}
	}
	return out
}

// cryptoCheckRevoked reports an error when cert is listed in any VALID CRL in the
// store. A CRL only counts when (a) its issuer is the cert's issuer (DER byte
// compare) and (b) its NextUpdate has not passed — otherwise it is skipped, so a
// stale CRL file can neither revoke nor DoS. Signatures are verified against
// store.ca at load time (plans/http-support-with-mtls-auth-plan.md §5).
func cryptoCheckRevoked(cert *x509.Certificate, store *crlStore) error {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if len(store.crls) == 0 {
		return nil
	}
	now := time.Now()
	for _, crl := range store.crls {
		if !bytes.Equal(crl.RawIssuer, cert.RawIssuer) {
			continue
		}
		if crl.NextUpdate.Before(now) {
			continue // stale CRL: don't trust it
		}
		revoked := func(serial *big.Int) bool {
			return serial != nil && serial.Cmp(cert.SerialNumber) == 0
		}
		for _, e := range crl.RevokedCertificateEntries {
			if revoked(e.SerialNumber) {
				return fmt.Errorf("certificate %q is revoked (serial %s)", cert.Subject.CommonName, cert.SerialNumber)
			}
		}
		for _, e := range crl.RevokedCertificates { // deprecated field fallback
			if revoked(e.SerialNumber) {
				return fmt.Errorf("certificate %q is revoked (serial %s)", cert.Subject.CommonName, cert.SerialNumber)
			}
		}
	}
	return nil
}

// cryptoMonitorCRL keeps the CRL store in sync with path and runs until stop is
// closed (plans/http-support-with-mtls-auth-plan.md §5):
//   - refresh=true : re-load the file every `period` (daemon-managed refresh);
//   - refresh=false: stat every crlPoll and re-load only when the file changed —
//     so a CRL managed by an external CA is picked up as soon as it is updated.
//
// A missing file means "no revocation data" (allowed); a file that disappears
// later clears the store; an unreadable/corrupt file keeps the previous lists
// and warns (fail-safe: never drop revocations because of a read hiccup).
func cryptoMonitorCRL(path string, refresh bool, period time.Duration, store *crlStore, stop <-chan struct{}) {
	load := func() {
		crls, err := cryptoLoadCRLs(path)
		if err == nil {
			crls = cryptoVerifyCRLs(crls, store.caCert())
		}
		if err != nil {
			if os.IsNotExist(err) {
				store.set(nil) // file absent: no revocation data (allowed)
				store.mu.Lock()
				store.lastStat = time.Time{}
				store.lastSize = 0
				store.mu.Unlock()
			} else {
				fmt.Fprintf(os.Stderr, "%s: warning: CRL reload %s: %v (keeping previous lists)\n", appName, path, err)
			}
			return
		}
		store.set(crls)
		if fi, err := os.Stat(path); err == nil {
			store.noteFile(fi)
		}
	}
	load() // initial load (warns once if the file is corrupt; absent is quiet)
	if period <= 0 {
		period = defCrlPeriod * time.Second
	}
	if !refresh {
		period = crlPoll
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if !refresh {
				fi, err := os.Stat(path)
				if err != nil {
					// File absent: sync anyway (clears the store if a CRL was
					// loaded earlier — a deleted CRL must release revocations).
					load()
					continue
				}
				if !store.fileChanged(fi) {
					continue
				}
			}
			load()
		}
	}
}

// cryptoLoadCertPool reads a PEM file with one or more certificates into a pool.
func cryptoLoadCertPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

// cryptoFirstCert returns the first certificate in a PEM file.
func cryptoFirstCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("no certificate found in %s", path)
		}
		b = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
}

// cryptoServerTLSConfig builds the daemon's mTLS server config (see
// plans/http-support-with-mtls-auth-plan.md §4.1): server cert + key, client CA pool, required and
// verified client certificates, and — when a CRL store is given — revocation
// checking of every cert in the verified chain via VerifyPeerCertificate.
func cryptoServerTLSConfig(serverCert, serverKey, caCert string, crls *crlStore) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, fmt.Errorf("server cert/key %s/%s: %v — run 'kbtool mtls' or point ca_cert/server_cert/server_key at a valid pair", serverCert, serverKey, err)
	}
	pool, err := cryptoLoadCertPool(caCert)
	if err != nil {
		return nil, fmt.Errorf("client CA %s: %v — run 'kbtool mtls' or point ca_cert at the CA that signs client certs", caCert, err)
	}
	if crls != nil {
		// The first cert in the CA PEM is the CRL-signing CA; CRLs that do not
		// verify against it are dropped at load time.
		if ca, err := cryptoFirstCert(caCert); err == nil {
			crls.mu.Lock()
			crls.ca = ca
			crls.mu.Unlock()
		}
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	if crls != nil {
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			if len(chains) == 0 || len(chains[0]) == 0 {
				return errors.New("no verified certificate chain")
			}
			for _, cert := range chains[0] {
				if err := cryptoCheckRevoked(cert, crls); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return cfg, nil
}

// cryptoClientTLSConfig builds the client's mTLS config from a clientConfig:
// trust the given CA, present the client key pair, verify the server against
// server_name (default "localhost" — the SAN kbtool mtls always includes).
func cryptoClientTLSConfig(cc *clientConfig) (*tls.Config, error) {
	caPath := clientResolve(cc.CaCert, "ca.crt")
	certPath := clientResolve(cc.ClientCert, "client.crt")
	keyPath := clientResolve(cc.ClientKey, "client.key")
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("client cert/key %s/%s: %v", certPath, keyPath, err)
	}
	pool, err := cryptoLoadCertPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("client CA %s: %v", caPath, err)
	}
	// ServerName is left empty when unset: over HTTP the dialer uses the URL's
	// host (matching an IP SAN or a DNS SAN as appropriate). Callers that serve
	// over a unix socket set it explicitly (unixEndpointFor, plan §3.2).
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
		Certificates: []tls.Certificate{pair},
		ServerName:   cc.ServerName,
	}, nil
}

// ---------- daemon client (remote executor) ----------

// endpoint describes how to reach a daemon: a unix socket (newline JSON-RPC,
// optionally over TLS) or a TCP HTTP endpoint (optionally mTLS).
type endpoint struct {
	kind   string // "unix" | "http"
	socket string // kind=unix
	url    string // kind=http, e.g. "https://host:9876"
	tlsCfg *tls.Config
}

// remoteExec is a client-side proxy to a daemon. toolDisabled is a stub: the
// remote daemon enforces the config and remoteExec never serves tools/list
// itself (plans/kbtool-preserve-config-plan.md §4.3).
type remoteExec struct {
	ep endpoint
}

func (r *remoteExec) toolDisabled(name string) bool { return false }

// execResult extracts the tool result text from a JSON-RPC response.
func execResult(res rpcResult) (string, bool) {
	if res.Error != nil {
		return res.Error.Message, true
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(res.Result, &out); err != nil {
		// result may be a bare string
		var s string
		if json.Unmarshal(res.Result, &s) == nil {
			return stripInvisible(s), false
		}
		return stripInvisible(string(res.Result)), false
	}
	var text string
	for _, c := range out.Content {
		if c.Type == "text" {
			text += c.Text
		}
	}
	// Security: sanitize even if the daemon on the other end predates stripping
	// (cross-version defense in depth; idempotent when it already is).
	return stripInvisible(text), out.IsError
}

func (r *remoteExec) Execute(name string, args json.RawMessage) (string, bool) {
	argsVal := map[string]any{}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &argsVal)
	}
	req := rpcRequest{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call"}
	req.Params = mustMarshal(map[string]any{"name": name, "arguments": argsVal})
	data, _ := json.Marshal(req)

	if r.ep.kind == "unix" {
		c, err := net.Dial("unix", r.ep.socket)
		if err != nil {
			return "cannot reach daemon at " + r.ep.socket + ": " + err.Error(), true
		}
		defer c.Close()
		if r.ep.tlsCfg != nil {
			tc := tls.Client(c, r.ep.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return "daemon TLS handshake at " + r.ep.socket + ": " + err.Error(), true
			}
			c = tc
		}
		_ = c.SetDeadline(time.Now().Add(120 * time.Second))
		if _, err := c.Write(append(data, '\n')); err != nil {
			return err.Error(), true
		}
		br := bufio.NewReader(c)
		line, err := br.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			return "no response: " + err.Error(), true
		}
		var res rpcResult
		if err := json.Unmarshal(line, &res); err != nil {
			return "bad response: " + err.Error(), true
		}
		return execResult(res)
	}

	// HTTP endpoint: one JSON-RPC message per POST /mcp request.
	var tr *http.Transport
	if r.ep.tlsCfg != nil {
		// A custom TLSClientConfig opts the stdlib client OUT of automatic HTTP/2
		// (Go ≥1.24, Issue 14275) — ForceAttemptHTTP2 re-enables the ALPN "h2"
		// offer so mTLS connections negotiate HTTP/2 with the server.
		tr = &http.Transport{TLSClientConfig: r.ep.tlsCfg, ForceAttemptHTTP2: true}
	} else {
		tr = &http.Transport{}
	}
	client := &http.Client{Transport: tr, Timeout: 120 * time.Second}
	resp, err := client.Post(r.ep.url+"/mcp", "application/json", bytes.NewReader(data))
	if err != nil {
		return "cannot reach daemon at " + r.ep.url + ": " + err.Error(), true
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	if err != nil {
		return "no response: " + err.Error(), true
	}
	var res rpcResult
	if err := json.Unmarshal(body, &res); err != nil {
		return "bad response: " + err.Error(), true
	}
	return execResult(res)
}

// pingEndpoint checks that an endpoint answers (unix: MCP "ping"; http: /healthz).
func pingEndpoint(ep endpoint) error {
	if ep.kind == "unix" {
		c, err := net.Dial("unix", ep.socket)
		if err != nil {
			return err
		}
		defer c.Close()
		if ep.tlsCfg != nil {
			tc := tls.Client(c, ep.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return err
			}
			c = tc
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		data, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "ping"})
		if _, err := c.Write(append(data, '\n')); err != nil {
			return err
		}
		br := bufio.NewReader(c)
		line, err := br.ReadBytes('\n')
		if err != nil {
			return err
		}
		var res rpcResult
		if err := json.Unmarshal(line, &res); err != nil {
			return fmt.Errorf("bad ping response: %v", err)
		}
		if res.Error != nil {
			return fmt.Errorf("%s", res.Error.Message)
		}
		return nil
	}
	var tr *http.Transport
	if ep.tlsCfg != nil {
		tr = &http.Transport{TLSClientConfig: ep.tlsCfg, ForceAttemptHTTP2: true}
	} else {
		tr = &http.Transport{}
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	resp, err := client.Get(ep.url + "/healthz")
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %s", resp.Status)
	}
	return nil
}

// ---------- client config (client.json — plans/http-support-with-mtls-auth-plan.md §3.2) ----------
//
// <stateDir>/client.json is the CLIENT-side connection config: which daemon to
// reach (unix socket or host:port) and, when tls=true, the CA + client key
// pair for mTLS. kbtool mtls and `daemon start -http/-mtls` create it when
// absent; it is also part of the `kbtool client -export` bundle so a remote
// machine can import a working client setup in one step.

type clientConfig struct {
	Version    int    `json:"version"`
	Updated    string `json:"updated,omitempty"`
	UnixSocket string `json:"unix_socket,omitempty"` // unix socket to use (empty => host:port)
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	TLS        bool   `json:"tls,omitempty"` // mTLS: present client cert, verify server via ServerName
	ServerName string `json:"server_name,omitempty"`
	CaCert     string `json:"ca_cert,omitempty"` // relative to <stateDir> unless absolute
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
}

func clientConfigPath() string { return filepath.Join(stateDir(), "client.json") }

func clientResolve(p, defName string) string {
	if p == "" {
		return filepath.Join(stateDir(), defName)
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(stateDir(), p)
}

func loadClientConfig() (*clientConfig, error) {
	b, err := os.ReadFile(clientConfigPath())
	if err != nil {
		return nil, err
	}
	var cc clientConfig
	if err := json.Unmarshal(b, &cc); err != nil {
		return nil, err
	}
	return &cc, nil
}

// loadClientConfigSafe returns nil on any error — a broken client config must
// never block local CLI use.
func loadClientConfigSafe() *clientConfig {
	cc, err := loadClientConfig()
	if err != nil {
		return nil
	}
	return cc
}

// atomicWrite writes data to path via a temp file + rename (house style, see
// the board file writer).
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func saveClientConfig(cc *clientConfig) error {
	if cc.Version == 0 {
		cc.Version = 1
	}
	cc.Updated = time.Now().UTC().Format(time.RFC3339)
	b, err := json.MarshalIndent(cc, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(clientConfigPath(), append(b, '\n'), 0644)
}

// ensureClientConfigFromArgs decides whether a start line should create an absent
// client.json (plans/http-support-with-mtls-auth-plan.md §4.6): only when the effective
// options (flag > config > default) enable network serving. Returns (path, created).
func ensureClientConfigFromArgs(args []string, socket string) (string, bool) {
	fs := flag.NewFlagSet("ensure-client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	httpOn := fs.Bool("http", false, "")
	mtlsOn := fs.Bool("mtls", false, "")
	bind := fs.String("bind", "", "")
	// Parse-only key-source flags (never persisted — see persistDaemonArgs).
	fs.String("db-key-env", "", "")
	fs.String("db-key-file", "", "")
	if err := fs.Parse(flagFirst(args, map[string]bool{"bind": true, "db-key-env": true, "db-key-file": true})); err != nil {
		return "", false
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	cfg := loadConfigWarned()
	httpEff := *httpOn
	if !set["http"] && cfg != nil {
		httpEff = cfg.Http
	}
	mtlsEff := *mtlsOn
	if !set["mtls"] && cfg != nil {
		mtlsEff = cfg.Mtls
	}
	if !httpEff && !mtlsEff {
		return "", false // local unix-socket-only daemon: nothing to record
	}
	addr := *bind
	if addr == "" && cfg != nil && cfg.HTTPAddr != "" {
		addr = cfg.HTTPAddr
	}
	return ensureClientConfig(httpEff, mtlsEff, addr, socket)
}

// endpointFromClientConfig turns a client config into a usable endpoint.
func endpointFromClientConfig(cc *clientConfig) (endpoint, string, bool) {
	if cc.UnixSocket != "" {
		ep := endpoint{kind: "unix", socket: cc.UnixSocket}
		if cc.TLS {
			cfg, err := cryptoClientTLSConfig(cc)
			if err != nil {
				return endpoint{}, "", false
			}
			if cfg.ServerName == "" {
				cfg.ServerName = defaultUnixServerName() // must match a server.crt SAN
			}
			ep.tlsCfg = cfg
		}
		desc := "unix " + cc.UnixSocket
		if cc.TLS {
			desc += " (mtls)"
		}
		return ep, desc, true
	}
	if cc.Host == "" {
		return endpoint{}, "", false
	}
	port := cc.Port
	if port <= 0 {
		port = defHTTPPort
	}
	url := net.JoinHostPort(cc.Host, strconv.Itoa(port))
	ep := endpoint{kind: "http", url: "http://" + url}
	if cc.TLS {
		cfg, err := cryptoClientTLSConfig(cc)
		if err != nil {
			return endpoint{}, "", false
		}
		ep.tlsCfg = cfg
		ep.url = "https://" + url
	}
	return ep, ep.url, true
}

// ensureClientConfig creates <stateDir>/client.json when absent (see
// plans/http-support-with-mtls-auth-plan.md §4.6): the local CLI then finds the daemon's endpoint
// automatically. It never overwrites an existing (possibly imported) file.
func ensureClientConfig(httpOn, mtls bool, addr, socket string) (string, bool) {
	path := clientConfigPath()
	if fileExists(path) {
		return "", false
	}
	cc := clientConfig{Version: 1}
	if httpOn {
		host, port := splitListenAddr(addr)
		cc.Host, cc.Port = host, port
	} else {
		cc.UnixSocket = socket
	}
	if mtls {
		cc.TLS = true
		if cc.UnixSocket != "" {
			cc.ServerName = "localhost" // SAN name for unix-socket TLS; over HTTP the URL host is used
		}
		cc.CaCert = "ca.crt"
		cc.ClientCert = "client.crt"
		cc.ClientKey = "client.key"
	}
	if err := saveClientConfig(&cc); err != nil {
		return "", false
	}
	return path, true
}

// splitListenAddr maps a listen address to a client-connectable host:port
// (wildcards become 127.0.0.1).
func splitListenAddr(addr string) (string, int) {
	host, portS, err := net.SplitHostPort(addr)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	port, err := strconv.Atoi(portS)
	if err != nil || port <= 0 {
		port = defHTTPPort
	}
	return host, port
}

// defaultUnixServerName picks a verifiable name for a local unix-socket TLS
// connection: the first SAN of the local server.crt (whatever 'kbtool mtls'
// generated, or an external CA's value), falling back to "localhost".
func defaultUnixServerName() string {
	if b, err := os.ReadFile(filepath.Join(stateDir(), "server.crt")); err == nil {
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				continue
			}
			for _, n := range cert.DNSNames {
				return n
			}
			for _, ip := range cert.IPAddresses {
				return ip.String()
			}
		}
	}
	return "localhost"
}

// unixEndpointFor builds a local-socket endpoint, TLS-wrapping it when
// client.json says tls:true — either because it names that exact socket, or
// because it is a host:port-only config (then the local daemon, same
// installation, serves its unix socket with mTLS too).
func unixEndpointFor(socket string) endpoint {
	ep := endpoint{kind: "unix", socket: socket}
	if cc := loadClientConfigSafe(); cc != nil && cc.TLS && (cc.UnixSocket == "" || cc.UnixSocket == socket) {
		if cfg, err := cryptoClientTLSConfig(cc); err == nil {
			if cfg.ServerName == "" {
				cfg.ServerName = defaultUnixServerName() // must match a server.crt SAN
			}
			ep.tlsCfg = cfg
		}
	}
	return ep
}

func socketAlive(socket string) bool { return pingEndpoint(unixEndpointFor(socket)) == nil }

// liveDaemon returns the first reachable daemon (local sockets, then the
// client.json endpoint — unix or http), or ok=false.
// Resolution order (plans/http-support-with-mtls-auth-plan.md §8):
// KBTOOL_SOCKET, <state>/daemon.sock, <state>/mcp.sock, client.json endpoint.
func liveDaemon() (*remoteExec, string, bool) {
	type cand struct {
		ep   endpoint
		desc string
	}
	var cs []cand
	add := func(socket string) {
		ep := unixEndpointFor(socket)
		desc := "unix " + socket
		if ep.tlsCfg != nil {
			desc += " (mtls)"
		}
		cs = append(cs, cand{ep, desc})
	}
	if s := os.Getenv("KBTOOL_SOCKET"); s != "" {
		add(s)
	}
	sd := stateDir()
	add(filepath.Join(sd, "daemon.sock"))
	add(filepath.Join(sd, "mcp.sock"))
	if cc := loadClientConfigSafe(); cc != nil {
		if ep, desc, ok := endpointFromClientConfig(cc); ok {
			cs = append(cs, cand{ep, desc})
		}
	}
	for _, c := range cs {
		if pingEndpoint(c.ep) == nil {
			return &remoteExec{ep: c.ep}, c.desc, true
		}
	}
	return nil, "", false
}

// ---------- state / process management ----------

func stateDir() string {
	if d := os.Getenv("KBTOOL_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, appName)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", appName)
	}
	return "." + appName
}

func dbPath() string {
	if d := os.Getenv("KBTOOL_DB"); d != "" {
		return d
	}
	return filepath.Join(stateDir(), "kb.db")
}

func socketPath(name string) string {
	if name == "daemon" {
		if s := os.Getenv("KBTOOL_SOCKET"); s != "" {
			return s
		}
	}
	return filepath.Join(stateDir(), name+".sock")
}

func pidPath(name string) string { return filepath.Join(stateDir(), name+".pid") }
func logPath(name string) string { return filepath.Join(stateDir(), name+".log") }

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

func writePidFile(name string) {
	_ = os.MkdirAll(stateDir(), 0755)
	_ = os.WriteFile(pidPath(name), []byte(strconv.Itoa(os.Getpid())), 0644)
}

func removePidFile(name string) { _ = os.Remove(pidPath(name)) }

func pidFromPidfile(name string) int {
	b, err := os.ReadFile(pidPath(name))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

// ---------- config: persisted build/daemon options (plans/kbtool-config-plan.md) ----------
//
// <stateDir>/config.json is a small, hand-editable JSON snapshot of how the KB was
// last built and how the daemon should serve it. `kbtool build` always rewrites it
// (a -git build also records live=true + the repo list); `daemon start` / `mcp
// start` merge in the flags explicitly passed on that line; `daemon run` never
// writes. Readers resolve options as: explicit CLI flag > config value > built-in
// default — so a bare `kbtool daemon start` after `kbtool build -git A B` serves
// with -live A B and any rebuild reuses the recorded build options. A missing file
// means "pre-config behavior"; a corrupt file warns and degrades to "no config".

type config struct {
	Version       int      `json:"version"`
	Updated       string   `json:"updated,omitempty"`
	Sources       []string `json:"sources,omitempty"`
	DB            string   `json:"db,omitempty"`
	Dim           int      `json:"dim,omitempty"`
	Chunk         int      `json:"chunk,omitempty"`
	Overlap       int      `json:"overlap,omitempty"`
	MaxKB         int      `json:"maxKB,omitempty"`
	Git           bool     `json:"git,omitempty"`
	GitMaxCommits int      `json:"gitMaxCommits,omitempty"`
	GitDiffMaxKB  int      `json:"gitDiffMaxKB,omitempty"`
	KWPath        *bool    `json:"kwPath,omitempty"` // pointer: distinguishes false from absent
	Live          bool     `json:"live,omitempty"`
	LiveRepos     []string `json:"liveRepos,omitempty"`
	// GitTools (plans/new-tool-options-plan.md): nil (absent) → false; the git tools
	// (git_blame/git_log) are served only when true AND not in DisableTools.
	GitTools *bool `json:"git_tools,omitempty"`
	// MessageBoard: same rule for the message board tools (board_*).
	MessageBoard *bool `json:"message_board,omitempty"`
	// DisableTools: per-tool kill switch (plans/new-tool-options-plan.md). nil (absent) →
	// defaultDisableTools applies; non-nil (even an empty list) → exactly that
	// list. Always honored — it beats the group options. Once present it is never
	// overwritten by kbtool writes (seed-or-preserve).
	DisableTools *[]string `json:"disable_tools,omitempty"`
	// Path trust (plans/constrain-file-ops-to-trusted-paths-plan.md): the git tools may
	// read only inside the trusted set = -live repos + indexed git sources +
	// trusted_paths. forbidden_paths ALWAYS wins over trusted — it can forbid a
	// default-trusted -live repo, or a subpath within any trusted path. Absent
	// ≡ empty; preserved verbatim by every config writer (no seeding: empty is
	// the natural default).
	TrustedPaths   []string `json:"trusted_paths,omitempty"`
	ForbiddenPaths []string `json:"forbidden_paths,omitempty"`

	// Network / mTLS serving options (plans/http-support-with-mtls-auth-plan.md §3.1).
	Http     bool   `json:"http,omitempty"` // also serve over TCP HTTP (IPv4/IPv6)
	Mtls     bool   `json:"mtls,omitempty"` // require mTLS on the served socket(s)
	HTTPAddr string `json:"http_addr,omitempty"`
	// HTTPAllowInsecure (plans/guard-against-plain-http-plan.md): allow cleartext
	// (unauthenticated) HTTP on a NON-loopback bind. Absent (false) is the default
	// — a non-loopback -http bind then requires -mtls. Persisted like the other
	// network options; a prominent warning is logged whenever it is in effect.
	HTTPAllowInsecure bool   `json:"http_allow_insecure,omitempty"`
	CaCert            string `json:"ca_cert,omitempty"`      // CA that vouches for clients (PEM)
	ServerCert        string `json:"server_cert,omitempty"`  // server cert (PEM)
	ServerKey         string `json:"server_key,omitempty"`   // server key (PEM)
	CrlFile           string `json:"crl_file,omitempty"`     // client CRL PEM; may not exist
	CrlRefresh        bool   `json:"crl_refresh,omitempty"`  // true: periodic reload; false (default): file watch
	CrlInterval       int    `json:"crl_interval,omitempty"` // seconds, when CrlRefresh
}

func configPath() string { return filepath.Join(stateDir(), "config.json") }

// loadConfig returns the config, or (nil, nil) when the file does not exist.
func loadConfig() (*config, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %v", configPath(), err)
	}
	return &c, nil
}

// loadConfigWarned is the read path for serving commands: missing = normal state
// (nil, quiet); corrupt = one stderr warning, then "no config" — a bad state file
// must never block serving (plans/kbtool-config-plan.md decision 8).
func loadConfigWarned() *config {
	c, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: ignoring unreadable config (%v)\n", appName, err)
		return nil
	}
	return c
}

// saveConfig writes the config atomically (tmp + rename in the same dir, like
// boardSave) so a crash can never leave a half-written file.
func saveConfig(c *config) error {
	c.Version = 1
	c.Updated = time.Now().UTC().Format(time.RFC3339)
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// absolutized returns each path via filepath.Abs (errors tolerated).
func absolutized(ps []string) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if a, err := filepath.Abs(p); err == nil {
			p = a
		}
		out = append(out, p)
	}
	return out
}

// liveRepoPath absolutizes p and, when p sits inside a git repo, returns the repo
// toplevel: repoFor() matches the live path's BASENAME against the source label
// (the toplevel's basename), so subdirectory checkouts must resolve upward.
func liveRepoPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	if top, ok := gitToplevel(p); ok {
		return top
	}
	return p
}

// defaultDB resolves the db file when a command's -db flag is not given: the
// recorded config db (plans/kbtool-config-plan.md) or the state-dir default.
func defaultDB() string {
	if c := loadConfigWarned(); c != nil && c.DB != "" {
		return c.DB
	}
	return dbPath()
}

// Tool families gated by group options (plans/new-tool-options-plan.md §2 decision 1):
// each family is served only when its option is true (default false) AND its
// members are not in disable_tools.
var (
	gitToolNames   = []string{"git_blame", "git_log"}
	boardToolNames = []string{"board_signup", "board_whoami", "board_sign", "board_post",
		"board_read", "board_threads", "board_search", "board_confirm"}
)

// defaultDisableTools is the seeded default for disable_tools (and the default
// when the field is absent): the listed tools are disabled endpoints, kept as a
// sane default.
var defaultDisableTools = []string{"kb_status", "board_sign"}

// effectiveDisabledSet resolves the full set of disabled tools for a config
// (plans/new-tool-options-plan.md §4.1):
//
//	(DisableTools if non-nil — even an empty list — else defaultDisableTools)
//	∪ (gitToolNames   when git_tools is false or absent)
//	∪ (boardToolNames when message_board is false or absent)
//
// The per-tool list is always honored — it beats the group options. Unknown
// names simply never match. c==nil (no/corrupt config) → all defaults.
func effectiveDisabledSet(c *config) map[string]bool {
	m := make(map[string]bool, 16)
	if c != nil && c.DisableTools != nil {
		for _, t := range *c.DisableTools {
			if t != "" {
				m[t] = true
			}
		}
	} else {
		for _, t := range defaultDisableTools {
			m[t] = true
		}
	}
	if !(c != nil && c.GitTools != nil && *c.GitTools) {
		for _, t := range gitToolNames {
			m[t] = true
		}
	}
	if !(c != nil && c.MessageBoard != nil && *c.MessageBoard) {
		for _, t := range boardToolNames {
			m[t] = true
		}
	}
	return m
}

// loadDisabledSet is the serving read path: missing config → defaults; corrupt
// config → one warning + defaults (never blocks serving).
func loadDisabledSet() map[string]bool {
	return effectiveDisabledSet(loadConfigWarned())
}

// ensureToolOptions seeds the tool options for a config write (see
// plans/new-tool-options-plan.md §4.2): disable_tools → ["kb_status", "board_sign"], git_tools → false, message_board → false —
// each only when absent, so a user's value (true, false, or any list) is never
// re-stamped; the file ends up documenting exactly what is off.
func ensureToolOptions(c *config) {
	if c.DisableTools == nil {
		def := append([]string(nil), defaultDisableTools...)
		c.DisableTools = &def
	}
	if c.GitTools == nil {
		v := false
		c.GitTools = &v
	}
	if c.MessageBoard == nil {
		v := false
		c.MessageBoard = &v
	}
}

// persistDaemonArgs records the daemon flags the user explicitly passed on a
// `daemon start` / `mcp start` line into the config (plans/kbtool-config-plan.md §4.3),
// merging onto the existing file and saving atomically; returns true when written.
// Bare starts (no relevant flags) never touch the file. Explicit -live=false /
// -git=false / -kwpath=false are honored: they clear the recorded option.
func persistDaemonArgs(args []string) bool {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	src := fs.String("src", "", "")
	live := fs.Bool("live", false, "")
	dim := fs.Int("dim", 0, "")
	chunk := fs.Int("chunk", 0, "")
	overlap := fs.Int("overlap", 0, "")
	maxkb := fs.Int("maxkb", 0, "")
	git := fs.Bool("git", false, "")
	gitmaxcommits := fs.Int("gitmaxcommits", 0, "")
	gitdiffmaxkb := fs.Int("gitdiffmaxkb", 0, "")
	kwpath := fs.Bool("kwpath", false, "")
	dbp := fs.String("db", "", "")
	httpOn := fs.Bool("http", false, "")
	mtlsOn := fs.Bool("mtls", false, "")
	insecure := fs.Bool("http-allow-insecure", false, "")
	bind := fs.String("bind", "", "")
	crl := fs.String("crl", "", "")
	crlrefresh := fs.Bool("crlrefresh", false, "")
	crlinterval := fs.Int("crlinterval", 0, "")
	// Parse-only: the key-source flags must NEVER be recorded in config.json
	// (the key is secret); declaring them just keeps parsing successful.
	fs.String("db-key-env", "", "")
	fs.String("db-key-file", "", "")
	if err := fs.Parse(flagFirst(args, map[string]bool{"src": true, "dim": true, "chunk": true, "overlap": true, "maxkb": true, "gitmaxcommits": true, "gitdiffmaxkb": true, "db": true, "bind": true, "crl": true, "crlinterval": true, "db-key-env": true, "db-key-file": true})); err != nil {
		return false // the child daemonRun re-validates the args authoritatively
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	delete(set, "db-key-env") // key sources are parse-only and never count as options
	delete(set, "db-key-file")
	if len(set) == 0 {
		return false // bare start: never touch the file
	}
	base := loadConfigWarned()
	if base == nil {
		base = &config{}
	}
	if set["src"] {
		base.Sources = absolutized([]string{*src})
	}
	if set["live"] {
		base.Live = *live
		base.LiveRepos = nil
		if *live {
			for _, r := range fs.Args() {
				base.LiveRepos = append(base.LiveRepos, liveRepoPath(r))
			}
		}
	}
	if set["dim"] {
		base.Dim = *dim
	}
	if set["chunk"] {
		base.Chunk = *chunk
	}
	if set["overlap"] {
		base.Overlap = *overlap
	}
	if set["maxkb"] {
		base.MaxKB = *maxkb
	}
	if set["git"] {
		base.Git = *git
	}
	if set["gitmaxcommits"] {
		base.GitMaxCommits = *gitmaxcommits
	}
	if set["gitdiffmaxkb"] {
		base.GitDiffMaxKB = *gitdiffmaxkb
	}
	if set["kwpath"] {
		v := *kwpath
		base.KWPath = &v
	}
	if set["db"] {
		base.DB = *dbp
	}
	// Network / mTLS options (plans/http-support-with-mtls-auth-plan.md §3.1).
	if set["http"] {
		base.Http = *httpOn
	}
	if set["mtls"] {
		base.Mtls = *mtlsOn
	}
	// Cleartext-HTTP opt-in (plans/guard-against-plain-http-plan.md): explicit
	// -http-allow-insecure=false clears a previously recorded opt-in.
	if set["http-allow-insecure"] {
		base.HTTPAllowInsecure = *insecure
	}
	if set["bind"] {
		base.HTTPAddr = *bind
	}
	if set["crl"] {
		base.CrlFile = *crl
	}
	if set["crlrefresh"] {
		base.CrlRefresh = *crlrefresh
	}
	if set["crlinterval"] {
		base.CrlInterval = *crlinterval
	}
	// Seed the tool options when absent; existing values (true, false, any list)
	// are preserved untouched (plans/new-tool-options-plan.md §2 decisions 4-5).
	ensureToolOptions(base)
	if err := saveConfig(base); err != nil {
		fmt.Fprintf(os.Stderr, "%s: warning: could not write config: %v\n", appName, err)
		return false
	}
	return true
}

// loadOrBuildStore loads the DB from the at-rest store (plain or encrypted) or
// builds it from opts.Sources (and persists it through the store, so an encrypted
// store stays encrypted). It returns (nil, nil) for board-only mode — no DB and
// nothing to build from (encrypt-at-rest plan §Design; supersedes the old
// plain-file loadOrBuild, plans/kbtool-config-plan.md §4.4).
func loadOrBuildStore(st *kbStore, opts BuildOpts, forceBuild bool) (*DB, error) {
	if forceBuild || (len(st.dbBytes) == 0 && len(opts.Sources) > 0) {
		db, err := buildDB(opts)
		if err != nil {
			return nil, err
		}
		if err := st.saveDB(db); err != nil {
			return nil, err
		}
		return db, nil
	}
	if len(st.dbBytes) == 0 {
		return nil, nil // board-only mode (no codebase DB)
	}
	return st.db()
}

// localExec builds the one-shot executor (stdio mcp): load the db from the at-rest
// store (plain or encrypted), or — when it is missing — build from an explicit src,
// the configured sources, and otherwise nothing (board-only). (plans/kbtool-config-plan.md
// §4.4.) keyEnv/keyFile supply the db-at-rest key when the store is encrypted;
// this path NEVER prompts: stdio MCP stdin is the protocol, not a TTY, so a
// missing key fails closed with a clear error (encrypt-at-rest plan §Design).
func localExec(src, keyEnv, keyFile string) (executor, error) {
	cfg := loadConfigWarned()
	var sources []string
	if src != "" {
		sources = []string{src}
	} else if cfg != nil && len(cfg.Sources) > 0 {
		sources = cfg.Sources
	}
	dbFile := defaultDB()
	opts := BuildOpts{
		Sources: sources, Dim: defDim, Chunk: defChunk, Overlap: defOverlap, MaxKB: defMaxKB,
		GitMaxCommits: defGitMaxCommits, GitDiffMaxKB: defGitDiffMaxKB,
	}
	if cfg != nil {
		if cfg.Dim > 0 {
			opts.Dim = cfg.Dim
		}
		if cfg.Chunk > 0 {
			opts.Chunk = cfg.Chunk
		}
		if cfg.Overlap >= 0 {
			opts.Overlap = cfg.Overlap
		}
		if cfg.MaxKB > 0 {
			opts.MaxKB = cfg.MaxKB
		}
		opts.Git = cfg.Git
		if cfg.GitMaxCommits > 0 {
			opts.GitMaxCommits = cfg.GitMaxCommits
		}
		if cfg.GitDiffMaxKB > 0 {
			opts.GitDiffMaxKB = cfg.GitDiffMaxKB
		}
		opts.KWPath = cfg.KWPath
	}
	st, err := openStore(dbFile, keyEnv, keyFile, false, true)
	if err != nil {
		return nil, err
	}
	if err := st.checkConsistency(); err != nil {
		return nil, err
	}
	db, err := loadOrBuildStore(st, opts, false)
	if err != nil {
		return nil, err
	}
	tb := newToolbox(db, nil)
	tb.Store = st // board ops (and any rebuild) persist through the same store
	return tb, nil
}

// ---------- cleartext-HTTP guard (plans/guard-against-plain-http-plan.md) ----------
//
// Invariant: a non-loopback, unauthenticated TCP surface is never created by
// accident. Loopback binds are local trust (like the unix socket); mTLS binds are
// authenticated (cert + CRL). Anything else on a non-loopback address requires the
// explicit -http-allow-insecure opt-in.

// isLoopbackBind reports whether a TCP listen address (host:port) binds only to
// loopback — 127.0.0.0/8 (IPv4), ::1 (IPv6), or the literal "localhost". An empty
// host ("", "0.0.0.0", "::") means all interfaces: NOT loopback. A host that is not
// an IP literal and not "localhost" (a hostname) is treated as non-loopback (fail
// closed — its resolution target is unknown to us).
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false // malformed; net.Listen will report it — fail closed
	}
	if host == "localhost" {
		return true
	}
	if host == "" { // all interfaces
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // hostname / unparseable: fail closed
	}
	return ip.IsLoopback() // 127.0.0.0/8, ::1
}

// validateHTTPBind enforces the cleartext-HTTP guard: a NON-loopback TCP bind
// requires mTLS (-mtls) or the explicit -http-allow-insecure opt-in. Loopback
// binds are always allowed (local trust). Returns nil when there is nothing to
// guard (no HTTP listener) or the bind is permitted.
func validateHTTPBind(httpOn, mtls, insecure bool, addr string) error {
	if !httpOn {
		return nil // unix-socket-only daemon: no TCP surface to guard
	}
	if isLoopbackBind(addr) {
		return nil // loopback: local trust, cleartext allowed
	}
	if mtls {
		return nil // mTLS: authenticated, allowed on any interface
	}
	if insecure {
		return nil // explicit opt-in to cleartext on a non-loopback bind
	}
	return fmt.Errorf(
		"refusing to serve cleartext (unauthenticated) HTTP on non-loopback address %s\n"+
			"  → local access only:      -http -bind 127.0.0.1:%d\n"+
			"  → remote access (secure): -http -bind %s -mtls   (run 'kbtool mtls' first)\n"+
			"  → accept the risk:        -http -bind %s -http-allow-insecure",
		addr, defHTTPPort, addr, addr)
}

// logTail returns the last n lines of a file ("" when unreadable/empty). Used to
// surface a failed daemon's own error message on `daemon start`.
func logTail(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// daemonRun is the foreground service: load/build the DB into RAM and serve MCP over
// a unix socket until interrupted.
//
// Options (plans/kbtool-config-plan.md §4.4): explicit CLI flag > config.json (recorded by
// the last `kbtool build` / `daemon start`) > built-in default. So a bare
// `kbtool daemon start` after `kbtool build -git A B` serves with -live A B, and any
// rebuild (no db, or -build) reuses the recorded -git/-dim/-chunk/-overlap/-maxkb/
// -kwpath/-db options.
func daemonRun(name string, args []string) {
	fs := flag.NewFlagSet(name+" run", flag.ExitOnError)
	src := fs.String("src", "", "source dir to build from when no DB exists (default: config sources)")
	build := fs.Bool("build", false, "force rebuild from sources")
	live := fs.Bool("live", false, "treat positional args as live git repos for git_blame/git_log (default: from config)")
	dim := fs.Int("dim", defDim, "embedding dimension")
	chunk := fs.Int("chunk", defChunk, "chunk size (lines)")
	overlap := fs.Int("overlap", defOverlap, "chunk overlap (lines)")
	maxkb := fs.Int("maxkb", defMaxKB, "max file size (KB)")
	git := fs.Bool("git", false, "rebuild with git history (commit messages + diffs) + provenance (default: from config)")
	gitmaxcommits := fs.Int("gitmaxcommits", defGitMaxCommits, "per-repo commit cap for -git history")
	gitdiffmaxkb := fs.Int("gitdiffmaxkb", defGitDiffMaxKB, "global byte cap (KB) on baked diff content")
	kwpath := fs.Bool("kwpath", true, "include path-leaf + kind tokens in the keyword index (default on)")
	dbp := fs.String("db", "", "db file (default: config db, else <state>/kb.db)")
	// At-rest encryption (plans/encrypt-at-rest-db-and-message-board-plan.md): when the store
	// is encrypted these supply the key; otherwise they are ignored (plain store).
	keyEnv := fs.String("db-key-env", "", "DB-at-rest key from environment variable $NAME (when the store is encrypted)")
	keyFile := fs.String("db-key-file", "", "DB-at-rest key from file PATH (when the store is encrypted)")
	// Network / mTLS (plans/http-support-with-mtls-auth-plan.md §4.1).
	httpOn := fs.Bool("http", false, "also serve over TCP HTTP (IPv4/IPv6; default off — unix socket only)")
	mtls := fs.Bool("mtls", false, "require mTLS on the served socket(s) (needs server + client certs)")
	// Cleartext-HTTP guard (plans/guard-against-plain-http-plan.md): a NON-loopback -http
	// bind is refused unless -mtls or this explicit opt-in is set. Without -mtls the
	// default bind is loopback (127.0.0.1:9876), so cleartext never leaks by accident.
	httpAllowInsecure := fs.Bool("http-allow-insecure", false, "allow cleartext (unauthenticated) HTTP on a NON-loopback bind (default: refused — use -mtls, or bind 127.0.0.1)")
	bind := fs.String("bind", "", "TCP listen address host:port, IPv6 in brackets (default: config http_addr, else :9876 with -mtls / 127.0.0.1:9876 without)")
	crl := fs.String("crl", "", "CRL PEM file with revoked client certs (default: config crl_file, else <state>/crl.pem; may not exist)")
	crlrefresh := fs.Bool("crlrefresh", false, "periodically re-load the CRL file (default off: watch the file for changes)")
	crlinterval := fs.Int("crlinterval", defCrlPeriod, "CRL reload period in seconds when -crlrefresh")
	args = flagFirst(args, map[string]bool{"src": true, "dim": true, "chunk": true, "overlap": true, "maxkb": true, "gitmaxcommits": true, "gitdiffmaxkb": true, "db": true, "bind": true, "crl": true, "crlinterval": true, "db-key-env": true, "db-key-file": true})
	fs.Parse(args)

	cfg := loadConfigWarned()
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// --- each option: explicit flag > config > default ---
	rDim := *dim
	if !set["dim"] && cfg != nil && cfg.Dim > 0 {
		rDim = cfg.Dim
	}
	rChunk := *chunk
	if !set["chunk"] && cfg != nil && cfg.Chunk > 0 {
		rChunk = cfg.Chunk
	}
	rOverlap := *overlap
	if !set["overlap"] && cfg != nil && cfg.Overlap >= 0 {
		rOverlap = cfg.Overlap
	}
	rMaxKB := *maxkb
	if !set["maxkb"] && cfg != nil && cfg.MaxKB > 0 {
		rMaxKB = cfg.MaxKB
	}
	rGit := *git
	if !set["git"] && cfg != nil {
		rGit = cfg.Git
	}
	rGitMax := *gitmaxcommits
	if !set["gitmaxcommits"] && cfg != nil && cfg.GitMaxCommits > 0 {
		rGitMax = cfg.GitMaxCommits
	}
	rGitDiff := *gitdiffmaxkb
	if !set["gitdiffmaxkb"] && cfg != nil && cfg.GitDiffMaxKB > 0 {
		rGitDiff = cfg.GitDiffMaxKB
	}
	rKW := *kwpath
	if !set["kwpath"] && cfg != nil && cfg.KWPath != nil {
		rKW = *cfg.KWPath
	}
	dbFile := *dbp
	if dbFile == "" && cfg != nil && cfg.DB != "" {
		dbFile = cfg.DB
	}
	if dbFile == "" {
		dbFile = dbPath()
	}

	// --- network / mTLS options: explicit flag > config > default (decision 11) ---
	rHTTP := *httpOn
	if !set["http"] && cfg != nil {
		rHTTP = cfg.Http
	}
	rMtls := *mtls
	if !set["mtls"] && cfg != nil {
		rMtls = cfg.Mtls
	}
	// Cleartext-HTTP opt-in (plans/guard-against-plain-http-plan.md): flag > config.
	rInsecure := *httpAllowInsecure
	if !set["http-allow-insecure"] && cfg != nil {
		rInsecure = cfg.HTTPAllowInsecure
	}
	rAddr := *bind
	if rAddr == "" && cfg != nil && cfg.HTTPAddr != "" {
		rAddr = cfg.HTTPAddr
	}
	if rAddr == "" {
		// Default bind (plans/guard-against-plain-http-plan.md): cleartext (no -mtls)
		// defaults to loopback 127.0.0.1:9876 (local trust only); mTLS defaults to
		// dual-stack :9876 (authenticated — any interface is fine).
		if rMtls {
			rAddr = net.JoinHostPort("", strconv.Itoa(defHTTPPort)) // dual-stack IPv4+IPv6
		} else {
			rAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(defHTTPPort))
		}
	}
	// Cleartext-HTTP guard (plans/guard-against-plain-http-plan.md): a non-loopback bind
	// requires -mtls or -http-allow-insecure. Fails before the store is opened and
	// the pid file / socket exist, so a rejected start leaves no state behind.
	if err := validateHTTPBind(rHTTP, rMtls, rInsecure, rAddr); err != nil {
		fatal(err)
	}
	if rHTTP && !rMtls && !isLoopbackBind(rAddr) {
		// We only reach here when rInsecure is true (else the guard above failed):
		// the operator explicitly accepted cleartext on a non-loopback address.
		fmt.Fprintf(os.Stderr, "%s: WARNING: serving cleartext (unauthenticated) HTTP on non-loopback %s — any reachable process can use the full MCP API\n", appName, rAddr)
	}
	rCrl := *crl
	if rCrl == "" && cfg != nil && cfg.CrlFile != "" {
		rCrl = cfg.CrlFile
	}
	if rCrl == "" {
		rCrl = filepath.Join(stateDir(), "crl.pem")
	}
	if !filepath.IsAbs(rCrl) {
		rCrl = filepath.Join(stateDir(), rCrl)
	}
	rCrlRefresh := *crlrefresh
	if !set["crlrefresh"] && cfg != nil {
		rCrlRefresh = cfg.CrlRefresh
	}
	rCrlInterval := *crlinterval
	if !set["crlinterval"] && cfg != nil && cfg.CrlInterval > 0 {
		rCrlInterval = cfg.CrlInterval
	}
	if rCrlInterval <= 0 {
		rCrlInterval = defCrlPeriod
	}
	serverCert, serverKey, caCert := "server.crt", "server.key", "ca.crt"
	if cfg != nil {
		if cfg.ServerCert != "" {
			serverCert = cfg.ServerCert
		}
		if cfg.ServerKey != "" {
			serverKey = cfg.ServerKey
		}
		if cfg.CaCert != "" {
			caCert = cfg.CaCert
		}
	}
	if !filepath.IsAbs(serverCert) {
		serverCert = filepath.Join(stateDir(), serverCert)
	}
	if !filepath.IsAbs(serverKey) {
		serverKey = filepath.Join(stateDir(), serverKey)
	}
	if !filepath.IsAbs(caCert) {
		caCert = filepath.Join(stateDir(), caCert)
	}

	// --- src / live repos (legacy positional rules kept; config layers underneath) ---
	var liveRepos []string
	if set["live"] && *live {
		liveRepos = fs.Args() // explicit -live: the positional repos (pre-config behavior)
	} else if !*live && fs.NArg() > 0 && *src == "" {
		*src = fs.Arg(0) // legacy: first positional is the build src (also with explicit -live=false)
	}
	if len(liveRepos) == 0 && !set["live"] && cfg != nil && cfg.Live && *src == "" {
		liveRepos = cfg.LiveRepos // recorded by `build -git` or an earlier `daemon start -live …`
	}
	var sources []string
	if *src != "" {
		sources = []string{*src}
	} else if cfg != nil {
		sources = cfg.Sources
	}
	if *build && len(sources) == 0 {
		sources = []string{"."} // pre-config fallback: -build with nothing else means cwd
	}

	// --- at-rest store (encrypt-at-rest plan §Design): resolve the key (flag /
	// $KBTOOL_DBKEY / prompt), open the store (plain or encrypted), and refuse a
	// mixed state BEFORE serving. This fails before the pid file is written, so a
	// wrong key or inconsistent store leaves no state behind.
	st, err := openStore(dbFile, *keyEnv, *keyFile, true, true)
	if err != nil {
		fatal(err)
	}
	if err := st.checkConsistency(); err != nil {
		fatal(err)
	}

	_ = os.MkdirAll(stateDir(), 0755)
	writePidFile(name)
	socket := socketPath(name)

	// --- mTLS setup (fail closed: never serve insecure, plan decision 15) ---
	var tlsCfg *tls.Config
	crlStop := make(chan struct{})
	if rMtls {
		store := &crlStore{}
		var err error
		tlsCfg, err = cryptoServerTLSConfig(serverCert, serverKey, caCert, store)
		if err != nil {
			removePidFile(name)
			fatal(err)
		}
		go cryptoMonitorCRL(rCrl, rCrlRefresh, time.Duration(rCrlInterval)*time.Second, store, crlStop)
	}

	opts := BuildOpts{
		Sources: sources,
		Dim:     rDim, Chunk: rChunk, Overlap: rOverlap, MaxKB: rMaxKB,
		Git: rGit, GitMaxCommits: rGitMax, GitDiffMaxKB: rGitDiff,
		KWPath: &rKW,
	}
	db, err := loadOrBuildStore(st, opts, *build)
	if err != nil {
		removePidFile(name)
		fatal(err)
	}
	tb := newToolbox(db, liveRepos)
	tb.Store = st // at-rest persistence: every board/db save re-encrypts with the in-memory key

	// Auto-initialize the message board at startup when enabled (see
	// plans/new-message-board-initilization.md §2.1): the board (file, or bundle member when encrypted) +
	// welcome thread exist before the first agent signs up. Idempotent; a failure
	// is a warning (board calls still work — the first board_signup would create it).
	if cfg != nil && cfg.MessageBoard != nil && *cfg.MessageBoard {
		if err := ensureBoardReady(st); err != nil {
			fmt.Fprintf(os.Stderr, "%s: warning: message board init: %v\n", appName, err)
		} else {
			fmt.Fprintf(os.Stderr, "%s: message board ready at %s\n", appName, st.boardCarrier())
		}
	}

	// --- listen: unix socket always; TCP when -http (see
	// plans/http-support-with-mtls-auth-plan.md §4.1) ---
	os.Remove(socket)
	// bind() creates the socket file with 0777 & ~umask — world-connectable
	// under the usual umask 022 (srw-rw-rw-). The daemon socket carries the
	// full MCP API with no per-connection auth, so it must be owner-only
	// (plans/next-security-features.md §6/§12): set umask 0177 so the socket is
	// created srw------- (0600), then restore the prior umask immediately so
	// no other file creation is affected.
	umask := syscall.Umask(0177)
	ul, err := net.Listen("unix", socket)
	syscall.Umask(umask)
	if err != nil {
		os.Remove(socket)
		removePidFile(name)
		fatal(fmt.Errorf("unix listen %s: %v", socket, err))
	}
	if tlsCfg != nil {
		ul = tls.NewListener(ul, tlsCfg.Clone())
	}
	var httpSrv *http.Server
	var httpLn net.Listener
	if rHTTP {
		httpLn, err = net.Listen("tcp", rAddr) // bind check (IPv4/IPv6) before serving
		if err != nil {
			ul.Close()
			os.Remove(socket)
			removePidFile(name)
			fatal(fmt.Errorf("tcp listen %s: %v", rAddr, err))
		}
		httpSrv = &http.Server{
			Handler:           httpHandler(tb),
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig:         tlsCfg, // nil => cleartext HTTP/1.1
		}
	}

	errc := make(chan error, 2)
	go serveUnix(ul, tb, errc)
	if httpSrv != nil {
		go func() {
			if tlsCfg != nil {
				// ServeTLS wraps the listener and (Go ≥1.24) negotiates HTTP/2
				// via ALPN — it clones TLSConfig, so the unix listener above is
				// unaffected.
				errc <- httpSrv.ServeTLS(httpLn, "", "")
			} else {
				errc <- httpSrv.Serve(httpLn)
			}
		}()
	}
	desc := "unix " + socket
	if rHTTP {
		scheme := "http"
		if tlsCfg != nil {
			scheme = "https"
		}
		host, port, _ := net.SplitHostPort(rAddr)
		if host == "" {
			host = "*"
		}
		desc += fmt.Sprintf(" + %s://%s:%s", scheme, host, port)
	}
	if rMtls {
		desc += " [mtls]"
	}
	if st.enc {
		desc += " [encrypted store]"
	}
	if db != nil {
		fmt.Fprintf(os.Stderr, "%s %s: serving %d chunks on %s (pid %d)\n", appName, name, len(db.Chunks), desc, os.Getpid())
	} else {
		fmt.Fprintf(os.Stderr, "%s %s: board-only mode (no codebase db) on %s (pid %d)\n", appName, name, desc, os.Getpid())
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case s := <-sig:
		fmt.Fprintf(os.Stderr, "%s %s: received %v, shutting down\n", appName, name, s)
	case e := <-errc:
		if e != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "%s %s: server error: %v\n", appName, name, e)
		}
	}
	close(crlStop)
	if httpSrv != nil {
		_ = httpSrv.Close() // unblocks ServeTLS/Serve; connections drain
	}
	ul.Close()
	os.Remove(socket)
	removePidFile(name)
}

// bgStart spawns the service detached and waits for its socket.
func bgStart(name string, args []string) error {
	socket := socketPath(name)
	if socketAlive(socket) {
		fmt.Printf("%s %s already running (pid %d), socket %s\n", appName, name, pidFromPidfile(name), socket)
		return nil
	}
	_ = os.MkdirAll(stateDir(), 0755)
	logf, err := os.OpenFile(logPath(name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		logf.Close()
		return err
	}
	cmdArgs := append([]string{name, "run"}, args...)
	cmd := exec.Command(exe, cmdArgs...)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// At-rest key hand-off (encrypt-at-rest plan §Design): the detached child needs
	// the key to decrypt an encrypted store. Precedence:
	//   1. -db-key-env / -db-key-file in args  -> the child resolves them itself
	//   2. $KBTOOL_DBKEY already in the env    -> the child inherits it
	//   3. neither                             -> the parent (which owns the TTY)
	//      prompts with echo disabled and passes the key to the child via the
	//      KBTOOL_DBKEY env var ONLY — never argv, never config.json, never a file.
	if !argsHaveKeySource(args) {
		dbp := defaultDB()
		if fileExists(dbp) {
			if m, merr := fileMagic(dbp); merr == nil && m == bundleMagic && os.Getenv(dbKeyEnv) == "" {
				k, perr := promptSecret("db key: ")
				if perr != nil {
					logf.Close()
					return fmt.Errorf("encrypted store %s: cannot read a db key for the daemon: %v (pass -db-key-env/-db-key-file, export %s, or run interactively)", dbp, perr, dbKeyEnv)
				}
				if len(k) == 0 {
					logf.Close()
					return fmt.Errorf("encrypted store %s: db key is empty", dbp)
				}
				cmd.Env = append(os.Environ(), dbKeyEnv+"="+string(k))
			}
		}
	}
	if err := cmd.Start(); err != nil {
		logf.Close()
		return err
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	logf.Close()

	ok := false
	for i := 0; i < 200; i++ {
		if socketAlive(socket) {
			ok = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if ok {
		fmt.Printf("%s %s started (pid %d), socket %s\n", appName, name, pid, socket)
		return nil
	}
	// maybe still starting
	if p := pidFromPidfile(name); p > 0 && pidAlive(p) {
		fmt.Printf("%s %s starting (pid %d), socket %s\n", appName, name, p, socket)
		return nil
	}
	// The child died before its socket came up (e.g. the cleartext-HTTP guard,
	// plans/guard-against-plain-http-plan.md): surface its own error message inline.
	if tail := logTail(logPath(name), 12); tail != "" {
		fmt.Fprintln(os.Stderr, strings.TrimSpace(tail))
	}
	return fmt.Errorf("start failed; see log %s", logPath(name))
}

// argsHaveKeySource reports whether args explicitly carry a db-at-rest key source
// (-db-key-env NAME / -db-key-file PATH, either flag spelling), in which case the
// child process resolves the key itself (encrypt-at-rest plan §Design).
func argsHaveKeySource(args []string) bool {
	for _, s := range args {
		if s == "-db-key-env" || s == "-db-key-file" ||
			strings.HasPrefix(s, "-db-key-env=") || strings.HasPrefix(s, "-db-key-file=") {
			return true
		}
	}
	return false
}

// bgStop terminates the service (SIGTERM then SIGKILL) and cleans up.
func bgStop(name string) error {
	socket := socketPath(name)
	pid := pidFromPidfile(name)
	if !pidAlive(pid) {
		os.Remove(socket)
		removePidFile(name)
		fmt.Printf("%s %s not running (cleaned up stale files)\n", appName, name)
		return nil
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for i := 0; i < 50; i++ {
		if !pidAlive(pid) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if pidAlive(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	os.Remove(socket)
	removePidFile(name)
	fmt.Printf("%s %s stopped\n", appName, name)
	return nil
}

// bgStatus reports whether the service is up, and if so its kb_status.
func bgStatus(name string) {
	socket := socketPath(name)
	pid := pidFromPidfile(name)
	if socketAlive(socket) {
		fmt.Printf("%s: running (pid %d), socket %s\n", name, pid, socket)
		if text, _ := daemonClientForSocket(socket).Execute("kb_status", nil); text != "" {
			fmt.Println("  " + text)
		}
		return
	}
	fmt.Printf("%s: stopped\n", name)
}

// daemonClientForSocket builds an executor for a specific unix socket, TLS-wrapping
// it when client.json marks that socket for mTLS.
func daemonClientForSocket(socket string) executor {
	return &remoteExec{ep: unixEndpointFor(socket)}
}

// ---------- CLI commands ----------

// flagFirst moves flag tokens (and the value of value-taking flags) to the front so
// that flag.NewFlagSet.Parse handles them even when the user writes flags after a
// positional arg, e.g. `kbtool query "text" -k 5` or `kbtool build ./src -dim 512`.
func flagFirst(a []string, valueFlags map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(a); i++ {
		s := a[i]
		if len(s) > 1 && s[0] == '-' {
			flags = append(flags, s)
			name := s[1:]
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
				continue
			}
			if valueFlags[name] && i+1 < len(a) {
				i++
				flags = append(flags, a[i])
			}
		} else {
			pos = append(pos, s)
		}
	}
	return append(flags, pos...)
}

func doBuild(a []string) {
	a = flagFirst(a, map[string]bool{"dim": true, "chunk": true, "overlap": true, "maxkb": true, "db": true, "gitmaxcommits": true, "gitdiffmaxkb": true, "db-key-env": true, "db-key-file": true})
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	dim := fs.Int("dim", defDim, "embedding dimension")
	chunk := fs.Int("chunk", defChunk, "chunk size (lines)")
	overlap := fs.Int("overlap", defOverlap, "chunk overlap (lines)")
	maxkb := fs.Int("maxkb", defMaxKB, "max file size (KB)")
	git := fs.Bool("git", false, "index git history (commit messages + diffs) and bake a provenance summary into code chunks")
	gitmaxcommits := fs.Int("gitmaxcommits", defGitMaxCommits, "per-repo commit cap for -git history")
	gitdiffmaxkb := fs.Int("gitdiffmaxkb", defGitDiffMaxKB, "global byte cap (KB) on baked diff content")
	kwpath := fs.Bool("kwpath", true, "include path-leaf + kind tokens in the keyword index (default on; -kwpath=false disables)")
	dbp := fs.String("db", dbPath(), "output db file")
	// At-rest encryption (plans/encrypt-at-rest-db-and-message-board-plan.md §Design):
	// a resolved key writes the store as a KBX1 bundle (kb.db + the message board
	// inside, a pre-existing plain board.bin absorbed and removed); no key writes
	// a plain KBV1 db exactly as before. -encrypt prompts (hidden input) and wins
	// over the key-source flags. The key is held in memory only.
	keyEnv := fs.String("db-key-env", "", "DB-at-rest key from environment variable $NAME: write the store ENCRYPTED")
	keyFile := fs.String("db-key-file", "", "DB-at-rest key from file PATH: write the store ENCRYPTED")
	encrypt := fs.Bool("encrypt", false, "prompt for a DB-at-rest key (hidden input) and write the store ENCRYPTED")
	fs.Parse(a)
	var sources []string
	if fs.NArg() > 0 {
		sources = fs.Args()
	} else {
		sources = []string{"."}
	}
	opts := BuildOpts{
		Sources: sources, Dim: *dim, Chunk: *chunk, Overlap: *overlap, MaxKB: *maxkb,
		Git: *git, GitMaxCommits: *gitmaxcommits, GitDiffMaxKB: *gitdiffmaxkb,
		KWPath: kwpath,
	}
	// Resolve the at-rest key BEFORE the (expensive) build (encrypt-at-rest plan
	// §Design): -encrypt prompts; else -db-key-env NAME / -db-key-file PATH /
	// $KBTOOL_DBKEY; else nil (plain). A wrong key or an unkeyed encrypted store
	// fails here, before any work is done.
	var key []byte
	if *encrypt {
		k, perr := promptSecret("db key: ")
		if perr != nil {
			fatal(perr)
		}
		if len(k) == 0 {
			fatal(errors.New("db key is empty; refusing to create an encrypted store without a key"))
		}
		key = k
	} else {
		var have bool
		var rerr error
		key, have, rerr = resolveKey(*keyEnv, *keyFile, false)
		if rerr != nil {
			fatal(rerr)
		}
		if !have {
			key = nil
		}
	}
	st, err := openKBStore(*dbp, key)
	if err != nil {
		fatal(err)
	}
	if st.enc && st.key == nil {
		fatal(fmt.Errorf("%s is an encrypted store; provide its key to rebuild it (-db-key-env, -db-key-file, or -encrypt)", *dbp))
	}
	if key != nil {
		st.enc = true // a key always means encrypted output (existing plain store => promote)
		st.key = key
	}
	db, err := buildDB(opts)
	if err != nil {
		fatal(err)
	}
	if err := st.saveDB(db); err != nil {
		fatal(err)
	}
	if st.enc && fileExists(st.boardPath) {
		_ = os.Remove(st.boardPath) // absorbed into the bundle by saveDB
	}
	fi, _ := os.Stat(*dbp)
	sz := int64(0)
	if fi != nil {
		sz = fi.Size()
	}
	if st.enc {
		fmt.Printf("built %d source(s): %d chunks -> %s (%.1f KB, ENCRYPTED: KBX1 bundle with kb.db + message board)\n",
			len(sources), len(db.Chunks), *dbp, float64(sz)/1024)
	} else {
		fmt.Printf("built %d source(s): %d chunks -> %s (%.1f KB)\n", len(sources), len(db.Chunks), *dbp, float64(sz)/1024)
	}

	// Record the invocation (plans/kbtool-config-plan.md §4.2) so a bare `kbtool daemon
	// start` reproduces it: same sources, same build knobs, and — for a -git build —
	// live=true + the repo list (as git toplevels, so repoFor's basename label-match
	// works even when the build was invoked on a subdirectory).
	cfg := &config{
		Sources:       absolutized(sources),
		DB:            *dbp,
		Dim:           *dim,
		Chunk:         *chunk,
		Overlap:       *overlap,
		MaxKB:         *maxkb,
		Git:           *git,
		GitMaxCommits: *gitmaxcommits,
		GitDiffMaxKB:  *gitdiffmaxkb,
		KWPath:        kwpath,
	}
	if *git {
		cfg.Live = true
		for _, s := range sources {
			cfg.LiveRepos = append(cfg.LiveRepos, liveRepoPath(s))
		}
	}
	// Tool options (plans/new-tool-options-plan.md §4.2): once a user's value exists in
	// the file it is preserved verbatim — true, false, or any list, never
	// re-stamped with a default; when absent, seed it so the file documents which
	// tools are off.
	if prev := loadConfigWarned(); prev != nil {
		if prev.DisableTools != nil {
			cfg.DisableTools = prev.DisableTools
		}
		if prev.GitTools != nil {
			cfg.GitTools = prev.GitTools
		}
		if prev.MessageBoard != nil {
			cfg.MessageBoard = prev.MessageBoard
		}
		// Network / mTLS options survive a rebuild (see
		// plans/http-support-with-mtls-auth-plan.md decision 13): doBuild rebuilds the struct from scratch,
		// so the previous file's connection settings are copied across.
		cfg.Http = prev.Http
		cfg.Mtls = prev.Mtls
		cfg.HTTPAddr = prev.HTTPAddr
		cfg.CaCert = prev.CaCert
		cfg.ServerCert = prev.ServerCert
		cfg.ServerKey = prev.ServerKey
		cfg.CrlFile = prev.CrlFile
		cfg.CrlRefresh = prev.CrlRefresh
		cfg.CrlInterval = prev.CrlInterval
		// Path trust survives a rebuild (see
		// plans/constrain-file-ops-to-trusted-paths-plan.md §3.5): doBuild rebuilds the struct from scratch, so copy across.
		cfg.TrustedPaths = prev.TrustedPaths
		cfg.ForbiddenPaths = prev.ForbiddenPaths
	}
	ensureToolOptions(cfg)
	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "kbtool: warning: could not write config: %v\n", err)
	} else {
		fmt.Printf("config: wrote %s (a bare `kbtool daemon start` will use these options)\n", configPath())
	}
}

// oneShotToolbox loads the at-rest store (plain or encrypted; key resolved from
// -db-key-env / -db-key-file, or prompted when the store is encrypted) and returns
// a ready Toolbox over the indexed DB. Shared by the one-shot CLI commands
// (query, terms, bundle, call) so the direct-DB access path behaves identically.
func oneShotToolbox(dbp, keyEnv, keyFile string) (*Toolbox, error) {
	st, err := openStore(dbp, keyEnv, keyFile, true, true)
	if err != nil {
		return nil, err
	}
	if err := st.checkConsistency(); err != nil {
		return nil, err
	}
	if len(st.dbBytes) == 0 {
		return nil, fmt.Errorf("no daemon running and no db at %s; run 'kbtool build .' first", dbp)
	}
	db, err := st.db()
	if err != nil {
		return nil, err
	}
	tb := newToolbox(db, nil)
	tb.Store = st
	return tb, nil
}

// doTerms implements `kbtool terms <term> [-k N] [-json]` — the citable
// absence/presence census (plans/context-bundle-plan.md). Exit codes:
// 0 = present, 3 = ABSENT in indexed sources, 1 = error.
func doTerms(a []string) {
	a = flagFirst(a, map[string]bool{"k": true, "db": true, "db-key-env": true, "db-key-file": true})
	fs := flag.NewFlagSet("terms", flag.ExitOnError)
	k := fs.Int("k", termsDefaultMaxFiles, "max files to show (the true total is always reported)")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	dbp := fs.String("db", defaultDB(), "db file (used when daemon is down; default: config db)")
	keyEnv := fs.String("db-key-env", "", "DB-at-rest key from environment variable $NAME (when the store is encrypted)")
	keyFile := fs.String("db-key-file", "", "DB-at-rest key from file PATH (when the store is encrypted)")
	fs.Parse(a)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: kbtool terms <identifier-or-string> [-k N] [-json]")
		os.Exit(2)
	}
	term := strings.Join(fs.Args(), " ")
	args := mustMarshal(map[string]any{"term": term, "k": *k, "json": true})

	var text string
	var isErr bool
	if ex, sock, ok := liveDaemon(); ok {
		text, isErr = ex.Execute("kb_terms", args)
		fmt.Fprintf(os.Stderr, "(via daemon: %s)\n", sock)
	} else {
		tb, err := oneShotToolbox(*dbp, *keyEnv, *keyFile)
		if err != nil {
			fatal(err)
		}
		text, isErr = tb.Execute("kb_terms", args)
	}
	if isErr {
		fmt.Fprintln(os.Stderr, appName+": "+text)
		os.Exit(1)
	}
	var r termsResult
	if err := json.Unmarshal([]byte(text), &r); err != nil {
		fmt.Fprintln(os.Stderr, text)
		os.Exit(1)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Print(renderTerms(&r))
	}
	if !r.Present {
		os.Exit(3) // distinct, scriptable absence result (0 = present, 1 = error)
	}
}

// doBundle implements `kbtool bundle <file:line>` / `kbtool bundle -q QUERY`
// — context-bundle expansion of a known location or a query's top hits
// (plans/context-bundle-plan.md).
func doBundle(a []string) {
	a = flagFirst(a, map[string]bool{"q": true, "k": true, "db": true, "db-key-env": true, "db-key-file": true})
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	q := fs.String("q", "", "query text: bundle the top hits of this search (instead of a file:line target)")
	k := fs.Int("k", bundleDefaultHits, "hits to bundle when -q is used (default 3, max 8)")
	dbp := fs.String("db", defaultDB(), "db file (used when daemon is down; default: config db)")
	keyEnv := fs.String("db-key-env", "", "DB-at-rest key from environment variable $NAME (when the store is encrypted)")
	keyFile := fs.String("db-key-file", "", "DB-at-rest key from file PATH (when the store is encrypted)")
	fs.Parse(a)
	target := strings.Join(fs.Args(), " ")
	if *q == "" && target == "" {
		fmt.Fprintln(os.Stderr, "usage: kbtool bundle <file:line> | kbtool bundle -q \"query text\" [-k N]")
		os.Exit(2)
	}
	if *q != "" && target != "" {
		fatal(errors.New("bundle: give a file:line target OR -q, not both"))
	}
	args := mustMarshal(map[string]any{"target": target, "q": *q, "k": *k})
	var text string
	var isErr bool
	if ex, sock, ok := liveDaemon(); ok {
		text, isErr = ex.Execute("kb_bundle", args)
		fmt.Fprintf(os.Stderr, "(via daemon: %s)\n", sock)
	} else {
		tb, err := oneShotToolbox(*dbp, *keyEnv, *keyFile)
		if err != nil {
			fatal(err)
		}
		text, isErr = tb.Execute("kb_bundle", args)
	}
	if isErr {
		fmt.Fprintln(os.Stderr, text)
		os.Exit(1)
	}
	fmt.Println(text)
}

func printResults(res []Result, full bool) {
	if len(res) == 0 {
		fmt.Println("no matches")
		return
	}
	for i, r := range res {
		c := r.C
		fmt.Printf("%d. %s:%d-%d [%s] score=%.4f\n", i+1, c.Path, c.Start, c.End, c.Kind, r.Score)
		if full {
			fmt.Println(c.Text)
		} else {
			snip := strings.TrimSpace(clip(strings.ReplaceAll(c.Text, "\n", " "), 300))
			if snip != "" {
				fmt.Println("   " + snip)
			}
		}
		fmt.Println()
	}
}

func doQuery(a []string) {
	a = flagFirst(a, map[string]bool{"k": true, "min": true, "path": true, "kind": true, "db": true, "mode": true, "kw-w": true, "vec-w": true, "db-key-env": true, "db-key-file": true})
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	k := fs.Int("k", 8, "max results")
	min := fs.Float64("min", 0, "min dense-vector score (gates the vector channel only; 0 = off)")
	full := fs.Bool("full", false, "full chunk text")
	path := fs.String("path", "", "path substring filter")
	kind := fs.String("kind", "", "kind filter (code|doc|text|commit|diff)")
	mode := fs.String("mode", ModeHybrid, "search mode: hybrid|vector|keyword|weighted (default hybrid)")
	kwW := fs.Float64("kw-w", defWKeyword, "keyword weight for -mode weighted (default 0.6)")
	vecW := fs.Float64("vec-w", defWVector, "vector weight for -mode weighted (default 0.4)")
	bundle := fs.Bool("bundle", false, "expand each top hit into a context bundle (neighborhood, propagation, imports, tests) instead of listing snippets")
	dbp := fs.String("db", defaultDB(), "db file (used when daemon is down; default: config db)")
	keyEnv := fs.String("db-key-env", "", "DB-at-rest key from environment variable $NAME (when the store is encrypted)")
	keyFile := fs.String("db-key-file", "", "DB-at-rest key from file PATH (when the store is encrypted)")
	fs.Parse(a)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: kbtool query [-k N] [-min f] [-full] [-path sub] [-kind K] [-mode hybrid|vector|keyword|weighted] \"query text\"")
		os.Exit(2)
	}
	q := strings.Join(fs.Args(), " ")

	// -bundle (plans/context-bundle-plan.md): the same kb_bundle tool serves both
	// access paths, so the expansion is identical via daemon or direct DB.
	if *bundle {
		args := mustMarshal(map[string]any{"q": q, "k": *k})
		if ex, sock, ok := liveDaemon(); ok {
			text, isErr := ex.Execute("kb_bundle", args)
			if isErr {
				fmt.Fprintln(os.Stderr, text)
				os.Exit(1)
			}
			fmt.Println(text)
			fmt.Fprintf(os.Stderr, "(via daemon: %s)\n", sock)
			return
		}
		tb, err := oneShotToolbox(*dbp, *keyEnv, *keyFile)
		if err != nil {
			fatal(err)
		}
		text, isErr := tb.Execute("kb_bundle", args)
		if isErr {
			fmt.Fprintln(os.Stderr, text)
			os.Exit(1)
		}
		fmt.Println(text)
		return
	}

	// Prefer the daemon when it is up.
	if ex, sock, ok := liveDaemon(); ok {
		args := mustMarshal(map[string]any{
			"q": q, "k": *k, "min": *min, "full": *full, "path": *path, "kind": *kind,
			"mode": *mode, "weights": map[string]float64{"keyword": *kwW, "vector": *vecW},
		})
		text, _ := ex.Execute("search_codebase", args)
		fmt.Println(text)
		fmt.Fprintf(os.Stderr, "(via daemon: %s)\n", sock)
		return
	}

	// One-shot local search through the at-rest store (plain or encrypted; the key is
	// resolved from -db-key-env / -db-key-file, or prompted when the store is encrypted).
	st, err := openStore(*dbp, *keyEnv, *keyFile, true, true)
	if err != nil {
		fatal(err)
	}
	if err := st.checkConsistency(); err != nil {
		fatal(err)
	}
	if len(st.dbBytes) == 0 {
		fatal(fmt.Errorf("no daemon running and no db at %s; run 'kbtool build .' first", *dbp))
	}
	db, err := st.db()
	if err != nil {
		fatal(err)
	}
	// Message board (plans/message-board-plan.md §4): merge board messages into the
	// in-memory index so board content is searchable (kind=board) — via the store so
	// an encrypted board (inside the bundle) is merged too.
	tbq := newToolbox(db, nil)
	tbq.Store = st
	tbq.refreshBoard()
	res, err := db.SearchW(q, *k, *path, *kind, *min, *full, *mode, *kwW, *vecW)
	if err != nil {
		fatal(err)
	}
	printResults(res, *full)
}

func doTools(a []string) {
	fs := flag.NewFlagSet("tools", flag.ExitOnError)
	qwen := fs.Bool("qwen", false, "emit an OpenAI/Qwen function-calling 'tools' array")
	fs.Parse(a)
	// Hide config-disabled tools (plans/kbtool-preserve-config-plan.md §4.4): the CLI
	// tools list must match what the daemon will actually serve.
	disabled := loadDisabledSet()
	tools := toolSchemas()
	kept := tools[:0]
	for _, t := range tools {
		if !disabled[t.Name] {
			kept = append(kept, t)
		}
	}
	var v any
	if *qwen {
		v = qwenTools(kept)
	} else {
		v = kept
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

// doBench runs an in-process query benchmark: load the DB once, then run n
// deterministic synthetic queries (real identifier tokens drawn from the corpus) and
// report min/p50/p95/max latency. This measures pure query cost (no process spawn,
// no socket, no DB reload) — the honest way to check the tier-2 §10 target of
// p95 < 100 ms for N ≤ 50k chunks.
func doBench(a []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	dbp := fs.String("db", defaultDB(), "db file (default: config db)")
	n := fs.Int("n", 100, "number of queries to run")
	mode := fs.String("mode", ModeHybrid, "search mode: hybrid|vector|keyword|weighted")
	k := fs.Int("k", 8, "results per query")
	seed := fs.Int64("seed", 42, "RNG seed for the synthetic query pool (deterministic)")
	keyEnv := fs.String("db-key-env", "", "DB-at-rest key from environment variable $NAME (when the store is encrypted)")
	keyFile := fs.String("db-key-file", "", "DB-at-rest key from file PATH (when the store is encrypted)")
	fs.Parse(a)
	// At-rest store (plain or encrypted): resolve the key when the store is encrypted.
	st, err := openStore(*dbp, *keyEnv, *keyFile, true, true)
	if err != nil {
		fatal(err)
	}
	if err := st.checkConsistency(); err != nil {
		fatal(err)
	}
	if len(st.dbBytes) == 0 {
		fatal(fmt.Errorf("no db at %s; run 'kbtool build .' first", *dbp))
	}
	db, err := st.db()
	if err != nil {
		fatal(err)
	}
	if len(db.Chunks) == 0 {
		fatal(fmt.Errorf("db %s has no chunks", *dbp))
	}
	rng := rand.New(rand.NewSource(*seed))
	pool := benchQueries(db, 64, rng)
	if len(pool) == 0 {
		fatal(fmt.Errorf("could not derive a query pool from the corpus"))
	}
	// warmup (first query pays one-time map/slice allocations)
	if _, err := db.SearchW(pool[0], *k, "", "", 0, false, *mode, defWKeyword, defWVector); err != nil {
		fatal(err)
	}
	times := make([]time.Duration, 0, *n)
	for i := 0; i < *n; i++ {
		q := pool[i%len(pool)]
		t0 := time.Now()
		if _, err := db.SearchW(q, *k, "", "", 0, false, *mode, defWKeyword, defWVector); err != nil {
			fatal(err)
		}
		times = append(times, time.Since(t0))
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	pctl := func(p float64) time.Duration {
		idx := int(float64(len(times))*p+0.5) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(times) {
			idx = len(times) - 1
		}
		return times[idx]
	}
	fmt.Printf("bench: %d queries, mode=%s, chunks=%d, terms=%d\n", *n, *mode, len(db.Chunks), kwTermCount(db))
	fmt.Printf("  min=%v p50=%v p95=%v max=%v\n", times[0], pctl(0.5), pctl(0.95), times[len(times)-1])
}

func kwTermCount(db *DB) int {
	if db.KW == nil {
		return 0
	}
	return len(db.KW.Terms)
}

// benchQueries builds a deterministic pool of realistic queries: 1-3 real identifier
// tokens drawn from random chunk texts (exact-identifier style queries dominate real
// agent usage per the tier-2 plan).
func benchQueries(db *DB, size int, rng *rand.Rand) []string {
	var pool []string
	seen := map[string]bool{}
	for len(pool) < size && len(db.Chunks) > 0 {
		c := db.Chunks[rng.Intn(len(db.Chunks))]
		toks := tokenize(c.Text)
		if len(toks) == 0 {
			continue
		}
		m := 1 + rng.Intn(3) // 1-3 tokens
		var q []string
		for j := 0; j < m && len(toks) > 0; j++ {
			if t := toks[rng.Intn(len(toks))]; len(t) > 1 {
				q = append(q, t)
			}
		}
		if len(q) == 0 {
			continue
		}
		s := strings.Join(q, " ")
		if !seen[s] {
			seen[s] = true
			pool = append(pool, s)
		}
	}
	return pool
}

func doCall(a []string) {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	dbp := fs.String("db", defaultDB(), "db file (used when daemon is down; default: config db)")
	keyEnv := fs.String("db-key-env", "", "DB-at-rest key from environment variable $NAME (when the store is encrypted)")
	keyFile := fs.String("db-key-file", "", "DB-at-rest key from file PATH (when the store is encrypted)")
	fs.Parse(a)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: kbtool call <tool> ['{json args}']")
		os.Exit(2)
	}
	name := fs.Arg(0)
	argsRaw := []byte("{}")
	if fs.NArg() >= 2 {
		argsRaw = []byte(fs.Arg(1))
	}
	if !json.Valid(argsRaw) {
		fatal(fmt.Errorf("args must be valid JSON, got: %s", argsRaw))
	}

	if ex, sock, ok := liveDaemon(); ok {
		text, isErr := ex.Execute(name, argsRaw)
		fmt.Println(text)
		fmt.Fprintf(os.Stderr, "(via daemon: %s)\n", sock)
		if isErr {
			os.Exit(1)
		}
		return
	}

	// At-rest store (plain or encrypted): resolve the key (prompting when the store is
	// encrypted and no key flag was given) so one-shot db/board ops work daemon-down.
	st, err := openStore(*dbp, *keyEnv, *keyFile, true, true)
	if err != nil {
		fatal(err)
	}
	if err := st.checkConsistency(); err != nil {
		fatal(err)
	}
	var tb *Toolbox
	if len(st.dbBytes) > 0 {
		db, err := st.db()
		if err != nil {
			fatal(err)
		}
		tb = newToolbox(db, nil)
	} else if strings.HasPrefix(name, "board_") {
		tb = newToolbox(nil, nil) // board works without a codebase DB
	} else {
		fatal(fmt.Errorf("no daemon running and no db at %s; run 'kbtool build .' first", *dbp))
	}
	tb.Store = st
	text, isErr := tb.Execute(name, argsRaw)
	fmt.Println(text)
	if isErr {
		os.Exit(1)
	}
}

func doMCP(a []string) {
	// At-rest key flags for the stdio server (encrypt-at-rest plan §Design):
	// `kbtool mcp -db-key-env NAME`. Flags placed before the subcommand apply to
	// the stdio server; the subcommands (serve/run/start) parse their own copies.
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	keyEnv := fs.String("db-key-env", "", "DB-at-rest key from environment variable $NAME (when the store is encrypted)")
	keyFile := fs.String("db-key-file", "", "DB-at-rest key from file PATH (when the store is encrypted)")
	fs.Parse(a)
	rest := fs.Args()
	if len(rest) == 0 {
		ex, err := localExec("", *keyEnv, *keyFile)
		if err != nil {
			fatal(err)
		}
		if err := serveStdio(ex); err != nil {
			fatal(err)
		}
		return
	}
	sub := rest[0]
	rest = rest[1:]
	switch sub {
	case "serve", "run":
		daemonRun("mcp", rest)
	case "start":
		if err := bgStart("mcp", rest); err != nil {
			fatal(err)
		}
		// Record explicitly passed flags (plans/kbtool-config-plan.md §4.3); bare start is a no-op.
		if persistDaemonArgs(rest) {
			fmt.Printf("config: updated %s\n", configPath())
		}
		// Create client.json when absent so the local CLI finds the daemon endpoint
		// (plans/http-support-with-mtls-auth-plan.md §4.6).
		if p, ok := ensureClientConfigFromArgs(rest, filepath.Join(stateDir(), "mcp.sock")); ok {
			fmt.Printf("client: created %s\n", p)
		}
	case "stop":
		if err := bgStop("mcp"); err != nil {
			fatal(err)
		}
	case "status":
		bgStatus("mcp")
	default:
		fmt.Fprintln(os.Stderr, "usage: kbtool mcp [serve|start|stop|status]")
		os.Exit(2)
	}
}

func doDaemon(a []string) {
	if len(a) == 0 {
		fmt.Fprintln(os.Stderr, "usage: kbtool daemon run|start|stop|status")
		os.Exit(2)
	}
	sub, rest := a[0], a[1:]
	switch sub {
	case "run":
		daemonRun("daemon", rest)
	case "start":
		if err := bgStart("daemon", rest); err != nil {
			fatal(err)
		}
		// Record explicitly passed flags (plans/kbtool-config-plan.md §4.3); bare start is a no-op.
		if persistDaemonArgs(rest) {
			fmt.Printf("config: updated %s\n", configPath())
		}
		// Create client.json when absent so the local CLI finds the daemon endpoint
		// (plans/http-support-with-mtls-auth-plan.md §4.6).
		if p, ok := ensureClientConfigFromArgs(rest, filepath.Join(stateDir(), "daemon.sock")); ok {
			fmt.Printf("client: created %s\n", p)
		}
	case "stop":
		if err := bgStop("daemon"); err != nil {
			fatal(err)
		}
	case "status":
		bgStatus("daemon")
	default:
		fmt.Fprintln(os.Stderr, "usage: kbtool daemon run|start|stop|status")
		os.Exit(2)
	}
}

// ---------- kbtool mtls (local mTLS PKI — plans/http-support-with-mtls-auth-plan.md §4.2) ----------
//
// Generates a local ECDSA P-256 CA plus server and client leaf certificates
// under <stateDir>, records the serving options in config.json, and creates
// client.json when absent. All crypto primitives below carry the crypto
// prefix (house rule, plans/http-support-with-mtls-auth-plan.md §2).

// cryptoRandomSerial returns a random positive serial number below 2^159 (RFC 5280).
func cryptoRandomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	n, err := crand.Int(crand.Reader, limit)
	if err != nil || n.Sign() <= 0 {
		return big.NewInt(1)
	}
	return n
}

// cryptoGenerateCA creates a self-signed ECDSA P-256 CA certificate.
func cryptoGenerateCA(cn string, expire time.Duration) (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          cryptoRandomSerial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"kbtool"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(expire),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		fatal(err)
	}
	return key, cert
}

// cryptoGenerateLeaf signs a server or client leaf certificate with the CA,
// carrying the requested IP/DNS SANs.
func cryptoGenerateLeaf(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, cn string, ips []net.IP, dns []string, expire time.Duration) (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: cryptoRandomSerial(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"kbtool"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(expire),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  ips,
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		fatal(err)
	}
	return key, cert
}

// cryptoPEMCert encodes a certificate as PEM.
func cryptoPEMCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// cryptoPEMKey encodes an ECDSA private key as PEM.
func cryptoPEMKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// doMtls implements `kbtool mtls -ip … | -dns … [-expire 24h]`:
// creates ca.crt/ca.key, server.crt/server.key (with the SANs), client.crt/
// client.key under <stateDir>; sets http/mtls (+ bind address when exactly one
// IP is given) in config.json; and creates client.json when absent.
func doMtls(a []string) {
	fs := flag.NewFlagSet("mtls", flag.ExitOnError)
	ip := fs.String("ip", "", "comma-separated IP SANs (at least one of -ip/-dns required)")
	dns := fs.String("dns", "", "comma-separated DNS SANs (at least one of -ip/-dns required)")
	expire := fs.Duration("expire", 24*time.Hour, "CA/server/client certificate validity (e.g. 24h, 720h)")
	fs.Parse(a)

	var ips []net.IP
	if *ip != "" {
		for _, s := range strings.Split(*ip, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			p := net.ParseIP(s)
			if p == nil {
				fatal(fmt.Errorf("mtls: invalid -ip entry %q", s))
			}
			ips = append(ips, p)
		}
	}
	var names []string
	if *dns != "" {
		for _, s := range strings.Split(*dns, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			names = append(names, s)
		}
	}
	if len(ips) == 0 && len(names) == 0 {
		fatal(errors.New("mtls: at least one of -ip or -dns is required (comma-separated SAN entries)"))
	}
	if *expire <= 0 {
		fatal(errors.New("mtls: -expire must be > 0"))
	}

	sd := stateDir()
	if err := os.MkdirAll(sd, 0755); err != nil {
		fatal(err)
	}

	// Exactly one IP (and no DNS) => that IP is the daemon's TCP bind address
	// (plans/http-support-with-mtls-auth-plan.md §4.2); otherwise bind dual-stack so
	// DNS-name clients (any IPv4/IPv6 resolution) can reach the daemon.
	bindAddr := net.JoinHostPort("", strconv.Itoa(defHTTPPort)) // ":9876" — IPv4+IPv6
	if len(ips) == 1 && len(names) == 0 {
		bindAddr = net.JoinHostPort(ips[0].String(), strconv.Itoa(defHTTPPort))
	}

	caKey, caCert := cryptoGenerateCA("kbtool local CA", *expire)
	serverKey, serverCert := cryptoGenerateLeaf(caKey, caCert, "kbtool daemon", ips, names, *expire)
	clientKey, clientCert := cryptoGenerateLeaf(caKey, caCert, "kbtool client", nil, nil, *expire)

	files := map[string][]byte{
		"ca.crt":     cryptoPEMCert(caCert),
		"ca.key":     cryptoPEMKey(caKey),
		"server.crt": cryptoPEMCert(serverCert),
		"server.key": cryptoPEMKey(serverKey),
		"client.crt": cryptoPEMCert(clientCert),
		"client.key": cryptoPEMKey(clientKey),
	}
	for name, data := range files {
		p := filepath.Join(sd, name)
		mode := os.FileMode(0644)
		if strings.HasSuffix(name, ".key") {
			mode = 0600
		}
		if err := os.WriteFile(p, data, mode); err != nil {
			fatal(err)
		}
	}

	// Record the serving options in config.json (seed-or-preserve for the tool
	// options; only the network fields are stamped here).
	c := loadConfigWarned()
	if c == nil {
		c = &config{}
	}
	c.Http = true
	c.Mtls = true
	if bindAddr != "" {
		c.HTTPAddr = bindAddr
	}
	c.CaCert = "ca.crt"
	c.ServerCert = "server.crt"
	c.ServerKey = "server.key"
	c.CrlFile = "crl.pem"
	// CrlRefresh stays at its default (false: watch the file, no periodic reload).
	ensureToolOptions(c)
	if err := saveConfig(c); err != nil {
		fatal(err)
	}

	// 'kbtool mtls' creates client.json (plan §4.2): it regenerated the local
	// PKI, so the local client config must point at the new certs. The connect
	// name matches a SAN: a DNS name when given (portable for import on another
	// machine — that machine must resolve it), else the single bound IP.
	host, port := "", defHTTPPort
	if len(names) > 0 {
		host = names[0]
	} else if len(ips) == 1 {
		host = ips[0].String()
	}
	if err := saveClientConfig(&clientConfig{Version: 1, Host: host, Port: port,
		TLS:    true,
		CaCert: "ca.crt", ClientCert: "client.crt", ClientKey: "client.key"}); err != nil {
		fatal(err)
	}
	fmt.Printf("client: wrote %s (local CLI now uses the new mTLS setup)\n", clientConfigPath())
	fmt.Printf("mtls: CA + server + client certificates under %s (valid for %s)\n", sd, *expire)
	fmt.Printf("mtls: server SANs: ip=[%s] dns=[%s]\n", strings.Join(mapIps(ips), ","), strings.Join(names, ","))
	fmt.Printf("mtls: config %s: http=%v mtls=%v%s\n", configPath(), true, true, extraBind(bindAddr))
	fmt.Printf("mtls: now: kbtool daemon start -http -mtls   (or: kbtool daemon run -http -mtls)\n")
}

// mapIps renders []net.IP as strings (for display).
func mapIps(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, p := range ips {
		out = append(out, p.String())
	}
	return out
}

// extraBind renders the bind-address note for the doMtls summary ("" when unset).
func extraBind(bindAddr string) string {
	if bindAddr == "" {
		return ""
	}
	return ", http_addr=" + bindAddr
}

// ---------- kbtool client (encrypted client-setup bundle — plan §3.3/§4.3) ----------
//
//   -export [file] -key PASS  encrypt (tar.gz of ca.crt, client.crt, client.key,
//                              client.json) with PBKDF2-HMAC-SHA256 + AES-256-GCM
//   -import file  -key PASS   decrypt + extract into <stateDir> (never overwrites
//                              without -yes)
//
// Bundle layout: "KBX1" | version u16 LE | salt(16) | nonce(12) | GCM ciphertext.

// cryptoPbkdf2SHA256 implements PBKDF2 with HMAC-SHA256 (RFC 2898) — stdlib-only
// (crypto/pbkdf2 is not in the standard library).
func cryptoPbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	var out []byte
	block := 1
	for len(out) < keyLen {
		buf := make([]byte, len(salt)+4)
		copy(buf, salt)
		binary.BigEndian.PutUint32(buf[len(salt):], uint32(block))
		mac := hmac.New(sha256.New, password)
		mac.Write(buf)
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
		block++
	}
	return out[:keyLen]
}

// cryptoEncryptBundle encrypts plain under key:
// "KBX1" | version u16 LE | salt(16) | nonce(12) | AES-256-GCM ciphertext+tag.
func cryptoEncryptBundle(plain, key []byte) []byte {
	salt := make([]byte, 16)
	if _, err := crand.Read(salt); err != nil {
		fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err := crand.Read(nonce); err != nil {
		fatal(err)
	}
	block, err := aes.NewCipher(cryptoPbkdf2SHA256(key, salt, bundlePBKDF2, 32))
	if err != nil {
		fatal(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		fatal(err)
	}
	out := make([]byte, 0, 4+2+16+12+len(plain)+g.Overhead())
	out = append(out, bundleMagic...)
	var v [2]byte
	binary.LittleEndian.PutUint16(v[:], bundleVersion)
	out = append(out, v[:]...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = g.Seal(out, nonce, plain, nil)
	return out
}

// cryptoDecryptBundle reverses cryptoEncryptBundle; errors on bad magic,
// version, or a wrong passphrase (GCM auth failure).
func cryptoDecryptBundle(data, key []byte) ([]byte, error) {
	min := 4 + 2 + 16 + 12 + 16
	if len(data) < min {
		return nil, errors.New("bundle too short (not a KBX1 bundle?)")
	}
	if string(data[:4]) != bundleMagic {
		return nil, fmt.Errorf("bad bundle magic %q (want %q)", data[:4], bundleMagic)
	}
	ver := binary.LittleEndian.Uint16(data[4:6])
	if ver != bundleVersion {
		return nil, fmt.Errorf("unsupported bundle version %d (this kbtool has %d)", ver, bundleVersion)
	}
	salt := data[6 : 6+16]
	nonce := data[22 : 22+12]
	ct := data[34:]
	block, err := aes.NewCipher(cryptoPbkdf2SHA256(key, salt, bundlePBKDF2, 32))
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ct) < g.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	plain, err := g.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("decryption failed (wrong -key?)")
	}
	return plain, nil
}

// cryptoTarGZ packs the named files (tar name -> path on disk) into a tar.gz.
func cryptoTarGZ(files map[string]string) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		data, err := os.ReadFile(files[n])
		if err != nil {
			return nil, err
		}
		hdr := &tar.Header{Name: n, Mode: 0644, Size: int64(len(data)), ModTime: time.Now()}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// cryptoTarGZMem packs in-memory files (tar name -> bytes) into a tar.gz. It is the
// in-memory twin of cryptoTarGZ (which reads from disk): the at-rest store needs to
// pack byte slices it already holds (the serialized DB and board), not files on disk.
// Names are sorted for a deterministic archive (encrypt-at-rest plan §Design).
func cryptoTarGZMem(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		data := files[n]
		hdr := &tar.Header{Name: n, Mode: 0644, Size: int64(len(data)), ModTime: time.Now()}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// storeBundleFiles whitelists the tar members of the at-rest store bundle: only the
// knowledge base and the message board, by basename. Everything else is skipped, so a
// hand-crafted tar can never smuggle a path out of the bundle (mirrors bundleAllowed).
var storeBundleFiles = map[string]bool{
	"kb.db":     true,
	"board.bin": true,
}

// cryptoTarGZExtractMem extracts a tar.gz into a map (tar basename -> bytes), keeping
// only storeBundleFiles. It never touches the filesystem, so it is traversal-safe by
// construction (the at-rest counterpart of cryptoTarGZExtract).
func cryptoTarGZExtractMem(data []byte) (map[string][]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		if !storeBundleFiles[base] {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 512*1024*1024))
		if err != nil {
			return nil, err
		}
		out[base] = b
	}
	return out, nil
}

// fileMagic returns the first 4 bytes of p (the format tag: "KBV1" plain DB, "MBD1"
// plain board, or "KBX1" encrypted store bundle) so callers can tell the on-disk shape
// apart before committing to a read path (encrypt-at-rest plan §Design).
func fileMagic(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var head [4]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return "", err
	}
	return string(head[:]), nil
}

// bundleAllowed lists the file basenames an import may write (everything else
// in the tar is skipped) — the traversal-safe whitelist (plan §3.3).
var bundleAllowed = map[string]bool{
	"ca.crt":      true,
	"client.crt":  true,
	"client.key":  true,
	"client.json": true,
}

// cryptoTarGZExtract extracts the whitelisted files of a tar.gz into destDir.
// Only basenames in bundleAllowed are written (path traversal impossible);
// existing files are refused unless overwrite is true.
func cryptoTarGZExtract(data []byte, destDir string, overwrite bool) ([]string, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	var written []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		if !bundleAllowed[base] {
			fmt.Fprintf(os.Stderr, "%s: client: skipping bundled %q (not one of ca.crt, client.crt, client.key, client.json)\n", appName, hdr.Name)
			continue
		}
		target := filepath.Join(destDir, base)
		if !overwrite && fileExists(target) {
			return nil, fmt.Errorf("refusing to overwrite existing %s — re-run with -yes to replace it", target)
		}
		f, err := os.Create(target)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(f, io.LimitReader(tr, 64*1024*1024)); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		os.Chmod(target, 0600)
		written = append(written, target)
	}
	return written, nil
}

// ---------- at-rest store: encrypted kb.db + message board (encrypt-at-rest plan) ----------
//
// The at-rest knowledge base (the KBV1 vector DB and the MBD1 message board) is stored
// in one of two shapes:
//
//	plain      kb.db = KBV1 binary;   board = board.bin (MBD1) next to it
//	encrypted  kb.db = KBX1 bundle (PBKDF2+AES-256-GCM over a tar.gz) holding BOTH
//	           kb.db and board.bin; the key lives in process memory only
//
// kbStore is the single persistence authority for a command: every db/board load and
// save funnels through it so the two files can never drift out of sync (both encrypted
// or both plain). The key is never written to config.json, argv, or a file kbtool owns.

// dbKeyEnv is the internal hand-off variable `daemon start` sets for its detached
// `daemon run` child so the passphrase never appears on a command line. A user may
// also export it manually for one-shot commands.
const dbKeyEnv = "KBTOOL_DBKEY"

// promptSecret reads one line from the controlling terminal with echo disabled, so a
// passphrase typed for -encrypt / daemon startup is not visible on the screen or in the
// shell scrollback. It uses raw ioctl (TCGETS/TCSETS) — stdlib only, Linux, matching the
// project's existing syscall usage. If the input is not a tty (or the ioctl fails) it
// falls back to a plain read so non-interactive use still works.
func promptSecret(label string) ([]byte, error) {
	fmt.Fprint(os.Stderr, label)
	fd := int(os.Stdin.Fd())
	var old syscall.Termios
	hidden := false
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x5401 /* TCGETS */, uintptr(unsafe.Pointer(&old))); errno == 0 {
		now := old
		now.Lflag &^= syscall.ECHO
		if _, _, errno2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x5402 /* TCSETS */, uintptr(unsafe.Pointer(&now))); errno2 == 0 {
			hidden = true
		}
	}
	if hidden {
		fmt.Fprint(os.Stderr, "(hidden) ")
	}
	line, err := readLineTrim(os.Stdin)
	if hidden {
		// restore the terminal, and print a newline (the user's Enter was swallowed)
		syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x5402, uintptr(unsafe.Pointer(&old)))
		fmt.Fprintln(os.Stderr)
	}
	if err != nil {
		return nil, err
	}
	return []byte(line), nil
}

// readLineTrim reads a single line from r and trims surrounding whitespace/newline.
func readLineTrim(r io.Reader) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			c := buf[0]
			if c == '\n' {
				break
			}
			sb.WriteByte(c)
		}
		if err != nil {
			if err == io.EOF && sb.Len() > 0 {
				break
			}
			return strings.TrimSpace(sb.String()), err
		}
	}
	return strings.TrimSpace(sb.String()), nil
}

// resolveKey resolves the DB-at-rest key. Precedence (encrypt-at-rest plan §Design):
//
//  1. keyEnv  — name of an environment variable holding the key ($keyEnv)
//  2. keyFile — path to a file whose (trimmed) contents are the key
//  3. $KBTOOL_DBKEY — set by `daemon start` for the detached child (or exported by hand)
//  4. interactive prompt — only when allowPrompt is true
//
// Returns (key, haveKey, err). haveKey=false with err=nil means "no source applied";
// the caller decides whether a key is required for the operation.
func resolveKey(keyEnv, keyFile string, allowPrompt bool) ([]byte, bool, error) {
	if keyEnv != "" {
		v := os.Getenv(keyEnv)
		if v == "" {
			return nil, false, fmt.Errorf("-db-key-env %q: environment variable is empty or unset", keyEnv)
		}
		return []byte(v), true, nil
	}
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, false, fmt.Errorf("-db-key-file %q: %v", keyFile, err)
		}
		return bytes.TrimSpace(b), true, nil
	}
	if v := os.Getenv(dbKeyEnv); v != "" {
		return []byte(v), true, nil
	}
	if allowPrompt {
		k, err := promptSecret("db key: ")
		if err != nil {
			return nil, false, fmt.Errorf("prompt for db key: %v", err)
		}
		if len(k) == 0 {
			return nil, false, errors.New("db key is empty")
		}
		return k, true, nil
	}
	return nil, false, nil
}

// kbStore owns the at-rest KB (DB + board) for one command. See the section comment
// above for the two on-disk shapes. The key is held in memory only (st.key).
type kbStore struct {
	path      string // kb.db (plain KBV1 file or KBX1 bundle)
	boardPath string // plain-mode board file (board.bin); unused when enc
	enc       bool   // true when the on-disk state is the encrypted bundle
	key       []byte // in-memory passphrase (non-nil only when a key was supplied)
	dbBytes   []byte // serialized DB (immutable once built), cached at load time
}

// openKBStore inspects path and returns a store ready for that shape. When the file is
// an encrypted bundle and a key is supplied, it verifies the key by decrypting (a wrong
// key fails here, before any serving). With no key it still reports enc=true so
// `status` can describe the store; reading/writing then requires a key (see methods).
func openKBStore(path string, key []byte) (*kbStore, error) {
	st := &kbStore{path: path, boardPath: boardPath(), key: key}
	if !fileExists(path) {
		st.enc = key != nil // a key with no file yet => the store will be created encrypted
		return st, nil
	}
	m, err := fileMagic(path)
	if err != nil {
		return nil, err
	}
	switch m {
	case magic: // KBV1: plain DB
		st.enc = false
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		st.dbBytes = b
	case bundleMagic: // KBX1: encrypted store bundle
		st.enc = true
		if key == nil {
			return st, nil // no key: enc reported, contents unreadable (status-only)
		}
		dbB, _, err := readStoreBundle(path, key) // verifies the key; board read on demand
		if err != nil {
			return nil, err
		}
		st.dbBytes = dbB
	default:
		return nil, fmt.Errorf("%s: unrecognized format %q (want %q plain or %q encrypted)", path, m, magic, bundleMagic)
	}
	return st, nil
}

// readStoreBundle decrypts the KBX1 bundle at path and returns its serialized kb.db and
// board.bin members (either may be empty when absent). A wrong key surfaces here as a
// GCM authentication failure.
func readStoreBundle(path string, key []byte) (dbBytes, boardBytes []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	plain, err := cryptoDecryptBundle(data, key)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %v (wrong -db-key / key file?)", path, err)
	}
	files, err := cryptoTarGZExtractMem(plain)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: corrupt bundle: %v", path, err)
	}
	return files["kb.db"], files["board.bin"], nil
}

// db decodes the in-memory (or on-disk) DB. nil DB is legal (board-only mode).
func (st *kbStore) db() (*DB, error) {
	if len(st.dbBytes) == 0 {
		return nil, nil
	}
	return readDB(bytes.NewReader(st.dbBytes))
}

// boardExists reports whether a board is present (inside the bundle, or as board.bin).
func (st *kbStore) boardExists() bool {
	if st.enc {
		if st.key == nil {
			return false // cannot tell without a key
		}
		_, bb, err := readStoreBundle(st.path, st.key)
		return err == nil && len(bb) > 0
	}
	return fileExists(st.boardPath)
}

// boardMtime returns the modification time of the authoritative board carrier (the
// bundle in encrypted mode, board.bin in plain mode) for the mtime gate; ok=false when
// no board carrier exists yet. It is cheap (a single stat — no decryption).
func (st *kbStore) boardMtime() (time.Time, bool) {
	if st.enc {
		if fi, err := os.Stat(st.path); err == nil {
			return fi.ModTime(), true
		}
		return time.Time{}, false
	}
	if fi, err := os.Stat(st.boardPath); err == nil {
		return fi.ModTime(), true
	}
	return time.Time{}, false
}

// loadBoard returns the board, creating a fresh one when create && absent.
func (st *kbStore) loadBoard(create bool) (*Board, error) {
	if st.enc {
		if st.key == nil {
			if create {
				return newBoard(), nil
			}
			return nil, fmt.Errorf("board is encrypted; a key is required to read it (-db-key-env / -db-key-file)")
		}
		_, bb, err := readStoreBundle(st.path, st.key)
		if err != nil {
			return nil, err
		}
		if len(bb) == 0 {
			if create {
				return newBoard(), nil
			}
			return nil, fmt.Errorf("no board in the encrypted store yet (created at daemon start when message_board=true, or on first board_signup)")
		}
		return readBoard(bytes.NewReader(bb))
	}
	if _, err := os.Stat(st.boardPath); err != nil {
		if create {
			return newBoard(), nil
		}
		return nil, fmt.Errorf("board not found at %s — it is created at daemon start (message_board=true) or on first board_signup", st.boardPath)
	}
	return loadBoardFile(st.boardPath)
}

// currentBoardBytes returns the serialized current board (nil when absent), reading the
// authoritative on-disk copy (bundle or board.bin) so a rebuild carries the board over.
// When the store is (being) encrypted but the file at st.path is not yet a bundle
// (plain→encrypted promotion), the plain board.bin is the authoritative copy.
func (st *kbStore) currentBoardBytes() []byte {
	if st.enc {
		if fileExists(st.path) {
			if m, err := fileMagic(st.path); err == nil && m == bundleMagic {
				if st.key == nil {
					return nil
				}
				if _, bb, err := readStoreBundle(st.path, st.key); err == nil {
					return bb
				}
				return nil
			}
			// file at st.path is not a bundle (plain or hand-edited): fall through
			// to the plain board file below
		}
		if st.key == nil {
			return nil
		}
	}
	if !fileExists(st.boardPath) {
		return nil
	}
	b, err := loadBoardFile(st.boardPath)
	if err != nil {
		return nil
	}
	return boardMarshal(b)
}

// writeBundle packs {kb.db, board.bin?} into a tar.gz, encrypts it under st.key, and
// atomically writes it to st.path. This is the single encrypted-persist path: the board
// and DB are always stored together, so they cannot drift apart.
func (st *kbStore) writeBundle(dbB, boardB []byte) error {
	if st.key == nil {
		return errors.New("store is encrypted but no key is loaded")
	}
	files := map[string][]byte{"kb.db": dbB}
	if len(boardB) > 0 {
		files["board.bin"] = boardB
	}
	plain, err := cryptoTarGZMem(files)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(st.path), 0755); err != nil {
		return err
	}
	return atomicWrite(st.path, cryptoEncryptBundle(plain, st.key), 0600)
}

// saveBoard persists the board; in encrypted mode it re-bundles the (immutable) DB with
// the new board under the in-memory key (an empty DB is legal: board-only encrypted
// mode stores a bundle with an empty kb.db member). In plain mode it writes board.bin.
func (st *kbStore) saveBoard(b *Board) error {
	if st.enc {
		return st.writeBundle(st.dbBytes, boardMarshal(b))
	}
	return boardSave(st.boardPath, b)
}

// boardCarrier returns the on-disk file that holds the board (board.bin in plain mode;
// the encrypted bundle in enc mode) for display messages.
func (st *kbStore) boardCarrier() string {
	if st.enc {
		return st.path
	}
	return st.boardPath
}

// saveDB persists the DB (and, in encrypted mode, re-bundles the current board). It sets
// st.dbBytes so subsequent board saves reuse the same DB bytes without re-serializing.
func (st *kbStore) saveDB(db *DB) error {
	dbB := dbMarshal(db)
	st.dbBytes = dbB
	if st.enc {
		return st.writeBundle(dbB, st.currentBoardBytes())
	}
	if err := os.MkdirAll(filepath.Dir(st.path), 0755); err != nil {
		return err
	}
	return os.WriteFile(st.path, dbB, 0644)
}

// lock serializes board read-modify-write across processes (flock on a STABLE file).
// The lock file is stable per mode: board.bin.lock in plain mode, kb.db.lock in
// encrypted mode — so cross-process safety is unchanged by the at-rest encryption.
func (st *kbStore) lock() (func(), error) {
	if st.enc {
		return boardLock(st.path)
	}
	return boardLock(st.boardPath)
}

// checkConsistency enforces "both encrypted or both plain" (encrypt-at-rest plan §4):
// the daemon/mcp refuses to serve a mixed state (encrypted kb.db with a stray plain
// board.bin, or a plain kb.db with an encrypted board.bin).
func (st *kbStore) checkConsistency() error {
	if st.enc {
		if fileExists(st.boardPath) {
			return fmt.Errorf(
				"inconsistent store: %s is an encrypted bundle (the board lives INSIDE it) but a plain board file %s also exists; remove the stray board file (its contents are in the bundle) or rebuild cleanly",
				st.path, st.boardPath)
		}
		return nil
	}
	if fileExists(st.boardPath) {
		if m, err := fileMagic(st.boardPath); err == nil && m == bundleMagic {
			return fmt.Errorf(
				"inconsistent store: %s is a plain DB but the board file %s is an encrypted bundle; rebuild with a consistent (encrypted or plain) mode",
				st.path, st.boardPath)
		}
	}
	return nil
}

// openStore resolves the key (flags / $KBTOOL_DBKEY / prompt) and opens the store at
// dbPath. A key is resolved (and, when allowPrompt, a prompt offered) ONLY when the
// store is actually encrypted — a plain store never prompts. When the store is
// encrypted it REQUIRES a resolved key (fail closed) unless requireKey is false (used
// by `status`, which may merely describe an encrypted store without reading it).
func openStore(dbPath, keyEnv, keyFile string, allowPrompt, requireKey bool) (*kbStore, error) {
	enc := false
	if fileExists(dbPath) {
		if m, err := fileMagic(dbPath); err == nil {
			enc = (m == bundleMagic)
		}
	}
	key, haveKey, err := resolveKey(keyEnv, keyFile, allowPrompt && enc)
	if err != nil {
		return nil, err
	}
	st, err := openKBStore(dbPath, key)
	if err != nil {
		return nil, err
	}
	if st.enc && !haveKey && requireKey {
		return nil, fmt.Errorf("%s is an encrypted store; provide a key (-db-key-env, -db-key-file, or export %s)", dbPath, dbKeyEnv)
	}
	return st, nil
}

// doClient implements `kbtool client -export [file] -key PASS` /
// `kbtool client -import file -key PASS [-yes]`.
func doClient(a []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	export := fs.String("export", "", "export the client setup as an encrypted bundle; optional value = output file (default <state>/kbtool-client.kbx)")
	importF := fs.String("import", "", "import (decrypt + extract) an encrypted client bundle")
	key := fs.String("key", "", "bundle passphrase (required for -export and -import)")
	yes := fs.Bool("yes", false, "-import: overwrite existing files in <stateDir>")
	fs.Parse(a)

	doExp, doImp := *export != "", *importF != ""
	if doExp == doImp {
		fatal(errors.New("client: provide exactly one of -export [file] or -import <file>"))
	}
	if *key == "" {
		fatal(errors.New("client: -key is required (bundle passphrase)"))
	}

	sd := stateDir()
	if doExp {
		out := *export
		if out == "" {
			out = filepath.Join(sd, "kbtool-client.kbx")
		}
		files := map[string]string{
			"ca.crt":      filepath.Join(sd, "ca.crt"),
			"client.crt":  filepath.Join(sd, "client.crt"),
			"client.key":  filepath.Join(sd, "client.key"),
			"client.json": clientConfigPath(),
		}
		for n, p := range files {
			if !fileExists(p) {
				if n == "client.json" {
					// A working client.json is part of the bundle; synthesize the
					// default (local socket + mTLS names) when absent.
					if err := saveClientConfig(&clientConfig{
						Version:    1,
						UnixSocket: filepath.Join(sd, "daemon.sock"),
						TLS:        true,
						ServerName: "localhost",
						CaCert:     "ca.crt",
						ClientCert: "client.crt",
						ClientKey:  "client.key",
					}); err != nil {
						fatal(err)
					}
					continue
				}
				fatal(fmt.Errorf("client: %s is missing (run 'kbtool mtls' first)", p))
			}
		}
		plain, err := cryptoTarGZ(files)
		if err != nil {
			fatal(err)
		}
		bundle := cryptoEncryptBundle(plain, []byte(*key))
		if err := atomicWrite(out, bundle, 0600); err != nil {
			fatal(err)
		}
		fmt.Printf("client: exported %s (encrypted with your -key; send it + the passphrase to the target machine)\n", out)
		fmt.Printf("client: on the target:  kbtool client -import %s -key <pass> [-yes]\n", out)
		return
	}

	// -import
	if err := os.MkdirAll(sd, 0755); err != nil {
		fatal(err)
	}
	data, err := os.ReadFile(*importF)
	if err != nil {
		fatal(err)
	}
	plain, err := cryptoDecryptBundle(data, []byte(*key))
	if err != nil {
		fatal(fmt.Errorf("client: import %s: %v", *importF, err))
	}
	written, err := cryptoTarGZExtract(plain, sd, *yes)
	if err != nil {
		fatal(err)
	}
	for _, w := range written {
		fmt.Printf("client: wrote %s\n", w)
	}
	fmt.Println("client: import done — the local CLI now uses the imported setup (client.json, certs under " + sd + ")")
}

func doStatus(a []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	keyEnv := fs.String("db-key-env", "", "DB-at-rest key from environment variable $NAME (to read an encrypted store)")
	keyFile := fs.String("db-key-file", "", "DB-at-rest key from file PATH (to read an encrypted store)")
	fs.Parse(a)
	// Recorded build/daemon options (plans/kbtool-config-plan.md §4.5); loaded first so
	// the db line can honor the recorded -db path.
	c, cfgErr := loadConfig()
	dbp := dbPath()
	if cfgErr == nil && c != nil && c.DB != "" {
		dbp = c.DB
	}
	if fileExists(dbp) {
		if fi, err := os.Stat(dbp); err == nil {
			fmt.Printf("db: %s (%.1f KB)\n", dbp, float64(fi.Size())/1024)
		}
	} else {
		fmt.Printf("db: not found at %s\n", dbp)
	}
	// At-rest store state (encrypt-at-rest plan §4.6): describe the on-disk shape.
	// Never prompts (status is non-interactive); -db-key-env / -db-key-file /
	// $KBTOOL_DBKEY are honored when given so board stats can be read.
	st, stErr := openStore(dbp, *keyEnv, *keyFile, false, false)
	if stErr != nil {
		fmt.Printf("db key: %v\n", stErr)
		if st2, err2 := openKBStore(dbp, nil); err2 == nil {
			st = st2
		}
	}
	if st != nil && st.enc {
		if st.key != nil {
			fmt.Printf("at-rest:  ENCRYPTED (KBX1 bundle: kb.db + message board; key loaded)\n")
		} else {
			fmt.Printf("at-rest:  ENCRYPTED (KBX1 bundle: kb.db + message board; key required to read: -db-key-env / -db-key-file / %s)\n", dbKeyEnv)
		}
	}
	if cfgErr != nil {
		fmt.Printf("config: unreadable at %s (%v)\n", configPath(), cfgErr)
	} else if c == nil {
		fmt.Printf("config: not found at %s (run 'kbtool build …' to record daemon options)\n", configPath())
	} else {
		fmt.Printf("config: %s\n", configPath())
		fmt.Printf("  sources=%v git=%v live=%v liveRepos=%v\n", c.Sources, c.Git, c.Live, c.LiveRepos)
		fmt.Printf("  dim=%d chunk=%d overlap=%d maxKB=%d kwPath=%v db=%s updated=%s\n",
			c.Dim, c.Chunk, c.Overlap, c.MaxKB, kwPathStr(c), c.DB, c.Updated)
	}
	// MCP tool options + effective disabled set (plans/new-tool-options-plan.md §4.3):
	// computed from the same config load above (defaults apply when the fields
	// or the file are absent/corrupt).
	gt, bd, dt := "false (default)", "false (default)", "[kb_status, board_sign] (default)"
	if c != nil {
		if c.GitTools != nil {
			gt = strconv.FormatBool(*c.GitTools)
		}
		if c.MessageBoard != nil {
			bd = strconv.FormatBool(*c.MessageBoard)
		}
		if c.DisableTools != nil {
			dt = "[" + strings.Join(*c.DisableTools, ", ") + "]"
		}
	}
	fmt.Printf("tool options: git_tools=%s message_board=%s disable_tools=%s\n", gt, bd, dt)
	if names := sortedStringKeys(effectiveDisabledSet(c)); len(names) == 0 {
		fmt.Println("disabled tools: none (all tools enabled)")
	} else {
		fmt.Printf("disabled tools: %s\n", strings.Join(names, ", "))
	}
	// Path trust (plans/constrain-file-ops-to-trusted-paths-plan.md §3.6): what the
	// git tools may read, and the rule that always wins.
	trustedP, forbiddenP := "[] (absent)", "[] (absent)"
	if c != nil {
		if c.TrustedPaths != nil {
			trustedP = "[" + strings.Join(c.TrustedPaths, ", ") + "]"
		}
		if c.ForbiddenPaths != nil {
			forbiddenP = "[" + strings.Join(c.ForbiddenPaths, ", ") + "]"
		}
	}
	fmt.Printf("path trust:   trusted_paths=%s  forbidden_paths=%s\n", trustedP, forbiddenP)
	fmt.Println("  (git tools read only: -live repos + indexed git sources + trusted_paths; forbidden_paths always wins)")
	// Network / mTLS (plans/http-support-with-mtls-auth-plan.md §4.5): what the daemon
	// will serve, and what the local client config points at.
	httpOn, mtlsOn, insecureOn, addr, crl := false, false, false, "", ""
	if c != nil {
		httpOn, mtlsOn, insecureOn, addr, crl = c.Http, c.Mtls, c.HTTPAllowInsecure, c.HTTPAddr, c.CrlFile
	}
	if addr == "" {
		// Default bind (plans/guard-against-plain-http-plan.md): mtls -> dual-stack, else loopback.
		if mtlsOn {
			addr = fmt.Sprintf(":%d", defHTTPPort)
		} else {
			addr = fmt.Sprintf("127.0.0.1:%d", defHTTPPort)
		}
	}
	if crl == "" {
		crl = filepath.Join(stateDir(), "crl.pem")
	}
	if !httpOn && !mtlsOn {
		fmt.Println("network:  unix socket only (no -http / -mtls configured)")
	} else {
		fmt.Printf("network:  http=%v mtls=%v insecure=%v bind=%s crl=%s (exists=%v, refresh=%v)\n",
			httpOn, mtlsOn, insecureOn, addr, crl, fileExists(crl), c != nil && c.CrlRefresh)
	}
	if cc, err := loadClientConfig(); err == nil {
		what := ""
		if cc.UnixSocket != "" {
			what = "unix " + cc.UnixSocket
		} else {
			scheme := "http"
			if cc.TLS {
				scheme = "https"
			}
			what = fmt.Sprintf("%s://%s:%d", scheme, cc.Host, cc.Port)
		}
		if cc.TLS {
			what += " (mtls)"
		}
		fmt.Printf("client:   %s  (%s)\n", what, clientConfigPath())
	} else {
		fmt.Printf("client:   no client.json at %s\n", clientConfigPath())
	}
	if b := (&Toolbox{Store: st}).boardStats(); b != "" {
		fmt.Println(b)
	}
	for _, name := range []string{"daemon", "mcp"} {
		socket := socketPath(name)
		if socketAlive(socket) {
			fmt.Printf("%s: running (pid %d), socket %s\n", name, pidFromPidfile(name), socket)
		} else {
			fmt.Printf("%s: stopped\n", name)
		}
	}
}

func usage() { usageTo(os.Stdout) }

func usageTo(w io.Writer) {
	fmt.Fprint(w, `kbtool - code & documentation knowledge base (hybrid BM25+vector search, local embeddings, MCP)
          + signed multi-agent message board (topical threads, task delegation, confirmations)

Usage:
  kbtool build [opts] dirA dirB …        one or more source dirs (each may be a git repo)
        -git                    index git history (commit messages + diffs) + provenance summary
        -gitmaxcommits N        per-repo commit cap (default 200)
        -gitdiffmaxkb M         global byte cap on baked diffs (default 8000)
        -kwpath[=false]        include path-leaf + kind tokens in the keyword index (default on)
        -dim N -chunk N -overlap N -maxkb N -db OUT
        -db-key-env NAME       DB-at-rest key from $NAME: write the store ENCRYPTED
        -db-key-file PATH      DB-at-rest key from file PATH: write the store ENCRYPTED
        -encrypt               prompt for a DB-at-rest key (hidden input); ENCRYPTED store
  kbtool query "text" [-k N] [-min f] [-full] [-path sub] [-kind code|doc|text|commit|diff]
                       [-mode hybrid|vector|keyword|weighted] [-kw-w F] [-vec-w F] [-bundle]
                       [-db-key-env NAME | -db-key-file PATH]
        -mode                  hybrid (default) = BM25+vector rank fusion; vector = dense only;
                               keyword = BM25 only; weighted = weighted fusion
        -kw-w / -vec-w         fusion weights for -mode weighted (default 0.6 / 0.4)
        -bundle                expand each top hit into a context bundle instead of listing snippets
  kbtool terms <term> [-k N] [-json] [-db PATH]
                       [-db-key-env NAME | -db-key-file PATH]
        COMPLETE occurrence census of an exact identifier/string across the
        indexed source: per-file counts + representative lines. Absence is a
        citable result (distinct from 'present but didn't rank').
        Exit codes: 0 = present, 3 = ABSENT in indexed sources, 1 = error.
  kbtool bundle <file:line> | -q "query text" [-k N] [-db PATH]
                       [-db-key-env NAME | -db-key-file PATH]
        Context-bundle expansion: for a location (or a query's top hits) one
        consolidated read pack per hit — package neighborhood (sibling files +
        one-line summary), tree-wide literal/identifier propagation (stable
        fragments, so constructed strings surface), import verdicts (internal /
        external not-in-tree / unresolved — never a wrong verdict), and paired
        test files. See also: kbtool query "text" -bundle.
  kbtool bench -db PATH [-n N] [-mode M] [-db-key-env NAME | -db-key-file PATH]
                               in-process query benchmark (min/p50/p95/max)
  kbtool tools [-qwen]
  kbtool call <tool> ['{json args}'] [-db-key-env NAME | -db-key-file PATH]
  kbtool mcp [-db-key-env NAME | -db-key-file PATH]   MCP server over stdio (agent spawns it)
  kbtool mcp  serve|start [opts] [-live] [repo …] [-db-key-env NAME | -db-key-file PATH] | stop | status
  kbtool daemon run [opts] [-live] [repo …]      load the pre-built DB, serve (live repos for git_blame/git_log)
  kbtool daemon start [opts] [-live] [repo …]    | stop | status
  kbtool daemon start/run additionally: [-http] [-mtls] [-bind HOST:PORT]
                                         [-crl FILE] [-crlrefresh] [-crlinterval SEC]
                                         [-db-key-env NAME | -db-key-file PATH]
  kbtool mtls -ip 10.0.0.5 [-dns kb.local] [-expire 24h]
                                        generate the local mTLS PKI (CA + server + client certs),
                                        record http/mtls in config.json, create client.json (absent only)
  kbtool client -export [file] -key PASS         export an encrypted bundle of the client setup
  kbtool client -import file -key PASS [-yes]    decrypt + extract a bundle into <stateDir>
  kbtool status
  kbtool version (or -v / --version)       print the version and exit

  -live is a boolean: the paths that follow it are live git repos used by the
  git_blame/git_log tools (post-build state).
  [opts] = -src DIR -dim N -chunk N -overlap N -maxkb N -git -gitmaxcommits N
           -gitdiffmaxkb N -kwpath[=false] -db PATH   (run additionally: -build)

Options persist (see plans/kbtool-config-plan.md) — <stateDir>/config.json, hand-editable JSON:
  • kbtool build records its options; a -git build also records live=true + the git
    repo list, so a bare 'kbtool daemon start' starts with -live <repos>, and any
    daemon rebuild reuses the recorded -git/-dim/-chunk/-overlap/-maxkb/-kwpath/-db.
  • 'daemon start' / 'mcp start' additionally record the flags explicitly passed on
    that line (e.g. -live, -src, -db); 'daemon run' never writes.
  • Precedence: explicit flag > config > default. 'kbtool status' shows the file.

MCP tools — enabled/disabled by options in config.json (plans/new-tool-options-plan.md):
  • Group options (default false — off until you set them true):
        git_tools     enables the git tools: git_blame, git_log
        message_board enables the message board tools: board_signup, board_whoami,
                      board_sign, board_post, board_read, board_threads,
                      board_search, board_confirm
  • disable_tools is a list of tool names — a per-tool kill switch that is ALWAYS
    honored, even over the group options: add a name (even a core one) to disable
    it, remove it to re-enable; [] disables nothing (default ["kb_status", "board_sign"]).
  • A tool is served when its group option is on AND its name is not in
    disable_tools. Enabled by default: search_codebase, get_chunk, list_files,
    kb_terms, kb_bundle.
  • Path trust (plans/constrain-file-ops-to-trusted-paths-plan.md): the git tools
    (git_blame/git_log) may read only inside the trusted set = -live repos +
    indexed git sources + trusted_paths (config). forbidden_paths (config)
    ALWAYS wins over trusted — it can forbid a default-trusted repo or a
    subpath of a trusted path. 'kbtool status' and kb_status report the set.
  • Once present in config.json, git_tools / message_board / disable_tools are NEVER
    overwritten by kbtool CLI writes (build / daemon start / mcp start); absent
    options are seeded (false / false / ["kb_status", "board_sign"]) so the file documents the
    state.
  • 'kbtool tools', MCP tools/list, and the initialize instructions only show
    enabled tools; disabled tools are refused at tools/call with an explanation.
  • 'kbtool status' reports the options and the effective disabled set.

Message board (AI-agent collaboration; see plans/message-board-plan.md +
plans/new-message-board-initilization.md).
  Signed, append-only, multi-thread; works standalone (no codebase DB needed).
  Auto-initialized at daemon start when message_board=true (board file + welcome
  thread); in one-shot mode the first board_signup creates it.
  Every board call takes the seed as the credential — kbtool never stores the seed
  and it can never be retrieved, so store it on YOUR disk (shell tool) right away.
  Invoke via MCP tools/call or:  kbtool call <board_tool> '{"…"}'
    board_signup  {"name"}                     sign up: choose a name, get a private 64-hex seed
    board_whoami  {"seed"}                     which identity is this seed? (your signup name)
    board_sign    {"seed","text"}               sign text with the seed (returns pubkey + ed25519 sig)
    board_post    {"thread","text","seed","kind","refs","task"}
                  post a signed message (append-only); new thread id creates the thread
    board_read    {"thread","after","limit","seed"}
                  read a thread in order; each message shows author + verification status
    board_threads {"seed"}                      list threads + agent roster (ACTIVE/STALE)
    board_search  {"q","k","thread","seed"}     semantic search across ALL board messages
    board_confirm {"seed"}                      confirm liveness + show who is ACTIVE now
  Flow: board_signup (keep the seed private, store on disk with a shell command) →
  post a kind=hello intro in 'welcome' → delegate kind=task / collect kind=result
  (task='<thread>#<seq>') → trust only messages whose status is 'verified' AND whose
  author you expect.

Client/server networking (plans/http-support-with-mtls-auth-plan.md):
  • Default: the daemon serves ONLY its unix socket (<state>/daemon.sock or mcp.sock;
    KBTOOL_SOCKET overrides). The CLI finds it automatically.
  • 'daemon start -http' additionally serves TCP (IPv4 and/or IPv6, -bind HOST:PORT):
    GET /healthz + POST /mcp (JSON-RPC). With -mtls it is TLS (HTTP/2 negotiated via
    ALPN); -mtls requires client certs — run 'kbtool mtls' first.
  • Cleartext-HTTP guard (plans/guard-against-plain-http-plan.md): a NON-loopback -http
    bind is REFUSED unless -mtls or -http-allow-insecure is set. Default bind is
    127.0.0.1:9876 without -mtls (loopback = local trust) and :9876 (dual-stack) with
    -mtls. So: '-http' alone → loopback only; remote cleartext needs the explicit
    '-http-allow-insecure' (loudly warned); remote secure access needs '-mtls'.
  • CRL: <state>/crl.pem, when present, is enforced at the TLS handshake (revoked
    client certs are rejected). crl_refresh=false (default): the file is WATCHED for
    changes; crl_refresh=true: reloaded every crl_interval seconds (default 60).
    A missing CRL file is fine (= no revocation data).
  • client.json (created when absent by 'daemon start -http|-mtls' and 'kbtool mtls')
    tells the local CLI where to reach the daemon: unix_socket or host:port, with
    tls=true + ca/client cert names for mTLS. 'kbtool client -export/-import'
    moves a working client setup between machines (PBKDF2 + AES-256-GCM bundle).

Environment:
  KB_EMBED_URL / KB_EMBED_KEY / KB_EMBED_MODEL   remote OpenAI-compatible embeddings
  KBTOOL_DIR                                     state dir (default ~/.config/kbtool;
                                                 config.json lives here too)
  KBTOOL_DB                                      db file (default <state>/kb.db)
  KBTOOL_SOCKET                                  daemon socket override
  KBTOOL_BOARD                                   message board file (default <dir-of-db>/board.bin)
  KBTOOL_BOARD_TTL                               seconds an agent stays ACTIVE after last-seen (default 120)
  KBTOOL_DBKEY                                   db-at-rest key hand-off: set by "daemon start" for
                                                 its child; also honored directly by one-shot commands
                                                 (precedence: -db-key-env > -db-key-file > $KBTOOL_DBKEY > prompt)

At-rest encryption (plans/encrypt-at-rest-db-and-message-board-plan.md):
  • With a key, "kbtool build" writes kb.db as a KBX1 bundle — the same symmetric
    format as "kbtool client -export" (PBKDF2-HMAC-SHA256 + AES-256-GCM over a
    tar.gz) — holding BOTH the KBV1 database and the MBD1 message board inside.
    Without a key the store stays plain (kb.db + board.bin), exactly as before.
  • DB and board are always both encrypted or both plain; the daemon refuses a
    mixed state. While it runs, the key lives only in process memory and every
    board/db save is re-encrypted with it. The key is never written to
    config.json, argv, or any file kbtool owns.
  • "daemon start" prompts (hidden input) for the key when the store is encrypted
    and no -db-key-env/-db-key-file was given, and passes it to the detached
    child via $KBTOOL_DBKEY only. "daemon run" / one-shot commands prompt (TTY)
    or accept the key flags; "kbtool mcp" (stdio) never prompts — it reads the
    key from -db-key-env / -db-key-file / $KBTOOL_DBKEY or fails closed.
  • "kbtool status" reports the store's shape (encrypted: key required to read)

Examples:
  kbtool build /path/to/repoA /path/to/repoB
  kbtool build -git /path/to/repoA            # include git history + provenance; records daemon options
  kbtool query "how do we parse config"        # hybrid (BM25 + vector) by default
  kbtool query "TokenBucketLimiter" -mode keyword
  kbtool query "how do we parse config" -mode vector
  kbtool call search_codebase '{"q":"error handling","k":5,"kind":"commit"}'
  kbtool daemon start                       # bare start: uses the last build's recorded options
  kbtool daemon start -live /path/to/repoA  # …or override + re-record explicit flags
  kbtool call git_blame '{"file":"repoA/pkg/util.go"}'
  kbtool call git_log '{"repo":"repoA","n":20}'
  kbtool mcp   # for an MCP client / Qwen 3.8 agent
  kbtool call board_signup '{"name":"alice"}'
  kbtool call board_post '{"thread":"welcome","kind":"hello","text":"I'm alice, a code reviewer.","seed":"<64-hex>"}'
  kbtool call board_post '{"thread":"research-auth","kind":"task","text":"Research how tokens refresh.","seed":"<64-hex>"}'
  kbtool call board_read '{"thread":"research-auth","seed":"<64-hex>"}'
  kbtool call board_whoami '{"seed":"<64-hex>"}'
  kbtool call board_confirm '{"seed":"<64-hex>"}'
`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, appName+":", err)
	os.Exit(1)
}

// printVersion writes the CLI version to w (kbtool version / -v / --version).
func printVersion(w io.Writer) {
	fmt.Fprintln(w, appName, "version", appVer)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, rest := os.Args[1], os.Args[2:]
	switch cmd {
	case "build":
		doBuild(rest)
	case "query", "search":
		doQuery(rest)
	case "terms":
		doTerms(rest)
	case "bundle":
		doBundle(rest)
	case "bench":
		doBench(rest)
	case "tools":
		doTools(rest)
	case "call":
		doCall(rest)
	case "mcp":
		doMCP(rest)
	case "daemon":
		doDaemon(rest)
	case "mtls":
		doMtls(rest)
	case "client":
		doClient(rest)
	case "status", "stats":
		doStatus(rest)
	case "version", "-v", "--version":
		printVersion(os.Stdout)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		usage()
		os.Exit(2)
	}
}
