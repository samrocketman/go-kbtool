# AGENTS.md — go-kbtool (`kbtool`)

AI-agent and contributor instructions for this repository. Read this before
touching any code.

## What this project is

`kbtool` is a single-binary Go tool: a code & documentation knowledge base
(hybrid BM25 + local-hash vector search), an MCP server, a signed multi-agent
message board, at-rest DB encryption, and an mTLS/HTTP daemon. It is
deliberately a **one-file, zero-dependency** program.

```
kbtool.go          ALL production code (package main, ~8k lines)
message_board.gohtml  html/template for `kbtool board dump`, embedded via //go:embed
collaboration.md.gotmpl  text/template for AGENTS_COLLABORATION.md (`kbtool collaborate`), embedded via //go:embed
kbtool_test.go     ALL tests (package main, ~4.3k lines, 200+ tests)
.goreleaser.yaml   cross-compile + release packaging (linux/darwin/windows)
.github/workflows/ ci.yml (PR gate) + release.yml (auto semver tag + publish)
Makefile           lint / test / release / release-snapshot targets
docs/              per-subcommand docs: <cmd>-simple.md ↔ <cmd>.md pairs
plans/             implementation plans (one per feature), written BEFORE work
go.mod             `module kbtool`, go 1.21 — NO dependencies, ever
```

## Hard requirements (breaking any of these is a bug)

1. **Single-command build.** The entire tool must always compile with:
   `go build -o kbtool kbtool.go`
   All non-test code lives in `kbtool.go` — the ONLY non-test `.go` file in
   the package. Never split it into multiple files, never add a `pkg/`
   directory, never vendor code. Enforced by
   `TestSingleFilePackage` / `TestSingleCommandBuild`.

   **Exceptions: `message_board.gohtml` and `collaboration.md.gotmpl`** are
   the only allowed additional build inputs. `message_board.gohtml` is the
   `html/template` for `kbtool board dump`; `collaboration.md.gotmpl` is the
   `text/template` that `kbtool collaborate` renders into
   AGENTS_COLLABORATION.md (converted from the collaborative planning
   workspace's AGENTS.md). Neither is Go code; both are compiled into the
   binary with `//go:embed` from `kbtool.go` and must never be read from
   disk at runtime or shipped as separate release assets. They must sit next
   to `kbtool.go` so the single build command still works, and each must
   stay covered by a test that runs the binary built with that command from
   a directory without the template. Do not add other embedded or non-`.go`
   build inputs without the owner's approval.
2. **Go standard library only.** No third-party modules, no `go.sum`.
   `go.mod` must remain dependency-free. If a feature seems to need an
   external library, inline a minimal stdlib implementation instead (as was
   done for argon2/chacha20-style crypto in sibling projects).
3. **All tests are Go, all in one file.** Tests live in `kbtool_test.go`
   only — no separate `*_test.go` files, no shell-based test scripts.
   Tests are hermetic: temp dirs, no network, no global state; tests that
   need an external tool (`git`, `go`) skip when it is absent.
4. **Supported platforms only.** Targets: linux × amd64/386/arm(6,7)/arm64,
   darwin × amd64/arm64, windows × amd64/386/arm64. `osCompatSupportedPlatform`
   lists exactly this matrix, and a compile-time guard makes every other
   GOOS/GOARCH fail to build ("duplicate key false in map literal"), so nobody
   ships a binary without equivalent support. Adding a platform means adding
   it to that constant, its `osCompat*` implementation (kernel constants
   checked against Go's `zsysnum_*`/`zerrors_*`/`ztypes_*` tables) and
   `.goreleaser.yaml` together. All platform-specific code follows the
   `osCompat*` rules under Conventions.

## Conventions

### Code
- `gofmt -l .` must output nothing; `go vet ./...` must pass. Run both before
  committing.
- **Function prefixes.** Two families of functions are named by what they do:
  - `crypto*`: functions whose job is cryptography — key derivation,
    signing and verification, AEAD, certificate and CA generation, CRLs, TLS
    configs, and the encrypted bundle and tar helpers (e.g.
    `cryptoDeriveSeed`, `cryptoServerTLSConfig`, `cryptoEncryptBundle`).
  - `osCompat*`: everything that differs by operating system. Build tags
    would break the single-file rule, so every `osCompat` function compiles
    on every platform and branches on `runtime.GOOS`:
    - `osCompat<Name>` is the entry point the rest of the code calls;
    - `osCompatLinux*`, `osCompatMacos*` and `osCompatWindows*` hold what
      differs per OS;
    - `osCompatUnix*` is the single native implementation Linux and macOS
      share, driven by their `osCompatUnixABI` (`osCompatLinuxABI` /
      `osCompatMacosABI`).

    Linux and macOS make the native kernel calls (`flock`, `umask`, `kill`,
    termios ioctls, `O_NOFOLLOW`) through `osCompatSyscall`. Windows is the
    only portable implementation, used only when explicitly chosen. Never use
    a platform-specific `syscall` symbol (`syscall.Flock`, `Setsid`,
    `Termios`, …) outside `osCompat*`. Any such symbol breaks the build for
    the other platforms.
- `appVer` (the CLI version) is a **`var`**, not a const — it must stay
  injectable via `-ldflags "-X main.appVer=<version>"` (GoReleaser does this
  for every release). It must be plain `MAJOR.MINOR.PATCH` (no `v` prefix,
  no suffixes). Initial/default version is `0.1.0`.
- `kbtool version` / `-v` / `--version` all print exactly
  `kbtool version <ver>` on one line (enforced by tests).
- `usage()` writes through `usageTo(io.Writer)` so tests can capture it;
  keep user-facing command output testable that way when adding features.
- Backwards compatibility is **NOT** a constraint — even after release. The
  databases are meant to be short-lived and are rebuilt before any complex
  task, so on-disk formats, flags, and options may evolve freely. This is an
  alpha tool: write no migration code, no format compatibility shims and no
  deprecation warnings.

### Tests
- Append to `kbtool_test.go` under a **new numbered group** with a
  `// ---------- N. <name> ----------` header, and add the group to the
  numbered list in the file's header comment (groups 1–51 currently).
- Every test should have a comment explaining *why* it exists (what
  regression it pins). This repo's owner may rewrite tests later from those
  notes.
- Prefer direct function-level tests over spawning the binary; use
  `t.TempDir()`, in-memory data, and the existing helper functions.
- The doc-consistency tests (group 22) enforce: README links to every
  `docs/<cmd>-simple.md`, and simple/full doc pairs cross-link each other.
  Keep that true when adding subcommands or docs.

### Documentation & plans
- README, `docs/` and the CLI help text are written for **macOS and Linux**.
  Leave Windows quirks out of them (stop-request files instead of signals,
  PowerShell passphrase prompts, lock-file emulation, missing `SIGHUP`, path
  or shell differences). Windows behavior is documented only in the
  `osCompatWindows*` code comments.
- README, `docs/` and the CLI help text describe **only the current
  behavior**. When a change alters behavior, rewrite the affected text as if
  it had always worked this way:
  - no "breaking change", "migration", "previously", "no longer", "was
    renamed" or "removed in" notes, and no instructions for upgrading old
    setups;
  - no references to `plans/` (plans are internal implementation history,
    not user documentation);
  - update every page that mentions the changed command, flag, file or
    config field in the same change, simple and full pages alike.
- Before implementing a feature, write `plans/<feature>-plan.md` describing
  goals, files touched, design decisions, and a verification section.
- Before committing, update that plan with a **Summary** and a **Test
  record** (what was tested, why each test exists, what was verified, and
  what could only be verified in CI).
- `plans/research/` is irrelevant historical research — ignore it.
- `plans/next-security-features.md` is an audit draft for the owner to turn
  into future plans — do not implement from it.

### Release pipeline (do not regress)
- `.goreleaser.yaml`: `CGO_ENABLED=0`, matrix exactly per §Hard requirement 4,
  ldflags `-s -w -X main.appVer={{ .Version }}`, binary-format archives
  named `kbtool-<os>-<arch>` (i386/armvN aliases), `checksums.txt`,
  `prerelease: auto`, changelog excludes `^docs:`/`^test:`.
- `release.yml`: push to `main` (or `workflow_dispatch` with a bump choice)
  → change detection → `make test` → gofmt/vet → semver bump → tag →
  `goreleaser release`. Bump defaults to patch; PR labels
  `release:major` / `release:minor` override; **no-tags case must emit
  v0.1.0** (the initial release), not v0.0.1.
- `ci.yml`: PR gate = tests + lint + goreleaser snapshot build uploaded as
  `kbtool-binaries` artifacts. Actions are pinned by full SHA — keep them
  pinned (and pinned in lockstep with
  `home-assistant-decrypt-backup`'s pins when upgrading).
- Local release rehearsal: `make release-snapshot` (or
  `goreleaser build --snapshot --clean`); full `goreleaser build` needs a git
  remote (CI-only).
- The Makefile is the single entry point used by the workflows (`make test`,
  `make lint`, `make release-snapshot`, `make release`) — keep those targets.

### Git
- This directory is its own git repository. Never initialize a git repo in
  the parent directory (`/home/ubuntu/projects`) — repos live in child
  folders.
- Commit messages: imperative subject, one line; detail in the body.
  Feature work is committed together with its updated plan.
- `.gitignore` excludes the built `kbtool` binary and `dist/` — keep it.

## Common commands

```sh
go build -o kbtool kbtool.go     # the canonical build (hard requirement)
./kbtool version                 # -> kbtool version 0.1.0
go test ./...                    # full hermetic suite
go test -run 'TestName' -v ./... # one test
gofmt -l . && go vet ./...       # must both be clean
make test | make lint            # same as above (workflow entry points)
make release-snapshot            # goreleaser snapshot build into dist/
```

## Environment facts

- Go 1.21+ (module declares 1.21); tested with 1.27.
- `goreleaser` is not installed by default; fetch a release binary to
  rehearsal-test releases.
- No remote is configured locally; push/tag operations happen on GitHub.
