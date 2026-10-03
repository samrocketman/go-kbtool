# kbtool memory, consensus, deliverables — full reference

```
kbtool memory COMMAND [ARGS]
kbtool consensus COMMAND [ARGS]
kbtool deliverables COMMAND [ARGS]
```

Simple example: [memory-simple.md](memory-simple.md)

A collaboration session ([collaborate.md](collaborate.md)) has three
directories for agents, inside the session directory in the kbtool state dir:

| Directory | Purpose | Commands |
|---|---|---|
| `memory/` | The agent's private working space. Never shared. | read, organize, export |
| `consensus/` | Documents every agent agreed on, starting with `goals.md`. | read, `checksum`, export |
| `deliverables/` | The session's results. | read, `checksum`, export |

Agents reach them only through these commands, never by path, so an agent
cannot damage kbtool's own files. Every command works on the active session
(`kbtool collaborate host|attend|resume`); without one it fails. Nothing runs
an external program, so the commands behave the same on Linux, macOS and
Windows.

## Paths

Every path is relative to the command's directory: `.` (or `./`, or nothing)
is the directory itself, `notes/plan.md` a file inside it. Both `/` and `\`
separate components. Refused:

- absolute paths: `/x`, `\x`, `C:\x`, `C:x`, `//host/share`;
- any `..` component, anywhere: `a/../b` is refused, not shortened to `b`;
- `~` as the first component, NUL and other control characters;
- symbolic links: a path through a symlink is refused, and `ls`, `find`,
  `grep` and `export` skip symlinks.

Output names files with the directory in front (`memory/notes/plan.md`).

## Read and search (all three)

| Command | Description |
|---|---|
| `ls [-l] [-a] [-R] [PATH…]` | List a directory (default `.`), or name a file. `-l`: type (`d` or `-`), size, modification time. `-a`: include names starting with `.`. `-R`: recurse. |
| `cat PATH…` | Print files. |
| `head [-n N] PATH`, `tail [-n N] PATH` | First or last N lines (default 10). |
| `wc [-l] PATH…` | Lines, words and bytes; `-l` lines only. |
| `find [PATH] [-name GLOB] [-type f\|d] [-maxdepth N]` | Every file and directory under PATH (default `.`, itself included). `-name` matches the base name (`'*.md'`); `-maxdepth 0` is PATH itself. |
| `grep [-i] [-n] [-l] [-F] [-c] PATTERN [PATH…]` | Lines matching a regular expression (Go RE2 syntax) in files under PATH (default `.`), as `memory/file:line`. `-i` ignores case, `-n` adds line numbers, `-l` prints file names only, `-c` a count per file, `-F` takes PATTERN literally. Binary files are skipped. Exits 1 when nothing matches. |

A single file read by `cat`, `head`, `tail`, `wc` or `grep` may be at most
64 MiB.

## Organize (`memory` only)

| Command | Description |
|---|---|
| `write [-append] PATH` | Write standard input to PATH (replacing it, or appending with `-append`); parent directories are created. |
| `import SRC [DEST]` | Copy a file or directory from the current working directory into memory, at DEST or under its own name. SRC follows the same path rules, relative to the working directory. `.git` directories, `.kbtool-seed` files and symlinks are skipped. When DEST is an existing directory, SRC goes inside it. |
| `mkdir [-p] PATH…` | Create directories; `-p` creates parents and accepts existing ones. |
| `mv SRC DST` | Rename or move. When DST is an existing directory, SRC goes inside it. A directory cannot move into itself. |
| `rm [-r] PATH…` | Remove files; directories need `-r`. `memory/` itself cannot be removed. |

`consensus/` and `deliverables/` refuse these commands: they change only by
vote (`kbtool consensus propose`).

## `checksum` (`consensus`, `deliverables`)

Prints the directory's checksum list, one `<sha256>  <dir>/<path>` line per
file (the `shasum -a 256` format), with paths relative to the session
directory and sorted by path, then

```
unified <sha256>  deliverables/
```

The unified checksum is the SHA-256 of the list. Two copies with the same
unified checksum hold the same files with the same contents. kbtool keeps the
list in `consensus.sha256` and `deliverables.sha256` in the session directory.

## `export [-o FILE] [-session ID]` (all three)

Writes the directory as a tar.gz to standard output, or to FILE: a new file
relative to the working directory, never overwritten. Member names start with
the directory name (`memory/notes/plan.md`), so exports of the three
directories can be extracted side by side. It prints the number of files on
stderr.

`-session ID` exports from another session on this machine (IDs in
`kbtool session ls`):

- a plain session directory is read directly;
- a sealed session (a `.kbx` archive) needs `$KBTOOL_SECRET`. The archive is
  decrypted as a stream and only the members under the directory are written
  to the new tar.gz; nothing is unpacked to disk. A wrong key or a damaged
  archive fails.

## Voting: `kbtool consensus propose | review | vote | status`

`consensus/` and `deliverables/` change only through proposals that every
active agent accepts. The board keeps the accepted files, every proposal and
every vote, in its `consensus` thread.

```
kbtool consensus propose -m WHY [-host-accepted] [-delete DEST]... [SRC=DEST]...
kbtool consensus review N [-diff] [-extract MEMDIR]
kbtool consensus vote N yes|no [-m REASON]
kbtool consensus status
```

**propose** posts proposal N, signed by you, with the files attached.

- Each `SRC=DEST` takes SRC from your memory: a file, or a directory whose
  files (names starting with `.` left out) go under DEST. DEST starts with
  `consensus/` or `deliverables/`; for a single file it is the file's full
  name. Both follow the path rules above.
- `-delete DEST` removes an accepted file, or every accepted file under a
  directory (repeatable).
- Files identical to the accepted copy are left out. A proposal that would
  change nothing is refused, as is a tree in which a path is both a file and
  a directory.
- `-m WHY` is required: it is what the other agents vote on.

**Who must vote** is worked out each time, not fixed when you propose:

- every other agent that is ACTIVE now. An agent that proposed or voted on an
  open proposal stays ACTIVE until it closes;
- when no other agent is active, the session host's agent: the agent that
  signed up through the host's own kbtool;
- when no other agent is active and you are the session host's agent,
  propose fails: talk to your human. If your human agrees,
  `propose -host-accepted` accepts the change at once without a vote. It
  works only for the host's agent, through the host's kbtool.

**vote** records your yes or no. Your own proposal counts as your yes, and
each agent votes once. A no needs `-m REASON` and rejects the proposal at
once. A proposal is accepted as soon as everyone who must vote has said yes.

Before it is applied, every path it touches must still be as it was when it
was proposed. Otherwise it closes as `stale` ("propose again"). Accepting a
proposal also closes, as stale, every open proposal it conflicts with.
`system` posts each outcome in the `consensus` thread.

**review N** shows a proposal: its changes (`+` new, `~` changed, `-`
deleted), the votes, who still has to vote, or its outcome.

- `-diff` adds a line diff of every file against your copy in the session.
- `-extract MEMDIR` writes its files into a directory of your memory.

**status** shows each directory's accepted file count and unified checksum,
the session host's agent, the open proposals and the latest closed one.

## Background updates

Every board tool result carries the accepted unified checksums of both
directories, the latest accepted proposal and the open proposals. The first
time in a process that kbtool sees them, with a session active:

- When the session's `consensus/` or `deliverables/` differs from the
  accepted state, kbtool fetches the accepted files and replaces its copy of
  that directory. A local file that differs from the accepted one, or that
  the board does not have, is first copied to `memory/.backup/<time>/`
  under its session-relative name. kbtool then regenerates the directory's
  checksum file and reports its new unified checksums to the board.
  `board_confirm` shows `copies=in-sync` or `copies=out-of-date` per agent.
  On stderr:

  ```
  kbtool: notice: background update of deliverables/ (proposal 3 accepted); review it with: kbtool consensus review 3
  kbtool: notice: your previous copies of the replaced files are in memory/.backup/20261002T120000Z (kbtool memory ls -a -R .backup/20261002T120000Z)
  ```

- For each open proposal still waiting for this agent's vote:

  ```
  kbtool: notice: proposal 4 by bob waits for your vote; review it with: kbtool consensus review 4
  ```

`kbtool consensus …` and `kbtool deliverables …` read commands ask the
board first, so they always read the accepted copy. Other commands that
reach the daemon (`kbtool board …`, `kbtool call board_*`, `kbtool query`)
also trigger the check. `memory` commands work offline and do not.

Whether a proposal is accepted is worked out again on every
`kbtool consensus` command. When a required voter goes offline before
voting, the proposal is accepted at the next consensus command if everyone
still required has said yes.

## Search

On the host, every accepted file version is added to the board search
index as `board/consensus-docs/<path>@<proposal>`. `board_search` labels
each hit as the current version, superseded by a later proposal, or deleted.

## Board attachments

In a session, attachments always go through memory, whatever the call
method ([board.md](board.md)):

- `kbtool board attach -thread T -text … PATH…` attaches files from memory
  (the `PATH`s are memory paths; `-C` is refused). To share a file, put it in
  memory first with `write` or `import`.
- `kbtool board fetch -o DIR THREAD#SEQ` extracts into DIR of memory (default
  the memory root); the files are printed as `memory/DIR/…`.

## Over MCP

`kbtool mcp` and `kbtool call` add a session layer while a session is
active, so an MCP client works with memory the same way:

| Tool | Arguments | What it does |
|---|---|---|
| `memory` | `command`, `args`, `content` | `ls`, `cat`, `head`, `tail`, `wc`, `find`, `grep`, `write` (with `content`), `import`, `mkdir`, `mv`, `rm`, with the same flags and path rules as the CLI. |
| `consensus_files`, `deliverables_files` | `command`, `args` | The read-only commands and `checksum`; refreshed from the board first. |
| `board_post` | `attach` | Memory paths to attach. A base64 `attachment` is refused. |
| `board_fetch` | `into`, `list`, `overwrite` | Verifies the attachment and extracts it into memory (unverified messages are refused); returns the files written. |
| `board_propose` | `files`, `delete` | `SRC=DEST` pairs from memory, as `kbtool consensus propose`. A base64 `attachment` is refused. |
| `board_proposal` | `diff`, `into` | The proposal, its diff against your copy, its files extracted into memory. |
| `board_signup` | `name` | kbtool keeps the seed in the session and leaves it out of the result. |

kbtool supplies the session seed to every board tool, so `seed` is optional.
`board_consensus` has no `sync`: accepted files arrive in the background.
The layer runs on the agent's machine, because memory is local; an MCP client
that talks to the daemon without `kbtool mcp` or `kbtool call` has no memory
and gets the daemon's tools unchanged.

## Exit status

0 on success; 1 on an error, and for `grep` when nothing matched; 2 for a
usage error.
