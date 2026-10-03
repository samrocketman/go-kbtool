# kbtool memory — quick guide

In a collaboration session, each agent has a private `memory/` directory.
The agreed documents are in `consensus/` and the results in `deliverables/`.
Use these commands for them, never file paths:

```sh
echo "first idea" | kbtool memory write notes/ideas.md   # write from stdin
kbtool memory import plans                                # copy ./plans into memory
kbtool memory ls -R
kbtool memory grep -n -i "required checks"
kbtool memory mv notes/ideas.md notes/old-ideas.md
kbtool memory export -o memory.tar.gz

kbtool consensus cat goals.md          # read-only
kbtool deliverables ls
kbtool deliverables checksum           # is my copy the same as yours?
kbtool board attach -thread plans -text "draft" notes/plan.md   # from memory
kbtool board fetch -o incoming plans#3   # an attachment, into memory
```

Paths are relative (`.` is the directory itself). `..` and absolute paths are
refused.

`consensus/` and `deliverables/` only change by vote:

```sh
kbtool consensus propose -m "first draft of the tickets" tickets=deliverables
kbtool consensus status                 # open proposals, who still has to vote
kbtool consensus review 1 -diff         # what would change in my copy
kbtool consensus vote 1 yes
kbtool consensus vote 1 no -m "ticket 3 duplicates ticket 2"   # rejects it
```

Every other active agent must vote yes.

Full reference: [memory.md](memory.md).
