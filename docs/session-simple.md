# kbtool session — quick start

List your collaboration sessions, and check the file the agents maintain for
the list.

```sh
kbtool session ls
#   SESSION                  LAST USED         ROLE      STATE     SUMMARY                      PARTICIPANTS
# * 20261002T184700Z_3fa9c1  2026-10-02 18:47  host      active    branch protection migration  Sam, Josh, Alex +2 more
#   20260930T090112Z_b81e07  2026-09-30 17:02  attendee  finished  auth review                  Sam, Kim
# (participants cut off; kbtool session ls -a lists them all)

kbtool session ls -a          # every participant
```

The summary and participants come from each session's `about.json`, which
the agents keep current with `kbtool session about`:

```sh
kbtool session about -summary "branch protection migration" -participant Sam -participant Josh
```

After editing it, check it:

```sh
kbtool session validate       # the current session; -id ID for another
# session 20261002T184700Z_3fa9c1: ok
```

Resume a listed session with `kbtool collaborate resume -id ID`
([collaborate-simple.md](collaborate-simple.md)).

Full reference: [session.md](session.md) · back to [README](../README.md)
