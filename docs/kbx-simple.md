# kbtool kbx — quick start

Change the key of everything kbtool encrypts in its state dir (`kb.db` and
the finished sessions of `kbtool collaborate host -encrypt`).

```sh
kbtool collaborate finish                 # rekeying needs no active session
export KBTOOL_SECRET='the current key'
kbtool kbx rekey                          # asks for the new key twice
export KBTOOL_SECRET='the new key'        # from now on
```

Every file of the state dir shares one key, so a single file there cannot be
rekeyed on its own. A KBX file elsewhere (for example a copied archive) can:

```sh
kbtool kbx rekey ~/backup/3f9c0e5a7b1d4c2e8a6f0b9d1e7c5a3b.kbx
```

Full reference: [kbx.md](kbx.md) · back to [README](../README.md)
