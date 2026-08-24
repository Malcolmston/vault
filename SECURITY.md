# Security

## What this protects against

Someone who reads the database — a stolen backup, a copied file, a snapshot,
a misplaced disk — learns nothing about the values in it. Every value is
encrypted with AES-256-GCM under its own data key, and only that data key is
encrypted under the master key.

`FileStore` extends that to the index itself: owners, names, metadata and
timestamps are inside the envelope too, so a stolen file leaks only its size.
`SqliteStore` and any store you write keep those as ordinary columns, so they
leak what you keep, if not what it says.

Values are authenticated, not merely encrypted. An altered ciphertext fails to
open rather than decrypting to something else, and a wrong key fails the same
way, so neither can be told from the other.

## What it does not protect against

- **Anyone who has the master key.** The vault is a lock, not a guard. Whoever
  holds the key holds the secrets.
- **Anything in the process.** Opened values are ordinary strings in memory.
  JavaScript cannot reliably erase them, and a heap dump or a debugger will
  find them.
- **The caller.** `open`, `read` and `resolve` hand back plaintext; what
  happens to it next — a log line, an error message, an HTTP response — is
  outside the vault.
- **Traffic analysis.** File size, row counts and write timing say something
  about how much you keep and when it changes.
- **Timing.** Nothing here is written to run in constant time.
- **Metadata you choose to store.** It is deliberately in the clear. Do not put
  a secret in it.
- **Someone who can delete.** Values tied to their entry cannot be moved or
  swapped, and a thinned audit trail can be spotted — but nothing here stops a
  writer with database access from deleting rows outright, or from re-hashing a
  trail they can rewrite whole. Keep backups, and keep the audit log where the
  vault's own writer cannot reach it.

## Values are tied to where they live

Since 1.4, each entry's data key is sealed with its owner and name as
additional authenticated data. Ciphertext moved from one entry to another will
not open in its new home.

That matters because the per-owner scoping is otherwise only enforced by the
code path: before 1.4, anyone who could write to the store could copy one
owner's sealed bytes into a row they controlled and read them back. Now the
cryptography enforces it too, and no key is needed to notice.

Entries written before 1.4 are not tied down. They still open, and `rekey` or
`reseal` migrates them. Until you run one, those entries have the old property.

## Choosing a key

`generateKey()` returns 32 random bytes, base64. Keep it out of the repository
and out of the process list: `fileKey("/etc/vault.key")` on a file only the
service can read, or `envKey("VAULT_KEY")` from a secret manager.

Losing every key loses every value sealed under them; there is no recovery
path, and that is the point. `rekey` before retiring a key, and keep the old
one in `previousKeys` until you are sure nothing is left under it.

## Reporting something

Open an issue at https://github.com/Malcolmston/vault/issues. If it is a
vulnerability rather than a bug, say so in the title and leave the details for
a private channel.
