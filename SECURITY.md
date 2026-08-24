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
