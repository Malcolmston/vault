# Changelog

Every version published to npm, newest first. Dates are the day the version
went to the registry.

The tags for versions before `v0.5.4` were added after the fact, when this
repository was created — the code they point at is the 0.5.4-era tree, not the
source those versions were built from. Use them to find the notes, not to read
the code; the published tarballs on npm are the real artifacts.

## 2.0.0 — 2026-08-24

The compatibility shims come off, and two defaults change to what they should
always have been. [MIGRATING.md](MIGRATING.md) has the upgrade in full; nothing
here is a rename, and every method keeps its name, arguments and meaning.

### Breaking

- **Entries written before 1.4 no longer open.** 1.4 tied each data key to its
  entry's owner and name; entries older than that have no tie, and through 1.x
  the vault quietly fell back to opening them anyway. That meant a vault could
  carry untied entries indefinitely with nobody the wiser. Now it fails
  instead.

  Run `reseal()` on 1.7 before upgrading, or start 2.0 with
  `allowUnbound: true` and run it there. The new `unbound()` reports what is
  still untied, and separately what does not open under any key at all.

- **`strictWrites` defaults to true.** A write that would land on top of a
  change made since the vault last read the entry throws 409 rather than
  silently winning. Losing a write and telling the loser it succeeded was never
  a good default. `strictWrites: false` restores it for single-writer programs.

- **`VaultStore.putIf` is required.** It was optional, and a store without it
  got a read-then-write with a window where two writers could both believe they
  had won. With `strictWrites` on by default that window would be a promise the
  vault could not keep. The four stores that ship already implement it;
  `page` stays optional, because its absence costs memory rather than a
  guarantee.

- **`SecretRecord.revision` and `.shares` are required.** They were optional so
  that stores written against older versions kept compiling. At runtime the
  vault still reads a missing `revision` as 1 and missing `shares` as none, so
  a 1.x store will not break mid-upgrade.

### Added

- `unbound()`, to find entries that still need tying down, and `allowUnbound`
  to open them while you do.

### Removed

- The read-then-write fallback for stores without `putIf`, and every caveat in
  the documentation that existed to describe it.

## 1.7.0 — 2026-08-24

Additive. Two things people were doing by hand.

### Added

- **`putBytes` / `openBytes`** for values that are not text — a certificate, a
  keyfile, a kubeconfig. Base64 on the way in and out, done once here rather
  than once per caller. The entry is marked as bytes in its metadata, so
  `openBytes` refuses an entry holding text instead of decoding a password into
  noise and returning it. `sealed: false` is refused for bytes: they would sit
  in the database as base64 and read back as text, which is a trap.
- **References inside strings.** `"postgres://app:@vault:db_password@host/db"`
  now resolves, where before only a whole-string reference did. Several in one
  string all resolve, and a reference inside a string can name a shared secret
  as `@vault:alice/db`.

  A string that is entirely one reference is still handed back as the value
  itself rather than interpolated into a copy, so nothing that worked before
  changed shape.

## 1.6.0 — 2026-08-24

Additive. Scale: nothing here needs the whole vault in memory any more.

### Added

- **`VaultStore.page`**, optional, and every shipped store implements it.
  Keyset paging on `(owner, name)` rather than an offset, so a write during a
  walk cannot make a page skip or repeat a record.
- The vault's own whole-store walks — `rekey`, `reseal`, `purgeExpired`,
  `rotationDue`, `sharedWith`, `exportAll` — go through pages where the store
  offers them. Six operations that each loaded the entire store into memory now
  hold one page. A store without `page` falls back to `all()`, exactly as
  before; nothing breaks.
- **`Vault.page(owner, { after, limit, where })`** for listing an owner's
  entries a page at a time, returning the cursor to continue from. `list` is
  unchanged.
- **`exportStream` and `importStream`**: an export as one sealed line per
  entry, so neither end holds the vault. `importAll` reads both this and the
  original single-blob format, so the choice only has to be made on the way
  out.

  The trade is worth stating plainly rather than burying: one sealed blob hides
  how many entries there are and how big each is. A line-per-entry document
  does not. Use `exportAll` for a vault that fits, `exportStream` for one that
  does not.

- `pageSize` on `VaultOptions`, and `DEFAULT_PAGE_SIZE`.

## 1.5.0 — 2026-08-24

Additive. The master key no longer has to exist in the process.

### Added

- **`KeyWrapper`**: an alternative to `KeyProvider` that never hands the vault
  key material. It does the two operations the vault actually needs — wrap a
  data key, unwrap it again — wherever the key lives: AWS KMS, Cloud KMS,
  Vault's transit engine, an HSM. A `KeyProvider` puts the key in memory, where
  a heap dump has it; a wrapper does not.

  This only works cheaply because of the envelope introduced in 0.5.0: it is
  the small data key that crosses the boundary, never the value, so it is one
  short round trip per entry rather than sending secrets over the wire. There
  is a test asserting that what reaches a wrapper is 32 bytes and not the
  secret.

  The `binding` from 1.4 is passed to the wrapper, so handing it to the service
  as an encryption context makes the KMS enforce the same tie.

- A wrapper is accepted anywhere a key is: as `key`, in `previousKeys`, and as
  the argument to `rekey`. So moving an existing vault onto a KMS is
  `rekey(wrapper)` rather than a migration, and moving back off is
  `rekey(material)`. Both directions are tested.

- `isKeyWrapper`, and `KeySource` for "anything the vault takes as a key".

### Internal

`Vault` no longer holds a `CryptoKey`. Everything above the key now goes
through one small interface with `wrap` and `unwrap`, and a local key is just
an implementation of it. That is why a KMS needed no new code paths anywhere
else — and why `previousKeys` can hold a mix of local keys and wrappers while a
rekey is half done.

## 1.4.0 — 2026-08-24

Integrity. Two things that were trusted to the code path are now enforced by
the cryptography.

### Sealed values are tied to where they live

Each entry's data key is sealed with its owner and name as additional
authenticated data, so ciphertext copied from one row to another will not open
in its new home.

This closes a real hole rather than hardening a theoretical one. Before 1.4,
anyone who could write to the store — a DBA, a compromised process, a backup
restored across rows — could copy one owner's sealed bytes into a row they
controlled and read the secret back, without needing any key. Per-owner scoping
is the vault's main claim over an encrypted map, and it was enforced only by
the code that read from the store. Now it is enforced by the tag.

It also turns a bad restore from a silent wrong answer into a loud failure.

Entries written before 1.4 have no tie and keep opening; `rekey` or `reseal`
gives them one on the way past. Trying bound first and unbound second is not a
way around it — a key sealed *with* a binding will not open without one, so
only a genuinely old entry can take the fallback.

### The audit trail is hash-chained

Every entry carries a hash over its own contents and the hash before it, so an
edited line or a deleted one can be spotted with the new `verifyChain`.
`PostgresAuditLog` takes a transaction-scoped advisory lock while appending, so
two processes writing at once cannot fork the chain.

What it buys is worth being exact about: it proves the middle of a log has not
been touched. It does not stop somebody who can rewrite the whole table from
re-hashing it, or from lopping off the end. For that the log has to live where
the vault's writer cannot reach, and `verifyChain` is what tells you whether
what came back from there adds up.

### Fixed

- `remove` never awaited its audit write. The entry was a floating promise, so
  the fail-closed guarantee 1.3 introduced did not apply to deletions, and the
  line could be lost entirely if the process exited first. Every audit write is
  awaited now.
- A test asserted that an encrypted file did not contain the string `"api"`.
  The file is base64, so it did, about once in 1,200 runs. Markers in that test
  are long enough to mean something now.

## 1.3.0 — 2026-08-24

Additive. Two things a vault behind an API needs and this one did not have:
letting somebody else read a secret, and being able to say afterwards who did.

### Sharing

- `share(owner, name, { with, expiresAt })` lets another owner read one entry,
  `unshare` withdraws it, `shares` says who can read one of yours, and
  `sharedWith` says what you can read of other people's.
- Grants are **read-only, always**. Writing, rotating and deleting stay with the
  owner however widely an entry is shared — a grant that could overwrite the
  credential would make "shared with" mean "owned by".
- A reader names the owner: `open("bob", "token", { from: "alice" })`. That is
  deliberately explicit, so a grant can never quietly shadow something the
  reader already keeps under the same name.
- References reach shared secrets as `@vault:alice/token`. A name cannot
  contain a slash, so the two forms never collide.
- `shares` reports lapsed grants and `sharedWith` does not: one answers "who
  could have seen this", the other "what can I open".
- Grants survive a replacing write, and go through the same guarded path as any
  other change, so a grant and a value written at the same moment cannot lose
  each other.

### A stored audit trail

- `VaultOptions.audit` takes an `AuditLog` and every action is written to it —
  including the refusals, which are usually the ones worth having. A read
  through a grant records both sides: `owner` is whose secret it was, `by` is
  who read it.
- **A log that cannot be written fails the operation, by default.** An audit
  trail with silent gaps is worse than none, because it looks like evidence.
  `{ log, required: false }` makes it best-effort instead.
- `MemoryAuditLog` ships in the main entry; `SqliteAuditLog` and
  `PostgresAuditLog` ship beside their stores. None has a method that deletes a
  line — retention belongs to whoever owns the database.
- `onAccess` is unchanged and still fire-and-forget. Both can be set.

One caveat worth knowing: the entry is written after the action and before the
call returns, so a failed append reports something that did in fact happen.
That is the cost of recording outcomes rather than intentions, and it fails in
the safe direction — the caller is told something went wrong.

## 1.2.0 — 2026-08-24

Additive. The release that makes the vault safe to run from more than one
process, which is what the README always claimed it was for.

### Added

- **Optimistic concurrency.** Every entry carries a `revision` that advances on
  each write. Pass the one you read back as `expectedRevision` and a write that
  would land on top of someone else's throws 409 instead of overwriting it;
  `{ expectedRevision: null }` claims a name only if it is free. `remove` takes
  it too, as a read-then-delete.
- **`strictWrites`** applies that to every write without passing it each time.
  Off by default, because it turns a write that used to succeed into a 409 and
  1.1's behaviour has to keep working.
- **`VaultStore.putIf`**, optional, for stores that can compare and set in one
  statement. `PostgresStore` and `SqliteStore` implement it, so a contested
  write is settled by the database; `FileStore` settles it under its lock. A
  store without it falls back to check-then-write, which narrows the window
  rather than closing it — nothing breaks, and the README says which store
  gives which guarantee.
- **`PostgresStore`**, behind `@mstone6969/vault/stores/postgres`. The first
  store that several processes can share safely. Bun-only, like `SqliteStore`.
  Call `migrate()` once before first use; it is not run for you.
- **`FileStore` now locks.** Writes take a lock file and re-read the file while
  holding it, so two processes on one path queue up instead of overwriting each
  other. A lock older than `staleAfter` is broken, so a crash does not lock
  everyone out forever. `lockTimeout` and `staleAfter` are constructor options.
- **`rotateDue()`** rotates everything a policy says is overdue — the companion
  to `rotationDue()`, which only ever told you. One entry that will not rotate
  is named in the report and the rest still go.
- **`resolve` walks nested structures.** A `@vault:` reference now works
  anywhere in a config object or array, not only at the top level. Anything
  that is not a string, plain object or array is passed through as itself, and
  a branch holding no references is handed back rather than copied.

### Fixed

- `rotate` wrote twice — once for the value, once to stamp `rotatedAt` — and
  the second write was guarded by nothing. Under `strictWrites` a concurrent
  writer could be clobbered by that stamp. It is one write now, so a rotation
  advances the revision once rather than twice.
- Coverage was reported but never enforced: `test:coverage` was
  `bun test --coverage`, which exits 0 whatever the numbers say, so CI would
  have gone green on a regression. It now parses the lcov report and fails
  below 100%, and that failure has been demonstrated rather than assumed.

## 1.1.0 — 2026-08-23

Additive. Nothing published before this keeps working differently.

### Added

- `exportAll` / `importAll`: the whole vault as one sealed document. Values are
  opened and re-sealed under the key you pass rather than copied across, so the
  far end can have a master key of its own — metadata, expiry, rotation
  policies, finality and history come with them. An export refuses when a value
  will not open, rather than dropping it: a backup missing entries would look
  fine right up until it was needed. An import leaves entries that already exist
  alone and names them, unless told to overwrite.
- `passphraseKey(passphrase, salt)`: a master key stretched from a passphrase
  with PBKDF2-HMAC-SHA256, 600,000 iterations by default.
- `list(owner, where)` narrows a listing to entries whose metadata matches.
  Metadata only — filtering on a value would mean opening every secret in the
  vault to answer a listing.

### Fixed

- Two README examples predated the release that changed them: `put`'s fourth
  argument had been shown as bare metadata since 0.5.0 made it an options
  object, and `{ open: true }` since 1.0.0 renamed it to `{ sealed: false }`.
  Both would have thrown or silently done nothing. Every example in the README
  is now run before release.

## 1.0.0 — 2026-08-24

The surface is settled. What it covers and what a change to it costs is in the
README's Stability section; the short version is that a breaking change now
needs a 2.0.

### Breaking

- `PutOptions.open` is now `PutOptions.sealed`, and means the opposite:
  `{ sealed: false }` where you wrote `{ open: true }`. It was too easy to read
  the old name as a relative of `Vault.open`, which is a different idea.
- `reseal` returns a report — `{ rekeyed, failed }` — instead of a count, and
  no longer stops at the first value it cannot open. One unopenable entry used
  to abort the run and leave the rest unsealed; now it is named in `failed` and
  the others are done. Same contract as `rekey`.

### Fixed

- A store no longer hands out the records it is keeping. Mutating something
  returned by `get`, `list` or `all` used to rewrite the store from underneath
  it; every store now returns copies.
- `put` inherits `final` from the entry it replaces, like every other option.
- The timestamp `rotate` returns is the one it wrote, rather than a second
  `new Date()` a few microseconds later.

### Added

- A CommonJS build, so `require("@mstone6969/vault")` works as well as
  `import`. The build refuses to finish if the CommonJS copy will not load
  under `require`.
- `SECURITY.md`: what the vault protects against, what it does not, and how to
  choose and retire a key.

## 0.5.5 — 2026-08-24

The first release published by CI rather than from a laptop.

- `CHANGELOG.md` ships with the package, so `node_modules` carries the history
  as well as the reference.
- Continuous integration: types, documentation, tests at 100%, build, and an
  import under Node on every push.
- Releases are cut by pushing a tag rather than publishing from a laptop. The
  workflow refuses a tag that disagrees with `package.json`, because a tag on
  the wrong commit would put a version on npm that cannot be taken back.
- `LICENSE` file, so the MIT licence `package.json` always claimed is actually
  in the repository.
- The release workflow does nothing for a tag whose version npm already has,
  so a retroactive or re-pushed tag does not cry wolf.

No library code changed.

## 0.5.4 — 2026-08-23

- `repository`, `homepage` and `bugs` metadata, so npmjs.com links back to the
  source and the README's links to the reference resolve there.
- The licence file ships with the package.

No code changes.

## 0.5.3 — 2026-08-23

- The README points at the generated reference instead of repeating it in a
  table. That table had already drifted: it still described `put`'s fourth
  argument as bare metadata, which 0.5.0 changed to an options object.

No code changes. 0.5.1 and 0.5.2 were not used.

## 0.5.0 — 2026-08-23

The release that made it a vault rather than an encrypted map.

### Envelope encryption

Every value is now sealed under its own data key, and only that key is sealed
under the master key. Changing the master key re-seals a handful of bytes per
entry rather than every value, and one exposed data key exposes one value
rather than all of them. Values written by earlier versions are sealed under
the master key directly; they still open, and `rekey` gives them an envelope on
the way past.

### Keys

- `rekey(next)` re-seals every entry under a new master key and reports what it
  could not open, leaving those entries untouched — re-sealing what you cannot
  read would only destroy it.
- `previousKeys` keeps retired keys readable, so a `rekey` that stops halfway
  leaves a mix that still opens.
- Key providers: `envKey`, `fileKey`, `staticKey`, or one method of your own.
  Called the first time a key is needed, not when the vault is built.

### Lifecycle

- `open: true` stores a value in the clear, readable with `read()`. Sealed
  entries answer 403.
- `final: true` refuses every future replacement.
- `expiresAt` stops an entry resolving; `purgeExpired()` clears them out.
- `rotate()` keeps what it replaced, up to `historyLimit` (5 by default), and
  `versions()` opens them.
- `reseal()` gives entries fresh data keys without changing the master key.
- Options left out of `put` are inherited, so rotating a credential does not
  forget what kind it is or when it expires.

### Rotation policies

An entry can carry how to make its next value without carrying the value.
`{ kind: "random" }` has the vault generate one; `{ kind: "generator" }` names a
function you registered, which is told the entry and its non-secret arguments
and deliberately not the value it is replacing. `rotationDue()` reports entries
whose interval has elapsed. `randomValue()` samples by rejection rather than
modulo, so an odd-length alphabet stays unbiased.

### Storage

- `FileStore`: one encrypted file holding the whole index. The other stores
  seal values and leave owners and names in the open; here what leaks at rest
  is the file's size. Writes are flushed and renamed into place, and a failed
  write rolls the in-memory index back. Uses only `node:fs`, so it runs on Node
  as well as Bun.
- `SqliteStore` gained the columns the new fields need, and upgrades a table
  written by an older version when it opens it.

### Everything else

- `onAccess` reports put, open, read, remove, rotate, rekey and every refusal
  with its reason. Never awaited, and its failures are swallowed: an audit
  trail that throws must not take the vault with it.
- A generated API reference ships in `docs/`, and `docs:check` fails the build
  if any exported member is undocumented.

### Breaking

- `put`'s fourth argument is an options object: `put(owner, name, value, {
  metadata })` rather than `put(owner, name, value, metadata)`.
- `VaultStore.put` takes a whole record, and `VaultStore` gains `all()`. A
  custom store must implement it.

0.3.0 was built but never published; its `rekey` and `previousKeys` work went
out as part of this release.

## 0.2.0 — 2026-08-23

- `put` takes non-secret `metadata`, stored in the clear and returned by
  `list`, so a listing can say which login a credential is for without opening
  anything.
- `SqliteStore` adds the metadata column to a table written by 0.1.0.

Additive: metadata defaults to `{}` and existing calls are unchanged.

## 0.1.0 — 2026-08-23

First release. A write-only credential store: values go in sealed with
AES-256-GCM and only `open()` and `resolve()` take them out. Per-owner scoping,
`@vault:` references for configuration, and two stores — `MemoryStore` and
`SqliteStore`.
