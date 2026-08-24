# Changelog

Every version published to npm, newest first. Dates are the day the version
went to the registry.

The tags for versions before `v0.5.4` were added after the fact, when this
repository was created — the code they point at is the 0.5.4-era tree, not the
source those versions were built from. Use them to find the notes, not to read
the code; the published tarballs on npm are the real artifacts.

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
