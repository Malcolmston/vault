# @mstone6969/vault

A write-only credential vault. Values go in encrypted; the only way one comes
back out is `open()` or `resolve()`, so a vault can sit behind an API without a
reveal endpoint.

```bash
bun add @mstone6969/vault
```

## Use

```ts
import { generateKey, MemoryStore, Vault } from "@mstone6969/vault"

const vault = new Vault({
    key: process.env.VAULT_KEY ?? generateKey(), // 32 bytes, base64
    store: new MemoryStore(),
})

await vault.put("alice", "stripe_key", "sk_live_…")

await vault.list("alice")
// [{ owner: "alice", name: "stripe_key", metadata: {}, createdAt: …, updatedAt: … }]
// — no value, ever

await vault.open("alice", "stripe_key") // "sk_live_…"
```

Everything is scoped by an owner, so one vault serves many accounts and two
people can both keep a `token` without seeing each other's.

## How a value is sealed

Every value gets its own **data key**. The value is sealed under that, and only
the data key is sealed under your master key:

```
value ──sealed under──▶ data key ──sealed under──▶ master key
```

Two things follow. Changing the master key re-seals a handful of bytes per
entry rather than every value, so `rekey` is cheap whatever you keep in there.
And a data key that leaks opens one value, not all of them.

Values written by earlier versions are sealed under the master key directly;
they still open, and `rekey` gives them an envelope on the way past.

## Metadata

A value is sealed, but the facts *about* it usually should not be. `put` takes
a map of non-secret strings that `list` returns as-is:

```ts
await vault.put("alice", "deploy", privateKey, {
    kind: "ssh",
    publicKey: "ssh-ed25519 AAAA…",
})

await vault.list("alice")
// [{ name: "deploy", metadata: { kind: "ssh", publicKey: "ssh-ed25519 AAAA…" }, … }]
```

That is what lets a listing say what something is — which login a password
belongs to, which public key pairs with a sealed private one — without opening
anything. Replacing a value replaces its metadata too.

It is stored in the clear. Put nothing in it you would not show.

## References

Configuration can name a secret instead of holding one. `resolve` swaps
`@vault:<name>` for the stored value and leaves everything else alone:

```ts
await vault.resolve("alice", {
    NODE_ENV: "production",
    API_KEY: "@vault:stripe_key",
})
// { NODE_ENV: "production", API_KEY: "sk_live_…" }
```

A reference to a secret that isn't there **throws**. Running a job with a blank
credential is worse than not running it. Change the prefix with
`new Vault({ …, prefix: "secret://" })`.

## Storage

Three stores ship with the package.

**`FileStore`** keeps everything in one encrypted file. The other stores seal
values and leave the rest in the open — SQLite has an `owner` column and a
`name` column, so anyone who can read the file learns what you keep even if
they cannot read it. Here the whole index is inside a single envelope, and what
leaks at rest is the file's size:

```ts
import { FileStore } from "@mstone6969/vault/stores/file"

const store = new FileStore("./secrets.vault", fileKey("/etc/vault.key"))
```

Give the file a key of its own, or hand it the vault's — sharing means one key
opens both layers. It is loaded and written whole, so it suits hundreds of
secrets and one writer, not millions and many.

Writes go to a temporary file, are flushed to disk, and are renamed into place,
so neither a crash nor a power loss leaves a half-written index — which matters
more here than elsewhere, because the whole index is one envelope and a torn
file would lose every record rather than one. Nothing locks the file, so two
writers on the same path are still last-write-wins. Unlike `SqliteStore`, it
uses only `node:fs`, so it runs on Node as well as Bun.

**`MemoryStore`** ships in the main entry. **`SqliteStore`** is Bun-only — it
imports `bun:sqlite`, so it lives behind a subpath and never loads unless you
ask for it:

```ts
import { SqliteStore } from "@mstone6969/vault/stores/sqlite"

const store = new SqliteStore("./vault.sqlite") // or ":memory:", or a Database
```

Everything else runs on Node 18+ as well as Bun.

To keep secrets in a database you already run, implement `VaultStore` — four
methods, all scoped by owner, all dealing in sealed strings and never plaintext:

```ts
type VaultStore = {
    get(owner: string, name: string): Promise<SecretRecord | null>
    list(owner: string): Promise<SecretRecord[]>
    all(): Promise<SecretRecord[]>
    put(record: {
        owner: string
        name: string
        sealed: string
        metadata: Record<string, string>
    }): Promise<SecretRecord>
    remove(owner: string, name: string): Promise<boolean>
}
```

## Encryption

AES-256-GCM, a fresh 12-byte IV per write, stored as `iv:payload` in base64.
GCM's authentication tag means an altered value fails to open rather than
decrypting to something wrong — both cases are covered by tests.

The key never leaves your process, and the package never writes it anywhere.

## Lifecycle

An entry can be more than a value:

```ts
await vault.put("alice", "region", "eu-west-1", { open: true })   // readable
await vault.put("alice", "root_ca", pem, { final: true })         // written once
await vault.put("alice", "token", value, { expiresAt: tomorrow }) // stops working
await vault.rotate("alice", "deploy", next)                       // keeps the old one
```

- **`open`** stores the value in the clear, and `read()` gives it back. For
  configuration rather than credentials; a sealed entry answers 403.
- **`final`** refuses every future replacement — delete it or live with it.
- **`expiresAt`** stops the entry resolving once it passes. `purgeExpired()`
  clears them out when you are ready.
- **`rotate`** keeps what it replaced, up to `historyLimit` (5 by default), and
  `versions()` opens them. A job that read the credential moments before a
  rotation can still finish on what it was given.

## Rotating without knowing the value

An entry can carry a **rotation policy**: how to make its next value. That is a
recipe, never a value, so it is stored in the open beside the metadata — and
whatever runs the rotation is told how to make the next password without being
told the current one.

```ts
await vault.put("alice", "db", firstPassword, {
    metadata: { username: "ada" },
    rotation: { kind: "random", length: 24, every: 86_400 },
})

await vault.rotate("alice", "db")   // no value: the policy makes one
```

For a credential only the far end can mint, name a generator instead. The vault
stores the *name*; the function stays in your process:

```ts
const vault = new Vault({
    key,
    store,
    generators: {
        provider: async ({ arguments: args }) => api.mintKey(args.account),
    },
})

await vault.put("alice", "api", currentKey, {
    rotation: { kind: "generator", generator: "provider", arguments: { account: "acct_123" } },
})
```

A generator is told which entry is being rotated and its policy's arguments —
deliberately not the value it is replacing. One that needs the old value can
ask the vault for it.

`rotationDue(now?)` reports entries whose `every` has elapsed since they were
last rotated. Nothing rotates them for you; schedule it and act on the list.

Rotating keeps everything the entry already had — its metadata, its policy, its
expiry — and records `rotatedAt`. Only the value changes.

Anything you leave out of `put` stays as it was, so rotating a credential does
not quietly forget what kind it is or when it expires.

`reseal()` re-seals values under fresh data keys without changing the master
key — cheap hygiene, so the ciphertext of an unchanged secret stops being
comparable between two copies of the database.

## Where the key comes from

```ts
new Vault({ key: envKey("VAULT_KEY"), store })    // an environment variable
new Vault({ key: fileKey("/etc/vault.key"), store })  // a file
new Vault({ key: staticKey(material), store })    // one you already have
```

A provider is one method — write your own for a KMS or anything else. It is
called the first time a key is actually needed, not when the vault is built, so
a vault nobody uses never reaches for one.

## Watching what happens

```ts
new Vault({
    key,
    store,
    onAccess: (event) => log(event), // put, open, read, remove, rotate, rekey, denied
})
```

Every refusal is reported too, with the reason — `final`, `sealed`, `expired`.
The hook is never awaited and its failures are swallowed: an audit trail that
throws must not take the vault with it.

### Changing the key

`rekey` opens every value with the current key and re-seals it under a new one:

```ts
const report = await vault.rekey(nextKey)
// { rekeyed: 128, failed: [] }
```

The old key stays readable for the life of that vault, so a run that stops
halfway leaves a mix that still opens. Construct the next one with both until
you are sure:

```ts
new Vault({ key: nextKey, previousKeys: [oldKey], store })
```

A value that will not open under any key it holds is **left exactly as it was**
and named in `failed` — re-sealing what cannot be read would only destroy it.

> [!WARNING]
> Losing every key loses every value sealed under them. Rekey before you retire
> a key, and back the current one up where you would back up a password.

## API reference

The reference is generated from the source and ships inside the package, so
`node_modules/@mstone6969/vault/docs` is the same documentation you get here —
every function, parameter, type and thrown error, with examples.

| Start at | For |
| --- | --- |
| [`Vault`](./docs/index/classes/Vault.md) | Everything you do with secrets |
| [`VaultOptions`](./docs/index/type-aliases/VaultOptions.md) | Building one: keys, store, history, generators, audit hook |
| [`PutOptions`](./docs/index/type-aliases/PutOptions.md) | `open`, `final`, `expiresAt`, `rotation`, `keepHistory` |
| [`RotationPolicy`](./docs/index/type-aliases/RotationPolicy.md) | How the next value is made |
| [`FileStore`](./docs/index/classes/FileStore.md) · [`MemoryStore`](./docs/index/classes/MemoryStore.md) · [`SqliteStore`](./docs/stores/sqlite/classes/SqliteStore.md) | The stores that ship |
| [`VaultStore`](./docs/index/type-aliases/VaultStore.md) | Writing your own |
| [`KeyProvider`](./docs/index/type-aliases/KeyProvider.md) | Where the master key comes from |
| [`VaultError`](./docs/index/classes/VaultError.md) · [`VaultKeyError`](./docs/index/classes/VaultKeyError.md) | What is thrown, and the status each suggests |

Names are up to 64 characters of letters, numbers, dot, dash or underscore.
Bad input throws `VaultError`, which carries a suggested HTTP `status` so the
vault can sit behind an API without the caller knowing its internals; key and
ciphertext problems throw `VaultKeyError`.

Regenerate the reference with `bun run docs`. `bun run docs:check` fails if any
exported member is undocumented, and `prepublishOnly` runs it — so the
reference cannot fall behind the code the way a table in this file can.

## Versions

Every published version, and what changed, is in
[CHANGELOG.md](./CHANGELOG.md).

## Releasing

Releases are cut by CI, not from a laptop. Bump the version, commit, and push a
matching tag:

```bash
npm version patch      # or minor
git push --follow-tags
```

The tag triggers the release workflow, which refuses a tag that disagrees with
`package.json`, runs the same gate as `prepublishOnly` — types, documentation,
tests at 100%, build, reference, and an import under Node — and only then
publishes with the `NPM_TOKEN` repository secret.

`workflow_dispatch` runs everything except the publish, for checking the
pipeline without spending a version number.

## Stability

1.0 means the surface below is settled, and a breaking change to it needs a
2.0:

- The `Vault` class and its methods.
- `VaultStore`, so a store written today keeps working.
- `KeyProvider`, and the three providers that ship.
- `SecretRecord`, `SecretSummary`, `PutOptions`, `RotationPolicy`,
  `VaultEvent`, and the errors.
- The sealed format, `iv:payload` under a data key. A version that could not
  open what an earlier one wrote would be a 2.0.

Adding an optional field to an options object, a new store, or a new provider
is a minor version. Anything that changes what an existing call does is a
major one.

## Security

What the vault protects against, what it does not, and how to choose a key:
[SECURITY.md](./SECURITY.md).

## Development

```bash
bun test              # the suite
bun run test:coverage # the suite, and fail if anything in src is untested
bun run typecheck
bun run docs          # generate docs/ from the TSDoc comments
bun run docs:check    # fail if any exported member is undocumented
```

Every line and function in `src` is covered, and every exported member carries
TSDoc; `test:coverage` and `docs:check` enforce both, and `prepublishOnly` runs
them. Bun accepts `coverageThreshold` in bunfig.toml but does not act on it, so
the coverage check reads the lcov report itself and exits non-zero on a gap.

The generated reference lives in `docs/` and ships with the package.
