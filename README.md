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
    metadata: { kind: "ssh", publicKey: "ssh-ed25519 AAAA…" },
})

await vault.list("alice")
// [{ name: "deploy", metadata: { kind: "ssh", publicKey: "ssh-ed25519 AAAA…" }, … }]
```

That is what lets a listing say what something is — which login a password
belongs to, which public key pairs with a sealed private one — without opening
anything. Replacing a value replaces its metadata too.

A listing can be narrowed to entries whose metadata matches:

```ts
await vault.list("alice", { kind: "ssh" })
```

Only metadata, because it is the only part kept in the clear. Filtering on a
value would mean opening every secret in the vault to answer a listing.

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

References work anywhere in a structure, not only at the top:

```ts
await vault.resolve("alice", {
    database: { host: "db.internal", password: "@vault:db" },
    webhooks: [{ url: "@vault:hook" }],
})
```

Objects and arrays are walked; anything else — a number, a Date, a class
instance — is passed through as itself. A branch containing no references at
all is handed back rather than copied.

A reference to a secret that isn't there **throws**. Running a job with a blank
credential is worse than not running it. Change the prefix with
`new Vault({ …, prefix: "secret://" })`.

## Storage

Four stores ship with the package. If more than one process writes the same
vault, use `PostgresStore` — see [More than one writer](#more-than-one-writer).

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
file would lose every record rather than one. Writes also take a lock file
beside the store and re-read the file while holding it, so two processes on the
same path queue up instead of overwriting each other. Unlike `SqliteStore`, it
uses only `node:fs`, so it runs on Node as well as Bun.

**`MemoryStore`** ships in the main entry. **`SqliteStore`** is Bun-only — it
imports `bun:sqlite`, so it lives behind a subpath and never loads unless you
ask for it:

```ts
import { SqliteStore } from "@mstone6969/vault/stores/sqlite"

const store = new SqliteStore("./vault.sqlite") // or ":memory:", or a Database
```

**`PostgresStore`** is the one to reach for when several processes share a
vault. It is Bun-only too, since it uses Bun's built-in `SQL`:

```ts
import { PostgresStore } from "@mstone6969/vault/stores/postgres"

const store = new PostgresStore(process.env.DATABASE_URL!)
await store.migrate() // once, before first use
```

`migrate` is not run for you, because a library should not create tables behind
your back the first time you read from it. It is safe to call on every start,
and from several processes at once.

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
    // Optional. Without it you get a weaker guarantee, not an error.
    putIf?(record: SecretRecord, expectedRevision: number | null): Promise<SecretRecord | null>
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
await vault.put("alice", "region", "eu-west-1", { sealed: false }) // readable
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

`every` says how often, in seconds. `rotationDue()` reports what is overdue and
`rotateDue()` acts on it, so a scheduled job is two lines:

```ts
const { rotated, failed } = await vault.rotateDue()
for (const { name, reason } of failed) console.warn(name, reason)
```

One credential that will not rotate — a provider that is down, a generator that
throws — is named in `failed` and the rest still go. A pass that abandoned the
remaining credentials because one endpoint was unreachable would be worse than
not running.

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
new Vault({ key: passphraseKey(phrase, salt), store })  // something remembered
```

`passphraseKey` stretches a passphrase into a key with PBKDF2-HMAC-SHA256,
600,000 iterations by default — deliberately slow, so that guessing at the
passphrase costs the guesser real time. The salt is not a secret and does not
have to be hidden, but it does have to be the same one every time, or the key
comes out different and nothing opens. Keep it beside the vault.

A passphrase is only ever as good as the passphrase. Prefer a generated key
where you have somewhere to keep one.

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

## Sharing

An entry belongs to one owner. To let somebody else read it, grant it:

```ts
await vault.share("alice", "deploy-key", { with: "bob" })

await vault.open("bob", "deploy-key", { from: "alice" })
```

The reader names whose entry they want. That is deliberate — a grant can never
quietly shadow something the reader already keeps under the same name, and
`open("bob", "deploy-key")` still means Bob's own.

Grants are **read-only, always**. Writing, rotating and deleting stay with the
owner however widely an entry is shared; a grant that could overwrite the
credential would make "shared with" mean "owned by". They can be temporary:

```ts
await vault.share("alice", "db", { with: "carol", expiresAt: friday })
```

`shares(owner, name)` says who can read one of yours — lapsed grants included,
because "who could have seen this" is the question it exists to answer.
`sharedWith(reader)` is the other direction, and leaves lapsed grants out
because it answers what you can open right now.

Withdrawing takes effect immediately:

```ts
await vault.unshare("alice", "deploy-key", { with: "bob" })
```

It says nothing about what Bob already read and kept, which is why a withdrawn
grant is also a reason to rotate the value.

References reach shared secrets by naming the owner, and a name cannot contain
a slash, so the two forms never collide:

```ts
await vault.resolve("bob", {
    OURS: "@vault:own-token",
    THEIRS: "@vault:alice/db",
})
```

## Keeping a record

`onAccess` is a callback the vault does not wait for. For a trail that outlives
the process, give it a log:

```ts
import { Vault } from "@mstone6969/vault"
import { SqliteAuditLog } from "@mstone6969/vault/stores/sqlite"

const audit = new SqliteAuditLog("./audit.sqlite")
const vault = new Vault({ key, store, audit })

await vault.open("alice", "db")

// Read the trail from the log, not from the vault.
await audit.entries({ owner: "alice", action: "open", since: monday })
```

Every action is recorded, including the refusals — usually the interesting
ones. A read through a grant records both sides: `owner` is whose secret it
was, `by` is who read it.

**A log that cannot be written fails the operation.** That is the default and
it is deliberate: an audit trail with silent gaps is worse than none, because
it looks like evidence. If you would rather the vault carry on:

```ts
new Vault({ key, store, audit: { log, required: false } })
```

The entry is written after the action and before the call returns, so a failed
append reports something that did in fact happen. That is the cost of recording
outcomes rather than intentions, and it fails in the safe direction — the
caller is told something went wrong.

Three logs ship: `MemoryAuditLog` for tests and development, `SqliteAuditLog`
and `PostgresAuditLog` for a record that lasts. None of them has a method that
deletes a line. Retention belongs to whoever owns the database, not to the
library writing to it.

## More than one writer

Every entry carries a `revision` that goes up by one on each write. Read it,
and hand it back to refuse a write that would land on top of someone else's:

```ts
const [entry] = await vault.list("alice")

await vault.put("alice", "token", next, { expectedRevision: entry.revision })
// throws 409 if anything wrote to it in between
```

`{ expectedRevision: null }` means "only if it does not exist yet", which is how
to claim a name without racing another writer for it.

To get that protection on every write without passing it each time, build the
vault with `strictWrites`:

```ts
const vault = new Vault({ key, store, strictWrites: true })
```

It is off by default because it turns a write that used to succeed into a 409,
and a vault written against 1.1 should keep behaving the way it did. Turn it on
wherever more than one process writes the same store. Without it, two writers
racing on one entry silently lose one of the two values — and the loser is told
the write succeeded.

How airtight it is depends on the store:

| Store | Contested write |
| --- | --- |
| `PostgresStore` | Settled by the database, in one statement |
| `SqliteStore` | Settled by SQLite, in one statement |
| `FileStore` | Settled under a lock file, one writer at a time |
| `MemoryStore` | Settled — there is only one process to contend |
| Your own | Checked, then written: narrower, not closed |

A custom store gets the weaker guarantee unless it implements `putIf`, which is
one method and optional. Nothing breaks without it; the window between the
check and the write just stays open.

`remove` takes `expectedRevision` too. That one is read-then-delete rather than
a single step, because a delete you can see is easier to live with than a write
you cannot.

## Moving a vault

`exportAll` packs everything into one sealed document, and `importAll` unpacks
it somewhere else:

```ts
const carried = generateKey()
await Bun.write("backup.txt", await vault.exportAll(carried))

// on the other machine, in a vault with a master key of its own
const report = await elsewhere.importAll(await Bun.file("backup.txt").text(), carried)
// { imported: 42, skipped: [] }
```

Values are opened and re-sealed under the key you pass, rather than copied
across as they are — which is what lets the far end have a different master key.
Metadata, expiry, rotation policies, finality and history come too.

Two things follow from that. It is the one operation that holds every secret in
memory at once, so give it a key you would give the vault itself and treat the
document as the vault in a single string. And it refuses rather than skipping
when a value will not open: an export that quietly dropped what it could not
read would look like a backup right up until you needed it.

An import leaves entries that already exist alone and names them in `skipped`,
unless you pass `{ overwrite: true }`. Restoring a backup over a vault that has
moved on should not silently undo the newer values.

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
