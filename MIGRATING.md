# Upgrading to 2.0

Four things changed. Two need action; two are type-level and the compiler will
find them for you.

## 1. Entries written before 1.4 no longer open by default

1.4 tied each entry's data key to its owner and name, so sealed bytes copied
between rows stop opening. Entries written before that have no tie. Through
1.x the vault silently fell back to opening them anyway — which meant a vault
could carry untied entries for years without anyone noticing.

Since 2.0 it does not. **Migrate before upgrading, or turn the fallback back on
while you do.**

The safe order, on 1.7:

```ts
await vault.reseal()          // ties every entry down, master key unchanged
```

`reseal` keeps the same master key, so it is the cheap one. `rekey` does it too
if you were changing keys anyway.

Then on 2.0, confirm:

```ts
const vault = new Vault({ key, store, allowUnbound: true })
const { untied, unopenable } = await vault.unbound()
```

`untied` empty means you are done — drop `allowUnbound` and the vault is strict.
`unopenable` is a separate problem: those entries do not open under any key this
vault holds, which was true before the upgrade too.

If you upgrade first and find things failing, `allowUnbound: true` restores the
old behaviour so you can run `reseal` and then turn it off.

## 2. `strictWrites` is on by default

A write that would land on top of a change made since the vault last read the
entry now throws 409 instead of overwriting it silently. This is what you want
if more than one process writes the store, and it is one more error to handle
if only one does.

To keep 1.x behaviour:

```ts
new Vault({ key, store, strictWrites: false })
```

## 3. A custom store must implement `putIf`

Only if you wrote your own `VaultStore`; the four that ship already do.

Through 1.x it was optional, and a store without it got a read-then-write with
a window where two writers could both believe they had won. With `strictWrites`
now on by default, that window would be a promise the vault could not keep.

```ts
async putIf(record, expectedRevision) {
    // Compare and set in one statement: an UPDATE … WHERE revision = ?,
    // or whatever your database does atomically.
    // Return the written record, or null if the revision did not match.
}
```

`page` is still optional. Its absence costs memory, not a guarantee.

## 4. `SecretRecord.revision` and `.shares` are required

Again, only for a custom store. Both were optional so that stores written
against older versions kept compiling. Keep `revision` as the number the vault
hands you, and `shares` as an array that may be empty.

At runtime the vault still reads a missing `revision` as 1 and a missing
`shares` as none, so a 1.x store will not break mid-upgrade — the types just say
what a store is expected to keep now.

## Nothing else moved

Every other method has the same name, the same arguments and the same meaning.
`open`, `read`, `resolve`, `put`, `rotate`, `share`, `exportAll` and the rest are
unchanged.
