import { generateKey, importKey, open, seal } from "./crypto"
import { dataUrl, parseDataUrl } from "./dataurl"
import { VaultError, VaultKeyError } from "./errors"
import {
    isKeyProvider,
    isKeyWrapper,
    staticKey,
    type KeyProvider,
    type KeyWrapper,
} from "./providers"
import type {
    AuditLog,
    PutOptions,
    RotationPolicy,
    SecretRecord,
    SecretSummary,
    Share,
    VaultEvent,
    VaultStore,
} from "./types"

/**
 * How a stored value is referenced from configuration.
 *
 * @remarks
 * {@link Vault.resolve} substitutes any value that starts with this. Give a
 * vault its own {@link VaultOptions.prefix} when `@vault:` already means
 * something else in the configuration you are resolving.
 *
 * @defaultValue `"@vault:"`
 */
export const DEFAULT_PREFIX = "@vault:"

/**
 * How many previous values an entry keeps, unless you say otherwise.
 *
 * @remarks
 * Only {@link Vault.rotate} adds to history, so this is how many superseded
 * values {@link Vault.versions} can still hand back.
 *
 * @defaultValue 5
 * @see {@link VaultOptions.historyLimit}
 */
export const DEFAULT_HISTORY_LIMIT = 5

/** How many records the vault reads at a time when walking the whole store. */
export const DEFAULT_PAGE_SIZE = 200

/**
 * The metadata key marking an entry as bytes rather than text.
 *
 * @remarks
 * In the metadata rather than a field of its own so that every store already
 * carries it, including one written against an older version. It is in the
 * clear, like all metadata — that an entry holds bytes is not a secret.
 */
export const BYTES_MARKER = "@vault:bytes"

/**
 * The metadata key holding an entry's media type.
 *
 * @remarks
 * Beside {@link BYTES_MARKER} and in the clear for the same reason: what kind
 * of thing an entry is helps a listing without saying what it says.
 */
export const TYPE_MARKER = "@vault:type"

/**
 * What ends a name inside a longer string.
 *
 * @remarks
 * Anything outside the characters a name may contain. Used to tell a string
 * that *is* a reference from one that merely holds some.
 */
const NAME_END = /[^A-Za-z0-9._/-]/

/** What {@link Vault.putBytes} accepts beyond a {@link Vault.put}. */
export type PutBytesOptions = PutOptions & {
    /**
     * What the bytes are — `image/png`, `application/pkcs8`.
     *
     * @remarks
     * Stored in the clear with the rest of the metadata, and used by
     * {@link Vault.openDataUrl}. Left out, the entry is bytes of no stated
     * kind and a data URL calls them `application/octet-stream`.
     */
    contentType?: string
}

/** What {@link Vault.unbound} found still needing migration. */
export type UnboundReport = {
    /**
     * Entries whose data key opens, but is not tied to the entry — written
     * before 1.4 and not rekeyed since.
     */
    untied: string[]
    /**
     * Entries that do not open under any key this vault holds, tied or not.
     *
     * @remarks
     * A different problem, and one that was there before the upgrade: a key
     * that was retired without a `rekey`, or a record altered underneath the
     * vault. Listed separately so a migration is not mistaken for a loss.
     */
    unopenable: string[]
}

/** One page of a listing, and where to carry on from. */
export type Page = {
    /** The entries on this page, by name. */
    entries: SecretSummary[]
    /**
     * What to pass as `after` for the next page, or null when this was the
     * last one.
     */
    cursor: string | null
}

/** What a document from {@link Vault.exportAll} starts with. */
export const EXPORT_MAGIC = "VAULTEXPORT1"

/**
 * What a document from {@link Vault.exportStream} starts with.
 *
 * @remarks
 * A second format because the first is one sealed blob, which cannot be
 * written or read a piece at a time. This one seals each entry on its own line,
 * so neither end has to hold the whole vault. {@link Vault.importAll} reads
 * both.
 */
export const EXPORT_MAGIC_STREAM = "VAULTEXPORT2"

/** What an import wrote, and what it left alone. */
export type ImportReport = {
    /** How many entries were written. */
    imported: number
    /** Entries already present and left as they were, by `owner/name`. */
    skipped: string[]
}

const NAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/

/**
 * What a random rotation draws from unless the policy says otherwise.
 *
 * @remarks
 * Letters and digits only, so a generated value survives being pasted into a
 * shell command or a connection string without quoting. Set
 * {@link RotationPolicy.alphabet} for anything narrower or wider.
 *
 * @defaultValue A-Z, a-z and 0-9: 62 characters
 * @see {@link randomValue}
 */
export const DEFAULT_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

/**
 * Everything a generator is told: which entry is being rotated and the
 * non-secret arguments its policy carries. Deliberately not the current value —
 * a generator that needs it can ask the vault for it.
 *
 * @see {@link Generator}, {@link RotationPolicy.arguments}
 */
export type RotationContext = {
    /** Whose entry is being rotated. */
    owner: string
    /** Which entry is being rotated. */
    name: string
    /** The non-secret arguments its policy carries. */
    arguments: Record<string, string>
}

/**
 * Produces the next value for an entry whose policy names it.
 *
 * @remarks
 * Registered under a name in {@link VaultOptions.generators} and asked for by
 * {@link RotationPolicy.generator}. Use one where the vault cannot invent the
 * value itself — a key only the far end can mint, or a password that has to be
 * set on a database before it means anything.
 *
 * @param context Which entry is being rotated and its policy's arguments. Not
 *   the value being replaced.
 * @returns The next value, or a promise of it.
 *
 * @example Minting a key at the provider that issues it
 * ```ts
 * const vault = new Vault({
 *     key: generateKey(),
 *     store: new MemoryStore(),
 *     generators: {
 *         provider: async ({ arguments: args }) => mintKeyFor(args.account),
 *     },
 * })
 *
 * await vault.put("alice", "api", "old-key", {
 *     rotation: {
 *         kind: "generator",
 *         generator: "provider",
 *         arguments: { account: "acct_123" },
 *     },
 * })
 * await vault.rotate("alice", "api")
 * ```
 */
export type Generator = (context: RotationContext) => Promise<string> | string

/**
 * A random string of `length` characters drawn from `alphabet`.
 *
 * Sampling is rejected rather than folded with `%`, so every character is
 * equally likely however odd the alphabet's length.
 *
 * @param length How many characters to produce. Defaults to 32.
 * @param alphabet The characters to draw from. Defaults to
 *   {@link DEFAULT_ALPHABET}.
 * @returns A fresh string of exactly `length` characters.
 * @throws {@link VaultError} 422 when `length` is below one, or `alphabet` has
 *   fewer than two characters — neither can produce anything unguessable.
 *
 * @example
 * ```ts
 * randomValue()                        // 32 characters of A-Z, a-z, 0-9
 * randomValue(16, "0123456789abcdef")  // 16 hex characters
 * ```
 *
 * @see {@link RotationPolicy} to have the vault call this during a rotation.
 */
export function randomValue(length = 32, alphabet = DEFAULT_ALPHABET): string {
    if (length < 1) throw new VaultError("A generated value needs at least one character.")
    if (alphabet.length < 2) {
        throw new VaultError("A generated value needs an alphabet of at least two characters.")
    }

    const ceiling = Math.floor(256 / alphabet.length) * alphabet.length
    let value = ""
    while (value.length < length) {
        const bytes = crypto.getRandomValues(new Uint8Array(length))
        for (const byte of bytes) {
            if (byte >= ceiling) continue
            value += alphabet[byte % alphabet.length]
            if (value.length === length) break
        }
    }
    return value
}

/**
 * Everything a {@link Vault} is built from.
 *
 * @example
 * ```ts
 * import { Vault, MemoryStore, envKey } from "@mstone6969/vault"
 *
 * const vault = new Vault({
 *     key: envKey("VAULT_KEY"),
 *     store: new MemoryStore(),
 *     historyLimit: 2,
 *     onAccess: (event) => console.log(event.action, event.owner, event.name),
 * })
 * ```
 */
export type VaultOptions = {
    /**
     * What wraps this vault's data keys: base64 key material, an imported key,
     * a {@link KeyProvider} that finds one, or a {@link KeyWrapper} that keeps
     * the key somewhere this process cannot see it.
     */
    key: KeySource
    /** Where records are kept. */
    store: VaultStore
    /**
     * Reference prefix, `@vault:` unless you say otherwise.
     *
     * @defaultValue {@link DEFAULT_PREFIX}
     */
    prefix?: string
    /**
     * Keys this vault will still open values with, but never seal under.
     *
     * Keep the old key here while a `rekey` is in flight, or after one that did
     * not finish: values left under it stay readable instead of becoming
     * unopenable the moment the primary key changes.
     *
     * @defaultValue none
     * @see {@link Vault.rekey}
     */
    previousKeys?: KeySource[]
    /**
     * How many previous values `rotate` keeps.
     *
     * @defaultValue {@link DEFAULT_HISTORY_LIMIT}
     */
    historyLimit?: number
    /**
     * Functions that mint new values, by the name a rotation policy uses.
     *
     * The vault stores the *name*, never the function — so what is written down
     * is that an entry can be rotated, not how to impersonate the thing that
     * rotates it.
     *
     * @defaultValue none, so a `generator` policy fails with 501
     */
    generators?: Record<string, Generator>
    /**
     * Called after everything the vault does, for an audit trail. It is never
     * awaited and its failures are ignored — logging must not break a vault.
     *
     * @see {@link VaultEvent} for what it is told, including the refusals,
     *   which arrive as `denied` with a `detail` saying which rule was hit.
     */
    onAccess?: (event: VaultEvent) => void
    /**
     * Refuse any write that would overwrite a change made since the vault last
     * read the entry.
     *
     * @remarks
     * On by default since 2.0. Two writers racing on one entry would otherwise
     * silently lose one of the two values, and tell the loser it had succeeded
     * — which is not a default anything should have had.
     *
     * Turning it off restores 1.x behaviour: last write wins, quietly. There
     * are single-writer programs where that is fine and one fewer error to
     * handle.
     *
     * A caller passing {@link PutOptions.expectedRevision} gets the same
     * protection for that one call whatever this is set to.
     *
     * @defaultValue true
     */
    strictWrites?: boolean
    /**
     * How many records to read at a time when walking the whole store.
     *
     * @remarks
     * Only used where the store implements {@link VaultStore.page}. Larger
     * pages mean fewer round trips and more memory held at once.
     *
     * @defaultValue {@link DEFAULT_PAGE_SIZE}
     */
    pageSize?: number
    /**
     * Open entries written before 1.4, whose data keys are not tied to their
     * entry.
     *
     * @remarks
     * Through 1.x the vault always fell back to this, which meant a vault could
     * carry untied entries for years without anyone noticing. Since 2.0 it is
     * off, and such an entry fails to open rather than quietly working.
     *
     * Turn it on to migrate: run `rekey` or `reseal`, which ties every entry
     * down on the way past, then turn it off again. `unbound()` says whether
     * anything is left.
     *
     * @defaultValue false
     * @see {@link Vault.unbound}
     */
    allowUnbound?: boolean
    /**
     * Where to write an audit trail that outlives the process.
     *
     * @remarks
     * Unlike {@link VaultOptions.onAccess}, which is a callback the vault does
     * not wait for, this is awaited — and by default a log that cannot be
     * written **fails the operation**. An audit trail with silent gaps is worse
     * than no audit trail, because it looks like evidence. Pass
     * `{ log, required: false }` for a best-effort log instead.
     *
     * Both can be set: the callback for live logging, the log for the record.
     *
     * @defaultValue none
     * @see {@link AuditLog}
     */
    audit?:
        | AuditLog
        | {
              /** Where to write it. */
              log: AuditLog
              /**
               * Whether a log that cannot be written should fail the operation.
               *
               * @defaultValue true
               */
              required?: boolean
          }
}

/** {@link PutOptions} plus what only the vault itself may set. */
type InternalPutOptions = PutOptions & {
    /** Stamped by {@link Vault.rotate}, so a rotation is one write and not two. */
    rotatedAt?: Date
}

/**
 * What a pass of {@link Vault.rotateDue} rotated, and what it could not.
 *
 * @see {@link Vault.rotateDue}
 */
export type RotateDueReport = {
    /** Entries rotated, by `owner/name`. */
    rotated: string[]
    /** Entries that would not rotate, left exactly as they were. */
    failed: {
        /** Which entry, as `owner/name`. */
        name: string
        /** What went wrong, as the error said it. */
        reason: string
    }[]
}

/** Who is reading, when it is not the entry's own owner. */
export type Access = {
    /**
     * The owner the entry belongs to, for reading something shared with you.
     *
     * @remarks
     * Left out, the entry is the caller's own. Naming an owner asks for their
     * entry instead, which works only if they shared it — and keeps a grant
     * from colliding with something the caller already keeps under that name.
     *
     * @see {@link Vault.share}
     */
    from?: string
}

/**
 * What a `rekey` did, and to what it could not do it.
 *
 * @see {@link Vault.rekey}
 */
export type RekeyReport = {
    /** How many entries were re-sealed under the new key. */
    rekeyed: number
    /** Entries that would not open, by `owner/name`, left exactly as they were. */
    failed: string[]
}

/** Anything the vault will take as the thing that wraps its data keys. */
export type KeySource = string | CryptoKey | KeyProvider | KeyWrapper

function toKey(key: string | CryptoKey | KeyProvider): Promise<CryptoKey> {
    const provider = isKeyProvider(key) ? key : staticKey(key)
    return Promise.resolve(provider.key()).then((resolved) =>
        typeof resolved === "string" ? importKey(resolved) : resolved
    )
}

/**
 * What the vault actually asks of a key: wrap a data key, unwrap it again.
 *
 * @remarks
 * The one place the difference between a key held here and a key held by a KMS
 * lives. Everything above this works the same either way, which is why moving a
 * vault onto a KMS is a `rekey` rather than a migration.
 *
 * `binding` is undefined only for entries written before 1.4, which have none.
 */
type Wrapper = {
    wrap(material: string, binding: string | undefined): Promise<string>
    unwrap(wrapped: string, binding: string | undefined): Promise<string>
}

/**
 * Turns anything a caller may pass as a key into a {@link Wrapper}.
 *
 * @param source A key, a provider, or a wrapper.
 * @returns Something that wraps and unwraps data keys.
 */
function toWrapper(source: KeySource): Wrapper {
    if (isKeyWrapper(source)) {
        return {
            // A binding of "" rather than none: a service that takes an
            // encryption context needs *something*, and empty says "unbound"
            // consistently in both directions.
            wrap: (material, binding) => source.wrap(material, binding ?? ""),
            unwrap: (wrapped, binding) => source.unwrap(wrapped, binding ?? ""),
        }
    }

    // Resolved once, on first use: a provider may be slow or may fail, and a
    // vault nobody uses should do neither.
    let key: Promise<CryptoKey> | null = null
    const resolve = () => (key ??= toKey(source))

    return {
        async wrap(material, binding) {
            return seal(await resolve(), material, binding)
        },
        async unwrap(wrapped, binding) {
            return open(await resolve(), wrapped, binding)
        },
    }
}

function summarise(record: SecretRecord): SecretSummary {
    const { sealed: _sealed, sealedKey: _key, plain, history, ...rest } = record
    const summary: SecretSummary = { ...rest, versions: history.length }
    if (!record.isSealed && plain !== null) summary.value = plain
    return summary
}

/** One entry inside an export document: opened, so it can be re-sealed. */
type ExportedEntry = {
    owner: string
    name: string
    value: string
    history: string[]
    isSealed: boolean
    isFinal: boolean
    expiresAt: string | Date | null
    rotation: SecretRecord["rotation"]
    rotatedAt: string | Date | null
    metadata: Record<string, string>
    createdAt: string | Date
    updatedAt: string | Date
}

function isExpired(record: SecretRecord, now: Date): boolean {
    return record.expiresAt !== null && record.expiresAt.getTime() <= now.getTime()
}

/**
 * A write-only credential store: values go in, and only `open`, `read` and
 * `resolve` take them out again.
 *
 * Every value is sealed under its own data key, and only that key is sealed
 * under the master key. Changing the master key therefore re-seals a handful of
 * bytes per entry rather than every value, and one exposed data key exposes one
 * value rather than all of them.
 *
 * @example Storing a credential and handing it to the thing that needs it
 * ```ts
 * import { Vault, MemoryStore, generateKey } from "@mstone6969/vault"
 *
 * const vault = new Vault({ key: generateKey(), store: new MemoryStore() })
 *
 * await vault.put("alice", "stripe_key", "sk_live_x", {
 *     metadata: { kind: "api" },
 * })
 *
 * // Nothing but open, read and resolve gets the value back out.
 * await vault.list("alice")   // name, metadata, dates — no value
 * await vault.open("alice", "stripe_key")
 * await vault.resolve("alice", { STRIPE_KEY: "@vault:stripe_key" })
 * ```
 *
 * @see {@link VaultOptions} for what it is built from, {@link VaultStore} for
 *   where the records go, and {@link VaultError} for what it throws.
 */
export class Vault {
    /** What wraps this vault's data keys, and what used to. Built at
     * construction but not contacted until something needs a key. */
    private current: Wrapper
    private retiredWrappers: Wrapper[]
    private readonly store: VaultStore
    private readonly historyLimit: number
    private readonly generators: Record<string, Generator>
    private readonly onAccess: ((event: VaultEvent) => void) | undefined
    private readonly strictWrites: boolean
    private readonly audit: AuditLog | undefined
    private readonly auditRequired: boolean
    private readonly pageSize: number
    private readonly allowUnbound: boolean
    /** The prefix {@link Vault.resolve} treats as a reference. */
    readonly prefix: string

    /**
     * @param options The key, the store and the policies this vault applies.
     *   Nothing is contacted here: the key is resolved on first use, so a vault
     *   built from a provider that is slow or unreachable costs nothing until
     *   something asks it for a value.
     */
    constructor({
        key,
        store,
        prefix = DEFAULT_PREFIX,
        previousKeys = [],
        historyLimit = DEFAULT_HISTORY_LIMIT,
        generators = {},
        onAccess,
        strictWrites = true,
        audit,
        pageSize = DEFAULT_PAGE_SIZE,
        allowUnbound = false,
    }: VaultOptions) {
        this.current = toWrapper(key)
        this.retiredWrappers = previousKeys.map(toWrapper)
        this.store = store
        this.prefix = prefix
        this.historyLimit = historyLimit
        this.generators = generators
        this.onAccess = onAccess
        this.strictWrites = strictWrites

        const settings = audit && "log" in audit ? audit : { log: audit, required: true }
        this.audit = settings.log
        this.auditRequired = settings.required ?? true
        this.pageSize = pageSize
        this.allowUnbound = allowUnbound
    }



    /**
     * Every record in the store, a page at a time where the store can do that.
     *
     * @remarks
     * What `rekey`, `reseal`, `purgeExpired`, `rotationDue`, `sharedWith` and
     * `exportAll` walk. A store with {@link VaultStore.page} is read in pages,
     * so none of those holds the whole vault in memory; one without falls back
     * to {@link VaultStore.all}, which is what they all used to do.
     *
     * @param owner Only this owner's records, or every owner when left out.
     * @yields Each record, ordered by owner then name when paged.
     */
    private async *scan(owner?: string): AsyncGenerator<SecretRecord> {
        if (owner !== undefined) {
            // One owner is already a bounded read; every store can do it.
            for (const record of await this.store.list(owner)) yield record
            return
        }

        if (!this.store.page) {
            for (const record of await this.store.all()) yield record
            return
        }

        let after: string | null = null
        for (;;) {
            const page: SecretRecord[] = await this.store.page(after, this.pageSize)
            for (const record of page) yield record

            if (page.length < this.pageSize) return
            const last = page[page.length - 1]!
            after = `${last.owner}\u0000${last.name}`
        }
    }

    /**
     * Reports one action to `onAccess` and, if there is one, writes it to the
     * audit log.
     *
     * @remarks
     * `onAccess` stays fire-and-forget: it is a callback for logging, and a
     * logger that throws must not take the vault with it.
     *
     * A stored audit log is the opposite. It is awaited, and by default a log
     * that cannot be written fails the operation — an audit trail that silently
     * loses entries is worse than none at all, because it looks like evidence.
     *
     * The entry is written after the action and before the call returns, so a
     * failed append reports an operation that did in fact happen. That is the
     * cost of recording outcomes rather than intentions, and it fails in the
     * safe direction: the caller is told something went wrong.
     *
     * @param event What happened.
     * @returns Nothing, once it is recorded.
     * @throws {@link VaultError} 500 when a required audit log will not take it.
     */
    private async record(event: Omit<VaultEvent, "at">): Promise<void> {
        const entry: VaultEvent = { ...event, at: new Date() }

        if (this.onAccess) {
            try {
                this.onAccess(entry)
            } catch {
                // An audit trail that throws must not take the vault with it.
            }
        }

        if (!this.audit) return

        try {
            await this.audit.append(entry)
        } catch (error) {
            if (!this.auditRequired) return
            throw new VaultError(
                `The audit log would not take this ${entry.action}, so it was refused: ` +
                    `${error instanceof Error ? error.message : String(error)}`,
                500
            )
        }
    }

    /** Opens something with the master key, falling back to retired ones. */
    private async unsealWithMaster(
        sealed: string,
        binding: string | undefined
    ): Promise<string> {
        try {
            return await this.current.unwrap(sealed, binding)
        } catch (error) {
            for (const previous of this.retiredWrappers) {
                try {
                    return await previous.unwrap(sealed, binding)
                } catch {
                    // Not this one either; keep going.
                }
            }
            throw error
        }
    }

    /** Opens a value: its data key first, then the value under that key. */
    private async unseal(
        sealed: string,
        sealedKey: string | null,
        binding: string
    ): Promise<string> {
        if (!sealedKey) {
            // Written before envelope encryption: sealed under the master key.
            return this.unsealWithMaster(sealed, undefined)
        }

        return open(await importKey(await this.rewrap(sealedKey, binding)), sealed)
    }

    /** Seals a value under a fresh data key, and that key under the master. */
    private async enseal(
        value: string,
        binding: string
    ): Promise<{ sealed: string; sealedKey: string }> {
        const material = generateKey()
        const dataKey = await importKey(material)
        return {
            sealed: await seal(dataKey, value),
            // The data key is what is tied to the entry. Binding it is enough:
            // the value cannot be opened without its own key, so ciphertext
            // moved to another entry is ciphertext nobody can unwrap.
            sealedKey: await this.current.wrap(material, binding),
        }
    }

    /**
     * What an entry's data key is sealed as belonging to.
     *
     * @remarks
     * Owner and name, separated by a byte that cannot occur in either — a name
     * is checked against a character class that excludes it, and joining them
     * any other way would let `("a/b", "c")` and `("a", "b/c")` produce the
     * same binding.
     *
     * @param owner Whose entry it is.
     * @param name What it is called.
     * @returns The binding to seal and open its data key with.
     */
    private static binding(owner: string, name: string): string {
        return `${owner}\u0000${name}`
    }

    private checkName(name: string): string {
        const clean = String(name ?? "").trim()
        if (!NAME_PATTERN.test(clean)) {
            throw new VaultError(
                "A name can be up to 64 characters: letters, numbers, dot, dash or underscore."
            )
        }
        return clean
    }

    /**
     * Everything an owner holds, sorted by name. Never a sealed value.
     *
     * @param owner Whose entries to list.
     * @returns One summary per entry, in name order. A sealed value is absent
     *   entirely; an entry stored in the open carries its value in `value`.
     *
     * @remarks
     * Expiry hides nothing here: an entry past its `expiresAt` is still listed,
     * and still refuses to open, until {@link Vault.purgeExpired} clears it.
     *
     * @example
     * ```ts
     * await vault.put("alice", "stripe_key", "sk_live_x", {
     *     metadata: { kind: "api" },
     * })
     *
     * const [entry] = await vault.list("alice")
     * entry.name      // "stripe_key"
     * entry.metadata  // { kind: "api" }
     * entry.versions  // 0
     * ```
     *
     * @see {@link SecretSummary}
     * @param where Metadata every returned entry must match exactly. Only
     *   metadata, because it is the only part kept in the clear — filtering on
     *   a value would mean opening every secret to answer a listing.
     */
    async list(
        owner: string,
        where: Record<string, string> = {}
    ): Promise<SecretSummary[]> {
        const wanted = Object.entries(where)
        const records = await this.store.list(owner)

        return records
            .filter((record) =>
                wanted.every(([field, value]) => record.metadata[field] === value)
            )
            .map(summarise)
            .sort((a, b) => a.name.localeCompare(b.name))
    }

    /**
     * Stores a value, replacing whatever was under that name.
     *
     * `metadata` is kept in the clear and comes back from `list`, so it must
     * hold nothing secret — a credential's kind, or the username it belongs to,
     * not the password.
     *
     * @param owner Whose entry it is. Owners never see each other's entries.
     * @param name What to call it: 1-64 characters of letters, numbers, dot,
     *   dash or underscore. Surrounding whitespace is trimmed.
     * @param value The value to store.
     * @param options Metadata, expiry, rotation policy, and whether the entry
     *   is sealed, final, or keeps what it replaces. An option left out is
     *   inherited from the existing entry.
     * @returns The stored entry, summarised — never its sealed value.
     * @throws {@link VaultError} 422 when the name is not 1-64 characters of
     *   letters, numbers, dot, dash or underscore, or the value is empty.
     * @throws {@link VaultError} 409 when the entry is already there and
     *   `final`: it can be deleted, never replaced.
     *
     * @example Replacing a value without restating what the entry is
     * ```ts
     * await vault.put("alice", "db", "first-password", {
     *     metadata: { kind: "login", username: "ada" },
     *     rotation: { kind: "random", length: 24 },
     * })
     *
     * // Still a login, still rotatable at 24 characters, still sealed.
     * await vault.put("alice", "db", "second-password")
     * ```
     *
     * @see {@link Vault.rotate} to replace a value and keep the old one,
     *   {@link PutOptions} for the rest of the options.
     */
    async put(
        owner: string,
        name: string,
        value: string,
        options: PutOptions = {}
    ): Promise<SecretSummary> {
        // `rotate` stamps through here rather than writing a second time: two
        // writes would advance the revision twice for one logical change, and
        // the second one would not be guarded by anything.
        const { rotatedAt } = options as InternalPutOptions
        const clean = this.checkName(name)
        if (!value) throw new VaultError("A secret needs a value.")

        const existing = await this.store.get(owner, clean)
        if (existing?.isFinal) {
            await this.record({ action: "denied", owner, name: clean, detail: "final" })
            throw new VaultError(
                `"${clean}" is final: it cannot be changed, only deleted.`,
                409
            )
        }

        const now = new Date()
        // An option left out means "as it was": rotating a credential should
        // not quietly forget what kind it is or when it expires.
        const isSealed =
            options.sealed === undefined ? (existing?.isSealed ?? true) : options.sealed
        const history =
            options.keepHistory && existing && existing.sealed
                ? [
                      {
                          sealed: existing.sealed,
                          sealedKey: existing.sealedKey,
                          createdAt: existing.updatedAt,
                      },
                      ...existing.history,
                  ].slice(0, this.historyLimit)
                : (existing?.history ?? [])

        const body = isSealed
            ? { ...(await this.enseal(value, Vault.binding(owner, clean))), plain: null }
            : { sealed: "", sealedKey: null, plain: value }

        const record = {
            owner,
            name: clean,
            ...body,
            isSealed,
            isFinal: options.final ?? existing?.isFinal ?? false,
            rotation:
                options.rotation === undefined
                    ? (existing?.rotation ?? null)
                    : options.rotation,
            rotatedAt: rotatedAt ?? existing?.rotatedAt ?? null,
            expiresAt:
                options.expiresAt === undefined
                    ? (existing?.expiresAt ?? null)
                    : options.expiresAt,
            history,
            metadata: options.metadata ?? existing?.metadata ?? {},
            createdAt: existing?.createdAt ?? now,
            updatedAt: now,
            // A record from before revisions reads as 1, so it must be written
            // back as 2 — counting from 0 would leave it stuck at 1 forever.
            revision: (existing ? (existing.revision ?? 1) : 0) + 1,
            // Grants survive a replacement, like everything else about an
            // entry: rotating a shared credential must not quietly revoke it.
            shares: existing?.shares ?? [],
        }

        const stored = await this.write(record, existing, options.expectedRevision)
        await this.record({ action: "put", owner, name: clean })
        return summarise(stored)
    }

    /**
     * Writes a record, comparing revisions first when anything asked us to.
     *
     * @param record The record to write, revision already incremented.
     * @param existing What was read a moment ago, or null.
     * @param expected What the caller demanded the revision be, if anything.
     * @returns The stored record.
     * @throws {@link VaultError} 409 when the entry is not at the revision it
     *   was supposed to be.
     */
    private async write(
        record: SecretRecord,
        existing: SecretRecord | null,
        expected: number | null | undefined
    ): Promise<SecretRecord> {
        // Nothing to compare against: the caller did not ask, and this vault
        // was not told to insist. 1.1 and earlier behaviour, exactly.
        if (expected === undefined && !this.strictWrites) {
            return this.store.put(record)
        }

        // Left to ourselves, we guard against whatever we just read — which is
        // what makes a lost update impossible rather than merely unlikely.
        const against =
            expected === undefined ? (existing ? (existing.revision ?? 1) : null) : expected

        const stored = await this.store.putIf(record, against)
        if (stored) return stored

        await this.record({
            action: "denied",
            owner: record.owner,
            name: record.name,
            detail: "revision",
        })
        throw new VaultError(
            against === null
                ? `"${record.name}" already exists.`
                : `"${record.name}" has changed since revision ${against}.`,
            409
        )
    }

    /**
     * Stores bytes rather than text — a certificate, a keyfile, a kubeconfig.
     *
     * @remarks
     * Values are text underneath, so this base64s on the way in and
     * {@link Vault.openBytes} decodes on the way out. Doing it here rather than
     * leaving it to every caller means one encoding rather than several, and
     * `openBytes` refuses a value that was not written this way instead of
     * handing back plausible-looking rubbish.
     *
     * Everything else about the entry works the same: metadata, expiry,
     * rotation, sharing, history.
     *
     * @param owner Whose entry it is.
     * @param name What to call it.
     * @param value The bytes.
     * @param options As {@link Vault.put}, plus `contentType` to say what the
     *   bytes are — kept in the clear beside the other metadata, and what
     *   {@link Vault.openDataUrl} puts in the URL. `sealed: false` is refused:
     *   bytes kept in the clear would be base64 in the database and read back
     *   as text, which is a trap rather than a feature.
     * @returns The entry, summarised.
     * @throws {@link VaultError} 422 when asked to store bytes in the open, or
     *   when the name is not a legal one.
     * @throws {@link VaultError} 409 when the entry is final.
     *
     * @example
     * ```ts
     * await vault.putBytes("alice", "tls-key", await Bun.file("tls.key").bytes())
     * const key = await vault.openBytes("alice", "tls-key")
     * ```
     */
    async putBytes(
        owner: string,
        name: string,
        value: Uint8Array,
        options: PutBytesOptions = {}
    ): Promise<SecretSummary> {
        if (options.sealed === false) {
            throw new VaultError(
                "Bytes cannot be stored in the open: they would be base64 in the " +
                    "database and come back as text."
            )
        }
        if (value.length === 0) throw new VaultError("A secret needs a value.")

        return this.put(owner, name, Buffer.from(value).toString("base64"), {
            ...options,
            metadata: {
                ...(options.metadata ?? {}),
                [BYTES_MARKER]: "base64",
                ...(options.contentType === undefined
                    ? {}
                    : { [TYPE_MARKER]: options.contentType }),
            },
        })
    }

    /**
     * Reads back what {@link Vault.putBytes} stored.
     *
     * @param owner Whose entry it is.
     * @param name The entry to open.
     * @param access `from` to read something another owner shared.
     * @returns The bytes.
     * @throws {@link VaultError} 404 when there is no such entry.
     * @throws {@link VaultError} 410 when it has expired.
     * @throws {@link VaultError} 415 when the entry holds text rather than
     *   bytes — better than base64-decoding a password and returning noise.
     * @throws {@link VaultError} 403 when it belongs to somebody who has not
     *   shared it.
     */
    async openBytes(owner: string, name: string, access: Access = {}): Promise<Uint8Array> {
        const clean = this.checkName(name)
        const record = await this.reach(owner, clean, access.from)

        if (record.metadata[BYTES_MARKER] === undefined) {
            throw new VaultError(
                `"${clean}" holds text, not bytes. Use open() for it.`,
                415
            )
        }

        return new Uint8Array(Buffer.from(await this.open(owner, clean, access), "base64"))
    }

    /**
     * An entry as a data URL, ready to hand to anything that takes one.
     *
     * @remarks
     * The point is to get from a stored secret to something usable without the
     * caller doing the base64 and the media type by hand each time — an
     * `<img src>`, a `fetch`, a config field that wants an inline certificate.
     *
     * Bytes use the `contentType` they were stored with, or
     * `application/octet-stream` when they were stored without one. A text
     * entry becomes `text/plain;charset=utf-8`, since that is what it is.
     *
     * The URL contains the secret. It is as sensitive as the value itself, and
     * data URLs have a way of ending up in logs, DOM dumps and browser history
     * — treat what comes back the way you would treat {@link Vault.open}.
     *
     * @param owner Whose entry it is.
     * @param name The entry to encode.
     * @param access `from` to read something another owner shared.
     * @returns `data:<type>;base64,<value>`.
     * @throws {@link VaultError} 404 when there is no such entry.
     * @throws {@link VaultError} 410 when it has expired.
     * @throws {@link VaultError} 403 when it belongs to somebody who has not
     *   shared it.
     *
     * @example
     * ```ts
     * await vault.putBytes("alice", "logo", png, { contentType: "image/png" })
     * await vault.openDataUrl("alice", "logo")
     * // "data:image/png;base64,iVBORw0KGgo…"
     * ```
     */
    async openDataUrl(owner: string, name: string, access: Access = {}): Promise<string> {
        const clean = this.checkName(name)
        const record = await this.reach(owner, clean, access.from)

        if (record.metadata[BYTES_MARKER] === undefined) {
            const text = await this.open(owner, clean, access)
            return dataUrl(new TextEncoder().encode(text), "text/plain;charset=utf-8")
        }

        return dataUrl(
            await this.openBytes(owner, clean, access),
            record.metadata[TYPE_MARKER] ?? "application/octet-stream"
        )
    }

    /**
     * Stores what a data URL carries, keeping its media type.
     *
     * @remarks
     * The way back in: a file picked in a browser, a certificate pasted as a
     * URL, anything already in that shape. The media type from the URL becomes
     * the entry's `contentType`, so {@link Vault.openDataUrl} gives back the
     * same URL it was handed.
     *
     * @param owner Whose entry it is.
     * @param name What to call it.
     * @param url The data URL, base64 or percent-encoded.
     * @param options As {@link Vault.putBytes}. A `contentType` given here wins
     *   over the one in the URL.
     * @returns The entry, summarised.
     * @throws {@link VaultError} 422 when it is not a data URL, or its payload
     *   will not decode.
     *
     * @example
     * ```ts
     * await vault.putDataUrl("alice", "logo", "data:image/png;base64,iVBORw0KGgo=")
     * ```
     */
    async putDataUrl(
        owner: string,
        name: string,
        url: string,
        options: PutBytesOptions = {}
    ): Promise<SecretSummary> {
        const { mediaType, bytes } = parseDataUrl(url)
        return this.putBytes(owner, name, bytes, {
            ...options,
            contentType: options.contentType ?? mediaType,
        })
    }

    /**
     * Replaces a value, keeping the one it replaces.
     *
     * Called without a value, the entry's rotation policy produces one — which
     * is the point of storing a policy: whatever runs the rotation is told how
     * to make the next password, never what the current one is.
     *
     * Previous values stay openable, so a job that read the credential moments
     * before a rotation can still finish on what it was given.
     *
     * @param owner Whose entry to rotate.
     * @param name The entry to rotate.
     * @param value The new value. Left out, the entry's rotation policy makes
     *   one.
     * @param options As {@link Vault.put}, minus `keepHistory`: a rotation
     *   always keeps what it replaced, up to {@link VaultOptions.historyLimit}.
     * @returns The rotated entry, summarised, with `rotatedAt` stamped.
     * @throws {@link VaultError} 404 when no value is given and there is no
     *   such entry to take a policy from.
     * @throws {@link VaultError} 410 when no value is given and the entry has
     *   expired.
     * @throws {@link VaultError} 422 when no value is given and the entry has
     *   no rotation policy to make one with.
     * @throws {@link VaultError} 501 when the policy names a generator this
     *   vault was not constructed with.
     * @throws {@link VaultError} 409 when the entry is final.
     *
     * @example
     * ```ts
     * await vault.put("alice", "db", "first-password", {
     *     rotation: { kind: "random", length: 24 },
     * })
     *
     * const rotated = await vault.rotate("alice", "db")
     * rotated.rotatedAt                    // stamped just now
     * await vault.versions("alice", "db")  // ["first-password"]
     * ```
     *
     * @see {@link Vault.rotationDue} for which entries are asking for this.
     */
    async rotate(
        owner: string,
        name: string,
        value?: string,
        options: Omit<PutOptions, "keepHistory"> = {}
    ): Promise<SecretSummary> {
        const clean = this.checkName(name)
        const next = value ?? (await this.generate(owner, clean))

        await this.record({ action: "rotate", owner, name: clean })
        return this.put(owner, clean, next, {
            ...options,
            keepHistory: true,
            rotatedAt: new Date(),
        } as InternalPutOptions)
    }

    /** The next value an entry's policy calls for. */
    private async generate(owner: string, name: string): Promise<string> {
        const record = await this.require(owner, name)
        const policy = record.rotation

        if (!policy) {
            throw new VaultError(
                `"${name}" has no rotation policy, so there is nothing to make the next value with.`
            )
        }

        if (policy.kind === "random") {
            return randomValue(policy.length, policy.alphabet)
        }

        const generator = policy.generator ? this.generators[policy.generator] : undefined
        if (!generator) {
            throw new VaultError(
                `"${name}" wants the "${policy.generator ?? "unnamed"}" generator, which this vault does not have.`,
                501
            )
        }
        return generator({ owner, name, arguments: policy.arguments ?? {} })
    }

    /**
     * Entries whose policy says how often they want rotating, and whose time
     * has come. Nothing rotates them for you — schedule this and act on it.
     *
     * @param now The moment to judge against. Pass a later one to ask what will
     *   be due by then.
     * @returns Summaries of every entry, whoever owns it, whose
     *   {@link RotationPolicy.every} seconds have passed since it was last
     *   rotated — or since it was stored, if it never has been.
     *
     * @remarks
     * One of the three calls that reach across owners, so it belongs to
     * whatever runs the schedule rather than to a request.
     *
     * @example
     * ```ts
     * await vault.put("alice", "db", "x", {
     *     rotation: { kind: "random", every: 86_400 },
     * })
     *
     * for (const entry of await vault.rotationDue()) {
     *     await vault.rotate(entry.owner, entry.name)
     * }
     * ```
     */
    async rotationDue(now = new Date()): Promise<SecretSummary[]> {
        const due: SecretSummary[] = []
        for await (const record of this.scan()) {
            const every = record.rotation?.every
            if (!every) continue
            const last = (record.rotatedAt ?? record.createdAt).getTime()
            if (now.getTime() - last >= every * 1000) due.push(summarise(record))
        }
        return due
    }

    /**
     * Rotates everything a policy says is overdue.
     *
     * @remarks
     * The companion to {@link Vault.rotationDue}, which only tells you. Run it
     * on a schedule and credentials rotate themselves — which is the whole
     * point of an entry carrying a policy rather than a person remembering.
     *
     * One entry that will not rotate does not stop the others. A generator that
     * throws, an entry gone final, a policy naming a generator this vault does
     * not have: each is caught, named in `failed` with what went wrong, and the
     * run carries on. A rotation pass that abandoned the remaining credentials
     * because one provider was down would be worse than useless.
     *
     * @param now What to treat as the current time, for testing.
     * @returns What rotated, and what would not.
     *
     * @example
     * ```ts
     * const { rotated, failed } = await vault.rotateDue()
     * for (const { name, reason } of failed) console.warn(name, reason)
     * ```
     *
     * @see {@link Vault.rotationDue} to see what is overdue without acting.
     */
    async rotateDue(now = new Date()): Promise<RotateDueReport> {
        const report: RotateDueReport = { rotated: [], failed: [] }

        for (const due of await this.rotationDue(now)) {
            const where = `${due.owner}/${due.name}`
            try {
                await this.rotate(due.owner, due.name)
                report.rotated.push(where)
            } catch (error) {
                report.failed.push({
                    name: where,
                    reason: error instanceof Error ? error.message : String(error),
                })
            }
        }

        return report
    }

    /**
     * Previous values of an entry, newest first, opened.
     *
     * @param owner Whose entry it is.
     * @param name The entry to look back through.
     * @returns The values it used to hold, newest first, in the clear. Empty
     *   for an entry that has never been rotated.
     * @throws {@link VaultError} 404 when there is no such entry.
     * @throws {@link VaultError} 410 when the entry has expired.
     * @throws {@link VaultError} 422 when the name is not a legal one.
     * @throws {@link VaultKeyError} 500 when a kept value will not open under
     *   the master key or any of {@link VaultOptions.previousKeys}.
     *
     * @example
     * ```ts
     * await vault.put("alice", "deploy", "v1")
     * await vault.rotate("alice", "deploy", "v2")
     * await vault.rotate("alice", "deploy", "v3")
     *
     * await vault.versions("alice", "deploy")  // ["v2", "v1"]
     * ```
     */
    async versions(owner: string, name: string): Promise<string[]> {
        const record = await this.require(owner, name)
        return Promise.all(
            record.history.map((entry) =>
                this.unseal(entry.sealed, entry.sealedKey, Vault.binding(owner, name))
            )
        )
    }

    /**
     * True when the owner has a secret under that name, expired or not.
     *
     * @param owner Whose entry to look for.
     * @param name The name to look for.
     * @returns Whether a record exists under it.
     * @throws {@link VaultError} 422 when the name is not a legal one.
     *
     * @remarks
     * Opens nothing and is not stopped by expiry, so it answers "is this name
     * taken" rather than "can this value still be used".
     */
    async has(owner: string, name: string): Promise<boolean> {
        return (await this.store.get(owner, this.checkName(name))) !== null
    }

    /**
     * Removes a secret, returning false if it wasn't there.
     *
     * @param owner Whose entry to delete.
     * @param name The entry to delete.
     * @returns True when something was deleted, false when there was nothing
     *   under that name.
     * @throws {@link VaultError} 422 when the name is not a legal one.
     *
     * @remarks
     * Deleting takes the kept previous values with it, and it is the one thing
     * a `final` entry allows.
     * @param options `expectedRevision` refuses the delete unless the entry
     *   is still at that revision — for deleting something you just looked at
     *   and do not want to delete a newer version of. It is read-then-delete
     *   rather than one atomic step, so it narrows the window without closing
     *   it; a delete is easier to live with than a lost write, which is why
     *   this does not have the store-level guarantee `put` does.
     */
    async remove(
        owner: string,
        name: string,
        { expectedRevision }: { expectedRevision?: number } = {}
    ): Promise<boolean> {
        const clean = this.checkName(name)

        if (expectedRevision !== undefined) {
            const current = await this.store.get(owner, clean)
            if (current && (current.revision ?? 1) !== expectedRevision) {
                await this.record({ action: "denied", owner, name: clean, detail: "revision" })
                throw new VaultError(
                    `"${clean}" has changed since revision ${expectedRevision}.`,
                    409
                )
            }
        }

        const removed = await this.store.remove(owner, clean)
        if (removed) await this.record({ action: "remove", owner, name })
        return removed
    }

    private async require(
        owner: string,
        name: string,
        now = new Date()
    ): Promise<SecretRecord> {
        const clean = this.checkName(name)
        const record = await this.store.get(owner, clean)
        if (!record) throw new VaultError(`No secret named "${clean}" in the vault.`, 404)

        if (isExpired(record, now)) {
            await this.record({ action: "denied", owner, name: clean, detail: "expired" })
            throw new VaultError(`"${clean}" expired and can no longer be used.`, 410)
        }
        return record
    }

    /**
     * Reads one value back. The only way plaintext leaves a sealed entry — keep
     * it in memory and out of logs and responses.
     *
     * @param owner Whose entry to open.
     * @param name The entry to open.
     * @returns The value, sealed or not.
     * @throws {@link VaultError} 404 when there is no such entry.
     * @throws {@link VaultError} 410 when the entry has expired. The record is
     *   still there; it just cannot be used.
     * @throws {@link VaultError} 422 when the name is not a legal one.
     * @throws {@link VaultKeyError} 500 when the value will not open under the
     *   master key or any of {@link VaultOptions.previousKeys} — a wrong key or
     *   an altered value, which GCM cannot tell apart.
     *
     * @example
     * ```ts
     * await vault.put("alice", "token", "shhh")
     * await vault.open("alice", "token")  // "shhh"
     * ```
     *
     * @see {@link Vault.read} for entries stored in the open,
     *   {@link Vault.resolve} for substituting several at once.
     */
    async open(owner: string, name: string, { from }: Access = {}): Promise<string> {
        const record = await this.reach(owner, name, from)
        const value = record.isSealed
            ? await this.unseal(
                  record.sealed,
                  record.sealedKey,
                  Vault.binding(record.owner, record.name)
              )
            : (record.plain ?? "")

        await this.record({ action: "open", owner: record.owner, name, by: from && owner })
        return value
    }

    /**
     * Reads an entry stored in the open. A sealed one refuses.
     *
     * @param owner Whose entry to read.
     * @param name The entry to read.
     * @returns The value, which was stored with `open: true` and was therefore
     *   never secret.
     * @throws {@link VaultError} 403 when the entry is sealed.
     *   {@link Vault.open} is the only way a sealed value comes out.
     * @throws {@link VaultError} 404 when there is no such entry.
     * @throws {@link VaultError} 410 when the entry has expired.
     * @throws {@link VaultError} 422 when the name is not a legal one.
     *
     * @example
     * ```ts
     * await vault.put("alice", "region", "eu-west-1", { open: true })
     * await vault.read("alice", "region")  // "eu-west-1"
     *
     * await vault.put("alice", "token", "shhh")
     * await vault.read("alice", "token")   // throws: 403, sealed
     * ```
     */
    async read(owner: string, name: string, { from }: Access = {}): Promise<string> {
        const record = await this.reach(owner, name, from)
        if (record.isSealed) {
            await this.record({ action: "denied", owner: record.owner, name, detail: "sealed" })
            throw new VaultError(`"${name}" is sealed and cannot be read back.`, 403)
        }

        await this.record({ action: "read", owner: record.owner, name, by: from && owner })
        return record.plain ?? ""
    }

    /**
     * The record behind a read, whether it is the caller's own or one shared
     * with them.
     *
     * @param caller Who is asking.
     * @param name The entry they want.
     * @param from The owner it belongs to, when that is not the caller.
     * @returns The record, if they are allowed it.
     * @throws {@link VaultError} 404 when there is no such entry.
     * @throws {@link VaultError} 403 when it exists but is not shared with
     *   them, or the grant has lapsed.
     * @throws {@link VaultError} 410 when the entry has expired.
     */
    private async reach(
        caller: string,
        name: string,
        from: string | undefined
    ): Promise<SecretRecord> {
        if (from === undefined || from === caller) return this.require(caller, name)

        const now = new Date()
        const record = await this.require(from, name, now)
        const granted = (record.shares ?? []).find((share) => share.with === caller)

        if (!granted || (granted.expiresAt !== null && granted.expiresAt <= now)) {
            await this.record({
                action: "denied",
                owner: from,
                name,
                by: caller,
                detail: granted ? "grant expired" : "not shared",
            })
            throw new VaultError(
                `"${name}" belongs to ${from} and is not shared with ${caller}.`,
                403
            )
        }

        return record
    }

    /**
     * Substitutes `@vault:<name>` references in a set of values — an
     * environment, a config object — leaving everything else alone.
     *
     * A reference to a secret that isn't there, or that has expired, throws:
     * running with a blank credential is worse than not running.
     *
     * @typeParam T The shape passed in, which is the shape handed back.
     * @param owner Whose entries the references name.
     * @param values The set to substitute into. Not modified.
     * @returns A copy with every reference replaced by its value. Anything
     *   holding no references at all is handed straight back, not copied.
     * @throws {@link VaultError} 404 when a reference names no entry.
     * @throws {@link VaultError} 410 when a referenced entry has expired.
     * @throws {@link VaultError} 422 when what follows the prefix is not a
     *   legal name, or the structure refers back to itself.
     *
     * @remarks
     * Nested objects and arrays are walked, so a reference works anywhere in a
     * config file rather than only at the top level. Anything that is not a
     * string, a plain object or an array is passed through untouched — a Date
     * or a class instance comes out the far side as itself, not as a bag of
     * fields.
     *
     * Whitespace around the name is ignored, so `"@vault: token "` finds
     * `token`. Sealed and open entries both resolve; the prefix comes from
     * {@link Vault.prefix}.
     *
     * `"@vault:alice/token"` reaches a secret alice shared with the caller.
     * A name cannot contain a slash, so that form is never mistaken for one of
     * the caller's own entries.
     *
     * @example Filling in an environment before spawning something
     * ```ts
     * await vault.put("alice", "token", "secret")
     *
     * await vault.resolve("alice", {
     *     PLAIN: "kept",
     *     API_TOKEN: "@vault:token",
     * })
     * // { PLAIN: "kept", API_TOKEN: "secret" }
     * ```
     *
     * @example Anywhere in a config, not only at the top
     * ```ts
     * await vault.resolve("alice", {
     *     database: { host: "db.internal", password: "@vault:db" },
     *     webhooks: [{ url: "@vault:hook" }],
     * })
     * ```
     */
    async resolve<T>(owner: string, values: T): Promise<T> {
        return (await this.substitute(owner, values, new WeakSet())) as T
    }

    /**
     * Swaps every reference in one string for the secret it names.
     *
     * @remarks
     * A whole-string reference is handed back as the value itself, so a
     * reference is not forced through string conversion. Anything else — a
     * reference inside a connection string, a header, a URL — is substituted in
     * place.
     *
     * @param owner Whose secrets a reference may name.
     * @param value The string to substitute into.
     * @returns The string with its references replaced, or the same string when
     *   it holds none.
     */
    private async interpolate(owner: string, value: string): Promise<string> {
        if (!value.includes(this.prefix)) return value

        // The whole string is one reference: hand back the value itself rather
        // than a copy of it, which is what every version before 1.7 did.
        const whole = value.trim()
        if (whole.startsWith(this.prefix)) {
            // Trimmed before testing: whitespace around the name has always
            // been ignored, so "@vault: token " is still one whole reference.
            const named = whole.slice(this.prefix.length).trim()
            if (named.length > 0 && !NAME_END.test(named)) return this.lookup(owner, named)
        }

        const pattern = new RegExp(
            `${this.prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([A-Za-z0-9._/-]+)`,
            "g"
        )

        let out = ""
        let last = 0
        for (const found of value.matchAll(pattern)) {
            out += value.slice(last, found.index)
            out += await this.lookup(owner, found[1]!)
            last = found.index + found[0].length
        }

        return out + value.slice(last)
    }

    /**
     * The secret one reference names, whoever it belongs to.
     *
     * @remarks
     * `alice/token` reaches a secret alice shared; `token` is the caller's own.
     * A name cannot contain a slash, so the two forms never collide.
     *
     * @param owner Who is asking.
     * @param reference What followed the prefix.
     * @returns The value.
     */
    private async lookup(owner: string, reference: string): Promise<string> {
        const wanted = reference.trim()
        const slash = wanted.indexOf("/")

        return slash === -1
            ? this.open(owner, wanted)
            : this.open(owner, wanted.slice(slash + 1), { from: wanted.slice(0, slash) })
    }

    /**
     * Walks a value, swapping references for secrets as it goes.
     *
     * @param owner Whose secrets a reference may name.
     * @param value The value to walk: a string, an array, a plain object, or
     *   anything else, which is returned untouched.
     * @param seen Objects already on the path here, to catch a cycle rather
     *   than following it forever.
     * @returns The value with every reference in it replaced.
     * @throws {@link VaultError} 422 when the structure refers back to itself.
     */
    private async substitute(
        owner: string,
        value: unknown,
        seen: WeakSet<object>
    ): Promise<unknown> {
        if (typeof value === "string") return this.interpolate(owner, value)

        if (value === null || typeof value !== "object") return value

        // Dates, buffers, class instances: things that are objects but are not
        // configuration, and would come out the far side mangled.
        if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype) {
            return value
        }

        if (seen.has(value)) {
            throw new VaultError("That configuration refers back to itself.")
        }
        seen.add(value)

        try {
            // Rebuilt only if something in it actually changed, so a config
            // with no references in it comes back as the object handed over
            // rather than as a copy of it.
            let changed = false

            if (Array.isArray(value)) {
                const out = []
                for (const item of value) {
                    const next = await this.substitute(owner, item, seen)
                    changed ||= next !== item
                    out.push(next)
                }
                return changed ? out : value
            }

            const out: Record<string, unknown> = {}
            for (const [key, item] of Object.entries(value)) {
                const next = await this.substitute(owner, item, seen)
                changed ||= next !== item
                out[key] = next
            }
            return changed ? out : value
        } finally {
            // Off the path again: the same object appearing twice side by side
            // is repetition, not a cycle, and must still resolve.
            seen.delete(value)
        }
    }

    /**
     * Re-seals values under fresh data keys, without changing the master key.
     *
     * Cheap hygiene: the ciphertext of an unchanged secret stops being
     * comparable between two copies of the database taken at different times.
     *
     * @param owner Limit it to one owner's entries. Left out, it walks the
     *   whole store, whoever owns it.
     * @returns How many entries were re-sealed. Entries stored in the open hold
     *   nothing to re-seal and are skipped.
     * @throws {@link VaultKeyError} 500 when a value will not open. Unlike
     *   {@link Vault.rekey} this stops there, having already re-sealed the
     *   entries it got to — those are unharmed, since the key did not change.
     *
     * @example
     * ```ts
     * await vault.reseal("alice")  // just this owner
     * await vault.reseal()         // the whole store
     * ```
     */
    async reseal(owner?: string): Promise<RekeyReport> {
        const report: RekeyReport = { rekeyed: 0, failed: [] }

        for await (const record of this.scan(owner)) {
            if (!record.isSealed || !record.sealed) continue

            try {
                const bound = Vault.binding(record.owner, record.name)
                const value = await this.unseal(record.sealed, record.sealedKey, bound)
                await this.store.put({ ...record, ...(await this.enseal(value, bound)) })
                report.rekeyed += 1
            } catch {
                // One unopenable value must not abort the run and leave the
                // rest unsealed — same contract as rekey.
                report.failed.push(`${record.owner}/${record.name}`)
            }
        }
        return report
    }

    /**
     * Re-seals every data key under a new master key.
     *
     * The old key is kept as a fallback for the rest of this vault's life, so a
     * run that stops halfway leaves a mix that still opens. Construct the next
     * vault with `key: next, previousKeys: [old]` until you are confident, then
     * drop the old one.
     *
     * An entry that will not open is left untouched and named in the report,
     * because re-sealing what you cannot read would only destroy it.
     *
     * @param next The new master key: base64, already imported, or a provider
     *   that finds one.
     * @returns How many entries moved, and which would not, by `owner/name`.
     * @throws {@link VaultKeyError} 500 when `next` is not a usable key. It is
     *   resolved before anything is written, so nothing has changed.
     *
     * @remarks
     * Walks every owner, and changes this vault as it goes: from here on it
     * seals under `next` and keeps the key it had as a fallback. An entry
     * stored in the open holds no key and is skipped, and one written before
     * envelope encryption is given a data key on the way past.
     *
     * @example
     * ```ts
     * const next = generateKey()
     * const report = await vault.rekey(next)
     * report.rekeyed  // 2
     * report.failed   // ["alice/stranger"] — left exactly as they were
     *
     * // Until the failures are dealt with, keep the old key readable.
     * const moved = new Vault({ key: next, store, previousKeys: [old] })
     * ```
     *
     * @see {@link RekeyReport}, {@link VaultOptions.previousKeys}
     */
    async rekey(next: KeySource): Promise<RekeyReport> {
        const nextWrapper = toWrapper(next)
        const report: RekeyReport = { rekeyed: 0, failed: [] }

        for await (const record of this.scan()) {
            // Entries in the open hold no key to re-seal.
            if (!record.isSealed) continue

            try {
                const history = await this.rekeyHistory(record, nextWrapper)

                if (record.sealedKey) {
                    // Envelope: only the data key moves.
                    const bound = Vault.binding(record.owner, record.name)
                    const material = await this.rewrap(record.sealedKey, bound)
                    await this.store.put({
                        ...record,
                        // Re-sealed bound, so a rekey is also what migrates an
                        // entry written before 1.4 onto the tie.
                        sealedKey: await nextWrapper.wrap(material, bound),
                        history,
                    })
                } else {
                    // Written before envelopes: give it one on the way past.
                    const value = await this.unsealWithMaster(record.sealed, undefined)
                    const material = generateKey()
                    const dataKey = await importKey(material)
                    await this.store.put({
                        ...record,
                        sealed: await seal(dataKey, value),
                        sealedKey: await nextWrapper.wrap(
                            material,
                            Vault.binding(record.owner, record.name)
                        ),
                        history,
                    })
                }
                report.rekeyed += 1
            } catch {
                report.failed.push(`${record.owner}/${record.name}`)
            }
        }

        // Everything from here wraps under the new key; the old one stays
        // readable in case a value was missed.
        this.retiredWrappers = [this.current, ...this.retiredWrappers]
        this.current = nextWrapper

        await this.record({
            action: "rekey",
            owner: "",
            name: null,
            detail: `${report.rekeyed} re-sealed, ${report.failed.length} failed`,
        })
        return report
    }

    /** Moves an entry's kept values onto the new master key alongside it. */
    private async rekeyHistory(
        record: SecretRecord,
        nextWrapper: Wrapper
    ): Promise<SecretRecord["history"]> {
        const binding = Vault.binding(record.owner, record.name)
        return Promise.all(
            record.history.map(async (entry) => {
                if (!entry.sealedKey) return entry
                const material = await this.rewrap(entry.sealedKey, binding)
                return { ...entry, sealedKey: await nextWrapper.wrap(material, binding) }
            })
        )
    }

    /**
     * Unwraps a data key that may or may not be tied to its entry yet.
     *
     * @remarks
     * Bound first. A key sealed *with* a binding will not open without one, so
     * falling back to unbound can only ever reach a key written before 1.4 — it
     * is a migration path, not a way around the tie.
     *
     * Since 2.0 that fallback is off unless {@link VaultOptions.allowUnbound}
     * asks for it, so a vault that believes it has migrated finds out rather
     * than carrying untied entries indefinitely.
     *
     * @param sealedKey The wrapped data key.
     * @param binding What it should belong to.
     * @returns The data key material.
     * @throws {@link VaultKeyError} when no key this vault holds opens it.
     */
    private async rewrap(sealedKey: string, binding: string): Promise<string> {
        try {
            return await this.unsealWithMaster(sealedKey, binding)
        } catch (error) {
            if (!this.allowUnbound) throw error
            try {
                return await this.unsealWithMaster(sealedKey, undefined)
            } catch {
                throw error
            }
        }
    }

    /**
     * One page of an owner's entries, for listing a vault too large to hand
     * back whole.
     *
     * @remarks
     * {@link Vault.list} returns everything an owner has, which is the right
     * answer until it is not. This walks in pages of at most `limit`, newest
     * cursor last, and hands back the cursor to ask for the next one.
     *
     * Keyset paging, not an offset: a write during the walk cannot make a page
     * skip or repeat an entry.
     *
     * @param owner Whose entries to list.
     * @param options `limit` caps the page, `after` continues from a previous
     *   one, and `where` narrows by metadata as {@link Vault.list} does.
     * @returns The entries, and the cursor to pass as `after` next time —
     *   null when that was the last page.
     *
     * @example
     * ```ts
     * let after: string | null = null
     * do {
     *     const page = await vault.page("alice", { after, limit: 100 })
     *     for (const entry of page.entries) console.log(entry.name)
     *     after = page.cursor
     * } while (after !== null)
     * ```
     */
    async page(
        owner: string,
        {
            limit = DEFAULT_PAGE_SIZE,
            after = null,
            where = {},
        }: { limit?: number; after?: string | null; where?: Record<string, string> } = {}
    ): Promise<Page> {
        const wanted = Object.entries(where)

        const ordered = (await this.store.list(owner))
            .filter((record) => after === null || record.name > after)
            .filter((record) =>
                wanted.every(([field, value]) => record.metadata[field] === value)
            )
            .sort((a, b) => a.name.localeCompare(b.name))

        const entries = ordered.slice(0, limit).map(summarise)
        // A full page might still be the last one; the caller finds out by
        // asking for the next and getting nothing, which is the honest answer
        // without a second count.
        const cursor = entries.length < limit ? null : (entries[entries.length - 1]?.name ?? null)

        return { entries, cursor }
    }

    /**
     * Packs everything into one sealed document, for moving a vault somewhere
     * else or keeping a copy off the machine.
     *
     * @remarks
     * Values are opened and re-sealed under `key`, not copied across as they
     * are — so the document can be imported into a vault with a different
     * master key, which is the point of having one. Metadata, expiry, rotation
     * policies and history come too.
     *
     * That also means this is the one operation that holds every secret in
     * memory at once. Give it a key you would give the vault itself, and treat
     * what comes back as the vault in a single string.
     *
     * @param key What to seal the document under: base64, an imported key, or a
     *   provider.
     * @param owner Only this owner's entries, or every owner when left out.
     * @returns A document beginning with {@link EXPORT_MAGIC}.
     * @throws {@link VaultKeyError} when a value will not open under any key
     *   this vault holds — an export that quietly dropped entries would be
     *   worse than one that fails.
     *
     * @example
     * ```ts
     * import { generateKey } from "@mstone6969/vault"
     *
     * const carried = generateKey()
     * await Bun.write("vault-backup.txt", await vault.exportAll(carried))
     * ```
     */
    async exportAll(
        key: string | CryptoKey | KeyProvider,
        owner?: string
    ): Promise<string> {
        const exportKey = await toKey(key)
        const entries: ExportedEntry[] = []
        for await (const record of this.scan(owner)) {
            entries.push(await this.exportable(record))
        }

        await this.record({
            action: "open",
            owner: owner ?? "",
            name: null,
            detail: `exported ${entries.length} entries`,
        })
        return `${EXPORT_MAGIC}\n${await seal(exportKey, JSON.stringify(entries))}`
    }

    /**
     * The same export, a line at a time, for a vault too large to hold in
     * memory.
     *
     * @remarks
     * {@link Vault.exportAll} is one sealed blob, which means opening every
     * secret at once and keeping them all until the document is built. This
     * seals each entry on its own line, so the most either end holds is one
     * entry — at the cost of leaking how many entries there are and roughly how
     * big each is, which the single blob hides.
     *
     * Pick on that basis: `exportAll` for a vault that fits and a document that
     * gives nothing away, this for one that does not fit.
     *
     * @param key What to seal the lines under: base64, an imported key, or a
     *   provider.
     * @param owner Only this owner's entries, or every owner when left out.
     * @yields The magic line, then one sealed line per entry. Join with
     *   newlines to make a document {@link Vault.importAll} will read.
     * @throws {@link VaultKeyError} when a value will not open — as with
     *   `exportAll`, an export that quietly dropped entries would be worse than
     *   one that fails.
     *
     * @example
     * ```ts
     * const file = Bun.file("vault-backup.txt").writer()
     * for await (const line of vault.exportStream(carried)) {
     *     file.write(`${line}\n`)
     * }
     * await file.end()
     * ```
     */
    async *exportStream(
        key: string | CryptoKey | KeyProvider,
        owner?: string
    ): AsyncGenerator<string> {
        const exportKey = await toKey(key)
        yield EXPORT_MAGIC_STREAM

        let count = 0
        for await (const record of this.scan(owner)) {
            yield await seal(exportKey, JSON.stringify(await this.exportable(record)))
            count += 1
        }

        await this.record({
            action: "open",
            owner: owner ?? "",
            name: null,
            detail: `exported ${count} entries`,
        })
    }

    /**
     * One record as it goes into an export: opened, so the far end can re-seal
     * it under its own key.
     *
     * @param record What to pack.
     * @returns The entry, value and history in the clear.
     * @throws {@link VaultKeyError} when a value will not open.
     */
    private async exportable(record: SecretRecord): Promise<ExportedEntry> {
        const bound = Vault.binding(record.owner, record.name)
        return {
            owner: record.owner,
            name: record.name,
            value: record.isSealed
                ? await this.unseal(record.sealed, record.sealedKey, bound)
                : (record.plain ?? ""),
            history: await Promise.all(
                record.history.map((entry) => this.unseal(entry.sealed, entry.sealedKey, bound))
            ),
            isSealed: record.isSealed,
            isFinal: record.isFinal,
            expiresAt: record.expiresAt,
            rotation: record.rotation,
            rotatedAt: record.rotatedAt,
            metadata: record.metadata,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
        }
    }

    /**
     * Unpacks a document from {@link Vault.exportAll} into this vault, sealing
     * every value under this vault's master key.
     *
     * @remarks
     * Entries already here are left alone unless `overwrite` says otherwise,
     * and named in the report — importing a backup over a vault that has moved
     * on should not quietly undo the newer values.
     *
     * @param document What {@link Vault.exportAll} produced.
     * @param key The key that document was sealed under.
     * @param options `overwrite` replaces entries that already exist.
     * @returns What was written, and what was left alone.
     * @throws {@link VaultKeyError} when the document is not one of ours, or
     *   the key does not open it.
     *
     * @example
     * ```ts
     * const report = await vault.importAll(backup, carried)
     * // { imported: 42, skipped: ["alice/db"] }
     * ```
     */
    async importAll(
        document: string,
        key: string | CryptoKey | KeyProvider,
        { overwrite = false }: { overwrite?: boolean } = {}
    ): Promise<ImportReport> {
        const [magic, ...rest] = document.trim().split("\n")
        const importKey = await toKey(key)

        let entries: ExportedEntry[]
        if (magic === EXPORT_MAGIC && rest[0]) {
            entries = JSON.parse(await open(importKey, rest[0])) as ExportedEntry[]
        } else if (magic === EXPORT_MAGIC_STREAM) {
            // One sealed entry per line. Read whole here; `importStream` is the
            // one that does not hold them all.
            entries = await Promise.all(
                rest
                    .filter((line) => line.length > 0)
                    .map(async (line) => JSON.parse(await open(importKey, line)) as ExportedEntry)
            )
        } else {
            throw new VaultKeyError("That is not a vault export.")
        }

        const report: ImportReport = { imported: 0, skipped: [] }

        for (const entry of entries) {
            if (await this.absorb(entry, overwrite, report)) report.imported += 1
        }

        await this.record({
            action: "put",
            owner: "",
            name: null,
            detail: `imported ${report.imported} entries`,
        })
        return report
    }

    /**
     * Lets another owner read one of your entries.
     *
     * @remarks
     * Read-only, always. Writing, rotating and deleting stay with the owner
     * however widely an entry is shared — a grant that could overwrite the
     * credential would make "shared with" mean "owned by".
     *
     * The reader reaches it by naming who it belongs to:
     * `open("bob", "token", { from: "alice" })`. That is deliberately explicit,
     * so a grant can never quietly shadow something the reader already keeps
     * under the same name.
     *
     * Sharing again with the same owner replaces the grant rather than adding
     * a second one, which is how you change or remove an expiry.
     *
     * @param owner Whose entry it is. Only they can share it.
     * @param name The entry to share.
     * @param options `with` names the owner who may read it; `expiresAt` makes
     *   the grant temporary.
     * @returns The entry, summarised.
     * @throws {@link VaultError} 404 when there is no such entry.
     * @throws {@link VaultError} 410 when the entry has expired.
     * @throws {@link VaultError} 422 when the name is not a legal one, or when
     *   an owner is asked to share with themselves.
     *
     * @example
     * ```ts
     * await vault.share("alice", "deploy-key", { with: "bob" })
     * await vault.open("bob", "deploy-key", { from: "alice" })
     *
     * // Until Friday only.
     * await vault.share("alice", "db", { with: "carol", expiresAt: friday })
     * ```
     *
     * @see {@link Vault.unshare} to withdraw it, {@link Vault.shares} to see
     *   who has one.
     */
    async share(
        owner: string,
        name: string,
        { with: reader, expiresAt = null }: { with: string; expiresAt?: Date | null }
    ): Promise<SecretSummary> {
        const clean = this.checkName(name)
        if (!reader) throw new VaultError("A grant needs somebody to grant it to.")
        if (reader === owner) {
            throw new VaultError(`${owner} already owns "${clean}".`)
        }

        const record = await this.require(owner, clean)
        const shares = [
            ...(record.shares ?? []).filter((share) => share.with !== reader),
            { with: reader, expiresAt, grantedAt: new Date() },
        ]

        // Through the guarded path like any other change to an entry: a grant
        // added at the same moment as a value must not be lost to it.
        const stored = await this.write(
            { ...record, shares, updatedAt: new Date(), revision: (record.revision ?? 1) + 1 },
            record,
            undefined
        )
        await this.record({ action: "share", owner, name: clean, detail: reader })
        return summarise(stored)
    }

    /**
     * Withdraws a grant.
     *
     * @remarks
     * Takes effect at once: the next read by that owner is refused. It says
     * nothing about what they already read and kept, which is why a withdrawn
     * grant is a reason to rotate the value as well.
     *
     * @param owner Whose entry it is.
     * @param name The entry to stop sharing.
     * @param options `with` names the owner to withdraw from.
     * @returns Whether there was a grant to withdraw.
     * @throws {@link VaultError} 404 when there is no such entry.
     * @throws {@link VaultError} 410 when the entry has expired.
     * @throws {@link VaultError} 422 when the name is not a legal one.
     *
     * @example
     * ```ts
     * await vault.unshare("alice", "deploy-key", { with: "bob" })
     * // Bob cannot read it again — but rotate it too, if he already has.
     * await vault.rotate("alice", "deploy-key")
     * ```
     */
    async unshare(
        owner: string,
        name: string,
        { with: reader }: { with: string }
    ): Promise<boolean> {
        const clean = this.checkName(name)
        const record = await this.require(owner, clean)
        const shares = (record.shares ?? []).filter((share) => share.with !== reader)

        if (shares.length === (record.shares ?? []).length) return false

        await this.write(
            { ...record, shares, updatedAt: new Date(), revision: (record.revision ?? 1) + 1 },
            record,
            undefined
        )
        await this.record({ action: "unshare", owner, name: clean, detail: reader })
        return true
    }

    /**
     * Who can read one of your entries, besides you.
     *
     * @param owner Whose entry it is.
     * @param name The entry to ask about.
     * @returns The grants on it, lapsed ones included — a grant that has run
     *   out is still a fact about who once had access, and hiding it would make
     *   this a worse answer to "who could have seen this".
     * @throws {@link VaultError} 404 when there is no such entry.
     * @throws {@link VaultError} 410 when the entry has expired.
     * @throws {@link VaultError} 422 when the name is not a legal one.
     *
     * @example
     * ```ts
     * for (const { with: who, expiresAt } of await vault.shares("alice", "db")) {
     *     console.log(who, expiresAt ?? "indefinitely")
     * }
     * ```
     */
    async shares(owner: string, name: string): Promise<Share[]> {
        const record = await this.require(owner, this.checkName(name))
        return record.shares ?? []
    }

    /**
     * Everything other owners have shared with you.
     *
     * @remarks
     * The other direction from {@link Vault.shares}: not "who can read mine"
     * but "what can I read". Walks every owner's entries, so it is the one read
     * that crosses the whole store.
     *
     * Lapsed grants are left out here, because this answers what the caller can
     * actually open right now.
     *
     * @param reader Who is asking.
     * @param now What to treat as the current time, for testing.
     * @returns The entries shared with them, each summarised, with the owner to
     *   pass as `from`.
     *
     * @example
     * ```ts
     * for (const entry of await vault.sharedWith("bob")) {
     *     await vault.open("bob", entry.name, { from: entry.owner })
     * }
     * ```
     */
    async sharedWith(reader: string, now = new Date()): Promise<SecretSummary[]> {
        const found: SecretSummary[] = []
        for await (const record of this.scan()) {
            if (record.owner === reader || isExpired(record, now)) continue
            const granted = (record.shares ?? []).find((share) => share.with === reader)
            if (!granted) continue
            if (granted.expiresAt && granted.expiresAt <= now) continue
            found.push(summarise(record))
        }

        return found
            .sort((a, b) =>
                a.owner === b.owner
                    ? a.name.localeCompare(b.name)
                    : a.owner.localeCompare(b.owner)
            )
    }

    /**
     * Writes one entry from an export into this vault, sealed under its key.
     *
     * @param entry The entry as the document carried it.
     * @param overwrite Whether to replace an entry already here.
     * @param report Where to note one that was left alone.
     * @returns Whether it was written.
     */
    private async absorb(
        entry: ExportedEntry,
        overwrite: boolean,
        report: ImportReport
    ): Promise<boolean> {
        const existing = await this.store.get(entry.owner, entry.name)
        if (existing && !overwrite) {
            report.skipped.push(`${entry.owner}/${entry.name}`)
            return false
        }

        const bound = Vault.binding(entry.owner, entry.name)
        const body = entry.isSealed
            ? { ...(await this.enseal(entry.value, bound)), plain: null }
            : { sealed: "", sealedKey: null, plain: entry.value }

        // History is re-sealed too, each value under a key of its own.
        const history = []
        for (const value of entry.history) {
            history.push({
                ...(await this.enseal(value, bound)),
                createdAt: new Date(entry.updatedAt),
            })
        }

        await this.store.put({
            owner: entry.owner,
            name: entry.name,
            ...body,
            isSealed: entry.isSealed,
            isFinal: entry.isFinal,
            expiresAt: entry.expiresAt === null ? null : new Date(entry.expiresAt),
            history,
            rotation: entry.rotation,
            rotatedAt: entry.rotatedAt === null ? null : new Date(entry.rotatedAt),
            metadata: entry.metadata,
            createdAt: new Date(entry.createdAt),
            updatedAt: new Date(entry.updatedAt),
            // An import starts the entry's revision afresh: it is a new record
            // in this vault, whatever it had been through in the last one.
            revision: 1,
            shares: [],
        })
        return true
    }

    /**
     * Reads a streamed export a line at a time, so neither end holds the whole
     * vault.
     *
     * @remarks
     * The counterpart to {@link Vault.exportStream}. {@link Vault.importAll}
     * reads the same document but collects it first; this one writes each entry
     * as it arrives, which is what makes a vault larger than memory movable.
     *
     * @param lines The document's lines, magic line first, as
     *   {@link Vault.exportStream} yielded them.
     * @param key The key the lines were sealed under.
     * @param options `overwrite` replaces entries that already exist.
     * @returns What was written, and what was left alone.
     * @throws {@link VaultKeyError} when the document is not a streamed export,
     *   or the key does not open it.
     *
     * @example
     * ```ts
     * const text = await Bun.file("vault-backup.txt").text()
     * const report = await vault.importStream(text.split("\n"), carried)
     * ```
     */
    async importStream(
        lines: AsyncIterable<string> | Iterable<string>,
        key: string | CryptoKey | KeyProvider,
        { overwrite = false }: { overwrite?: boolean } = {}
    ): Promise<ImportReport> {
        const importKey = await toKey(key)
        const report: ImportReport = { imported: 0, skipped: [] }
        let seenMagic = false

        for await (const line of lines) {
            const trimmed = line.trim()
            if (!trimmed) continue

            if (!seenMagic) {
                if (trimmed !== EXPORT_MAGIC_STREAM) {
                    throw new VaultKeyError("That is not a streamed vault export.")
                }
                seenMagic = true
                continue
            }

            const entry = JSON.parse(await open(importKey, trimmed)) as ExportedEntry
            if (await this.absorb(entry, overwrite, report)) report.imported += 1
        }

        if (!seenMagic) throw new VaultKeyError("That is not a streamed vault export.")

        await this.record({
            action: "put",
            owner: "",
            name: null,
            detail: `imported ${report.imported} entries`,
        })
        return report
    }

    /**
     * Entries whose data keys are not yet tied to them — everything written
     * before 1.4 and never rekeyed since.
     *
     * @remarks
     * What to run before turning {@link VaultOptions.allowUnbound} off, and
     * after a migration to confirm there is nothing left. An empty answer means
     * every entry is tied down.
     *
     * It has to try opening each entry's data key to tell, so this is a walk of
     * the whole vault and not a cheap one. It is a migration tool, not
     * something to call on a request.
     *
     * @returns The entries still untied, by `owner/name`, and those that would
     *   not open at all either way.
     *
     * @example
     * ```ts
     * const vault = new Vault({ key, store, allowUnbound: true })
     * await vault.reseal()
     *
     * const { untied } = await vault.unbound()
     * if (untied.length === 0) {
     *     // safe to drop allowUnbound
     * }
     * ```
     */
    async unbound(): Promise<UnboundReport> {
        const untied: string[] = []
        const unopenable: string[] = []

        for await (const record of this.scan()) {
            if (!record.isSealed || !record.sealedKey) continue
            const where = `${record.owner}/${record.name}`
            const bound = Vault.binding(record.owner, record.name)

            try {
                await this.unsealWithMaster(record.sealedKey, bound)
            } catch {
                try {
                    await this.unsealWithMaster(record.sealedKey, undefined)
                    untied.push(where)
                } catch {
                    unopenable.push(where)
                }
            }
        }

        return { untied, unopenable }
    }

    /**
     * Deletes entries whose time is up. Returns how many went.
     *
     * @param now The moment to judge against. Pass a later one to see what a
     *   run then would take.
     * @returns How many entries were deleted.
     *
     * @remarks
     * Walks every owner. Expiry stops an entry being used, not being stored:
     * until this runs, an expired entry is still there and still listed.
     *
     * @example
     * ```ts
     * await vault.put("alice", "temporary", "x", {
     *     expiresAt: new Date(Date.now() - 1),
     * })
     *
     * await vault.open("alice", "temporary")  // throws: 410, expired
     * await vault.purgeExpired()              // 1
     * await vault.has("alice", "temporary")   // false
     * ```
     */
    async purgeExpired(now = new Date()): Promise<number> {
        // Collected before deleting: removing records while paging through them
        // would move the ground under the cursor.
        const expired: SecretRecord[] = []
        for await (const record of this.scan()) {
            if (isExpired(record, now)) expired.push(record)
        }

        for (const record of expired) {
            await this.store.remove(record.owner, record.name)
        }
        return expired.length
    }
}
