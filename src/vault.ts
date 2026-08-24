import { generateKey, importKey, open, seal } from "./crypto"
import { VaultError, VaultKeyError } from "./errors"
import { isKeyProvider, staticKey, type KeyProvider } from "./providers"
import type {
    PutOptions,
    RotationPolicy,
    SecretRecord,
    SecretSummary,
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

/** What a document from {@link Vault.exportAll} starts with. */
export const EXPORT_MAGIC = "VAULTEXPORT1"

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
    /** The master key: base64, already imported, or a provider that finds one. */
    key: string | CryptoKey | KeyProvider
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
    previousKeys?: (string | CryptoKey | KeyProvider)[]
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
     * Off by default, because it turns a write that used to succeed into a 409
     * and vaults written against 1.1 should keep behaving as they did. Turn it
     * on wherever more than one process writes the same store: without it, two
     * writers racing on one entry silently lose one of the two values, and the
     * loser is told the write succeeded.
     *
     * A single caller passing {@link PutOptions.expectedRevision} gets the same
     * protection for that one call whatever this is set to.
     *
     * How airtight it is depends on the store — see {@link VaultStore.putIf}.
     *
     * @defaultValue false
     */
    strictWrites?: boolean
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

function toKey(key: string | CryptoKey | KeyProvider): Promise<CryptoKey> {
    const provider = isKeyProvider(key) ? key : staticKey(key)
    return Promise.resolve(provider.key()).then((resolved) =>
        typeof resolved === "string" ? importKey(resolved) : resolved
    )
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
    private keySource: string | CryptoKey | KeyProvider
    private previousSources: (string | CryptoKey | KeyProvider)[]
    /** Resolved on first use, not at construction: a provider may need to wait,
     * or fail, and a vault nobody uses should do neither. */
    private keyCache: Promise<CryptoKey> | null = null
    private previousCache: Promise<CryptoKey>[] | null = null
    private readonly store: VaultStore
    private readonly historyLimit: number
    private readonly generators: Record<string, Generator>
    private readonly onAccess: ((event: VaultEvent) => void) | undefined
    private readonly strictWrites: boolean
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
        strictWrites = false,
    }: VaultOptions) {
        this.keySource = key
        this.previousSources = previousKeys
        this.store = store
        this.prefix = prefix
        this.historyLimit = historyLimit
        this.generators = generators
        this.onAccess = onAccess
        this.strictWrites = strictWrites
    }

    private master(): Promise<CryptoKey> {
        this.keyCache ??= toKey(this.keySource)
        return this.keyCache
    }

    private retired(): Promise<CryptoKey>[] {
        this.previousCache ??= this.previousSources.map(toKey)
        return this.previousCache
    }

    private record(event: Omit<VaultEvent, "at">): void {
        if (!this.onAccess) return
        try {
            this.onAccess({ ...event, at: new Date() })
        } catch {
            // An audit trail that throws must not take the vault with it.
        }
    }

    /** Opens something with the master key, falling back to retired ones. */
    private async unsealWithMaster(sealed: string): Promise<string> {
        try {
            return await open(await this.master(), sealed)
        } catch (error) {
            for (const previous of this.retired()) {
                try {
                    return await open(await previous, sealed)
                } catch {
                    // Not this one either; keep going.
                }
            }
            throw error
        }
    }

    /** Opens a value: its data key first, then the value under that key. */
    private async unseal(sealed: string, sealedKey: string | null): Promise<string> {
        if (!sealedKey) {
            // Written before envelope encryption: sealed under the master key.
            return this.unsealWithMaster(sealed)
        }
        const dataKey = await importKey(await this.unsealWithMaster(sealedKey))
        return open(dataKey, sealed)
    }

    /** Seals a value under a fresh data key, and that key under the master. */
    private async enseal(value: string): Promise<{ sealed: string; sealedKey: string }> {
        const material = generateKey()
        const dataKey = await importKey(material)
        return {
            sealed: await seal(dataKey, value),
            sealedKey: await seal(await this.master(), material),
        }
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
            this.record({ action: "denied", owner, name: clean, detail: "final" })
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
            ? { ...(await this.enseal(value)), plain: null }
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
        }

        const stored = await this.write(record, existing, options.expectedRevision)
        this.record({ action: "put", owner, name: clean })
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

        if (this.store.putIf) {
            const stored = await this.store.putIf(record, against)
            if (stored) return stored
        } else {
            // No atomic path. Re-read as late as we can and compare: the window
            // is smaller than doing nothing, and it is the best a store that
            // cannot compare-and-set can offer.
            const current = await this.store.get(record.owner, record.name)
            const now = current ? (current.revision ?? 1) : null
            if (now === against) {
                return this.store.put(record)
            }
        }

        this.record({
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

        this.record({ action: "rotate", owner, name: clean })
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
        const records = await this.store.all()
        return records
            .filter((record) => {
                const every = record.rotation?.every
                if (!every) return false
                const last = (record.rotatedAt ?? record.createdAt).getTime()
                return now.getTime() - last >= every * 1000
            })
            .map(summarise)
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
            record.history.map((entry) => this.unseal(entry.sealed, entry.sealedKey))
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
                this.record({ action: "denied", owner, name: clean, detail: "revision" })
                throw new VaultError(
                    `"${clean}" has changed since revision ${expectedRevision}.`,
                    409
                )
            }
        }

        const removed = await this.store.remove(owner, clean)
        if (removed) this.record({ action: "remove", owner, name })
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
            this.record({ action: "denied", owner, name: clean, detail: "expired" })
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
    async open(owner: string, name: string): Promise<string> {
        const record = await this.require(owner, name)
        const value = record.isSealed
            ? await this.unseal(record.sealed, record.sealedKey)
            : (record.plain ?? "")

        this.record({ action: "open", owner, name })
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
    async read(owner: string, name: string): Promise<string> {
        const record = await this.require(owner, name)
        if (record.isSealed) {
            this.record({ action: "denied", owner, name, detail: "sealed" })
            throw new VaultError(`"${name}" is sealed and cannot be read back.`, 403)
        }

        this.record({ action: "read", owner, name })
        return record.plain ?? ""
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
        if (typeof value === "string") {
            return value.startsWith(this.prefix)
                ? this.open(owner, value.slice(this.prefix.length).trim())
                : value
        }

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
        const records = owner ? await this.store.list(owner) : await this.store.all()
        const report: RekeyReport = { rekeyed: 0, failed: [] }

        for (const record of records) {
            if (!record.isSealed || !record.sealed) continue

            try {
                const value = await this.unseal(record.sealed, record.sealedKey)
                await this.store.put({ ...record, ...(await this.enseal(value)) })
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
    async rekey(next: string | CryptoKey | KeyProvider): Promise<RekeyReport> {
        const nextKey = await toKey(next)
        const report: RekeyReport = { rekeyed: 0, failed: [] }

        for (const record of await this.store.all()) {
            // Entries in the open hold no key to re-seal.
            if (!record.isSealed) continue

            try {
                const history = await this.rekeyHistory(record, nextKey)

                if (record.sealedKey) {
                    // Envelope: only the data key moves.
                    const material = await this.unsealWithMaster(record.sealedKey)
                    await this.store.put({
                        ...record,
                        sealedKey: await seal(nextKey, material),
                        history,
                    })
                } else {
                    // Written before envelopes: give it one on the way past.
                    const value = await this.unsealWithMaster(record.sealed)
                    const material = generateKey()
                    const dataKey = await importKey(material)
                    await this.store.put({
                        ...record,
                        sealed: await seal(dataKey, value),
                        sealedKey: await seal(nextKey, material),
                        history,
                    })
                }
                report.rekeyed += 1
            } catch {
                report.failed.push(`${record.owner}/${record.name}`)
            }
        }

        // Everything from here seals under the new key; the old one stays
        // readable in case a value was missed.
        this.previousSources = [this.keySource, ...this.previousSources]
        this.keySource = nextKey
        this.keyCache = Promise.resolve(nextKey)
        this.previousCache = null

        this.record({
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
        nextKey: CryptoKey
    ): Promise<SecretRecord["history"]> {
        return Promise.all(
            record.history.map(async (entry) => {
                if (!entry.sealedKey) return entry
                const material = await this.unsealWithMaster(entry.sealedKey)
                return { ...entry, sealedKey: await seal(nextKey, material) }
            })
        )
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
        const records = owner ? await this.store.list(owner) : await this.store.all()

        const entries: ExportedEntry[] = []
        for (const record of records) {
            entries.push({
                owner: record.owner,
                name: record.name,
                // Opened here, so the far end can re-seal under its own key.
                value: record.isSealed
                    ? await this.unseal(record.sealed, record.sealedKey)
                    : (record.plain ?? ""),
                history: await Promise.all(
                    record.history.map((entry) => this.unseal(entry.sealed, entry.sealedKey))
                ),
                isSealed: record.isSealed,
                isFinal: record.isFinal,
                expiresAt: record.expiresAt,
                rotation: record.rotation,
                rotatedAt: record.rotatedAt,
                metadata: record.metadata,
                createdAt: record.createdAt,
                updatedAt: record.updatedAt,
            })
        }

        this.record({
            action: "open",
            owner: owner ?? "",
            name: null,
            detail: `exported ${entries.length} entries`,
        })
        return `${EXPORT_MAGIC}\n${await seal(exportKey, JSON.stringify(entries))}`
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
        const [magic, payload] = document.trim().split("\n")
        if (magic !== EXPORT_MAGIC || !payload) {
            throw new VaultKeyError("That is not a vault export.")
        }

        const opened = await open(await toKey(key), payload)
        const entries = JSON.parse(opened) as ExportedEntry[]
        const report: ImportReport = { imported: 0, skipped: [] }

        for (const entry of entries) {
            const existing = await this.store.get(entry.owner, entry.name)
            if (existing && !overwrite) {
                report.skipped.push(`${entry.owner}/${entry.name}`)
                continue
            }

            const body = entry.isSealed
                ? { ...(await this.enseal(entry.value)), plain: null }
                : { sealed: "", sealedKey: null, plain: entry.value }

            // History is re-sealed too, each value under a key of its own.
            const history = []
            for (const value of entry.history) {
                history.push({
                    ...(await this.enseal(value)),
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
            })
            report.imported += 1
        }

        this.record({
            action: "put",
            owner: "",
            name: null,
            detail: `imported ${report.imported} entries`,
        })
        return report
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
        const expired = (await this.store.all()).filter((record) => isExpired(record, now))
        for (const record of expired) {
            await this.store.remove(record.owner, record.name)
        }
        return expired.length
    }
}
