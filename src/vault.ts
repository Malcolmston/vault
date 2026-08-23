import { generateKey, importKey, open, seal } from "./crypto"
import { VaultError } from "./errors"
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
    }: VaultOptions) {
        this.keySource = key
        this.previousSources = previousKeys
        this.store = store
        this.prefix = prefix
        this.historyLimit = historyLimit
        this.generators = generators
        this.onAccess = onAccess
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
     */
    async list(owner: string): Promise<SecretSummary[]> {
        const records = await this.store.list(owner)
        return records.map(summarise).sort((a, b) => a.name.localeCompare(b.name))
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
        const isSealed = options.open === undefined ? (existing?.isSealed ?? true) : !options.open
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

        const stored = await this.store.put({
            owner,
            name: clean,
            ...body,
            isSealed,
            isFinal: options.final === true,
            rotation:
                options.rotation === undefined
                    ? (existing?.rotation ?? null)
                    : options.rotation,
            rotatedAt: existing?.rotatedAt ?? null,
            expiresAt:
                options.expiresAt === undefined
                    ? (existing?.expiresAt ?? null)
                    : options.expiresAt,
            history,
            metadata: options.metadata ?? existing?.metadata ?? {},
            createdAt: existing?.createdAt ?? now,
            updatedAt: now,
        })

        this.record({ action: "put", owner, name: clean })
        return summarise(stored)
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
        const summary = await this.put(owner, clean, next, { ...options, keepHistory: true })

        // Stamped after the fact, so a failed rotation does not look like one.
        const stored = await this.store.get(owner, clean)
        if (stored) await this.store.put({ ...stored, rotatedAt: new Date() })
        return { ...summary, rotatedAt: new Date() }
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
     */
    async remove(owner: string, name: string): Promise<boolean> {
        const removed = await this.store.remove(owner, this.checkName(name))
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
     * @param owner Whose entries the references name.
     * @param values The set to substitute into. Not modified.
     * @returns A copy with every reference replaced by its value, or the same
     *   object back when nothing in it is a reference.
     * @throws {@link VaultError} 404 when a reference names no entry.
     * @throws {@link VaultError} 410 when a referenced entry has expired.
     * @throws {@link VaultError} 422 when what follows the prefix is not a
     *   legal name.
     *
     * @remarks
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
     */
    async resolve(
        owner: string,
        values: Record<string, string>
    ): Promise<Record<string, string>> {
        const references = Object.entries(values).filter(([, value]) =>
            value.startsWith(this.prefix)
        )
        if (references.length === 0) return values

        const resolved = { ...values }
        for (const [key, value] of references) {
            resolved[key] = await this.open(owner, value.slice(this.prefix.length).trim())
        }
        return resolved
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
    async reseal(owner?: string): Promise<number> {
        const records = owner ? await this.store.list(owner) : await this.store.all()
        let resealed = 0

        for (const record of records) {
            if (!record.isSealed || !record.sealed) continue
            const value = await this.unseal(record.sealed, record.sealedKey)
            await this.store.put({ ...record, ...(await this.enseal(value)) })
            resealed += 1
        }
        return resealed
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
