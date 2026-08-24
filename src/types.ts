/**
 * A value a rotatable entry used to hold.
 *
 * @remarks
 * Kept sealed, exactly as the live value is, so history costs no more trust
 * than the entry itself. A job that read the credential moments before a
 * rotation can still finish on what it was given.
 *
 * @example
 * ```ts
 * await vault.rotate("alice", "db")
 * // The value that was live until the rotation, opened:
 * const [previous] = await vault.versions("alice", "db")
 * ```
 *
 * @see {@link SecretRecord.history}
 */
export type HistoryEntry = {
    /** The value, sealed exactly as the live one is. */
    sealed: string
    /**
     * The data key that opens it, itself sealed under the master key.
     *
     * Null on values kept before envelope encryption, which are sealed under
     * the master key directly. A `rekey` moves the non-null ones onto the new
     * master key and leaves the rest alone.
     */
    sealedKey: string | null
    /** When this value was replaced. */
    createdAt: Date
}

/**
 * How an entry's next value is produced.
 *
 * This is a recipe, not a value: it says *how* to make the next password, never
 * what the current one is. Storing it means an entry can be rotated by anything
 * holding the vault, without that thing being told the secret it is replacing.
 *
 * @example
 * ```ts
 * // The vault mints the next value itself.
 * await vault.put("alice", "db", "current", {
 *     rotation: { kind: "random", length: 40, every: 60 * 60 * 24 * 30 },
 * })
 *
 * // Or a function registered on the vault does, for a credential only the
 * // far end can issue.
 * await vault.put("alice", "aws", "current", {
 *     rotation: { kind: "generator", generator: "aws", arguments: { user: "ci" } },
 * })
 * await vault.rotate("alice", "aws")
 * ```
 *
 * @see {@link PutOptions.rotation}
 */
export type RotationPolicy = {
    /**
     * `random` has the vault generate one. `generator` calls a function you
     * registered by name — for a credential only the far end can mint.
     *
     * @remarks
     * `generator` names a function in the vault's `generators`; rotating with a
     * name the vault does not have fails rather than inventing a value.
     */
    kind: "random" | "generator"
    /**
     * random: how many characters. Default 32.
     *
     * @defaultValue 32
     */
    length?: number
    /**
     * random: which characters to draw from.
     *
     * @remarks
     * Sampling is unbiased whatever the length, so an alphabet trimmed to what
     * a system accepts costs nothing. Needs at least two characters.
     *
     * @defaultValue `DEFAULT_ALPHABET` — the 62 ASCII letters and digits
     */
    alphabet?: string
    /**
     * generator: which registered generator to call.
     *
     * @remarks
     * A name, not a function. What is written down is that an entry can be
     * rotated, not how to impersonate the thing that rotates it — the function
     * stays in the process that built the vault.
     */
    generator?: string
    /**
     * generator: non-secret arguments, e.g. which account to rotate.
     *
     * @remarks
     * Stored in the clear beside the policy, so it must hold nothing secret.
     * Reaches the generator as the `arguments` of its context.
     */
    arguments?: Record<string, string>
    /**
     * How often it wants rotating, in seconds. Nothing enforces it; `rotationDue` reports it.
     *
     * @remarks
     * Measured from `rotatedAt`, or from `createdAt` for an entry never
     * rotated. Left out, the entry is never reported as due.
     *
     * @example
     * ```ts
     * for (const secret of await vault.rotationDue()) {
     *     await vault.rotate(secret.owner, secret.name)
     * }
     * ```
     */
    every?: number
}

/**
 * A stored secret, as the store keeps it.
 *
 * @remarks
 * The shape a {@link VaultStore} reads and writes, and the only place the
 * sealed bytes appear. Callers of the vault get {@link SecretSummary} instead.
 * A store persists these fields as given: none of them mean anything to it.
 *
 * @see {@link SecretSummary}
 */
export type SecretRecord = {
    /** Whose it is. The vault never reaches across owners except to rekey. */
    owner: string
    /**
     * What it is called, and how a reference finds it.
     *
     * @remarks
     * Up to 64 characters of letters, numbers, dot, dash or underscore —
     * checked by the vault before it reaches a store. Unique per owner.
     */
    name: string
    /**
     * The value, sealed under this entry's data key — `iv:payload`, base64.
     * Empty when the entry is not sealed.
     */
    sealed: string
    /**
     * This entry's data key, sealed under the master key.
     *
     * Every value gets its own key, and only these are re-sealed when the
     * master key changes: rekeying costs one small operation per entry rather
     * than re-encrypting every byte, and one leaked data key exposes one value.
     *
     * Null on entries written before envelope encryption, whose value is sealed
     * under the master key directly.
     */
    sealedKey: string | null
    /**
     * The value in the open. Only ever set when `isSealed` is false.
     *
     * @remarks
     * This is the one field a store holds that is readable without a key, so an
     * entry only lands here when `put` was told `open: true`.
     */
    plain: string | null
    /**
     * False for entries stored in the open, which can be read back.
     *
     * @remarks
     * Left out of a replacing `put`, an entry keeps whatever it already was:
     * rotating a credential should not quietly unseal it.
     *
     * @defaultValue true for a new entry
     */
    isSealed: boolean
    /**
     * Written once: a store must refuse to replace it.
     *
     * @remarks
     * The refusing is the vault's — a store writes what it is given. `put` on a
     * final entry throws and records a `denied` event with detail `"final"`.
     * Removing it still works; finality is about change, not deletion.
     */
    isFinal: boolean
    /**
     * When the entry stops resolving, or null if it does not.
     *
     * @remarks
     * The entry stays in the store past this moment, but `open`, `read` and
     * `resolve` refuse it. `purgeExpired` is what actually deletes it.
     */
    expiresAt: Date | null
    /**
     * Previous values, newest first. Empty unless the entry keeps history.
     *
     * @remarks
     * Filled by `rotate`, or by a `put` told `keepHistory: true`, and trimmed
     * to the vault's `historyLimit`.
     */
    history: HistoryEntry[]
    /** How to produce the next value, or null if nothing knows. */
    rotation: RotationPolicy | null
    /**
     * When it was last rotated, as opposed to merely replaced.
     *
     * @remarks
     * Null until the first rotation, which is why `rotationDue` falls back to
     * `createdAt` when deciding whether `every` has elapsed.
     */
    rotatedAt: Date | null
    /**
     * Non-secret facts, stored in the clear and returned by `list`: what kind
     * of credential it is, which username it belongs to, a public key.
     */
    metadata: Record<string, string>
    /** When the entry was first stored. Survives replacement. */
    createdAt: Date
    /** When it last changed. */
    updatedAt: Date
}

/**
 * A stored secret, as callers are allowed to see it: no sealed value.
 *
 * @remarks
 * What `put`, `rotate`, `list` and `rotationDue` hand back. The sealed bytes,
 * the data key and the kept history are dropped rather than hidden, so a
 * summary can be logged or returned from an API without leaking anything the
 * master key protects.
 *
 * @example
 * ```ts
 * for (const secret of await vault.list("alice")) {
 *     console.log(secret.name, secret.metadata.kind, secret.versions)
 * }
 * ```
 *
 * @see {@link SecretRecord}
 */
export type SecretSummary = Omit<
    SecretRecord,
    "sealed" | "sealedKey" | "plain" | "history"
> & {
    /**
     * Present only for entries stored in the open.
     *
     * @remarks
     * A sealed entry leaves this undefined however it is summarised; its value
     * only comes out of `open`.
     */
    value?: string
    /**
     * How many previous values are kept.
     *
     * @remarks
     * A count, not the values: `versions` on the vault opens those, one at a
     * time and only for whoever holds the key.
     */
    versions: number
}

/**
 * What `put` is allowed to say about an entry beyond its value.
 *
 * @remarks
 * Every field left out means "as it was" on a replacing `put`, so rotating a
 * credential does not quietly forget what kind it is or when it expires. The
 * exception is `final`, which must be asked for each time.
 *
 * @example
 * ```ts
 * await vault.put("alice", "db", "s3cret", {
 *     metadata: { kind: "postgres", user: "app" },
 *     rotation: { kind: "random", length: 40 },
 *     expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
 * })
 * ```
 */
export type PutOptions = {
    /**
     * Non-secret facts to keep beside the value, returned by `list`. Replaces
     * whatever was there; leave it out to keep what the entry already has.
     */
    metadata?: Record<string, string>
    /**
     * How to produce the next value when it is rotated.
     *
     * @remarks
     * Pass null to drop a policy an entry already has; leaving it out keeps it.
     *
     * @see {@link RotationPolicy}
     */
    rotation?: RotationPolicy | null
    /**
     * Whether to encrypt the value.
     *
     * @remarks
     * `false` stores it in the clear, where {@link Vault.read} gives it back —
     * for values that belong beside the secrets but are not secret, like a host
     * or an account id. Left out, the entry keeps how it was already stored.
     *
     * Named for what it is rather than its opposite, so it does not read as a
     * relative of {@link Vault.open}, which is a different idea entirely.
     *
     * @defaultValue true
     */
    sealed?: boolean
    /**
     * Refuse every future replacement.
     *
     * @remarks
     * Not sticky: it is taken from this call alone, so it must be repeated by
     * anything rewriting the entry — which nothing can, once it is set.
     *
     * @defaultValue false
     */
    final?: boolean
    /**
     * When it should stop resolving.
     *
     * @remarks
     * Pass null to make an expiring entry permanent again.
     *
     * @defaultValue null
     */
    expiresAt?: Date | null
    /**
     * Keep the value being replaced, up to `historyLimit`.
     *
     * @remarks
     * What `rotate` sets for you; set it by hand when replacing a value
     * yourself and something may still be running on the old one.
     *
     * @defaultValue false
     */
    keepHistory?: boolean
}

/**
 * Where records live. Implement this to keep secrets in whatever database you
 * already run; `MemoryStore`, `SqliteStore` and `FileStore` ship with the
 * package.
 *
 * A store persists records as given and enforces nothing: the rules about
 * finality, expiry and history are the vault's.
 *
 * @example
 * ```ts
 * import { Vault, MemoryStore } from "@mstone6969/vault"
 *
 * const vault = new Vault({ key, store: new MemoryStore() })
 * ```
 *
 * @see {@link SecretRecord}
 */
export type VaultStore = {
    /**
     * One record, or null when there is none under that name.
     *
     * @param owner Whose entry to look for.
     * @param name The entry's name, already checked by the vault.
     * @returns The record as it was written, or null.
     */
    get(owner: string, name: string): Promise<SecretRecord | null>
    /**
     * Every record one owner holds, in any order.
     *
     * @param owner Whose entries to return.
     * @returns The owner's records; the vault sorts them by name itself.
     */
    list(owner: string): Promise<SecretRecord[]>
    /**
     * Every record the store holds, whoever owns it. Only `rekey` and
     * `purgeExpired` need this — nothing else reaches across owners.
     *
     * @returns Every record, in any order.
     */
    all(): Promise<SecretRecord[]>
    /**
     * Writes a record, replacing any under the same owner and name.
     *
     * @param record The record to write. Store it as given: `isFinal` is the
     *   vault's rule to enforce, not the store's.
     * @returns The record as stored, which is what the caller sees.
     */
    put(record: SecretRecord): Promise<SecretRecord>
    /**
     * Deletes a record, returning false when there was nothing to delete.
     *
     * @param owner Whose entry to delete.
     * @param name The entry to delete.
     * @returns True when a record went, false when there was none.
     */
    remove(owner: string, name: string): Promise<boolean>
}

/**
 * Something a vault did, for whoever is keeping an audit trail.
 *
 * @remarks
 * Handed to the vault's `onAccess`, which is never awaited and whose failures
 * are ignored — logging must not break a vault. Events carry names, never
 * values, so the trail is safe to keep wherever logs go.
 *
 * @example
 * ```ts
 * const vault = new Vault({
 *     key,
 *     store,
 *     onAccess: (event) => {
 *         if (event.action === "denied") {
 *             console.warn(`refused ${event.owner}/${event.name}: ${event.detail}`)
 *         }
 *     },
 * })
 * ```
 */
export type VaultEvent = {
    /**
     * What was attempted. `denied` means the vault refused; see `detail`.
     *
     * @remarks
     * `open` is a sealed value coming out, `read` an entry stored in the open.
     * A `rotate` is also recorded as the `put` that carries it out.
     */
    action: "put" | "open" | "read" | "remove" | "rotate" | "rekey" | "denied"
    /** Whose entry it was. Empty for vault-wide actions. */
    owner: string
    /** The entry involved, or null for vault-wide actions like `rekey`. */
    name: string | null
    /** When it happened. */
    at: Date
    /**
     * Why a `denied` happened, or what a vault-wide action touched.
     *
     * @remarks
     * On a `denied`: `"final"` for a replacement of an entry written once,
     * `"sealed"` for a `read` of a value only `open` returns, `"expired"` for
     * an entry past `expiresAt`. On a `rekey`, how many entries moved and how
     * many would not open.
     */
    detail?: string
}
