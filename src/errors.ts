/**
 * A caller mistake: a bad name, an empty value, a missing secret.
 *
 * @remarks
 * Everything the vault throws on purpose is a `VaultError`, so a caller can
 * tell "you asked for something that cannot be done" apart from a bug, and
 * answer accordingly, with one `instanceof`.
 *
 * @example Turning a vault call into an HTTP response
 * ```ts
 * import { Vault, VaultError, MemoryStore, generateKey } from "@mstone6969/vault"
 *
 * const vault = new Vault({ key: generateKey(), store: new MemoryStore() })
 *
 * try {
 *     return new Response(await vault.open("alice", "stripe"))
 * } catch (error) {
 *     if (error instanceof VaultError) {
 *         return new Response(error.message, { status: error.status })
 *     }
 *     throw error
 * }
 * ```
 *
 * @see {@link VaultKeyError} for the key and ciphertext failures.
 */
export class VaultError extends Error {
    /**
     * @param message What the caller did that the vault would not do. Names
     *   and owners appear in it; secret values never do, so it is safe to log.
     * @param status Suggested HTTP status. See {@link VaultError.status}.
     */
    constructor(
        message: string,
        /**
         * Suggested HTTP status, for callers putting this behind an API.
         *
         * @remarks
         * It is a suggestion, not a promise about transport: nothing in the
         * vault speaks HTTP. It exists so a handler can map a failure to a
         * response without knowing which check inside the vault failed.
         *
         * The statuses actually thrown:
         *
         * - `422` — bad input: a name that is not 1–64 characters of letters,
         *   numbers, dot, dash or underscore; an empty value; a `randomValue`
         *   length below one or an alphabet under two characters; a rotation
         *   asked of an entry with no rotation policy.
         * - `404` — no secret under that name for that owner.
         * - `409` — the entry is `final`, so it can be deleted but not
         *   replaced.
         * - `403` — the entry is sealed, so `read` will not hand it back.
         *   `open` is the only way out.
         * - `410` — the entry's `expiresAt` has passed. The record is still
         *   there; it just cannot be used.
         * - `501` — the entry's rotation policy names a generator this vault
         *   was not constructed with.
         * - `500` — {@link VaultKeyError}'s default: a key or ciphertext
         *   problem, which is the operator's fault rather than the caller's.
         *
         * @defaultValue 422
         */
        readonly status: number = 422
    ) {
        super(message)
        this.name = "VaultError"
    }
}

/**
 * The key is the wrong shape, or cannot open what it was given.
 *
 * @remarks
 * Thrown for a base64 key that is not 32 bytes, a sealed value not in
 * `iv:payload` form, and a value that will not open — which covers both the
 * wrong key and a value someone has altered, since GCM authenticates what it
 * decrypts and cannot tell you which it was. The key providers throw it too,
 * when the environment variable is unset or the key file is missing or empty.
 *
 * Its status is 500 rather than a 4xx because a request that reaches this did
 * nothing wrong: the vault is misconfigured, or its data no longer matches its
 * key.
 *
 * @example Distinguishing a key problem from a caller problem
 * ```ts
 * import { importKey, VaultKeyError } from "@mstone6969/vault"
 *
 * try {
 *     await importKey(process.env.VAULT_KEY!)
 * } catch (error) {
 *     if (error instanceof VaultKeyError) {
 *         console.error("vault key is unusable:", error.message)
 *         process.exit(1)
 *     }
 *     throw error
 * }
 * ```
 *
 * @see {@link VaultError} for the mistakes callers can fix themselves.
 */
export class VaultKeyError extends VaultError {
    /**
     * @param message What was wrong with the key or the sealed value. It never
     *   says which key was tried or what the value held.
     */
    constructor(message: string) {
        super(message, 500)
        this.name = "VaultKeyError"
    }
}
