import { VaultKeyError } from "./errors"

/**
 * Where the master key comes from.
 *
 * A vault takes a provider rather than a string so the key can live wherever
 * you keep such things — the environment, a file with tight permissions, or a
 * service that hands one over. Write your own for anything else; it is one
 * method.
 *
 * @remarks
 * Whoever holds the provider — {@link Vault} or {@link FileStore} — calls
 * `key` the first time a key is actually needed and keeps the promise, so a
 * provider that reaches over the network is asked once and a vault nobody uses
 * never asks at all. Anything thrown surfaces from that first operation, not
 * from the constructor.
 *
 * @example
 * A provider for something this package does not ship — here a KMS, but the
 * shape is the same for 1Password, age, or a file on a smartcard.
 * ```ts
 * import { Vault, MemoryStore, type KeyProvider } from "@mstone6969/vault"
 *
 * function kmsKey(id: string): KeyProvider {
 *     return {
 *         async key() {
 *             const response = await fetch(`https://kms.internal/keys/${id}`)
 *             if (!response.ok) throw new Error(`KMS refused key ${id}.`)
 *             return (await response.text()).trim() // base64
 *         },
 *     }
 * }
 *
 * const vault = new Vault({ key: kmsKey("vault-master"), store: new MemoryStore() })
 * await vault.put("alice", "db", "hunter2") // the KMS is called here, once
 * ```
 *
 * @see {@link staticKey}, {@link envKey} and {@link fileKey} for the ones that
 *   ship.
 */
export type KeyProvider = {
    /**
     * The key, base64 or already imported. Called once, when first needed.
     *
     * @returns The master key: a base64 string of 32 bytes, or a `CryptoKey`
     *   already imported for AES-GCM. May be a promise.
     * @throws Whatever the source of the key throws when it cannot produce
     *   one. The ones here throw {@link VaultKeyError}.
     */
    key(): Promise<string | CryptoKey> | string | CryptoKey
}

/**
 * A key you already have.
 *
 * Mostly for handing a key to something that wants a provider —
 * {@link Vault.rekey}, or a `previousKeys` entry — without wrapping it
 * yourself. Passing raw key material as `key` does this for you.
 *
 * @param key The master key: base64, or already imported.
 * @returns A provider that hands back `key` every time.
 *
 * @example
 * ```ts
 * import { Vault, MemoryStore, generateKey, staticKey } from "@mstone6969/vault"
 *
 * const vault = new Vault({ key: staticKey(generateKey()), store: new MemoryStore() })
 * ```
 */
export function staticKey(key: string | CryptoKey): KeyProvider {
    return { key: () => key }
}

/**
 * A key from an environment variable.
 *
 * @param name The variable to read, at the moment the key is first needed —
 *   so a process that loads its environment after building the vault still
 *   works.
 * @returns A provider that reads `process.env[name]`.
 * @throws {@link VaultKeyError} when the variable is unset or empty, at the first
 *   operation that needs a key rather than at construction.
 *
 * @example
 * ```ts
 * import { Vault, MemoryStore, envKey } from "@mstone6969/vault"
 *
 * const vault = new Vault({ key: envKey("VAULT_KEY"), store: new MemoryStore() })
 * await vault.put("alice", "db", "hunter2") // throws here if VAULT_KEY is unset
 * ```
 */
export function envKey(name: string): KeyProvider {
    return {
        key() {
            const value = process.env[name]
            if (!value) {
                throw new VaultKeyError(`${name} is not set, so there is no key to open with.`)
            }
            return value
        },
    }
}

/**
 * A key from a file — the usual way to keep one off the process list and out
 * of shell history. Whitespace around it is ignored, so a trailing newline
 * from `openssl rand -base64 32 > key` does no harm.
 *
 * @param path The key file, read at the moment the key is first needed. It is
 *   read once and kept, so replacing the file later does not change the key a
 *   running vault uses.
 * @returns A provider that reads and trims the file.
 * @throws {@link VaultKeyError} when the file is missing, or holds nothing but
 *   whitespace.
 *
 * @example
 * ```ts
 * import { Vault, FileStore, fileKey } from "@mstone6969/vault"
 *
 * // The store's own key opens the file; the vault's key seals the values.
 * const store = new FileStore("./secrets.vault", fileKey("/etc/vault.key"))
 * const vault = new Vault({ key: fileKey("/etc/vault.key"), store })
 * ```
 */
export function fileKey(path: string): KeyProvider {
    return {
        async key() {
            const file = Bun.file(path)
            if (!(await file.exists())) {
                throw new VaultKeyError(`No key file at ${path}.`)
            }
            const contents = (await file.text()).trim()
            if (!contents) throw new VaultKeyError(`The key file at ${path} is empty.`)
            return contents
        },
    }
}

/**
 * How hard a passphrase is to grind through, in PBKDF2 iterations.
 *
 * @remarks
 * OWASP's floor for PBKDF2-HMAC-SHA256. Raising it costs the legitimate holder
 * one derivation at startup and costs an attacker the same multiple on every
 * guess, so raise it if you can afford the wait.
 */
export const PASSPHRASE_ITERATIONS = 600_000

/**
 * A key derived from a passphrase, for when a person has to remember it.
 *
 * @remarks
 * The vault wants 32 random bytes; people do not remember those. This grinds a
 * passphrase into them with PBKDF2-HMAC-SHA256, which is only ever as strong as
 * the passphrase — a guessable one stays guessable however many iterations you
 * run. Prefer {@link fileKey} or {@link envKey} for anything a machine can hold
 * for you.
 *
 * The salt is not a secret, but it must be the same every time or the key comes
 * out different and nothing opens. Store it beside the vault, not inside it.
 *
 * Derivation happens once, the first time a key is needed, so the cost is paid
 * at startup rather than per operation.
 *
 * @param passphrase What the person types.
 * @param salt A stable, per-vault string. A UUID written down at setup is fine.
 * @param iterations How many rounds to grind.
 *   @defaultValue {@link PASSPHRASE_ITERATIONS}
 * @returns A provider that derives the key.
 * @throws {@link VaultKeyError} when the passphrase or salt is empty — both are
 *   mistakes that would otherwise produce a perfectly usable key protecting
 *   nothing.
 *
 * @example
 * ```ts
 * import { Vault, FileStore, passphraseKey } from "@mstone6969/vault"
 *
 * const key = passphraseKey(await prompt("Passphrase:"), "9f2c…the vault's salt")
 * const vault = new Vault({ key, store: new FileStore("./secrets.vault", key) })
 * ```
 */
export function passphraseKey(
    passphrase: string,
    salt: string,
    iterations: number = PASSPHRASE_ITERATIONS
): KeyProvider {
    return {
        async key() {
            if (!passphrase) throw new VaultKeyError("A passphrase cannot be empty.")
            if (!salt) throw new VaultKeyError("A passphrase needs a salt to go with it.")

            const material = await crypto.subtle.importKey(
                "raw",
                new TextEncoder().encode(passphrase),
                "PBKDF2",
                false,
                ["deriveBits"]
            )
            const bits = await crypto.subtle.deriveBits(
                {
                    name: "PBKDF2",
                    salt: new TextEncoder().encode(salt),
                    iterations,
                    hash: "SHA-256",
                },
                material,
                256
            )
            return Buffer.from(bits).toString("base64")
        },
    }
}

/**
 * Somewhere else that wraps and unwraps data keys, so the master key never
 * reaches this process.
 *
 * @remarks
 * A {@link KeyProvider} hands the vault key material, which means the key is in
 * memory and a heap dump has it. A wrapper instead does the two operations the
 * vault actually needs — wrap a data key, unwrap it again — somewhere the
 * process cannot see: AWS KMS, Google Cloud KMS, HashiCorp Vault's transit
 * engine, an HSM.
 *
 * This fits because of the envelope: only the small data key is ever wrapped,
 * never the value, so it is one short round trip per entry rather than sending
 * secrets over the wire. `rekey` becomes re-wrapping, and it is how you move a
 * vault onto a KMS — read with the old key, write with the wrapper.
 *
 * A wrapper is accepted anywhere a key is: as `key`, in `previousKeys`, and as
 * the argument to `rekey`.
 *
 * @example A wrapper over AWS KMS
 * ```ts
 * const wrapper: KeyWrapper = {
 *     async wrap(material, binding) {
 *         const out = await kms.send(new EncryptCommand({
 *             KeyId: "alias/vault",
 *             Plaintext: Buffer.from(material, "base64"),
 *             EncryptionContext: { binding },
 *         }))
 *         return Buffer.from(out.CiphertextBlob!).toString("base64")
 *     },
 *     async unwrap(wrapped, binding) {
 *         const out = await kms.send(new DecryptCommand({
 *             CiphertextBlob: Buffer.from(wrapped, "base64"),
 *             EncryptionContext: { binding },
 *         }))
 *         return Buffer.from(out.Plaintext!).toString("base64")
 *     },
 * }
 *
 * const vault = new Vault({ key: wrapper, store })
 * ```
 *
 * @see {@link KeyProvider} for when the key may live in the process.
 */
export type KeyWrapper = {
    /**
     * Wraps a data key.
     *
     * @param material The data key, base64.
     * @param binding What the key belongs to — pass it to the service as an
     *   encryption context, so unwrapping it as anything else fails there too.
     *   Empty for an entry written before 1.4, which has no binding.
     * @returns The wrapped key, to be stored as-is.
     */
    wrap(material: string, binding: string): Promise<string>
    /**
     * Unwraps a data key.
     *
     * @param wrapped What {@link KeyWrapper.wrap} returned.
     * @param binding The same binding it was wrapped with.
     * @returns The data key, base64.
     * @throws Whatever the service throws when it will not unwrap.
     */
    unwrap(wrapped: string, binding: string): Promise<string>
}

/**
 * Whether something is a {@link KeyWrapper} rather than a key or a provider.
 *
 * @param value Anything.
 * @returns True when it has both `wrap` and `unwrap`.
 */
export function isKeyWrapper(value: unknown): value is KeyWrapper {
    return (
        typeof value === "object" &&
        value !== null &&
        typeof (value as KeyWrapper).wrap === "function" &&
        typeof (value as KeyWrapper).unwrap === "function"
    )
}

/**
 * True when something is a provider rather than a key.
 *
 * {@link Vault} and {@link FileStore} accept either, and use this to tell them
 * apart: anything with a callable `key` is a provider, everything else is key
 * material to be wrapped in {@link staticKey}. A `CryptoKey` has no `key`
 * method, so it never matches.
 *
 * @param value Anything — key material, a provider, or neither.
 * @returns Whether `value` has a callable `key`, narrowing it to
 *   {@link KeyProvider}.
 *
 * @example
 * ```ts
 * import { envKey, isKeyProvider, staticKey } from "@mstone6969/vault"
 *
 * isKeyProvider(envKey("VAULT_KEY")) // true
 * isKeyProvider(staticKey("...")) // true
 * isKeyProvider("base64-key-material") // false
 * ```
 */
export function isKeyProvider(value: unknown): value is KeyProvider {
    return typeof (value as KeyProvider)?.key === "function"
}
