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
