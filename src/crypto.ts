import { VaultKeyError } from "./errors"

/**
 * AES-256-GCM. Sealed values are `iv:payload`, both base64: the IV is fresh per
 * write, and GCM's tag means a tampered value fails to open rather than
 * decrypting to something wrong.
 *
 * These primitives know nothing about the vault. {@link Vault} builds envelope
 * encryption on top of them: {@link generateKey} mints a data key per value,
 * {@link seal} seals the value under it, and only that data key is sealed under
 * the master key.
 */

/**
 * IV length in bytes.
 *
 * @remarks
 * 12 because that is the width GCM is defined around; anything else makes the
 * cipher derive one, which is slower and buys nothing.
 */
const IV_BYTES = 12

/**
 * Key length in bytes — 32, i.e. AES-256. {@link importKey} rejects anything
 * else rather than silently selecting a weaker cipher.
 */
const KEY_BYTES = 32

/**
 * A new random key, base64 encoded — store it somewhere safe.
 *
 * @returns 32 random bytes, base64. Nothing keeps a copy, so a key that is lost
 *   takes every value sealed under it with it.
 * @remarks
 * Used for master keys you generate once and keep, and — inside the vault — for
 * the throwaway data key minted per written value.
 * @example
 * ```ts
 * import { generateKey, importKey, seal } from "@mstone6969/vault"
 *
 * const material = generateKey()
 * const key = await importKey(material)
 * const sealed = await seal(key, "hunter2")
 * ```
 * @see {@link importKey} to turn the string back into a usable key.
 */
export function generateKey(): string {
    return Buffer.from(crypto.getRandomValues(new Uint8Array(KEY_BYTES))).toString("base64")
}

/**
 * Imports a base64 key produced by {@link generateKey}.
 *
 * @param base64Key The key material, base64 encoded, decoding to exactly 32
 *   bytes.
 * @returns A key usable with {@link seal} and {@link open}.
 * @throws {@link VaultKeyError} When the decoded material is not 32 bytes. Note
 *   that base64 decoding is lenient: rubbish that is not base64 at all decodes
 *   to too few bytes and surfaces here as a length complaint rather than a
 *   parse error.
 * @remarks
 * The imported key is not extractable, so the raw bytes cannot be read back out
 * of it — a value only ever leaves via {@link open}.
 * @example
 * ```ts
 * import { importKey, MemoryStore, Vault } from "@mstone6969/vault"
 *
 * const key = await importKey(process.env.VAULT_KEY!)
 * const vault = new Vault({ key, store: new MemoryStore() })
 * ```
 */
export async function importKey(base64Key: string): Promise<CryptoKey> {
    const raw = Buffer.from(base64Key, "base64")
    if (raw.length !== KEY_BYTES) {
        throw new VaultKeyError(
            `A vault key must be ${KEY_BYTES} bytes, base64 encoded — got ${raw.length}.`
        )
    }
    return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"])
}

/**
 * Seals a value under a key.
 *
 * @param key The key to seal under.
 * @param plaintext What to seal.
 * @returns `iv:payload`, both base64. A fresh IV every time, so the same value
 *   sealed twice gives two different results.
 * @remarks
 * That the output differs every time is the point: an observer with the store
 * in front of them cannot tell that two entries hold the same password, nor
 * that a value was replaced with itself. It also means a sealed string is no
 * good as a cache key or an equality check.
 *
 * Nothing about the key is written into the output, so the caller must
 * remember which key sealed what — the vault does that by keeping each value's
 * data key beside it in {@link SecretRecord.sealedKey}.
 * @example
 * ```ts
 * import { generateKey, importKey, open, seal } from "@mstone6969/vault"
 *
 * const key = await importKey(generateKey())
 * const sealed = await seal(key, "s3cret")
 * sealed.split(":").length // 2
 * await open(key, sealed) // "s3cret"
 * ```
 * @param binding What this ciphertext belongs to, mixed into the
 *   authentication tag but not stored. A value sealed with one will not open
 *   without exactly the same one, which is how the vault stops sealed bytes
 *   being moved from one entry to another.
 */
export async function seal(
    key: CryptoKey,
    plaintext: string,
    binding?: string
): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES))
    const sealed = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, ...additional(binding) },
        key,
        new TextEncoder().encode(plaintext)
    )
    return `${Buffer.from(iv).toString("base64")}:${Buffer.from(sealed).toString("base64")}`
}

/**
 * The binding as GCM's additional authenticated data, or nothing.
 *
 * @param binding What the ciphertext is tied to, if anything.
 * @returns An object to spread into the algorithm parameters.
 */
function additional(binding: string | undefined): { additionalData?: Uint8Array } {
    return binding === undefined
        ? {}
        : { additionalData: new TextEncoder().encode(binding) }
}

/**
 * Opens a value sealed by {@link seal}.
 *
 * @param key The key it was sealed under.
 * @param sealed The `iv:payload` string to open.
 * @returns The plaintext.
 * @throws {@link VaultKeyError} When the key is wrong, the value has been
 *   altered, or it is not in `iv:payload` form. A wrong key fails rather than
 *   returning nonsense, because GCM authenticates what it decrypts.
 * @remarks
 * That failure mode is worth relying on. A caller does not need to check
 * whether what came back looks plausible: if this returns at all, the value is
 * byte for byte what was sealed, under the key that sealed it. It is also why
 * {@link Vault.rekey} can try each key in turn and know which one was right,
 * and why a store that silently corrupts a record produces an error rather
 * than a credential that fails somewhere far away.
 *
 * The error deliberately does not say which of the three went wrong: telling
 * an attacker apart from a typo is not worth telling an attacker anything.
 * @example
 * ```ts
 * import { generateKey, importKey, open, seal, VaultKeyError } from "@mstone6969/vault"
 *
 * const key = await importKey(generateKey())
 * const other = await importKey(generateKey())
 * const sealed = await seal(key, "s3cret")
 *
 * try {
 *     await open(other, sealed)
 * } catch (error) {
 *     error instanceof VaultKeyError // true — never a wrong plaintext
 * }
 * ```
 * @param binding What the ciphertext was sealed as belonging to. Must match
 *   what {@link seal} was given, or the value will not open.
 */
export async function open(
    key: CryptoKey,
    sealed: string,
    binding?: string
): Promise<string> {
    const [iv, payload] = sealed.split(":")
    if (!iv || !payload) {
        throw new VaultKeyError("A sealed value must look like iv:payload.")
    }

    try {
        const opened = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: Buffer.from(iv, "base64"), ...additional(binding) },
            key,
            Buffer.from(payload, "base64")
        )
        return new TextDecoder().decode(opened)
    } catch {
        throw new VaultKeyError(
            "That value could not be opened — wrong key, wrong place, or it has been altered."
        )
    }
}
