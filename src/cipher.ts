import { VaultKeyError } from "./errors"

/**
 * How values are sealed, and how to use something else.
 *
 * @remarks
 * The vault seals with AES-256-GCM and always has. This is the seam for
 * changing that: a named algorithm, recorded in the ciphertext so that values
 * written under one still open after you have moved to another.
 */

/**
 * One way of sealing a value.
 *
 * @remarks
 * Implement this to use an algorithm the package does not ship — a
 * FIPS-validated module, ChaCha20-Poly1305 through `node:crypto` on Node, a
 * post-quantum scheme when you need one. Register it with
 * {@link VaultOptions.ciphers} and the vault can read it; set
 * {@link VaultOptions.cipher} and new writes use it.
 *
 * The vault owns the framing: what `seal` returns is stored behind `$name$`, so
 * a payload may be shaped however the algorithm likes. It must not contain a
 * newline, since a streamed export puts one entry per line.
 *
 * A cipher does not see the entry it belongs to, and does not need to. The tie
 * that stops a value being moved between entries is on the data key, which the
 * master key or {@link KeyWrapper} seals with the owner and name as additional
 * data — and a value cannot be opened without its own key. So an algorithm
 * here only has to be a sound authenticated cipher; it cannot weaken 1.4's
 * guarantee by leaving something out.
 *
 * @example ChaCha20-Poly1305 on Node
 * ```ts
 * const chacha: Cipher = {
 *     name: "C20P",
 *     generateKey: () => randomBytes(32).toString("base64"),
 *     async seal(material, plaintext) {
 *         const iv = randomBytes(12)
 *         const c = createCipheriv("chacha20-poly1305",
 *             Buffer.from(material, "base64"), iv, { authTagLength: 16 })
 *         const body = Buffer.concat([c.update(plaintext, "utf8"), c.final()])
 *         return [iv, c.getAuthTag(), body].map((p) => p.toString("base64")).join(":")
 *     },
 *     async open(material, payload) { … },
 * }
 * ```
 *
 * That one runs on Node but not on Bun, whose `node:crypto` has no
 * `chacha20-poly1305`. Check your runtime before committing a vault to an
 * algorithm — a vault that cannot open its own values is not recoverable.
 */
export type Cipher = {
    /**
     * What this algorithm is called, recorded with every value it seals.
     *
     * @remarks
     * Letters, numbers, dash and underscore. Pick one and keep it: change the
     * name and the vault stops recognising everything already written under it.
     */
    readonly name: string
    /**
     * A fresh key for one value.
     *
     * @returns Key material, base64, of whatever length the algorithm wants.
     */
    generateKey(): string
    /**
     * Seals one value.
     *
     * @param material The key, as {@link Cipher.generateKey} produced.
     * @param plaintext What to seal.
     * @returns The sealed payload, with no newline in it.
     */
    seal(material: string, plaintext: string): Promise<string>
    /**
     * Opens one value.
     *
     * @param material The key it was sealed under.
     * @param payload What {@link Cipher.seal} returned.
     * @returns The plaintext.
     * @throws When the key is wrong or the value was altered.
     */
    open(material: string, payload: string): Promise<string>
}

/** What a name may be made of, so the framing cannot be confused. */
const CIPHER_NAME = /^[A-Za-z0-9_-]+$/

/** IV length in bytes: the width GCM is defined around. */
const IV_BYTES = 12

/**
 * AES-GCM at a given key size.
 *
 * @remarks
 * `aesGcm(256)` is what the vault has always used and still uses unless told
 * otherwise. The smaller sizes are here because the seam should hold more than
 * one thing to be worth having, and because AES-128 is meaningfully quicker
 * where a great many small values are opened at once. Nothing about AES-256 is
 * known to be weak; if you have no reason to move, do not.
 *
 * @param bits 128, 192 or 256.
 * @returns A cipher named `A128GCM`, `A192GCM` or `A256GCM`.
 * @throws {@link VaultKeyError} for any other size.
 *
 * @example
 * ```ts
 * const vault = new Vault({ key, store, cipher: aesGcm(128) })
 * ```
 */
export function aesGcm(bits: 128 | 192 | 256): Cipher {
    if (bits !== 128 && bits !== 192 && bits !== 256) {
        throw new VaultKeyError(`AES has no ${bits}-bit key size.`)
    }
    const bytes = bits / 8

    const key = (material: string) => {
        const raw = Buffer.from(material, "base64")
        if (raw.length !== bytes) {
            throw new VaultKeyError(
                `An AES-${bits} key must be ${bytes} bytes; this one is ${raw.length}.`
            )
        }
        return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
            "encrypt",
            "decrypt",
        ])
    }

    return {
        name: `A${bits}GCM`,

        generateKey() {
            return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64")
        },

        async seal(material, plaintext) {
            const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES))
            const sealed = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                await key(material),
                new TextEncoder().encode(plaintext)
            )
            return `${Buffer.from(iv).toString("base64")}:${Buffer.from(sealed).toString("base64")}`
        },

        async open(material, payload) {
            const [iv, body] = payload.split(":")
            if (!iv || !body) {
                throw new VaultKeyError("A sealed value must look like iv:payload.")
            }

            try {
                const opened = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: Buffer.from(iv, "base64") },
                    await key(material),
                    Buffer.from(body, "base64")
                )
                return new TextDecoder().decode(opened)
            } catch {
                throw new VaultKeyError(
                    "That value could not be opened — wrong key, wrong place, or it has been altered."
                )
            }
        },
    }
}

/** What the vault seals with unless told otherwise, and always has. */
export const DEFAULT_CIPHER: Cipher = aesGcm(256)

/**
 * Puts a cipher's name in front of its payload, so it can be found again.
 *
 * @remarks
 * The default is written bare, exactly as every version before 2.3 wrote it —
 * there is no marker to add to a value already in the right format, and adding
 * one would rewrite every ciphertext for no gain. Anything else is prefixed
 * `$name$`, which cannot collide with the bare form because base64 has no `$`.
 *
 * @param cipher What sealed it.
 * @param payload What it returned.
 * @returns The value as it is stored.
 */
export function frame(cipher: Cipher, payload: string): string {
    return cipher.name === DEFAULT_CIPHER.name ? payload : `$${cipher.name}$${payload}`
}

/** A stored value, split into what sealed it and what it holds. */
export type Framed = {
    /** The algorithm's name — the default's when the value carries no marker. */
    name: string
    /** What to hand that algorithm's `open`. */
    payload: string
}

/**
 * Takes a stored value apart into the algorithm that sealed it and its payload.
 *
 * @param stored The value as the store holds it.
 * @returns The cipher's name — the default's when there is no marker — and the
 *   payload to hand it.
 */
export function unframe(stored: string): Framed {
    if (!stored.startsWith("$")) return { name: DEFAULT_CIPHER.name, payload: stored }

    const end = stored.indexOf("$", 1)
    const name = end === -1 ? "" : stored.slice(1, end)
    if (end === -1 || !CIPHER_NAME.test(name)) {
        throw new VaultKeyError("That value does not say what sealed it.")
    }

    return { name, payload: stored.slice(end + 1) }
}
