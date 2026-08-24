import { VaultError } from "./errors"

/**
 * Ed25519 SSH keys, in the formats OpenSSH actually reads.
 *
 * @remarks
 * Ed25519 rather than RSA because there is nothing to choose: no key size to
 * get wrong, small keys, and every OpenSSH since 6.5 accepts them.
 *
 * Nothing here needs a vault. {@link Vault.putSshKey} is these functions with
 * the private half sealed and the public half kept in the clear.
 */

/** The one key type here. */
const KEY_TYPE = "ssh-ed25519"

/** What OpenSSH's private key format begins with. */
const AUTH_MAGIC = "openssh-key-v1\0"

/** A generated pair, in the two formats OpenSSH reads. */
export type SshKeyPair = {
    /**
     * The private key, as an OpenSSH PRIVATE KEY block.
     *
     * @remarks
     * Unencrypted — the vault is what protects it. Written to disk it would
     * need a passphrase; kept in a vault it has one, in the form of the master
     * key.
     */
    privateKey: string
    /** The public key, as one `authorized_keys` line. */
    publicKey: string
    /** The `SHA256:…` fingerprint, as `ssh-keygen -l` prints it. */
    fingerprint: string
}

/**
 * A length-prefixed string, as every SSH format is built from.
 *
 * @param bytes What to prefix.
 * @returns Four bytes of big-endian length, then the bytes.
 */
function field(bytes: Uint8Array): Uint8Array {
    const out = new Uint8Array(4 + bytes.length)
    new DataView(out.buffer).setUint32(0, bytes.length)
    out.set(bytes, 4)
    return out
}

/** The same, for text. */
function textField(text: string): Uint8Array {
    return field(new TextEncoder().encode(text))
}

/** Everything joined, in order. */
function join(parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0))
    let at = 0
    for (const part of parts) {
        out.set(part, at)
        at += part.length
    }
    return out
}

/**
 * The public key blob: the type, then the key.
 *
 * @param publicKey The 32 raw bytes.
 * @returns The blob that goes in both formats and in the fingerprint.
 */
function publicBlob(publicKey: Uint8Array): Uint8Array {
    return join([textField(KEY_TYPE), field(publicKey)])
}

/**
 * A public key as an `authorized_keys` line.
 *
 * @param publicKey The 32 raw bytes.
 * @param comment What to put after the key. Empty for none.
 * @returns `ssh-ed25519 AAAA… comment`.
 */
export function sshPublicLine(publicKey: Uint8Array, comment = ""): string {
    const line = `${KEY_TYPE} ${Buffer.from(publicBlob(publicKey)).toString("base64")}`
    return comment ? `${line} ${comment}` : line
}

/**
 * The fingerprint of a public key, as `ssh-keygen -l` prints it.
 *
 * @param publicLine An `authorized_keys` line, or just its base64 blob.
 * @returns `SHA256:` and the base64 digest, without the padding OpenSSH omits.
 * @throws {@link VaultError} 422 when that is not an Ed25519 public key.
 *
 * @example
 * ```ts
 * sshFingerprint("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…")
 * // "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
 * ```
 */
export async function sshFingerprint(publicLine: string): Promise<string> {
    const parts = publicLine.trim().split(/\s+/)
    const base64 = parts.length > 1 ? parts[1]! : parts[0]!
    const blob = Buffer.from(base64, "base64")

    if (!blob.subarray(4, 4 + KEY_TYPE.length).toString().startsWith(KEY_TYPE)) {
        throw new VaultError("That is not an ssh-ed25519 public key.")
    }

    const digest = await crypto.subtle.digest("SHA-256", blob)
    // OpenSSH prints it base64 with the padding stripped.
    return `SHA256:${Buffer.from(digest).toString("base64").replace(/=+$/, "")}`
}

/**
 * The private key, in OpenSSH's own format.
 *
 * @remarks
 * Built by hand because it is small and specified, and because pulling in a
 * dependency to write ninety bytes of framing would be a poor trade for a
 * package that has none.
 *
 * The layout is `openssh-key-v1`, the cipher and KDF (both `none`, since the
 * vault is the protection), one public key, and a private section holding the
 * key twice over — as OpenSSH stores it — with a check value repeated so a
 * wrong passphrase is obvious, and padded to the cipher's block size.
 *
 * @param seed The 32-byte private seed.
 * @param publicKey The 32-byte public key.
 * @param comment What to record alongside it.
 * @returns A PEM block OpenSSH will read.
 */
function privatePem(seed: Uint8Array, publicKey: Uint8Array, comment: string): string {
    // Repeated so that a tool decrypting with the wrong passphrase sees two
    // halves that disagree. Nothing here is encrypted, but the format wants it.
    const check = crypto.getRandomValues(new Uint8Array(4))

    const parts: Uint8Array[] = [
        check,
        check,
        textField(KEY_TYPE),
        field(publicKey),
        // OpenSSH keeps the seed and the public key together as the private key.
        field(join([seed, publicKey])),
        textField(comment),
    ]

    // Padded with 1, 2, 3… to a multiple of 8, which is what "none" uses.
    const body = join(parts)
    const padding = new Uint8Array((8 - (body.length % 8)) % 8)
    for (let i = 0; i < padding.length; i += 1) padding[i] = i + 1

    const key = join([
        new TextEncoder().encode(AUTH_MAGIC),
        textField("none"),
        textField("none"),
        textField(""),
        new Uint8Array([0, 0, 0, 1]),
        field(publicBlob(publicKey)),
        field(join([body, padding])),
    ])

    const base64 = Buffer.from(key).toString("base64")
    const lines = base64.match(/.{1,70}/g) ?? []
    return [
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        ...lines,
        "-----END OPENSSH PRIVATE KEY-----",
        "",
    ].join("\n")
}

/**
 * Makes an Ed25519 SSH key.
 *
 * @param comment What to record in both halves — a host, a purpose, whatever
 *   `ssh-keygen -C` would have been given.
 * @returns The private key, the public line, and the fingerprint.
 *
 * @example
 * ```ts
 * const key = await generateSshKey("deploy@ci")
 * key.publicKey    // "ssh-ed25519 AAAAC3… deploy@ci"
 * key.fingerprint  // "SHA256:…"
 * ```
 */
export async function generateSshKey(comment = ""): Promise<SshKeyPair> {
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
        "sign",
        "verify",
    ])) as unknown as CryptoKeyPair

    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))
    // A PKCS#8 Ed25519 key is a fixed 48 bytes: 16 of structure, then the seed.
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))
    const seed = pkcs8.slice(16)

    const publicLine = sshPublicLine(publicKey, comment)
    return {
        privateKey: privatePem(seed, publicKey, comment),
        publicKey: publicLine,
        fingerprint: await sshFingerprint(publicLine),
    }
}
