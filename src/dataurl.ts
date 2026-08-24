import { VaultError } from "./errors"

/**
 * Data URLs, in both directions.
 *
 * @remarks
 * Kept apart from {@link Vault} because neither function needs a key, a store,
 * or anything else about a vault: they are the encoding, and the vault's
 * `openDataUrl` and `putDataUrl` are that encoding applied to an entry.
 */

/** What a value with no stated type is, per RFC 2397. */
export const DEFAULT_MEDIA_TYPE = "text/plain;charset=US-ASCII"

/** A media type: `type/subtype`, with optional `;parameter=value` parts. */
const MEDIA_TYPE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*(;[^;]+)*$/

/** What {@link parseDataUrl} pulled out of one. */
export type ParsedDataUrl = {
    /** The media type as the URL stated it, or the RFC's default. */
    mediaType: string
    /** The bytes. */
    bytes: Uint8Array
}

/**
 * Builds a data URL.
 *
 * @remarks
 * Always base64, never percent-encoding: the bytes here are usually a key or a
 * certificate rather than text, and base64 is both shorter and the only form
 * that is safe for arbitrary bytes.
 *
 * @param bytes What to encode.
 * @param mediaType The media type, `application/octet-stream` when left out —
 *   the honest answer for bytes nobody described, rather than the RFC's
 *   `text/plain` default, which would be a claim about content this cannot
 *   make.
 * @returns `data:<mediaType>;base64,<data>`.
 * @throws {@link VaultError} 422 when the media type is not one.
 *
 * @example
 * ```ts
 * dataUrl(new Uint8Array([1, 2, 3]), "application/pkcs8")
 * // "data:application/pkcs8;base64,AQID"
 * ```
 */
export function dataUrl(bytes: Uint8Array, mediaType = "application/octet-stream"): string {
    if (!MEDIA_TYPE.test(mediaType)) {
        throw new VaultError(`"${mediaType}" is not a media type.`)
    }
    return `data:${mediaType};base64,${Buffer.from(bytes).toString("base64")}`
}

/**
 * Reads a data URL back into bytes and a media type.
 *
 * @remarks
 * Both forms are accepted: base64, and percent-encoded text as a browser or a
 * hand-written URL may produce.
 *
 * @param url The data URL.
 * @returns Its media type and bytes.
 * @throws {@link VaultError} 422 when it is not a data URL, or its payload will
 *   not decode.
 *
 * @example
 * ```ts
 * parseDataUrl("data:image/png;base64,iVBORw0KGgo=")
 * // { mediaType: "image/png", bytes: Uint8Array(8) [ … ] }
 * ```
 */
export function parseDataUrl(url: string): ParsedDataUrl {
    const comma = url.indexOf(",")
    if (!url.startsWith("data:") || comma === -1) {
        throw new VaultError("That is not a data URL.")
    }

    const header = url.slice("data:".length, comma)
    const payload = url.slice(comma + 1)
    const base64 = header.endsWith(";base64")
    const stated = base64 ? header.slice(0, -";base64".length) : header
    const mediaType = stated === "" ? DEFAULT_MEDIA_TYPE : stated

    if (!MEDIA_TYPE.test(mediaType)) {
        throw new VaultError(`"${mediaType}" is not a media type.`)
    }

    if (!base64) {
        return { mediaType, bytes: new TextEncoder().encode(decodeURIComponent(payload)) }
    }

    // Buffer.from ignores anything that is not base64 rather than refusing, so
    // the round trip is what actually checks it.
    const bytes = new Uint8Array(Buffer.from(payload, "base64"))
    if (Buffer.from(bytes).toString("base64").replace(/=+$/, "") !== payload.replace(/=+$/, "")) {
        throw new VaultError("That data URL's payload is not valid base64.")
    }

    return { mediaType, bytes }
}
