import type { AuditEntry, AuditLog, AuditQuery } from "./types"

/** How many entries a {@link MemoryAuditLog} keeps before dropping the oldest. */
export const DEFAULT_AUDIT_LIMIT = 10_000

/**
 * Narrows a set of entries the way {@link AuditLog.entries} promises to.
 *
 * @remarks
 * Shared by every audit log so that "newest first", the meaning of `limit`, and
 * which end of `since`/`until` is inclusive cannot drift between them.
 *
 * @param entries Everything the log holds, in any order.
 * @param query Which of them to return.
 * @returns The matching entries, newest first.
 */
export function matching(entries: AuditEntry[], query: AuditQuery = {}): AuditEntry[] {
    const { owner, name, action, since, until, limit } = query

    const found = entries
        .map((entry, order) => ({ entry, order }))
        .filter(({ entry }) => {
            if (owner !== undefined && entry.owner !== owner) return false
            if (name !== undefined && entry.name !== name) return false
            if (action !== undefined && entry.action !== action) return false
            if (since !== undefined && entry.at < since) return false
            if (until !== undefined && entry.at >= until) return false
            return true
        })
        // Two actions in the same millisecond are common, and sorting on the
        // clock alone would hand them back oldest-first — the opposite of what
        // this promises. The order they arrived in breaks the tie, which is
        // what the SQL logs do with their row ids.
        .sort((a, b) => b.entry.at.getTime() - a.entry.at.getTime() || b.order - a.order)
        .map(({ entry }) => entry)

    return limit === undefined ? found : found.slice(0, limit)
}

/**
 * The hash of one entry, over its contents and the hash before it.
 *
 * @remarks
 * The chaining is what makes a *deleted* line detectable: hashing an entry on
 * its own would catch an edit, but not a removal. Every log that ships uses
 * this, so a trail written to SQLite and one written to Postgres hash the same.
 *
 * The fields go in in a fixed order rather than through `JSON.stringify` of the
 * whole entry, so that a field added to {@link VaultEvent} later cannot quietly
 * change the hash of everything already written.
 *
 * @param entry What happened.
 * @param previous The hash before this one, or null when it is the first.
 * @returns The hash, hex.
 */
export async function chainHash(
    entry: AuditEntry,
    previous: string | null
): Promise<string> {
    const parts = [
        previous ?? "",
        entry.action,
        entry.owner,
        entry.name ?? "",
        entry.by ?? "",
        entry.detail ?? "",
        String(entry.at.getTime()),
    ]
    // Length-prefixed, so no two different entries can flatten to the same
    // string by moving a separator into a field.
    const canonical = parts.map((part) => `${part.length}:${part}`).join("")

    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical))
    return Buffer.from(digest).toString("hex")
}

/** What {@link verifyChain} found. */
export type ChainReport = {
    /** Whether every entry links to the one before it. */
    intact: boolean
    /**
     * Where it stops adding up, as an index into the entries given, or null
     * when nothing is wrong.
     *
     * @remarks
     * A break means the entry there was edited, or that one before it was
     * removed. Which of the two it is cannot be told from the chain alone.
     */
    brokenAt: number | null
    /** Entries carrying no hash at all, so nothing about them can be checked. */
    unchained: number
}

/**
 * Checks that a run of audit entries has not been edited or thinned out.
 *
 * @remarks
 * Give it exactly what {@link AuditLog.entries} returned for an *unfiltered*
 * query — the chain runs through every entry, so a filtered slice will look
 * broken even when nothing is wrong.
 *
 * A hash chain proves the middle of a log has not been touched. It cannot stop
 * someone who can write to the database from re-hashing the whole thing, or
 * from lopping off the end. For that you need the log somewhere the vault's
 * writer cannot reach — another database, an append-only bucket — and this is
 * what tells you whether what came back from there adds up.
 *
 * @param entries The entries, newest first, as the log hands them over.
 * @returns Whether the chain holds, and where it stops if not.
 *
 * @example
 * ```ts
 * const report = await verifyChain(await audit.entries())
 * if (!report.intact) console.error("audit trail broken at", report.brokenAt)
 * ```
 */
export async function verifyChain(entries: AuditEntry[]): Promise<ChainReport> {
    // Given newest first; the chain reads the other way.
    const oldestFirst = [...entries].reverse()
    let previous: string | null = null
    let unchained = 0

    for (let index = 0; index < oldestFirst.length; index += 1) {
        const entry = oldestFirst[index]!

        if (entry.hash === undefined) {
            unchained += 1
            continue
        }

        if (entry.previous !== undefined && entry.previous !== previous) {
            return { intact: false, brokenAt: entries.length - 1 - index, unchained }
        }
        if ((await chainHash(entry, previous)) !== entry.hash) {
            return { intact: false, brokenAt: entries.length - 1 - index, unchained }
        }
        previous = entry.hash
    }

    return { intact: true, brokenAt: null, unchained }
}

/**
 * An audit trail in memory, for tests and for development.
 *
 * @remarks
 * It goes when the process does, so it is not the log to reach for if anyone
 * will ever ask what happened last week — `SqliteAuditLog` and
 * `PostgresAuditLog` are. It keeps the most recent `limit` entries and drops
 * the oldest, so a long-running process cannot fill memory with its own
 * history.
 *
 * @example
 * ```ts
 * import { MemoryAuditLog, Vault } from "@mstone6969/vault"
 *
 * const audit = new MemoryAuditLog()
 * const vault = new Vault({ key, store, audit })
 *
 * await vault.put("alice", "token", "value")
 * await audit.entries({ owner: "alice" }) // [{ action: "put", … }]
 * ```
 *
 * @see {@link AuditLog}
 */
export class MemoryAuditLog implements AuditLog {
    private readonly kept: AuditEntry[] = []
    private readonly limit: number
    /** The hash of the entry written most recently, to chain the next to. */
    private last: string | null = null

    /**
     * @param limit How many entries to keep before the oldest start falling off
     *   the end.
     */
    constructor(limit: number = DEFAULT_AUDIT_LIMIT) {
        this.limit = limit
    }

    /**
     * Writes one entry.
     *
     * @param entry What happened.
     * @returns Nothing.
     */
    async append(entry: AuditEntry): Promise<void> {
        const previous = this.last
        const chained: AuditEntry = { ...entry, previous, hash: await chainHash(entry, previous) }
        this.last = chained.hash!

        this.kept.push(chained)
        // Dropping the oldest breaks the chain at the front, which
        // `verifyChain` will report — an in-memory log is not the one to reach
        // for if the trail has to add up later.
        if (this.kept.length > this.limit) this.kept.shift()
    }

    /**
     * Reads entries back, newest first.
     *
     * @param query Which ones. Everything when left out.
     * @returns Copies of the matching entries, so a caller cannot rewrite
     *   history by editing what it was handed.
     */
    async entries(query?: AuditQuery): Promise<AuditEntry[]> {
        return matching(this.kept, query).map((entry) => ({ ...entry }))
    }
}
