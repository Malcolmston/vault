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
        this.kept.push({ ...entry })
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
