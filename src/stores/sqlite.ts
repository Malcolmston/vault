import { Database } from "bun:sqlite"
import type { HistoryEntry, SecretRecord, VaultStore } from "../types"

type Row = {
    owner: string
    name: string
    sealed: string
    sealed_key: string | null
    plain: string | null
    is_sealed: number
    is_final: number
    expires_at: number | null
    history: string | null
    rotation: string | null
    rotated_at: number | null
    metadata: string | null
    created_at: number
    updated_at: number
    revision: number | null
}

/** Columns added after 0.1.0, applied to tables that predate them. */
const LATER_COLUMNS: [string, string][] = [
    ["sealed_key", "TEXT"],
    ["plain", "TEXT"],
    ["is_sealed", "INTEGER NOT NULL DEFAULT 1"],
    ["is_final", "INTEGER NOT NULL DEFAULT 0"],
    ["expires_at", "INTEGER"],
    ["history", "TEXT"],
    ["rotation", "TEXT"],
    ["rotated_at", "INTEGER"],
    ["metadata", "TEXT"],
    ["revision", "INTEGER NOT NULL DEFAULT 1"],
]

/**
 * Keeps records in SQLite through `bun:sqlite`. Pass a file path, ":memory:",
 * or a Database you already opened.
 *
 * Values are sealed, but owners, names and metadata are ordinary columns —
 * anyone who can read the file learns what you keep, if not what it says. Use
 * `FileStore` when even that should be hidden.
 *
 * @remarks
 * `bun:sqlite` makes this store Bun-only: importing it on Node fails at the
 * import, not at the first query. That is why it is reached through
 * `@mstone6969/vault/stores/sqlite` instead of the package's main entry —
 * a Node program that imports the main entry never loads this file, and never
 * sees the Bun-only import.
 *
 * Every method is `async` only to satisfy {@link VaultStore}; `bun:sqlite` is
 * synchronous, so nothing here waits on I/O.
 *
 * @example
 * ```ts
 * import { Vault } from "@mstone6969/vault"
 * import { SqliteStore } from "@mstone6969/vault/stores/sqlite"
 *
 * const store = new SqliteStore("./vault.sqlite")
 * const vault = new Vault({ key: process.env.VAULT_KEY!, store })
 *
 * await vault.put("alice", "db-password", "hunter2", {
 *     metadata: { kind: "postgres" },
 * })
 * console.log(await vault.open("alice", "db-password")) // "hunter2"
 * store.close()
 * ```
 *
 * @see {@link VaultStore} for what a store owes the vault.
 */
export class SqliteStore implements VaultStore {
    private readonly db: Database
    private readonly table: string

    /**
     * Opens the database if it was given a path, and makes sure the table is
     * there and current.
     *
     * The table is created in its 0.1.0 shape if it is missing, and then every
     * column added since — `sealed_key`, `plain`, `is_sealed`, `is_final`,
     * `expires_at`, `history`, `rotation`, `rotated_at`, `metadata` — is
     * ALTERed in if it is absent. So a table written by an older version of
     * the package is upgraded the moment a newer one opens it, in place and
     * without a migration step of your own, and rows that predate a column
     * read back with sensible defaults: no history, no metadata, sealed, not
     * final, no expiry.
     *
     * @param database A file path to open, ":memory:" for a database that
     *   lasts as long as the process, or a `Database` you already opened —
     *   useful for keeping the vault's table beside your own in one file, and
     *   inside your own transactions.
     * @defaultValue `":memory:"`
     * @param table Which table to keep records in. Give it a name of its own
     *   when one database holds several vaults.
     * @defaultValue `"vault_secrets"`
     * @throws Whatever `bun:sqlite` throws when the path cannot be opened, or
     *   when `table` already exists with an incompatible shape.
     *
     * @example Sharing a database you already opened
     * ```ts
     * import { Database } from "bun:sqlite"
     * import { SqliteStore } from "@mstone6969/vault/stores/sqlite"
     *
     * const db = new Database("./app.sqlite")
     * const store = new SqliteStore(db, "shared_secrets")
     * ```
     */
    constructor(database: string | Database = ":memory:", table = "vault_secrets") {
        this.db = typeof database === "string" ? new Database(database) : database
        this.table = table
        this.db.run(
            `CREATE TABLE IF NOT EXISTS ${this.table} (
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                sealed TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (owner, name)
            )`
        )

        const present = new Set(
            this.db
                .query<{ name: string }, []>(`PRAGMA table_info(${this.table})`)
                .all()
                .map((column) => column.name)
        )
        for (const [column, type] of LATER_COLUMNS) {
            if (!present.has(column)) {
                this.db.run(`ALTER TABLE ${this.table} ADD COLUMN ${column} ${type}`)
            }
        }
    }

    /**
     * Turns a row back into a record: JSON columns parsed, epoch milliseconds
     * back into `Date`, integers back into booleans.
     *
     * Every column added after 0.1.0 is read defensively, because a row
     * written before that column existed reads back as null.
     *
     * @param row One row of {@link SqliteStore}'s table, as SQLite returns it.
     * @returns The record that row stands for.
     */
    private static toRecord(row: Row): SecretRecord {
        const history: HistoryEntry[] = row.history
            ? (JSON.parse(row.history) as { sealed: string; sealedKey: string | null; createdAt: string }[]).map(
                  (entry) => ({ ...entry, createdAt: new Date(entry.createdAt) })
              )
            : []

        return {
            owner: row.owner,
            name: row.name,
            sealed: row.sealed,
            sealedKey: row.sealed_key,
            plain: row.plain,
            isSealed: row.is_sealed !== 0,
            isFinal: row.is_final !== 0,
            expiresAt: row.expires_at === null ? null : new Date(row.expires_at),
            history,
            rotation: row.rotation
                ? (JSON.parse(row.rotation) as SecretRecord["rotation"])
                : null,
            rotatedAt: row.rotated_at === null ? null : new Date(row.rotated_at),
            metadata: row.metadata ? (JSON.parse(row.metadata) as Record<string, string>) : {},
            createdAt: new Date(row.created_at),
            updatedAt: new Date(row.updated_at),
            revision: row.revision ?? 1,
        }
    }

    /**
     * One record, or null when there is none under that name.
     *
     * The record carries the sealed value, not the plaintext: use
     * `Vault.open` to get a value back out.
     *
     * @param owner Whose entry to look for.
     * @param name The entry's name.
     * @returns The stored record, or null when that owner has nothing under
     *   that name.
     */
    async get(owner: string, name: string): Promise<SecretRecord | null> {
        const row = this.db
            .query<Row, [string, string]>(
                `SELECT * FROM ${this.table} WHERE owner = ? AND name = ?`
            )
            .get(owner, name)
        return row ? SqliteStore.toRecord(row) : null
    }

    /**
     * Every record one owner holds, in whatever order SQLite returns them —
     * the vault sorts what it shows.
     *
     * @param owner Whose entries to return.
     * @returns That owner's records, empty when they hold none.
     */
    async list(owner: string): Promise<SecretRecord[]> {
        return this.db
            .query<Row, [string]>(`SELECT * FROM ${this.table} WHERE owner = ?`)
            .all(owner)
            .map(SqliteStore.toRecord)
    }

    /**
     * Every record, whoever owns it.
     *
     * Only `Vault.rekey` and `Vault.purgeExpired` need this;
     * everything else stays inside one owner. It loads the whole table, so it
     * is the one method that costs more as the vault grows.
     *
     * @returns Every record in the table.
     */
    async all(): Promise<SecretRecord[]> {
        return this.db
            .query<Row, []>(`SELECT * FROM ${this.table}`)
            .all()
            .map(SqliteStore.toRecord)
    }

    /**
     * Writes a record, replacing any under the same owner and name.
     *
     * `created_at` is deliberately left out of the conflict update: a
     * replacement keeps the moment the entry first appeared. Nothing here
     * enforces finality or expiry — those are the vault's rules, and the store
     * writes what it is given.
     *
     * @param record The record to write. `owner` and `name` are its key.
     * @returns The record as it reads back out of SQLite, which is what
     *   callers should keep — dates have been through epoch milliseconds and
     *   JSON columns through a round trip.
     * @throws Error if the row cannot be read back immediately after writing
     *   it, which means the database is not behaving as SQLite.
     */
    async put(record: SecretRecord): Promise<SecretRecord> {
        this.db
            .query(
                `INSERT INTO ${this.table}
                    (owner, name, sealed, sealed_key, plain, is_sealed, is_final,
                     expires_at, history, rotation, rotated_at, metadata,
                     created_at, updated_at, revision)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(owner, name) DO UPDATE SET
                    sealed = excluded.sealed,
                    sealed_key = excluded.sealed_key,
                    plain = excluded.plain,
                    is_sealed = excluded.is_sealed,
                    is_final = excluded.is_final,
                    expires_at = excluded.expires_at,
                    history = excluded.history,
                    rotation = excluded.rotation,
                    rotated_at = excluded.rotated_at,
                    metadata = excluded.metadata,
                    updated_at = excluded.updated_at,
                    revision = excluded.revision`
            )
            .run(
                record.owner,
                record.name,
                record.sealed,
                record.sealedKey,
                record.plain,
                record.isSealed ? 1 : 0,
                record.isFinal ? 1 : 0,
                record.expiresAt?.getTime() ?? null,
                JSON.stringify(record.history),
                record.rotation ? JSON.stringify(record.rotation) : null,
                record.rotatedAt?.getTime() ?? null,
                JSON.stringify(record.metadata),
                record.createdAt.getTime(),
                record.updatedAt.getTime(),
                record.revision ?? 1
            )

        const stored = await this.get(record.owner, record.name)
        if (!stored) throw new Error("The record vanished immediately after writing it.")
        return stored
    }

    /**
     * Writes a record only if the stored one is still at `expectedRevision`.
     *
     * @remarks
     * SQLite settles this in one statement — an `INSERT … WHERE NOT EXISTS` to
     * claim a name, an `UPDATE … WHERE revision = ?` to replace a value — so
     * two writers racing on one entry cannot both win. Within a process
     * `bun:sqlite` is synchronous anyway; this is what makes it safe between
     * processes sharing the file.
     *
     * @param record The record to write, revision already incremented.
     * @param expectedRevision What the stored revision must be, or null to
     *   require that nothing is stored under that name yet.
     * @returns The written record, or null when the revision did not match.
     */
    async putIf(
        record: SecretRecord,
        expectedRevision: number | null
    ): Promise<SecretRecord | null> {
        const changed =
            expectedRevision === null
                ? this.claim(record)
                : this.replace(record, expectedRevision)

        return changed ? await this.get(record.owner, record.name) : null
    }

    /** Inserts a record, unless that name is taken. True if it went in. */
    private claim(record: SecretRecord): boolean {
        const result = this.db
            .query(
                `INSERT OR IGNORE INTO ${this.table}
                    (owner, name, sealed, sealed_key, plain, is_sealed, is_final,
                     expires_at, history, rotation, rotated_at, metadata,
                     created_at, updated_at, revision)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            )
            .run(...SqliteStore.bind(record))
        return result.changes > 0
    }

    /** Replaces a record, but only at the revision given. True if it did. */
    private replace(record: SecretRecord, expectedRevision: number): boolean {
        const result = this.db
            .query(
                `UPDATE ${this.table} SET
                    sealed = ?, sealed_key = ?, plain = ?, is_sealed = ?,
                    is_final = ?, expires_at = ?, history = ?, rotation = ?,
                    rotated_at = ?, metadata = ?, updated_at = ?, revision = ?
                 WHERE owner = ? AND name = ? AND revision = ?`
            )
            .run(
                record.sealed,
                record.sealedKey,
                record.plain,
                record.isSealed ? 1 : 0,
                record.isFinal ? 1 : 0,
                record.expiresAt?.getTime() ?? null,
                JSON.stringify(record.history),
                record.rotation ? JSON.stringify(record.rotation) : null,
                record.rotatedAt?.getTime() ?? null,
                JSON.stringify(record.metadata),
                record.updatedAt.getTime(),
                record.revision ?? 1,
                record.owner,
                record.name,
                expectedRevision
            )
        return result.changes > 0
    }

    /** A record as the insert's parameters, in column order. */
    private static bind(record: SecretRecord): (string | number | null)[] {
        return [
            record.owner,
            record.name,
            record.sealed,
            record.sealedKey,
            record.plain,
            record.isSealed ? 1 : 0,
            record.isFinal ? 1 : 0,
            record.expiresAt?.getTime() ?? null,
            JSON.stringify(record.history),
            record.rotation ? JSON.stringify(record.rotation) : null,
            record.rotatedAt?.getTime() ?? null,
            JSON.stringify(record.metadata),
            record.createdAt.getTime(),
            record.updatedAt.getTime(),
            record.revision ?? 1,
        ]
    }

    /**
     * Deletes a record, returning false when there was nothing to delete.
     *
     * History goes with it: the row holds the previous values, so deleting an
     * entry deletes every version of it.
     *
     * @param owner Whose entry to delete.
     * @param name The entry's name.
     * @returns True when a record was there and is now gone, false when there
     *   was nothing under that name.
     */
    async remove(owner: string, name: string): Promise<boolean> {
        const existing = await this.get(owner, name)
        if (!existing) return false
        this.db.query(`DELETE FROM ${this.table} WHERE owner = ? AND name = ?`).run(owner, name)
        return true
    }

    /**
     * Closes the underlying database.
     *
     * This closes a `Database` you passed to the constructor as well — the
     * store does not track who opened it, so anything else using that same
     * handle stops working too. Call it on the owner of the connection only.
     *
     * @returns Nothing; the store is unusable afterwards.
     */
    close(): void {
        this.db.close()
    }
}
