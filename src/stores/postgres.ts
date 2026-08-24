import { SQL } from "bun"
import type { HistoryEntry, SecretRecord, VaultStore } from "../types"

/** One row of a {@link PostgresStore} table, as Postgres hands it back. */
type Row = {
    owner: string
    name: string
    sealed: string
    sealed_key: string | null
    plain: string | null
    is_sealed: boolean
    is_final: boolean
    expires_at: Date | null
    history: HistoryEntry[] | string | null
    rotation: SecretRecord["rotation"] | string
    rotated_at: Date | null
    metadata: Record<string, string> | string | null
    created_at: Date
    updated_at: Date
    revision: number
}

/**
 * Keeps records in PostgreSQL through Bun's built-in `SQL` client.
 *
 * The store to use when more than one process writes the same vault. The
 * others cannot do that safely: `MemoryStore` is one process by definition,
 * `SqliteStore` is one machine, and `FileStore` serialises writes with a lock
 * file, which works but does not scale past a handful of writers. Here the
 * compare-and-set is a `WHERE revision = $n` that the database settles, so two
 * API instances can share one vault.
 *
 * Values are sealed, but owners, names and metadata are ordinary columns, as
 * in `SqliteStore` — anyone who can read the database learns what you keep, if
 * not what it says.
 *
 * @remarks
 * `bun`'s `SQL` makes this Bun-only, so it lives behind a subpath and never
 * loads unless you ask for it: a Node program importing the package's main
 * entry never sees this file.
 *
 * Call {@link PostgresStore.migrate} once before first use. It is not run
 * automatically, because creating tables is not something a library should do
 * behind your back the first time you read from it.
 *
 * @example
 * ```ts
 * import { Vault } from "@mstone6969/vault"
 * import { PostgresStore } from "@mstone6969/vault/stores/postgres"
 *
 * const store = new PostgresStore(process.env.DATABASE_URL!)
 * await store.migrate()
 *
 * const vault = new Vault({ key: process.env.VAULT_KEY!, store, strictWrites: true })
 * await vault.put("alice", "db-password", "hunter2")
 * await store.close()
 * ```
 *
 * @see {@link VaultStore} for what a store owes the vault.
 */
export class PostgresStore implements VaultStore {
    private readonly sql: SQL
    private readonly table: string
    /** True once the caller passed us a client to share, in which case closing
     * is theirs to do. */
    private readonly borrowed: boolean

    /**
     * @param database A connection string, or a `SQL` client you already have.
     *   Passing a client shares its pool and leaves closing it to you.
     * @param table What to call the table. Quoted as an identifier, so it must
     *   be a plain name — it is interpolated, not bound, because Postgres will
     *   not take a table name as a parameter.
     * @throws When `table` is not a plain identifier.
     */
    constructor(database: string | SQL, table = "vault_secrets") {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) {
            throw new Error(`"${table}" is not a usable table name.`)
        }
        this.borrowed = typeof database !== "string"
        this.sql = typeof database === "string" ? new SQL(database) : database
        this.table = table
    }

    /**
     * Creates the table if it is not there, and adds any column a older
     * version of this store did not write.
     *
     * Safe to run every time the process starts, and safe to run from several
     * processes at once: every statement is `IF NOT EXISTS`.
     *
     * @returns Nothing, once the table matches what this version expects.
     */
    async migrate(): Promise<void> {
        await this.sql.unsafe(`
            CREATE TABLE IF NOT EXISTS "${this.table}" (
                owner       TEXT NOT NULL,
                name        TEXT NOT NULL,
                sealed      TEXT NOT NULL,
                sealed_key  TEXT,
                plain       TEXT,
                is_sealed   BOOLEAN NOT NULL DEFAULT TRUE,
                is_final    BOOLEAN NOT NULL DEFAULT FALSE,
                expires_at  TIMESTAMPTZ,
                history     JSONB NOT NULL DEFAULT '[]'::jsonb,
                rotation    JSONB,
                rotated_at  TIMESTAMPTZ,
                metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at  TIMESTAMPTZ NOT NULL,
                updated_at  TIMESTAMPTZ NOT NULL,
                revision    INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (owner, name)
            )
        `)
        // Named separately so a table made by an earlier version gains it.
        await this.sql.unsafe(
            `ALTER TABLE "${this.table}" ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 1`
        )
    }

    /**
     * Turns a row back into a record.
     *
     * @param row One row of the store's table.
     * @returns The record it stands for.
     */
    /**
     * A JSONB column as a value, however the driver handed it over.
     *
     * @param value What the column held.
     * @param fallback What an absent column means.
     * @returns The parsed value.
     */
    private static json<T>(value: T | string | null, fallback: T): T {
        if (value === null || value === undefined) return fallback
        // Bun's SQL client hands JSONB back as text on some connections and as
        // a parsed value on others, so this takes it either way.
        return typeof value === "string" ? (JSON.parse(value) as T) : value
    }

    private static toRecord(row: Row): SecretRecord {
        return {
            owner: row.owner,
            name: row.name,
            sealed: row.sealed,
            sealedKey: row.sealed_key,
            plain: row.plain,
            isSealed: row.is_sealed,
            isFinal: row.is_final,
            expiresAt: row.expires_at,
            history: PostgresStore.json<HistoryEntry[]>(row.history, []).map((entry) => ({
                ...entry,
                createdAt: new Date(entry.createdAt),
            })),
            rotation: PostgresStore.json<SecretRecord["rotation"]>(row.rotation, null),
            rotatedAt: row.rotated_at,
            metadata: PostgresStore.json<Record<string, string>>(row.metadata, {}),
            createdAt: row.created_at,
            updatedAt: row.updated_at,
            revision: row.revision,
        }
    }

    /**
     * One record, or null when there is none under that name.
     *
     * @param owner Whose entry to look for.
     * @param name The entry's name.
     * @returns The stored record, sealed value and all, or null.
     */
    async get(owner: string, name: string): Promise<SecretRecord | null> {
        const rows = (await this.sql.unsafe(
            `SELECT * FROM "${this.table}" WHERE owner = $1 AND name = $2`,
            [owner, name]
        )) as Row[]
        return rows[0] ? PostgresStore.toRecord(rows[0]) : null
    }

    /**
     * Every record one owner holds.
     *
     * @param owner Whose entries to return.
     * @returns That owner's records, empty when they hold none.
     */
    async list(owner: string): Promise<SecretRecord[]> {
        const rows = (await this.sql.unsafe(
            `SELECT * FROM "${this.table}" WHERE owner = $1`,
            [owner]
        )) as Row[]
        return rows.map(PostgresStore.toRecord)
    }

    /**
     * Every record in the store, whoever owns it. What `rekey` walks.
     *
     * @returns Every record, empty when the table is.
     */
    async all(): Promise<SecretRecord[]> {
        const rows = (await this.sql.unsafe(`SELECT * FROM "${this.table}"`)) as Row[]
        return rows.map(PostgresStore.toRecord)
    }

    /**
     * Writes a record, replacing whatever is under that name.
     *
     * @param record The record to write.
     * @returns The record as stored.
     */
    async put(record: SecretRecord): Promise<SecretRecord> {
        const rows = (await this.sql.unsafe(
            `INSERT INTO "${this.table}"
                (owner, name, sealed, sealed_key, plain, is_sealed, is_final,
                 expires_at, history, rotation, rotated_at, metadata,
                 created_at, updated_at, revision)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
             ON CONFLICT (owner, name) DO UPDATE SET
                sealed = EXCLUDED.sealed,
                sealed_key = EXCLUDED.sealed_key,
                plain = EXCLUDED.plain,
                is_sealed = EXCLUDED.is_sealed,
                is_final = EXCLUDED.is_final,
                expires_at = EXCLUDED.expires_at,
                history = EXCLUDED.history,
                rotation = EXCLUDED.rotation,
                rotated_at = EXCLUDED.rotated_at,
                metadata = EXCLUDED.metadata,
                updated_at = EXCLUDED.updated_at,
                revision = EXCLUDED.revision
             RETURNING *`,
            PostgresStore.bind(record)
        )) as Row[]
        return PostgresStore.toRecord(rows[0]!)
    }

    /**
     * Writes a record only if the stored one is still at `expectedRevision`.
     *
     * @remarks
     * The whole point of this store. Postgres decides the comparison inside a
     * single statement, so two processes racing on one entry cannot both
     * believe they won: the `ON CONFLICT … WHERE` claims a name only if it is
     * free, and the `UPDATE … WHERE revision = $n` replaces a value only if
     * nobody moved it since it was read.
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
        const rows = (
            expectedRevision === null
                ? await this.sql.unsafe(
                      `INSERT INTO "${this.table}"
                        (owner, name, sealed, sealed_key, plain, is_sealed, is_final,
                         expires_at, history, rotation, rotated_at, metadata,
                         created_at, updated_at, revision)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                       ON CONFLICT (owner, name) DO NOTHING
                       RETURNING *`,
                      PostgresStore.bind(record)
                  )
                : await this.sql.unsafe(
                      `UPDATE "${this.table}" SET
                        sealed = $3, sealed_key = $4, plain = $5, is_sealed = $6,
                        is_final = $7, expires_at = $8, history = $9, rotation = $10,
                        rotated_at = $11, metadata = $12, updated_at = $13,
                        revision = $14
                       WHERE owner = $1 AND name = $2 AND revision = $15
                       RETURNING *`,
                      [
                          record.owner,
                          record.name,
                          record.sealed,
                          record.sealedKey,
                          record.plain,
                          record.isSealed,
                          record.isFinal,
                          record.expiresAt,
                          JSON.stringify(record.history),
                          record.rotation ? JSON.stringify(record.rotation) : null,
                          record.rotatedAt,
                          JSON.stringify(record.metadata),
                          record.updatedAt,
                          record.revision ?? 1,
                          expectedRevision,
                      ]
                  )
        ) as Row[]

        return rows[0] ? PostgresStore.toRecord(rows[0]) : null
    }

    /** A record as an insert's parameters, in column order. */
    private static bind(record: SecretRecord): unknown[] {
        return [
            record.owner,
            record.name,
            record.sealed,
            record.sealedKey,
            record.plain,
            record.isSealed,
            record.isFinal,
            record.expiresAt,
            JSON.stringify(record.history),
            record.rotation ? JSON.stringify(record.rotation) : null,
            record.rotatedAt,
            JSON.stringify(record.metadata),
            record.createdAt,
            record.updatedAt,
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
     * @returns True when a record was there and is now gone.
     */
    async remove(owner: string, name: string): Promise<boolean> {
        const rows = (await this.sql.unsafe(
            `DELETE FROM "${this.table}" WHERE owner = $1 AND name = $2 RETURNING owner`,
            [owner, name]
        )) as { owner: string }[]
        return rows.length > 0
    }

    /**
     * Closes the connection pool.
     *
     * Does nothing when the store was built from a `SQL` client you passed in:
     * that pool is yours, and something else is probably still using it.
     *
     * @returns Nothing, once the pool is closed.
     */
    async close(): Promise<void> {
        if (!this.borrowed) await this.sql.close()
    }
}
