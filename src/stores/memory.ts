import type { SecretRecord, VaultStore } from "../types"

/** A record of its own, so callers and the store cannot alter each other's. */
function copy(record: SecretRecord): SecretRecord {
    return structuredClone(record)
}

/**
 * Keeps sealed values in a Map. Handy for tests and short-lived processes.
 *
 * Nothing is written anywhere: when the process ends every record goes with it.
 * That is the point — a test gets a clean vault per run without a file to
 * create and delete, and a short-lived worker holding a few credentials in
 * memory leaves nothing behind on disk.
 *
 * @remarks
 * Like every {@link VaultStore}, this persists records exactly as given and
 * enforces nothing: finality, expiry and history are rules the {@link Vault}
 * applies before it calls {@link MemoryStore.put}.
 * @example
 * ```ts
 * import { generateKey, MemoryStore, Vault } from "@mstone6969/vault"
 *
 * const vault = new Vault({ key: generateKey(), store: new MemoryStore() })
 * await vault.put("alice", "db-password", "hunter2")
 * ```
 * @see {@link FileStore} for a store that survives the process.
 */
export class MemoryStore implements VaultStore {
    /** Records by `owner name`, the key {@link MemoryStore.key} builds. */
    private readonly records: Map<string, SecretRecord>

    /**
     * Makes an empty store.
     *
     * @remarks
     * Takes nothing: there is no file to name and no key to hand it, since
     * records never leave the process.
     * @example
     * ```ts
     * import { MemoryStore } from "@mstone6969/vault"
     *
     * const store = new MemoryStore()
     * ```
     */
    constructor() {
        this.records = new Map()
    }

    /**
     * The Map key for one entry: owners are separate namespaces, so the name
     * alone is not unique.
     *
     * @param owner Whose entry it is.
     * @param name What the entry is called.
     * @returns The two joined by a space.
     */
    private static key(owner: string, name: string): string {
        return `${owner} ${name}`
    }

    /**
     * One record, or null when there is none under that name.
     *
     * @param owner Whose entry to look for.
     * @param name What the entry is called.
     * @returns The stored record, or null if this owner has nothing by that
     *   name. The record itself is returned, not a copy, so callers must not
     *   mutate it.
     * @example
     * ```ts
     * import { MemoryStore } from "@mstone6969/vault"
     *
     * const store = new MemoryStore()
     * const record = await store.get("alice", "db-password") // null
     * ```
     */
    async get(owner: string, name: string): Promise<SecretRecord | null> {
        const record = this.records.get(MemoryStore.key(owner, name))
        return record ? copy(record) : null
    }

    /**
     * Every record one owner holds.
     *
     * @param owner Whose entries to return.
     * @returns That owner's records, in no particular order — the vault's
     *   `list` sorts them. Empty for an owner the store has never heard of.
     * @see {@link MemoryStore.all} when the caller needs every owner's records.
     */
    async list(owner: string): Promise<SecretRecord[]> {
        return [...this.records.values()]
            .filter((record) => record.owner === owner)
            .map(copy)
    }

    /**
     * Every record, whoever owns it.
     *
     * @returns All records the store holds, in no particular order.
     * @remarks
     * This is the only place anything reaches across owners, and it exists for
     * the vault-wide operations — `rekey`, `reseal` and `purgeExpired` — which
     * have to touch every entry. Ordinary reads go through
     * {@link MemoryStore.list}.
     */
    async all(): Promise<SecretRecord[]> {
        return [...this.records.values()].map(copy)
    }

    /**
     * Writes a record, replacing any under the same owner and name.
     *
     * @param record The record to keep, stored as given.
     * @returns The same record, so a caller can write and use the result in one
     *   step.
     * @remarks
     * An `isFinal` record is replaced here without complaint: refusing that is
     * the vault's job, and it checks before it calls this.
     */
    async put(record: SecretRecord): Promise<SecretRecord> {
        this.records.set(MemoryStore.key(record.owner, record.name), copy(record))
        return copy(record)
    }

    /**
     * Deletes a record, returning false when there was nothing to delete.
     *
     * @param owner Whose entry to delete.
     * @param name What the entry is called.
     * @returns True if a record was removed, false if there was none — so a
     *   caller can tell a delete from a no-op.
     */
    async remove(owner: string, name: string): Promise<boolean> {
        return this.records.delete(MemoryStore.key(owner, name))
    }
}
