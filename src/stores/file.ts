import { open as openFile, readFile, rename, unlink } from "node:fs/promises"
import { importKey, open, seal } from "../crypto"
import { VaultKeyError } from "../errors"
import { isKeyProvider, staticKey, type KeyProvider } from "../providers"
import type { SecretRecord, VaultStore } from "../types"

/** What a vault file starts with, so a wrong file is refused, not parsed. */
const MAGIC = "VAULT1"

/**
 * Keeps every record in one encrypted file.
 *
 * The other stores seal values and leave the rest in the open: SQLite has an
 * `owner` column and a `name` column, and anyone who can read the file learns
 * what you keep even if they cannot read it. Here the whole index — owners,
 * names, metadata, timestamps, everything — is inside a single AES-256-GCM
 * envelope. What leaks from the file at rest is its size.
 *
 * The trade is that it is loaded and written whole, so it suits hundreds of
 * secrets rather than millions, and one writer rather than several. Writes go
 * to a temporary file and are renamed into place, so a crash mid-write leaves
 * the previous file rather than half of a new one.
 *
 * @remarks
 * The store is encrypted under its own key, separate from the master key the
 * {@link Vault} seals values with, so the file is two layers deep: the index
 * under the store's key, each value under its own data key under the vault's.
 * Handing both layers the same key is allowed and sometimes what you want, but
 * then one key opens both.
 *
 * The key is resolved on the first read or write, not at construction, so a
 * provider that reaches for a file or a network service is asked once and only
 * when a record is actually wanted. A bad key surfaces from that first
 * operation as a {@link VaultKeyError}, not from `new`.
 *
 * Nothing here locks the file. Two stores writing the same path — two
 * processes, or two instances in one — each hold their own copy of the index
 * and write it whole, so the last save wins and the other's writes are gone.
 * Keep one writer per file.
 *
 * @example
 * A vault whose names are as hidden as its values. The store's key opens the
 * file; the vault's key seals what is inside it.
 * ```ts
 * import { Vault, fileKey } from "@mstone6969/vault"
 * import { FileStore } from "@mstone6969/vault/stores/file"
 *
 * const store = new FileStore("./secrets.vault", fileKey("/etc/vault-file.key"))
 * const vault = new Vault({ key: fileKey("/etc/vault-master.key"), store })
 *
 * await vault.put("alice", "db", "hunter2") // the file is written here
 * await vault.open("alice", "db") // "hunter2"
 * ```
 *
 * @see {@link VaultStore} for what a store owes the vault, and `MemoryStore`
 *   and `SqliteStore` for the two that keep their index in the open.
 */
export class FileStore implements VaultStore {
    private readonly path: string
    private readonly keySource: string | CryptoKey | KeyProvider
    /** Resolved on first read or write, not at construction. */
    private keyCache: Promise<CryptoKey> | null = null
    private records: Map<string, SecretRecord> | null = null

    /**
     * @param path Where to keep the file. Created on first write, so a path
     *   that does not exist yet is an empty store rather than an error.
     * @param key The key the *file* is encrypted with: base64, already
     *   imported, or a {@link KeyProvider} that finds one. Give it one of its
     *   own, or hand it the vault's — sharing means one key opens both layers.
     *
     * @example
     * ```ts
     * import { generateKey } from "@mstone6969/vault"
     * import { FileStore } from "@mstone6969/vault/stores/file"
     *
     * // Nothing is read or written until the first call.
     * const store = new FileStore("./secrets.vault", generateKey())
     * ```
     */
    constructor(path: string, key: string | CryptoKey | KeyProvider) {
        this.path = path
        this.keySource = key
    }

    private key(): Promise<CryptoKey> {
        this.keyCache ??= (async () => {
            const provider = isKeyProvider(this.keySource) ? this.keySource : staticKey(this.keySource)
            const resolved = await provider.key()
            return typeof resolved === "string" ? importKey(resolved) : resolved
        })()
        return this.keyCache
    }

    private static id(owner: string, name: string): string {
        return `${owner} ${name}`
    }

    /**
     * Reads and decrypts the file, once, keeping it in memory afterwards.
     *
     * @returns The whole index, keyed by owner and name. The same map every
     *   time until {@link FileStore.forget} drops it.
     * @throws {@link VaultKeyError} when the file does not begin with the magic line —
     *   something that is not one of ours is refused rather than parsed — or
     *   when the key does not open it.
     */
    private async load(): Promise<Map<string, SecretRecord>> {
        if (this.records) return this.records

        let contents: string
        try {
            contents = (await readFile(this.path, "utf8")).trim()
        } catch (error) {
            // No file yet is an empty store, not a failure. Anything else —
            // a permission problem, a directory in the way — is the caller's
            // to hear about.
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
            this.records = new Map()
            return this.records
        }

        const [magic, payload] = contents.split("\n")
        if (magic !== MAGIC || !payload) {
            throw new VaultKeyError(`${this.path} is not a vault file.`)
        }

        const opened = await open(await this.key(), payload)
        const parsed = JSON.parse(opened) as SecretRecord[]

        this.records = new Map(
            parsed.map((record) => [
                FileStore.id(record.owner, record.name),
                {
                    ...record,
                    expiresAt: record.expiresAt === null ? null : new Date(record.expiresAt),
                    history: record.history.map((entry) => ({
                        ...entry,
                        createdAt: new Date(entry.createdAt),
                    })),
                    rotatedAt: record.rotatedAt === null ? null : new Date(record.rotatedAt),
                    createdAt: new Date(record.createdAt),
                    updatedAt: new Date(record.updatedAt),
                },
            ])
        )
        return this.records
    }

    /**
     * Seals everything and swaps the file for the new one in a single move.
     *
     * Every record goes into one envelope, so the cost of a write is the size
     * of the whole store, not of the record that changed.
     *
     * @returns Nothing, once the new file is in place.
     * @throws {@link VaultKeyError} when the key cannot be resolved or imported.
     */
    private async save(): Promise<void> {
        const records = await this.load()
        const sealed = await seal(await this.key(), JSON.stringify([...records.values()]))

        // A name of its own per write, so two writers collide on the file they
        // are replacing rather than on each other's half-written temporary.
        const temporary = `${this.path}.${process.pid}.${Date.now()}.writing`
        const handle = await openFile(temporary, "w")
        try {
            await handle.writeFile(`${MAGIC}\n${sealed}\n`)
            // Flush before the rename: without this a power loss can leave the
            // new name pointing at a file the disk never finished writing, and
            // since the whole index is one envelope that loses every record,
            // not one.
            await handle.sync()
        } finally {
            await handle.close()
        }

        // Rename is atomic on the same filesystem: readers see one file or the
        // other, never a half-written one.
        await rename(temporary, this.path)
    }

    /**
     * One record, or null when there is none under that name.
     *
     * @param owner Whose record to look for.
     * @param name What it is called.
     * @returns The record, or null.
     * @throws {@link VaultKeyError} on the first call if the file is not a vault file,
     *   or the key does not open it.
     */
    async get(owner: string, name: string): Promise<SecretRecord | null> {
        return (await this.load()).get(FileStore.id(owner, name)) ?? null
    }

    /**
     * Every record one owner holds.
     *
     * The filtering happens in memory, over the whole index — there is no
     * per-owner slice of the file to read on its own.
     *
     * @param owner Whose records to return.
     * @returns That owner's records, in whatever order they were written.
     * @throws {@link VaultKeyError} on the first call if the file cannot be opened.
     */
    async list(owner: string): Promise<SecretRecord[]> {
        return [...(await this.load()).values()].filter((record) => record.owner === owner)
    }

    /**
     * Every record, whoever owns it.
     *
     * @returns All of them. Only `rekey` and `purgeExpired` need this.
     * @throws {@link VaultKeyError} on the first call if the file cannot be opened.
     *
     * @example
     * Check a file opens under the key you think it does, before trusting it.
     * ```ts
     * import { VaultKeyError } from "@mstone6969/vault"
     * import { FileStore } from "@mstone6969/vault/stores/file"
     *
     * try {
     *     await new FileStore("./secrets.vault", process.env.VAULT_FILE_KEY!).all()
     * } catch (error) {
     *     if (error instanceof VaultKeyError) console.error(error.message)
     * }
     * ```
     */
    async all(): Promise<SecretRecord[]> {
        return [...(await this.load()).values()]
    }

    /**
     * Writes a record, replacing any under the same owner and name.
     *
     * The whole file is re-sealed and rewritten, so writes cost the size of the
     * store rather than of the record.
     *
     * @param record The record to keep. Stored as given: finality, expiry and
     *   history are the vault's rules, not the store's.
     * @returns The same record, so callers can chain.
     * @throws {@link VaultKeyError} if the file cannot be opened, or the key cannot be
     *   resolved.
     */
    async put(record: SecretRecord): Promise<SecretRecord> {
        const records = await this.load()
        const id = FileStore.id(record.owner, record.name)
        const displaced = records.get(id)

        records.set(id, record)
        try {
            await this.save()
        } catch (error) {
            // Put the index back: a write that failed must not leave memory
            // claiming something the file does not hold.
            if (displaced) records.set(id, displaced)
            else records.delete(id)
            throw error
        }
        return record
    }

    /**
     * Deletes a record, returning false when there was nothing to delete.
     *
     * @param owner Whose record to delete.
     * @param name What it is called.
     * @returns Whether a record was there to delete. The file is only rewritten
     *   when one was.
     * @throws {@link VaultKeyError} if the file cannot be opened.
     */
    async remove(owner: string, name: string): Promise<boolean> {
        const records = await this.load()
        const id = FileStore.id(owner, name)
        const removed = records.get(id)
        if (!removed) return false

        records.delete(id)
        try {
            await this.save()
        } catch (error) {
            records.set(id, removed)
            throw error
        }
        return true
    }

    /**
     * Forgets what it read, so the next call goes back to the file.
     *
     * The point of a store that holds its whole index in memory is that reads
     * are free; the cost is that a file another process rewrote is invisible
     * until you say this. It also drops the decrypted index, which is the only
     * place the names live in the clear.
     *
     * @example
     * ```ts
     * import { FileStore } from "@mstone6969/vault/stores/file"
     *
     * const store = new FileStore("./secrets.vault", process.env.VAULT_FILE_KEY!)
     * await store.all() // reads and decrypts the file
     * store.forget()
     * await store.all() // reads it again
     * ```
     */
    forget(): void {
        this.records = null
    }

    /**
     * Deletes the file and everything in it.
     *
     * The in-memory index is emptied first, so a store that is used again
     * writes a fresh file rather than resurrecting what was there.
     *
     * @returns Nothing. A file that is already gone is the outcome wanted, not
     *   an error.
     */
    async destroy(): Promise<void> {
        this.records = new Map()
        await unlink(this.path).catch(() => {
            // Already gone is the outcome we wanted.
        })
    }
}
