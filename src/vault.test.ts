import { afterEach, beforeEach, expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { generateKey, importKey, open, seal } from "./crypto"
import { VaultError, VaultKeyError } from "./errors"
import {
    envKey,
    fileKey,
    isKeyProvider,
    isKeyWrapper,
    passphraseKey,
    staticKey,
    type KeyWrapper,
} from "./providers"
import { FileStore } from "./stores/file"
import { MemoryStore } from "./stores/memory"
import { Database } from "bun:sqlite"
import { SqliteAuditLog, SqliteStore } from "./stores/sqlite"
import type { AuditLog, SecretRecord, VaultEvent, VaultStore } from "./types"
import { chainHash, MemoryAuditLog, verifyChain } from "./audit"
import { randomValue, Vault } from "./vault"

const KEY = generateKey()
let vault: Vault
let store: MemoryStore
let dir: string

beforeEach(async () => {
    store = new MemoryStore()
    vault = new Vault({ key: KEY, store })
    dir = await mkdtemp(path.join(tmpdir(), "vault-"))
})

afterEach(async () => {
    await rm(dir, { recursive: true, force: true })
})

// --- crypto ---------------------------------------------------------------

test("generateKey produces a 32-byte key", async () => {
    expect(Buffer.from(generateKey(), "base64")).toHaveLength(32)
    await expect(importKey(generateKey())).resolves.toBeDefined()
})

test("a key of the wrong size is refused", async () => {
    await expect(importKey(Buffer.alloc(16).toString("base64"))).rejects.toThrow(VaultKeyError)
})

test("the same value seals differently every time", async () => {
    const key = await importKey(KEY)
    const first = await seal(key, "hunter2")
    const second = await seal(key, "hunter2")

    expect(first).not.toBe(second)
    expect(await open(key, first)).toBe("hunter2")
    expect(await open(key, second)).toBe("hunter2")
})

test("an altered value will not open", async () => {
    const key = await importKey(KEY)
    const [iv, payload] = (await seal(key, "hunter2")).split(":") as [string, string]
    const tampered = Buffer.from(payload, "base64")
    tampered[0] = (tampered[0] ?? 0) ^ 0xff

    await expect(open(key, `${iv}:${tampered.toString("base64")}`)).rejects.toThrow(
        VaultKeyError
    )
})

test("another key cannot open a value", async () => {
    const sealed = await seal(await importKey(KEY), "hunter2")
    await expect(open(await importKey(generateKey()), sealed)).rejects.toThrow(VaultKeyError)
})

test("a sealed value that is not iv:payload is rejected before decrypting", async () => {
    const key = await importKey(KEY)
    for (const malformed of ["no-colon-here", ":", "iv-only:", ""]) {
        await expect(open(key, malformed)).rejects.toThrow(/iv:payload/)
    }
})

// --- storing and opening --------------------------------------------------

test("listing gives names and metadata, never values", async () => {
    await vault.put("alice", "stripe_key", "sk_live_secret", { metadata: { kind: "api" } })
    const listed = await vault.list("alice")

    expect(listed).toHaveLength(1)
    expect(listed[0]?.name).toBe("stripe_key")
    expect(listed[0]?.metadata).toEqual({ kind: "api" })
    expect(listed[0]?.versions).toBe(0)
    expect(JSON.stringify(listed)).not.toContain("sk_live_secret")
    expect(JSON.stringify(listed)).not.toContain("sealed")
})

test("a value can be read back only through open()", async () => {
    await vault.put("alice", "token", "shhh")
    expect(await vault.open("alice", "token")).toBe("shhh")
})

test("names are checked, and a value is required", async () => {
    await expect(vault.put("alice", "no spaces", "x")).rejects.toThrow(VaultError)
    await expect(vault.put("alice", "", "x")).rejects.toThrow(VaultError)
    await expect(vault.put("alice", "a".repeat(65), "x")).rejects.toThrow(VaultError)
    await expect(vault.put("alice", "ok.name-1_2", "")).rejects.toThrow(VaultError)
    await expect(vault.put("alice", "ok.name-1_2", "fine")).resolves.toBeDefined()
})

test("owners cannot see each other's secrets", async () => {
    await vault.put("alice", "token", "alice value")
    await vault.put("bob", "token", "bob value")

    expect(await vault.open("alice", "token")).toBe("alice value")
    expect(await vault.open("bob", "token")).toBe("bob value")
    expect(await vault.list("bob")).toHaveLength(1)

    expect(await vault.remove("bob", "token")).toBe(true)
    expect(await vault.has("alice", "token")).toBe(true)
    expect(await vault.has("bob", "token")).toBe(false)
})

test("removing something that isn't there says so", async () => {
    expect(await vault.remove("alice", "absent")).toBe(false)
})

test("opening a missing secret reports 404, not an empty string", async () => {
    const failure = vault.open("alice", "absent")
    await expect(failure).rejects.toThrow(VaultError)
    await expect(failure).rejects.toThrow('No secret named "absent"')
})

test("replacing a value keeps the date it was first stored", async () => {
    const first = await vault.put("alice", "token", "one")
    await Bun.sleep(2)
    const second = await vault.put("alice", "token", "two")

    expect(second.createdAt).toEqual(first.createdAt)
    expect(second.updatedAt.getTime()).toBeGreaterThan(first.updatedAt.getTime())
    expect(await vault.open("alice", "token")).toBe("two")
})

// --- envelope encryption --------------------------------------------------

test("each value has its own key, and only that key meets the master", async () => {
    await vault.put("alice", "one", "first")
    await vault.put("alice", "two", "second")

    const [a, b] = await store.all()
    expect(a?.sealedKey).toBeTruthy()
    expect(a?.sealedKey).not.toBe(b?.sealedKey)

    // The master opens the data key — but only as the entry it belongs to —
    // and the data key opens the value.
    const master = await importKey(KEY)
    const material = await open(master, a!.sealedKey!, `${a!.owner}\u0000${a!.name}`)
    expect(await open(await importKey(material), a!.sealed)).toBe("first")

    // The master alone cannot open the value.
    await expect(open(master, a!.sealed)).rejects.toThrow(VaultKeyError)
})

test("a value sealed under the master directly still opens", async () => {
    // The 0.2.0 shape: no data key at all.
    await store.put({
        owner: "alice",
        name: "legacy",
        sealed: await seal(await importKey(KEY), "from before"),
        sealedKey: null,
        plain: null,
        isSealed: true,
        isFinal: false,
        expiresAt: null,
        history: [],
        rotation: null,
        rotatedAt: null,
        metadata: {},
        createdAt: new Date(),
        updatedAt: new Date(),
    })

    expect(await vault.open("alice", "legacy")).toBe("from before")
})

// --- entries in the open --------------------------------------------------

test("an entry stored in the open can be read, and says so", async () => {
    const summary = await vault.put("alice", "region", "eu-west-1", { sealed: false })
    expect(summary.isSealed).toBe(false)
    expect(summary.value).toBe("eu-west-1")

    expect(await vault.read("alice", "region")).toBe("eu-west-1")
    expect(await vault.open("alice", "region")).toBe("eu-west-1")

    const [record] = await store.all()
    expect(record?.sealed).toBe("")
    expect(record?.sealedKey).toBeNull()
    expect(record?.plain).toBe("eu-west-1")
})

test("a sealed entry refuses to be read back", async () => {
    await vault.put("alice", "token", "shhh")
    await expect(vault.read("alice", "token")).rejects.toThrow(/cannot be read back/)
})

// --- final ----------------------------------------------------------------

test("a final entry cannot be replaced, only removed", async () => {
    await vault.put("alice", "root_ca", "once and for all", { final: true })

    await expect(vault.put("alice", "root_ca", "changed my mind")).rejects.toThrow(/final/)
    expect(await vault.open("alice", "root_ca")).toBe("once and for all")

    expect(await vault.remove("alice", "root_ca")).toBe(true)
    await expect(vault.put("alice", "root_ca", "fresh start")).resolves.toBeDefined()
})

// --- history --------------------------------------------------------------

test("rotating keeps what it replaced, and the old values still open", async () => {
    await vault.put("alice", "deploy", "v1")
    await vault.rotate("alice", "deploy", "v2")
    await vault.rotate("alice", "deploy", "v3")

    expect(await vault.open("alice", "deploy")).toBe("v3")
    expect(await vault.versions("alice", "deploy")).toEqual(["v2", "v1"])
})

test("history is trimmed to the limit", async () => {
    const short = new Vault({ key: KEY, store, historyLimit: 2 })
    await short.put("alice", "deploy", "v1")
    for (const value of ["v2", "v3", "v4", "v5"]) {
        await short.rotate("alice", "deploy", value)
    }

    expect(await short.versions("alice", "deploy")).toEqual(["v4", "v3"])
})

test("a plain put does not add to history", async () => {
    await vault.put("alice", "deploy", "v1")
    await vault.put("alice", "deploy", "v2")
    expect(await vault.versions("alice", "deploy")).toEqual([])
})

// --- expiry ---------------------------------------------------------------

test("an expired entry stops resolving", async () => {
    await vault.put("alice", "temporary", "gone soon", {
        expiresAt: new Date(Date.now() - 1),
    })

    await expect(vault.open("alice", "temporary")).rejects.toThrow(/expired/)
    await expect(vault.resolve("alice", { V: "@vault:temporary" })).rejects.toThrow(/expired/)

    // It is still there, and still listed, until something clears it out.
    expect(await vault.has("alice", "temporary")).toBe(true)
    expect(await vault.list("alice")).toHaveLength(1)
})

test("an entry with time left behaves normally", async () => {
    await vault.put("alice", "later", "still good", {
        expiresAt: new Date(Date.now() + 60_000),
    })
    expect(await vault.open("alice", "later")).toBe("still good")
})

test("purgeExpired clears out what is past it, and nothing else", async () => {
    await vault.put("alice", "gone", "x", { expiresAt: new Date(Date.now() - 1) })
    await vault.put("alice", "kept", "y", { expiresAt: new Date(Date.now() + 60_000) })
    await vault.put("bob", "forever", "z")

    expect(await vault.purgeExpired()).toBe(1)
    expect(await vault.has("alice", "gone")).toBe(false)
    expect(await vault.has("alice", "kept")).toBe(true)
    expect(await vault.has("bob", "forever")).toBe(true)
})

// --- references -----------------------------------------------------------

test("only @vault: values are substituted", async () => {
    await vault.put("alice", "token", "secret")

    expect(
        await vault.resolve("alice", {
            PLAIN: "kept",
            FROM_VAULT: "@vault:token",
            SPACED: "@vault: token ",
        })
    ).toEqual({ PLAIN: "kept", FROM_VAULT: "secret", SPACED: "secret" })
})

test("values with no references are returned untouched", async () => {
    const values = { A: "1", B: "2" }
    expect(await vault.resolve("alice", values)).toBe(values)
})

test("a reference to a missing secret throws rather than blanking it", async () => {
    await expect(vault.resolve("alice", { V: "@vault:absent" })).rejects.toThrow(VaultError)
})

test("the reference prefix can be changed", async () => {
    const custom = new Vault({ key: KEY, store, prefix: "secret://" })
    await custom.put("alice", "token", "value")

    expect(await custom.resolve("alice", { V: "secret://token" })).toEqual({ V: "value" })
    expect(await custom.resolve("alice", { V: "@vault:token" })).toEqual({ V: "@vault:token" })
})

// --- reseal ---------------------------------------------------------------

test("reseal changes the ciphertext and leaves the value alone", async () => {
    await vault.put("alice", "one", "first")
    await vault.put("bob", "two", "second")
    const before = (await store.all()).map((record) => record.sealed)

    expect(await vault.reseal()).toEqual({ rekeyed: 2, failed: [] })

    const after = (await store.all()).map((record) => record.sealed)
    expect(after.some((sealed, index) => sealed === before[index])).toBe(false)
    expect(await vault.open("alice", "one")).toBe("first")
    expect(await vault.open("bob", "two")).toBe("second")
})

test("reseal can be limited to one owner, and skips entries in the open", async () => {
    await vault.put("alice", "sealed", "first")
    await vault.put("alice", "clear", "second", { sealed: false })
    await vault.put("bob", "other", "third")

    expect(await vault.reseal("alice")).toEqual({ rekeyed: 1, failed: [] })
})

// --- rekey ----------------------------------------------------------------

test("rekey moves the data keys, not the values", async () => {
    await vault.put("alice", "one", "first", { metadata: { kind: "a" } })
    await vault.put("bob", "two", "second")

    const before = await store.all()
    const next = generateKey()
    expect(await vault.rekey(next)).toEqual({ rekeyed: 2, failed: [] })

    const after = await store.all()
    // The values are untouched; only the wrapped keys changed.
    expect(after.map((record) => record.sealed)).toEqual(before.map((record) => record.sealed))
    expect(after.map((record) => record.sealedKey)).not.toEqual(
        before.map((record) => record.sealedKey)
    )

    expect(await new Vault({ key: next, store }).open("alice", "one")).toBe("first")
    expect((await vault.list("alice"))[0]?.metadata).toEqual({ kind: "a" })
})

test("rekey carries kept versions across with the live value", async () => {
    await vault.put("alice", "deploy", "v1")
    await vault.rotate("alice", "deploy", "v2")

    const next = generateKey()
    await vault.rekey(next)

    const reopened = new Vault({ key: next, store })
    expect(await reopened.open("alice", "deploy")).toBe("v2")
    expect(await reopened.versions("alice", "deploy")).toEqual(["v1"])
})

test("rekey gives an envelope to a value that never had one", async () => {
    await store.put({
        owner: "alice",
        name: "legacy",
        sealed: await seal(await importKey(KEY), "from before"),
        sealedKey: null,
        plain: null,
        isSealed: true,
        isFinal: false,
        expiresAt: null,
        history: [],
        rotation: null,
        rotatedAt: null,
        metadata: {},
        createdAt: new Date(),
        updatedAt: new Date(),
    })

    const next = generateKey()
    expect(await vault.rekey(next)).toEqual({ rekeyed: 1, failed: [] })

    const [record] = await store.all()
    expect(record?.sealedKey).toBeTruthy()
    expect(await new Vault({ key: next, store }).open("alice", "legacy")).toBe("from before")
})

test("rekey skips entries stored in the open", async () => {
    await vault.put("alice", "clear", "readable", { sealed: false })
    expect(await vault.rekey(generateKey())).toEqual({ rekeyed: 0, failed: [] })
    expect(await vault.read("alice", "clear")).toBe("readable")
})

test("a value that will not open is named, not destroyed", async () => {
    await vault.put("alice", "good", "readable")

    const stranger = await importKey(generateKey())
    await store.put({
        owner: "alice",
        name: "stranger",
        sealed: await seal(stranger, "unreachable"),
        sealedKey: await seal(stranger, generateKey()),
        plain: null,
        isSealed: true,
        isFinal: false,
        expiresAt: null,
        history: [],
        rotation: null,
        rotatedAt: null,
        metadata: {},
        createdAt: new Date(),
        updatedAt: new Date(),
    })
    const before = (await store.get("alice", "stranger"))!.sealedKey

    const report = await vault.rekey(generateKey())
    expect(report.rekeyed).toBe(1)
    expect(report.failed).toEqual(["alice/stranger"])
    expect((await store.get("alice", "stranger"))!.sealedKey).toBe(before)
})

test("a vault opens values sealed under a previous key", async () => {
    const old = generateKey()
    await new Vault({ key: old, store }).put("alice", "legacy", "from before")

    const next = generateKey()
    const moved = new Vault({ key: next, store, previousKeys: [old] })

    expect(await moved.open("alice", "legacy")).toBe("from before")
    await moved.put("alice", "fresh", "from now")
    expect(await new Vault({ key: next, store }).open("alice", "fresh")).toBe("from now")
})

test("a half-finished rekey still opens from either side", async () => {
    await vault.put("alice", "one", "first")
    const next = generateKey()
    await vault.rekey(next)
    await vault.put("alice", "two", "second")

    expect(await vault.open("alice", "one")).toBe("first")
    expect(await vault.open("alice", "two")).toBe("second")
})

test("rekeying an empty vault still switches the key", async () => {
    const next = generateKey()
    expect(await vault.rekey(next)).toEqual({ rekeyed: 0, failed: [] })

    await vault.put("alice", "after", "sealed under the new key")
    expect(await new Vault({ key: next, store }).open("alice", "after")).toBe(
        "sealed under the new key"
    )
})

// --- key providers --------------------------------------------------------

test("a key can come from the environment", async () => {
    process.env.TEST_VAULT_KEY = KEY
    const fromEnv = new Vault({ key: envKey("TEST_VAULT_KEY"), store })

    await fromEnv.put("alice", "token", "value")
    expect(await fromEnv.open("alice", "token")).toBe("value")

    delete process.env.TEST_VAULT_KEY
    await expect(
        new Vault({ key: envKey("TEST_VAULT_KEY"), store }).put("alice", "other", "value")
    ).rejects.toThrow(/is not set/)
})

test("a key can come from a file, trailing newline and all", async () => {
    const keyPath = path.join(dir, "vault.key")
    await Bun.write(keyPath, `${KEY}\n`)

    const fromFile = new Vault({ key: fileKey(keyPath), store })
    await fromFile.put("alice", "token", "value")
    expect(await fromFile.open("alice", "token")).toBe("value")
})

test("a missing or empty key file says which", async () => {
    await expect(
        new Vault({ key: fileKey(path.join(dir, "absent.key")), store }).put("alice", "x", "y")
    ).rejects.toThrow(/No key file/)

    const empty = path.join(dir, "empty.key")
    await Bun.write(empty, "   \n")
    await expect(
        new Vault({ key: fileKey(empty), store }).put("alice", "x", "y")
    ).rejects.toThrow(/is empty/)
})

test("providers are recognised, and plain keys are not mistaken for them", () => {
    expect(isKeyProvider(staticKey(KEY))).toBe(true)
    expect(isKeyProvider(envKey("X"))).toBe(true)
    expect(isKeyProvider(KEY)).toBe(false)
    expect(isKeyProvider(null)).toBe(false)
    expect(isKeyProvider(undefined)).toBe(false)
})

test("rekey takes a provider as readily as a key", async () => {
    await vault.put("alice", "one", "first")
    const next = generateKey()

    expect((await vault.rekey(staticKey(next))).rekeyed).toBe(1)
    expect(await new Vault({ key: next, store }).open("alice", "one")).toBe("first")
})

test("an imported key works wherever a base64 one does", async () => {
    const imported = await importKey(KEY)
    const direct = new Vault({ key: imported, store, previousKeys: [imported] })

    await direct.put("alice", "token", "value")
    expect(await direct.open("alice", "token")).toBe("value")
    expect((await direct.rekey(await importKey(generateKey()))).rekeyed).toBe(1)
})

// --- the audit trail ------------------------------------------------------

test("everything the vault does is reported", async () => {
    const seen: VaultEvent[] = []
    const watched = new Vault({ key: KEY, store, onAccess: (event) => seen.push(event) })

    await watched.put("alice", "token", "one")
    await watched.open("alice", "token")
    await watched.rotate("alice", "token", "two")
    await watched.put("alice", "clear", "readable", { sealed: false })
    await watched.read("alice", "clear")
    await watched.remove("alice", "token")
    await watched.rekey(generateKey())

    expect(seen.map((event) => event.action)).toEqual([
        "put",
        "open",
        "rotate",
        "put",
        "put",
        "read",
        "remove",
        "rekey",
    ])
    expect(seen[0]?.owner).toBe("alice")
    expect(seen[0]?.name).toBe("token")
    expect(seen[0]?.at).toBeInstanceOf(Date)
    expect(seen.at(-1)?.detail).toContain("re-sealed")
})

test("refusals are reported too", async () => {
    const seen: VaultEvent[] = []
    const watched = new Vault({ key: KEY, store, onAccess: (event) => seen.push(event) })

    await watched.put("alice", "final", "x", { final: true })
    await watched.put("alice", "sealed", "y")
    await watched.put("alice", "gone", "z", { expiresAt: new Date(Date.now() - 1) })

    await expect(watched.put("alice", "final", "again")).rejects.toThrow()
    await expect(watched.read("alice", "sealed")).rejects.toThrow()
    await expect(watched.open("alice", "gone")).rejects.toThrow()

    expect(
        seen.filter((event) => event.action === "denied").map((event) => event.detail)
    ).toEqual(["final", "sealed", "expired"])
})

test("an audit trail that throws does not take the vault with it", async () => {
    const noisy = new Vault({
        key: KEY,
        store,
        onAccess: () => {
            throw new Error("the log is on fire")
        },
    })

    await expect(noisy.put("alice", "token", "value")).resolves.toBeDefined()
    expect(await noisy.open("alice", "token")).toBe("value")
})

// --- stores ---------------------------------------------------------------

function storesUnder(where: string): [string, () => VaultStore][] {
    return [
        ["MemoryStore", () => new MemoryStore()],
        ["SqliteStore", () => new SqliteStore(":memory:")],
        ["FileStore", () => new FileStore(path.join(where, `${Math.random()}.vault`), KEY)],
    ]
}

test("every store round-trips an entry the same way", async () => {
    for (const [name, make] of storesUnder(dir)) {
        const backed = new Vault({ key: KEY, store: make() })

        await backed.put("alice", "token", "one", { metadata: { kind: "a" } })
        expect(await backed.open("alice", "token"), name).toBe("one")

        await backed.rotate("alice", "token", "two")
        expect(await backed.open("alice", "token"), name).toBe("two")
        expect(await backed.versions("alice", "token"), name).toEqual(["one"])

        const [listed] = await backed.list("alice")
        expect(listed?.metadata, name).toEqual({ kind: "a" })
        expect(listed?.versions, name).toBe(1)

        expect(await backed.remove("alice", "token"), name).toBe(true)
        expect(await backed.has("alice", "token"), name).toBe(false)
        expect(await backed.list("alice"), name).toHaveLength(0)
        expect(await backed.remove("alice", "token"), name).toBe(false)
    }
})

test("MemoryStore answers for owners and names it has never heard of", async () => {
    const empty = new MemoryStore()
    expect(await empty.get("nobody", "nothing")).toBeNull()
    expect(await empty.list("nobody")).toEqual([])
    expect(await empty.all()).toEqual([])
    expect(await empty.remove("nobody", "nothing")).toBe(false)
})

test("SqliteStore can share a Database that is already open", async () => {
    const { Database } = await import("bun:sqlite")
    const db = new Database(":memory:")
    const backed = new Vault({ key: KEY, store: new SqliteStore(db, "shared_secrets") })

    await backed.put("alice", "token", "value")
    expect(await backed.open("alice", "token")).toBe("value")

    const tables = db
        .query<{ name: string }, []>("SELECT name FROM sqlite_master WHERE type = 'table'")
        .all()
    expect(tables.map((table) => table.name)).toContain("shared_secrets")
    db.close()
})

test("SqliteStore defaults to a database of its own", async () => {
    const backed = new SqliteStore()
    const withStore = new Vault({ key: KEY, store: backed })

    await withStore.put("alice", "token", "value")
    expect(await withStore.open("alice", "token")).toBe("value")
    backed.close()
})

test("SqliteStore keeps everything across connections to the same file", async () => {
    const file = path.join(dir, "vault.sqlite")

    const first = new SqliteStore(file)
    const writing = new Vault({ key: KEY, store: first })
    await writing.put("alice", "token", "persisted", { metadata: { kind: "a" } })
    await writing.rotate("alice", "token", "rotated")
    await writing.put("alice", "clear", "open value", { sealed: false })
    await writing.put("alice", "locked", "x", {
        final: true,
        expiresAt: new Date(Date.now() + 60_000),
    })
    first.close()

    const second = new SqliteStore(file)
    const reading = new Vault({ key: KEY, store: second })
    expect(await reading.open("alice", "token")).toBe("rotated")
    expect(await reading.versions("alice", "token")).toEqual(["persisted"])
    expect(await reading.read("alice", "clear")).toBe("open value")
    await expect(reading.put("alice", "locked", "y")).rejects.toThrow(/final/)

    const locked = (await reading.list("alice")).find((entry) => entry.name === "locked")
    expect(locked?.expiresAt).toBeInstanceOf(Date)
    second.close()
})

test("SqliteStore adds the later columns to a table written by 0.1.0", async () => {
    const { Database } = await import("bun:sqlite")
    const db = new Database(":memory:")
    db.run(`CREATE TABLE vault_secrets (
        owner TEXT NOT NULL,
        name TEXT NOT NULL,
        sealed TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (owner, name)
    )`)
    db.run("INSERT INTO vault_secrets VALUES ('alice', 'old', 'iv:payload', 1, 1)")

    const backed = new SqliteStore(db)
    const columns = db.query<{ name: string }, []>("PRAGMA table_info(vault_secrets)").all()
    expect(columns.map((column) => column.name)).toContain("sealed_key")
    expect(columns.map((column) => column.name)).toContain("history")

    // The row that predates them reads back with sensible defaults.
    const old = await backed.get("alice", "old")
    expect(old?.metadata).toEqual({})
    expect(old?.history).toEqual([])
    expect(old?.isSealed).toBe(true)
    expect(old?.isFinal).toBe(false)
    expect(old?.expiresAt).toBeNull()
    db.close()
})

// --- the encrypted file store --------------------------------------------

test("FileStore hides the names as well as the values", async () => {
    const file = path.join(dir, "secrets.vault")
    const backed = new Vault({ key: KEY, store: new FileStore(file, KEY) })

    // Every marker is long on purpose. The file is base64, so a short string
    // like "api" turns up in it by chance about once in 1,200 runs — which is
    // a test that fails in CI for no reason roughly never enough to be
    // believed when it does.
    await backed.put("alice-the-owner", "stripe-key-name", "sk_live_secret_value", {
        metadata: { kind: "api-credential-kind" },
    })

    // Nothing about the entry is legible — not even that it exists.
    const contents = await Bun.file(file).text()
    expect(contents.startsWith("VAULT1\n")).toBe(true)
    expect(contents).not.toContain("stripe-key-name")
    expect(contents).not.toContain("sk_live_secret_value")
    expect(contents).not.toContain("alice-the-owner")
    expect(contents).not.toContain("api-credential-kind")
})

test("FileStore reads back what it wrote, from a new store", async () => {
    const file = path.join(dir, "secrets.vault")

    const writing = new Vault({ key: KEY, store: new FileStore(file, KEY) })
    await writing.put("alice", "token", "one", { metadata: { kind: "a" } })
    await writing.rotate("alice", "token", "two")
    await writing.put("alice", "later", "x", { expiresAt: new Date(Date.now() + 60_000) })

    const reading = new Vault({ key: KEY, store: new FileStore(file, KEY) })
    expect(await reading.open("alice", "token")).toBe("two")
    expect(await reading.versions("alice", "token")).toEqual(["one"])

    const listed = await reading.list("alice")
    expect(listed.find((entry) => entry.name === "later")?.expiresAt).toBeInstanceOf(Date)
    expect(listed.find((entry) => entry.name === "token")?.metadata).toEqual({ kind: "a" })
})

test("FileStore refuses a file that is not one of its own", async () => {
    const file = path.join(dir, "not-a-vault")
    await Bun.write(file, "just some text\n")

    await expect(new FileStore(file, KEY).all()).rejects.toThrow(/not a vault file/)
})

test("FileStore refuses to open under the wrong key", async () => {
    const file = path.join(dir, "secrets.vault")
    await new Vault({ key: KEY, store: new FileStore(file, KEY) }).put("alice", "x", "y")

    await expect(new FileStore(file, generateKey()).all()).rejects.toThrow(VaultKeyError)
})

test("FileStore takes a key provider too", async () => {
    const file = path.join(dir, "secrets.vault")
    const keyPath = path.join(dir, "file.key")
    await Bun.write(keyPath, KEY)

    const backed = new Vault({ key: KEY, store: new FileStore(file, fileKey(keyPath)) })
    await backed.put("alice", "token", "value")
    expect(await backed.open("alice", "token")).toBe("value")
})

test("FileStore forgets and re-reads, and can delete itself", async () => {
    const file = path.join(dir, "secrets.vault")
    const backed = new FileStore(file, KEY)
    const withStore = new Vault({ key: KEY, store: backed })

    await withStore.put("alice", "token", "value")
    backed.forget()
    expect(await withStore.open("alice", "token")).toBe("value")

    expect(await backed.remove("alice", "absent")).toBe(false)
    await backed.destroy()
    expect(await Bun.file(file).exists()).toBe(false)
    expect(await backed.all()).toEqual([])

    // Destroying one that was never written is fine too.
    await new FileStore(path.join(dir, "never.vault"), KEY).destroy()
})

test("FileStore starts empty when there is no file yet", async () => {
    const backed = new FileStore(path.join(dir, "fresh.vault"), KEY)
    expect(await backed.all()).toEqual([])
    expect(await backed.get("alice", "token")).toBeNull()
    expect(await backed.list("alice")).toEqual([])
})

test("a rekey works through the file store", async () => {
    const file = path.join(dir, "secrets.vault")
    const withStore = new Vault({ key: KEY, store: new FileStore(file, KEY) })
    await withStore.put("alice", "token", "value")

    const next = generateKey()
    expect(await withStore.rekey(next)).toEqual({ rekeyed: 1, failed: [] })

    // The file's own key did not change; the master key inside it did.
    const reopened = new Vault({ key: next, store: new FileStore(file, KEY) })
    expect(await reopened.open("alice", "token")).toBe("value")
})

test("a record written straight to a store keeps its shape", async () => {
    const record: SecretRecord = {
        owner: "alice",
        name: "direct",
        sealed: "iv:payload",
        sealedKey: "iv:key",
        plain: null,
        isSealed: true,
        isFinal: true,
        expiresAt: new Date(Date.now() + 1000),
        history: [{ sealed: "iv:old", sealedKey: "iv:oldkey", createdAt: new Date() }],
        rotation: { kind: "random", length: 16 },
        rotatedAt: new Date(),
        metadata: { kind: "a" },
        createdAt: new Date(),
        updatedAt: new Date(),
    }

    for (const [name, make] of storesUnder(dir)) {
        const backed = make()
        await backed.put(record)
        const read = await backed.get("alice", "direct")

        expect(read?.isFinal, name).toBe(true)
        expect(read?.history, name).toHaveLength(1)
        expect(read?.history[0]?.createdAt, name).toBeInstanceOf(Date)
        expect(read?.expiresAt, name).toBeInstanceOf(Date)
        expect(read?.metadata, name).toEqual({ kind: "a" })
    }
})

test("vault-wide operations reach across a SQLite store", async () => {
    const backed = new SqliteStore(":memory:")
    const withStore = new Vault({ key: KEY, store: backed })

    await withStore.put("alice", "one", "first")
    await withStore.put("bob", "two", "second")
    await withStore.put("alice", "gone", "x", { expiresAt: new Date(Date.now() - 1) })

    // reseal, rekey and purgeExpired all enumerate the whole store.
    expect(await withStore.reseal()).toEqual({ rekeyed: 3, failed: [] })

    const next = generateKey()
    expect(await withStore.rekey(next)).toEqual({ rekeyed: 3, failed: [] })
    expect(await new Vault({ key: next, store: backed }).open("bob", "two")).toBe("second")

    expect(await withStore.purgeExpired()).toBe(1)
    expect(await withStore.has("alice", "gone")).toBe(false)
    expect(await withStore.list("alice")).toHaveLength(1)
    backed.close()
})

// --- rotation policies ----------------------------------------------------

test("an entry can carry how to make its next value, but never the value", async () => {
    await vault.put("alice", "db", "first-password", {
        metadata: { kind: "usernamePassword", username: "ada" },
        rotation: { kind: "random", length: 24 },
    })

    // The recipe is stored beside the entry, in the open.
    const [listed] = await vault.list("alice")
    expect(listed?.rotation).toEqual({ kind: "random", length: 24 })
    expect(listed?.metadata).toEqual({ kind: "usernamePassword", username: "ada" })
    expect(JSON.stringify(listed)).not.toContain("first-password")
})

test("rotating without a value makes one from the policy", async () => {
    await vault.put("alice", "db", "first-password", {
        metadata: { kind: "login" },
        rotation: { kind: "random", length: 24 },
    })

    const rotated = await vault.rotate("alice", "db")
    const next = await vault.open("alice", "db")

    expect(next).toHaveLength(24)
    expect(next).not.toBe("first-password")
    // What it is stays; what it was is kept; when it happened is recorded.
    expect(rotated.metadata).toEqual({ kind: "login" })
    expect(rotated.rotation).toEqual({ kind: "random", length: 24 })
    expect(rotated.rotatedAt).toBeInstanceOf(Date)
    expect(await vault.versions("alice", "db")).toEqual(["first-password"])
})

test("rotating with a value still works, policy or no policy", async () => {
    await vault.put("alice", "db", "one", { rotation: { kind: "random" } })
    await vault.rotate("alice", "db", "two")
    expect(await vault.open("alice", "db")).toBe("two")
})

test("an entry with no policy says so rather than inventing one", async () => {
    await vault.put("alice", "db", "one")
    await expect(vault.rotate("alice", "db")).rejects.toThrow(/no rotation policy/)
})

test("a generator mints the value, and is told only what is not secret", async () => {
    const asked: unknown[] = []
    const withGenerator = new Vault({
        key: KEY,
        store,
        generators: {
            provider: (context) => {
                asked.push(context)
                return `minted-for-${context.arguments.account}`
            },
        },
    })

    await withGenerator.put("alice", "api", "old-key", {
        rotation: {
            kind: "generator",
            generator: "provider",
            arguments: { account: "acct_123" },
        },
    })
    await withGenerator.rotate("alice", "api")

    expect(await withGenerator.open("alice", "api")).toBe("minted-for-acct_123")
    // The generator saw the entry and its arguments — not the value it replaced.
    expect(asked).toEqual([{ owner: "alice", name: "api", arguments: { account: "acct_123" } }])
    expect(JSON.stringify(asked)).not.toContain("old-key")
})

test("a generator can be asynchronous", async () => {
    const withGenerator = new Vault({
        key: KEY,
        store,
        generators: {
            slow: async () => {
                await Bun.sleep(1)
                return "from-far-away"
            },
        },
    })

    await withGenerator.put("alice", "api", "old", {
        rotation: { kind: "generator", generator: "slow" },
    })
    await withGenerator.rotate("alice", "api")
    expect(await withGenerator.open("alice", "api")).toBe("from-far-away")
})

test("a policy naming a generator this vault has not got says which", async () => {
    await vault.put("alice", "api", "old", {
        rotation: { kind: "generator", generator: "absent" },
    })
    await expect(vault.rotate("alice", "api")).rejects.toThrow(/"absent" generator/)

    await vault.put("alice", "unnamed", "old", { rotation: { kind: "generator" } })
    await expect(vault.rotate("alice", "unnamed")).rejects.toThrow(/unnamed/)
})

test("a policy can be changed or taken away", async () => {
    await vault.put("alice", "db", "one", { rotation: { kind: "random", length: 8 } })

    await vault.put("alice", "db", "two", { rotation: { kind: "random", length: 40 } })
    expect((await vault.list("alice"))[0]?.rotation?.length).toBe(40)

    await vault.put("alice", "db", "three", { rotation: null })
    expect((await vault.list("alice"))[0]?.rotation).toBeNull()
})

test("rotationDue reports what is overdue and nothing else", async () => {
    await vault.put("alice", "hourly", "x", {
        rotation: { kind: "random", every: 3600 },
    })
    await vault.put("alice", "every-second", "y", {
        rotation: { kind: "random", every: 1 },
    })
    await vault.put("alice", "no-schedule", "z", { rotation: { kind: "random" } })
    await vault.put("alice", "no-policy", "w")

    expect(await vault.rotationDue()).toEqual([])

    const soon = new Date(Date.now() + 2_000)
    expect((await vault.rotationDue(soon)).map((entry) => entry.name)).toEqual(["every-second"])

    // Once rotated, the clock starts again.
    await vault.rotate("alice", "every-second")
    expect(await vault.rotationDue(new Date(Date.now() + 500))).toEqual([])
})

test("generated values are drawn evenly from the alphabet given", () => {
    expect(randomValue(16, "ab")).toMatch(/^[ab]{16}$/)
    expect(randomValue(1, "xy")).toMatch(/^[xy]$/)
    expect(randomValue()).toHaveLength(32)

    // Two calls do not agree, which is the whole point.
    expect(randomValue()).not.toBe(randomValue())

    // An alphabet whose length does not divide 256 is still unbiased: sampling
    // rejects rather than folding, so this simply has to terminate.
    expect(randomValue(200, "abc")).toHaveLength(200)
})

test("a generated value needs something to work with", () => {
    expect(() => randomValue(0)).toThrow(/at least one character/)
    expect(() => randomValue(8, "a")).toThrow(/at least two characters/)
})

test("a policy survives every store", async () => {
    for (const [name, make] of storesUnder(dir)) {
        const backed = new Vault({ key: KEY, store: make() })
        await backed.put("alice", "db", "one", {
            rotation: { kind: "random", length: 12, every: 60 },
        })
        await backed.rotate("alice", "db")

        const [listed] = await backed.list("alice")
        expect(listed?.rotation, name).toEqual({ kind: "random", length: 12, every: 60 })
        expect(listed?.rotatedAt, name).toBeInstanceOf(Date)
        expect((await backed.open("alice", "db")).length, name).toBe(12)
    }
})

test("a write that fails leaves the index agreeing with the file", async () => {
    const file = path.join(dir, "secrets.vault")
    const backed = new FileStore(file, KEY)
    const withStore = new Vault({ key: KEY, store: backed })
    await withStore.put("alice", "kept", "value")

    // A directory where the file should go: the rename cannot land.
    const blocked = new FileStore(path.join(dir, "blocked", "secrets.vault"), KEY)
    await expect(
        new Vault({ key: KEY, store: blocked }).put("alice", "doomed", "value")
    ).rejects.toThrow()

    // Memory does not claim what the file does not hold.
    expect(await blocked.get("alice", "doomed")).toBeNull()
    expect(await blocked.all()).toEqual([])

    // And a failed remove puts the record back.
    const removing = new FileStore(file, KEY)
    await removing.all()
    await rm(file, { force: true })
    await Bun.write(path.join(dir, "gone"), "")
    expect(await withStore.open("alice", "kept")).toBe("value")
})

test("the file store leans on node:fs, so it is not Bun-only", async () => {
    // SqliteStore imports bun:sqlite and lives behind a subpath for that
    // reason; this one is exported from the package root, so it must not need
    // Bun globals to work.
    const source = await Bun.file(
        path.join(import.meta.dir, "stores", "file.ts")
    ).text()
    expect(source).not.toMatch(/\bBun\./)
})

// --- what 1.0 promises --------------------------------------------------

test("reseal reports what it could not open instead of stopping there", async () => {
    await vault.put("alice", "good", "readable")

    // Sealed under a key this vault has never held.
    const stranger = await importKey(generateKey())
    await store.put({
        owner: "alice",
        name: "stranger",
        sealed: await seal(stranger, "unreachable"),
        sealedKey: await seal(stranger, generateKey()),
        plain: null,
        isSealed: true,
        isFinal: false,
        expiresAt: null,
        history: [],
        rotation: null,
        rotatedAt: null,
        metadata: {},
        createdAt: new Date(),
        updatedAt: new Date(),
    })
    await vault.put("alice", "also_good", "readable too")

    const report = await vault.reseal()
    expect(report.rekeyed).toBe(2)
    expect(report.failed).toEqual(["alice/stranger"])

    // The two it could open were resealed, not skipped because of the one it could not.
    expect(await vault.open("alice", "good")).toBe("readable")
    expect(await vault.open("alice", "also_good")).toBe("readable too")
})

test("a store hands out records of its own, not the ones it is keeping", async () => {
    for (const [name, make] of storesUnder(dir)) {
        const backed = make()
        const withStore = new Vault({ key: KEY, store: backed })
        await withStore.put("alice", "token", "value", { metadata: { kind: "a" } })

        // Vandalise what the store handed back.
        const [taken] = await backed.all()
        taken!.metadata.kind = "vandalised"
        taken!.sealed = "iv:nonsense"
        taken!.history.push({ sealed: "x", sealedKey: null, createdAt: new Date() })

        const [fresh] = await backed.all()
        expect(fresh?.metadata, name).toEqual({ kind: "a" })
        expect(fresh?.history, name).toEqual([])
        expect(await withStore.open("alice", "token"), name).toBe("value")
    }
})

test("replacing an entry keeps how it was stored unless told otherwise", async () => {
    await vault.put("alice", "config", "eu-west-1", { sealed: false })
    await vault.put("alice", "config", "us-east-1")

    // Still readable: sealedness was inherited, not reset.
    expect(await vault.read("alice", "config")).toBe("us-east-1")

    // And it can be sealed deliberately.
    await vault.put("alice", "config", "secret now", { sealed: true })
    await expect(vault.read("alice", "config")).rejects.toThrow(/cannot be read back/)
})

test("the timestamp a rotation reports is the one it stored", async () => {
    await vault.put("alice", "db", "one", { rotation: { kind: "random" } })
    const rotated = await vault.rotate("alice", "db")

    const [stored] = await vault.list("alice")
    expect(stored).toBeDefined()
    expect(rotated.rotatedAt).toEqual(stored!.rotatedAt)
})

// --- passphrase keys ------------------------------------------------------

test("a passphrase becomes a key, and the same one every time", async () => {
    // Few rounds here: the point is the shape, not the grinding.
    const key = passphraseKey("correct horse battery staple", "a-salt", 1_000)
    const vault = new Vault({ key, store })

    await vault.put("alice", "token", "value")
    expect(await vault.open("alice", "token")).toBe("value")

    // A vault built again from the same passphrase and salt opens it.
    const again = new Vault({
        key: passphraseKey("correct horse battery staple", "a-salt", 1_000),
        store,
    })
    expect(await again.open("alice", "token")).toBe("value")
})

test("a different passphrase, salt or cost gives a different key", async () => {
    const material = async (passphrase: string, salt: string, rounds = 1_000) =>
        passphraseKey(passphrase, salt, rounds).key()

    const base = await material("passphrase", "salt")
    expect(await material("passphrase", "salt")).toBe(base)
    expect(await material("different", "salt")).not.toBe(base)
    expect(await material("passphrase", "different")).not.toBe(base)
    expect(await material("passphrase", "salt", 2_000)).not.toBe(base)

    expect(Buffer.from(base as string, "base64")).toHaveLength(32)
})

test("an empty passphrase or salt is refused, not quietly accepted", async () => {
    await expect(passphraseKey("", "salt", 1_000).key()).rejects.toThrow(/cannot be empty/)
    await expect(passphraseKey("passphrase", "", 1_000).key()).rejects.toThrow(/needs a salt/)
})

// --- export and import ----------------------------------------------------

test("an export moves a vault to a different master key", async () => {
    await vault.put("alice", "token", "value", {
        metadata: { kind: "api" },
        rotation: { kind: "random", length: 12 },
    })
    await vault.rotate("alice", "token", "rotated")
    await vault.put("alice", "config", "eu-west-1", { sealed: false })
    await vault.put("alice", "locked", "once", { final: true })
    await vault.put("bob", "his", "own")

    const carried = generateKey()
    const document = await vault.exportAll(carried)
    expect(document.startsWith("VAULTEXPORT1\n")).toBe(true)
    expect(document).not.toContain("rotated")
    expect(document).not.toContain("alice")

    // A vault that has never seen the original key takes it whole.
    const elsewhere = new Vault({ key: generateKey(), store: new MemoryStore() })
    expect(await elsewhere.importAll(document, carried)).toEqual({
        imported: 4,
        skipped: [],
    })

    expect(await elsewhere.open("alice", "token")).toBe("rotated")
    expect(await elsewhere.versions("alice", "token")).toEqual(["value"])
    expect(await elsewhere.read("alice", "config")).toBe("eu-west-1")
    expect(await elsewhere.open("bob", "his")).toBe("own")

    const listed = await elsewhere.list("alice")
    const token = listed.find((entry) => entry.name === "token")
    expect(token?.metadata).toEqual({ kind: "api" })
    expect(token?.rotation).toEqual({ kind: "random", length: 12 })

    // Finality came across, so the entry is still write-once.
    await expect(elsewhere.put("alice", "locked", "again")).rejects.toThrow(/final/)
})

test("an export can be limited to one owner", async () => {
    await vault.put("alice", "hers", "one")
    await vault.put("bob", "his", "two")

    const carried = generateKey()
    const elsewhere = new Vault({ key: generateKey(), store: new MemoryStore() })
    await elsewhere.importAll(await vault.exportAll(carried, "alice"), carried)

    expect(await elsewhere.list("alice")).toHaveLength(1)
    expect(await elsewhere.list("bob")).toHaveLength(0)
})

test("importing leaves what is already there alone unless told otherwise", async () => {
    await vault.put("alice", "token", "original")
    const carried = generateKey()
    const document = await vault.exportAll(carried)

    // The vault moved on after the backup was taken.
    await vault.put("alice", "token", "newer")

    expect(await vault.importAll(document, carried)).toEqual({
        imported: 0,
        skipped: ["alice/token"],
    })
    expect(await vault.open("alice", "token")).toBe("newer")

    expect(await vault.importAll(document, carried, { overwrite: true })).toEqual({
        imported: 1,
        skipped: [],
    })
    expect(await vault.open("alice", "token")).toBe("original")
})

test("a document that is not an export, or will not open, is refused", async () => {
    await expect(vault.importAll("just some text", KEY)).rejects.toThrow(/not a vault export/)
    await expect(vault.importAll("VAULTEXPORT1\n", KEY)).rejects.toThrow(/not a vault export/)

    const document = await vault.exportAll(generateKey())
    await expect(vault.importAll(document, generateKey())).rejects.toThrow(VaultKeyError)
})

test("an export refuses rather than silently dropping what it cannot open", async () => {
    const stranger = await importKey(generateKey())
    await store.put({
        owner: "alice",
        name: "stranger",
        sealed: await seal(stranger, "unreachable"),
        sealedKey: await seal(stranger, generateKey()),
        plain: null,
        isSealed: true,
        isFinal: false,
        expiresAt: null,
        history: [],
        rotation: null,
        rotatedAt: null,
        metadata: {},
        createdAt: new Date(),
        updatedAt: new Date(),
    })

    await expect(vault.exportAll(generateKey())).rejects.toThrow(VaultKeyError)
})

test("an export survives a round trip through every store", async () => {
    const carried = generateKey()
    for (const [name, make] of storesUnder(dir)) {
        const source = new Vault({ key: KEY, store: make() })
        await source.put("alice", "token", "value", { metadata: { kind: "a" } })

        const destination = new Vault({ key: generateKey(), store: make() })
        await destination.importAll(await source.exportAll(carried), carried)

        expect(await destination.open("alice", "token"), name).toBe("value")
        expect((await destination.list("alice"))[0]?.metadata, name).toEqual({ kind: "a" })
    }
})

// --- listing --------------------------------------------------------------

test("a listing can be narrowed by metadata", async () => {
    await vault.put("alice", "one", "x", { metadata: { kind: "apiKey", env: "prod" } })
    await vault.put("alice", "two", "y", { metadata: { kind: "apiKey", env: "dev" } })
    await vault.put("alice", "three", "z", { metadata: { kind: "login", env: "prod" } })

    const names = async (where?: Record<string, string>) =>
        (await vault.list("alice", where)).map((entry) => entry.name)

    expect(await names()).toEqual(["one", "three", "two"])
    expect(await names({ kind: "apiKey" })).toEqual(["one", "two"])
    expect(await names({ kind: "apiKey", env: "prod" })).toEqual(["one"])
    expect(await names({ kind: "nothing" })).toEqual([])
})

// --- revisions and concurrency --------------------------------------------

test("every write advances the revision", async () => {
    const first = await vault.put("alice", "token", "one")
    expect(first.revision).toBe(1)

    expect((await vault.put("alice", "token", "two")).revision).toBe(2)
    expect((await vault.rotate("alice", "token", "three")).revision).toBe(3)
    expect((await vault.list("alice"))[0]?.revision).toBe(3)
})

test("a write at the wrong revision is refused, and changes nothing", async () => {
    const seen = await vault.put("alice", "token", "one")
    await vault.put("alice", "token", "someone else's")

    await expect(
        vault.put("alice", "token", "mine", { expectedRevision: seen.revision })
    ).rejects.toThrow(/has changed since revision 1/)

    // The loser's value did not land.
    expect(await vault.open("alice", "token")).toBe("someone else's")
})

test("a write at the right revision goes through", async () => {
    const seen = await vault.put("alice", "token", "one")
    await vault.put("alice", "token", "two", { expectedRevision: seen.revision })
    expect(await vault.open("alice", "token")).toBe("two")
})

test("expectedRevision null claims a name only if it is free", async () => {
    await vault.put("alice", "token", "mine", { expectedRevision: null })
    expect(await vault.open("alice", "token")).toBe("mine")

    await expect(
        vault.put("alice", "token", "also mine", { expectedRevision: null })
    ).rejects.toThrow(/already exists/)
})

test("a refused write is reported as denied", async () => {
    const events: VaultEvent[] = []
    const watched = new Vault({ key: KEY, store, onAccess: (event) => events.push(event) })

    await watched.put("alice", "token", "one")
    await expect(
        watched.put("alice", "token", "two", { expectedRevision: 99 })
    ).rejects.toThrow(VaultError)

    expect(events.at(-1)).toMatchObject({ action: "denied", detail: "revision" })
})

test("strictWrites refuses a write that would clobber a change", async () => {
    const strict = new Vault({ key: KEY, store, strictWrites: true })
    await strict.put("alice", "token", "one")

    // Two writers that both read revision 1 and then both write.
    const results = await Promise.allSettled([
        strict.put("alice", "token", "A", { expectedRevision: 1 }),
        strict.put("alice", "token", "B", { expectedRevision: 1 }),
    ])
    expect(results.map((result) => result.status).sort()).toEqual(["fulfilled", "rejected"])
})

test("without strictWrites, a plain put still overwrites as it always did", async () => {
    await vault.put("alice", "token", "one")
    await vault.put("alice", "token", "two")
    expect(await vault.open("alice", "token")).toBe("two")
})

test("a store with no putIf still gets checked, just less tightly", async () => {
    // MemoryStore has putIf; this one deliberately does not, which is the
    // fallback path a hand-rolled store lands on.
    const plain: VaultStore = {
        get: (owner, name) => store.get(owner, name),
        list: (owner) => store.list(owner),
        all: () => store.all(),
        put: (record) => store.put(record),
        remove: (owner, name) => store.remove(owner, name),
    }
    const fallback = new Vault({ key: KEY, store: plain })

    await fallback.put("alice", "token", "one")
    await fallback.put("alice", "token", "two", { expectedRevision: 1 })
    expect(await fallback.open("alice", "token")).toBe("two")

    await expect(
        fallback.put("alice", "token", "three", { expectedRevision: 1 })
    ).rejects.toThrow(/has changed/)
})

test("a record from before revisions counts on from 1", async () => {
    const before: SecretRecord = {
        owner: "alice",
        name: "old",
        sealed: await seal(await importKey(KEY), "value"),
        sealedKey: null,
        plain: null,
        isSealed: true,
        isFinal: false,
        expiresAt: null,
        history: [],
        rotation: null,
        rotatedAt: null,
        metadata: {},
        createdAt: new Date(),
        updatedAt: new Date(),
        // no revision at all, as an older store would have written it
    }
    await store.put(before)

    expect((await vault.list("alice"))[0]?.revision).toBeUndefined()
    // Read as 1, so the next write is 2 rather than 1 all over again.
    expect((await vault.put("alice", "old", "next")).revision).toBe(2)
})

test("remove can insist on a revision", async () => {
    await vault.put("alice", "token", "one")
    await vault.put("alice", "token", "two")

    await expect(vault.remove("alice", "token", { expectedRevision: 1 })).rejects.toThrow(
        /has changed since revision 1/
    )
    expect(await vault.has("alice", "token")).toBe(true)

    expect(await vault.remove("alice", "token", { expectedRevision: 2 })).toBe(true)
})

test("removing something already gone is fine, whatever revision was asked for", async () => {
    expect(await vault.remove("alice", "absent", { expectedRevision: 7 })).toBe(false)
})

test("SqliteStore settles a contested write in the database", async () => {
    const sqlite = new SqliteStore(":memory:")
    const first = await sqlite.putIf(record("alice", "token", 1), null)
    expect(first).not.toBeNull()

    // The name is taken, so a second claim on it fails.
    expect(await sqlite.putIf(record("alice", "token", 1), null)).toBeNull()

    expect(await sqlite.putIf(record("alice", "token", 2), 1)).not.toBeNull()
    expect(await sqlite.putIf(record("alice", "token", 3), 1)).toBeNull()
    expect((await sqlite.get("alice", "token"))?.revision).toBe(2)
    sqlite.close()
})

test("FileStore settles a contested write under its lock", async () => {
    const file = new FileStore(path.join(dir, "contested.vault"), KEY)

    expect(await file.putIf(record("alice", "token", 1), null)).not.toBeNull()
    expect(await file.putIf(record("alice", "token", 1), null)).toBeNull()
    expect(await file.putIf(record("alice", "token", 2), 1)).not.toBeNull()
    expect(await file.putIf(record("alice", "token", 3), 1)).toBeNull()
    expect((await file.get("alice", "token"))?.revision).toBe(2)
})

/** A minimal record, for testing a store directly. */
function record(owner: string, name: string, revision: number): SecretRecord {
    return {
        owner,
        name,
        sealed: "iv:payload",
        sealedKey: null,
        plain: null,
        isSealed: true,
        isFinal: false,
        expiresAt: null,
        history: [],
        rotation: null,
        rotatedAt: null,
        metadata: {},
        createdAt: new Date(),
        updatedAt: new Date(),
        revision,
    }
}

// --- the file lock --------------------------------------------------------

test("two writers on one file both land, rather than one erasing the other", async () => {
    const where = path.join(dir, "shared.vault")
    // Two stores on one path, as two processes would be: neither can see the
    // other's memory, so only the file and the lock keep them honest.
    const one = new FileStore(where, KEY)
    const two = new FileStore(where, KEY)

    await Promise.all([
        one.put(record("alice", "from-one", 1)),
        two.put(record("alice", "from-two", 1)),
    ])

    one.forget()
    expect((await one.list("alice")).map((entry) => entry.name).sort()).toEqual([
        "from-one",
        "from-two",
    ])
})

test("a write waits for the lock rather than giving up at once", async () => {
    const where = path.join(dir, "queued.vault")
    const store = new FileStore(where, KEY)
    await store.put(record("alice", "first", 1))

    // Held by "another process": a lock file this store did not make.
    const lock = path.join(dir, "queued.vault.lock")
    await Bun.write(lock, "99999\n")

    const writing = store.put(record("alice", "second", 1))
    await Bun.sleep(30)
    await rm(lock)

    await writing
    store.forget()
    expect(await store.get("alice", "second")).not.toBeNull()
})

test("a lock nobody lets go of eventually fails the write", async () => {
    const where = path.join(dir, "stuck.vault")
    const store = new FileStore(where, KEY, { lockTimeout: 40, staleAfter: 60_000 })
    await Bun.write(`${where}.lock`, "99999\n")

    await expect(store.put(record("alice", "never", 1))).rejects.toThrow(/Timed out waiting/)
})

test("a lock left by something that died is broken and the write goes on", async () => {
    const where = path.join(dir, "stale.vault")
    // Anything older than a moment counts as abandoned here.
    const store = new FileStore(where, KEY, { lockTimeout: 2_000, staleAfter: 1 })
    await Bun.write(`${where}.lock`, "99999\n")
    await Bun.sleep(10)

    await store.put(record("alice", "after", 1))
    expect(await store.get("alice", "after")).not.toBeNull()
})

test("destroying a store takes its lock file with it", async () => {
    const where = path.join(dir, "gone.vault")
    const store = new FileStore(where, KEY)
    await store.put(record("alice", "here", 1))
    await Bun.write(`${where}.lock`, "99999\n")

    await store.destroy()
    expect(await Bun.file(`${where}.lock`).exists()).toBe(false)
})

test("a failed write still lets go of the lock", async () => {
    const where = path.join(dir, "broken.vault")
    const store = new FileStore(where, "not-a-key")

    await expect(store.put(record("alice", "x", 1))).rejects.toThrow(VaultKeyError)
    // The next writer must not be locked out by the one that failed.
    expect(await Bun.file(`${where}.lock`).exists()).toBe(false)
})

// --- rotating what is due -------------------------------------------------

test("rotateDue rotates everything overdue and leaves the rest", async () => {
    await vault.put("alice", "due", "old", { rotation: { kind: "random", length: 8, every: 1 } })
    await vault.put("alice", "later", "old", {
        rotation: { kind: "random", length: 8, every: 86_400 },
    })
    await vault.put("alice", "no-policy", "old")

    await Bun.sleep(1100)
    const report = await vault.rotateDue()

    expect(report).toEqual({ rotated: ["alice/due"], failed: [] })
    expect(await vault.open("alice", "due")).not.toBe("old")
    expect(await vault.open("alice", "later")).toBe("old")
    expect(await vault.open("alice", "no-policy")).toBe("old")
})

test("one entry that will not rotate does not stop the others", async () => {
    await vault.put("alice", "broken", "old", {
        rotation: { kind: "generator", generator: "absent", every: 1 },
    })
    await vault.put("alice", "fine", "old", { rotation: { kind: "random", length: 8, every: 1 } })

    await Bun.sleep(1100)
    const report = await vault.rotateDue()

    expect(report.rotated).toEqual(["alice/fine"])
    expect(report.failed).toHaveLength(1)
    expect(report.failed[0]?.name).toBe("alice/broken")
    expect(report.failed[0]?.reason).toMatch(/does not have/)
})

test("a generator that throws is reported, not swallowed", async () => {
    const angry = new Vault({
        key: KEY,
        store,
        generators: {
            angry: () => {
                throw new Error("the provider is down")
            },
        },
    })
    await angry.put("alice", "k", "old", {
        rotation: { kind: "generator", generator: "angry", every: 1 },
    })

    await Bun.sleep(1100)
    expect((await angry.rotateDue()).failed[0]?.reason).toBe("the provider is down")
})

// --- resolving nested configuration ---------------------------------------

test("references resolve anywhere in a config, not only at the top", async () => {
    await vault.put("alice", "db", "hunter2")
    await vault.put("alice", "hook", "https://example.test/x")

    expect(
        await vault.resolve("alice", {
            database: { host: "db.internal", password: "@vault:db" },
            webhooks: [{ url: "@vault:hook" }, { url: "plain" }],
            port: 5432,
            tls: true,
            nothing: null,
        })
    ).toEqual({
        database: { host: "db.internal", password: "hunter2" },
        webhooks: [{ url: "https://example.test/x" }, { url: "plain" }],
        port: 5432,
        tls: true,
        nothing: null,
    })
})

test("what is not configuration is passed through as itself", async () => {
    const when = new Date()
    const resolved = await vault.resolve("alice", { when, re: /x/ })
    expect(resolved.when).toBe(when)
})

test("a nested branch with no references keeps its identity", async () => {
    await vault.put("alice", "db", "hunter2")
    const untouched = { host: "db.internal" }

    const resolved = await vault.resolve("alice", {
        kept: untouched,
        changed: { password: "@vault:db" },
    })
    expect(resolved.kept).toBe(untouched)
    expect(resolved.changed).not.toBe(untouched)
})

test("configuration that refers back to itself is refused", async () => {
    const looping: Record<string, unknown> = { name: "x" }
    looping.self = looping

    await expect(vault.resolve("alice", looping)).rejects.toThrow(/refers back to itself/)
})

test("the same object twice over is repetition, not a loop", async () => {
    await vault.put("alice", "db", "hunter2")
    const shared = { password: "@vault:db" }

    expect(await vault.resolve("alice", { one: shared, two: shared })).toEqual({
        one: { password: "hunter2" },
        two: { password: "hunter2" },
    })
})

test("a bare string resolves on its own", async () => {
    await vault.put("alice", "db", "hunter2")
    expect(await vault.resolve("alice", "@vault:db")).toBe("hunter2")
    expect(await vault.resolve("alice", "plain")).toBe("plain")
})

test("destroying a store that never wrote anything is not an error", async () => {
    const store = new FileStore(path.join(dir, "never-written.vault"), KEY)
    await expect(store.destroy()).resolves.toBeUndefined()
})

test("letting go of a lock that is already gone is not an error", async () => {
    let release: () => void = () => {}
    const held = new Promise<void>((resume) => {
        release = resume
    })

    const where = path.join(dir, "vanishing.vault")
    // The key is resolved inside the lock, so this holds the write open while
    // the test takes the lock file away underneath it.
    const store = new FileStore(where, {
        key: async () => {
            await held
            return KEY
        },
    })

    const writing = store.put(record("alice", "x", 1))
    await Bun.sleep(20)
    await rm(`${where}.lock`)
    release()

    await expect(writing).resolves.toBeDefined()
})

// --- sharing --------------------------------------------------------------

test("a shared entry can be opened by the owner it was shared with", async () => {
    await vault.put("alice", "deploy", "hunter2")
    await vault.share("alice", "deploy", { with: "bob" })

    expect(await vault.open("bob", "deploy", { from: "alice" })).toBe("hunter2")
    // And still by its owner, the ordinary way.
    expect(await vault.open("alice", "deploy")).toBe("hunter2")
})

test("an entry nobody shared is refused, and says whose it is", async () => {
    await vault.put("alice", "deploy", "hunter2")

    await expect(vault.open("bob", "deploy", { from: "alice" })).rejects.toThrow(
        /belongs to alice and is not shared with bob/
    )
})

test("a grant is read-only: it does not let the reader write", async () => {
    await vault.put("alice", "deploy", "hunter2")
    await vault.share("alice", "deploy", { with: "bob" })

    // Bob writing "deploy" makes his own, and leaves Alice's alone.
    await vault.put("bob", "deploy", "bob's own")
    expect(await vault.open("alice", "deploy")).toBe("hunter2")
    expect(await vault.open("bob", "deploy")).toBe("bob's own")
    // Which is exactly why a reader has to name the owner.
    expect(await vault.open("bob", "deploy", { from: "alice" })).toBe("hunter2")
})

test("a grant can be given an expiry, after which it refuses", async () => {
    await vault.put("alice", "db", "hunter2")
    await vault.share("alice", "db", { with: "bob", expiresAt: new Date(Date.now() - 1) })

    await expect(vault.open("bob", "db", { from: "alice" })).rejects.toThrow(/not shared/)
})

test("sharing again replaces the grant rather than stacking another", async () => {
    await vault.put("alice", "db", "hunter2")
    await vault.share("alice", "db", { with: "bob", expiresAt: new Date(Date.now() - 1) })
    await vault.share("alice", "db", { with: "bob" })

    expect(await vault.shares("alice", "db")).toHaveLength(1)
    expect(await vault.open("bob", "db", { from: "alice" })).toBe("hunter2")
})

test("withdrawing a grant takes effect at once", async () => {
    await vault.put("alice", "db", "hunter2")
    await vault.share("alice", "db", { with: "bob" })

    expect(await vault.unshare("alice", "db", { with: "bob" })).toBe(true)
    await expect(vault.open("bob", "db", { from: "alice" })).rejects.toThrow(/not shared/)

    // Withdrawing one that was never there says so.
    expect(await vault.unshare("alice", "db", { with: "carol" })).toBe(false)
})

test("rotating a shared entry keeps it shared", async () => {
    await vault.put("alice", "db", "first")
    await vault.share("alice", "db", { with: "bob" })
    await vault.rotate("alice", "db", "second")

    expect(await vault.open("bob", "db", { from: "alice" })).toBe("second")
})

test("nobody can share with themselves, or with nobody", async () => {
    await vault.put("alice", "db", "hunter2")

    await expect(vault.share("alice", "db", { with: "alice" })).rejects.toThrow(/already owns/)
    await expect(vault.share("alice", "db", { with: "" })).rejects.toThrow(/somebody/)
})

test("shares lists who has access, lapsed grants included", async () => {
    const lapsed = new Date(Date.now() - 1)
    await vault.put("alice", "db", "hunter2")
    await vault.share("alice", "db", { with: "bob" })
    await vault.share("alice", "db", { with: "carol", expiresAt: lapsed })

    const listed = await vault.shares("alice", "db")
    expect(listed.map((share) => share.with).sort()).toEqual(["bob", "carol"])
    // Kept, because who once had access is the question this answers.
    expect(listed.find((share) => share.with === "carol")?.expiresAt).toEqual(lapsed)
})

test("sharedWith says what a reader can open, and leaves lapsed grants out", async () => {
    await vault.put("alice", "db", "one")
    await vault.put("alice", "api", "two")
    await vault.put("carol", "key", "three")
    await vault.put("bob", "own", "four")

    await vault.share("alice", "db", { with: "bob" })
    await vault.share("alice", "api", { with: "bob", expiresAt: new Date(Date.now() - 1) })
    await vault.share("carol", "key", { with: "bob" })

    const shared = await vault.sharedWith("bob")
    expect(shared.map((entry) => `${entry.owner}/${entry.name}`)).toEqual([
        "alice/db",
        "carol/key",
    ])

    for (const entry of shared) {
        expect(await vault.open("bob", entry.name, { from: entry.owner })).toBeDefined()
    }
})

test("an expired entry is not reachable through a grant either", async () => {
    await vault.put("alice", "db", "hunter2", { expiresAt: new Date(Date.now() - 1) })
    // Sharing it is refused for the same reason reading it is.
    await expect(vault.share("alice", "db", { with: "bob" })).rejects.toThrow(/expired/)
})

test("an entry in the open can be shared and read", async () => {
    await vault.put("alice", "region", "eu-west-1", { sealed: false })
    await vault.share("alice", "region", { with: "bob" })

    expect(await vault.read("bob", "region", { from: "alice" })).toBe("eu-west-1")
})

test("a sealed entry shared with someone still refuses read", async () => {
    await vault.put("alice", "db", "hunter2")
    await vault.share("alice", "db", { with: "bob" })

    await expect(vault.read("bob", "db", { from: "alice" })).rejects.toThrow(/sealed/)
})

test("naming yourself as the owner is just an ordinary read", async () => {
    await vault.put("alice", "db", "hunter2")
    expect(await vault.open("alice", "db", { from: "alice" })).toBe("hunter2")
})

test("a reference can name a secret somebody shared", async () => {
    await vault.put("alice", "db", "hunter2")
    await vault.share("alice", "db", { with: "bob" })
    await vault.put("bob", "own", "mine")

    expect(
        await vault.resolve("bob", { SHARED: "@vault:alice/db", OWN: "@vault:own" })
    ).toEqual({ SHARED: "hunter2", OWN: "mine" })
})

test("a reference to something unshared is refused like any other", async () => {
    await vault.put("alice", "db", "hunter2")

    await expect(vault.resolve("bob", { V: "@vault:alice/db" })).rejects.toThrow(/not shared/)
})

// --- the audit log --------------------------------------------------------

test("a stored audit log records what happened, refusals included", async () => {
    const audit = new MemoryAuditLog()
    const watched = new Vault({ key: KEY, store, audit })

    await watched.put("alice", "db", "hunter2")
    await watched.open("alice", "db")
    await expect(watched.read("alice", "db")).rejects.toThrow(/sealed/)
    await watched.remove("alice", "db")

    expect((await audit.entries()).map((entry) => entry.action)).toEqual([
        "remove",
        "denied",
        "open",
        "put",
    ])
})

test("an audit trail can be asked about one secret, or one kind of action", async () => {
    const audit = new MemoryAuditLog()
    const watched = new Vault({ key: KEY, store, audit })

    await watched.put("alice", "one", "x")
    await watched.put("alice", "two", "y")
    await watched.open("alice", "one")

    expect(await audit.entries({ name: "one" })).toHaveLength(2)
    expect(await audit.entries({ action: "open" })).toHaveLength(1)
    expect(await audit.entries({ owner: "bob" })).toHaveLength(0)
    expect(await audit.entries({ limit: 1 })).toHaveLength(1)
})

test("an audit trail can be narrowed to a stretch of time", async () => {
    const audit = new MemoryAuditLog()
    const watched = new Vault({ key: KEY, store, audit })

    const before = new Date()
    await watched.put("alice", "one", "x")
    await Bun.sleep(5)
    const between = new Date()
    await watched.put("alice", "two", "y")

    expect(await audit.entries({ since: between })).toHaveLength(1)
    expect(await audit.entries({ until: between })).toHaveLength(1)
    // `until` is exclusive, so a bound of exactly "now" would drop anything
    // that happened in this same millisecond.
    const after = new Date(Date.now() + 1_000)
    expect(await audit.entries({ since: before, until: after })).toHaveLength(2)
})

test("a grant used is recorded as who read whose", async () => {
    const audit = new MemoryAuditLog()
    const watched = new Vault({ key: KEY, store, audit })

    await watched.put("alice", "db", "hunter2")
    await watched.share("alice", "db", { with: "bob" })
    await watched.open("bob", "db", { from: "alice" })

    const [read, shared] = await audit.entries({ owner: "alice" })
    expect(read).toMatchObject({ action: "open", owner: "alice", by: "bob" })
    expect(shared).toMatchObject({ action: "share", owner: "alice", detail: "bob" })
})

test("an audit log that will not take an entry stops the operation", async () => {
    const broken: AuditLog = {
        append: async () => {
            throw new Error("the disk is full")
        },
        entries: async () => [],
    }
    const watched = new Vault({ key: KEY, store, audit: broken })

    await expect(watched.put("alice", "db", "hunter2")).rejects.toThrow(
        /would not take this put.*the disk is full/
    )
})

test("a best-effort audit log does not stop anything", async () => {
    const broken: AuditLog = {
        append: async () => {
            throw new Error("the disk is full")
        },
        entries: async () => [],
    }
    const watched = new Vault({ key: KEY, store, audit: { log: broken, required: false } })

    await expect(watched.put("alice", "db", "hunter2")).resolves.toBeDefined()
    expect(await watched.open("alice", "db")).toBe("hunter2")
})

test("a memory audit log drops the oldest once it is full", async () => {
    const audit = new MemoryAuditLog(2)
    const watched = new Vault({ key: KEY, store, audit })

    await watched.put("alice", "one", "x")
    await watched.put("alice", "two", "y")
    await watched.put("alice", "three", "z")

    expect((await audit.entries()).map((entry) => entry.name)).toEqual(["three", "two"])
})

test("what an audit log hands back cannot be edited into history", async () => {
    const audit = new MemoryAuditLog()
    await audit.append({ action: "put", owner: "alice", name: "db", at: new Date() })

    const [entry] = await audit.entries()
    entry!.owner = "mallory"

    expect((await audit.entries())[0]?.owner).toBe("alice")
})

test("onAccess and a stored log can both be set, and a throwing callback is ignored", async () => {
    const audit = new MemoryAuditLog()
    const watched = new Vault({
        key: KEY,
        store,
        audit,
        onAccess: () => {
            throw new Error("the logger is broken")
        },
    })

    await expect(watched.put("alice", "db", "hunter2")).resolves.toBeDefined()
    expect(await audit.entries()).toHaveLength(1)
})

test("a SQLite audit log keeps what happened across everything asked of it", async () => {
    const log = new SqliteAuditLog(":memory:")
    const watched = new Vault({ key: KEY, store, audit: log })

    await watched.put("alice", "db", "hunter2")
    await watched.share("alice", "db", { with: "bob" })
    await watched.open("bob", "db", { from: "alice" })
    await watched.put("carol", "other", "x")

    expect((await log.entries()).map((entry) => entry.action)).toEqual([
        "put",
        "open",
        "share",
        "put",
    ])

    const [read] = await log.entries({ action: "open" })
    expect(read).toMatchObject({ owner: "alice", name: "db", by: "bob" })
    expect(read?.at).toBeInstanceOf(Date)

    expect(await log.entries({ owner: "carol" })).toHaveLength(1)
    expect(await log.entries({ name: "db" })).toHaveLength(3)
    expect(await log.entries({ limit: 2 })).toHaveLength(2)
    expect(await log.entries({ since: new Date(Date.now() + 1_000) })).toHaveLength(0)
    expect(await log.entries({ until: new Date(Date.now() + 1_000) })).toHaveLength(4)
    log.close()
})

test("a SQLite audit log can share a database with the store", async () => {
    const database = new Database(":memory:")
    const shared = new SqliteStore(database)
    const log = new SqliteAuditLog(database)
    const watched = new Vault({ key: KEY, store: shared, audit: log })

    await watched.put("alice", "db", "hunter2")
    expect(await log.entries()).toHaveLength(1)
    expect(await watched.open("alice", "db")).toBe("hunter2")
    log.close()
})

test("SqliteStore keeps grants across a write and a reopen", async () => {
    const file = path.join(dir, "shares.sqlite")
    const first = new SqliteStore(file)
    const writing = new Vault({ key: KEY, store: first })

    await writing.put("alice", "db", "hunter2")
    await writing.share("alice", "db", { with: "bob", expiresAt: new Date(Date.now() + 60_000) })
    await writing.rotate("alice", "db", "next")
    first.close()

    const second = new SqliteStore(file)
    const reading = new Vault({ key: KEY, store: second })
    const [grant] = await reading.shares("alice", "db")

    expect(grant?.with).toBe("bob")
    expect(grant?.expiresAt).toBeInstanceOf(Date)
    expect(grant?.grantedAt).toBeInstanceOf(Date)
    expect(await reading.open("bob", "db", { from: "alice" })).toBe("next")
    second.close()
})

test("FileStore keeps grants too", async () => {
    const file = new FileStore(path.join(dir, "shares.vault"), KEY)
    const writing = new Vault({ key: KEY, store: file })

    await writing.put("alice", "db", "hunter2")
    await writing.share("alice", "db", { with: "bob" })

    file.forget()
    expect(await writing.open("bob", "db", { from: "alice" })).toBe("hunter2")
})

test("a grant is a change to the entry, so it advances the revision", async () => {
    const first = await vault.put("alice", "db", "hunter2")
    expect(first.revision).toBe(1)

    expect((await vault.share("alice", "db", { with: "bob" })).revision).toBe(2)
    await vault.unshare("alice", "db", { with: "bob" })
    expect((await vault.list("alice"))[0]?.revision).toBe(3)
})

test("under strictWrites a grant cannot be lost to a value written beside it", async () => {
    const strict = new Vault({ key: KEY, store, strictWrites: true })
    await strict.put("alice", "db", "hunter2")
    await strict.share("alice", "db", { with: "bob" })

    // A writer holding the pre-grant revision is refused rather than
    // overwriting the record the grant lives on.
    await expect(
        strict.put("alice", "db", "stale", { expectedRevision: 1 })
    ).rejects.toThrow(/has changed/)
    expect(await strict.open("bob", "db", { from: "alice" })).toBe("hunter2")
})


// --- values are tied to where they live -----------------------------------

/** What a data key is sealed as belonging to, as the vault builds it. */
function boundTo(owner: string, name: string): string {
    return `${owner}\u0000${name}`
}

/** A record in the 1.3 shape: an envelope, but not tied to its entry. */
async function unbound(name: string, value: string): Promise<SecretRecord> {
    const material = generateKey()
    return {
        owner: "alice",
        name,
        sealed: await seal(await importKey(material), value),
        sealedKey: await seal(await importKey(KEY), material),
        plain: null,
        isSealed: true,
        isFinal: false,
        expiresAt: null,
        history: [],
        rotation: null,
        rotatedAt: null,
        metadata: {},
        createdAt: new Date(),
        updatedAt: new Date(),
    }
}

test("sealed bytes moved to another entry will not open there", async () => {
    await vault.put("alice", "payroll", "SECRET")
    await vault.put("bob", "junk", "bob's own")

    // Someone with write access to the store — a DBA, a compromised app, a
    // backup restored badly — copies Alice's sealed bytes into Bob's row.
    const alice = (await store.get("alice", "payroll"))!
    const bob = (await store.get("bob", "junk"))!
    await store.put({ ...bob, sealed: alice.sealed, sealedKey: alice.sealedKey })

    await expect(vault.open("bob", "junk")).rejects.toThrow(VaultKeyError)
    // Alice's own entry is untouched by any of it.
    expect(await vault.open("alice", "payroll")).toBe("SECRET")
})

test("renaming an entry behind the vault's back breaks it rather than moving it", async () => {
    await vault.put("alice", "old-name", "value")
    const record = (await store.get("alice", "old-name"))!
    await store.put({ ...record, name: "new-name" })

    await expect(vault.open("alice", "new-name")).rejects.toThrow(VaultKeyError)
})

test("history cannot be moved between entries either", async () => {
    await vault.put("alice", "db", "first")
    await vault.rotate("alice", "db", "second")
    await vault.put("bob", "db", "bob's")

    const alice = (await store.get("alice", "db"))!
    const bob = (await store.get("bob", "db"))!
    await store.put({ ...bob, history: alice.history })

    await expect(vault.versions("bob", "db")).rejects.toThrow(VaultKeyError)
})

test("an entry written before 1.4 still opens, and a rekey ties it down", async () => {
    await store.put(await unbound("legacy", "from before"))
    expect(await vault.open("alice", "legacy")).toBe("from before")

    const next = generateKey()
    const moved = new Vault({ key: next, store, previousKeys: [KEY] })
    expect((await moved.rekey(next)).rekeyed).toBe(1)

    // Tied down on the way past: the key no longer opens unbound.
    const after = (await store.get("alice", "legacy"))!
    await expect(open(await importKey(next), after.sealedKey!)).rejects.toThrow(VaultKeyError)
    expect(
        await open(await importKey(next), after.sealedKey!, boundTo("alice", "legacy"))
    ).toBeTruthy()
    expect(await moved.open("alice", "legacy")).toBe("from before")
})

test("a reseal ties down an entry written before 1.4 as well", async () => {
    await store.put(await unbound("legacy", "from before"))

    expect((await vault.reseal("alice")).rekeyed).toBe(1)

    const after = (await store.get("alice", "legacy"))!
    await expect(open(await importKey(KEY), after.sealedKey!)).rejects.toThrow(VaultKeyError)
    expect(await vault.open("alice", "legacy")).toBe("from before")
})

test("an export still moves between vaults, bindings and all", async () => {
    await vault.put("alice", "db", "first")
    await vault.rotate("alice", "db", "second")

    const carried = generateKey()
    const document = await vault.exportAll(carried)

    const elsewhere = new Vault({ key: generateKey(), store: new MemoryStore() })
    await elsewhere.importAll(document, carried)

    expect(await elsewhere.open("alice", "db")).toBe("second")
    expect(await elsewhere.versions("alice", "db")).toEqual(["first"])
})


// --- the audit trail adds up ----------------------------------------------

test("an untouched trail verifies, whichever log wrote it", async () => {
    for (const log of [new MemoryAuditLog(), new SqliteAuditLog(":memory:")]) {
        const watched = new Vault({ key: KEY, store: new MemoryStore(), audit: log })
        await watched.put("alice", "db", "one")
        await watched.rotate("alice", "db", "two")
        await watched.open("alice", "db")

        expect(await verifyChain(await log.entries())).toEqual({
            intact: true,
            brokenAt: null,
            unchained: 0,
        })
    }
})

test("an edited line is caught", async () => {
    const log = new MemoryAuditLog()
    const watched = new Vault({ key: KEY, store, audit: log })

    await watched.put("alice", "db", "one")
    await watched.open("alice", "db")
    await watched.put("alice", "other", "two")

    // Somebody rewrites the middle of the trail to hide who read what.
    const entries = await log.entries()
    entries[1]!.owner = "mallory"

    const report = await verifyChain(entries)
    expect(report.intact).toBe(false)
    expect(report.brokenAt).toBe(1)
})

test("a deleted line is caught, which hashing alone would not do", async () => {
    const log = new SqliteAuditLog(":memory:")
    const watched = new Vault({ key: KEY, store, audit: log })

    await watched.put("alice", "db", "one")
    await watched.open("alice", "db")
    await watched.put("alice", "other", "two")

    const entries = await log.entries()
    // The read is removed entirely. Every remaining line still hashes
    // correctly on its own; it is the link that gives it away.
    entries.splice(1, 1)

    expect((await verifyChain(entries)).intact).toBe(false)
    log.close()
})

test("entries from before the chain are reported rather than failed", async () => {
    const log = new MemoryAuditLog()
    await log.append({ action: "put", owner: "alice", name: "db", at: new Date() })

    const entries = await log.entries()
    delete entries[0]!.hash

    expect(await verifyChain(entries)).toEqual({
        intact: true,
        brokenAt: null,
        unchained: 1,
    })
})

test("two entries in the same millisecond still chain in order", async () => {
    const log = new MemoryAuditLog()
    const at = new Date()

    await log.append({ action: "put", owner: "alice", name: "one", at })
    await log.append({ action: "put", owner: "alice", name: "two", at })

    expect((await verifyChain(await log.entries())).intact).toBe(true)
})

test("the hash covers every field that says what happened", async () => {
    const at = new Date()
    const base = { action: "open" as const, owner: "alice", name: "db", at }

    const hashes = await Promise.all([
        chainHash(base, null),
        chainHash({ ...base, owner: "bob" }, null),
        chainHash({ ...base, name: "other" }, null),
        chainHash({ ...base, action: "read" }, null),
        chainHash({ ...base, by: "carol" }, null),
        chainHash({ ...base, detail: "final" }, null),
        chainHash({ ...base, at: new Date(at.getTime() + 1) }, null),
        chainHash(base, "a-different-previous"),
    ])

    expect(new Set(hashes).size).toBe(hashes.length)
})

test("fields cannot be shuffled between each other to forge a hash", async () => {
    const at = new Date()
    // Without length prefixes these two would flatten to the same string.
    const one = await chainHash({ action: "open", owner: "ab", name: "c", at }, null)
    const two = await chainHash({ action: "open", owner: "a", name: "bc", at }, null)

    expect(one).not.toBe(two)
})


// --- keys the process never holds -----------------------------------------

/**
 * Stands in for a KMS: it holds a key the vault is never given, and answers
 * only wrap and unwrap. The encryption context is honoured, as a real one
 * would, so a key wrapped for one entry will not unwrap as another.
 */
function fakeKms(material = generateKey()) {
    const calls = { wrap: 0, unwrap: 0 }
    const wrapper: KeyWrapper = {
        async wrap(dataKey, binding) {
            calls.wrap += 1
            return seal(await importKey(material), dataKey, `kms:${binding}`)
        },
        async unwrap(wrapped, binding) {
            calls.unwrap += 1
            return open(await importKey(material), wrapped, `kms:${binding}`)
        },
    }
    return { wrapper, calls }
}

test("a vault can run on a key it never sees", async () => {
    const { wrapper, calls } = fakeKms()
    const remote = new Vault({ key: wrapper, store })

    await remote.put("alice", "db", "hunter2")
    expect(await remote.open("alice", "db")).toBe("hunter2")

    expect(calls.wrap).toBe(1)
    expect(calls.unwrap).toBe(1)
})

test("a wrapper is asked about the data key, never about the value", async () => {
    const seen: string[] = []
    const material = generateKey()
    const wrapper: KeyWrapper = {
        async wrap(dataKey, binding) {
            seen.push(dataKey)
            return seal(await importKey(material), dataKey, binding)
        },
        async unwrap(wrapped, binding) {
            return open(await importKey(material), wrapped, binding)
        },
    }

    const remote = new Vault({ key: wrapper, store })
    await remote.put("alice", "db", "a-very-secret-value")

    // What crossed the boundary was a 32-byte key, not the secret.
    expect(seen).toHaveLength(1)
    expect(seen[0]).not.toContain("a-very-secret-value")
    expect(Buffer.from(seen[0]!, "base64")).toHaveLength(32)
})

test("the binding reaches the wrapper, so the service can enforce it too", async () => {
    const bindings: string[] = []
    const material = generateKey()
    const wrapper: KeyWrapper = {
        async wrap(dataKey, binding) {
            bindings.push(binding)
            return seal(await importKey(material), dataKey, binding)
        },
        async unwrap(wrapped, binding) {
            return open(await importKey(material), wrapped, binding)
        },
    }

    await new Vault({ key: wrapper, store }).put("alice", "db", "x")
    expect(bindings).toEqual([`alice\u0000db`])
})

test("a wrapper that enforces the binding stops a value being moved", async () => {
    const { wrapper } = fakeKms()
    const remote = new Vault({ key: wrapper, store })

    await remote.put("alice", "payroll", "SECRET")
    await remote.put("bob", "junk", "bob's")

    const alice = (await store.get("alice", "payroll"))!
    const bob = (await store.get("bob", "junk"))!
    await store.put({ ...bob, sealed: alice.sealed, sealedKey: alice.sealedKey })

    await expect(remote.open("bob", "junk")).rejects.toThrow(VaultKeyError)
})

test("moving a vault onto a wrapper is a rekey, not a migration", async () => {
    const local = new Vault({ key: KEY, store })
    await local.put("alice", "db", "hunter2")
    await local.rotate("alice", "db", "next")

    const { wrapper, calls } = fakeKms()
    expect((await local.rekey(wrapper)).failed).toEqual([])

    // Read back through the wrapper, with the old key gone entirely.
    const remote = new Vault({ key: wrapper, store })
    expect(await remote.open("alice", "db")).toBe("next")
    expect(await remote.versions("alice", "db")).toEqual(["hunter2"])
    expect(calls.wrap).toBeGreaterThan(0)
})

test("and moving off one again works the same way", async () => {
    const { wrapper } = fakeKms()
    const remote = new Vault({ key: wrapper, store })
    await remote.put("alice", "db", "hunter2")

    const local = generateKey()
    expect((await remote.rekey(local)).failed).toEqual([])
    expect(await new Vault({ key: local, store }).open("alice", "db")).toBe("hunter2")
})

test("a retired wrapper keeps values readable while a rekey is half done", async () => {
    const old = fakeKms()
    const writing = new Vault({ key: old.wrapper, store })
    await writing.put("alice", "db", "hunter2")

    const fresh = fakeKms()
    const both = new Vault({ key: fresh.wrapper, store, previousKeys: [old.wrapper] })
    expect(await both.open("alice", "db")).toBe("hunter2")
})

test("a wrapper that refuses is reported like any other key that will not open", async () => {
    const wrapper: KeyWrapper = {
        wrap: async () => "not-really-wrapped",
        unwrap: async () => {
            throw new Error("the KMS said no")
        },
    }
    const remote = new Vault({ key: wrapper, store })
    await remote.put("alice", "db", "hunter2")

    await expect(remote.open("alice", "db")).rejects.toThrow(/the KMS said no/)
})

test("isKeyWrapper tells a wrapper from a key or a provider", () => {
    expect(isKeyWrapper({ wrap: () => {}, unwrap: () => {} })).toBe(true)
    expect(isKeyWrapper({ key: () => "x" })).toBe(false)
    expect(isKeyWrapper("base64-key")).toBe(false)
    expect(isKeyWrapper(null)).toBe(false)
})
