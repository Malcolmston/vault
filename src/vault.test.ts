import { afterEach, beforeEach, expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { generateKey, importKey, open, seal } from "./crypto"
import { VaultError, VaultKeyError } from "./errors"
import { envKey, fileKey, isKeyProvider, passphraseKey, staticKey } from "./providers"
import { FileStore } from "./stores/file"
import { MemoryStore } from "./stores/memory"
import { SqliteStore } from "./stores/sqlite"
import type { SecretRecord, VaultEvent, VaultStore } from "./types"
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

    // The master opens the data key; the data key opens the value.
    const master = await importKey(KEY)
    const material = await open(master, a!.sealedKey!)
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

    await backed.put("alice", "stripe_key", "sk_live_secret", { metadata: { kind: "api" } })

    // Nothing about the entry is legible — not even that it exists.
    const contents = await Bun.file(file).text()
    expect(contents.startsWith("VAULT1\n")).toBe(true)
    expect(contents).not.toContain("stripe_key")
    expect(contents).not.toContain("sk_live_secret")
    expect(contents).not.toContain("alice")
    expect(contents).not.toContain("api")
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
