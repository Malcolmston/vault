/**
 * Runs against a real PostgreSQL, because the whole point of this store is what
 * the database does with two writers at once, and a fake would only test the
 * fake. Skipped when there is nowhere to connect to.
 */
import { afterAll, beforeEach, describe, expect, test } from "bun:test"
import { generateKey, Vault } from "../index"
import { PostgresStore } from "./postgres"

const URL = process.env.VAULT_TEST_DATABASE_URL
const TABLE = "vault_test_secrets"

describe.skipIf(!URL)("PostgresStore", () => {
    const store = new PostgresStore(URL ?? "", TABLE)

    beforeEach(async () => {
        await store.migrate()
        for (const record of await store.all()) {
            await store.remove(record.owner, record.name)
        }
    })

    afterAll(async () => {
        await store.close()
    })

    test("a table name that is not an identifier is refused", () => {
        // It cannot be a bound parameter, so it is interpolated — and therefore
        // has to be checked rather than trusted.
        expect(() => new PostgresStore(URL ?? "", 'secrets"; DROP TABLE users --')).toThrow(
            /not a usable table name/
        )
    })

    test("migrating twice is not an error", async () => {
        await expect(store.migrate()).resolves.toBeUndefined()
    })

    test("a secret survives the round trip whole", async () => {
        const vault = new Vault({ key: generateKey(), store })
        const expires = new Date(Date.now() + 60_000)

        await vault.put("alice", "db", "hunter2", {
            metadata: { kind: "postgres" },
            rotation: { kind: "random", length: 12 },
            expiresAt: expires,
        })
        await vault.rotate("alice", "db", "next")

        expect(await vault.open("alice", "db")).toBe("next")
        expect(await vault.versions("alice", "db")).toEqual(["hunter2"])

        const [entry] = await vault.list("alice")
        expect(entry?.metadata).toEqual({ kind: "postgres" })
        expect(entry?.rotation).toEqual({ kind: "random", length: 12 })
        expect(entry?.expiresAt?.getTime()).toBe(expires.getTime())
        expect(entry?.rotatedAt).toBeInstanceOf(Date)
        // One write per rotation, not two.
        expect(entry?.revision).toBe(2)
    })

    test("an entry in the open comes back readable", async () => {
        const vault = new Vault({ key: generateKey(), store })
        await vault.put("alice", "region", "eu-west-1", { sealed: false })
        expect(await vault.read("alice", "region")).toBe("eu-west-1")
    })

    test("owners are kept apart, and all() crosses them", async () => {
        const vault = new Vault({ key: generateKey(), store })
        await vault.put("alice", "hers", "a")
        await vault.put("bob", "his", "b")

        expect((await vault.list("alice")).map((entry) => entry.name)).toEqual(["hers"])
        expect(await store.all()).toHaveLength(2)
    })

    test("the database settles a contested write", async () => {
        const vault = new Vault({ key: generateKey(), store, strictWrites: true })
        await vault.put("alice", "token", "one")

        const results = await Promise.allSettled([
            vault.put("alice", "token", "A", { expectedRevision: 1 }),
            vault.put("alice", "token", "B", { expectedRevision: 1 }),
        ])

        // Exactly one, which is the property no other store can promise across
        // processes.
        expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1)
        expect((await store.get("alice", "token"))?.revision).toBe(2)
    })

    test("claiming a name that is taken fails rather than replacing it", async () => {
        const vault = new Vault({ key: generateKey(), store })
        await vault.put("alice", "token", "mine", { expectedRevision: null })

        await expect(
            vault.put("alice", "token", "yours", { expectedRevision: null })
        ).rejects.toThrow(/already exists/)
        expect(await vault.open("alice", "token")).toBe("mine")
    })

    test("removing says whether there was anything to remove", async () => {
        const vault = new Vault({ key: generateKey(), store })
        await vault.put("alice", "token", "one")

        expect(await store.remove("alice", "token")).toBe(true)
        expect(await store.remove("alice", "token")).toBe(false)
        expect(await store.get("alice", "token")).toBeNull()
    })

    test("a client passed in is left open for whoever owns it", async () => {
        const { SQL } = await import("bun")
        const shared = new SQL(URL ?? "")
        const borrower = new PostgresStore(shared, TABLE)

        await borrower.close()
        // Still usable, because closing a borrowed pool is not ours to do.
        await expect(borrower.all()).resolves.toBeDefined()
        await shared.close()
    })
})
