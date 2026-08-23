/**
 * Builds the publishable package: JavaScript with Bun, declarations with tsc.
 *
 * The root bundle holds everything that runs anywhere, and the memory-store
 * subpath re-exports from it so there is one copy of each class — two bundles
 * would mean two `VaultError`s and a failing `instanceof`.
 *
 * SqliteStore is built separately because it imports `bun:sqlite`: keeping it
 * out of the root bundle is what lets Node import this package at all. Its
 * bundle shares nothing but erased types, so there is nothing to duplicate.
 */
import { mkdir, rm } from "node:fs/promises"

await rm("dist", { recursive: true, force: true })

const built = await Bun.build({
    entrypoints: ["src/index.ts"],
    outdir: "dist",
    target: "node",
    format: "esm",
    sourcemap: "linked",
    // bun:sqlite is a runtime builtin; never try to bundle it.
    external: ["bun:sqlite"],
})

if (!built.success) {
    for (const log of built.logs) console.error(log)
    process.exit(1)
}

const sqlite = await Bun.build({
    entrypoints: ["src/stores/sqlite.ts"],
    outdir: "dist/stores",
    target: "bun",
    format: "esm",
    sourcemap: "linked",
    external: ["bun:sqlite"],
})

if (!sqlite.success) {
    for (const log of sqlite.logs) console.error(log)
    process.exit(1)
}

// The memory store points back at the root bundle: one class, one identity.
await mkdir("dist/stores", { recursive: true })
await Bun.write("dist/stores/memory.js", 'export { MemoryStore } from "../index.js";\n')
await Bun.write("dist/stores/file.js", 'export { FileStore } from "../index.js";\n')

const types = Bun.spawnSync(["bunx", "tsc", "-p", "tsconfig.build.json"], {
    stdout: "inherit",
    stderr: "inherit",
})
if (types.exitCode !== 0) process.exit(types.exitCode ?? 1)

// Import what was just written: a bundle whose exports are not defined is
// worse than a failed build, because it only breaks for whoever installs it.
const bundle = await import(`${import.meta.dir}/dist/index.js`)
const REQUIRED = [
    "Vault",
    "MemoryStore",
    "FileStore",
    "envKey",
    "fileKey",
    "staticKey",
    "VaultError",
    "VaultKeyError",
    "generateKey",
    "importKey",
    "seal",
    "open",
    "DEFAULT_PREFIX",
]
const missing = REQUIRED.filter((name) => bundle[name] === undefined)
if (missing.length > 0) {
    console.error(`Bundle is missing exports: ${missing.join(", ")}`)
    process.exit(1)
}

const smoke = new bundle.Vault({
    key: bundle.generateKey(),
    store: new bundle.MemoryStore(),
})
await smoke.put("build", "check", "value")
if ((await smoke.open("build", "check")) !== "value") {
    console.error("Bundle failed its round-trip check.")
    process.exit(1)
}

// The root bundle must stay importable from Node, which cannot resolve bun:*.
if ((await Bun.file("dist/index.js").text()).includes("bun:sqlite")) {
    console.error("dist/index.js pulls in bun:sqlite; Node could not import it.")
    process.exit(1)
}

for (const output of [...built.outputs, ...sqlite.outputs]) {
    console.log(`  ${output.path.split("/dist/")[1]}  ${(output.size / 1024).toFixed(1)} KB`)
}
