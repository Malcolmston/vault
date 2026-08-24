/**
 * Builds the publishable package: JavaScript with Bun, declarations with tsc.
 *
 * The root bundle holds everything that runs anywhere, and the memory-store
 * subpath re-exports from it so there is one copy of each class — two bundles
 * would mean two `VaultError`s and a failing `instanceof`.
 *
 * SqliteStore and PostgresStore are built separately because they import
 * Bun builtins — `bun:sqlite` and `bun` — and keeping those out of the root
 * bundle is what lets Node import this package at all. Their bundles share
 * nothing but erased types, so there is nothing to duplicate.
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

// A CommonJS copy, so `require("@mstone6969/vault")` works too. Node decides
// which one it is loading by extension, hence .cjs rather than a second
// package.json.
const commonjs = await Bun.build({
    entrypoints: ["src/index.ts"],
    outdir: "dist",
    target: "node",
    format: "cjs",
    naming: "[dir]/[name].cjs",
    sourcemap: "linked",
    external: ["bun:sqlite"],
})

if (!commonjs.success) {
    for (const log of commonjs.logs) console.error(log)
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

const postgres = await Bun.build({
    entrypoints: ["src/stores/postgres.ts"],
    outdir: "dist/stores",
    target: "bun",
    format: "esm",
    sourcemap: "linked",
    // `bun` is the runtime itself, and holds the SQL client.
    external: ["bun", "bun:sqlite"],
})

if (!postgres.success) {
    for (const log of postgres.logs) console.error(log)
    process.exit(1)
}

// The memory store points back at the root bundle: one class, one identity.
await mkdir("dist/stores", { recursive: true })
await Bun.write("dist/stores/memory.js", 'export { MemoryStore } from "../index.js";\n')
await Bun.write("dist/stores/file.js", 'export { FileStore } from "../index.js";\n')
await Bun.write(
    "dist/stores/memory.cjs",
    'module.exports = { MemoryStore: require("../index.cjs").MemoryStore };\n'
)
await Bun.write(
    "dist/stores/file.cjs",
    'module.exports = { FileStore: require("../index.cjs").FileStore };\n'
)

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

// Neither root bundle may pull in a Bun builtin, which Node cannot resolve.
for (const entry of ["dist/index.js", "dist/index.cjs"]) {
    const text = await Bun.file(entry).text()
    for (const builtin of ["bun:sqlite", 'from "bun"', 'require("bun")']) {
        if (text.includes(builtin)) {
            console.error(`${entry} pulls in ${builtin}; Node could not load it.`)
            process.exit(1)
        }
    }
}

// And the CommonJS copy has to actually load under require().
const required = Bun.spawnSync([
    "node",
    "-e",
    'const v = require("./dist/index.cjs"); if (!v.Vault) throw new Error("no Vault export")',
])
if (required.exitCode !== 0) {
    console.error("dist/index.cjs does not load under require():")
    console.error(new TextDecoder().decode(required.stderr))
    process.exit(1)
}

for (const output of [...built.outputs, ...commonjs.outputs, ...sqlite.outputs]) {
    console.log(`  ${output.path.split("/dist/")[1]}  ${(output.size / 1024).toFixed(1)} KB`)
}
