/**
 * Runs the tests with coverage and fails if anything is uncovered.
 *
 * `bun test --coverage` reports but does not enforce: a `coverageThreshold` in
 * bunfig.toml is not applied to the exit code, so CI would go green on a
 * regression. This reads the lcov report itself and decides.
 */
import { rm } from "node:fs/promises"

const DIR = ".coverage"
const REQUIRED = 100

await rm(DIR, { recursive: true, force: true })

const run = Bun.spawnSync(
    ["bun", "test", "--coverage", "--coverage-reporter=lcov", `--coverage-dir=${DIR}`],
    { stdout: "inherit", stderr: "inherit" }
)
if (run.exitCode !== 0) process.exit(run.exitCode ?? 1)

const report = await Bun.file(`${DIR}/lcov.info`).text()

type Tally = { file: string; lines: [number, number]; functions: [number, number] }
const tallies: Tally[] = []
let current: Tally | null = null

for (const line of report.split("\n")) {
    if (line.startsWith("SF:")) {
        current = { file: line.slice(3), lines: [0, 0], functions: [0, 0] }
        tallies.push(current)
    } else if (!current) {
        continue
    } else if (line.startsWith("LF:")) {
        current.lines[1] = Number(line.slice(3))
    } else if (line.startsWith("LH:")) {
        current.lines[0] = Number(line.slice(3))
    } else if (line.startsWith("FNF:")) {
        current.functions[1] = Number(line.slice(4))
    } else if (line.startsWith("FNH:")) {
        current.functions[0] = Number(line.slice(4))
    }
}

if (tallies.length === 0) {
    console.error("No coverage was reported at all. Something is wrong with the run.")
    process.exit(1)
}

const percent = (hit: number, total: number) => (total === 0 ? 100 : (hit / total) * 100)
const short = []

for (const tally of tallies) {
    const lines = percent(...tally.lines)
    const functions = percent(...tally.functions)
    if (lines < REQUIRED || functions < REQUIRED) {
        short.push(
            `  ${tally.file}: ${lines.toFixed(2)}% of lines, ${functions.toFixed(2)}% of functions`
        )
    }
}

if (short.length > 0) {
    console.error(`\nCoverage is below ${REQUIRED}%:`)
    console.error(short.join("\n"))
    process.exit(1)
}

console.log(`\nEvery one of ${tallies.length} files is fully covered.`)
