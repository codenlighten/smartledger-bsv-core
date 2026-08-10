#!/usr/bin/env node
'use strict'

/**
 * Ratchet on `any` in src/.
 *
 * `any` is not banned — some of it is honest. A dynamically-built error tree,
 * a spec-defined JSON blob whose fields move independently of this library, a
 * dual-callable constructor seen from inside its own body: those are places
 * where a precise type would be a guess dressed up as a fact.
 *
 * What is banned is DRIFT. Every `any` that remains should be one someone
 * decided to keep, not one left over from a mechanical conversion. So the
 * count is pinned here and the check fails if it goes up. Lowering the pin is
 * a normal part of a commit that removes some; raising it needs a reason in
 * the commit message.
 *
 * Counted: `: any`, `as any`, `any[]`, `<any>` in src/**.ts, excluding
 * comments and string literals.
 */

const fs = require('fs')
const path = require('path')

const SRC = path.join(__dirname, '..', 'src')

// Lower this when you remove some. Raising it needs a reason.
const BUDGET = Number(process.env.ANY_BUDGET ?? 245)

function walk (dir) {
  const out = []
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) out.push(...walk(p))
    else if (e.name.endsWith('.ts') && !e.name.endsWith('.d.ts')) out.push(p)
  }
  return out
}

/** Blank out comments and string literals so prose does not count. */
function strip (src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length))
    .replace(/'(?:[^'\\\n]|\\.)*'/g, (m) => ' '.repeat(m.length))
    .replace(/"(?:[^"\\\n]|\\.)*"/g, (m) => ' '.repeat(m.length))
    .replace(/`(?:[^`\\]|\\.)*`/g, (m) => ' '.repeat(m.length))
}

const perFile = []
let total = 0
for (const f of walk(SRC)) {
  const code = strip(fs.readFileSync(f, 'utf8'))
  const n = (code.match(/\bany\b/g) ?? []).length
  if (n > 0) perFile.push([path.relative(SRC, f), n])
  total += n
}
perFile.sort((a, b) => b[1] - a[1])

if (total > BUDGET) {
  console.error(`\nFAIL: ${total} uses of \`any\` in src/, budget is ${BUDGET}.\n`)
  console.error('Worst offenders:')
  for (const [f, n] of perFile.slice(0, 10)) console.error(`  ${String(n).padStart(4)}  ${f}`)
  console.error('\nEither type it properly, or raise BUDGET in this script with')
  console.error('a reason in the commit message.\n')
  process.exit(1)
}

if (total < BUDGET) {
  console.log(`any-budget:   ${total} of ${BUDGET} — ${BUDGET - total} under. Lower BUDGET to ${total} in scripts/check-any-budget.js.`)
} else {
  console.log(`any-budget:   ${total} of ${BUDGET} — at budget`)
}
