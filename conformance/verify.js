#!/usr/bin/env node
'use strict'

// Replay the corpus against an implementation and report any behavior change.
//
//   node conformance/verify.js                      # verify current library
//   node conformance/verify.js --lib=../bsv-core    # verify the rewrite
//   node conformance/verify.js --errors=full        # also compare error wording
//   node conformance/verify.js --suite=script
//
// Exit code is non-zero on any diff, so this drops straight into CI.

const path = require('path')
const { loadSuites, runSuite, readFixture, compare } = require('./lib/harness')
const selfcheck = require('./selfcheck')

function parseArgs (argv) {
  const args = { lib: null, suite: null, errors: 'name', quiet: false }
  for (const a of argv.slice(2)) {
    if (a.startsWith('--lib=')) args.lib = a.slice(6)
    else if (a.startsWith('--suite=')) args.suite = a.slice(8)
    else if (a.startsWith('--errors=')) args.errors = a.slice(9)
    else if (a === '--quiet') args.quiet = true
    else throw new Error(`unknown argument: ${a}`)
  }
  if (!['name', 'full'].includes(args.errors)) {
    throw new Error(`--errors must be "name" or "full", got "${args.errors}"`)
  }
  return args
}

function preview (v) {
  const s = typeof v === 'string' ? v : JSON.stringify(v)
  if (s === undefined) return String(v)
  return s.length > 160 ? s.slice(0, 157) + '...' : s
}

async function main () {
  const args = parseArgs(process.argv)
  const libPath = args.lib ? path.resolve(args.lib) : path.join(__dirname, '..', 'index.js')
  const bsv = require(libPath)

  console.log(`library:  ${libPath}`)
  console.log(`version:  ${bsv.version || '(unknown)'}`)
  console.log(`errors:   compared by ${args.errors === 'full' ? 'name and message' : 'name only'}`)
  console.log('')

  const checks = selfcheck.run(bsv)
  const checkFails = checks.filter((c) => !c.ok)
  if (checkFails.length) {
    console.error(`selfcheck: FAILED ${checkFails.length}/${checks.length} published vectors\n`)
    for (const f of checkFails) {
      console.error(`  ${f.label}\n    expected: ${f.expected}\n    actual:   ${f.actual}`)
    }
    process.exitCode = 1
  } else {
    console.log(`selfcheck: ${checks.length}/${checks.length} published vectors reproduce`)
  }

  const suites = loadSuites(args.suite)
  let totalDiffs = 0
  let totalCases = 0
  const missingFixtures = []

  for (const suite of suites) {
    const fixture = readFixture(suite.name)
    if (!fixture) {
      missingFixtures.push(suite.name)
      continue
    }
    const actual = await runSuite(suite, bsv)
    const diffs = compare(fixture.cases, actual, args.errors)
    totalCases += Object.keys(actual).length
    totalDiffs += diffs.length

    const status = diffs.length ? `${diffs.length} DIFF` : 'ok'
    console.log(`  ${suite.name.padEnd(16)} ${String(Object.keys(actual).length).padStart(4)} cases  ${status}`)

    if (diffs.length && !args.quiet) {
      // Outcome flips first — an input that was rejected and now succeeds (or
      // vice versa) is the most dangerous class of change.
      const order = { outcome: 0, error: 1, value: 2, missing: 3, added: 4 }
      diffs.sort((a, b) => order[a.kind] - order[b.kind])
      for (const d of diffs) {
        console.log(`      [${d.kind}] ${d.case}`)
        console.log(`        ${d.detail}`)
        if (d.expected !== undefined) console.log(`        fixture: ${preview(d.expected)}`)
        if (d.actual !== undefined) console.log(`        run:     ${preview(d.actual)}`)
      }
    }
  }

  console.log('')
  if (missingFixtures.length) {
    console.log(`no fixture recorded for: ${missingFixtures.join(', ')}`)
  }
  if (totalDiffs) {
    console.log(`FAIL: ${totalDiffs} difference(s) across ${totalCases} cases`)
    process.exitCode = 1
  } else {
    console.log(`PASS: ${totalCases} cases match the corpus`)
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
