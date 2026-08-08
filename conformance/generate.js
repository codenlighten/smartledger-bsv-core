#!/usr/bin/env node
'use strict'

// Freeze the current library's observable behavior into fixtures.
//
//   node conformance/generate.js                 # generate all suites
//   node conformance/generate.js --suite=script  # regenerate one suite
//   node conformance/generate.js --lib=../new    # record a different impl
//   node conformance/generate.js --force         # allow overwriting fixtures
//
// Overwriting an existing fixture requires --force. Fixtures are the reference
// against which the rewrite is judged; silently regenerating them would let a
// regression rewrite its own baseline, which defeats the entire exercise.

const fs = require('fs')
const path = require('path')
const { loadSuites, runSuite, writeFixture, fixturePath, FIXTURES_DIR } = require('./lib/harness')
const selfcheck = require('./selfcheck')

function parseArgs (argv) {
  const args = { force: false, lib: null, suite: null }
  for (const a of argv.slice(2)) {
    if (a === '--force') args.force = true
    else if (a.startsWith('--lib=')) args.lib = a.slice(6)
    else if (a.startsWith('--suite=')) args.suite = a.slice(8)
    else throw new Error(`unknown argument: ${a}`)
  }
  return args
}

async function main () {
  const args = parseArgs(process.argv)
  const libPath = args.lib ? path.resolve(args.lib) : path.join(__dirname, '..', 'index.js')
  const bsv = require(libPath)

  console.log(`library:  ${libPath}`)
  console.log(`version:  ${bsv.version || '(unknown)'}`)
  console.log('')

  // Gate 1: published vectors must reproduce.
  const checks = selfcheck.run(bsv)
  const failed = checks.filter((c) => !c.ok)
  console.log(`selfcheck: ${checks.length - failed.length}/${checks.length} published vectors reproduce`)
  if (failed.length) {
    console.error('\nFAIL: published vectors disagree with the library.\n')
    for (const f of failed) {
      console.error(`  ${f.label}`)
      console.error(`    expected: ${f.expected}`)
      console.error(`    actual:   ${f.actual}`)
    }
    console.error('\nEither a vector in vectors.js is wrong, or the library is wrong.')
    console.error('Do not generate fixtures until this is resolved.')
    process.exit(1)
  }

  // Gate 2: never clobber an existing fixture without --force.
  const suites = loadSuites(args.suite)
  if (!suites.length) {
    console.error(args.suite ? `no suite named "${args.suite}"` : 'no suites found')
    process.exit(1)
  }
  if (!args.force) {
    const existing = suites.filter((s) => fs.existsSync(fixturePath(s.name)))
    if (existing.length) {
      console.error(`\nrefusing to overwrite existing fixtures: ${existing.map((s) => s.name).join(', ')}`)
      console.error('pass --force if you intend to move the baseline (and review the diff).')
      process.exit(1)
    }
  }

  let totalCases = 0
  let totalThrows = 0
  const summary = []

  for (const suite of suites) {
    const results = await runSuite(suite, bsv)
    const names = Object.keys(results)
    const throws = names.filter((n) => results[n].outcome === 'throws').length
    totalCases += names.length
    totalThrows += throws

    writeFixture(suite.name, {
      suite: suite.name,
      generatedBy: bsv.version || '(unknown)',
      caseCount: names.length,
      cases: results
    })

    summary.push({ suite: suite.name, cases: names.length, throws })
    console.log(`  ${suite.name.padEnd(16)} ${String(names.length).padStart(4)} cases  (${throws} reject)`)
  }

  fs.writeFileSync(
    path.join(FIXTURES_DIR, 'MANIFEST.json'),
    JSON.stringify({
      generatedBy: bsv.version || '(unknown)',
      node: process.version,
      suiteCount: suites.length,
      caseCount: totalCases,
      rejectCount: totalThrows,
      suites: summary
    }, null, 2) + '\n'
  )

  console.log('')
  console.log(`total: ${totalCases} cases across ${suites.length} suites (${totalThrows} record a rejection)`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
