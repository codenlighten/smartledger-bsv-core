'use strict'

/**
 * Row-by-row delta between this package and @smartledger/bsv on the SV Node
 * script vectors: every row where the two disagree, grouped by what the node
 * expects. Each is a porting target, since the library passes the whole corpus.
 *
 *   npm run vectors:sv-delta -- --lib=../smartledger-bsv
 *   npm run vectors:sv-delta -- --lib=/path/to/node_modules/@smartledger/bsv
 *
 * Both are scored by tools/sv-vector-harness.js with the same flags, so a row
 * listed here differs because the implementations do, not the harness. Pass
 * --node-flags-only to score both without granting MONOLITH/MAGNETIC.
 *
 * Reports only: it exits 0 whatever it finds, and non-zero only when it could
 * not compare (no --lib, or the two runs scored different rows).
 */

const path = require('path')
const harness = require('./sv-vector-harness')

const libArg = process.argv.find(a => a.startsWith('--lib='))
if (!libArg) {
  console.error('usage: node tools/sv-vector-delta.js --lib=<path to @smartledger/bsv>')
  process.exit(2)
}
const nodeFlagsOnly = process.argv.indexOf('--node-flags-only') !== -1
const opts = { nodeFlagsOnly }

const core = harness.runAll(opts)
const libPath = path.resolve(libArg.slice('--lib='.length))
const lib = require(libPath)
harness.use(lib)
const other = harness.runAll(opts)

function outcome (r) {
  if (r.passed) return r.row.expected === 'OK' ? 'OK' : 'rejects ' + (r.gotCode || '?')
  if (r.direction === 'accept') return 'ACCEPTS'
  return r.gotErrstr ? 'rejects ' + harness.errorCode(r.gotErrstr) : String(r.reason).slice(0, 40)
}

const byIndex = new Map(other.map(r => [r.index, r]))
// Same corpus, same parser: every row should be scored by both. Say so plainly
// if not, rather than comparing a row with nothing.
const missing = core.filter(r => !byIndex.has(r.index)).map(r => r.index)
if (missing.length || other.length !== core.length) {
  console.error('the two runs scored different rows; not comparable. Missing: ' + missing.join(', '))
  process.exit(1)
}
const delta = core.filter(r => byIndex.get(r.index).passed !== r.passed)

console.log()
console.log('=== SV Node v1.2.2 script vectors: this package vs @smartledger/bsv ' +
  (lib.version || '') + ' ===')
console.log('library     :', libPath)
console.log('flags       :', nodeFlagsOnly ? 'node flags only' : 'node flags + MONOLITH/MAGNETIC, as both harnesses run')
console.log()
console.log('this package passes :', core.filter(r => r.passed).length + '/' + core.length)
console.log('library passes      :', other.filter(r => r.passed).length + '/' + other.length)
console.log('rows that differ    :', delta.length,
  ' (this package fails, library passes: ' + delta.filter(r => !r.passed).length +
  '; the reverse: ' + delta.filter(r => r.passed).length + ')')

const groups = {}
delta.forEach(function (r) {
  const key = 'node ' + r.row.expected + (r.direction === 'accept' ? '  — FALSE ACCEPT here' : '')
  ;(groups[key] = groups[key] || []).push(r)
})
Object.keys(groups).sort((a, b) => groups[b].length - groups[a].length).forEach(function (k) {
  console.log()
  console.log('--- ' + k + '  (' + groups[k].length + ') ---')
  groups[k].forEach(function (r) {
    console.log('  ' + String(r.index).padStart(5) +
      '  here: ' + outcome(r).padEnd(34) + ' library: ' + outcome(byIndex.get(r.index)))
    console.log('         ' + harness.describe(r.row))
  })
})
// Both reject, but for different reasons: the outcome is right here and the
// node's reason is not. The library reports the node's reason (or a documented
// narrower name) on every such row, so these are porting targets too.
const reasonDelta = core.filter(function (r) {
  const o = byIndex.get(r.index)
  return r.codeMatches === false && o.codeMatches === true
})
console.log()
console.log('--- same outcome, wrong reason here (' + reasonDelta.length + ') ---')
reasonDelta.forEach(function (r) {
  console.log('  ' + String(r.index).padStart(5) + '  node ' + String(r.expectedCode).padEnd(24) +
    ' here ' + String(r.gotCode).padEnd(22) + ' library ' + byIndex.get(r.index).gotCode)
  console.log('         ' + harness.describe(r.row))
})
const reverseReason = core.filter(function (r) {
  return r.codeMatches === true && byIndex.get(r.index).codeMatches === false
})
console.log('  (the reverse, right here and wrong in the library: ' + reverseReason.length +
  (reverseReason.length ? ', rows ' + reverseReason.map(r => r.index).join(', ') : '') + ')')
console.log()
