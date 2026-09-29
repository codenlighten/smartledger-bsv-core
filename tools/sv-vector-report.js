'use strict'

/**
 * How far this interpreter is from the reference node.
 *
 *   npm run vectors:sv
 *   npm run vectors:sv -- --verbose          # also print each failing script
 *   npm run vectors:sv -- --node-flags-only  # don't grant MONOLITH/MAGNETIC
 *
 * Adapted from @smartledger/bsv tools/sv-vector-report.js (the JavaScript library this package
 * ports), so the two report the same corpus through the same logic and their
 * figures can be compared line for line. In this package it REPORTS and does not
 * gate: the numbers are expected to move while the port reaches parity with the
 * node, after which it becomes a gate. Build first (`npm run build`); it measures
 * dist/, which is what ships.
 *
 * Reports only: it always exits 0.
 *
 * False accepts are listed first and separately. Accepting a script the
 * network rejects is the direction that can cost money; rejecting one it
 * accepts only costs a transaction.
 */

const harness = require('./sv-vector-harness')

const verbose = process.argv.indexOf('--verbose') !== -1
const nodeFlagsOnly = process.argv.indexOf('--node-flags-only') !== -1
const results = harness.runAll({ nodeFlagsOnly })

const failing = results.filter(r => !r.passed)
const accepts = failing.filter(r => r.direction === 'accept')
const rejects = failing.filter(r => r.direction === 'reject')
const passing = results.length - failing.length

console.log()
console.log('=== SV Node v1.2.2 script vectors ===' +
  (nodeFlagsOnly ? '  (node flags only: MONOLITH/MAGNETIC not granted)' : ''))
console.log()
console.log('vectors run   :', results.length)
console.log('passing       :', passing,
  ' (' + (100 * passing / results.length).toFixed(1) + '%)')
console.log('failing       :', failing.length,
  ' (' + (100 * failing.length / results.length).toFixed(1) + '%)')
console.log()
console.log('--- direction ---')
console.log('  false accepts (we accept, node rejects) :', accepts.length,
  accepts.length ? '  <- the direction that can cost money' : '')
console.log('  false rejects (we reject, node accepts) :', rejects.length)

const comparable = results.filter(r => r.codeMatches !== null)
const wrongCode = comparable.filter(r => !r.codeMatches)
const aliased = comparable.filter(r => r.codeMatches && r.gotCode !== r.expectedCode)
console.log()
console.log('--- result codes, on the', comparable.length, 'vectors the node rejects ---')
console.log('  exact match                             :',
  comparable.length - wrongCode.length - aliased.length)
console.log('  matched via a documented narrower name  :', aliased.length)
console.log('  wrong reason                            :', wrongCode.length,
  wrongCode.length ? '  <- the outcome is right, the reason is not' : '')

if (wrongCode.length) {
  const byCode = {}
  wrongCode.forEach(function (r) {
    const key = r.expectedCode + '  <-  ' + (r.gotCode || '(none)')
    byCode[key] = (byCode[key] || 0) + 1
  })
  Object.keys(byCode).sort((a, b) => byCode[b] - byCode[a])
    .forEach(k => console.log(String(byCode[k]).padStart(5), k))
}

const byReason = {}
failing.forEach(function (r) {
  const key = String(r.reason).replace(/vector.*/, '').slice(0, 62)
  byReason[key] = (byReason[key] || 0) + 1
})
console.log()
console.log('--- failure reasons ---')
Object.keys(byReason).sort((a, b) => byReason[b] - byReason[a]).slice(0, 16)
  .forEach(k => console.log(String(byReason[k]).padStart(5), k))

if (accepts.length) {
  console.log()
  console.log('--- false accepts ---')
  accepts.slice(0, verbose ? accepts.length : 10).forEach(function (r) {
    console.log('  ' + r.id + '  ' + harness.describe(r.row))
  })
  if (!verbose && accepts.length > 10) {
    console.log('  ... and ' + (accepts.length - 10) + ' more; pass --verbose')
  }
}

// Every failing row, always: this report exists so the list shrinks visibly.
console.log()
console.log('--- every failing row: index in script_tests.json, node expects, we got ---')
failing.forEach(function (r) {
  let got = String(r.reason)
  if (r.direction === 'accept') got = 'ACCEPTED'
  else if (r.gotErrstr) got = harness.errorCode(r.gotErrstr)
  console.log('  ' + String(r.index).padStart(5) + '  ' +
    (r.direction === 'accept' ? 'FALSE-ACCEPT' : 'false-reject') +
    '  node ' + String(r.row.expected).padEnd(24) + ' got ' + got)
  if (verbose) console.log('         ' + harness.describe(r.row))
})
console.log()
