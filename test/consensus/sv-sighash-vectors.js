'use strict'

/**
 * Transaction digest vectors from the SV Node — the regression gate.
 *
 * The work is in tools/sv-sighash-harness.js, ported from @smartledger/bsv with the
 * corpus, so both implementations answer to the node rather than to themselves. That
 * file documents the corpus layout and the node's routing.
 *
 * Unlike the script and transaction vectors, this one carries no known-failure
 * list. It has never had a failing row and there is no reason it should: a
 * digest is a pure function of a transaction and a hash type, with no era to
 * negotiate.
 */

require('chai').should()
const harness = require('../../tools/sv-sighash-harness')

describe('SV Node sighash vectors', function () {
  this.timeout(120000)

  const results = harness.runAll()

  it('covers the whole corpus', function () {
    results.length.should.equal(1000)
  })

  it('matches the node on both digest columns', function () {
    const failures = results.filter(r => !r.passed)
      .map(r => '#' + r.index + ' ' + r.reason)
    failures.slice(0, 8).should.deep.equal([],
      failures.length + ' of ' + results.length + ' rows disagree with the node')
  })

  it('routes every Chronicle-bit row to the original digest', function () {
    // Stated separately so a routing regression reads as one rather than as
    // hundreds of unexplained hash mismatches.
    const withBit = harness.chronicleRows()
    withBit.length.should.equal(511)
    withBit.forEach(v => v[4].should.equal(v[5]))
    results.filter(r => r.chronicleBit)
      .forEach(r => r.algorithm.should.equal('OTDA'))
  })

  it('still exercises both algorithms', function () {
    // Guards the test above: if the routing collapsed to OTDA everywhere it
    // would pass, and this is what would notice.
    results.filter(r => r.algorithm === 'BIP143').length.should.be.above(0)
    results.filter(r => r.algorithm === 'OTDA').length.should.be.above(0)
  })
})
