'use strict'

/* global describe, it, afterEach */

// Regression: the secrets.js RNG callback re-draws on an all-zero draw. A broken
// or stubbed CSPRNG that returns all-zero bytes forever (e.g. a bundle mocking
// node crypto to Buffer.alloc) previously made that loop spin forever. The bounded
// loop now throws a clear error instead of hanging.

const assert = require('assert')
const Shamir = require('../../lib/crypto/shamir')
const Random = require('../../lib/crypto/random')

describe('Shamir RNG degenerate-source cap', function () {
  const orig = Random.getRandomBuffer
  afterEach(function () { Random.getRandomBuffer = orig })

  it('throws (does not hang) when the CSPRNG is stuck returning all zeros', function () {
    Random.getRandomBuffer = function (n) { return Buffer.alloc(n, 0) }
    assert.throws(function () {
      Shamir.split('secret', 2, 3)
    }, /all-zero|degenerate/)
  })

  it('still splits/combines normally with a healthy CSPRNG', function () {
    const shares = Shamir.split('round-trip', 2, 3)
    assert.strictEqual(Shamir.combine(shares.slice(0, 2)).toString('utf8'), 'round-trip')
  })
})
