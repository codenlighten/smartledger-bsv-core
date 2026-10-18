'use strict'

/* global describe, it, beforeEach, afterEach */

// Runtime deprecation notices, and the first API marked with one.
//
// Ported from @smartledger/bsv (9.1.0 for the mechanism, 9.17.0 for Script.fromHex) so
// the two libraries mark the same APIs with the same wording and the same env switch.
//
// The property under test is not "it prints". It is that marking an API is a NON-breaking
// act: the notice fires once, it is silenceable, and the function still returns exactly
// what it returned before. A deprecation that changes behaviour is just a breaking change
// wearing a warning's name.

require('chai').should()
const bsv = require('../..')
const deprecate = bsv.util.deprecate
const Script = bsv.Script

describe('util/deprecate', function () {
  beforeEach(function () {
    deprecate.reset()
    deprecate.setEnabled(false) // keep the suite's output clean; `fired` is still recorded
  })
  afterEach(function () {
    deprecate.reset()
    deprecate.setEnabled(true)
  })

  it('fires once per `what`, however many times it is called', function () {
    deprecate({ what: 'A' }).should.equal(true)
    deprecate({ what: 'A' }).should.equal(false)
    deprecate({ what: 'A' }).should.equal(false)
    deprecate.fired().length.should.equal(1)
  })

  it('keys on `what`, so two different APIs each get their own notice', function () {
    deprecate({ what: 'A' })
    deprecate({ what: 'B' })
    deprecate.fired().map(function (f) { return f.what }).should.deep.equal(['A', 'B'])
  })

  it('records what fired even when output is silenced', function () {
    deprecate.isEnabled().should.equal(false)
    deprecate({ what: 'A', since: '1.1.0', removeIn: '2.0.0' })
    const f = deprecate.fired()[0]
    f.since.should.equal('1.1.0')
    f.removeIn.should.equal('2.0.0')
  })

  it('names the version that will break the caller, or says none is set', function () {
    deprecate({ what: 'A', since: '1.1.0', removeIn: '2.0.0', use: 'B', why: 'it is wrong' })
    deprecate.fired()[0].message.should.equal(
      '[@smartledger/bsv-core] A is deprecated since 1.1.0. It is wrong. Use B instead. ' +
      'It will be removed in 2.0.0.')

    deprecate({ what: 'C' })
    deprecate.fired()[1].message.should.equal(
      '[@smartledger/bsv-core] C is deprecated. A removal version has not been set; ' +
      'it will not be removed in a 1.x release.')
  })

  it('refuses to be set up without a `what` — at wrapping time, not call time', function () {
    // Deferring this check meant `deprecate.fn(f)` wrapped cleanly and then threw on every
    // subsequent call, turning a deprecation into the breaking change it exists to avoid,
    // at a call site far from the mistake.
    ;(function () { deprecate.fn(function () {}) }).should.throw(/requires \{ what: string \}/)
    ;(function () { deprecate.fn(function () {}, { what: '' }) }).should.throw(/requires \{ what: string \}/)
    ;(function () { deprecate.fn('not a function', { what: 'A' }) }).should.throw(/requires a function/)
  })

  it('wraps a function without changing what it does', function () {
    const wrapped = deprecate.fn(function add (a, b) { return a + b }, { what: 'add' })
    wrapped(2, 3).should.equal(5)
    wrapped(2, 3).should.equal(5)
    wrapped.name.should.equal('add')
    wrapped.length.should.equal(2)
    deprecate.fired().length.should.equal(1)
  })

  it('keeps `this` when it wraps a prototype method', function () {
    function K (v) { this.v = v }
    K.prototype.get = deprecate.fn(function () { return this.v }, { what: 'K#get' })
    new K(7).get().should.equal(7)
  })

  it('warns on first read of a deprecated property, and computes it once', function () {
    const target = {}
    let calls = 0
    deprecate.property(target, 'old', function () { calls++; return 'value' }, { what: 'old' })
    target.old.should.equal('value')
    target.old.should.equal('value')
    calls.should.equal(1)
    deprecate.fired().length.should.equal(1)
  })

  describe('Script.fromHex() with a string that is not whole hex', function () {
    // `Buffer.from(str, 'hex')` stops at the first character it cannot decode and returns
    // what it had, so a malformed string yields a SHORTER script, or none, instead of an
    // error. Refusing it outright is a breaking change, so 1.1.0 marks it and 2.0.0 throws.

    it('warns, and still returns the truncated script it always returned', function () {
      Script.fromHex('76a914deadbeefZZZZ88ac').toHex().should.equal('76a914deadbeef')
      deprecate.fired().length.should.equal(1)
      deprecate.fired()[0].what.should.equal(
        'Script.fromHex() with a string that is not whole hex')
      deprecate.fired()[0].removeIn.should.equal('2.0.0')
    })

    it('catches an odd number of digits, which isHexa() alone does not', function () {
      // '76a91' is "hex" by isHexa and still drops its last nibble.
      Script.fromHex('76a91').toHex().should.equal('76a9')
      deprecate.fired().length.should.equal(1)
    })

    it('says nothing about a string that does decode whole', function () {
      const whole = '76a914' + 'ab'.repeat(20) + '88ac'
      Script.fromHex(whole).toHex().should.equal(whole)
      Script.fromHex('').toHex().should.equal('')
      Script.fromHex(whole.toUpperCase()).toHex().should.equal(whole)
      deprecate.fired().length.should.equal(0)
    })
  })
  describe('the plan id is carried into the record', function () {
    it('fired() exposes the stable plan id, not only the prose', function () {
      deprecate.reset()
      deprecate({ what: 'X#y', since: '1.10.0', removeIn: '2.0.0', plan: 'x-y-planned', use: 'X#z' })
      var rec = deprecate.fired()[0]
      rec.plan.should.equal('x-y-planned')
      rec.what.should.equal('X#y')
      // docs/RELEASE-2.0.0.md keys on the id and shares it with the sibling package, so it has
      // to be readable at runtime and not only parsed out of the source by the plan guard
      rec.message.indexOf('x-y-planned').should.equal(-1, 'the id is never printed')
    })

    it('is null when a notice declares no plan, rather than absent', function () {
      deprecate.reset()
      deprecate({ what: 'A#b' })
      ;(deprecate.fired()[0].plan === null).should.equal(true)
    })
  })
})
