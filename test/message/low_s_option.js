'use strict'

/* global describe, it, beforeEach, afterEach */

// Ported from bsv 9.38.0's test/message/low_s_option.js, and the port exists because of what
// 1.7.0 did: it ACCEPTED `{ lowS: true }` and ignored it. JavaScript does not object to an extra
// argument, so the twin verified `true` with no error and no warning, while the sibling package's
// docs/RELIED-UPON-PROPERTIES.md told integrators to make exactly that call. A strictness option
// that silently does nothing is worse than no option, because the call then sits in the caller's
// code as evidence the hazard was handled.
//
// What the option does and does not do: it refuses ONE twin — the same `r` with `s` replaced by
// `n - s`, carried in a second compact string. It does not make a signature unique per
// (key, message); the set of valid low-s signatures over a message is as large as the nonce space.

require('chai').should()
const bsv = require('../..')
const deprecate = require('../../dist/util/deprecate')
const BN = bsv.crypto.BN

describe('Message low-s option', function () {
  const priv = bsv.PrivateKey.fromBuffer(Buffer.from('6d'.repeat(32), 'hex'))
  const address = priv.toAddress().toString()
  const message = 'authority: release funds to alice'

  function twinOf (sigB64) {
    const raw = Buffer.from(sigB64, 'base64')
    const recid = (raw[0] - 31) & 3
    const n = bsv.crypto.Point.getN()
    const s = BN.fromBuffer(raw.slice(33, 65))
    // in-domain flip: the header must stay inside 31..34, or the parser throws and the test
    // measures the parser instead of the rule
    return Buffer.concat([
      Buffer.from([31 + (recid ^ 1)]),
      raw.slice(1, 33),
      n.sub(s).toBuffer({ size: 32 })
    ]).toString('base64')
  }

  let was, origWarn
  beforeEach(function () {
    was = deprecate.isEnabled()
    deprecate.setEnabled(false)
    deprecate.reset()
    origWarn = console.warn
    console.warn = function () {}
  })
  afterEach(function () {
    console.warn = origWarn
    deprecate.setEnabled(was)
    deprecate.reset()
  })

  it('the option is a real parameter, not an ignored extra argument', function () {
    bsv.Message.prototype.verify.length.should.equal(3)
    bsv.Message.verify.length.should.equal(4)
  })

  it('accepts what sign() produces, with and without the option', function () {
    const sig = bsv.Message(message).sign(priv)
    bsv.Message(message).verify(address, sig).should.equal(true)
    bsv.Message(message).verify(address, sig, { lowS: true }).should.equal(true)
  })

  it('verifies the high-s twin by default, and refuses it with the option', function () {
    const twin = twinOf(bsv.Message(message).sign(priv))
    bsv.Message(message).verify(address, twin).should.equal(true)
    const m = bsv.Message(message)
    m.verify(address, twin, { lowS: true }).should.equal(false)
    m.error.should.equal('The signature is not canonical: s is above half the curve order')
  })

  it('forwards the option through the static form', function () {
    const twin = twinOf(bsv.Message(message).sign(priv))
    bsv.Message.verify(message, address, twin).should.equal(true)
    bsv.Message.verify(message, address, twin, { lowS: true }).should.equal(false)
  })

  it('fires the notice only when a high-s signature is actually accepted', function () {
    deprecate.setEnabled(true)
    const sig = bsv.Message(message).sign(priv)
    bsv.Message(message).verify(address, sig)
    deprecate.fired().length.should.equal(0, 'a canonical signature must raise nothing')
    bsv.Message(message).verify(address, twinOf(sig), { lowS: true })
    deprecate.fired().length.should.equal(0, 'a refusal must raise nothing either')
    bsv.Message(message).verify(address, twinOf(sig))
    const fired = deprecate.fired()
    fired.length.should.equal(1)
    fired[0].what.should.equal('Message#verify() accepting a non-canonical (high-s) signature')
    fired[0].since.should.equal('1.8.0')
    fired[0].removeIn.should.equal('2.0.0')
  })

  it('the behavioural probe the sibling package documents passes here', function () {
    // An arity check would pass on a build that wired the parameter and ignored it, which is
    // exactly what 1.7.0 did, so the probe tests behaviour.
    const twin = twinOf(bsv.Message(message).sign(priv))
    const works = bsv.Message(message).verify(address, twin) === true &&
      bsv.Message(message).verify(address, twin, { lowS: true }) === false
    works.should.equal(true)
  })

  it('the option does not make a signature unique: distinct low-s signatures all pass it', function () {
    const magic = bsv.Message(message).magicHash()
    const sigs = []
    for (let i = 0; i < 4; i++) {
      const e = new bsv.crypto.ECDSA()
      e.hashbuf = magic
      e.privkey = priv
      e.pubkey = priv.toPublicKey()
      if (i > 0) e.set({ k: BN.fromBuffer(bsv.crypto.Hash.sha256(Buffer.from('nonce' + i, 'utf8'))) })
      e.sign()
      e.calci()
      sigs.push(e.sig.toCompact().toString('base64'))
    }
    const distinct = {}
    sigs.forEach(function (b64) {
      distinct[b64] = true
      bsv.Message(message).verify(address, b64, { lowS: true }).should.equal(true)
    })
    Object.keys(distinct).length.should.equal(sigs.length, 'each nonce must give a different signature')
  })
})
