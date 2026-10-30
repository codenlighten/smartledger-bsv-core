'use strict'

/* global describe, it, afterEach */

// A SECURITY option must come from the options object the caller handed in, never from its
// prototype chain. Plain `opts.requirePow !== false` also reads `Object.prototype.requirePow`, so
// prototype pollution elsewhere in the process switched proof-of-work checking off for every
// caller that passed `{}` or nothing: on 9.44.0 a header whose work fails and whose merkle root
// matches came back `valid: true`.
//
// Each case sets the relaxing value on Object.prototype and asserts the outcome equals the
// outcome with no pollution. The control half matters: it proves the guard being tested is
// really on in the unpolluted state, so the pollution is what would turn it off. Each key is
// deleted in a finally block and afterEach checks nothing leaked into other tests.

require('chai').should()
const assert = require('assert')
const bsv = require('../..')
const ownOption = require('../../dist/util/own-option')

const KEYS = ['requirePow', 'trustedHash', 'disableMoreOutputThanInput', 'disableLargeFees',
  'disableDustOutputs', 'disableIsFullySigned', 'powLimit', 'minWork',
  'skipAnchor', 'allowUncheckedSeal', 'allowUnknownSpvFormat', 'allowLowValue', 'disableAll',
  'afterChronicle', 'noSorting', 'allowEmptyLock', 'validate', 'max']

// Pollution has two acceptable outcomes: the call behaves exactly as it does unpolluted, or it is
// REFUSED with the "inherited from the prototype chain" error. What it must never do is read the
// inherited value as the caller's choice. An AssertionError inside fn is not a refusal.
const REFUSAL = /inherited from the prototype chain/

function polluted (key, value, fn) {
  Object.defineProperty(Object.prototype, key, { value, configurable: true, writable: true }) // eslint-disable-line no-extend-native
  try {
    return fn()
  } catch (e) {
    if (e && REFUSAL.test(e.message)) return 'refused'
    throw e
  } finally { delete Object.prototype[key] }
}

function outcome (fn) {
  try { return { value: fn() } } catch (e) { return { threw: e.message } }
}

function rev (b) { return Buffer.from(b).reverse().toString('hex') }

describe('security: options are read as OWN properties only', function () {
  afterEach(function () {
    KEYS.forEach(function (k) {
      assert.strictEqual(Object.hasOwn(Object.prototype, k), false,
        'Object.prototype.' + k + ' leaked out of a test')
    })
  })

  describe('ownOption', function () {
    it('returns an own value, including a falsy one', function () {
      ownOption({ a: false }, 'a').should.equal(false)
      ownOption({ a: 0 }, 'a').should.equal(0)
    })
    it('refuses an inherited value instead of reading it as absent', function () {
      assert.throws(function () { ownOption(Object.create({ a: false }), 'a') }, REFUSAL)
      assert.throws(function () { ownOption({}, 'toString') }, REFUSAL)
    })
    it('a tightening option built with Object.create(defaults) is refused, not silently dropped', function () {
      const opts = Object.assign(Object.create({ minWork: '1' + '0'.repeat(40) }), { txid: 'x' })
      assert.throws(function () { ownOption(opts, 'minWork') }, REFUSAL)
    })
    it('reads an own value on Object.create(null) and ignores a symbol key', function () {
      const o = Object.create(null)
      o.a = 1
      ownOption(o, 'a').should.equal(1)
      assert.strictEqual(ownOption({ [Symbol('a')]: 1 }, 'a'), undefined)
    })
    it('reads an own accessor, and treats a non-object as having no options', function () {
      ownOption(Object.defineProperty({}, 'a', { get: function () { return 7 }, enumerable: true }), 'a').should.equal(7)
      assert.strictEqual(ownOption(undefined, 'a'), undefined)
      assert.strictEqual(ownOption(null, 'a'), undefined)
      assert.strictEqual(ownOption('requirePow', 'length'), undefined)
    })
  })

  describe('SPV proof of work', function () {
    const H = bsv.crypto.Hash
    const a = Buffer.alloc(32, 1)
    const b = Buffer.alloc(32, 2)
    const header = Buffer.alloc(80)
    header.writeInt32LE(1, 0)
    H.sha256sha256(Buffer.concat([a, b])).copy(header, 36)
    header.writeUInt32LE(1700000000, 68)
    header.writeUInt32LE(0x1d00ffff, 72)
    header.writeUInt32LE(12345, 76) // a nonce that does not meet the target

    function inclusion () {
      return bsv.SPV.verifyTxInclusion({ txid: rev(a), index: 0, nodes: [rev(b)], header })
    }

    it('control: a header whose work fails is refused by default', function () {
      const r = inclusion()
      r.rootMatches.should.equal(true)
      r.powValid.should.equal(false)
      r.valid.should.equal(false)
    })

    it('an inherited requirePow=false does not turn the check off', function () {
      polluted('requirePow', false, function () { inclusion().valid.should.equal(false) })
    })

    // A header that declares an easy target (0x207fffff, regtest) and meets it. By default its
    // declared target is above the powLimit, so it is refused as too easy; a powLimit inherited
    // from the prototype chain would raise that ceiling and let a forged header through.
    function easyHeader () {
      const h = Buffer.from(header)
      h.writeUInt32LE(0x207fffff, 72)
      for (let nonce = 0; nonce < 1000; nonce++) {
        h.writeUInt32LE(nonce, 76)
        const r = bsv.SPV.verifyTxInclusion({ txid: rev(a), index: 0, nodes: [rev(b)], header: h, powLimit: 0x207fffff })
        if (r.powValid) return h
      }
      throw new Error('no nonce met the easy target')
    }

    it('control: a header declaring a target above the powLimit is refused by default', function () {
      const h = easyHeader()
      const r = bsv.SPV.verifyTxInclusion({ txid: rev(a), index: 0, nodes: [rev(b)], header: h })
      r.powValid.should.equal(true)
      r.targetAllowed.should.equal(false)
      r.valid.should.equal(false)
    })

    it('an inherited powLimit does not raise the ceiling on the declared target', function () {
      const h = easyHeader()
      polluted('powLimit', 0x207fffff, function () {
        const r = bsv.SPV.verifyTxInclusion({ txid: rev(a), index: 0, nodes: [rev(b)], header: h })
        r.targetAllowed.should.equal(false)
        r.valid.should.equal(false)
      })
    })

    it('an inherited requirePow=false does not weaken verifyHeaderChain', function () {
      const control = outcome(function () { return bsv.SPV.verifyHeaderChain([header]) })
      const got = polluted('requirePow', false, function () {
        return outcome(function () { return bsv.SPV.verifyHeaderChain([header]) })
      })
      if (got.threw !== undefined && REFUSAL.test(got.threw)) return
      JSON.stringify(got).should.equal(JSON.stringify(control))
    })
  })

  describe('Transaction serialization checks', function () {
    function overspend () {
      const key = new bsv.PrivateKey()
      const addr = key.toAddress()
      const tx = new bsv.Transaction().from({
        txId: '11'.repeat(32),
        outputIndex: 0,
        script: bsv.Script.buildPublicKeyHashOut(addr).toHex(),
        satoshis: 100000
      })
      tx.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(addr), satoshis: 5000000 }))
      return tx.sign(key)
    }

    it('control: an overspend is refused by default', function () {
      assert.ok(overspend().getSerializationError())
    })

    it('inherited disable* flags do not switch the checks off', function () {
      ;['disableMoreOutputThanInput', 'disableLargeFees', 'disableDustOutputs', 'disableIsFullySigned']
        .forEach(function (k) {
          polluted(k, true, function () {
            assert.ok(overspend().getSerializationError(), k + ' inherited from Object.prototype switched a check off')
          })
        })
    })

    it('an own disable flag still works (the option is not removed)', function () {
      const tx = overspend()
      const err = tx.getSerializationError({ disableMoreOutputThanInput: true })
      const control = tx.getSerializationError()
      assert.notStrictEqual(err && err.message, control && control.message)
    })
  })

  describe('flags, serialization, scripts and inscriptions', function () {
    const Interpreter = bsv.Script.Interpreter

    it('an inherited afterChronicle=false does not drop the Chronicle flags from mainnetFlags()', function () {
      const control = Interpreter.mainnetFlags()
      ;(control & Interpreter.SCRIPT_ENABLE_CHRONICLE).should.not.equal(0)
      polluted('afterChronicle', false, function () {
        Interpreter.mainnetFlags().should.equal(control)
      })
      ;(Interpreter.mainnetFlags({ afterChronicle: false }) & Interpreter.SCRIPT_ENABLE_CHRONICLE).should.equal(0)
    })

    it('an inherited disableAll does not make serialize() skip every check', function () {
      const key = new bsv.PrivateKey()
      const addr = key.toAddress()
      const tx = new bsv.Transaction().from({
        txId: '11'.repeat(32),
        outputIndex: 0,
        script: bsv.Script.buildPublicKeyHashOut(addr).toHex(),
        satoshis: 100000
      })
      tx.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(addr), satoshis: 5000000 }))
      tx.sign(key)
      assert.throws(function () { tx.serialize({}) })
      polluted('disableAll', true, function () {
        assert.throws(function () { tx.serialize({}) })
      })
      assert.strictEqual(typeof tx.serialize({ disableAll: true }), 'string')
    })

    it('an inherited max does not rewrite the process-wide consensus limits', function () {
      const snap = () => [Interpreter.MAX_SCRIPT_ELEMENT_SIZE, Interpreter.MAX_SCRIPT_SIZE, Interpreter.MAX_OPS_PER_SCRIPT]
      Interpreter.useMainnetConsensus({})
      const control = snap()
      try {
        polluted('max', 123, () => { Interpreter.useMainnetConsensus({}) })
        snap().should.deep.equal(control)
      } finally { Interpreter.useMainnetConsensus({}) }
    })

    it('an inherited noSorting does not change the order of a multisig lock', function () {
      const keys = [new bsv.PrivateKey(), new bsv.PrivateKey(), new bsv.PrivateKey()].map(function (k) { return k.toPublicKey() })
      const control = bsv.Script.buildMultisigOut(keys, 2).toHex()
      polluted('noSorting', true, function () {
        bsv.Script.buildMultisigOut(keys, 2).toHex().should.equal(control)
      })
    })

    it('an inherited allowEmptyLock does not let an inscription carry no lock', function () {
      const build = function () { return bsv.Ordinals.buildInscription({ lock: new bsv.Script(), contentType: 'text/plain', data: Buffer.from('x') }) }
      assert.throws(build, /lock is empty/)
      polluted('allowEmptyLock', true, function () { assert.throws(build, /lock is empty/) })
    })
  })
})
