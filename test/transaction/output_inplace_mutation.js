'use strict'

/* global describe, it, beforeEach, afterEach */

// Ported from bsv 9.39.0's test/transaction/output_inplace_mutation.js, because this port has the
// identical shape: `output.script` hands out the live Script object, `toBufferWriter` writes
// `_scriptBuffer` — the bytes the output was SET from — so mutating the object is dropped from the
// transaction while `getSize()` measures the mutation. The size and the bytes then disagree and
// the fee is computed for an output that will not be broadcast.
//
// The behaviour is unchanged and deliberate. Since 1.7.0 `getSize()` says so, because that is the
// one place both byte strings have already been computed. The notice cannot fire without a
// mutation: parsing a script and re-encoding it is byte-faithful, which the last test pins.

require('chai').should()
const bsv = require('../..')
const deprecate = require('../../dist/util/deprecate')

describe('Output in-place script mutation', function () {
  let was, origWarn, warned
  beforeEach(function () {
    was = deprecate.isEnabled()
    deprecate.setEnabled(false)
    deprecate.reset()
    warned = []
    origWarn = console.warn
    console.warn = function (m) { warned.push(m) }
  })
  afterEach(function () {
    console.warn = origWarn
    deprecate.setEnabled(was)
    deprecate.reset()
  })

  function oneOutputTx () {
    const tx = new bsv.Transaction()
    tx.to(bsv.PrivateKey.fromRandom().toAddress(), 1000)
    return tx
  }

  it('drops a mutation made through the script getter from the serialized transaction', function () {
    const tx = oneOutputTx()
    const before = tx.toString()
    tx.outputs[0].script.add(bsv.Opcode.OP_NOP)
    tx.outputs[0].script.toASM().should.match(/OP_NOP$/)
    tx.toString().should.equal(before, 'the mutation must not reach the bytes without a re-set')
  })

  it('getSize() and the serialized length disagree after such a mutation', function () {
    const out = oneOutputTx().outputs[0]
    const serialized = out.toBufferWriter().toBuffer().length
    out.script.add(bsv.Opcode.OP_NOP)
    out.getSize().should.equal(serialized + 1)
    out.toBufferWriter().toBuffer().length.should.equal(serialized)
  })

  it('says so once, through the 1.7.0 notice', function () {
    deprecate.setEnabled(true)
    const out = oneOutputTx().outputs[0]
    out.script.add(bsv.Opcode.OP_NOP)
    deprecate.fired().length.should.equal(0, 'the mutation alone must not fire it')
    out.getSize()
    const fired = deprecate.fired()
    fired.length.should.equal(1)
    fired[0].what.should.equal('mutating a parsed output script in place and expecting it to serialize')
    fired[0].removeIn.should.equal('2.0.0')
    out.getSize()
    deprecate.fired().length.should.equal(1, 'warn once, not once per size enquiry')
    warned.length.should.equal(1)
  })

  it('stays silent when the object and the bytes agree', function () {
    deprecate.setEnabled(true)
    const out = oneOutputTx().outputs[0]
    out.getSize()
    out.script.toASM()
    out.getSize()
    deprecate.fired().length.should.equal(0)
  })

  it('stays silent on the null-script path, which answers from the raw bytes', function () {
    deprecate.setEnabled(true)
    const out = new bsv.Transaction.Output({ satoshis: 1000, script: Buffer.from('4c', 'hex') })
    out._script = null
    out.getSize().should.equal(8 + 1 + 1)
    out.getSize().should.equal(out.toBufferWriter().toBuffer().length)
    deprecate.fired().length.should.equal(0)
  })

  it('the documented remedy re-syncs the bytes', function () {
    const tx = oneOutputTx()
    const before = tx.toString()
    tx.outputs[0].script.add(bsv.Opcode.OP_NOP)
    tx.outputs[0].setScript(tx.outputs[0].script)
    tx.toString().should.not.equal(before)
    const out = tx.outputs[0]
    out.getSize().should.equal(out.toBufferWriter().toBuffer().length)
  })

  it('parse and re-encode is byte-faithful, which is why the notice has no false positives', function () {
    // Exhaustive over every script of two bytes or fewer, plus the shapes that would be the
    // candidates for a divergence. The full 0..3-byte sweep (16,843,009) and a 400,000-script
    // push-biased random sweep were run once in the JS library, both clean.
    const divergent = []
    function check (buf) {
      let out
      try { out = bsv.Script.fromBuffer(buf).toBuffer() } catch (e) { divergent.push([buf.toString('hex'), 'threw ' + e.message]); return }
      if (!out.equals(buf)) divergent.push([buf.toString('hex'), out.toString('hex')])
    }
    check(Buffer.alloc(0))
    for (let a = 0; a < 256; a++) {
      check(Buffer.from([a]))
      for (let b = 0; b < 256; b++) check(Buffer.from([a, b]))
    }
    ;['4c01ff', '4d0100ff', '4e01000000ff', '01ff', '6a4c', '6a4d01', '6a4e0100', '4c', '4c00',
      '4d0000', '4e00000000', '6a4c050102', '6a0548656c6c6f', 'ab'.repeat(600)
    ].forEach(function (hex) { check(Buffer.from(hex, 'hex')) })
    divergent.should.deep.equal([], 'a script that does not re-encode to its own bytes would make ' +
      'the 1.7.0 notice fire without any mutation')
  })

  it('an input mutated in place loses it too, and nothing there can see it for free', function () {
    const tx = new bsv.Transaction().from({
      txId: 'ab'.repeat(32),
      outputIndex: 0,
      script: bsv.Script.buildPublicKeyHashOut(bsv.PrivateKey.fromRandom().toAddress()).toHex(),
      satoshis: 5000
    })
    const before = tx.toString()
    tx.inputs[0].script.add(bsv.Opcode.OP_NOP)
    tx.toString().should.equal(before)
    tx.inputs[0].setScript(tx.inputs[0].script)
    tx.toString().should.not.equal(before)
  })
})
