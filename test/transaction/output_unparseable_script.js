'use strict'

/* global describe, it */

// An output script the node ACCEPTS and MINES can be one our parser cannot decode.
//
// Post-Genesis a top-level OP_RETURN terminates evaluation as successful before the rest of
// the script is reached — the node's own comment says the remainder "does not affect the
// validity (even in presence of unbalanced IFs, invalid opcodes etc)". So `6a4c`, `6a4d01`
// and `6a4e0100` — OP_RETURN followed by a push whose LENGTH FIELD is cut off — are valid
// locking scripts. Measured 2026-10-13 on a compiled node by two independent harnesses; one
// funded each lock, broadcast the spend and MINED it, so such an output can legitimately
// exist on chain and be read back by a wallet using this library.
//
// Our Script parser is eager and throws on those bytes, and `Output#setScriptFromBuffer`
// turns that throw into `this._script = null`, keeping the raw bytes in `_scriptBuffer`.
// `output.script` is therefore NULL for an output read from a perfectly valid transaction.
//
// Two call sites dereferenced it without asking and threw a raw TypeError — untyped, so a
// consumer's `catch (e) { if (e instanceof bsv.errors...) }` could not classify it:
//
//   * Transaction#_hasDustOutputs, reached from getSerializationError() and serialize()
//   * Output#getSize, reached from Transaction#_estimateSize() (fee estimation)
//
// Both are fixed. The verdicts are unchanged; only the crash is gone.

var bsv = require('../..')
var errors = bsv.errors
require('chai').should()
var expect = require('chai').expect

// OP_RETURN + a truncated length field, in the three shapes the length field can take.
var ACCEPTED_BY_NODE = ['6a4c', '6a4d01', '6a4e0100']

function txWithOutputScript (lockHex, satoshisLE) {
  var lock = Buffer.from(lockHex, 'hex')
  var len = lock.length.toString(16)
  if (len.length % 2) len = '0' + len
  return '0100000001' + '00'.repeat(32) + 'ffffffff' + '0100' + 'ffffffff' +
    '01' + satoshisLE + len + lockHex + '00000000'
}

var BELOW_DUST = '0100000000000000' // 1 satoshi
var ABOVE_DUST = '00e1f50500000000'

describe('an output script the node accepts but we cannot parse', function () {
  it('leaves output.script null rather than failing to construct the transaction', function () {
    ACCEPTED_BY_NODE.forEach(function (lock) {
      var tx = new bsv.Transaction(txWithOutputScript(lock, BELOW_DUST))
      expect(tx.outputs[0].script).to.equal(null, lock)
      tx.outputs[0]._scriptBuffer.toString('hex').should.equal(lock)
    })
  })

  it('round-trips the transaction byte-exact, so the bytes are never lost', function () {
    ACCEPTED_BY_NODE.forEach(function (lock) {
      var raw = txWithOutputScript(lock, BELOW_DUST)
      new bsv.Transaction(raw).toString().should.equal(raw, lock)
    })
  })

  it('reports the raw script in toObject() and inspect()', function () {
    var tx = new bsv.Transaction(txWithOutputScript('6a4c', BELOW_DUST))
    tx.outputs[0].toObject().script.should.equal('6a4c')
    tx.outputs[0].inspect().should.match(/6a4c/)
  })

  describe('the dust check answers instead of throwing a raw TypeError', function () {
    it('gives a typed DustOutputs below the dust threshold', function () {
      ACCEPTED_BY_NODE.forEach(function (lock) {
        var tx = new bsv.Transaction(txWithOutputScript(lock, BELOW_DUST))
        var err = tx._hasDustOutputs({})
        expect(err).to.be.an.instanceOf(errors.Transaction.DustOutputs, lock)
      })
    })

    it('gives no error above the dust threshold', function () {
      ACCEPTED_BY_NODE.forEach(function (lock) {
        var tx = new bsv.Transaction(txWithOutputScript(lock, ABOVE_DUST))
        expect(tx._hasDustOutputs({})).to.equal(undefined, lock)
      })
    })

    it('leaves the verdict for a WELL-FORMED data output exactly as it was', function () {
      // The exemption still applies to a script we can parse, which is the whole point of
      // the rule. `6a51` is OP_RETURN OP_1 — a data output by our Solver analogue.
      var tx = new bsv.Transaction(txWithOutputScript('6a51', BELOW_DUST))
      expect(tx._hasDustOutputs({})).to.equal(undefined)
      // And a plain non-data sub-dust output is still dust.
      var bare = new bsv.Transaction(txWithOutputScript('51', BELOW_DUST))
      expect(bare._hasDustOutputs({})).to.be.an.instanceOf(errors.Transaction.DustOutputs)
    })
  })

  describe('getSize answers from the raw bytes when the script did not parse', function () {
    it('returns the true serialized size', function () {
      // 8 bytes of satoshis + 1 varint + the script itself.
      ACCEPTED_BY_NODE.forEach(function (lock) {
        var tx = new bsv.Transaction(txWithOutputScript(lock, BELOW_DUST))
        var expected = 8 + 1 + (lock.length / 2)
        tx.outputs[0].getSize().should.equal(expected, lock)
        // and it agrees with what the output actually serializes to
        tx.outputs[0].toBufferWriter().toBuffer().length.should.equal(expected, lock)
      })
    })

    it('lets fee estimation run on a transaction read from the chain', function () {
      ACCEPTED_BY_NODE.forEach(function (lock) {
        var tx = new bsv.Transaction(txWithOutputScript(lock, BELOW_DUST))
        tx._estimateSize().should.be.a('number', lock)
      })
    })
  })
})

describe('getSize measures the Script OBJECT, which serialization does not', function () {
  // Documented current behaviour, deliberately NOT changed here.
  //
  // `output.script` hands out the live Script object, but `toBufferWriter` writes
  // `_scriptBuffer`. So a caller who mutates the script in place sees the mutation in the
  // object and in getSize(), while the transaction serializes WITHOUT it. Both halves of
  // that disagreement are pinned so neither can move unnoticed: changing either side alters
  // observable behaviour for well-formed scripts, which STABILITY.md protects, so it is a
  // separate decision rather than part of a crash fix.
  //
  // The documented setter path, setScript(), is honoured correctly and is what callers
  // should use.
  it('reports the mutated size while the transaction drops the mutation', function () {
    var o = new bsv.Transaction.Output({ script: bsv.Script.fromHex('6a0548656c6c6f'), satoshis: 1000 })
    o.getSize().should.equal(16)
    o.toBufferWriter().toBuffer().length.should.equal(16)

    o.script.add(Buffer.from('deadbeef', 'hex'))

    o.script.toHex().should.equal('6a0548656c6c6f04deadbeef')
    o.getSize().should.equal(21, 'getSize measures the mutated object')
    o.toBufferWriter().toBuffer().length.should.equal(16, 'serialization keeps _scriptBuffer')
    o._scriptBuffer.toString('hex').should.equal('6a0548656c6c6f')
  })

  it('honours setScript(), which is the supported way to change it', function () {
    var o = new bsv.Transaction.Output({ script: bsv.Script.fromHex('6a0548656c6c6f'), satoshis: 1000 })
    o.setScript(bsv.Script.fromHex('6a0548656c6c6f04deadbeef'))
    o.getSize().should.equal(21)
    o.toBufferWriter().toBuffer().length.should.equal(21)
  })
})
