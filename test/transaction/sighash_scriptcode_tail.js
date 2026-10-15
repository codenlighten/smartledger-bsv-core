'use strict'

/* global describe, it */

// The node does NOT serialize the whole scriptCode into the original-algorithm signature
// digest when that script ends in a push it cannot decode.
//
// `CTransactionSignatureSerializer::SerializeScriptCode` writes
// `WriteCompactSize(scriptCode.size() - nCodeSeparators)` and then the bytes up to the iterator
// the LAST, FAILED `GetOp` left behind — and `GetOp2` advances `pc` past the opcode, and past a
// complete length field, BEFORE testing whether the rest is present. So the opcode and whatever
// length field it managed to read are written, and the partial operand after them is dropped,
// while the length prefix still counts it. The preimage the node hashes therefore declares more
// bytes than it contains.
//
// This library serialized the scriptCode in full, which gave a DIFFERENT DIGEST for those
// scripts — a signature valid on the network would not verify here, and one made here would not
// verify there. 9.35.0 made those scripts parseable, which is what brought the path within
// reach: before it, the parse threw and no digest was computed at all.
//
// Reachable on the original algorithm, which `SignatureHash` selects when
// `enabledSighashForkid && sigHashType.hasForkId() && !sigHashType.hasChronicle()` is false —
// so for a non-FORKID hash type, and for 0x61, FORKID|CHRONICLE, which is post-Chronicle and
// current. BIP-143 is unaffected: its scriptCode goes through the plain CScript serializer with
// no GetOp walk.
//
// The fixture and the expected bytes in test/data/sighash-scriptcode-tail.json were emitted by a
// compiled bitcoin-sv v1.2.3. Ten of its 55 rows disagreed with this library before the fix, at
// both original-algorithm hash types, for `6a4d01`, `6a4e0100`, `6a4c050102`, `6a4d030001ff` and
// `6a050102`. `6a4c` is NOT one of them: its partial prefix is empty, so there is nothing to
// drop — which is the kind of row that tells a model apart from a guess.

require('chai').should()
const bsv = require('../..')
const Transaction = bsv.Transaction
const Script = bsv.Script
const BN = bsv.crypto.BN
const Sighash = Transaction.Sighash
const FORKID = Script.Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID

const CORPUS = require('../data/sighash-scriptcode-tail.json')

function fixtureTx () {
  const f = CORPUS.fixture
  const t = new Transaction()
  t.version = f.version
  t.nLockTime = f.nLockTime
  t.from({ txId: f.prevTxId, outputIndex: f.outputIndex, script: '', satoshis: f.inputSatoshis })
  t.inputs[0].sequenceNumber = f.sequenceNumber
  t.addOutput(new Transaction.Output({ satoshis: f.output.satoshis, script: Script.fromHex(f.output.script) }))
  return t
}

describe('the scriptCode tail the node does not sign', function () {
  const sats = new BN(CORPUS.fixture.inputSatoshis)

  it('agrees with the reference node on every preimage and every digest', function () {
    CORPUS.rows.length.should.equal(55)
    CORPUS.rows.forEach(function (row) {
      const ht = parseInt(row.sighashType, 16)
      const sub = Script.fromHex(row.scriptCode)
      const pre = Sighash.sighashPreimage(fixtureTx(), ht, 0, sub, sats, FORKID)
      pre.toString('hex').should.equal(row.preimage, row.id + ' preimage')
      // sighash() returns the digest reversed, as every caller of it expects
      const dig = Sighash.sighash(fixtureTx(), ht, 0, sub, sats, FORKID)
      Buffer.from(dig).reverse().toString('hex').should.equal(row.digest, row.id + ' digest')
    })
  })

  it('declares the full length and writes fewer bytes, exactly where the node does', function () {
    // 6a4d030001ff: OP_RETURN, then PUSHDATA2 declaring 3 bytes with 2 present. The field
    // declares 6 and carries 4.
    const pre = Sighash.sighashPreimage(fixtureTx(), 0x01, 0, Script.fromHex('6a4d030001ff'), sats, FORKID).toString('hex')
    pre.should.contain('066a4d0300')
    pre.should.not.contain('066a4d030001ff')
  })

  it('leaves a script with nothing to drop alone, including an empty partial prefix', function () {
    // 6a4c has a cut-off prefix of ZERO bytes, so the node writes the whole script. A fix that
    // dropped "the undecodable chunk" rather than "the bytes past where GetOp stopped" would
    // break this row, and it would still pass the five rows above.
    const pre = Sighash.sighashPreimage(fixtureTx(), 0x01, 0, Script.fromHex('6a4c'), sats, FORKID).toString('hex')
    pre.should.contain('026a4c')
    // and a well-formed push is untouched
    const ok = Sighash.sighashPreimage(fixtureTx(), 0x01, 0, Script.fromHex('6a0401020304'), sats, FORKID).toString('hex')
    ok.should.contain('066a0401020304')
  })

  it('does not change the BIP-143 digest, which never walked the script', function () {
    CORPUS.rows.filter(function (r) { return r.sighashType === '0x41' || r.sighashType === '0xc1' || r.sighashType === '0x43' })
      .forEach(function (row) {
        const pre = Sighash.sighashPreimage(fixtureTx(), parseInt(row.sighashType, 16), 0, Script.fromHex(row.scriptCode), sats, FORKID)
        pre.toString('hex').should.equal(row.preimage, row.id + ' (BIP-143) preimage')
      })
  })

  it('round-trips a signature over the corrected digest', function () {
    // The digest is only useful if signing and verifying both use it.
    const key = bsv.PrivateKey.fromBuffer(Buffer.from('22'.repeat(32), 'hex'))
    const sub = Script.fromHex('6a4c050102')
    const tx = fixtureTx()
    const sig = Sighash.sign(tx, key, 0x61, 0, sub, sats, FORKID)
    Sighash.verify(tx, sig, key.toPublicKey(), 0, sub, sats, FORKID).should.equal(true)
  })

  it('leaves the separator rule where it was', function () {
    // ab6a4c: OP_CODESEPARATOR then 6a4c. The separator is removed and the declared length
    // drops with it, which is what the node's `size() - nCodeSeparators` does, and the
    // undecodable chunk still has nothing to drop.
    const pre = Sighash.sighashPreimage(fixtureTx(), 0x01, 0, Script.fromHex('ab6a4c'), sats, FORKID).toString('hex')
    pre.should.contain('026a4c')
  })
})
