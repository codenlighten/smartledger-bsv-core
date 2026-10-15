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

  // These were MODEL-DERIVED when written — their expected bytes came from the rule in
  // SerializeScriptCode, applied by hand to cases the 55-row corpus does not contain. They are
  // now NODE-MEASURED: the three shapes were emitted for all five hash types by a compiled
  // bitcoin-sv v1.2.3 and, independently and byte-identically, by a Rust node, and those 15 rows
  // are vendored beside the other 55 as `handAssembledRows`. The test below asserts them
  // directly; the ones after it keep their hand-written assertions as a readable statement of
  // what the rule says, which is worth having even once the bytes are pinned.
  //
  // They are the rows that distinguish the node's rule from the shortcut it is easy to write
  // instead, so they are the ones worth having from outside.

  it('agrees with two independent node implementations on the hand-assembled rows too', function () {
    // A parse cannot produce these scripts' chunk lists, so nothing in the 55 rows covers them.
    CORPUS.handAssembledRows.length.should.equal(15)
    CORPUS.handAssembledRows.forEach(function (row) {
      const ht = parseInt(row.sighashType, 16)
      const sub = Script.fromHex(row.scriptCode)
      Sighash.sighashPreimage(fixtureTx(), ht, 0, sub, sats, FORKID).toString('hex')
        .should.equal(row.preimage, row.id + ' preimage')
      Buffer.from(Sighash.sighash(fixtureTx(), ht, 0, sub, sats, FORKID)).reverse().toString('hex')
        .should.equal(row.digest, row.id + ' digest')
    })
  })

  it('asks the BYTES, so a hand-assembled chunk list cannot mislead it', function () {
    // The case that broke the first version of this fix. A chunk list built by hand can put an
    // undecodable push in the MIDDLE, which a parse never does — and the node, which only ever
    // sees bytes, stops there and drops everything after it. A rule that looked at the last
    // chunk saw a perfectly good OP_1 and dropped nothing.
    const chunks = [{ opcodenum: 0x4c, len: 5, buf: Buffer.from('aabb', 'hex') }, { opcodenum: 0x51 }]
    const hand = new Script().set({ chunks })
    hand.toHex().should.equal('4c05aabb51')
    const pre = Sighash.sighashPreimage(fixtureTx(), 0x01, 0, hand, sats, FORKID).toString('hex')
    // declares 5, carries 2: the walk stops after the length field
    pre.should.contain('054c05ffffffff')
    pre.should.not.contain('aabb')
  })

  it('counts only the separators the walk reaches, which the corpus already pins', function () {
    // ab6a4c050102: OP_CODESEPARATOR, OP_RETURN, then PUSHDATA1 declaring 5 with 2 present.
    // The node counts the one separator it passes, so the field declares 6 - 1 = 5 and carries
    // the three bytes the walk reached with the separator excised: 6a4c05.
    //
    // Which makes this script's field IDENTICAL to plain 6a4c050102's — and that one the
    // compiled node judged. So this is not a model-derived case: the expected digest below is
    // read out of the node-measured corpus, and if our separator accounting were off by that
    // one byte the two would not agree.
    const withSep = Sighash.sighashPreimage(fixtureTx(), 0x01, 0, Script.fromHex('ab6a4c050102'), sats, FORKID).toString('hex')
    withSep.should.contain('056a4c05ffffffff')
    const row = CORPUS.rows.filter(function (r) { return r.scriptCode === '6a4c050102' && r.sighashType === '0x01' })[0]
    ;(row === undefined).should.equal(false)
    const digest = Buffer.from(Sighash.sighash(fixtureTx(), 0x01, 0, Script.fromHex('ab6a4c050102'), sats, FORKID)).reverse().toString('hex')
    digest.should.equal(row.digest)
  })

  it('gives one digest for two different scripts, when the dropped bytes are all that differ', function () {
    // The sharpest consequence of the rule, and the REFERENCE's own digests show it: 4c05aabb51
    // and 4c05aabbab are different byte strings, but the node writes 4c05 for both and declares
    // 5 for both, so its original-algorithm digests are EQUAL — while its BIP-143 digests, which
    // carry every byte, differ. If the rule were "drop the chunk" or "write what we parsed" the
    // first pair would differ too. 4c05aabbab also puts a separator byte (0xab) inside the
    // DROPPED region, where it must not be counted; the walk never reads it as an opcode.
    //
    // Asserted against the vendored rows first, so the property is the node's and not ours, and
    // then against this library.
    const pick = function (script, ht) {
      const r = CORPUS.handAssembledRows.filter(function (x) { return x.scriptCode === script && x.sighashType === ht })[0]
      ;(r === undefined).should.equal(false, script + ' ' + ht + ' missing from the corpus')
      return r.digest
    }
    pick('4c05aabb51', '0x01').should.equal(pick('4c05aabbab', '0x01'))
    pick('4c05aabb51', '0x41').should.not.equal(pick('4c05aabbab', '0x41'))

    const ours = function (script, ht) {
      return Buffer.from(Sighash.sighash(fixtureTx(), parseInt(ht, 16), 0, Script.fromHex(script), sats, FORKID)).reverse().toString('hex')
    }
    ours('4c05aabb51', '0x01').should.equal(ours('4c05aabbab', '0x01'))
    ours('4c05aabb51', '0x41').should.not.equal(ours('4c05aabbab', '0x41'))
  })

  it('does not touch the caller\'s transaction or the other inputs', function () {
    // _scriptCodeLength lives on a throwaway copy. If it reached a real input, that input would
    // serialize a transaction that does not parse.
    const tx = fixtureTx()
    const before = tx.uncheckedSerialize()
    Sighash.sighashPreimage(tx, 0x61, 0, Script.fromHex('6a4c050102'), sats, FORKID)
    tx.uncheckedSerialize().should.equal(before)
    ;(tx.inputs[0]._scriptCodeLength === undefined).should.equal(true)
  })

  it('round-trips a signature over the corrected digest', function () {
    // The digest is only useful if signing and verifying both use it.
    const key = bsv.PrivateKey.fromBuffer(Buffer.from('22'.repeat(32), 'hex'))
    const sub = Script.fromHex('6a4c050102')
    const tx = fixtureTx()
    const sig = Sighash.sign(tx, key, 0x61, 0, sub, sats, FORKID)
    Sighash.verify(tx, sig, key.toPublicKey(), 0, sub, sats, FORKID).should.equal(true)
  })

  it('carries a spend whose signature IS checked, which is where the digest bites', function () {
    // A digest mismatch only matters where a signature is actually verified over it. In a lock
    // that is only `OP_RETURN` and junk, post-Genesis evaluation ends before the junk and no
    // signature is reached — so the sharp case is a lock that CHECKSIGs first and carries the
    // undecodable push after the OP_RETURN, where the tail is signed and never read.
    //
    // At hash type 0x61 this takes the original algorithm, so the dropped bytes are live. The
    // spend verifies here, through the interpreter, with the corrected digest. What is NOT
    // claimed: that a reference node accepts this transaction — that needs the node, and only
    // the 55 preimage rows above are node-measured.
    const key = bsv.PrivateKey.fromBuffer(Buffer.from('33'.repeat(32), 'hex'))
    const lock = Script.fromHex('21' + key.toPublicKey().toHex() + 'ac' + '6a4c050102')
    const ht = 0x61
    const tx = fixtureTx()
    const sig = Sighash.sign(tx, key, ht, 0, lock, sats, FORKID)
    tx.inputs[0].setScript(Script.fromASM(sig.toTxFormat().toString('hex')))
    const i = new Script.Interpreter()
    i.verify(tx.inputs[0].script, lock, tx, 0, Script.Interpreter.mainnetFlags(), sats)
      .should.equal(true, i.errstr)
    // and the signed field itself: 40 bytes declared, 38 written, the last two dropped
    const pre = Sighash.sighashPreimage(tx, ht, 0, lock, sats, FORKID).toString('hex')
    const lockHex = lock.toHex()
    lockHex.length.should.equal(80)
    pre.should.contain('28' + lockHex.slice(0, 76) + 'ffffffff')
    pre.should.not.contain(lockHex)
  })

  it('leaves the separator rule where it was', function () {
    // ab6a4c: OP_CODESEPARATOR then 6a4c. The separator is removed and the declared length
    // drops with it, which is what the node's `size() - nCodeSeparators` does, and the
    // undecodable chunk still has nothing to drop.
    const pre = Sighash.sighashPreimage(fixtureTx(), 0x01, 0, Script.fromHex('ab6a4c'), sats, FORKID).toString('hex')
    pre.should.contain('026a4c')
  })
})
