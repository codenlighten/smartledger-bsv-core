'use strict'

/* global describe, it */

const should = require('chai').should()
const crypto = require('crypto')
const bsv = require('../..')
const Script = bsv.Script
const Interpreter = Script.Interpreter
const Sighash = bsv.Transaction.Sighash
const Transaction = bsv.Transaction
const BN = bsv.crypto.BN
const Signature = bsv.crypto.Signature
const PrivateKey = bsv.PrivateKey

const CORPUS = require('../data/sighash-codesep-executed.json')
const FORKID = Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID

// The node's own walk, only as far as counting the separators it reaches - used to assert that
// the judged declared lengths follow the rule rather than just matching a stored number.
function walkSeparators (buf) {
  let pos = 0
  let separators = 0
  while (pos < buf.length) {
    const start = pos
    const opcode = buf[pos++]
    if (opcode <= 0x4e) {
      let size = 0
      if (opcode < 0x4c) {
        size = opcode
      } else if (opcode === 0x4c) {
        if (buf.length - pos < 1) { pos = start + 1; break }
        size = buf[pos++]
      } else if (opcode === 0x4d) {
        if (buf.length - pos < 2) { pos = start + 1; break }
        size = buf.readUInt16LE(pos); pos += 2
      } else {
        if (buf.length - pos < 4) { pos = start + 1; break }
        size = buf.readUInt32LE(pos); pos += 4
      }
      if (buf.length - pos < size) break
      pos += size
    } else if (opcode === 0xab) {
      separators++
    }
  }
  return separators
}

function d256 (b) {
  return crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest()
}

// OP_CODESEPARATOR moves the start of the signed script. Two things decide what gets signed:
// WHERE the interpreter says the last executed separator was, and WHAT each digest algorithm
// then does with the suffix. They are tested separately below, because only the second half
// was covered before: every pre-existing separator assertion in this suite passes sighash type
// 0x01, which routes to the original algorithm, so the BIP-143 rule - keep the separators,
// do not excise them - had no test at all.

describe('Sighash with an executed OP_CODESEPARATOR', function () {
  describe('the external corpus', function () {
    // Rows computed outside this library; see the fixture's `provenance`. They are ONE external
    // witness, not two - the two column files published with them are the same bytes.
    it('is internally consistent before it is used as evidence', function () {
      CORPUS.rows.length.should.equal(20)
      CORPUS.rows.forEach(function (r) {
        // the digest must be sha256d of the preimage in the row, or the row is corrupt
        d256(Buffer.from(r.expect.preimageHex, 'hex')).toString('hex')
          .should.equal(r.expect.digestHex, r.id + ': digest is not sha256d of its own preimage')
        // and the scriptCode must follow from the rule, re-derived here rather than trusted
        const prev = Buffer.from(r.prevScriptHex, 'hex')
        const suffix = r.codeSepEnd <= prev.length ? prev.slice(r.codeSepEnd) : Buffer.alloc(0)
        const expected = r.algorithm === 'bip143'
          ? suffix
          : new Script(new Script(suffix)).removeCodeseparators().toBuffer()
        expected.toString('hex').should.equal(r.expect.scriptCodeHex, r.id + ': scriptCode does not follow from the rule')
      })
    })

    it('covers both algorithms and a separator the walk never reaches', function () {
      const algos = {}
      CORPUS.rows.forEach(function (r) { algos[r.algorithm] = (algos[r.algorithm] || 0) + 1 })
      algos.bip143.should.equal(12)
      algos.original.should.equal(8)
      // one shape has the separator byte inside a push OPERAND, where it is data and not an opcode
      CORPUS.rows.filter(function (r) { return r.prevScriptHex === '5102ab516a' }).length.should.equal(5)
    })

    CORPUS.rows.forEach(function (r) {
      it('reproduces ' + r.id, function () {
        const prev = Buffer.from(r.prevScriptHex, 'hex')
        const suffix = r.codeSepEnd <= prev.length ? prev.slice(r.codeSepEnd) : Buffer.alloc(0)
        const tx = new Transaction(r.txHex)
        const pre = Sighash.sighashPreimage(tx, r.hashType, r.nIn, Script.fromBuffer(suffix), new BN(r.amount), FORKID)
        pre.toString('hex').should.equal(r.expect.preimageHex)
        d256(pre).toString('hex').should.equal(r.expect.digestHex)
        // Sighash.sighash hands back the reverse of the corpus order
        Buffer.from(Sighash.sighash(tx, r.hashType, r.nIn, Script.fromBuffer(suffix), new BN(r.amount), FORKID))
          .reverse().toString('hex').should.equal(r.expect.digestHex)
      })
    })

    it('routes each row to the algorithm the corpus labels, on the hash type alone', function () {
      CORPUS.rows.forEach(function (r) {
        const forkid = (r.hashType & Signature.SIGHASH_FORKID) !== 0
        const chronicle = (r.hashType & Signature.SIGHASH_CHRONICLE) !== 0
        const routed = (forkid && !chronicle) ? 'bip143' : 'original'
        routed.should.equal(r.algorithm, r.id)
      })
    })
  })

  describe('the two algorithms disagree about the separators in the suffix', function () {
    const tx = new Transaction(CORPUS.rows[0].txHex)
    const sats = new BN(100000)
    const suffix = Script.fromHex('52ab6a0401020304') // one separator still inside the signed script

    it('BIP-143 keeps them, declaring the suffix as it stands', function () {
      const pre = Sighash.sighashPreimage(tx, 0x41, 0, suffix, sats, FORKID).toString('hex')
      pre.should.contain('08' + '52ab6a0401020304')
    })

    it('the original algorithm excises them and drops the declared length with them', function () {
      const pre = Sighash.sighashPreimage(tx, 0x01, 0, suffix, sats, FORKID).toString('hex')
      pre.should.contain('07' + '526a0401020304')
      pre.should.not.contain('52ab6a')
    })

    it('a separator byte inside a push operand is data on BOTH paths', function () {
      // 5102ab516a: OP_1, PUSHDATA(2)[ab 51], OP_RETURN. The 0xab is operand content, so
      // nothing is excised and nothing is counted, whichever algorithm runs.
      const s = Script.fromHex('5102ab516a')
      Sighash.sighashPreimage(tx, 0x41, 0, s, sats, FORKID).toString('hex').should.contain('055102ab516a')
      Sighash.sighashPreimage(tx, 0x01, 0, s, sats, FORKID).toString('hex').should.contain('055102ab516a')
    })

    it('a 0xab consumed as a LENGTH byte is neither excised nor counted', function () {
      // 4d01ab: OP_PUSHDATA2 whose two length bytes are 01 ab. There is no separator here at
      // all; an implementation that counted 0xab bytes would declare 2 and drop one byte.
      const pre = Sighash.sighashPreimage(tx, 0x01, 0, Script.fromHex('4d01ab'), sats, FORKID).toString('hex')
      pre.should.contain('03' + '4d01ab')
    })
  })

  describe('where the interpreter says the separator was', function () {
    // The node's pbegincodehash is a byte pointer into the script; ours is a CHUNK INDEX.
    // These cases check that the scriptCode actually handed to signature verification is the
    // byte suffix the node would have taken, including the two rules that are easy to get
    // wrong: an unexecuted separator must not move it, and a separator byte inside a push
    // operand is not a separator.
    const priv = new PrivateKey(BN.fromBuffer(Buffer.alloc(32, 0x6d)))
    const pub = priv.toPublicKey()
    const pkPush = Buffer.concat([Buffer.from([pub.toBuffer().length]), pub.toBuffer()])

    function build (words) {
      return Buffer.concat(words.split(' ').map(function (w) {
        return w === '@PK' ? pkPush : Buffer.from(w, 'hex')
      }))
    }

    // OP_NOP (0x61) is the filler, so the stack holds only what OP_CHECKSIG needs.
    const CASES = [
      ['no separator at all', '@PK ac', 0],
      ['a separator first', 'ab @PK ac', 1],
      ['a separator after an opcode', '61 ab @PK ac', 2],
      ['two separators, the later one wins', '61 ab 61 ab @PK ac', 4],
      ['a separator byte inside a push operand does not count', '61 02ab51 75 @PK ac', 0],
      ['a separator in an untaken IF body does not count', '00 63 ab 68 @PK ac', 0],
      ['a separator in a taken IF body does count', '51 63 ab 68 @PK ac', 3],
      ['a separator in an untaken ELSE body does not count', '51 63 51 75 67 ab 68 @PK ac', 0],
      ['a separator in the taken branch of an if/else counts', '51 63 ab 67 52 68 @PK ac', 3],
      // each push encoding, so the offset is not only ever tested one or two bytes in
      ['a separator after a 75-byte direct push', '4b' + 'cc'.repeat(75) + ' 75 ab @PK ac', 78],
      ['a separator after a PUSHDATA1', '4c4c' + 'cc'.repeat(76) + ' 75 ab @PK ac', 80],
      ['a separator after a PUSHDATA2', '4d0001' + 'cc'.repeat(256) + ' 75 ab @PK ac', 261],
      ['separator bytes inside a long PUSHDATA2 operand are data',
        '4d0001' + 'ab'.repeat(256) + ' 75 @PK ac', 0],
      // nested conditionals: fExec is a stack, not a flag
      ['a separator in a taken branch inside a taken branch counts', '51 63 51 63 ab 68 68 @PK ac', 5],
      ['a separator in an untaken branch inside a taken branch does not', '51 63 00 63 ab 68 68 @PK ac', 0],
      ['a separator in a taken branch inside an UNTAKEN branch does not', '00 63 51 63 ab 68 68 @PK ac', 0],
      ['an executed separator is not undone by a later unexecuted one', 'ab 00 63 ab 68 @PK ac', 1]
    ]

    CASES.forEach(function (c) {
      const name = c[0]
      const words = c[1]
      const offset = c[2]
      it(name, function () {
        const lockBuf = build(words)
        const lock = Script.fromBuffer(lockBuf)
        const expected = lockBuf.slice(offset).toString('hex')
        const tx = new Transaction()
        tx.from({ txId: 'ab'.repeat(32), outputIndex: 0, script: lock.toHex(), satoshis: 100000 })
        tx.to(priv.toAddress(), 50000)
        const flags = FORKID | Interpreter.SCRIPT_VERIFY_STRICTENC

        // sign over the scriptCode we say the interpreter will use; if it uses another one the
        // signature cannot verify, so a wrong offset fails here even without the capture below
        const sig = Sighash.sign(tx, priv, Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID, 0,
          Script.fromBuffer(Buffer.from(expected, 'hex')), new BN(100000), flags)
        const scriptSig = new Script().add(Buffer.concat([
          sig.toDER(), Buffer.from([Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID])
        ]))

        let captured = null
        const original = Transaction.prototype.verifySignature
        Transaction.prototype.verifySignature = function (s, p, n, subscript) {
          captured = subscript.toBuffer().toString('hex')
          return original.apply(this, arguments)
        }
        const i = new Interpreter()
        let ok
        try {
          ok = i.verify(scriptSig, lock, tx, 0, flags, new BN(100000))
        } finally {
          Transaction.prototype.verifySignature = original
        }
        should.not.equal(captured, null, 'signature verification was never reached')
        captured.should.equal(expected)
        ok.should.equal(true, i.errstr)
      })
    })

    it('leaves pbegincodehash alone when no separator executes', function () {
      const i = new Interpreter()
      i.pbegincodehash.should.equal(0)
    })
  })

  describe('a chunk index and a byte pointer pick out the same suffix', function () {
    // Our pbegincodehash indexes CHUNKS, the node's points at BYTES. The two pick out the same
    // scriptCode only if each chunk serializes to exactly its own byte span and serialization is
    // the concatenation of those spans; given that, the byte offset after a separator chunk
    // equals the length of the serialized prefix, and the suffixes agree.
    //
    // That is evidence for the premises, NOT a proof of equivalence for every Script the API
    // accepts. It is measured over scripts PARSED FROM BYTES only: out of band, every script of
    // 0..3 bytes plus 600,000 biased random 4..12 byte scripts - 17,443,009 scripts, 56,502,963
    // chunk-slice comparisons, 0 divergences. A chunk list BUILT BY HAND is a different case and
    // is pinned separately below. The bounded version here is what the suite runs.
    it('holds for every script of 0..2 bytes and a seeded sample above that', function () {
      // the exhaustive sweep lives out of band; this is a regression guard, so it is sized
      // to finish well inside the suite's timeout rather than near it
      this.timeout(30000)
      let checked = 0
      function check (buf) {
        const s = Script.fromBuffer(buf)
        s.toBuffer().equals(buf).should.equal(true, 'roundtrip: ' + buf.toString('hex'))
        for (let i = 0; i <= s.chunks.length; i++) {
          const pre = new Script().set({ chunks: s.chunks.slice(0, i) }).toBuffer()
          const suf = new Script().set({ chunks: s.chunks.slice(i) }).toBuffer()
          checked++
          suf.equals(buf.slice(pre.length)).should.equal(true,
            buf.toString('hex') + ' at chunk ' + i + ': ' + suf.toString('hex') + ' vs ' + buf.slice(pre.length).toString('hex'))
        }
      }
      for (let len = 0; len <= 2; len++) {
        const total = Math.pow(256, len)
        for (let n = 0; n < total; n++) {
          const b = Buffer.alloc(len)
          let v = n
          for (let k = 0; k < len; k++) { b[k] = v & 0xff; v >>>= 8 }
          check(b)
        }
      }
      const POOL = [0xab, 0xab, 0x00, 0x01, 0x4b, 0x4c, 0x4d, 0x4e, 0x51, 0x63, 0x67, 0x68, 0x6a, 0xac, 0x75, 0xff]
      let rnd = 12345
      function nextRnd () { rnd = (rnd * 1103515245 + 12345) & 0x7fffffff; return rnd }
      for (let m = 0; m < 2000; m++) {
        const l = 3 + (nextRnd() % 8)
        const buf = Buffer.alloc(l)
        for (let j = 0; j < l; j++) {
          buf[j] = (nextRnd() % 3 === 0) ? (nextRnd() & 0xff) : POOL[nextRnd() % POOL.length]
        }
        check(buf)
      }
      checked.should.be.above(150000)
    })
  })

  describe('a chunk list built by hand, which no parse can produce', function () {
    // set({ chunks }) accepts a chunk whose declared len does not match its buf, and can put
    // such a chunk anywhere - a parse only ever leaves one LAST. Serializing that list gives
    // bytes a parser reads as something else entirely, so a chunk index and a byte pointer
    // genuinely disagree here. What matters is which way the disagreement falls.
    const hand = new Script().set({
      chunks: [
        { opcodenum: 0x4c, len: 5, buf: Buffer.from('aabb', 'hex') }, // declares 5, carries 2
        { opcodenum: 0xab }, // OP_CODESEPARATOR
        { opcodenum: 0x51 },
        { opcodenum: 0xac } // OP_CHECKSIG
      ]
    })

    it('serializes to bytes that re-parse as one push, separator and all', function () {
      const bytes = hand.toBuffer()
      bytes.toString('hex').should.equal('4c05aabbab51ac')
      const parsed = Script.fromBuffer(bytes)
      parsed.chunks.length.should.equal(1)
      parsed.chunks[0].opcodenum.should.equal(0x4c)
      // the separator and the OP_CHECKSIG are swallowed as push payload
      parsed.chunks.filter(function (c) { return c.opcodenum === 0xab }).length.should.equal(0)
      parsed.toBuffer().equals(bytes).should.equal(true)
    })

    it('fails CLOSED on the hand-built list rather than executing past the bad push', function () {
      // The safe direction. Were this to ACCEPT, a caller could be told an output needs a
      // signature while the bytes they ship are spendable by anyone.
      const bytes = hand.toBuffer()
      const tx = new Transaction()
      tx.from({ txId: 'ab'.repeat(32), outputIndex: 0, script: bytes.toString('hex'), satoshis: 100000 })
      tx.to(new PrivateKey(BN.fromBuffer(Buffer.alloc(32, 0x6d))).toAddress(), 50000)
      const i = new Interpreter()
      const flags = FORKID | Interpreter.SCRIPT_VERIFY_STRICTENC
      i.verify(new Script(), hand, tx, 0, flags, new BN(100000)).should.equal(false)
      i.errstr.should.equal('SCRIPT_ERR_BAD_OPCODE')
    })

    it('agrees with a node on the serialized bytes, which is all a node ever has', function () {
      const bytes = hand.toBuffer()
      const tx = new Transaction()
      tx.from({ txId: 'ab'.repeat(32), outputIndex: 0, script: bytes.toString('hex'), satoshis: 100000 })
      tx.to(new PrivateKey(BN.fromBuffer(Buffer.alloc(32, 0x6d))).toAddress(), 50000)
      const i = new Interpreter()
      const flags = FORKID | Interpreter.SCRIPT_VERIFY_STRICTENC
      // one push, left truthy on the stack, no signature check anywhere in it
      i.verify(new Script(), Script.fromBuffer(bytes), tx, 0, flags, new BN(100000)).should.equal(true)
    })

    it('only reaches that state through a len that disagrees with its buf', function () {
      // A parse can also produce len !== buf.length, but only for the FINAL chunk of a
      // truncated push, where there is nothing after it to mis-slice.
      const truncated = Script.fromBuffer(Buffer.from('ab01', 'hex'))
      const last = truncated.chunks[truncated.chunks.length - 1]
      last.opcodenum.should.equal(0x01)
      ;(last.buf ? last.buf.length : 0).should.not.equal(last.len)
      truncated.chunks.indexOf(last).should.equal(truncated.chunks.length - 1)
    })
  })

  describe('a separator together with an undecodable trailing push', function () {
    // Where the separator rule meets the node's SerializeScriptCode. The declared length drops
    // by the separators the walk reached, while the carried bytes stop where GetOp first failed,
    // so the field can declare more than it holds AND be short by the separator count at once.
    //
    // These rows were authored here with no expected values and judged elsewhere - a compiled
    // bitcoin-sv v1.2.3 and an independent Rust node, both run by one peer. They are the first
    // separator-bearing scriptCode any node has judged for this library:
    // test/data/sighash-scriptcode-tail.json, the other node-measured corpus, has none.
    const UC = require('../data/sighash-codesep-undecodable.json')

    it('is internally consistent before it is used as evidence', function () {
      UC.rows.length.should.equal(48)
      UC.provenance.emitters.length.should.equal(2)
      UC.rows.forEach(function (r) {
        d256(Buffer.from(r.expect.preimageHex, 'hex')).toString('hex')
          .should.equal(r.expect.digestHex, r.id + ': digest is not sha256d of its own preimage')
      })
    })

    UC.rows.forEach(function (r) {
      it('reproduces ' + r.id, function () {
        const prev = Buffer.from(r.prevScriptHex, 'hex')
        const suffix = prev.slice(r.codeSepEnd)
        suffix.toString('hex').should.equal(r.expect.scriptCodeSlicedHex)
        const tx = new Transaction(r.txHex)
        const pre = Sighash.sighashPreimage(tx, r.hashType, r.nIn, Script.fromBuffer(suffix), new BN(r.amount), FORKID)
        pre.toString('hex').should.equal(r.expect.preimageHex)
        d256(pre).toString('hex').should.equal(r.expect.digestHex)
      })
    })

    it('declares len(suffix) minus the separators the walk reached', function () {
      // read the declared length and the carried bytes straight out of each original-algorithm
      // preimage: version(4) + input count(1) + prevout(36) puts the varint at offset 41
      const expected = {
        '6a4c': [2, '6a4c'],
        ab6a4c: [2, '6a4c'],
        '6a4d01': [3, '6a4d'],
        ab6a4d01: [3, '6a4d'],
        abab6a4d01: [3, '6a4d'],
        ab6a4e010000: [5, '6a4e'],
        ab4c01: [2, '4c01'],
        abab4d0100: [3, '4d0100'],
        ab6aab4d01: [3, '6a4d'],
        '4d01ab': [3, '4d01ab'],
        ab4dab00: [3, '4dab00'],
        ab: [0, '']
      }
      let seen = 0
      UC.rows.forEach(function (r) {
        if (r.hashType !== 1) return // the original algorithm, no forkid bit
        const pre = Buffer.from(r.expect.preimageHex, 'hex')
        const declared = pre[41]
        const rest = pre.slice(42)
        const carried = rest.slice(0, rest.indexOf(Buffer.from('ffffffff', 'hex')))
        const want = expected[r.expect.scriptCodeSlicedHex]
        ;(want === undefined).should.equal(false, 'no expectation for ' + r.expect.scriptCodeSlicedHex)
        declared.should.equal(want[0], r.id + ': declared length')
        carried.toString('hex').should.equal(want[1], r.id + ': carried bytes')
        seen++
      })
      seen.should.equal(12)
    })

    it('does not EXCISE a 0xab that the parse reads as a length byte', function () {
      // 4d01ab is a PUSHDATA2 whose length bytes are 01 ab: no separator at all, nothing
      // excised, three bytes declared and three carried. Node-judged, not modelled.
      //
      // This pins the EXCISION half only. In all twelve judged bodies a naive count of 0xab
      // bytes gives the same DECLARED length as the walk's count, because the declared length
      // only consults that count when the walk stops early, and no judged body has a 0xab in a
      // length field AND an early stop. The count half is pinned separately below.
      const row = UC.rows.filter(function (r) {
        return r.expect.scriptCodeSlicedHex === '4d01ab' && r.hashType === 1
      })[0]
      ;(row === undefined).should.equal(false)
      Buffer.from(row.expect.preimageHex, 'hex').slice(41, 45).toString('hex').should.equal('034d01ab')
      // and ab4dab00: the FIRST 0xab is a separator, the second is inside the length field,
      // so exactly one is counted - 4 - 1 = 3 declared, and 4dab00 carried
      const two = UC.rows.filter(function (r) {
        return r.expect.scriptCodeSlicedHex === 'ab4dab00' && r.hashType === 1
      })[0]
      Buffer.from(two.expect.preimageHex, 'hex').slice(41, 45).toString('hex').should.equal('034dab00')
    })

    it('leaves BIP-143 untouched by all of it', function () {
      // BIP-143 writes the suffix verbatim: nothing excised, nothing dropped, length honest
      UC.rows.forEach(function (r) {
        if (r.algorithm !== 'bip143') return
        const sc = r.expect.scriptCodeSlicedHex
        const varint = Buffer.from([sc.length / 2]).toString('hex')
        r.expect.preimageHex.should.contain(varint + sc, r.id)
      })
    })
  })

  describe('the separator COUNT, which the judged corpus above cannot see', function () {
    // The declared length in this library has TWO derivations, and they always agree:
    //   walk stops early  -> set explicitly as len(suffix) - walk.separators
    //   walk reaches end  -> taken from the stripped script's own length, via the chunk-level
    //                        removeCodeseparators, which equals the same number
    // A sabotage of one is invisible to rows served by the other, which is why replacing the
    // walk's count with a naive count of every 0xab byte leaves all 48 rows of
    // sighash-codesep-undecodable.json green: no body there has a 0xab in a length field AND an
    // early stop, so for that question every one of them takes the stripped-length route.
    //
    // Measured both ways:
    //   naive byte count for the walk     -> 12 of 12 original rows HERE fail, 0 of 48 there
    //   byte-level excision instead of    -> 4 of 48 there fail (4d01ab, ab4dab00 at both
    //   chunk-level                          original hash types), 0 here
    // The two fixtures guard the two routes and neither covers the other's.
    //
    // These rows are node-judged: same two emitters as the sibling fixture, joined against a
    // fresh run of this library at 48 comparisons with 0 differences.
    const CP = require('../data/sighash-codesep-count-path.json')

    it('is internally consistent before it is used as evidence', function () {
      CP.rows.length.should.equal(24)
      CP.rows.forEach(function (r) {
        d256(Buffer.from(r.expect.preimageHex, 'hex')).toString('hex')
          .should.equal(r.expect.digestHex, r.id + ': digest is not sha256d of its own preimage')
      })
    })

    CP.rows.forEach(function (r) {
      it('reproduces ' + r.id, function () {
        const suffix = Buffer.from(r.prevScriptHex, 'hex').slice(r.codeSepEnd)
        suffix.toString('hex').should.equal(r.expect.scriptCodeSlicedHex)
        const tx = new Transaction(r.txHex)
        const pre = Sighash.sighashPreimage(tx, r.hashType, r.nIn, Script.fromBuffer(suffix), new BN(r.amount), FORKID)
        pre.toString('hex').should.equal(r.expect.preimageHex)
        d256(pre).toString('hex').should.equal(r.expect.digestHex)
      })
    })

    it('declares what the walk counted, not what a byte scan would count', function () {
      let seen = 0
      CP.rows.forEach(function (r) {
        if (r.hashType !== 1) return // the original algorithm, no forkid bit
        const body = r.expect.scriptCodeSlicedHex
        const declared = Buffer.from(r.expect.preimageHex, 'hex')[41]
        // the node-judged declared length, and the value a naive 0xab count would have produced
        declared.should.equal((body.length / 2) - walkSeparators(Buffer.from(body, 'hex')), body)
        declared.should.not.equal(r.declaredByNaiveByteCount, body + ': naive count would have matched')
        seen++
      })
      seen.should.equal(6)
    })

    it('gives a separator-bearing body the same signed field as its separator-free twin', function () {
      // ab6a4dab declares 4 - 1 = 3 and carries 6a4d; 6a4dab declares 3 - 0 = 3 and carries 6a4d.
      // Identical fields, so identical digests - which holds only if the count is subtracted.
      const pairs = [['6a4dab', 'ab6a4dab'], ['4dab', 'ab4dab'], ['6a4eab0000', 'ab6a4eababab']]
      pairs.forEach(function (pair) {
        const a = CP.rows.filter(function (r) { return r.expect.scriptCodeSlicedHex === pair[0] && r.hashType === 1 })[0]
        const b = CP.rows.filter(function (r) { return r.expect.scriptCodeSlicedHex === pair[1] && r.hashType === 1 })[0]
        ;(a === undefined || b === undefined).should.equal(false, pair.join('/'))
        a.expect.digestHex.should.equal(b.expect.digestHex, pair.join(' vs '))
      })
    })

    it('keeps BIP-143 writing the suffix verbatim for all of them', function () {
      CP.rows.forEach(function (r) {
        if (r.algorithm !== 'bip143') return
        const sc = r.expect.scriptCodeSlicedHex
        r.expect.preimageHex.should.contain(Buffer.from([sc.length / 2]).toString('hex') + sc, r.id)
      })
    })
  })

  describe('an out-of-range codeSepEnd', function () {
    it('is not a state our interpreter can reach, and slices to nothing if constructed', function () {
      // The corpus carries codeSepEnd 99 against a 10-byte script, which is synthetic: our
      // pbegincodehash is a chunk index the interpreter only ever sets to a position it has
      // reached. Constructed by hand, both sides slice to an empty scriptCode.
      const prev = Buffer.from('51ab52ab6a0401020304', 'hex')
      prev.length.should.equal(10)
      prev.slice(99).length.should.equal(0)
      const s = Script.fromBuffer(prev)
      new Script().set({ chunks: s.chunks.slice(99) }).toBuffer().length.should.equal(0)
      const row = CORPUS.rows.filter(function (r) { return r.codeSepEnd === 99 })[0]
      row.expect.scriptCodeHex.should.equal('')
    })
  })
})
