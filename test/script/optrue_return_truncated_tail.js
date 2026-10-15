'use strict'

/* global describe, it */

// A push whose LENGTH FIELD is cut off, after a top-level OP_RETURN.
//
// Post-Genesis the node stops at an executed top-level OP_RETURN and never reads the rest of
// the script — its own comment says the remainder "does not affect the validity (even in
// presence of unbalanced IFs, invalid opcodes etc)". So `6a4c`, `6a4d01` and `6a4e0100` are
// valid locking scripts, and one of them appears on livenet in
// ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767 (see
// test/transaction/output.js). This library THREW parsing them, in both eras, so it could not
// answer at all for an output the network accepts and mines.
//
// PORTED from @smartledger/bsv 9.35.0, where the fix and these rows originate. The flag words
// below were re-derived here rather than copied, and come out identical, which is expected for
// a port of the same constants and is asserted rather than assumed.
//
// The 22 rows below were judged on a compiled bitcoin-sv v1.2.3 by the op-codes lab and
// reproduced here before being accepted. 16 of the 22 already agreed; the 6 that did not are
// A1-A3 in both eras, and all six failed in `Script.fromBuffer` without reaching the
// interpreter. So the interpreter needed no change — which was a PREDICTION before the fix and
// is this file afterwards.
//
// Both flag words are rebuilt from the library's own named constants rather than written as
// hex: an undefined flag ORed into a word yields NaN, which looks exactly like a defect, and a
// hard-coded word stops being the library's own answer the moment a bit moves.
//
// AND THE WORDS ARE NOT COMPARABLE ACROSS IMPLEMENTATIONS. Corrected 2026-10-14 by the
// op-codes lab: `0x3d586f` is THIS library's numbering of that flag set, and the reference
// numbers the same set `0x3d406f` from its own `script_flags.h`. The two agree on which flags
// are set and disagree on the bit positions, so comparing the hex between them is meaningless
// even when it happens to pass — which it did, earlier the same day, and was read as
// confirmation. What makes the rows below comparable is that the oracle maps flag NAMES to
// this library's constants; the assertion in the first test pins only that our own derivation
// has not moved.

require('chai').should()
const bsv = require('../..')
const Script = bsv.Script
const Interpreter = Script.Interpreter
const BN = bsv.crypto.BN
// The predicate itself, so the invariant below is asserted against the shared
// definition the parser and toBuffer use rather than a restatement of it.
const isUndecodablePush = require('../../dist/script/push-decode.js').isUndecodablePush

const POST_GENESIS = Interpreter.mainnetFlags()
const PRE_GENESIS = Interpreter.SCRIPT_VERIFY_P2SH |
  Interpreter.SCRIPT_VERIFY_STRICTENC |
  Interpreter.SCRIPT_VERIFY_DERSIG

const SATS = 1000

function txSpending (sigHex) {
  const t = new bsv.Transaction()
  t.version = 1
  t.from({ txId: '00'.repeat(32), outputIndex: 0, script: '51', satoshis: SATS })
  t.inputs[0].setScript(Script.fromHex(sigHex))
  t.to(bsv.PrivateKey.fromRandom().toAddress(), 500)
  return t
}

function verdict (lockHex, sigHex, flags) {
  const i = new Interpreter()
  const ok = i.verify(Script.fromHex(sigHex), Script.fromHex(lockHex),
    txSpending(sigHex), 0, flags, new BN(SATS))
  return ok ? 'ok' : i.errstr.replace(/^SCRIPT_ERR_/, '')
}

// lock, scriptSig, node's pre-Genesis verdict, node's post-Genesis verdict
const ROWS = [
  ['6a4c', '51', 'OP_RETURN', 'ok'],
  ['6a4d01', '51', 'OP_RETURN', 'ok'],
  ['6a4e0100', '51', 'OP_RETURN', 'ok'],
  ['6a01', '51', 'OP_RETURN', 'ok'],
  ['6a4c50' + 'cd'.repeat(10), '51', 'OP_RETURN', 'ok'],
  ['636a4c68', '51', 'OP_RETURN', 'BAD_OPCODE'],
  ['636a4d0168', '51', 'OP_RETURN', 'BAD_OPCODE'],
  ['636a01', '51', 'OP_RETURN', 'BAD_OPCODE'],
  ['636a4c68', '00', 'BAD_OPCODE', 'BAD_OPCODE'],
  ['636a4d0168', '00', 'BAD_OPCODE', 'BAD_OPCODE'],
  ['636a01', '00', 'BAD_OPCODE', 'BAD_OPCODE']
]

describe('a cut-off push length after OP_RETURN', function () {
  it('pins this library\'s own flag words, which are not the reference\'s numbering', function () {
    // These are OUR bit positions for that set of flags, recorded so a change to them shows up
    // here rather than silently moving every verdict below. They are deliberately NOT compared
    // with the reference's words: it numbers the same set differently (0x3d406f post-Genesis),
    // so an equal hex would be a coincidence and an unequal one would mean nothing.
    ;(POST_GENESIS >>> 0).should.equal(0x3d586f)
    ;(PRE_GENESIS >>> 0).should.equal(0x7)
  })

  describe('agrees with the node on all 22 judged rows', function () {
    ROWS.forEach(function (r) {
      it('lock ' + r[0] + ' sig ' + r[1] + ' pre-Genesis: ' + r[2], function () {
        verdict(r[0], r[1], PRE_GENESIS).should.equal(r[2])
      })
      it('lock ' + r[0] + ' sig ' + r[1] + ' post-Genesis: ' + r[3], function () {
        verdict(r[0], r[1], POST_GENESIS).should.equal(r[3])
      })
    })
  })

  describe('leniency is confined to a TOP-LEVEL OP_RETURN, and not by the parser', function () {
    // The parser cannot know what executed, so it is unconditionally permissive. What keeps
    // the IF cases strict is that they now PARSE and the interpreter decides — which is why
    // rows B1-B6 above were already correct before the parser changed and must stay so.
    it('still fails a cut-off push inside a TAKEN IF branch after OP_RETURN', function () {
      verdict('636a4c68', '51', POST_GENESIS).should.equal('BAD_OPCODE')
    })

    it('still fails one inside an UNTAKEN branch, because the branch is scanned', function () {
      verdict('636a4c68', '00', POST_GENESIS).should.equal('BAD_OPCODE')
    })

    it('still fails pre-Genesis, where OP_RETURN ends the script unsuccessfully', function () {
      verdict('6a4c', '51', PRE_GENESIS).should.equal('OP_RETURN')
    })
  })

  describe('the bytes survive, which is what a txid depends on', function () {
    const SHAPES = ['6a4c', '6a4d', '6a4d01', '6a4e', '6a4e01', '6a4e0100', '4c', '4d', '4e',
      '636a4c68', '6a4c50' + 'cd'.repeat(10)]

    it('round-trips every shape through toBuffer byte for byte', function () {
      SHAPES.forEach(function (hex) {
        Script.fromHex(hex).toHex().should.equal(hex)
      })
    })

    it('parses every byte string: fromBuffer is total', function () {
      // 282,400 sequences were fuzzed when this landed — every 1- and 2-byte script, every
      // 3-byte script opening with a pushdata opcode, and 20,000 random ones — with zero
      // throws and zero round-trip mismatches. A sample is kept here; the property is that
      // a Script can always be built from bytes, as the node's CScript can, and a decode
      // failure surfaces at USE instead.
      for (let a = 0; a < 256; a++) {
        for (let b = 0; b < 256; b++) {
          const buf = Buffer.from([a, b])
          Script.fromBuffer(buf).toBuffer().should.deep.equal(buf)
        }
      }
    })

    it('keeps the two prefix lengths distinct in the text forms', function () {
      // `6a4d` and `6a4d01` have no push to render and no length token to render it with. If
      // both took the no-data branch they would print as `OP_RETURN OP_PUSHDATA2`: two
      // different scripts, one text. This file's sibling fixed that exact shape once already,
      // for unnamed opcodes written as bare hex.
      Script.fromHex('6a4d').toString().should.not.equal(Script.fromHex('6a4d01').toString())
      Script.fromHex('6a4d').toString().should.equal('OP_RETURN 0x4d')
      Script.fromHex('6a4d01').toString().should.equal('OP_RETURN 0x4d01')
      Script.fromHex('6a4c').toASM().should.equal('OP_RETURN 0x4c')
    })

    // The shapes above whose ONLY undecodable chunk is a cut-off length prefix. The other two
    // carry a complete prefix and short data, which the ASM grammar cannot write at all (see
    // the test after this one).
    const PREFIX_SHAPES = ['6a4c', '6a4d', '6a4d01', '6a4e', '6a4e01', '6a4e0100', '4c', '4d', '4e']

    it('reads that text back as the same script, through both text forms', function () {
      // This used to throw, and a comment here used to claim it read back as bare opcode
      // chunks. Neither was good enough: `toString` was emitting a token its own `fromString`
      // refused, so the text forms were write-only for a script that is on livenet. The
      // grammar had no way to say "a pushdata opcode with FEWER prefix bytes than its length
      // field takes", because `rawOpcodeToken` deliberately refuses a push byte. So
      // `_chunkToString` writes the raw bytes and `lenPrefixToken` reads them back — the same
      // escape this grammar already used for an opcode with no name.
      //
      // Measured over every 1- and 2-byte script plus every 3-byte script opening with a
      // pushdata opcode (590,080 parsed, 382,540 of them carrying an undecodable push):
      // fromString(toString()) returns the identical bytes for every one — 0 throws, 0 drift,
      // 0 isPushOnly changes. Before this, 69,448 of them threw.
      PREFIX_SHAPES.forEach(function (hex) {
        const s = Script.fromHex(hex)
        Script.fromString(s.toString()).toHex().should.equal(hex)
        Script.fromASM(s.toASM()).toHex().should.equal(hex)
        // and the same chunk, not merely the same bytes
        Script.fromString(s.toString()).chunks.should.deep.equal(s.chunks)
        Script.fromString(s.toString()).isPushOnly().should.equal(s.isPushOnly())
      })
    })

    it('accepts only tokens the grammar had no meaning for before', function () {
      // A new token rule is safe only if every token it accepts was previously REFUSED, and the
      // sweep above cannot see that, because it only ever feeds back text this library wrote.
      // The legacy spelling writes a push's LENGTH as a raw byte token — `0x47 0x3044…`, which
      // several tests in test/script/script.js use — so a rule that swallowed `0x47` would break
      // it. A general "these bytes, as one chunk" rule did exactly that, in 13 existing tests.
      //
      // This rule accepts a token only when its first byte is PUSHDATA1/2/4 AND fewer length
      // bytes follow than that opcode takes. Its six tokens are never a legacy length token
      // (0x01–0x4b) and never an unnamed opcode (above 0x4e), which is why nothing that parsed
      // before parses differently.
      const ACCEPTED = ['0x4c', '0x4d', '0x4d01', '0x4e', '0x4e01', '0x4e0100']
      ACCEPTED.forEach(function (t) {
        parseInt(t.slice(2, 4), 16).should.be.within(0x4c, 0x4e)
        Script.fromString(t).toHex().should.equal(t.slice(2))
        Script.fromASM(t).toHex().should.equal(t.slice(2))
      })
      // the legacy two-token data spelling is untouched
      Script.fromString('0x47 0x' + '11'.repeat(71)).toHex().should.equal('47' + '11'.repeat(71))
      // a COMPLETE length prefix is not this rule's business and still falls through
      ;(function () { Script.fromString('0x4c05') }).should.throw()
    })

    it('still cannot write a SHORT-DATA push in ASM, which is older than this and not ours', function () {
      // A push whose length prefix is complete and whose data is short has no ASM form: ASM
      // writes a push as its bare hex, and that hex is then read back as a push of exactly
      // that many bytes. So `4c05` + 2 bytes comes back as a 2-byte push. Nothing was broken
      // here by the cut-off-prefix work, and nothing is claimed to be fixed: in the sweep
      // above, 313,095 scripts come back from ASM with different bytes and 256,693 change
      // their `isPushOnly` answer, and @smartledger/bsv 9.36.0 gives the same two numbers
      // (313,092 and 256,693 — the three are empty PUSHDATA1 pushes, `4c004c`, whose
      // non-minimal encoding ASM also cannot write, and which only moved out of the throwing
      // column into this one).
      //
      // The pair that IS exact for all of them is toString/fromString, asserted above.
      const short = Script.fromHex('6a4c50' + 'cd'.repeat(10))
      Script.fromString(short.toString()).toHex().should.equal('6a4c50' + 'cd'.repeat(10))
      Script.fromASM(short.toASM()).toHex().should.not.equal('6a4c50' + 'cd'.repeat(10))
      // ASM reads those ten bytes back as a complete ten-byte push
      Script.fromASM(short.toASM()).toHex().should.equal('6a0a' + 'cd'.repeat(10))
    })
  })

  describe('every consumer that rebuilds or reads chunks keeps the bytes', function () {
    // A review of the change asked the right question: a malformed tail can be UNEXECUTED and
    // still be part of the bytes a signature covers. If any transform that rebuilds chunks
    // dropped it, this library would sign a different scriptCode from the node — a consensus
    // defect that no accept/reject test would see. So it is measured, not reasoned about.
    const bsvlib = require('../..')
    const Sighash = bsvlib.Transaction.Sighash
    const KEY = bsvlib.PrivateKey.fromBuffer(Buffer.from('11'.repeat(32), 'hex'))
    const SIGHASH = bsvlib.crypto.Signature.SIGHASH_ALL | bsvlib.crypto.Signature.SIGHASH_FORKID
    const LOCK = '21' + KEY.toPublicKey().toHex() + 'ac' + '6a4c'

    function spendingTx () {
      const t = new bsvlib.Transaction()
      t.version = 1
      t.from({ txId: '11'.repeat(32), outputIndex: 0, script: LOCK, satoshis: SATS })
      t.to(KEY.toAddress(), 4000)
      return t
    }

    // Read the next test with its hash type in view: 0x41 is FORKID, so this is the BIP-143
    // digest, which serializes the scriptCode through the plain CScript writer and does carry
    // every byte. The ORIGINAL algorithm does NOT: it writes only the bytes up to where the
    // script walk fails, while declaring the full length, and this library did not until
    // 2026-10-15. See test/transaction/sighash_scriptcode_tail.js, which measures all 55 rows of
    // a compiled node's reference corpus. `6a4c` below would be unaffected either way — its
    // partial prefix is empty — so nothing here was wrong, only narrower than it reads.
    it('signs the cut-off push, because the scriptCode is the whole locking script', function () {
      const lock = Script.fromHex(LOCK)
      const pre = Sighash.sighashPreimage(spendingTx(), SIGHASH, 0, lock, new BN(SATS)).toString('hex')
      pre.indexOf(LOCK).should.be.above(-1, 'the signed scriptCode must contain the tail')
      // And the varint before it must declare the full length, or the tail is signed as
      // something shorter than it is.
      const at = pre.indexOf(LOCK)
      pre.slice(at - 2, at).should.equal((LOCK.length / 2).toString(16))
    })

    it('produces a signature that verifies against that lock', function () {
      const lock = Script.fromHex(LOCK)
      const tx = spendingTx()
      const sig = Sighash.sign(tx, KEY, SIGHASH, 0, lock, new BN(SATS))
      tx.inputs[0].setScript(Script.fromASM(sig.toTxFormat().toString('hex')))
      const i = new Interpreter()
      i.verify(tx.inputs[0].script, lock, tx, 0, POST_GENESIS, new BN(SATS))
        .should.equal(true, i.errstr)
    })

    describe('a tail inside an IF after the OP_RETURN is signed but never read', function () {
      // The sharpest case, and one a peer had reasoned was unobservable. A cut-off push inside
      // an IF that comes BEFORE the OP_RETURN is BAD_OPCODE at the scan, so no signature is
      // ever reached (rows B1-B3 above). But post-Genesis an executed TOP-LEVEL OP_RETURN
      // stops evaluation entirely — the node's comment says the remainder "does not affect the
      // validity (even in presence of unbalanced IFs, invalid opcodes etc)" — so an IF placed
      // AFTER it holds bytes that are never read and still signed. That is precisely the gap
      // where a verdict can agree while the signed bytes differ.
      //
      // OP_CHECKSIG, not CHECKSIGVERIFY: the stack needs a result when OP_RETURN stops, or
      // both arms land on EVAL_FALSE_NO_RESULT and the signal is lost.
      //
      // NODE-CONFIRMED 2026-10-14. A compiled bitcoin-sv v1.2.3 judged all 30 rows of the
      // op-codes lab's sighash-tail set, this construction among them, and agrees on every
      // verdict. Until then these were our verdicts computed from our own preimage, which is
      // the weaker claim and was labelled as such.
      //
      // The IF is deliberately unbalanced. A balanced `63 4c 68` puts a truncated-DATA push
      // inside the IF instead, because the `68` is eaten as the length byte — so a cut-off
      // PREFIX inside an IF can only sit at the very end of the script.
      const TAILS = {
        'a cut-off PUSHDATA1': '634c',
        'a cut-off PUSHDATA2': '634d01',
        'a short DATA push': '634c50' + 'cd'.repeat(10),
        'a nested IF': '63634e0100'
      }

      function attempt (lockHex, signedOverHex) {
        const tx = spendingTx()
        const sig = Sighash.sign(tx, KEY, SIGHASH, 0, Script.fromHex(signedOverHex), new BN(SATS))
        tx.inputs[0].setScript(Script.fromASM(sig.toTxFormat().toString('hex')))
        const i = new Interpreter()
        const ok = i.verify(tx.inputs[0].script, Script.fromHex(lockHex), tx, 0,
          POST_GENESIS, new BN(SATS))
        return ok ? 'accept' : i.errstr.replace(/^SCRIPT_ERR_/, '')
      }

      const BASE = '21' + KEY.toPublicKey().toHex() + 'ac' + '6a'

      Object.keys(TAILS).forEach(function (label) {
        it('signs ' + label + ', so only the full-lock signature verifies', function () {
          const lock = BASE + TAILS[label]
          attempt(lock, lock).should.equal('accept')
          attempt(lock, BASE).should.equal('NULLFAIL')
        })
      })

      it('gives no signal without a tail, which is what makes the rows above mean something', function () {
        // Without this control, "accept / NULLFAIL" could come from any signature mismatch and
        // would say nothing about the tail.
        attempt(BASE, BASE).should.equal('accept')
      })
    })

    it('keeps the chunk through removeCodeseparators', function () {
      Script.fromHex('ab6a4c').removeCodeseparators().toHex().should.equal('6a4c')
    })

    it('keeps the chunk through findAndDelete', function () {
      Script.fromHex('516a4c').findAndDelete(Script.fromHex('51')).toHex().should.equal('6a4c')
      // And does not delete it when asked for something else.
      Script.fromHex('6a4c').findAndDelete(Script.fromHex('51')).toHex().should.equal('6a4c')
    })

    it('leaves isScriptHashIn answering as it did, for every newly-parseable shape', function () {
      // It used the parse THROW to answer false. Those buffers parse now, so the answer comes
      // from classify() instead — which only agrees if none of them classifies as a known
      // type. 66,585 shapes were enumerated when this landed and none did; a sample is kept.
      //
      // The pushdata opcode has to come LAST for its length field to be the thing that is
      // missing. Written the other way round the loop built `4c<a>` — a PUSHDATA1 whose length
      // byte IS present and whose data is short, which is the case that already agreed — and
      // reached no new shape at all. The `checked` assertion below is what caught that.
      let checked = 0
      ;[0x4c, 0x4d, 0x4e].forEach(function (op) {
        for (let a = 0; a < 256; a++) {
          const buf = Buffer.from([a, op])
          const sc = Script.fromBuffer(buf)
          if (!sc.chunks.some(function (c) { return c.lenPrefix !== undefined })) continue
          checked++
          sc.classify().should.equal(Script.types.UNKNOWN, buf.toString('hex'))
        }
      })
      checked.should.be.above(0, 'the loop must actually reach the new shapes')
    })

    it('serializes a hand-assembled chunk after one, with the stated hand-assembly limit', function () {
      // Not a defect, and not a supported construction: a chunk placed after a cut-off prefix
      // serializes to bytes in which the following chunk IS the length field, so it re-parses
      // as one chunk. lib/script/push-decode.js already states that a hand-assembled chunk
      // list must be round-tripped through Script.fromBuffer(script.toBuffer()) before any
      // predicate is asked of it. Pinned so the behaviour is known rather than discovered.
      const s = new Script()
      s.chunks = [{ opcodenum: 0x4c, lenPrefix: Buffer.alloc(0) }, { opcodenum: 0x51 }]
      s.toHex().should.equal('4c51')
      Script.fromHex('4c51').chunks.length.should.equal(1)
    })
  })

  describe('an output carrying one is a normal output now', function () {
    const RAW = '0100000001' + '00'.repeat(32) + 'ffffffff' + '0100' + 'ffffffff' +
      '01' + '0100000000000000' + '02' + '6a4c' + '00000000'

    it('gives output.script a Script rather than null', function () {
      const tx = new bsv.Transaction(RAW)
      tx.outputs[0].script.toHex().should.equal('6a4c')
      tx.outputs[0]._scriptBuffer.toString('hex').should.equal('6a4c')
    })

    it('round-trips the transaction byte-exact', function () {
      new bsv.Transaction(RAW).toString().should.equal(RAW)
    })

    it('is NOT a data output, and that is the consistent answer', function () {
      // `isDataOut` is OP_RETURN followed by push-only, and an undecodable push is not
      // push-only — which is the node's own answer from `IsPushOnly` once `GetOp` has failed.
      // So this is false, while a COMPLETE push after OP_RETURN (`6a4c0a` + ten bytes) is
      // true. The node has no isDataOut of its own, so what is pinned here is internal
      // consistency with isPushOnly rather than agreement with a reference.
      Script.fromHex('6a4c').isDataOut().should.equal(false)
      Script.fromHex('6a4c0a' + 'cd'.repeat(10)).isDataOut().should.equal(true)
    })

    it('leaves an undecodable push as the FINAL chunk, which is what keeps findAndDelete honest', function () {
      // This invariant is load-bearing and was asked for by the lab, which noted that
      // FindAndDelete with a signature present was not covered by its preimage run.
      //
      // The node's CScript::FindAndDelete (script.h) is
      //
      //   do {
      //       result.insert(result.end(), pc2, pc);
      //       while (end() - pc >= b.size() && std::equal(b.begin(), b.end(), pc)) {
      //           pc = pc + b.size(); ++nFound;
      //       }
      //       pc2 = pc;
      //   } while (GetOp(pc, opcode));
      //   if (nFound > 0) { result.insert(result.end(), pc2, end()); *this = result; }
      //
      // so iteration STOPS at the first GetOp failure and everything from there to the end
      // is copied through verbatim, never searched. Our findAndDelete instead walks every
      // chunk. Those two would disagree if a chunk could FOLLOW an undecodable push: the
      // node would preserve a later signature, we would delete it, and the scriptCode fed
      // to the sighash preimage would differ — a consensus-visible divergence in the
      // non-FORKID path, where CleanupScriptCode calls FindAndDelete.
      //
      // It cannot, and the reason is that both ways GetOp fails are the same fact: the
      // script ran out of bytes. A cut-off length prefix has no bytes after it by
      // definition, and a push whose data is short consumed the rest of the script. So an
      // undecodable push is necessarily TERMINAL, there is nothing after it to disagree
      // about, and the node's stopping point is the end of the script either way.
      //
      // Measured over 22,635 parsed byte strings (exhaustive to length 4 over a 12-byte
      // alphabet of pushdata, OP_RETURN and ordinary opcodes, plus the livenet shapes):
      // 17,141 contained an undecodable push and in every one it was the last chunk.
      const alphabet = [0x00, 0x01, 0x02, 0x4b, 0x4c, 0x4d, 0x4e, 0x51, 0x6a, 0x76, 0xac, 0xff]
      let seen = 0
      function check (bytes) {
        const s = Script.fromBuffer(Buffer.from(bytes))
        for (let i = 0; i < s.chunks.length; i++) {
          if (isUndecodablePush(s.chunks[i])) {
            seen++
            i.should.equal(s.chunks.length - 1,
              'undecodable push not final in ' + Buffer.from(bytes).toString('hex'))
          }
        }
      }
      function rec (prefix, depth) {
        if (prefix.length) check(prefix)
        if (depth === 3) return
        for (let i = 0; i < alphabet.length; i++) rec(prefix.concat([alphabet[i]]), depth + 1)
      }
      rec([], 0)
      seen.should.be.above(0) // the sweep must actually reach the condition

      // And the consequence, stated directly: the tail survives findAndDelete.
      const sig = Buffer.from('3006020101020101', 'hex')
      const s = Script.fromBuffer(Buffer.concat([
        Buffer.from([sig.length]), sig, Buffer.from('6a4c', 'hex')
      ]))
      s.findAndDelete(Script.fromBuffer(Buffer.concat([Buffer.from([sig.length]), sig])))
      s.toHex().should.equal('6a4c')
    })

    it('does not throw from any text or predicate path', function () {
      // The peer's original spec asked for toASM/toString/isDataOut to show an opaque tail
      // rather than throw. They do not throw; this pins that none of them does.
      ;['6a4c', '6a4d01', '6a4e0100', '4c'].forEach(function (hex) {
        const s = Script.fromHex(hex)
        ;(function () { s.toString(); s.toASM(); s.isDataOut(); s.isPushOnly(); s.toHex() })
          .should.not.throw()
      })
    })
  })
})
