'use strict'

/* global describe, it */

// A truncated push in a scriptSig was reported as SCRIPT_ERR_BAD_OPCODE where the SV Node
// reports SCRIPT_ERR_SIG_PUSHONLY. Both reject, so this is an error-NAME and check-ORDER
// divergence, not an accept/reject one — the fifth of that family found in this library,
// and the first found by someone outside the project.
//
// The node's ordering is explicit in VerifyScript: the push-only gate runs ABOVE EvalScript,
//
//     if(VerifySigPushOnly(flags)) {
//         if(...era...) {
//             if(!scriptSig.IsPushOnly())
//                 return SCRIPT_ERR_SIG_PUSHONLY;           // interpreter.cpp:2329-2331
//         }
//     }
//     ... EvalScript(... scriptSig ...)
//
// and IsPushOnly walks the script with GetOp, which FAILS on a push running past the end.
// So the node never evaluates the script. This library's isPushOnly tested only each chunk's
// opcode number, said a truncated push was a push, passed the gate, evaluated, and reported
// the instruction-read failure from EvalScript instead.
//
// Ported from @smartledger/bsv 9.33.1. Reported against bsv 9.33.0 and this package at
// 1.5.0 by the op-codes lab, from 24 vectors judged by a compiled bitcoin-sv v1.2.3;
// reproduced in both packages before being accepted, and IsPushOnly, GetOp2, VerifyScript
// and Solver were read at v1.2.3 to confirm the mechanism rather than the symptom.

require('chai').should()
const bsv = require('../..')
const Script = bsv.Script
const Interpreter = bsv.Script.Interpreter
const BN = bsv.crypto.BN

const LOCK = Script.fromHex('7551') // OP_DROP OP_1 — accepts whatever the scriptSig pushed

// Every way a push can declare more bytes than the script carries. `len` is the declared
// length, `buf` holds what is actually there.
const TRUNCATED = {
  'OP_PUSHDATA1 declaring 80 of 10': '4c50' + 'cd'.repeat(10),
  'OP_PUSHDATA2 declaring 80 of 10': '4d5000' + 'cd'.repeat(10),
  'OP_PUSHDATA4 declaring 80 of 10': '4e50000000' + 'cd'.repeat(10),
  'a direct push declaring 75 of 10': '4b' + 'cd'.repeat(10),
  'a direct push declaring 10 of 5': '0a' + 'cd'.repeat(5),
  'a one-byte push with no byte after it': '01'
}

function run (sigHex, flags) {
  const i = new Interpreter()
  const ok = i.verify(Script.fromHex(sigHex), LOCK, undefined, 0, flags, new BN(0))
  return { ok, errstr: i.errstr }
}

describe('a truncated push in a scriptSig', function () {
  describe('is refused by the push-only gate, above evaluation', function () {
    Object.keys(TRUNCATED).forEach(function (label) {
      it('reports SIG_PUSHONLY for ' + label, function () {
        const r = run(TRUNCATED[label], Interpreter.mainnetFlags())
        r.ok.should.equal(false)
        r.errstr.should.equal('SCRIPT_ERR_SIG_PUSHONLY')
      })
    })
  })

  describe('falls back to the instruction read when that gate does not apply', function () {
    // Without SCRIPT_VERIFY_SIGPUSHONLY there is no gate to fail, and the node reports the
    // decode failure from EvalScript — which is what this library already did everywhere and
    // must keep doing. Pinned so the fix cannot be mistaken for "SIG_PUSHONLY always".
    it('reports BAD_OPCODE with the flag off', function () {
      const flags = Interpreter.mainnetFlags() & ~Interpreter.SCRIPT_VERIFY_SIGPUSHONLY
      Object.keys(TRUNCATED).forEach(function (label) {
        run(TRUNCATED[label], flags).errstr
          .should.equal('SCRIPT_ERR_BAD_OPCODE', label)
      })
    })

    it('reports BAD_OPCODE pre-Genesis, where push-only is not required at all', function () {
      // The flag is set, but the era test inside the gate is not satisfied, so the new error
      // must not leak backwards into pre-Genesis scripts.
      const flags = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_VERIFY_SIGPUSHONLY
      Object.keys(TRUNCATED).forEach(function (label) {
        run(TRUNCATED[label], flags).errstr
          .should.equal('SCRIPT_ERR_BAD_OPCODE', label)
      })
    })
  })

  describe('leaves honest scripts exactly as they were', function () {
    it('still verifies a push that carries its bytes', function () {
      run('0a' + 'cd'.repeat(10), Interpreter.mainnetFlags()).ok.should.equal(true)
    })

    it('still reports MINIMALDATA for a non-minimal push, not SIG_PUSHONLY', function () {
      // A non-minimal push IS push-only, so it passes the gate and fails later.
      run('4c0a' + 'cd'.repeat(10), Interpreter.mainnetFlags()).errstr
        .should.equal('SCRIPT_ERR_MINIMALDATA')
    })

    it('still reports SIG_PUSHONLY for an ordinary non-push opcode', function () {
      run('75', Interpreter.mainnetFlags()).errstr.should.equal('SCRIPT_ERR_SIG_PUSHONLY')
    })

    it('still accepts the empty pushes and OP_RESERVED', function () {
      Script.fromHex('4c00').isPushOnly().should.equal(true)
      Script.fromHex('00').isPushOnly().should.equal(true)
      Script.fromHex('50').isPushOnly().should.equal(true)
    })
  })

  describe('the condition is `<`, not `!==`', function () {
    it('does not refuse a chunk whose buffer is longer than its declared length', function () {
      // GetOp2 fails when FEWER bytes remain than the push declares, and nothing else. A
      // chunk holding MORE bytes than it declares is not a truncated push: it is a chunk
      // that disagrees with its own serialization, and the extra bytes are the instructions
      // that follow. Writing this `!==` cost a FALSE REJECT, measured:
      //
      //   { opcodenum: 1, len: 1, buf: <aa51> }  serializes to  01 aa 51
      //   01 aa 51 parses back as                push <aa>, OP_1   -- both push-only
      //
      // so the node, which only ever sees the bytes, answers true.
      const hand = new Script({ chunks: [{ opcodenum: 1, len: 1, buf: Buffer.from('aa51', 'hex') }] })
      hand.toHex().should.equal('01aa51')
      Script.fromHex('01aa51').isPushOnly().should.equal(true)
      hand.isPushOnly().should.equal(true)
    })
  })

  describe('the data-output classifications move with it, as the node\'s do', function () {
    // The node classifies TX_NULL_DATA with the SAME IsPushOnly, applied to the script after
    // the OP_RETURN, or after OP_FALSE OP_RETURN:
    //
    //   if (isOpReturn && scriptPubKey.IsPushOnly(scriptPubKey.begin() + offset)) {
    //       typeRet = TX_NULL_DATA;                          // standard.cpp, Solver
    it('stops classifying a truncated push as a data output', function () {
      Script.fromHex('6a' + '4c50' + 'cd'.repeat(10)).isDataOut().should.equal(false)
      Script.fromHex('006a' + '4c50' + 'cd'.repeat(10)).isSafeDataOut().should.equal(false)
    })

    it('still classifies the honest ones', function () {
      Script.fromHex('6a' + '4c0a' + 'cd'.repeat(10)).isDataOut().should.equal(true)
      Script.fromHex('006a' + '4c0a' + 'cd'.repeat(10)).isSafeDataOut().should.equal(true)
    })
  })

  describe('a push with a truncated LENGTH FIELD is a separate, open divergence', function () {
    // `4c`, `4d01`, `4e0100`: GetOp2 fails at the LENGTH read rather than the data read, so
    // the node builds a script object and refuses it at evaluation. This library parses
    // eagerly and has nothing to put in `len`, so Script.fromBuffer throws and there is no
    // Script object to evaluate — no verdict at all. Both sides still reject and the throw is
    // fail-closed, so nothing is accepted that should not be. Not fixed here: giving the
    // parser a representation for an instruction it could not decode changes what
    // fromBuffer may return, which is a design decision with its own false-accept risk.
    // Recorded in the bsv repo's docs/NODE_DIVERGENCES.md.
    //
    // What is pinned is CONTAINMENT: a typed, catchable error at the boundary.
    const NO_LENGTH_FIELD = ['4c', '4d01', '4e0100']

    it('throws a typed Script.InvalidBuffer, not an internal error', function () {
      NO_LENGTH_FIELD.forEach(function (hex) {
        let caught = null
        try { Script.fromHex(hex) } catch (e) { caught = e }
        ;(caught === null).should.equal(false, hex + ' parsed when it should have thrown')
        caught.should.be.instanceof(bsv.errors.Script.InvalidBuffer)
        caught.message.should.match(/Invalid script buffer/)
      })
    })
  })

  describe('arrives this way from the wire, not only from fromHex', function () {
    it('survives transaction parsing and is then refused', function () {
      // How such a script actually reaches a verifier: the scriptSig is a length-prefixed
      // byte string in the transaction, so a truncated push inside it parses fine as a
      // transaction and only the script is malformed.
      const sig = '4c50' + 'cd'.repeat(10)
      const txHex = [
        '01000000', '01', 'ab'.repeat(32), '00000000',
        (sig.length / 2).toString(16).padStart(2, '0'), sig,
        'ffffffff', '00', '00000000'
      ].join('')
      const tx = new bsv.Transaction(txHex)
      tx.inputs[0].script.toHex().should.equal(sig)
      tx.inputs[0].script.isPushOnly().should.equal(false)
      run(tx.inputs[0].script.toHex(), Interpreter.mainnetFlags()).errstr
        .should.equal('SCRIPT_ERR_SIG_PUSHONLY')
    })
  })
})
