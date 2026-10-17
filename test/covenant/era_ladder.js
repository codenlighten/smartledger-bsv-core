'use strict'

/* global describe, it */

// The era ladder, pinned here because the sibling @smartledger/bsv pins it too and two
// implementations agreeing is worth nothing unless something fails when they drift.
//
//   Monolith (2018)  OP_SPLIT / OP_CAT and that group become available, and CANNOT be disabled
//                    in either implementation — so neither can answer about an earlier rule set.
//                    A verify() here is not era-evidence about pre-Monolith; it answers
//                    confidently about rules it does not model, which is worse than a no-op.
//   Genesis (2020)   element size and script numbers become unbounded. REQUIRED BY THE GATE:
//                    the preimage is 536 bytes against a 520-byte pre-Genesis element limit,
//                    and the in-script s = (e + Gx) mod n arithmetic is 32 bytes against a
//                    4-byte CScriptNum cap. Either limit alone sinks it.
//   Chronicle        OP_SUBSTR / OP_LEFT / OP_RIGHT return. Before it they are SILENT NO-OPS,
//                    not errors — they leave their operands on the stack — so a covenant that
//                    reads the preimage by slicing fails closed rather than running on the
//                    wrong stack.
//
// Both implementations were measured to agree on every rung on 2026-10-17. The mistake that
// produced this file is worth keeping: a peer and I each attributed a real pre-Genesis failure
// to OPCODE AVAILABILITY — OP_SPLIT being "unavailable" — when the actual gate was a SIZE
// LIMIT. Opcodes are the salient axis because documentation lists them, and here they were the
// wrong axis. Check the limits, not just the opcode table.

require('chai').should()
const bsv = require('../..')
const I = bsv.Script.Interpreter
const P = bsv.Covenant.PushTx
const H = bsv.Covenant.Helpers

const SATS = 50000
const FEE = 500
const MAIN = H.flags()
const PRE_CHRONICLE = MAIN & ~I.SCRIPT_UTXO_AFTER_CHRONICLE
const PRE_GENESIS = MAIN & ~(I.SCRIPT_UTXO_AFTER_GENESIS | I.SCRIPT_GENESIS |
  I.SCRIPT_UTXO_AFTER_CHRONICLE | I.SCRIPT_ENABLE_CHRONICLE)

function scratchTx () {
  const tx = new bsv.Transaction()
  tx.from(new bsv.Transaction.UnspentOutput({
    txId: 'e'.repeat(64), outputIndex: 0, script: '51', satoshis: SATS
  }))
  tx.to(bsv.PrivateKey.fromBuffer(Buffer.from('44'.repeat(32), 'hex')).toAddress(), 500)
  return tx
}

function raw (hex, flags) {
  const interp = new I()
  interp.verify(new bsv.Script(), bsv.Script.fromHex(hex), scratchTx(), 0, flags,
    new bsv.crypto.BN(SATS))
  return { err: interp.errstr || '', depth: interp.stack.length }
}

describe('era ladder (twin of @smartledger/bsv)', () => {
  it('Monolith: OP_SPLIT cannot be disabled, so this is not pre-Monolith evidence', () => {
    const hex = '06616263646566' + '52' + '7f' // <"abcdef"> 2 OP_SPLIT
    ;[I.SCRIPT_VERIFY_NONE, MAIN, PRE_GENESIS, PRE_CHRONICLE].forEach(flags => {
      raw(hex, flags).err.should.equal('', 'OP_SPLIT must run under every flag set')
    })
  })

  it('Chronicle: the splice opcodes are silent no-ops before it, not errors', () => {
    const hex = '06616263646566' + '51' + '52' + 'b3' // ... OP_SUBSTR
    const pre = raw(hex, PRE_CHRONICLE)
    pre.err.should.not.match(/BAD_OPCODE/, 'a no-op, not a rejection — that is the hazard')
    pre.depth.should.equal(3, 'the operands are left where they were')
    raw(hex, MAIN).depth.should.equal(1, 'and it really slices once enabled')
  })

  it('Genesis: both limits the gate depends on are era-gated, isolated', () => {
    const bigPush = '4d' + '1802' + 'aa'.repeat(536) + '51'
    raw(bigPush, PRE_GENESIS).err.should.equal('SCRIPT_ERR_PUSH_SIZE')
    raw(bigPush, MAIN).err.should.equal('')
    const bigArith = '20' + 'dd'.repeat(32) + '20' + 'ee'.repeat(32) + '93' + '75' + '51'
    raw(bigArith, PRE_GENESIS).err.should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
    raw(bigArith, MAIN).err.should.equal('')
  })

  it('the gate needs Genesis and not Chronicle, with the same bytes as the sibling', () => {
    const lock = P.authenticator()
    lock.toBuffer().length.should.equal(377, 'the sibling emits the same 377 bytes')
    const priv = bsv.PrivateKey.fromBuffer(Buffer.from('55'.repeat(32), 'hex'))
    const out = new bsv.Transaction.Output({
      script: bsv.Script.buildPublicKeyHashOut(priv.toAddress()), satoshis: SATS - FEE
    })
    const spend = H.fundAndSpend(lock, SATS, { outputs: [out] }).spend
    P.grind(spend, 0, lock, SATS)
    const preimage = H.rawPreimage(spend, 0, lock, SATS)
    preimage.length.should.be.above(520, 'the pre-Genesis element limit is 520 bytes')
    const unlock = new bsv.Script().add(Buffer.from(preimage))
    spend.inputs[0].setScript(unlock)

    const verify = (flags) => {
      const interp = new I()
      const ok = interp.verify(unlock, lock, spend, 0, flags, new bsv.crypto.BN(SATS))
      return { ok, err: interp.errstr || '' }
    }
    verify(MAIN).ok.should.equal(true)
    verify(PRE_CHRONICLE).ok.should.equal(true, 'the gate uses no Chronicle-gated opcode')
    const preGen = verify(PRE_GENESIS)
    preGen.ok.should.equal(false)
    preGen.err.should.equal('SCRIPT_ERR_PUSH_SIZE', 'the preimage cannot even be pushed')
  })
})
