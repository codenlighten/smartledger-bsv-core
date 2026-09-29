'use strict'

/* global describe, it */

// Which digest a signature asks for, and who decides.
//
// The node routes on the sighash type byte alone (interpreter.cpp, SignatureHash):
//
//   if(enabledSighashForkid && sigHashType.hasForkId() && !sigHashType.hasChronicle())
//       return SignatureHashBIP143(...);
//   return SignatureHashOriginal(...);
//
// This library used to require SCRIPT_ENABLE_CHRONICLE before honouring the 0x20 bit.
// The concern behind that gate was real — pre-Chronicle BIP-143 signatures exist whose
// type byte happens to set 0x20 — but the node answers it in CheckSignatureEncoding,
// which refuses such a signature as SCRIPT_ERR_ILLEGAL_CHRONICLE before any digest is
// taken. Gating it here instead made the digest depend on a flag the node never
// consults, and it split this library against itself: tx.sign() always produced
// BIP-143, while verification used the original algorithm once the flag was set, so a
// signature this library produced was rejected by its own interpreter.

require('chai').should()
const bsv = require('../..')
const Script = bsv.Script
const Interpreter = bsv.Script.Interpreter
const Signature = bsv.crypto.Signature
const BN = bsv.crypto.BN
const Transaction = bsv.Transaction

const key = bsv.PrivateKey.fromWIF('cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY')
const SATS = 10000
const ALL_FORKID = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
const ALL_FORKID_CHRONICLE = ALL_FORKID | Signature.SIGHASH_CHRONICLE

function spend (lock) {
  const tx = new Transaction()
  tx.addInput(new Transaction.Input({
    prevTxId: Buffer.alloc(32, 9),
    outputIndex: 0,
    script: new Script(),
    sequenceNumber: 0xffffffff
  }), lock, SATS)
  tx.to(key.toAddress(), SATS - 1000)
  return tx
}

function signAndVerify (type, flags) {
  const lock = Script.buildPublicKeyHashOut(key.toAddress())
  const tx = spend(lock)
  const sig = Transaction.Sighash.sign(tx, key, type, 0, lock, new BN(SATS), flags)
  const unlock = new Script()
    .add(Buffer.concat([sig.toDER(), Buffer.from([type & 0xff])]))
    .add(key.toPublicKey().toBuffer())
  const interp = new Interpreter()
  const ok = interp.verify(unlock, lock, tx, 0, flags, new BN(SATS))
  return { ok, errstr: interp.errstr }
}

describe('the Chronicle sighash bit decides the digest, not a flag', function () {
  const lock = Script.buildPublicKeyHashOut(key.toAddress())
  const tx = spend(lock)
  const digest = (type, flags) =>
    Transaction.Sighash.sighash(tx, type, 0, lock, new BN(SATS), flags).toString('hex')

  it('takes the original algorithm whenever the bit is set, flag or no flag', function () {
    const withFlag = digest(ALL_FORKID_CHRONICLE,
      Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID | Interpreter.SCRIPT_ENABLE_CHRONICLE)
    const withoutFlag = digest(ALL_FORKID_CHRONICLE, Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID)
    withoutFlag.should.equal(withFlag, 'the digest must not depend on SCRIPT_ENABLE_CHRONICLE')
  })

  it('still takes BIP-143 when the bit is clear', function () {
    const bip143 = digest(ALL_FORKID, Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID)
    bip143.should.not.equal(digest(ALL_FORKID_CHRONICLE, Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID))
  })

  // The bug this closes, stated as money: a signature the library produced and then
  // refused. Before the fix this verified false with SCRIPT_ERR_NULLFAIL.
  it('verifies a signature it produced itself, with the bit set', function () {
    const r = signAndVerify(ALL_FORKID_CHRONICLE, Interpreter.mainnetFlags())
    r.ok.should.equal(true, r.errstr)
  })

  it('verifies a signature it produced itself, with the bit clear', function () {
    const r = signAndVerify(ALL_FORKID, Interpreter.mainnetFlags())
    r.ok.should.equal(true, r.errstr)
  })

  it('refuses a signature asking for the original digest outside Chronicle', function () {
    // CheckSignatureEncoding is where the node stops a pre-Chronicle signature whose
    // type byte happens to set 0x20, which is what lets the digest route on the bit.
    const flags = Interpreter.SCRIPT_VERIFY_STRICTENC |
      Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID
    const r = signAndVerify(ALL_FORKID_CHRONICLE, flags)
    r.ok.should.equal(false)
    r.errstr.should.equal('SCRIPT_ERR_ILLEGAL_CHRONICLE')
  })

  it('does not edit the script it was handed', function () {
    // The original algorithm removes code separators. It used to do that in place, on
    // a Script the caller still holds — and on a covenant path that is the script a
    // later signature covers.
    const subscript = new Script()
      .add(Buffer.alloc(4, 7))
      .add(bsv.Opcode.OP_CODESEPARATOR)
      .add(bsv.Opcode.OP_DROP)
    const before = subscript.toHex()
    Transaction.Sighash.sighash(tx, ALL_FORKID_CHRONICLE, 0, subscript, new BN(SATS),
      Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID)
    subscript.toHex().should.equal(before)
  })
})
