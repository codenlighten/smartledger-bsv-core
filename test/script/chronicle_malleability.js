'use strict'

/* global describe, it */

// Ported from @smartledger/bsv, where both bugs were found first; kept identical so the two
// implementations can be compared row for row.
//
// Chronicle lets a transaction opt into malleability by using a version above 1. The node
// then stops applying the rules that exist only to keep a signed transaction from being
// rewritten in flight — EnforceNonMalleability(flags, checker.Version()) in
// src/script/interpreter.cpp, at seven sites — and SCRIPT_CHRONICLE is set on every block
// mined since activation at 943,816, so this is today's mainnet, not a future era.
//
// It is also the file that pins the else-if bug. checkSignatureEncoding chained its three
// checks, so SCRIPT_VERIFY_LOW_S — which mainnetFlags() sets — returned early and the
// STRICTENC block never ran. Three signatures the node refuses by name were accepted on
// the library's own default flags. The node has three independent ifs.
//
// The node's script_tests.json cannot see any of this: every one of its 1483 rows carries
// transaction version 1, and not one pairs LOW_S with a hash-type expectation.

const should = require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const Signature = bsv.crypto.Signature
const BN = bsv.crypto.BN
should.exist(should)

const LOW_S = Interpreter.SCRIPT_VERIFY_LOW_S
const STRICTENC = Interpreter.SCRIPT_VERIFY_STRICTENC
const FORKID = Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID
const CHRONICLE = Interpreter.SCRIPT_CHRONICLE
const P2SH = Interpreter.SCRIPT_VERIFY_P2SH
const GENESIS = Interpreter.SCRIPT_GENESIS
const UTXO_AFTER_GENESIS = Interpreter.SCRIPT_UTXO_AFTER_GENESIS
const UTXO_AFTER_CHRONICLE = Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE

function verifyWith (sigAsm, pubkeyAsm, flags, version) {
  const tx = new bsv.Transaction()
  tx.version = version === undefined ? 1 : version
  const interp = new Interpreter()
  const ok = interp.verify(Script.fromASM(sigAsm), Script.fromASM(pubkeyAsm), tx, 0, flags,
    new BN(0))
  return ok ? 'OK' : interp.errstr
}

// A low-S DER signature, to which we append whichever hash-type byte the case needs.
const DER = (function () {
  const key = bsv.PrivateKey.fromBuffer(Buffer.alloc(32, 0x11))
  return bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(Buffer.from('anything')), key).toDER()
})()

function checkSig (flags, hashType, version) {
  const interp = new Interpreter()
  const tx = new bsv.Transaction()
  tx.version = version === undefined ? 1 : version
  interp.set({ flags, tx, nin: 0 })
  const ok = interp.checkSignatureEncoding(Buffer.concat([DER, Buffer.from([hashType])]))
  return ok ? 'OK' : interp.errstr
}

describe('Chronicle malleability relaxations', function () {
  describe('checkSignatureEncoding runs all three checks, not the first that matches', function () {
    it('refuses an undefined hash type even when LOW_S is set', function () {
      checkSig(STRICTENC, 0x00).should.equal('SCRIPT_ERR_SIG_HASHTYPE')
      checkSig(STRICTENC | LOW_S, 0x00).should.equal('SCRIPT_ERR_SIG_HASHTYPE')
    })

    it('refuses a signature without FORKID where FORKID is required, with LOW_S set', function () {
      checkSig(STRICTENC | FORKID, 0x01).should.equal('SCRIPT_ERR_MUST_USE_FORKID')
      checkSig(STRICTENC | FORKID | LOW_S, 0x01).should.equal('SCRIPT_ERR_MUST_USE_FORKID')
    })

    it('refuses the Chronicle digest outside Chronicle, with LOW_S set', function () {
      const ht = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID | Signature.SIGHASH_CHRONICLE
      checkSig(STRICTENC | FORKID, ht).should.equal('SCRIPT_ERR_ILLEGAL_CHRONICLE')
      checkSig(STRICTENC | FORKID | LOW_S, ht).should.equal('SCRIPT_ERR_ILLEGAL_CHRONICLE')
    })

    it('refuses all three on the default mainnet flags', function () {
      const F = Interpreter.mainnetFlags()
      checkSig(F, 0x00).should.equal('SCRIPT_ERR_SIG_HASHTYPE')
      checkSig(F, 0x01).should.equal('SCRIPT_ERR_MUST_USE_FORKID')
      // mainnetFlags() enables Chronicle, so the Chronicle bit is legal there; the
      // pre-Chronicle case is covered above.
      checkSig(F, Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID).should.equal('OK')
    })

    it('and still reports a bad DER encoding first, as the node does', function () {
      const interp = new Interpreter()
      interp.set({ flags: STRICTENC | LOW_S, tx: new bsv.Transaction(), nin: 0 })
      interp.checkSignatureEncoding(Buffer.from('310602010102010101', 'hex'))
        .should.equal(false)
      interp.errstr.should.equal('SCRIPT_ERR_SIG_DER_INVALID_FORMAT')
    })
  })

  // The unit checks above pin checkSignatureEncoding. These spend a real P2PKH output with a
  // signature that genuinely verifies, so execution reaches the accept/reject decision — which
  // is what makes the bug a false accept rather than a wrong reason. All three were ACCEPTED by
  // 9.14.0 under its own mainnetFlags().
  describe('end to end: a spend the network rejects must not verify', function () {
    const key = bsv.PrivateKey.fromBuffer(Buffer.alloc(32, 0x22))
    const addr = key.toAddress()
    const SATS = 100000
    const lock = Script.buildPublicKeyHashOut(addr)

    function spend (hashType, signFlags, verifyFlags) {
      const utxo = new bsv.Transaction.UnspentOutput({
        txId: 'a'.repeat(64), outputIndex: 0, script: lock, satoshis: SATS
      })
      const tx = new bsv.Transaction().from(utxo).to(addr, SATS - 500)
      const sig = bsv.Transaction.Sighash.sign(tx, key, hashType, 0, lock, new BN(SATS), signFlags)
      const unlock = new Script().add(sig.toTxFormat()).add(key.toPublicKey().toBuffer())
      tx.inputs[0].setScript(unlock)
      const interp = new Interpreter()
      const ok = interp.verify(unlock, lock, tx, 0, verifyFlags, new BN(SATS))
      return ok ? 'OK' : interp.errstr
    }

    const MAINNET = Interpreter.mainnetFlags()

    it('refuses a signature with no FORKID bit where FORKID is required', function () {
      // Signed over the legacy digest, so the signature itself is valid.
      spend(Signature.SIGHASH_ALL, 0, MAINNET).should.equal('SCRIPT_ERR_MUST_USE_FORKID')
    })

    it('refuses an undefined hash type', function () {
      spend(0x60 | Signature.SIGHASH_FORKID, FORKID, MAINNET)
        .should.equal('SCRIPT_ERR_SIG_HASHTYPE')
    })

    it('refuses the Chronicle digest where Chronicle does not apply', function () {
      const noChronicle = MAINNET & ~(CHRONICLE | Interpreter.SCRIPT_ENABLE_CHRONICLE |
        UTXO_AFTER_CHRONICLE)
      const ht = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID | Signature.SIGHASH_CHRONICLE
      spend(ht, FORKID | CHRONICLE, noChronicle).should.equal('SCRIPT_ERR_ILLEGAL_CHRONICLE')
    })

    it('and still accepts a correctly signed spend', function () {
      spend(Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID, FORKID, MAINNET)
        .should.equal('OK')
    })
  })

  describe('a version above 1 under Chronicle is exempt', function () {
    const CH = P2SH | GENESIS | UTXO_AFTER_GENESIS | CHRONICLE | UTXO_AFTER_CHRONICLE

    it('from MINIMALIF', function () {
      const flags = CH | Interpreter.SCRIPT_VERIFY_MINIMALIF
      verifyWith('', 'OP_2 OP_IF OP_1 OP_ENDIF', flags, 1).should.equal('SCRIPT_ERR_MINIMALIF')
      verifyWith('', 'OP_2 OP_IF OP_1 OP_ENDIF', flags, 2).should.equal('OK')
    })

    it('from MINIMALDATA', function () {
      const flags = CH | Interpreter.SCRIPT_VERIFY_MINIMALDATA
      // OP_PUSHDATA1 pushing one byte, where a direct push would do.
      const nonMinimal = Script.fromBuffer(Buffer.from('4c0101', 'hex'))
      function run (version) {
        const tx = new bsv.Transaction(); tx.version = version
        const interp = new Interpreter()
        const ok = interp.verify(nonMinimal, Script.fromASM('OP_1'), tx, 0, flags, new BN(0))
        return ok ? 'OK' : interp.errstr
      }
      run(1).should.equal('SCRIPT_ERR_MINIMALDATA')
      run(2).should.equal('OK')
    })

    it('from LOW_S', function () {
      // A high-S signature: negate s and re-encode.
      const sig = Signature.fromDER(DER)
      const N = bsv.crypto.Point.getN()
      const high = new Signature(sig.r, N.sub(sig.s))
      const buf = Buffer.concat([high.toDER(),
        Buffer.from([Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID])])
      function run (version) {
        const interp = new Interpreter()
        const tx = new bsv.Transaction(); tx.version = version
        interp.set({ flags: CH | LOW_S | FORKID, tx, nin: 0 })
        const ok = interp.checkSignatureEncoding(buf)
        return ok ? 'OK' : interp.errstr
      }
      run(1).should.equal('SCRIPT_ERR_SIG_DER_HIGH_S')
      run(2).should.equal('OK')
    })

    it('from CLEANSTACK', function () {
      const flags = CH | Interpreter.SCRIPT_VERIFY_CLEANSTACK
      verifyWith('OP_1 OP_1', 'OP_NOP', flags, 1).should.equal('SCRIPT_ERR_CLEANSTACK')
      verifyWith('OP_1 OP_1', 'OP_NOP', flags, 2).should.equal('OK')
    })

    it('from SIGPUSHONLY', function () {
      const flags = CH | Interpreter.SCRIPT_VERIFY_SIGPUSHONLY
      verifyWith('OP_1 OP_NOP', 'OP_NOP', flags, 1).should.equal('SCRIPT_ERR_SIG_PUSHONLY')
      verifyWith('OP_1 OP_NOP', 'OP_NOP', flags, 2).should.equal('OK')
    })

    it('but not without Chronicle, where the version means nothing', function () {
      const flags = P2SH | GENESIS | UTXO_AFTER_GENESIS | Interpreter.SCRIPT_VERIFY_MINIMALIF
      verifyWith('', 'OP_2 OP_IF OP_1 OP_ENDIF', flags, 1).should.equal('SCRIPT_ERR_MINIMALIF')
      verifyWith('', 'OP_2 OP_IF OP_1 OP_ENDIF', flags, 2).should.equal('SCRIPT_ERR_MINIMALIF')
    })

    it('and version 1 and below stay non-malleable', function () {
      const flags = CH | Interpreter.SCRIPT_VERIFY_MINIMALIF
      ;[0, 1].forEach(function (v) {
        verifyWith('', 'OP_2 OP_IF OP_1 OP_ENDIF', flags, v)
          .should.equal('SCRIPT_ERR_MINIMALIF', 'version ' + v)
      })
    })
  })

  describe('a flag set no node builds is refused rather than guessed at', function () {
    it('post-Chronicle UTXO without post-Genesis', function () {
      verifyWith('OP_1', 'OP_1', P2SH | UTXO_AFTER_CHRONICLE)
        .should.equal('SCRIPT_ERR_INVALID_FLAGS')
    })

    it('CLEANSTACK without P2SH reports rather than throwing', function () {
      verifyWith('OP_1', 'OP_1', Interpreter.SCRIPT_VERIFY_CLEANSTACK)
        .should.equal('SCRIPT_ERR_INVALID_FLAGS')
    })
  })
})
