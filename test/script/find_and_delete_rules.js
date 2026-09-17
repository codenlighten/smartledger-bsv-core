'use strict'

/* global describe, it */

// Which signatures are removed from the scriptCode before it is signed, as the
// node does it (bitcoin-sv src/script/interpreter.cpp, CleanupScriptCode, and
// CScript::FindAndDelete in src/script/script.h):
//
//   // Drop the signature in scripts when SIGHASH_FORKID is not used.
//   if (!(flags & SCRIPT_ENABLE_SIGHASH_FORKID) || !sigHashType.hasForkId())
//       scriptCode.FindAndDelete(CScript(vchSig));
//
// and FindAndDelete removes every occurrence, consecutive ones included.
//
// The library removed the signature for every signature, FORKID or not. So a
// locking script that pushes a copy of the signature could be satisfied by a
// signature over the script WITHOUT that push: the library removed the push,
// found the digest it expected and accepted, while the node signs over the
// script as it is and rejects. The library called valid a spend the network
// calls invalid.

require('chai').should()
const expect = require('chai').expect
const bsv = require('../..')
const Script = bsv.Script
const Interpreter = Script.Interpreter
const Signature = bsv.crypto.Signature
const Opcode = bsv.Opcode
const BN = bsv.crypto.BN

const privateKey = bsv.PrivateKey.fromWIF('cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY')
const pubkey = privateKey.toPublicKey().toBuffer()
const SATS = 10000

function spending (lock) {
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.alloc(32, 9), outputIndex: 0, script: new Script(), sequenceNumber: 0xffffffff
  }), lock, SATS)
  tx.to(privateKey.toAddress(), SATS - 1000)
  return tx
}

// A signature made over `signedScript`, in the transaction spending `lock`.
function signatureOver (tx, signedScript, type, flags) {
  const sig = bsv.Transaction.Sighash.sign(tx, privateKey, type, 0, signedScript, new BN(SATS), flags)
  return Buffer.concat([sig.toDER(), Buffer.from([type & 0xff])])
}

function run (unlock, lock, tx, flags) {
  const interp = new Interpreter()
  const ok = interp.verify(unlock, lock, tx, 0, flags, new BN(SATS))
  return { ok, err: interp.errstr }
}

describe('findAndDelete follows the node', function () {
  const FORKID = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
  const forkidFlags = Interpreter.currentConsensusFlags()

  // <sig> OP_DROP <pubkey> OP_CHECKSIG, and the same script without <sig>.
  function scripts (sig) {
    const withoutPush = new Script().add(Opcode.OP_DROP).add(pubkey).add(Opcode.OP_CHECKSIG)
    const withPush = new Script().add(sig).add(Opcode.OP_DROP).add(pubkey).add(Opcode.OP_CHECKSIG)
    return { withoutPush, withPush }
  }

  it('with FORKID, a signature over the script minus a pushed copy of it is refused', function () {
    // The signature does not depend on the lock, only on the script it signs,
    // so it can be made first and then pushed into the lock.
    const probe = scripts(Buffer.alloc(72))
    let tx = spending(probe.withPush)
    const sig = signatureOver(tx, probe.withoutPush, FORKID)
    const lock = scripts(sig).withPush
    tx = spending(lock)
    // The funding script is part of the digest only through scriptCode, so the
    // signature made against the probe is still over `withoutPush` here.
    sig.equals(signatureOver(tx, scripts(sig).withoutPush, FORKID)).should.equal(true)
    const r = run(new Script().add(sig), lock, tx, forkidFlags)
    expect(r.ok, 'the node would reject this spend').to.equal(false)
  })

  it('with FORKID, a signature over the script as it is still verifies', function () {
    // Fixed point: sign over a lock that pushes an unrelated 72-byte value, so
    // nothing needs to be removed.
    const filler = Buffer.alloc(72, 0x5a)
    const lock = new Script().add(filler).add(Opcode.OP_DROP).add(pubkey).add(Opcode.OP_CHECKSIG)
    const tx = spending(lock)
    const sig = signatureOver(tx, lock, FORKID)
    const r = run(new Script().add(sig), lock, tx, forkidFlags)
    expect(r.ok, r.err).to.equal(true)
  })

  it('without FORKID, the pushed copy is still removed before checking', function () {
    const flags = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_VERIFY_STRICTENC
    const type = Signature.SIGHASH_ALL
    const probe = scripts(Buffer.alloc(71))
    let tx = spending(probe.withPush)
    const sig = signatureOver(tx, probe.withoutPush, type, flags)
    const lock = scripts(sig).withPush
    tx = spending(lock)
    const r = run(new Script().add(sig), lock, tx, flags)
    expect(r.ok, r.err).to.equal(true)
  })

  it('removes consecutive occurrences, as CScript::FindAndDelete does', function () {
    const sig = Buffer.alloc(72, 7)
    const s = new Script().add(sig).add(sig).add(Opcode.OP_1).add(sig).add(sig).add(sig)
    s.findAndDelete(new Script().add(sig))
    s.toBuffer().toString('hex').should.equal(new Script().add(Opcode.OP_1).toBuffer().toString('hex'))
  })

  // OP_CHECKMULTISIG goes through the same rule for each of its signatures.
  it('with FORKID, OP_CHECKMULTISIG refuses a signature over the script minus a pushed copy of it', function () {
    function multisig (sig) {
      const body = new Script().add(Opcode.OP_1).add(pubkey).add(Opcode.OP_1).add(Opcode.OP_CHECKMULTISIG)
      return {
        withoutPush: new Script().add(Opcode.OP_DROP).add(body),
        withPush: new Script().add(sig).add(Opcode.OP_DROP).add(body)
      }
    }
    // Rebuilt without the helpers' shared tx: withPush's size differs with the signature.
    const probe = multisig(Buffer.alloc(72))
    let tx = spending(probe.withPush)
    const sig = signatureOver(tx, probe.withoutPush, FORKID)
    const lock = multisig(sig).withPush
    tx = spending(lock)
    const cheat = run(new Script().add(Opcode.OP_0).add(sig), lock, tx, forkidFlags)
    expect(cheat.ok, 'the node would reject this spend').to.equal(false)
    // Control: a signature over the lock as it is verifies.
    const honest = signatureOver(tx, lock, FORKID)
    const h = run(new Script().add(Opcode.OP_0).add(honest), lock, tx, forkidFlags)
    expect(h.ok, h.err).to.equal(true)
  })
})

// Script#findAndDelete against a byte-level transcription of the node's
// CScript::FindAndDelete (bitcoin-sv v1.2.0, src/script/script.h), which shares no code
// with the library. Deterministic inputs are built to overlap: low-entropy signatures,
// empty signatures (whose push is OP_0), and consecutive copies.
describe('findAndDelete agrees with a transcription of the node', function () {
  function getOp (s, pc) {
    if (pc >= s.length) return -1
    const op = s[pc++]
    if (op <= 0x4e) {
      let n
      if (op < 0x4c) n = op
      else if (op === 0x4c) { if (s.length - pc < 1) return -1; n = s[pc]; pc += 1 } else if (op === 0x4d) { if (s.length - pc < 2) return -1; n = s.readUInt16LE(pc); pc += 2 } else { if (s.length - pc < 4) return -1; n = s.readUInt32LE(pc); pc += 4 }
      if (s.length - pc < n) return -1
      pc += n
    }
    return pc
  }
  function nodeFindAndDelete (s, b) {
    if (b.length === 0) return s
    const out = []
    let pc = 0
    let pc2 = 0
    let found = 0
    for (;;) {
      out.push(s.slice(pc2, pc))
      while (s.length - pc >= b.length && s.slice(pc, pc + b.length).equals(b)) { pc += b.length; found++ }
      pc2 = pc
      const nx = getOp(s, pc)
      if (nx < 0) break
      pc = nx
    }
    if (!found) return s
    out.push(s.slice(pc2))
    return Buffer.concat(out)
  }

  it('produces the same bytes over 3000 generated scripts', function () {
    let seed = 777
    function rnd (n) { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n }
    const ops = [0x00, 0x51, 0x52, 0x75, 0x76, 0x87, 0xac, 0xad, 0xae, 0xab]
    let removals = 0
    for (let t = 0; t < 3000; t++) {
      const sigLen = [0, 1, 2, 5, 71, 72, 76, 80][rnd(8)]
      const sig = Buffer.alloc(sigLen)
      for (let i = 0; i < sigLen; i++) sig[i] = rnd(3)
      const s = new Script()
      const n = 1 + rnd(12)
      for (let k = 0; k < n; k++) {
        const c = rnd(5)
        if (c < 2) s.add(sig)
        else if (c === 2) {
          const b = Buffer.alloc(rnd(6))
          for (let j = 0; j < b.length; j++) b[j] = rnd(3)
          s.add(b)
        } else s.add(ops[rnd(ops.length)])
      }
      const bytes = s.toBuffer()
      const expected = nodeFindAndDelete(bytes, new Script().add(sig).toBuffer())
      if (!expected.equals(bytes)) removals++
      const lib = Script.fromBuffer(bytes).findAndDelete(new Script().add(sig))
      lib.toBuffer().toString('hex').should.equal(expected.toString('hex'), 'sig ' + sig.toString('hex') + ' in ' + bytes.toString('hex'))
    }
    // Guard against a generator that never exercises a removal.
    removals.should.be.above(1000)
  })
})
