'use strict'

/**
 * The BSV Chronicle script surface.
 *
 * WHY THIS SUITE EXISTS: CHRONICLE.md records four places where this library
 * does not match the Chronicle release. Three of them fail loudly. One does
 * not — bytes 182/183 are OP_LSHIFTNUM/OP_RSHIFTNUM in Chronicle, this library
 * calls them OP_NOP4/OP_NOP5, and a script using them therefore VERIFIES
 * WITHOUT PERFORMING THE SHIFT. That is a wrong answer rather than an error,
 * and nothing in the test suite notices it.
 *
 * So this suite pins today's behaviour — the correct parts and the wrong parts
 * alike — before any of it is changed. When the gaps are closed, every case
 * below that flips is a deliberate outcome flip with a diff to point at, which
 * is exactly what verify.js ranks above all other differences. A fixture that
 * only recorded the correct behaviour would let the wrong behaviour change
 * silently in either direction.
 *
 * These cases pin the LIBRARY, not the protocol. Several of them record
 * behaviour that is known to be wrong; the fixture is a record of what we do
 * today, and CHRONICLE.md is the record of what we should do instead.
 */

/**
 * Opcode numbers per the Chronicle release, as published by the SV Node
 * documentation. Chronicle re-enables the string opcodes at NEW numbers —
 * 179/180/181, not their original 127/128/129 — because those bytes now carry
 * OP_SPLIT/OP_NUM2BIN/OP_BIN2NUM from the Magnetic upgrade.
 */
const CHRONICLE_OPCODES = {
  OP_VER: 98,
  OP_VERIF: 101,
  OP_VERNOTIF: 102,
  OP_2MUL: 141,
  OP_2DIV: 142,
  OP_SUBSTR: 179,
  OP_LEFT: 180,
  OP_RIGHT: 181,
  OP_LSHIFTNUM: 182,
  OP_RSHIFTNUM: 183
}

/** Run a script and record the verdict, the error string, and the final stack. */
function run (bsv, scriptPubkey, scriptSig) {
  const Interpreter = bsv.Script.Interpreter
  const i = new Interpreter()
  const sig = scriptSig || new bsv.Script()
  let verified
  try {
    verified = i.verify(sig, scriptPubkey, new bsv.Transaction(), 0, 0, new bsv.crypto.BN(0))
  } catch (err) {
    return { threw: err.name + ': ' + err.message }
  }
  return {
    verified,
    // Empty string when the script succeeded; the whole point of recording it
    // is that a changed error name is a changed outcome.
    errstr: i.errstr || '',
    stack: (i.stack || []).map((b) => b.toString('hex'))
  }
}

/** A script consisting of one raw opcode byte, bypassing the name table. */
function rawByte (bsv, byte) {
  return bsv.Script.fromBuffer(Buffer.from([byte]))
}

const cases = {
  // --- opcode numbering ----------------------------------------------------

  /**
   * Every Chronicle opcode by name. `null` marks one the library does not
   * define at all, which is how OP_LSHIFTNUM/OP_RSHIFTNUM show up.
   */
  'Chronicle opcode numbers as this library defines them': (bsv) => {
    const out = {}
    for (const name of Object.keys(CHRONICLE_OPCODES).sort()) {
      const got = bsv.Opcode.map[name]
      out[name] = got === undefined ? null : got
    }
    return out
  },

  /** The same, as agreement/disagreement with the published numbers. */
  'Chronicle opcode numbers: agreement with the spec': (bsv) => {
    const out = {}
    for (const name of Object.keys(CHRONICLE_OPCODES).sort()) {
      const want = CHRONICLE_OPCODES[name]
      const got = bsv.Opcode.map[name]
      out[name] = got === undefined ? 'MISSING' : (got === want ? 'ok' : 'WRONG:' + got)
    }
    return out
  },

  /**
   * What each byte in the contested range is called. This is where the NOP
   * renumbering lives: Chronicle assigns 182/183 to the shift opcodes, and
   * bytes above 185 are not valid opcodes in consensus at all.
   */
  'names assigned to bytes 176..190': (bsv) => {
    const out = {}
    for (let b = 176; b <= 190; b++) {
      const names = Object.keys(bsv.Opcode.map).filter((k) => bsv.Opcode.map[k] === b)
      out[b] = names.length ? names.sort().join('|') : null
    }
    return out
  },

  // --- restored string opcodes (correct today) -----------------------------
  //
  // These pass. They are pinned so that renumbering work on the neighbouring
  // bytes cannot break them without producing a diff.

  'OP_SUBSTR extracts a substring': (bsv) => run(bsv,
    new bsv.Script()
      .add(Buffer.from('hello'))
      .add(bsv.Opcode.OP_1)
      .add(bsv.Opcode.OP_3)
      .add(bsv.Opcode.OP_SUBSTR)),

  'OP_SUBSTR with a zero length': (bsv) => run(bsv,
    new bsv.Script()
      .add(Buffer.from('hello'))
      .add(bsv.Opcode.OP_1)
      .add(bsv.Opcode.OP_0)
      .add(bsv.Opcode.OP_SUBSTR)),

  'OP_SUBSTR past the end of the string': (bsv) => run(bsv,
    new bsv.Script()
      .add(Buffer.from('hi'))
      .add(bsv.Opcode.OP_1)
      .add(bsv.Opcode.OP_9)
      .add(bsv.Opcode.OP_SUBSTR)),

  'OP_LEFT keeps the leading bytes': (bsv) => run(bsv,
    new bsv.Script().add(Buffer.from('hello')).add(bsv.Opcode.OP_2).add(bsv.Opcode.OP_LEFT)),

  'OP_RIGHT keeps the trailing bytes': (bsv) => run(bsv,
    new bsv.Script().add(Buffer.from('hello')).add(bsv.Opcode.OP_2).add(bsv.Opcode.OP_RIGHT)),

  'OP_LEFT with a length of zero': (bsv) => run(bsv,
    new bsv.Script().add(Buffer.from('hello')).add(bsv.Opcode.OP_0).add(bsv.Opcode.OP_LEFT)),

  'OP_LEFT on an empty stack': (bsv) => run(bsv, new bsv.Script().add(bsv.Opcode.OP_LEFT)),

  // --- gap 1: the shift opcodes, and the silent no-op ----------------------
  //
  // THE IMPORTANT ONES. Today byte 182 parses as OP_NOP4 and evaluates as a
  // no-op that SUCCEEDS. When OP_LSHIFTNUM lands these flip from
  // verified:true to a real shift (or to a stack-operation error), and the
  // diff is the proof that the fix took effect.

  'byte 182 (OP_LSHIFTNUM in Chronicle) evaluated alone': (bsv) => run(bsv, rawByte(bsv, 182)),
  'byte 183 (OP_RSHIFTNUM in Chronicle) evaluated alone': (bsv) => run(bsv, rawByte(bsv, 183)),

  /**
   * With operands on the stack. A real OP_LSHIFTNUM consumes two items and
   * leaves the shifted value; today both operands survive untouched, which is
   * what makes the divergence invisible to a caller checking only the verdict.
   */
  'byte 182 with shift operands on the stack': (bsv) => run(bsv,
    new bsv.Script().add(bsv.Opcode.OP_4).add(bsv.Opcode.OP_1).add(rawByte(bsv, 182))),

  'byte 183 with shift operands on the stack': (bsv) => run(bsv,
    new bsv.Script().add(bsv.Opcode.OP_4).add(bsv.Opcode.OP_1).add(rawByte(bsv, 183))),

  /** Bytes 186-188 are not valid opcodes in consensus; this library names them. */
  'bytes 184..188 evaluated alone': (bsv) => {
    const out = {}
    for (let b = 184; b <= 188; b++) out[b] = run(bsv, rawByte(bsv, b))
    return out
  },

  // --- gap 2: OP_2MUL / OP_2DIV -------------------------------------------
  //
  // Chronicle restores both. Today they are hard-coded as permanently
  // disabled, so these record a loud failure that should become arithmetic.

  'OP_2MUL on a value': (bsv) => run(bsv,
    new bsv.Script().add(bsv.Opcode.OP_4).add(bsv.Opcode.OP_2MUL)),

  'OP_2DIV on a value': (bsv) => run(bsv,
    new bsv.Script().add(bsv.Opcode.OP_4).add(bsv.Opcode.OP_2DIV)),

  /**
   * In an UNEXECUTED branch. Disabled opcodes fail a script even inside a
   * false branch; restored ones do not. The two rules differ, so this case
   * distinguishes "restored" from "no longer rejected outright".
   */
  'OP_2MUL inside a false branch': (bsv) => run(bsv,
    new bsv.Script()
      .add(bsv.Opcode.OP_0)
      .add(bsv.Opcode.OP_IF)
      .add(bsv.Opcode.OP_2MUL)
      .add(bsv.Opcode.OP_ENDIF)
      .add(bsv.Opcode.OP_1)),

  // --- gap 3: the OP_VER family -------------------------------------------
  //
  // Present in the opcode map at the right numbers, absent from the
  // interpreter, so they hit the bad-opcode default.

  'OP_VER alone': (bsv) => run(bsv, new bsv.Script().add(bsv.Opcode.OP_VER)),

  'OP_VERIF alone': (bsv) => run(bsv, new bsv.Script().add(bsv.Opcode.OP_VERIF)),

  'OP_VERNOTIF alone': (bsv) => run(bsv, new bsv.Script().add(bsv.Opcode.OP_VERNOTIF)),

  /**
   * OP_VERIF/OP_VERNOTIF are special in Core: they fail a script even when
   * unexecuted, unlike every other opcode. Whether that survives their
   * Chronicle restoration is exactly the kind of thing worth pinning.
   */
  'OP_VERIF inside a false branch': (bsv) => run(bsv,
    new bsv.Script()
      .add(bsv.Opcode.OP_0)
      .add(bsv.Opcode.OP_IF)
      .add(bsv.Opcode.OP_VERIF)
      .add(bsv.Opcode.OP_ENDIF)
      .add(bsv.Opcode.OP_1)),

  // --- gap 4: the CHRONICLE sighash flag and OTDA --------------------------

  /** Every SIGHASH constant the library defines, by name and value. */
  'signature SIGHASH constants': (bsv) => {
    const S = bsv.crypto.Signature
    const out = {}
    for (const k of Object.keys(S).filter((k) => /^SIGHASH/.test(k)).sort()) {
      out[k] = S[k]
    }
    return out
  },

  /**
   * Chronicle selects the Original Transaction Digest Algorithm with a new
   * CHRONICLE = 0x20 flag. Recorded as a direct question so the fixture states
   * the absence rather than leaving it to be inferred from the list above.
   */
  'a sighash flag with value 0x20 exists': (bsv) => {
    const S = bsv.crypto.Signature
    const named = Object.keys(S).filter((k) => /^SIGHASH/.test(k) && S[k] === 0x20)
    return { present: named.length > 0, names: named.sort() }
  },

  /**
   * Signing with the 0x20 bit set. Today it is simply an unrecognized bit in
   * the sighash type; under Chronicle it selects a different digest, so the
   * signature bytes must change. Recording the signature pins that.
   */
  'sighash type with the 0x20 bit set': (bsv) => {
    // Derived, not a literal WIF: a hand-written key is a value nobody has
    // checked, and this corpus already had one fabricated vector caught the
    // hard way. 0x01 repeated is a valid secp256k1 scalar and is reproducible.
    const key = new bsv.PrivateKey(bsv.crypto.BN.fromBuffer(Buffer.alloc(32, 1)))
    const utxo = {
      txId: '0'.repeat(64),
      outputIndex: 0,
      script: bsv.Script.buildPublicKeyHashOut(key.toAddress()).toHex(),
      satoshis: 100000
    }
    const tx = new bsv.Transaction().from(utxo).to(key.toAddress(), 90000)
    const sighashType = bsv.crypto.Signature.SIGHASH_ALL |
      bsv.crypto.Signature.SIGHASH_FORKID | 0x20
    const preimage = bsv.Transaction.sighash.sighashPreimage
      ? bsv.Transaction.sighash.sighashPreimage(tx, sighashType, 0,
        bsv.Script.fromHex(utxo.script), new bsv.crypto.BN(utxo.satoshis))
      : null
    const digest = bsv.Transaction.sighash.sighash(tx, sighashType, 0,
      bsv.Script.fromHex(utxo.script), new bsv.crypto.BN(utxo.satoshis))
    return {
      sighashType,
      digest: digest.toString('hex'),
      preimageLength: preimage ? preimage.length : null
    }
  }
}

module.exports = { name: 'chronicle', cases }
