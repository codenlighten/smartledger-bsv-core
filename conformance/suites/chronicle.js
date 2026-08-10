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

/**
 * The transaction every OTDA case digests. Derived rather than written down:
 * 0x01 repeated is a valid secp256k1 scalar and reproduces exactly.
 */
function otdaFixture (bsv) {
  const key = new bsv.PrivateKey(bsv.crypto.BN.fromBuffer(Buffer.alloc(32, 1)))
  const utxo = {
    txId: '0'.repeat(64),
    outputIndex: 0,
    script: bsv.Script.buildPublicKeyHashOut(key.toAddress()).toHex(),
    satoshis: 100000
  }
  const tx = new bsv.Transaction().from(utxo).to(key.toAddress(), 90000)
  return {
    key,
    utxo,
    tx,
    sub: bsv.Script.fromHex(utxo.script),
    amt: new bsv.crypto.BN(utxo.satoshis),
    S: bsv.crypto.Signature,
    I: bsv.Script.Interpreter
  }
}

/**
 * Which ALGORITHM produced the digest for a given sighash type.
 *
 * Comparing against a fixed reference digest does not answer this: the sighash
 * type byte is committed INSIDE the preimage, so changing any bit of it — 0x20
 * included — changes the digest even when the algorithm is identical. The
 * comparison has to hold the type byte constant and vary only the routing.
 *
 * flags=0 forces the original algorithm, because BIP-143 requires both the
 * FORKID bit and SCRIPT_ENABLE_SIGHASH_FORKID.
 */
function whichAlgorithm (bsv, tx, sighashType, sub, amt) {
  const I = bsv.Script.Interpreter
  const got = bsv.Transaction.sighash.sighash(tx, sighashType, 0, sub, amt, I.SCRIPT_ENABLE_SIGHASH_FORKID)
  const forcedOtda = bsv.Transaction.sighash.sighash(tx, sighashType, 0, sub, amt, 0)
  return { digest: got.toString('hex'), algorithm: got.equals(forcedOtda) ? 'OTDA' : 'BIP143' }
}

/** Run a script with Chronicle enabled, against a transaction of `version`. */
function runChronicle (bsv, build, version) {
  const I = bsv.Script.Interpreter
  const i = new I()
  const tx = new bsv.Transaction()
  if (version != null) tx.version = version
  const script = new bsv.Script()
  build(script, bsv.Opcode, bsv)
  let verified
  try {
    verified = i.verify(new bsv.Script(), script, tx, 0, I.SCRIPT_ENABLE_CHRONICLE, new bsv.crypto.BN(0))
  } catch (err) {
    return { threw: err.name + ': ' + err.message }
  }
  return {
    verified,
    errstr: i.errstr || '',
    stack: (i.stack || []).map((b) => bsv.crypto.BN.fromScriptNumBuffer(b).toString())
  }
}

/** Push a signed script number. */
function num (bsv, v) { return new bsv.crypto.BN(v).toScriptNumBuffer() }

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

  // --- OTDA: the digest algorithms, and what selects them ------------------
  //
  // The Original Transaction Digest Algorithm is ALREADY IMPLEMENTED here: it
  // is the path taken when SIGHASH_FORKID is absent. What Chronicle changes is
  // how it is SELECTED — by setting CHRONICLE (0x20) — not what it computes.
  //
  // So these cases pin the two digests and the selection rule separately. When
  // the flag lands, the digest cases must NOT move and the selection cases
  // must; anything else means the algorithm changed when only the routing
  // should have.

  /** A fixed transaction to digest, built from a derived key. */
  'OTDA fixture transaction': (bsv) => {
    const { tx, sub } = otdaFixture(bsv)
    return { txid: tx.hash, subscript: sub.toHex() }
  },

  /** BIP-143. Selected today by SIGHASH_FORKID plus the interpreter flag. */
  'digest: BIP143 (ALL|FORKID)': (bsv) => {
    const { tx, sub, amt, S, I } = otdaFixture(bsv)
    return bsv.Transaction.sighash.sighash(tx, S.SIGHASH_ALL | S.SIGHASH_FORKID, 0, sub, amt,
      I.SCRIPT_ENABLE_SIGHASH_FORKID).toString('hex')
  },

  /** OTDA. Selected today by the ABSENCE of FORKID. */
  'digest: OTDA (ALL, no FORKID)': (bsv) => {
    const { tx, sub, amt, S } = otdaFixture(bsv)
    return bsv.Transaction.sighash.sighash(tx, S.SIGHASH_ALL, 0, sub, amt, 0).toString('hex')
  },

  /**
   * The SIGHASH_SINGLE bug — signing an input with no corresponding output
   * returns the constant 0x0000...0001 rather than a real digest. This is the
   * definitive fingerprint of the original algorithm, so it is pinned on its
   * own: if OTDA is ever reimplemented, losing this would be a silent
   * consensus break that a digest comparison alone might not reveal.
   */
  'digest: OTDA reproduces the SIGHASH_SINGLE bug': (bsv) => {
    const { key, utxo, sub, amt, S } = otdaFixture(bsv)
    const tx = new bsv.Transaction()
      .from(utxo)
      .from(Object.assign({}, utxo, { outputIndex: 1 }))
      .to(key.toAddress(), 1000)
    return bsv.Transaction.sighash.sighash(tx, S.SIGHASH_SINGLE, 1, sub, amt, 0).toString('hex')
  },

  /**
   * SELECTION, with the CHRONICLE bit set alongside FORKID. Today 0x20 is an
   * unrecognized bit and is silently ignored, so this equals the BIP143
   * digest. Under Chronicle it must select OTDA instead — meaning a signature
   * produced today with this sighash type commits to the WRONG digest for a
   * Chronicle verifier.
   */
  'selection: ALL|FORKID|CHRONICLE — which algorithm': (bsv) => {
    const { tx, sub, amt, S } = otdaFixture(bsv)
    return whichAlgorithm(bsv, tx, S.SIGHASH_ALL | S.SIGHASH_FORKID | 0x20, sub, amt)
  },

  /** SELECTION, with CHRONICLE but no FORKID. */
  'selection: ALL|CHRONICLE — which algorithm': (bsv) => {
    const { tx, sub, amt, S } = otdaFixture(bsv)
    return whichAlgorithm(bsv, tx, S.SIGHASH_ALL | 0x20, sub, amt)
  },

  /**
   * The same type byte WITH Chronicle enabled. This is the whole feature: the
   * bit is inert by default and selects OTDA once opted in.
   *
   * The gate is not timidity. Before Chronicle the 0x20 bit means nothing, so
   * BIP-143 signatures already exist whose type byte happens to set it;
   * honouring it unconditionally reinterprets them as OTDA. Pinned in both
   * states so neither the default nor the opted-in behaviour can drift.
   */
  'selection: ALL|FORKID|CHRONICLE with SCRIPT_ENABLE_CHRONICLE': (bsv) => {
    const { tx, sub, amt, S, I } = otdaFixture(bsv)
    const t = S.SIGHASH_ALL | S.SIGHASH_FORKID | S.SIGHASH_CHRONICLE
    const on = bsv.Transaction.sighash.sighash(tx, t, 0, sub, amt,
      I.SCRIPT_ENABLE_SIGHASH_FORKID | I.SCRIPT_ENABLE_CHRONICLE)
    const forcedOtda = bsv.Transaction.sighash.sighash(tx, t, 0, sub, amt, 0)
    return { digest: on.toString('hex'), algorithm: on.equals(forcedOtda) ? 'OTDA' : 'BIP143' }
  },

  /** The two controls, so a routing change is distinguishable from a digest change. */
  'selection: ALL|FORKID — which algorithm': (bsv) => {
    const { tx, sub, amt, S } = otdaFixture(bsv)
    return whichAlgorithm(bsv, tx, S.SIGHASH_ALL | S.SIGHASH_FORKID, sub, amt)
  },

  'selection: ALL — which algorithm': (bsv) => {
    const { tx, sub, amt, S } = otdaFixture(bsv)
    return whichAlgorithm(bsv, tx, S.SIGHASH_ALL, sub, amt)
  },

  /**
   * Whether the 0x20 bit survives signature-encoding validation. It does
   * today, which is why setting it is silently ineffective rather than an
   * error — the worst combination for a caller who believes it did something.
   */
  'selection: 0x20 passes checkSignatureEncoding': (bsv) => {
    const { tx, sub, amt, key, S, I } = otdaFixture(bsv)
    const t = S.SIGHASH_ALL | S.SIGHASH_FORKID | 0x20
    const sig = bsv.Transaction.sighash.sign(tx, key, t, 0, sub, amt, I.SCRIPT_ENABLE_SIGHASH_FORKID)
    const der = Buffer.concat([sig.toDER(), Buffer.from([t])])
    const i = new I()
    i.flags = I.SCRIPT_VERIFY_STRICTENC | I.SCRIPT_ENABLE_SIGHASH_FORKID
    return { accepted: i.checkSignatureEncoding(der), errstr: i.errstr || '' }
  },

  // --- Chronicle enabled: the restored opcodes ------------------------------
  //
  // Every case above records the DEFAULT (Chronicle off) behaviour. These
  // record the opted-in behaviour, so the two states are pinned independently
  // and neither can drift into the other.

  'enabled: OP_2MUL over a range': (bsv) => {
    const out = {}
    for (const v of [0, 1, 4, 5, -1, -5, 1000000]) {
      out[v] = runChronicle(bsv, (s, O) => s.add(num(bsv, v)).add(O.OP_2MUL))
    }
    return out
  },

  /**
   * OP_2DIV truncates toward zero — `-5 OP_2DIV` is -2, not -3 — matching the
   * existing OP_DIV so that `x OP_2DIV` and `x 2 OP_DIV` agree. Negative and
   * odd values are pinned because that is where a rounding change hides.
   */
  'enabled: OP_2DIV over a range': (bsv) => {
    const out = {}
    for (const v of [0, 1, 4, 5, -1, -4, -5, 1000001]) {
      out[v] = runChronicle(bsv, (s, O) => s.add(num(bsv, v)).add(O.OP_2DIV))
    }
    return out
  },

  'enabled: OP_2DIV agrees with OP_DIV by 2': (bsv) => {
    const out = {}
    for (const v of [5, -5, -4, 7]) {
      const a = runChronicle(bsv, (s, O) => s.add(num(bsv, v)).add(O.OP_2DIV))
      const b = runChronicle(bsv, (s, O) => s.add(num(bsv, v)).add(num(bsv, 2)).add(O.OP_DIV))
      out[v] = { op2div: a.stack, opdiv: b.stack, agree: JSON.stringify(a.stack) === JSON.stringify(b.stack) }
    }
    return out
  },

  'enabled: OP_2MUL in an unexecuted branch': (bsv) =>
    runChronicle(bsv, (s, O) => s.add(O.OP_0).add(O.OP_IF).add(O.OP_2MUL).add(O.OP_ENDIF).add(O.OP_1)),

  'enabled: OP_VER pushes the transaction version': (bsv) => {
    const out = {}
    for (const v of [1, 2, 10]) out[v] = runChronicle(bsv, (s, O) => s.add(O.OP_VER), v)
    return out
  },

  /** OP_VERIF is an IF whose condition is "top of stack equals tx version". */
  'enabled: OP_VERIF taken and not taken': (bsv) => ({
    matches: runChronicle(bsv, (s, O) => s.add(O.OP_2).add(O.OP_VERIF).add(O.OP_9).add(O.OP_ENDIF), 2),
    differs: runChronicle(bsv, (s, O) => s.add(O.OP_3).add(O.OP_VERIF).add(O.OP_9).add(O.OP_ENDIF).add(O.OP_1), 2)
  }),

  'enabled: OP_VERNOTIF taken and not taken': (bsv) => ({
    differs: runChronicle(bsv, (s, O) => s.add(O.OP_3).add(O.OP_VERNOTIF).add(O.OP_9).add(O.OP_ENDIF), 2),
    matches: runChronicle(bsv, (s, O) => s.add(O.OP_2).add(O.OP_VERNOTIF).add(O.OP_9).add(O.OP_ENDIF).add(O.OP_1), 2)
  }),

  /** OP_VERIF consumes its operand, as OP_IF does. */
  'enabled: OP_VERIF consumes the top of stack': (bsv) =>
    runChronicle(bsv, (s, O) => s.add(O.OP_7).add(O.OP_2).add(O.OP_VERIF).add(O.OP_ENDIF), 2),

  'enabled: OP_VERIF on an empty stack': (bsv) =>
    runChronicle(bsv, (s, O) => s.add(O.OP_VERIF).add(O.OP_ENDIF).add(O.OP_1), 2),
  // --- the shift opcodes, now implemented -----------------------------------
  //
  // Semantics come from SV Node's interpreter.cpp, not from the published
  // spec, which gives only "Inputs: a, b. Output: Shifts a left b bits" and
  // settles none of: operand order, what "preserving sign" means, negative or
  // oversized counts, or result encoding. Every one of those is pinned here.

  'enabled: OP_RSHIFTNUM over a range': (bsv) => {
    const out = {}
    for (const [v, k] of [[4, 1], [5, 1], [-5, 1], [-4, 1], [1, 3], [0, 5], [1024, 10]]) {
      out[v + '>>' + k] = runChronicle(bsv, (s, O) => s.add(num(bsv, v)).add(num(bsv, k)).add(O.OP_RSHIFTNUM))
    }
    return out
  },

  'enabled: OP_LSHIFTNUM over a range': (bsv) => {
    const out = {}
    for (const [v, k] of [[3, 2], [-3, 2], [1, 0], [1, 8], [-1, 4]]) {
      out[v + '<<' + k] = runChronicle(bsv, (s, O) => s.add(num(bsv, v)).add(num(bsv, k)).add(O.OP_LSHIFTNUM))
    }
    return out
  },

  /**
   * Sign handling is the detail the spec does not settle, so it gets its own
   * case: script numbers are sign-magnitude, so the shift moves the MAGNITUDE
   * and carries the sign. `-5 1 OP_RSHIFTNUM` is -2, not -3 — division
   * truncating toward zero, matching OP_DIV and OP_2DIV. A two's-complement
   * arithmetic shift would floor to -3.
   */
  'enabled: OP_RSHIFTNUM truncates toward zero, matching OP_2DIV': (bsv) => {
    const out = {}
    for (const v of [-5, -4, -1, 5, 7]) {
      const shift = runChronicle(bsv, (s, O) => s.add(num(bsv, v)).add(num(bsv, 1)).add(O.OP_RSHIFTNUM))
      const div = runChronicle(bsv, (s, O) => s.add(num(bsv, v)).add(O.OP_2DIV))
      out[v] = { rshiftnum: shift.stack, op2div: div.stack, agree: JSON.stringify(shift.stack) === JSON.stringify(div.stack) }
    }
    return out
  },

  'enabled: shift error cases': (bsv) => ({
    negativeCount: runChronicle(bsv, (s, O) => s.add(num(bsv, 4)).add(num(bsv, -1)).add(O.OP_RSHIFTNUM)),
    hugeRightCount: runChronicle(bsv, (s, O) => s.add(num(bsv, 4)).add(num(bsv, 1000)).add(O.OP_RSHIFTNUM)),
    leftOverflow: runChronicle(bsv, (s, O) => s.add(num(bsv, 4)).add(num(bsv, 1000)).add(O.OP_LSHIFTNUM)),
    emptyStack: runChronicle(bsv, (s, O) => s.add(O.OP_RSHIFTNUM))
  }),

  /**
   * With Chronicle OFF these bytes are UPGRADABLE NOPS on the network, not
   * errors. An earlier build returned BAD_OPCODE, which made this library
   * refuse scripts the network accepts — the mirror of the bug that made them
   * silently succeed.
   */
  'disabled: bytes 182/183 are upgradable NOPs, not errors': (bsv) => {
    const I = bsv.Script.Interpreter
    const runFlags = (byte, flags) => {
      const i = new I()
      const script = new bsv.Script().add(bsv.Opcode.OP_1).add(rawByte(bsv, byte))
      const verified = i.verify(new bsv.Script(), script, new bsv.Transaction(), 0, flags, new bsv.crypto.BN(0))
      return { verified, errstr: i.errstr || '' }
    }
    return {
      lshiftnumDefault: runFlags(182, 0),
      rshiftnumDefault: runFlags(183, 0),
      lshiftnumDiscouraged: runFlags(182, I.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS),
      rshiftnumDiscouraged: runFlags(183, I.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
    }
  },
  // --- divergences from SV Node, now closed ---------------------------------
  //
  // Five behaviours that did not match src/script/interpreter.cpp at v1.2.0.
  // Each is pinned in both flag states, because for three of them the DEFAULT
  // behaviour was the wrong one.

  /** A: the string opcodes are upgradable NOPs until Chronicle is enabled. */
  'node-parity: string opcodes are NOPs with Chronicle off': (bsv) => {
    const I = bsv.Script.Interpreter
    const build = (s, O) => s.add(Buffer.from('hello')).add(O.OP_1).add(O.OP_3).add(O.OP_SUBSTR)
    const at = (flags) => {
      const i = new I()
      const script = new bsv.Script()
      build(script, bsv.Opcode)
      const verified = i.verify(new bsv.Script(), script, new bsv.Transaction(), 0, flags, new bsv.crypto.BN(0))
      return { verified, errstr: i.errstr || '', stack: i.stack.map((b) => b.toString('hex')) }
    }
    return {
      off: at(0),
      discouraged: at(I.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS),
      on: at(I.SCRIPT_ENABLE_CHRONICLE)
    }
  },

  /** B: OP_VER pushes four little-endian bytes, not a script number. */
  'node-parity: OP_VER pushes 4-byte little-endian': (bsv) => {
    const out = {}
    for (const v of [1, 2, 10]) {
      out[v] = runChronicle(bsv, (s, O) => s.add(O.OP_VER), v).stack
    }
    return out
  },

  /**
   * C: OP_VERIF compares BYTE-WISE against those four bytes. A 1-byte OP_2 is
   * not equal to version 2 — it is simply false, not an error — so the
   * idiomatic form is `OP_VER OP_VERIF`.
   */
  'node-parity: OP_VERIF compares byte-wise, not numerically': (bsv) => ({
    oneByteOperand: runChronicle(bsv, (s, O) => s.add(O.OP_2).add(O.OP_VERIF).add(O.OP_9).add(O.OP_ENDIF).add(O.OP_1), 2),
    fourByteOperand: runChronicle(bsv, (s, O) => s.add(Buffer.from('02000000', 'hex')).add(O.OP_VERIF).add(O.OP_9).add(O.OP_ENDIF), 2),
    viaOpVer: runChronicle(bsv, (s, O) => s.add(O.OP_VER).add(O.OP_VERIF).add(O.OP_9).add(O.OP_ENDIF), 2),
    wrongVersion: runChronicle(bsv, (s, O) => s.add(Buffer.from('03000000', 'hex')).add(O.OP_VERIF).add(O.OP_9).add(O.OP_ENDIF).add(O.OP_1), 2)
  }),

  /** D: pre-Chronicle, OP_VERIF errors only in an EXECUTED branch. */
  'node-parity: OP_VERIF unexecuted with Chronicle off': (bsv) => {
    const I = bsv.Script.Interpreter
    const at = (build) => {
      const i = new I()
      const script = new bsv.Script()
      build(script, bsv.Opcode)
      const verified = i.verify(new bsv.Script(), script, new bsv.Transaction(), 0, 0, new bsv.crypto.BN(0))
      return { verified, errstr: i.errstr || '' }
    }
    return {
      unexecuted: at((s, O) => s.add(O.OP_0).add(O.OP_IF).add(O.OP_VERIF).add(O.OP_ENDIF).add(O.OP_1)),
      executed: at((s, O) => s.add(O.OP_1).add(O.OP_VERIF).add(O.OP_ENDIF))
    }
  },

  /**
   * E: the string opcodes ERROR on out-of-range arguments rather than
   * clamping. Clamping made scripts the node rejects succeed here.
   * `offset >= size` is strict — a begin index at the end is an error, not an
   * empty result.
   */
  'node-parity: string opcode range errors': (bsv) => ({
    substrPastEnd: runChronicle(bsv, (s, O) => s.add(Buffer.from('hi')).add(num(bsv, 1)).add(num(bsv, 9)).add(O.OP_SUBSTR)),
    substrOffsetAtEnd: runChronicle(bsv, (s, O) => s.add(Buffer.from('hi')).add(num(bsv, 2)).add(num(bsv, 1)).add(O.OP_SUBSTR)),
    substrExact: runChronicle(bsv, (s, O) => s.add(Buffer.from('hi')).add(num(bsv, 0)).add(num(bsv, 2)).add(O.OP_SUBSTR)),
    leftTooLong: runChronicle(bsv, (s, O) => s.add(Buffer.from('hi')).add(num(bsv, 9)).add(O.OP_LEFT)),
    rightTooLong: runChronicle(bsv, (s, O) => s.add(Buffer.from('hi')).add(num(bsv, 9)).add(O.OP_RIGHT))
  })

}

module.exports = { name: 'chronicle', cases }
