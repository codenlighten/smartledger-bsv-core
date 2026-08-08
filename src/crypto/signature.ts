'use strict'

import BN = require('./bn')
import _ = require('../util/_')
import $ = require('../util/preconditions')
import JSUtil = require('../util/js')
import type { Signature, SignatureConstructor, SignatureObj, ParsedDER } from './signature.types'
import type { PointConstructor } from './point.types'

const Signature = function Signature (this: Signature, r?: BN | SignatureObj, s?: BN) {
  if (!(this instanceof Signature)) {
    return new (Signature as SignatureConstructor)(r, s)
  }
  if (r instanceof BN) {
    this.set({
      r,
      s
    })
  } else if (r != null) {
    const obj = r as SignatureObj
    this.set(obj)
  }
} as unknown as SignatureConstructor

Signature.prototype.set = function (this: Signature, obj: SignatureObj): Signature {
  this.r = (obj.r ?? this.r) as BN
  this.s = (obj.s ?? this.s) as BN

  this.i = typeof obj.i !== 'undefined' ? obj.i : this.i // public key recovery parameter in range [0, 3]
  this.compressed = typeof obj.compressed !== 'undefined'
    ? obj.compressed
    : this.compressed // whether the recovered pubkey is compressed
  this.nhashtype = obj.nhashtype ?? this.nhashtype
  return this
}

Signature.fromCompact = function (buf: Buffer): Signature {
  $.checkArgument(Buffer.isBuffer(buf), 'Argument is expected to be a Buffer')

  const sig = new Signature()

  let compressed = true
  // A short buffer yields NaN here, which fails the range check below —
  // preserved deliberately rather than short-circuiting earlier.
  let i = (buf.slice(0, 1)[0] as number) - 27 - 4
  if (i < 0) {
    compressed = false
    i = i + 4
  }

  const b2 = buf.slice(1, 33)
  const b3 = buf.slice(33, 65)

  $.checkArgument(i === 0 || i === 1 || i === 2 || i === 3, new Error('i must be 0, 1, 2, or 3'))
  $.checkArgument(b2.length === 32, new Error('r must be 32 bytes'))
  $.checkArgument(b3.length === 32, new Error('s must be 32 bytes'))

  sig.compressed = compressed
  sig.i = i
  sig.r = BN.fromBuffer(b2)
  sig.s = BN.fromBuffer(b3)

  return sig
}

Signature.fromDER = Signature.fromBuffer = function (buf: Buffer, strict?: boolean): Signature {
  const obj = Signature.parseDER(buf, strict)
  const sig = new Signature()

  sig.r = obj.r
  sig.s = obj.s

  return sig
}

// The format used in a tx
Signature.fromTxFormat = function (buf: Buffer): Signature {
  const nhashtype = buf.readUInt8(buf.length - 1)
  const derbuf = buf.slice(0, buf.length - 1)
  const sig = Signature.fromDER(derbuf, false)
  sig.nhashtype = nhashtype
  return sig
}

Signature.fromString = function (str: string): Signature {
  const buf = Buffer.from(str, 'hex')
  return Signature.fromDER(buf)
}

/**
 * A DER INTEGER carrying r or s must be non-empty, positive (high bit clear,
 * since ECDSA r/s are unsigned), and minimally padded — a leading 0x00 is
 * permitted only to clear the high bit of the byte that follows. Anything else
 * is a second encoding of the same number, i.e. a malleable signature.
 */
function checkCanonicalInt (name: string, ibuf: Buffer): void {
  $.checkArgument(ibuf.length > 0, new Error('Length of ' + name + ' is zero'))
  // Guarded by the length check immediately above.
  $.checkArgument(((ibuf[0] as number) & 0x80) === 0, new Error('Value of ' + name + ' is negative'))
  $.checkArgument(!(ibuf.length > 1 && ibuf[0] === 0x00 && ((ibuf[1] as number) & 0x80) === 0),
    new Error('Value of ' + name + ' is excessively padded'))
}

/**
 * In order to mimic the non-strict DER encoding of OpenSSL, set strict = false.
 *
 * Non-strict is required to parse the non-canonical signatures already on chain
 * and is what fromTxFormat uses; consensus-level canonicality is enforced
 * separately by isTxDER under the interpreter's flags. Strict is the default and
 * is what application-level callers (fromDER/fromString) get.
 */
Signature.parseDER = function (buf: Buffer, strict?: boolean): ParsedDER {
  // NOTE ON THE `as number` READS BELOW: this parses untrusted input, so a
  // short buffer genuinely yields undefined. Each read is validated by the
  // $.checkArgument immediately following it (a header that is undefined is
  // not 0x02; a length that is undefined makes the subsequent slice empty and
  // fails the length equality check). The assertions are erased at runtime, so
  // malformed input still takes exactly the same path and throws exactly the
  // same errors as before — behavior the conformance corpus pins.
  $.checkArgument(Buffer.isBuffer(buf), new Error('DER formatted signature should be a buffer'))
  if (_.isUndefined(strict)) {
    strict = true
  }

  const header = buf[0] as number
  $.checkArgument(header === 0x30, new Error('Header byte should be 0x30'))

  let length = buf[1] as number
  const buflength = buf.slice(2).length
  $.checkArgument(!strict || length === buflength, new Error('Length byte should length of what follows'))

  length = length < buflength ? length : buflength

  const rheader = buf[2 + 0] as number
  $.checkArgument(rheader === 0x02, new Error('Integer byte for r should be 0x02'))

  const rlength = buf[2 + 1] as number
  const rbuf = buf.slice(2 + 2, 2 + 2 + rlength)
  const r = BN.fromBuffer(rbuf)
  const rneg = buf[2 + 1 + 1] === 0x00
  $.checkArgument(rlength === rbuf.length, new Error('Length of r incorrect'))

  const sheader = buf[2 + 2 + rlength + 0] as number
  $.checkArgument(sheader === 0x02, new Error('Integer byte for s should be 0x02'))

  const slength = buf[2 + 2 + rlength + 1] as number
  const sbuf = buf.slice(2 + 2 + rlength + 2, 2 + 2 + rlength + 2 + slength)
  const s = BN.fromBuffer(sbuf)
  const sneg = buf[2 + 2 + rlength + 2] === 0x00
  $.checkArgument(slength === sbuf.length, new Error('Length of s incorrect'))

  const sumlength = 2 + 2 + rlength + 2 + slength
  $.checkArgument(length === sumlength - 2, new Error('Length of signature incorrect'))

  if (strict) {
    checkCanonicalInt('r', rbuf)
    checkCanonicalInt('s', sbuf)
  }

  const obj = {
    header,
    length,
    rheader,
    rlength,
    rneg,
    rbuf,
    r,
    sheader,
    slength,
    sneg,
    sbuf,
    s
  }

  return obj
}

Signature.prototype.toCompact = function (this: Signature, i?: number, compressed?: boolean): Buffer {
  i = typeof i === 'number' ? i : this.i
  compressed = typeof compressed === 'boolean' ? compressed : this.compressed

  if (!(i === 0 || i === 1 || i === 2 || i === 3)) {
    throw new Error('i must be equal to 0, 1, 2, or 3')
  }

  let val = i + 27 + 4
  if (compressed === false) {
    val = val - 4
  }
  const b1 = Buffer.from([val])
  const b2 = this.r.toBuffer({
    size: 32
  })
  const b3 = this.s.toBuffer({
    size: 32
  })
  return Buffer.concat([b1, b2, b3])
}

Signature.prototype.toBuffer = Signature.prototype.toDER = function (this: Signature): Buffer {
  const rnbuf = this.r.toBuffer()
  const snbuf = this.s.toBuffer()

  // BN.toBuffer never returns an empty buffer for a valid signature scalar.
  const rneg = ((rnbuf[0] as number) & 0x80) !== 0
  const sneg = ((snbuf[0] as number) & 0x80) !== 0

  const rbuf = rneg ? Buffer.concat([Buffer.from([0x00]), rnbuf]) : rnbuf
  const sbuf = sneg ? Buffer.concat([Buffer.from([0x00]), snbuf]) : snbuf

  const rlength = rbuf.length
  const slength = sbuf.length
  const length = 2 + rlength + 2 + slength
  const rheader = 0x02
  const sheader = 0x02
  const header = 0x30

  const der = Buffer.concat([Buffer.from([header, length, rheader, rlength]), rbuf, Buffer.from([sheader, slength]), sbuf])
  return der
}

Signature.prototype.toString = function (this: Signature): string {
  const buf = this.toDER()
  return buf.toString('hex')
}

/**
 * This function is translated from bitcoind's IsDERSignature and is used in
 * the script interpreter.  This "DER" format actually includes an extra byte,
 * the nhashtype, at the end. It is really the tx format, not DER format.
 *
 * A canonical signature exists of: [30] [total len] [02] [len R] [R] [02] [len S] [S] [hashtype]
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 */
Signature.isTxDER = function (buf: Buffer): boolean {
  if (buf.length < 9) {
    //  Non-canonical signature: too short
    return false
  }
  if (buf.length > 73) {
    // Non-canonical signature: too long
    return false
  }
  if (buf[0] !== 0x30) {
    //  Non-canonical signature: wrong type
    return false
  }
  if (buf[1] !== buf.length - 3) {
    //  Non-canonical signature: wrong length marker
    return false
  }
  // isTxDER has already bounds-checked the header and length markers above.
  const nLenR = buf[3] as number
  if (5 + nLenR >= buf.length) {
    //  Non-canonical signature: S length misplaced
    return false
  }
  const nLenS = buf[5 + nLenR] as number
  if ((nLenR + nLenS + 7) !== buf.length) {
    //  Non-canonical signature: R+S length mismatch
    return false
  }

  const R = buf.slice(4)
  if (buf[4 - 2] !== 0x02) {
    //  Non-canonical signature: R value type mismatch
    return false
  }
  if (nLenR === 0) {
    //  Non-canonical signature: R length is zero
    return false
  }
  if (((R[0] as number) & 0x80) !== 0) {
    //  Non-canonical signature: R value negative
    return false
  }
  if (nLenR > 1 && (R[0] === 0x00) && ((R[1] as number) & 0x80) === 0) {
    //  Non-canonical signature: R value excessively padded
    return false
  }

  const S = buf.slice(6 + nLenR)
  if (buf[6 + nLenR - 2] !== 0x02) {
    //  Non-canonical signature: S value type mismatch
    return false
  }
  if (nLenS === 0) {
    //  Non-canonical signature: S length is zero
    return false
  }
  if (((S[0] as number) & 0x80) !== 0) {
    //  Non-canonical signature: S value negative
    return false
  }
  if (nLenS > 1 && (S[0] === 0x00) && ((S[1] as number) & 0x80) === 0) {
    //  Non-canonical signature: S value excessively padded
    return false
  }
  return true
}

/**
 * Compares to bitcoind's IsLowDERSignature
 * See also ECDSA signature algorithm which enforces this.
 * See also BIP 62, "low S values in signatures"
 */
Signature.prototype.hasLowS = function (this: Signature): boolean {
  if (this.s.lt(new BN(1)) ||
    this.s.gt(new BN('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', 'hex'))) {
    return false
  }
  return true
}

/**
 * @returns true if the nhashtype is exactly equal to one of the standard options or combinations thereof.
 * Translated from bitcoind's IsDefinedHashtypeSignature
 */
Signature.prototype.hasDefinedHashtype = function (this: Signature): boolean {
  if (!JSUtil.isNaturalNumber(this.nhashtype)) {
    return false
  }
  // accept with or without Signature.SIGHASH_ANYONECANPAY by ignoring the bit
  const temp = (this.nhashtype as number) & 0x1F
  if (temp < Signature.SIGHASH_ALL || temp > Signature.SIGHASH_SINGLE) {
    return false
  }
  return true
}

Signature.prototype.toTxFormat = function (this: Signature): Buffer {
  const derbuf = this.toDER()
  const buf = Buffer.alloc(1)
  buf.writeUInt8(this.nhashtype as number, 0)
  return Buffer.concat([derbuf, buf])
}

Signature.SIGHASH_ALL = 0x01
Signature.SIGHASH_NONE = 0x02
Signature.SIGHASH_SINGLE = 0x03
Signature.SIGHASH_FORKID = 0x40
Signature.SIGHASH_ANYONECANPAY = 0x80

// === SmartLedger Security Enhancement Methods ===

/**
 * Check if signature is canonical (s <= n/2) - SmartLedger security feature
 */
Signature.prototype.isCanonical = function (this: Signature): boolean {
  const Point = require('./point') as PointConstructor
  const nh = Point.getN().shrn(1) // n/2
  return this.s.lte(nh)
}

/**
 * Return canonicalized version of signature - SmartLedger security feature
 */
Signature.prototype.toCanonical = function (this: Signature): Signature {
  if (this.isCanonical()) {
    return new Signature({ r: this.r, s: this.s, i: this.i, compressed: this.compressed, nhashtype: this.nhashtype })
  }

  const Point = require('./point') as PointConstructor
  const n = Point.getN()
  const canonicalS = n.sub(this.s)

  return new Signature({ r: this.r, s: canonicalS, i: this.i, compressed: this.compressed, nhashtype: this.nhashtype })
}

/**
 * Validate signature parameters - SmartLedger security feature
 */
Signature.prototype.validate = function (this: Signature): boolean {
  if (!this.r || !this.s) {
    throw new Error('Signature missing r or s component')
  }

  if (this.r.isZero()) {
    throw new Error('Signature r component is zero')
  }

  if (this.s.isZero()) {
    throw new Error('Signature s component is zero')
  }

  const Point = require('./point') as PointConstructor
  const n = Point.getN()

  if (this.r.gte(n)) {
    throw new Error('Signature r component >= curve order')
  }

  if (this.s.gte(n)) {
    throw new Error('Signature s component >= curve order')
  }

  if (this.r.isNeg()) {
    throw new Error('Signature r component is negative')
  }

  if (this.s.isNeg()) {
    throw new Error('Signature s component is negative')
  }

  return true
}

/**
 * Boolean signature validation - SmartLedger security feature
 */
Signature.prototype.isValid = function (this: Signature): boolean {
  try {
    this.validate()
    return true
  } catch (e) {
    return false
  }
}

/**
 * Assert that this signature is safe to accept: r and s in (0, n) and s
 * canonical (low-S). Throws if not; returns `this` for chaining.
 *
 * This asserts rather than rewrites. Silently replacing a high-S s with n-s
 * cannot protect against malleability — ECDSA accepts s and n-s equally, so the
 * rewritten signature verifies exactly as the original did, and the only effect
 * is to hide from the caller that they were handed a malleated signature. Use
 * toCanonical() to deliberately normalize one.
 */
Signature.prototype.applySecurityPatches = function (this: Signature): Signature {
  const Point = require('./point') as PointConstructor
  const n = Point.getN()
  const nh = n.shrn(1) // n/2

  if (this.r.isZero() || this.s.isZero()) {
    throw new Error('Invalid signature: zero r or s')
  }
  if (this.r.gte(n) || this.s.gte(n)) {
    throw new Error('Invalid signature: out of range')
  }
  if (this.s.gt(nh)) {
    throw new Error('Invalid signature: non-canonical (high) s')
  }

  return this
}

export = Signature
