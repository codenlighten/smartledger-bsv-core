'use strict'

import BN = require('./bn')
import Point = require('./point')
import Signature = require('./signature')
import Random = require('./random')
import Hash = require('./hash')
import _ = require('../util/_')
import $ = require('../util/preconditions')
import type { ECDSA, ECDSAConstructor, ECDSAObj, Endian } from './ecdsa.types'
import type { PublicKey, PublicKeyConstructor } from '../publickey.types'
import type { PrivateKey } from '../privatekey.types'

// publickey is in this cycle, so it is resolved on demand rather than captured
// at load time.
const publicKeyClass = (): PublicKeyConstructor => require('../publickey')

// PRECONDITION FOR THE METHODS BELOW: every field on ECDSA is optional,
// because the object is built incrementally via set(). The signing and
// verification methods are only reachable once the relevant fields are
// populated — the static helpers (ECDSA.sign, ECDSA.verify) construct a fully
// populated instance before calling them. The assertions below state that
// precondition; they are erased at runtime, so a genuinely missing field still
// produces exactly the same TypeError it always did.

const ECDSA = function ECDSA (this: ECDSA, obj?: ECDSAObj) {
  if (!(this instanceof ECDSA)) {
    return new (ECDSA as ECDSAConstructor)(obj)
  }
  if (obj != null) {
    this.set(obj)
  }
} as unknown as ECDSAConstructor

// A nonce may be consumed by at most one signature: signing two messages under
// one k reveals the private key. Assigning k marks it fresh; _findSignature
// marks it stale once used, and derives a new RFC 6979 nonce when it is stale.
Object.defineProperty(ECDSA.prototype, 'k', {
  get: function (this: ECDSA) {
    return this._k
  },
  set: function (this: ECDSA, k: BN) {
    this._k = k
    this._kFresh = true
  },
  enumerable: true,
  configurable: true
})

ECDSA.prototype.set = function (this: ECDSA, obj: ECDSAObj): ECDSA {
  this.hashbuf = obj.hashbuf || (this.hashbuf as Buffer)
  this.endian = obj.endian || this.endian // the endianness of hashbuf
  this.privkey = obj.privkey || this.privkey
  this.pubkey = obj.pubkey || (this.privkey ? (this.privkey as PrivateKey).publicKey : this.pubkey)

  // === SmartLedger Signature Handling ===
  // Auto-parse DER buffers to Signature objects for compatibility
  if (obj.sig) {
    if (Buffer.isBuffer(obj.sig)) {
      // Parse DER buffer to Signature object
      const Signature = require('./signature')
      this.sig = Signature.fromDER(obj.sig)
    } else {
      // Already a Signature object
      this.sig = obj.sig
    }
  }
  // No else branch: `this.sig = this.sig` was a no-op. Unlike `k` below, `sig`
  // is a plain data property with no setter, so re-assigning it did nothing.

  // Must not be `this.k = obj.k || (this.k as BN)`: that re-runs the setter and would
  // re-mark an already-spent nonce as fresh.
  if (obj.k) {
    this.k = obj.k
  }
  this.verified = obj.verified || this.verified
  return this
}

ECDSA.prototype.privkey2pubkey = function (this: ECDSA): void {
  this.pubkey = (this.privkey as PrivateKey).toPublicKey()
}

ECDSA.prototype.calci = function (this: ECDSA): ECDSA {
  for (let i = 0; i < 4; i++) {
    (this.sig as Signature).i = i
    var Qprime
    try {
      Qprime = this.toPublicKey()
    } catch (e) {
      console.error(e)
      continue
    }

    if (Qprime.point.eq((this.pubkey as PublicKey).point)) {
      (this.sig as Signature).compressed = (this.pubkey as PublicKey).compressed
      return this
    }
  }

  (this.sig as Signature).i = undefined
  throw new Error('Unable to find valid recovery factor')
}

ECDSA.fromString = function (str: string): ECDSA {
  const obj = JSON.parse(str)
  return new (ECDSA as ECDSAConstructor)(obj)
}

ECDSA.prototype.randomK = function (this: ECDSA): ECDSA {
  const N = Point.getN()
  let k
  do {
    k = BN.fromBuffer(Random.getRandomBuffer(32))
  } while (!(k.lt(N) && k.gt(BN.Zero)))
  this.k = k
  return this
}

// https://tools.ietf.org/html/rfc6979#section-3.2
ECDSA.prototype.deterministicK = function (this: ECDSA, badrs?: number): ECDSA {
  // if r or s were invalid when this function was used in signing,
  // we do not want to actually compute r, s here for efficiency, so,
  // we can increment badrs. explained at end of RFC 6979 section 3.2
  if (_.isUndefined(badrs)) {
    badrs = 0
  }
  let v: Buffer = Buffer.alloc(32)
  v.fill(0x01)
  let k: Buffer = Buffer.alloc(32)
  k.fill(0x00)
  const x = (this.privkey as PrivateKey).bn.toBuffer({
    size: 32
  })
  const hashbuf = this.endian === 'little' ? Buffer.from((this.hashbuf as Buffer)).reverse() : (this.hashbuf as Buffer)
  k = Hash.sha256hmac(Buffer.concat([v, Buffer.from([0x00]), x, hashbuf]), k)
  v = Hash.sha256hmac(v, k)
  k = Hash.sha256hmac(Buffer.concat([v, Buffer.from([0x01]), x, hashbuf]), k)
  v = Hash.sha256hmac(v, k)
  v = Hash.sha256hmac(v, k)
  let T = BN.fromBuffer(v)
  const N = Point.getN()

  // also explained in 3.2, we must ensure T is in the proper range (0, N)
  for (let i = 0; i < badrs || !(T.lt(N) && T.gt(BN.Zero)); i++) {
    k = Hash.sha256hmac(Buffer.concat([v, Buffer.from([0x00])]), k)
    v = Hash.sha256hmac(v, k)
    v = Hash.sha256hmac(v, k)
    T = BN.fromBuffer(v)
  }

  this.k = T
  return this
}

// Information about public key recovery:
// https://bitcointalk.org/index.php?topic=6430.0
// http://stackoverflow.com/questions/19665491/how-do-i-get-an-ecdsa-public-key-from-just-a-bitcoin-signature-sec1-4-1-6-k
ECDSA.prototype.toPublicKey = function (this: ECDSA): PublicKey {
  // sig.i is the recovery parameter, always set before toPublicKey() is
  // called: calci() assigns it and fromCompact() parses it.
  const i = (this.sig as Signature).i as number
  $.checkArgument(i === 0 || i === 1 || i === 2 || i === 3, new Error('i must be equal to 0, 1, 2, or 3'))

  const e = BN.fromBuffer((this.hashbuf as Buffer))
  const r = (this.sig as Signature).r
  const s = (this.sig as Signature).s

  // A set LSB signifies that the y-coordinate is odd
  const isYOdd = (i & 1) !== 0

  // The more significant bit specifies whether we should use the
  // first or second candidate key.
  const isSecondKey = (i >> 1) !== 0

  const n = Point.getN()
  const G = Point.getG()

  // 1.1 Let x = r + jn
  const x = isSecondKey ? r.add(n) : r
  const R = Point.fromX(isYOdd, x)

  // 1.4 Check that nR is at infinity
  const nR = R.mul(n)

  if (!nR.isInfinity()) {
    throw new Error('nR is not a valid curve point')
  }

  // Compute -e from e
  const eNeg = e.neg().umod(n)

  // 1.6.1 Compute Q = r^-1 (sR - eG)
  // Q = r^-1 (sR + -eG)
  const rInv = r.invm(n)

  // var Q = R.multiplyTwo(s, G, eNeg).mul(rInv);
  const Q = R.mul(s).add(G.mul(eNeg)).mul(rInv)

  const pubkey = publicKeyClass().fromPoint(Q, (this.sig as Signature).compressed)

  return pubkey
}

ECDSA.prototype.sigError = function (this: ECDSA): string | false {
  if (!Buffer.isBuffer((this.hashbuf as Buffer)) || (this.hashbuf as Buffer).length !== 32) {
    return 'hashbuf must be a 32 byte buffer'
  }

  const r = (this.sig as Signature).r
  const s = (this.sig as Signature).s
  const n = Point.getN()

  try {
    // Reject out-of-range r, s: both must lie in [1, n-1]. lte(0) covers
    // negative and zero values; gte(n) covers anything at or above the order.
    if (r.lte(BN.Zero) || s.lte(BN.Zero) || r.gte(n) || s.gte(n)) {
      return 'r and s not in range'
    }

    const e = BN.fromBuffer((this.hashbuf as Buffer), this.endian
      ? {
          endian: this.endian
        }
      : undefined)

    // Standard ECDSA verification. This accepts both (r, s) and (r, n - s):
    // ECDSA is inherently malleable in s, and verifying the canonical form
    // yields the same accept/reject as verifying s directly, so there is no
    // need to canonicalize or retry here. Low-S is enforced at *signing* time
    // (see ECDSA.toLowS), which is where malleability protection belongs.
    const sinv = s.invm(n)
    const u1 = sinv.mul(e).umod(n)
    const u2 = sinv.mul(r).umod(n)

    const p = Point.getG().mulAdd(u1, (this.pubkey as PublicKey).point, u2)
    if (p.isInfinity()) {
      return 'p is infinity'
    }

    if (p.getX().umod(n).cmp(r) !== 0) {
      return 'Invalid signature'
    }
    return false
  } catch (error) {
    return 'Signature security validation failed: ' + (error as Error).message
  }
}

ECDSA.toLowS = function (s: BN): BN {
  // enforce low s
  // see BIP 62, "low S values in signatures"
  if (s.gt(BN.fromBuffer(Buffer.from('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', 'hex')))) {
    s = Point.getN().sub(s)
  }
  return s
}

ECDSA.prototype._findSignature = function (this: ECDSA, d: BN, e: BN): { s: BN, r: BN } {
  const N = Point.getN()
  const G = Point.getG()
  // try different values of k until r, s are valid
  let badrs = 0
  let k, Q, r, s
  do {
    // A spent nonce (!this._kFresh) must never be reused for a second message.
    if (!(this.k as BN) || !this._kFresh || badrs > 0) {
      this.deterministicK(badrs)
    }
    badrs++
    k = (this.k as BN)
    Q = G.mul(k)
    r = Q.getX().umod(N)
    s = k.invm(N).mul(e.add(d.mul(r))).umod(N)
  } while (r.cmp(BN.Zero) <= 0 || s.cmp(BN.Zero) <= 0)

  this._kFresh = false

  s = ECDSA.toLowS(s)
  return {
    s,
    r
  }
}

ECDSA.prototype.sign = function (this: ECDSA): ECDSA {
  const hashbuf = (this.hashbuf as Buffer)
  const privkey = this.privkey as PrivateKey
  const d = privkey.bn

  $.checkState(hashbuf != null && privkey != null && d != null, 'invalid parameters')
  $.checkState(Buffer.isBuffer(hashbuf) && hashbuf.length === 32, 'hashbuf must be a 32 byte buffer')

  const e = BN.fromBuffer(hashbuf, this.endian
    ? {
        endian: this.endian
      }
    : undefined)

  const obj = this._findSignature(d, e)
  obj.compressed = (this.pubkey as PublicKey).compressed

  this.sig = new Signature(obj)
  return this
}

ECDSA.prototype.signRandomK = function (this: ECDSA): ECDSA {
  this.randomK()
  return this.sign()
}

ECDSA.prototype.toString = function (this: ECDSA): string {
  // Only the populated fields are serialized, so this stays an incrementally
  // built record rather than a literal.
  const obj: Record<string, string> = {}
  if (this.hashbuf != null) {
    obj.hashbuf = this.hashbuf.toString('hex')
  }
  if (this.privkey != null) {
    obj.privkey = this.privkey.toString()
  }
  if (this.pubkey != null) {
    obj.pubkey = this.pubkey.toString()
  }
  if (this.sig != null) {
    obj.sig = this.sig.toString()
  }
  if (this.k != null) {
    obj.k = this.k.toString()
  }
  return JSON.stringify(obj)
}

// verify() returns a BOOLEAN: true only when the signature is valid.
//
// BREAKING (7.0): pre-7.0 this returned the ECDSA *instance* (truthy for
// chaining, with the real result on `.verified`), which silently accepted
// forged signatures whenever a caller wrote `if (ecdsa.verify())`. It now
// returns the boolean directly. `this.verified` is still set as a side effect,
// so `ecdsa.verify(); if (ecdsa.verified)` keeps working; only the chained
// `.verify().verified` idiom is gone — read the return value instead.
ECDSA.prototype.verify = function (this: ECDSA): boolean {
  this.verified = this.sigError() === false
  return this.verified
}

/**
 * Boolean verification. Retained as an explicit alias of verify() for callers
 * written against pre-7.0 code that needed the safe form; both now return a
 * strict boolean.
 * @returns {Boolean}
 */
ECDSA.prototype.verifyBool = function (this: ECDSA): boolean {
  return this.verify() === true
}

ECDSA.sign = function (hashbuf: Buffer, privkey: PrivateKey, endian?: Endian): Signature {
  return ECDSA().set({
    hashbuf,
    endian,
    privkey
  }).sign().sig as Signature
}

ECDSA.signWithCalcI = function (hashbuf: Buffer, privkey: PrivateKey, endian?: Endian): Signature {
  return ECDSA().set({
    hashbuf,
    endian,
    privkey
  }).sign().calci().sig as Signature
}

ECDSA.signRandomK = function (hashbuf: Buffer, privkey: PrivateKey, endian?: Endian): Signature {
  return ECDSA().set({
    hashbuf,
    endian,
    privkey
  }).signRandomK().sig as Signature
}

ECDSA.verify = function (hashbuf: Buffer, sig: Signature, pubkey: PublicKey, endian?: Endian): boolean {
  return ECDSA().set({
    hashbuf,
    endian,
    sig,
    pubkey
  }).verify()
}

export = ECDSA
