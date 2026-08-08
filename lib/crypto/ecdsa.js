'use strict'

const BN = require('./bn')
const Point = require('./point')
const Signature = require('./signature')
const PublicKey = require('../publickey')
const Random = require('./random')
const Hash = require('./hash')
const _ = require('../util/_')
const $ = require('../util/preconditions')

const ECDSA = function ECDSA (obj) {
  if (!(this instanceof ECDSA)) {
    return new ECDSA(obj)
  }
  if (obj) {
    this.set(obj)
  }
}

// A nonce may be consumed by at most one signature: signing two messages under
// one k reveals the private key. Assigning k marks it fresh; _findSignature
// marks it stale once used, and derives a new RFC 6979 nonce when it is stale.
Object.defineProperty(ECDSA.prototype, 'k', {
  get: function () {
    return this._k
  },
  set: function (k) {
    this._k = k
    this._kFresh = true
  },
  enumerable: true,
  configurable: true
})

ECDSA.prototype.set = function (obj) {
  this.hashbuf = obj.hashbuf || this.hashbuf
  this.endian = obj.endian || this.endian // the endianness of hashbuf
  this.privkey = obj.privkey || this.privkey
  this.pubkey = obj.pubkey || (this.privkey ? this.privkey.publicKey : this.pubkey)

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

  // Must not be `this.k = obj.k || this.k`: that re-runs the setter and would
  // re-mark an already-spent nonce as fresh.
  if (obj.k) {
    this.k = obj.k
  }
  this.verified = obj.verified || this.verified
  return this
}

ECDSA.prototype.privkey2pubkey = function () {
  this.pubkey = this.privkey.toPublicKey()
}

ECDSA.prototype.calci = function () {
  for (let i = 0; i < 4; i++) {
    this.sig.i = i
    var Qprime
    try {
      Qprime = this.toPublicKey()
    } catch (e) {
      console.error(e)
      continue
    }

    if (Qprime.point.eq(this.pubkey.point)) {
      this.sig.compressed = this.pubkey.compressed
      return this
    }
  }

  this.sig.i = undefined
  throw new Error('Unable to find valid recovery factor')
}

ECDSA.fromString = function (str) {
  const obj = JSON.parse(str)
  return new ECDSA(obj)
}

ECDSA.prototype.randomK = function () {
  const N = Point.getN()
  let k
  do {
    k = BN.fromBuffer(Random.getRandomBuffer(32))
  } while (!(k.lt(N) && k.gt(BN.Zero)))
  this.k = k
  return this
}

// https://tools.ietf.org/html/rfc6979#section-3.2
ECDSA.prototype.deterministicK = function (badrs) {
  // if r or s were invalid when this function was used in signing,
  // we do not want to actually compute r, s here for efficiency, so,
  // we can increment badrs. explained at end of RFC 6979 section 3.2
  if (_.isUndefined(badrs)) {
    badrs = 0
  }
  let v = Buffer.alloc(32)
  v.fill(0x01)
  let k = Buffer.alloc(32)
  k.fill(0x00)
  const x = this.privkey.bn.toBuffer({
    size: 32
  })
  const hashbuf = this.endian === 'little' ? Buffer.from(this.hashbuf).reverse() : this.hashbuf
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
ECDSA.prototype.toPublicKey = function () {
  const i = this.sig.i
  $.checkArgument(i === 0 || i === 1 || i === 2 || i === 3, new Error('i must be equal to 0, 1, 2, or 3'))

  const e = BN.fromBuffer(this.hashbuf)
  const r = this.sig.r
  const s = this.sig.s

  // A set LSB signifies that the y-coordinate is odd
  const isYOdd = i & 1

  // The more significant bit specifies whether we should use the
  // first or second candidate key.
  const isSecondKey = i >> 1

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

  const pubkey = PublicKey.fromPoint(Q, this.sig.compressed)

  return pubkey
}

ECDSA.prototype.sigError = function () {
  if (!Buffer.isBuffer(this.hashbuf) || this.hashbuf.length !== 32) {
    return 'hashbuf must be a 32 byte buffer'
  }

  const r = this.sig.r
  const s = this.sig.s
  const n = Point.getN()

  try {
    // Reject out-of-range r, s: both must lie in [1, n-1]. lte(0) covers
    // negative and zero values; gte(n) covers anything at or above the order.
    if (r.lte(BN.Zero) || s.lte(BN.Zero) || r.gte(n) || s.gte(n)) {
      return 'r and s not in range'
    }

    const e = BN.fromBuffer(this.hashbuf, this.endian
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

    const p = Point.getG().mulAdd(u1, this.pubkey.point, u2)
    if (p.isInfinity()) {
      return 'p is infinity'
    }

    if (p.getX().umod(n).cmp(r) !== 0) {
      return 'Invalid signature'
    }
    return false
  } catch (error) {
    return 'Signature security validation failed: ' + error.message
  }
}

ECDSA.toLowS = function (s) {
  // enforce low s
  // see BIP 62, "low S values in signatures"
  if (s.gt(BN.fromBuffer(Buffer.from('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', 'hex')))) {
    s = Point.getN().sub(s)
  }
  return s
}

ECDSA.prototype._findSignature = function (d, e) {
  const N = Point.getN()
  const G = Point.getG()
  // try different values of k until r, s are valid
  let badrs = 0
  let k, Q, r, s
  do {
    // A spent nonce (!this._kFresh) must never be reused for a second message.
    if (!this.k || !this._kFresh || badrs > 0) {
      this.deterministicK(badrs)
    }
    badrs++
    k = this.k
    Q = G.mul(k)
    r = Q.x.umod(N)
    s = k.invm(N).mul(e.add(d.mul(r))).umod(N)
  } while (r.cmp(BN.Zero) <= 0 || s.cmp(BN.Zero) <= 0)

  this._kFresh = false

  s = ECDSA.toLowS(s)
  return {
    s,
    r
  }
}

ECDSA.prototype.sign = function () {
  const hashbuf = this.hashbuf
  const privkey = this.privkey
  const d = privkey.bn

  $.checkState(hashbuf && privkey && d, new Error('invalid parameters'))
  $.checkState(Buffer.isBuffer(hashbuf) && hashbuf.length === 32, new Error('hashbuf must be a 32 byte buffer'))

  const e = BN.fromBuffer(hashbuf, this.endian
    ? {
        endian: this.endian
      }
    : undefined)

  const obj = this._findSignature(d, e)
  obj.compressed = this.pubkey.compressed

  this.sig = new Signature(obj)
  return this
}

ECDSA.prototype.signRandomK = function () {
  this.randomK()
  return this.sign()
}

ECDSA.prototype.toString = function () {
  const obj = {}
  if (this.hashbuf) {
    obj.hashbuf = this.hashbuf.toString('hex')
  }
  if (this.privkey) {
    obj.privkey = this.privkey.toString()
  }
  if (this.pubkey) {
    obj.pubkey = this.pubkey.toString()
  }
  if (this.sig) {
    obj.sig = this.sig.toString()
  }
  if (this.k) {
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
ECDSA.prototype.verify = function () {
  this.verified = !this.sigError()
  return this.verified
}

/**
 * Boolean verification. Retained as an explicit alias of verify() for callers
 * written against pre-7.0 code that needed the safe form; both now return a
 * strict boolean.
 * @returns {Boolean}
 */
ECDSA.prototype.verifyBool = function () {
  return this.verify() === true
}

ECDSA.sign = function (hashbuf, privkey, endian) {
  return ECDSA().set({
    hashbuf,
    endian,
    privkey
  }).sign().sig
}

ECDSA.signWithCalcI = function (hashbuf, privkey, endian) {
  return ECDSA().set({
    hashbuf,
    endian,
    privkey
  }).sign().calci().sig
}

ECDSA.signRandomK = function (hashbuf, privkey, endian) {
  return ECDSA().set({
    hashbuf,
    endian,
    privkey
  }).signRandomK().sig
}

ECDSA.verify = function (hashbuf, sig, pubkey, endian) {
  return ECDSA().set({
    hashbuf,
    endian,
    sig,
    pubkey
  }).verify()
}

module.exports = ECDSA
