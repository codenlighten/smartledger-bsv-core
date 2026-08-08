'use strict'

const { KEYS } = require('../vectors')

const hex = (s) => Buffer.from(s, 'hex')
const utf8 = (s) => Buffer.from(s, 'utf8')

// A spread of message hashes including the degenerate all-zero and all-ff
// digests, which have historically tripped up nonce derivation.
const DIGESTS = {
  zero: '00'.repeat(32),
  one: '00'.repeat(31) + '01',
  ff: 'ff'.repeat(32),
  abc: null // filled per-call via sha256('abc')
}

const cases = {
  // --- Deterministic signing (RFC 6979) ------------------------------------
  // Signatures must be reproducible byte-for-byte. Non-determinism here means
  // a random nonce, and a repeated random nonce leaks the private key.
  'sign is deterministic across calls': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const h = bsv.crypto.Hash.sha256(utf8('abc'))
    const a = bsv.crypto.ECDSA.sign(h, key)
    const b = bsv.crypto.ECDSA.sign(h, key)
    return { sig: a.toString(), stable: a.toString() === b.toString() }
  },

  'distinct messages give distinct nonces': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const sigs = ['a', 'b', 'c'].map((m) =>
      bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(utf8(m)), key))
    const rs = sigs.map((s) => s.r.toString(16))
    return { rs, allDistinct: new Set(rs).size === rs.length }
  },

  'sign/verify round-trip': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const h = bsv.crypto.Hash.sha256(utf8('conformance'))
    const sig = bsv.crypto.ECDSA.sign(h, key)
    return {
      verifies: bsv.crypto.ECDSA.verify(h, sig, key.publicKey),
      wrongMsg: bsv.crypto.ECDSA.verify(bsv.crypto.Hash.sha256(utf8('other')), sig, key.publicKey),
      wrongKey: bsv.crypto.ECDSA.verify(h, sig, bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2).publicKey)
    }
  },

  // --- Low-S / malleability -------------------------------------------------
  // Every produced signature must already be low-S; a high-S signature is a
  // second valid encoding of the same signature (transaction malleability).
  'produced signatures are low-S': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const half = bsv.crypto.Point.getN().shrn(1)
    return ['m1', 'm2', 'm3', 'm4', 'm5'].map((m) => {
      const sig = bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(utf8(m)), key)
      return sig.s.cmp(half) <= 0
    })
  },
  'toLowS is idempotent': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const sig = bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(utf8('x')), key)
    const once = bsv.crypto.ECDSA.toLowS(sig.s)
    const twice = bsv.crypto.ECDSA.toLowS(once)
    return { same: once.toString() === twice.toString() }
  },

  // --- Digest edge cases ----------------------------------------------------
  ...Object.keys(DIGESTS).filter((k) => DIGESTS[k]).reduce((acc, name) => {
    acc[`sign digest ${name}`] = (bsv) =>
      bsv.crypto.ECDSA.sign(hex(DIGESTS[name]), bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)).toString()
    return acc
  }, {}),
  'sign digest of sha256("abc")': (bsv) =>
    bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(utf8('abc')), bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)).toString(),

  // --- Input validation -----------------------------------------------------
  'sign rejects short digest': (bsv) =>
    bsv.crypto.ECDSA.sign(hex('0102'), bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)),
  'sign rejects string digest': (bsv) =>
    bsv.crypto.ECDSA.sign('abc', bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)),
  // Current behavior is an internal TypeError ("Cannot read properties of
  // undefined"), not a validation error. Pinned as-is so the rewrite has to
  // make an explicit decision; flagged for the API pass as a place that should
  // raise a typed InvalidArgument instead of leaking an internal property name.
  'sign with null key (crashes, does not validate)': (bsv) =>
    bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(utf8('a')), null),
  'verify with malformed signature': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    return bsv.crypto.ECDSA.verify(bsv.crypto.Hash.sha256(utf8('a')), {}, key.publicKey)
  },

  // --- Signature encoding ---------------------------------------------------
  'signature DER round-trip': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const sig = bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(utf8('der')), key)
    const der = sig.toDER()
    return { der, roundTrips: bsv.crypto.Signature.fromDER(der).toDER().toString('hex') === der.toString('hex') }
  },
  'isTxDER on well-formed': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const sig = bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(utf8('der')), key)
    return bsv.crypto.Signature.isTxDER(Buffer.concat([sig.toDER(), Buffer.from([0x41])]))
  },
  // Non-canonical DER encodings must be rejected — these are the classic
  // malleability vectors.
  'isTxDER rejects empty': (bsv) => bsv.crypto.Signature.isTxDER(hex('')),
  'isTxDER rejects wrong leading byte': (bsv) =>
    bsv.crypto.Signature.isTxDER(hex('31450221009a0221009a41')),
  'isTxDER rejects excess length': (bsv) =>
    bsv.crypto.Signature.isTxDER(Buffer.concat([hex('30'), Buffer.alloc(200, 2)])),
  'fromDER rejects negative R': (bsv) =>
    bsv.crypto.Signature.fromDER(hex('3006020180020101')),
  'fromDER rejects padded R': (bsv) =>
    bsv.crypto.Signature.fromDER(hex('30070203000001020101')),
  'fromDER rejects truncated': (bsv) => bsv.crypto.Signature.fromDER(hex('3006')),
  'fromDER rejects trailing garbage': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const der = bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(utf8('x')), key).toDER()
    return bsv.crypto.Signature.fromDER(Buffer.concat([der, hex('00')])).toString()
  },

  // --- Compact / recoverable ------------------------------------------------
  'compact signature round-trip': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const h = bsv.crypto.Hash.sha256(utf8('compact'))
    const sig = bsv.crypto.ECDSA.signWithCalcI(h, key)
    const compact = sig.toCompact()
    return { compact, i: sig.i, roundTrips: bsv.crypto.Signature.fromCompact(compact).toCompact().toString('hex') === compact.toString('hex') }
  }
}

module.exports = { name: 'ecdsa', cases }
