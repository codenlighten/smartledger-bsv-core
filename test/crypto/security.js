'use strict'

/* global describe, it, before */

require('chai').should()
const expect = require('chai').expect

const bsv = require('../../index.js')
const BN = bsv.crypto.BN
const ECDSA = bsv.crypto.ECDSA
const Hash = bsv.crypto.Hash
const Point = bsv.crypto.Point
const Signature = bsv.crypto.Signature
const SmartVerify = bsv.crypto.SmartVerify

describe('SmartLedger Security Patches', function () {
  let privateKey, publicKey, message, hash

  before(function () {
    privateKey = new bsv.PrivateKey()
    publicKey = privateKey.toPublicKey()
    message = 'SmartLedger security test message'
    hash = Hash.sha256(Buffer.from(message))
  })

  describe('Zero Parameter Attack Protection', function () {
    it('Signature.validate() throws when r = 0', function () {
      const sig = new Signature({ r: new BN(0), s: new BN(1) })
      expect(function () { sig.validate() }).to.throw(/r component is zero/)
    })

    it('Signature.validate() throws when s = 0', function () {
      const sig = new Signature({ r: new BN(1), s: new BN(0) })
      expect(function () { sig.validate() }).to.throw(/s component is zero/)
    })

    it('smartVerify rejects (without throwing) a zero-s signature', function () {
      const sig = new Signature({ r: new BN(1), s: new BN(0) })
      SmartVerify.smartVerify(hash, sig, publicKey).should.equal(false)
    })
  })

  describe('Canonical Signature Enforcement', function () {
    it('freshly produced signatures are canonical (low-S)', function () {
      const sig = ECDSA.sign(hash, privateKey)
      sig.isCanonical().should.equal(true)
      SmartVerify.isCanonical(sig).should.equal(true)
    })

    it('detects a non-canonical (high-S) signature', function () {
      const sig = ECDSA.sign(hash, privateKey)
      const n = Point.getN()
      const lowS = sig.s.lte(n.shrn(1)) ? sig.s : n.sub(sig.s)
      const highS = new Signature({ r: sig.r, s: n.sub(lowS) })

      highS.isCanonical().should.equal(false)
      SmartVerify.isCanonical(highS).should.equal(false)
    })

    it('toCanonical() converts a high-S signature to canonical form', function () {
      const sig = ECDSA.sign(hash, privateKey)
      const n = Point.getN()
      const lowS = sig.s.lte(n.shrn(1)) ? sig.s : n.sub(sig.s)
      const highS = new Signature({ r: sig.r, s: n.sub(lowS) })

      const canonical = highS.toCanonical()
      canonical.isCanonical().should.equal(true)
      // Both forms verify (ECDSA is malleable in s); canonicalization does not
      // change which key/message the signature is valid for.
      canonical.r.cmp(highS.r).should.equal(0)
    })

    it('toCanonical() returns a new signature and leaves the original alone', function () {
      const sig = ECDSA.sign(hash, privateKey)
      const n = Point.getN()
      const lowS = sig.s.lte(n.shrn(1)) ? sig.s : n.sub(sig.s)
      const highS = new Signature({ r: sig.r, s: n.sub(lowS) })
      const before = highS.s.toString()

      const canonical = highS.toCanonical()
      canonical.should.not.equal(highS)
      highS.s.toString().should.equal(before)
    })
  })

  describe('applySecurityPatches', function () {
    const highSig = function () {
      const sig = ECDSA.sign(hash, privateKey)
      const n = Point.getN()
      const lowS = sig.s.lte(n.shrn(1)) ? sig.s : n.sub(sig.s)
      return new Signature({ r: sig.r, s: n.sub(lowS) })
    }

    it('accepts a canonical signature and returns it for chaining', function () {
      const sig = ECDSA.sign(hash, privateKey)
      sig.applySecurityPatches().should.equal(sig)
    })

    it('rejects a non-canonical (high-S) signature rather than rewriting it', function () {
      // Rewriting s to n-s cannot protect against malleability: the rewritten
      // signature verifies exactly as the original, so silently normalizing only
      // hides from the caller that the signature was malleated.
      const highS = highSig()
      const before = highS.s.toString()

      expect(function () { highS.applySecurityPatches() }).to.throw(/non-canonical/)
      highS.s.toString().should.equal(before)
    })

    it('rejects zero and out-of-range components', function () {
      expect(function () {
        new Signature({ r: new BN(0), s: new BN(1) }).applySecurityPatches()
      }).to.throw(/zero r or s/)
      expect(function () {
        new Signature({ r: new BN(1), s: Point.getN() }).applySecurityPatches()
      }).to.throw(/out of range/)
    })
  })

  describe('SmartVerify Enhanced Validation', function () {
    it('accepts a valid signature', function () {
      const sig = ECDSA.sign(hash, privateKey)
      SmartVerify.smartVerify(hash, sig, publicKey).should.equal(true)
    })

    it('rejects a malleated (high-S) signature', function () {
      const sig = ECDSA.sign(hash, privateKey)
      const n = Point.getN()
      const lowS = sig.s.lte(n.shrn(1)) ? sig.s : n.sub(sig.s)
      const highS = new Signature({ r: sig.r, s: n.sub(lowS) })
      SmartVerify.isCanonical(highS).should.equal(false)
      SmartVerify.smartVerify(hash, highS, publicKey).should.equal(false)
      // ...while the canonical form of the same signature still verifies.
      SmartVerify.smartVerify(hash, new Signature({ r: sig.r, s: lowS }), publicKey).should.equal(true)
    })

    it('throws on an invalid (non-32-byte) message hash', function () {
      const sig = ECDSA.sign(hash, privateKey)
      const shortHash = Buffer.alloc(16)
      expect(function () {
        SmartVerify.smartVerify(shortHash, sig, publicKey)
      }).to.throw(/32-byte/)
    })

    it('rejects a signature from the wrong key', function () {
      const sig = ECDSA.sign(hash, privateKey)
      const otherPub = new bsv.PrivateKey().toPublicKey()
      SmartVerify.smartVerify(hash, sig, otherPub).should.equal(false)
    })
  })

  describe('Integration with Original BSV', function () {
    it('round-trips a Bitcoin message signature', function () {
      const sig = new bsv.Message(message).sign(privateKey)
      const verified = new bsv.Message(message).verify(publicKey.toAddress().toString(), sig)
      verified.should.equal(true)
    })

    it('signs a transaction to completion', function () {
      const utxo = {
        txId: 'a'.repeat(64),
        outputIndex: 0,
        address: privateKey.toAddress().toString(),
        script: bsv.Script.buildPublicKeyHashOut(privateKey.toAddress()).toHex(),
        satoshis: 100000
      }

      const transaction = new bsv.Transaction()
        .from(utxo)
        .to(privateKey.toAddress(), 50000)
        .sign(privateKey)

      transaction.isFullySigned().should.equal(true)
    })
  })
})
