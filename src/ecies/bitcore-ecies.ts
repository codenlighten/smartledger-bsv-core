'use strict'

// Bitcore ECIES, backed by the audited @noble suite (secp256k1 ECDH, SHA-2,
// HMAC, AES-CBC) instead of the elliptic/aes-js primitives. The wire format is
// unchanged and byte-compatible with prior versions (locked by the golden
// known-answer vector in test/ecies/bitcore-ecies.js). The scheme is unchanged:
//
//   S       = X coord of (senderPriv * recipientPub)        (ECDH, secp256k1)
//   kE||kM  = SHA-512(S)                                     (KDF)
//   c       = IV || AES-256-CBC_PKCS7(kE, IV, message)
//   d       = HMAC-SHA256(kM, c)                             (encrypt-then-MAC)
//   out     = [Rpub] || c || d
//
// Public API is identical to bitcore-ecies so it is a drop-in: it accepts the
// same bsv PrivateKey/PublicKey objects. Only key *decoding* touches bsv; all
// cryptography is @noble.

const { secp256k1 } = require('@noble/curves/secp256k1.js')
const { sha512, sha256 } = require('@noble/hashes/sha2.js')
const { hmac } = require('@noble/hashes/hmac.js')
const { cbc } = require('@noble/ciphers/aes.js')

import PublicKey = require('../publickey')
import $ = require('../util/preconditions')
import Random = require('../crypto/random')
import type { BitcoreECIES, BitcoreECIESConstructor, ECIESOptions, AESCBCStatic } from './types'

function buf (u8: Uint8Array): Buffer { return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength) }
function hmacSha256 (key: Uint8Array, data: Uint8Array): Buffer { return buf(hmac(sha256, key, data)) }

// Constant-time buffer comparison (see bitcore-ecies for rationale).
function constantTimeEqual (a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  // Non-null assertions, not bounds checks: this loop is a constant-time
  // comparison, and the assertions erase at compile time. A real guard here
  // would introduce a data-dependent branch, which is the whole point of the
  // function.
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

const AESCBC = function AESCBC () {} as unknown as AESCBCStatic

AESCBC.encrypt = function (messagebuf: Buffer, cipherkeybuf: Buffer, ivbuf: Buffer) {
  $.checkArgument(messagebuf)
  $.checkArgument(cipherkeybuf)
  $.checkArgument(ivbuf)
  ivbuf = ivbuf || Random.getRandomBuffer(128 / 8)
  const ct = cbc(Uint8Array.from(cipherkeybuf), Uint8Array.from(ivbuf)).encrypt(Uint8Array.from(messagebuf))
  return Buffer.concat([Buffer.from(ivbuf), buf(ct)])
}

AESCBC.decrypt = function (encbuf: Buffer, cipherkeybuf: Buffer) {
  $.checkArgument(encbuf)
  $.checkArgument(cipherkeybuf)
  const ivbuf = encbuf.slice(0, 128 / 8)
  const ctbuf = encbuf.slice(128 / 8)
  const msg = cbc(Uint8Array.from(cipherkeybuf), Uint8Array.from(ivbuf)).decrypt(Uint8Array.from(ctbuf))
  return buf(msg)
}

const ECIES = function ECIES (this: BitcoreECIES, opts?: ECIESOptions) {
  // Forward opts through the no-`new` guard; dropping it (the pre-7.0.2
  // `new ECIES()`) silently ignored { noKey, shortTag } when called as a
  // factory, changing the wire format (e.g. leaking the 33-byte sender pubkey).
  if (!(this instanceof ECIES)) return new (ECIES as unknown as BitcoreECIESConstructor)(opts)
  this.opts = opts || {}
}

ECIES.prototype.privateKey = function (this: BitcoreECIES, privateKey: any) {
  $.checkArgument(privateKey, 'no private key provided')
  this._privateKey = privateKey || null
  return this
}

ECIES.prototype.publicKey = function (this: BitcoreECIES, publicKey: any) {
  $.checkArgument(publicKey, 'no public key provided')
  this._publicKey = publicKey || null
  return this
}

const cachedProperty = function (name: string, getter: (this: BitcoreECIES) => Buffer) {
  const cachedName = '_' + name
  Object.defineProperty(ECIES.prototype, name, {
    configurable: false,
    enumerable: true,
    get: function (this: any) {
      let value = this[cachedName]
      if (!value) value = this[cachedName] = getter.apply(this)
      return value
    }
  })
}

// Sender's compressed public key (R), via @noble from the raw private scalar.
cachedProperty('Rbuf', function (this: BitcoreECIES) {
  const priv = this._privateKey!.bn.toBuffer({ size: 32 })
  return buf(secp256k1.getPublicKey(Uint8Array.from(priv), true))
})

// ECDH + KDF: S = X(priv * pub); kE||kM = SHA-512(S).
cachedProperty('kEkM', function (this: BitcoreECIES) {
  const priv = this._privateKey!.bn.toBuffer({ size: 32 })
  const pub = this._publicKey!.toDER() // SEC-encoded; @noble accepts either form
  const shared = secp256k1.getSharedSecret(Uint8Array.from(priv), Uint8Array.from(pub), true)
  const Sbuf = shared.slice(1) // drop the 02/03 prefix -> 32-byte X coordinate
  return buf(sha512(Sbuf))
})

cachedProperty('kE', function (this: BitcoreECIES) { return this.kEkM.slice(0, 32) })
cachedProperty('kM', function (this: BitcoreECIES) { return this.kEkM.slice(32, 64) })

ECIES.prototype.encrypt = function (this: BitcoreECIES, message: any, ivbuf: any) {
  if (!Buffer.isBuffer(message)) message = Buffer.from(message)
  if (ivbuf === undefined) {
    ivbuf = hmacSha256(this._privateKey!.toBuffer(), message).slice(0, 16)
  }
  const c = AESCBC.encrypt(message, this.kE, ivbuf)
  let d = hmacSha256(this.kM, c)
  if (this.opts.shortTag) d = d.slice(0, 4)
  if (this.opts.noKey) return Buffer.concat([c, d])
  return Buffer.concat([this.Rbuf, c, d])
}

ECIES.prototype.decrypt = function (this: BitcoreECIES, encbuf: any) {
  $.checkArgument(encbuf)
  let offset = 0
  const tagLength = this.opts.shortTag ? 4 : 32
  if (!this.opts.noKey) {
    let pub
    switch (encbuf[0]) {
      case 4: pub = encbuf.slice(0, 65); break
      case 3:
      case 2: pub = encbuf.slice(0, 33); break
      default: throw new Error('Invalid type: ' + encbuf[0])
    }
    this._publicKey = PublicKey.fromDER(pub)
    offset += pub.length
  }

  const c = encbuf.slice(offset, encbuf.length - tagLength)
  const d = encbuf.slice(encbuf.length - tagLength, encbuf.length)

  let d2 = hmacSha256(this.kM, c)
  if (this.opts.shortTag) d2 = d2.slice(0, 4)
  if (!constantTimeEqual(d, d2)) throw new Error('Invalid checksum')

  return AESCBC.decrypt(c, this.kE)
}

export = ECIES as unknown as BitcoreECIESConstructor
