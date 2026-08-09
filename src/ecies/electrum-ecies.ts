'use strict'

// Electrum BIE1 ECIES, backed by the audited @noble suite. Wire format unchanged
// and byte-compatible with prior versions (locked by the golden known-answer
// vector in test/ecies/electrum-ecies.js).

import PublicKey = require('../publickey')
import PrivateKey = require('../privatekey')
import $ = require('../util/preconditions')
import bitcoreECIES = require('./bitcore-ecies')
import errors = require('./errors')
import type { ElectrumECIES, ElectrumECIESConstructor, ECIESOptions, AESCBCStatic } from './types'

// The error tree is built dynamically; members arrive via an index signature.
type ErrCtor = new (...args: unknown[]) => Error
const err = (path: string): ErrCtor =>
  path.split('.').reduce<any>((o, k) => o[k], errors) as ErrCtor

const { secp256k1 } = require('@noble/curves/secp256k1.js')
const { sha512, sha256 } = require('@noble/hashes/sha2.js')
const { hmac } = require('@noble/hashes/hmac.js')
const { cbc } = require('@noble/ciphers/aes.js')

function buf (u8: Uint8Array): Buffer { return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength) }
function sha256hmac (data: Uint8Array, key: Uint8Array): Buffer { return buf(hmac(sha256, key, data)) }

const AESCBC = function AESCBC () {} as unknown as AESCBCStatic

AESCBC.encrypt = function (messagebuf: Buffer, keybuf: Buffer, ivbuf: Buffer) {
  $.checkArgument(messagebuf)
  $.checkArgument(keybuf)
  $.checkArgument(ivbuf)
  $.checkArgument(keybuf.length === 16, 'keybuf length must be 16')
  $.checkArgument(ivbuf.length === 16, 'ivbuf length must be 16')
  return buf(cbc(Uint8Array.from(keybuf), Uint8Array.from(ivbuf)).encrypt(Uint8Array.from(messagebuf)))
}

AESCBC.decrypt = function (encbuf: Buffer, keybuf: Buffer, ivbuf: Buffer) {
  $.checkArgument(encbuf)
  $.checkArgument(keybuf)
  $.checkArgument(ivbuf)
  $.checkArgument(keybuf.length === 16, 'keybuf length must be 16')
  $.checkArgument(ivbuf.length === 16, 'ivbuf length must be 16')
  return buf(cbc(Uint8Array.from(keybuf), Uint8Array.from(ivbuf)).decrypt(Uint8Array.from(encbuf)))
}

const ECIES = function ECIES (this: ElectrumECIES, opts?: ECIESOptions, algorithm = 'BIE1') {
  if (algorithm !== 'BIE1') throw new (err('UnsupportAlgorithm'))(algorithm)
  if (!(this instanceof ECIES)) {
    return new (ECIES as unknown as ElectrumECIESConstructor)(opts, algorithm)
  }
  this._privateKey = new PrivateKey()
  this.opts = opts || {}
  this.opts.ephemeralKey = true
}

ECIES.prototype.privateKey = function (this: ElectrumECIES, privateKey: any) {
  $.checkArgument(PrivateKey.isValid(privateKey), 'no private key provided')
  this._privateKey = PrivateKey(privateKey.toHex()) || null
  this.opts.ephemeralKey = false
  return this
}

ECIES.prototype.publicKey = function (this: ElectrumECIES, publicKey: any) {
  $.checkArgument(PublicKey.isValid(publicKey), 'no public key provided')
  this._publicKey = PublicKey(publicKey.toString()) || null
  if (this._publicKey != null) this.opts.fixedPublicKey = true
  return this
}

const defineProperty = function (name: string, getter: (this: ElectrumECIES) => Buffer) {
  const cachedName = '_' + name
  Object.defineProperty(ECIES.prototype, name, {
    configurable: false,
    enumerable: true,
    get: function (this: any) {
      let value = this[cachedName]
      value = this[cachedName] = getter.apply(this)
      return value
    }
  })
}

defineProperty('Rbuf', function (this: ElectrumECIES) {
  const priv = this._privateKey!.bn.toBuffer({ size: 32 })
  return buf(secp256k1.getPublicKey(Uint8Array.from(priv), true))
})

defineProperty('ivkEkM', function (this: ElectrumECIES) {
  const priv = this._privateKey!.bn.toBuffer({ size: 32 })
  const pub = this._publicKey!.toDER()
  const Sbuf = secp256k1.getSharedSecret(Uint8Array.from(priv), Uint8Array.from(pub), true)
  return buf(sha512(Sbuf))
})

defineProperty('iv', function (this: ElectrumECIES) { return this.ivkEkM.slice(0, 16) })
defineProperty('kE', function (this: ElectrumECIES) { return this.ivkEkM.slice(16, 32) })
defineProperty('kM', function (this: ElectrumECIES) { return this.ivkEkM.slice(32, 64) })

ECIES.prototype.encrypt = function (this: ElectrumECIES, message: any) {
  if (!Buffer.isBuffer(message)) message = Buffer.from(message)
  const ciphertext = AESCBC.encrypt(message, this.kE, this.iv)
  let encbuf
  const BIE1 = Buffer.from('BIE1')
  if (this.opts.noKey && !this.opts.ephemeralKey) {
    encbuf = Buffer.concat([BIE1, ciphertext])
  } else {
    encbuf = Buffer.concat([BIE1, this.Rbuf, ciphertext])
  }
  let tag = sha256hmac(encbuf, this.kM)
  if (this.opts.shortTag) tag = tag.slice(0, 4)
  return Buffer.concat([encbuf, tag])
}

ECIES.prototype.decrypt = function (this: ElectrumECIES, encbuf: any) {
  $.checkArgument(Buffer.isBuffer(encbuf), 'ciphetext must be a buffer')
  const tagLength = this.opts.shortTag ? 4 : 32
  let offset = 4
  const magic = encbuf.slice(0, 4)
  if (!magic.equals(Buffer.from('BIE1'))) {
    throw new (err('DecryptionError'))('Invalid Magic')
  }
  if (!this.opts.noKey) {
    const pub = encbuf.slice(4, 37)
    if (this.opts.fixedPublicKey) console.log('Notice: Overriding PublicKey in message. Consider use "noKey" option if you are not sending message to electrum and do not want to use ephemeral key')
    else this._publicKey = PublicKey.fromDER(pub)
    offset = 37
  }

  const ciphertext = encbuf.slice(offset, encbuf.length - tagLength)
  const tag = encbuf.slice(encbuf.length - tagLength, encbuf.length)

  let tag2 = sha256hmac(encbuf.slice(0, encbuf.length - tagLength), this.kM)
  if (this.opts.shortTag) tag2 = tag2.slice(0, 4)

  if (tag.length !== tag2.length) {
    throw new (err('DecryptionError'))('Invalid checksum')
  }
  let equal = 0
  // See the note in bitcore-ecies: assertions erase, a guard would branch.
  for (let i = 0; i < tag2.length; i++) equal |= (tag[i]! ^ tag2[i]!)
  if (equal !== 0) {
    throw new (err('DecryptionError'))('Invalid checksum')
  }

  return AESCBC.decrypt(ciphertext, this.kE, this.iv)
}

ECIES.bitcoreECIES = bitcoreECIES

export = ECIES as unknown as ElectrumECIESConstructor
