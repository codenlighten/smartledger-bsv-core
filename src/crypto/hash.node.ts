'use strict'

import crypto = require('crypto')
import $ = require('../util/preconditions')
import type { HashFunction, HashModule } from './types'

const Hash = {} as HashModule

/**
 * A SHA or SHA1 hash, which is always 160 bits or 20 bytes long.
 *
 * See:
 * https://en.wikipedia.org/wiki/SHA-1
 *
 * @param {Buffer} buf Data, a.k.a. pre-image, which can be any size.
 * @returns {Buffer} The hash in the form of a buffer.
 */
Hash.sha1 = function (buf: Buffer): Buffer {
  $.checkArgument(Buffer.isBuffer(buf))
  return crypto.createHash('sha1').update(buf).digest()
}

Hash.sha1.blocksize = 512

/**
 * A SHA256 hash, which is always 256 bits or 32 bytes long.
 *
 * See:
 * https://www.movable-type.co.uk/scripts/sha256.html
 *
 * @param {Buffer} buf Data, a.k.a. pre-image, which can be any size.
 * @returns {Buffer} The hash in the form of a buffer.
 */
Hash.sha256 = function (buf: Buffer): Buffer {
  $.checkArgument(Buffer.isBuffer(buf))
  return crypto.createHash('sha256').update(buf).digest()
}

Hash.sha256.blocksize = 512

/**
 * A double SHA256 hash, which is always 256 bits or 32 bytes bytes long. This
 * hash function is commonly used inside Bitcoin, particularly for the hash of a
 * block and the hash of a transaction.
 *
 * See:
 * https://www.movable-type.co.uk/scripts/sha256.html
 *
 * @param {Buffer} buf Data, a.k.a. pre-image, which can be any size.
 * @returns {Buffer} The hash in the form of a buffer.
 */
Hash.sha256sha256 = function (buf: Buffer): Buffer {
  $.checkArgument(Buffer.isBuffer(buf))
  return Hash.sha256(Hash.sha256(buf))
}

/**
 * A RIPEMD160 hash, which is always 160 bits or 20 bytes long.
 *
 * See:
 * https://en.wikipedia.org/wiki/RIPEMD
 *
 * @param {Buffer} buf Data, a.k.a. pre-image, which can be any size.
 * @returns {Buffer} The hash in the form of a buffer.
 */
Hash.ripemd160 = function (buf: Buffer): Buffer {
  $.checkArgument(Buffer.isBuffer(buf))
  return crypto.createHash('ripemd160').update(buf).digest()
}
/**
 * A RIPEMD160 hash of a SHA256 hash, which is always 160 bits or 20 bytes long.
 * This value is commonly used inside Bitcoin, particularly for Bitcoin
 * addresses.
 *
 * See:
 * https://en.wikipedia.org/wiki/RIPEMD
 *
 * @param {Buffer} buf Data, a.k.a. pre-image, which can be any size.
 * @returns {Buffer} The hash in the form of a buffer.
 */
Hash.sha256ripemd160 = function (buf: Buffer): Buffer {
  $.checkArgument(Buffer.isBuffer(buf))
  return Hash.ripemd160(Hash.sha256(buf))
}

/**
 * A SHA512 hash, which is always 512 bits or 64 bytes long.
 *
 * See:
 * https://en.wikipedia.org/wiki/SHA-2
 *
 * @param {Buffer} buf Data, a.k.a. pre-image, which can be any size.
 * @returns {Buffer} The hash in the form of a buffer.
 */
Hash.sha512 = function (buf: Buffer): Buffer {
  $.checkArgument(Buffer.isBuffer(buf))
  return crypto.createHash('sha512').update(buf).digest()
}

Hash.sha512.blocksize = 1024

/**
 * A way to do HMAC using any underlying hash function. If you ever find that
 * you want to hash two pieces of data together, you should use HMAC instead of
 * just using a hash function. Rather than doing hash(data1 + data2) you should
 * do HMAC(data1, data2). Actually, rather than use HMAC directly, we recommend
 * you use either sha256hmac or sha515hmac provided below.
 *
 * See:
 * https://en.wikipedia.org/wiki/Length_extension_attack
 * https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
 *
 * @param {function} hashf Which hash function to use.
 * @param {Buffer} data Data, which can be any size.
 * @param {Buffer} key Key, which can be any size.
 * @returns {Buffer} The HMAC in the form of a buffer.
 */
Hash.hmac = function (hashf: HashFunction, data: Buffer, key: Buffer): Buffer {
  // http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
  // http://tools.ietf.org/html/rfc4868#section-2
  $.checkArgument(Buffer.isBuffer(data))
  $.checkArgument(Buffer.isBuffer(key))
  $.checkArgument(hashf.blocksize)

  const blocksize = (hashf.blocksize as number) / 8

  let k = key
  if (k.length > blocksize) {
    k = hashf(k)
  } else if (k.length < blocksize) {
    // The original read `key < blocksize`, comparing a Buffer to a number,
    // which is always false — so this zero-padding branch never ran. It was
    // harmless only by accident: the XOR below indexes past the short key,
    // and `x ^ undefined` is `x ^ 0`, which is exactly what padding produces.
    // Written correctly here; the conformance corpus (RFC 4231 vectors)
    // confirms the output is unchanged.
    const fill = Buffer.alloc(blocksize)
    fill.fill(0)
    k.copy(fill)
    k = fill
  }

  const oKey = Buffer.alloc(blocksize)
  oKey.fill(0x5c)

  const iKey = Buffer.alloc(blocksize)
  iKey.fill(0x36)

  const oKeyPad = Buffer.alloc(blocksize)
  const iKeyPad = Buffer.alloc(blocksize)
  for (let i = 0; i < blocksize; i++) {
    oKeyPad[i] = (oKey[i] as number) ^ (k[i] as number)
    iKeyPad[i] = (iKey[i] as number) ^ (k[i] as number)
  }

  return hashf(Buffer.concat([oKeyPad, hashf(Buffer.concat([iKeyPad, data]))]))
}

/**
 * A SHA256 HMAC.
 *
 * @param {Buffer} data Data, which can be any size.
 * @param {Buffer} key Key, which can be any size.
 * @returns {Buffer} The HMAC in the form of a buffer.
 */
Hash.sha256hmac = function (data: Buffer, key: Buffer): Buffer {
  return Hash.hmac(Hash.sha256, data, key)
}

/**
 * A SHA512 HMAC.
 *
 * @param {Buffer} data Data, which can be any size.
 * @param {Buffer} key Key, which can be any size.
 * @returns {Buffer} The HMAC in the form of a buffer.
 */
Hash.sha512hmac = function (data: Buffer, key: Buffer): Buffer {
  return Hash.hmac(Hash.sha512, data, key)
}

export = Hash
