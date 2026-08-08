'use strict'

import _ = require('../util/_')
import bs58 = require('bs58')
import type { Base58, Base58Constructor } from './types'

/**
 * The alphabet for the Bitcoin-specific Base 58 encoding distinguishes between
 * lower case L and upper case i - neither of those characters are allowed to
 * prevent accidentaly miscopying of letters.
 */
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.split('')

/**
 * Base58 encoding/decoding. Addresses and private keys add a checksum on top
 * of this and use Base58Check instead.
 *
 * Constructor function rather than a class: callable with and without `new`.
 */
const Base58 = function Base58 (this: Base58, obj?: Buffer | string) {
  if (!(this instanceof Base58)) {
    return new (Base58 as Base58Constructor)(obj)
  }
  if (Buffer.isBuffer(obj)) {
    const buf = obj
    this.fromBuffer(buf)
  } else if (typeof obj === 'string') {
    const str = obj
    this.fromString(str)
  }
} as unknown as Base58Constructor

Base58.validCharacters = function validCharacters (chars: string | Buffer): boolean {
  const s = Buffer.isBuffer(chars) ? chars.toString() : chars
  return _.every(_.map(s.split(''), function (char: string) { return _.includes(ALPHABET, char) }))
}

Base58.prototype.set = function (this: Base58, obj: { buf?: Buffer }): Base58 {
  this.buf = obj.buf ?? this.buf
  return this
}

/**
 * Encode a buffer to Bsae 58.
 *
 * @param {Buffer} buf Any buffer to be encoded.
 * @returns {string} A Base 58 encoded string.
 */
Base58.encode = function (buf: Buffer): string {
  if (!Buffer.isBuffer(buf)) {
    throw new Error('Input should be a buffer')
  }
  return bs58.encode(buf)
}

/**
 * Decode a Base 58 string to a buffer.
 *
 * @param {string} str A Base 58 encoded string.
 * @returns {Buffer} The decoded buffer.
 */
Base58.decode = function (str: string): Buffer {
  if (typeof str !== 'string') {
    throw new Error('Input should be a string')
  }
  return Buffer.from(bs58.decode(str))
}

Base58.prototype.fromBuffer = function (this: Base58, buf: Buffer): Base58 {
  this.buf = buf
  return this
}

Base58.fromBuffer = function (buf: Buffer): Base58 {
  return new (Base58 as Base58Constructor)().fromBuffer(buf)
}

Base58.fromHex = function (hex: string): Base58 {
  return Base58.fromBuffer(Buffer.from(hex, 'hex'))
}

Base58.prototype.fromString = function (this: Base58, str: string): Base58 {
  const buf = Base58.decode(str)
  this.buf = buf
  return this
}

Base58.fromString = function (str: string): Base58 {
  return new (Base58 as Base58Constructor)().fromString(str)
}

Base58.prototype.toBuffer = function (this: Base58): Buffer {
  return this.buf as Buffer
}

Base58.prototype.toHex = function (this: Base58): string {
  return this.toBuffer().toString('hex')
}

Base58.prototype.toString = function (this: Base58): string {
  return Base58.encode(this.buf as Buffer)
}

export = Base58
