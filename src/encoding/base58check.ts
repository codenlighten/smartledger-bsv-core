'use strict'

import _ = require('../util/_')
import Base58 = require('./base58')
import Hash = require('../crypto/hash')
import type { Base58Check, Base58CheckConstructor } from './types'

const sha256sha256 = Hash.sha256sha256

/**
 * A Base58check object can encode/decodd Base 58, which is used primarily for
 * string-formatted Bitcoin addresses and private keys. This is the same as
 * Base58, except that it includes a checksum to prevent accidental mistypings.
 *
 * @param {object} obj Can be a string or buffer.
 */
const Base58Check = function Base58Check (this: Base58Check, obj?: Buffer | string) {
  if (!(this instanceof Base58Check)) { return new (Base58Check as Base58CheckConstructor)(obj) }
  if (Buffer.isBuffer(obj)) {
    const buf = obj
    this.fromBuffer(buf)
  } else if (typeof obj === 'string') {
    const str = obj
    this.fromString(str)
  }
} as unknown as Base58CheckConstructor

Base58Check.prototype.set = function (this: Base58Check, obj: { buf?: Buffer }): Base58Check {
  this.buf = obj.buf ?? this.buf
  return this
}

Base58Check.validChecksum = function validChecksum (data: Buffer | string, checksum?: Buffer | string): boolean {
  let d: Buffer = _.isString(data) ? Buffer.from(Base58.decode(data)) : data
  let c: Buffer | undefined = _.isString(checksum) ? Buffer.from(Base58.decode(checksum)) : checksum
  if (c == null) {
    c = d.slice(-4)
    d = d.slice(0, -4)
  }
  return Base58Check.checksum(d).toString('hex') === c.toString('hex')
}

Base58Check.decode = function (s: string): Buffer {
  if (typeof s !== 'string') { throw new Error('Input must be a string') }

  const buf = Buffer.from(Base58.decode(s))

  if (buf.length < 4) { throw new Error('Input string too short') }

  const data = buf.slice(0, -4)
  const csum = buf.slice(-4)

  const hash = sha256sha256(data)
  const hash4 = hash.slice(0, 4)

  if (csum.toString('hex') !== hash4.toString('hex')) { throw new Error('Checksum mismatch') }

  return data
}

Base58Check.checksum = function (buffer: Buffer): Buffer {
  return sha256sha256(buffer).slice(0, 4)
}

Base58Check.encode = function (buf: Buffer): string {
  if (!Buffer.isBuffer(buf)) { throw new Error('Input must be a buffer') }
  const checkedBuf = Buffer.alloc(buf.length + 4)
  const hash = Base58Check.checksum(buf)
  buf.copy(checkedBuf)
  hash.copy(checkedBuf, buf.length)
  return Base58.encode(checkedBuf)
}

Base58Check.prototype.fromBuffer = function (this: Base58Check, buf: Buffer): Base58Check {
  this.buf = buf
  return this
}

Base58Check.fromBuffer = function (buf: Buffer): Base58Check {
  return new (Base58Check as Base58CheckConstructor)().fromBuffer(buf)
}

Base58Check.fromHex = function (hex: string): Base58Check {
  return Base58Check.fromBuffer(Buffer.from(hex, 'hex'))
}

Base58Check.prototype.fromString = function (this: Base58Check, str: string): Base58Check {
  const buf = Base58Check.decode(str)
  this.buf = buf
  return this
}

Base58Check.fromString = function (str: string): Base58Check {
  const buf = Base58Check.decode(str)
  // Must be a Base58Check, not a Base58: returning the latter re-encodes without
  // the checksum, so a Base58Check.encode(...) -> fromString -> toString round
  // trip silently produced a different, unchecksummed string (no error).
  return new Base58Check(buf)
}

Base58Check.prototype.toBuffer = function (this: Base58Check): Buffer {
  return this.buf as Buffer
}

Base58Check.prototype.toHex = function (this: Base58Check): string {
  return this.toBuffer().toString('hex')
}

Base58Check.prototype.toString = function (this: Base58Check): string {
  return Base58Check.encode(this.buf as Buffer)
}

export = Base58Check
