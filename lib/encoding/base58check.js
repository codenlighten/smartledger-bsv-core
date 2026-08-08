'use strict'

const _ = require('../util/_')
const Base58 = require('./base58')
const buffer = require('buffer')
const sha256sha256 = require('../crypto/hash').sha256sha256

/**
 * A Base58check object can encode/decodd Base 58, which is used primarily for
 * string-formatted Bitcoin addresses and private keys. This is the same as
 * Base58, except that it includes a checksum to prevent accidental mistypings.
 *
 * @param {object} obj Can be a string or buffer.
 */
const Base58Check = function Base58Check (obj) {
  if (!(this instanceof Base58Check)) { return new Base58Check(obj) }
  if (Buffer.isBuffer(obj)) {
    const buf = obj
    this.fromBuffer(buf)
  } else if (typeof obj === 'string') {
    const str = obj
    this.fromString(str)
  }
}

Base58Check.prototype.set = function (obj) {
  this.buf = obj.buf || this.buf || undefined
  return this
}

Base58Check.validChecksum = function validChecksum (data, checksum) {
  if (_.isString(data)) {
    data = buffer.Buffer.from(Base58.decode(data))
  }
  if (_.isString(checksum)) {
    checksum = buffer.Buffer.from(Base58.decode(checksum))
  }
  if (!checksum) {
    checksum = data.slice(-4)
    data = data.slice(0, -4)
  }
  return Base58Check.checksum(data).toString('hex') === checksum.toString('hex')
}

Base58Check.decode = function (s) {
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

Base58Check.checksum = function (buffer) {
  return sha256sha256(buffer).slice(0, 4)
}

Base58Check.encode = function (buf) {
  if (!Buffer.isBuffer(buf)) { throw new Error('Input must be a buffer') }
  const checkedBuf = Buffer.alloc(buf.length + 4)
  const hash = Base58Check.checksum(buf)
  buf.copy(checkedBuf)
  hash.copy(checkedBuf, buf.length)
  return Base58.encode(checkedBuf)
}

Base58Check.prototype.fromBuffer = function (buf) {
  this.buf = buf
  return this
}

Base58Check.fromBuffer = function (buf) {
  return new Base58Check().fromBuffer(buf)
}

Base58Check.fromHex = function (hex) {
  return Base58Check.fromBuffer(Buffer.from(hex, 'hex'))
}

Base58Check.prototype.fromString = function (str) {
  const buf = Base58Check.decode(str)
  this.buf = buf
  return this
}

Base58Check.fromString = function (str) {
  const buf = Base58Check.decode(str)
  // Must be a Base58Check, not a Base58: returning the latter re-encodes without
  // the checksum, so a Base58Check.encode(...) -> fromString -> toString round
  // trip silently produced a different, unchecksummed string (no error).
  return new Base58Check(buf)
}

Base58Check.prototype.toBuffer = function () {
  return this.buf
}

Base58Check.prototype.toHex = function () {
  return this.toBuffer().toString('hex')
}

Base58Check.prototype.toString = function () {
  return Base58Check.encode(this.buf)
}

module.exports = Base58Check
