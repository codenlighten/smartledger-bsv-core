'use strict'

import BN = require('bn.js')
import $ = require('../util/preconditions')
import _ = require('../util/_')

/**
 * Bitcoin-specific extensions to bn.js, installed onto the class in place.
 *
 * The full shape this library exposes — native subset plus these additions,
 * and the replaced `toBuffer` — is declared in src/types/bn.js.d.ts. It lives
 * there rather than as a module augmentation here because bn.js is declared
 * with `export =`, which TypeScript treats as a non-module entity and refuses
 * to augment.
 */
type BNBufferOpts = BN.BufferOpts

const reversebuf = function (buf: Buffer): Buffer {
  const buf2 = Buffer.alloc(buf.length)
  for (let i = 0; i < buf.length; i++) {
    buf2[i] = buf[buf.length - 1 - i] as number
  }
  return buf2
}

BN.Zero = new BN(0)
BN.One = new BN(1)
BN.Minus1 = new BN(-1)

/**
 * Convert a number into a big number.
 *
 * @param {number} n Any positive or negative integer.
 */
BN.fromNumber = function (n: number): BN {
  $.checkArgument(_.isNumber(n))
  return new BN(n)
}

/**
 * Convert a string number into a big number.
 *
 * @param {string} str Any positive or negative integer formatted as a string.
 * @param {number} base The base of the number, defaults to 10.
 */
BN.fromString = function (str: string, base?: number): BN {
  $.checkArgument(_.isString(str))
  return new BN(str, base)
}

/**
 * Convert a buffer (such as a 256 bit binary private key) into a big number.
 * Sometimes these numbers can be formatted either as 'big endian' or 'little
 * endian', and so there is an opts parameter that lets you specify which
 * endianness is specified.
 *
 * @param {Buffer} buf A buffer number, such as a 256 bit hash or key.
 * @param {Object} opts With a property 'endian' that can be either 'big' or 'little'. Defaults big endian (most significant digit first).
 */
BN.fromBuffer = function (buf: Buffer, opts?: BNBufferOpts): BN {
  if (typeof opts !== 'undefined' && opts.endian === 'little') {
    buf = reversebuf(buf)
  }
  const hex = buf.toString('hex')
  const bn = new BN(hex, 16)
  return bn
}

/**
 * Instantiate a BigNumber from a "signed magnitude buffer". (a buffer where the
 * most significant bit represents the sign (0 = positive, 1 = negative)
 *
 * @param {Buffer} buf A buffer number, such as a 256 bit hash or key.
 * @param {Object} opts With a property 'endian' that can be either 'big' or 'little'. Defaults big endian (most significant digit first).
 */
BN.fromSM = function (buf: Buffer, opts?: { endian?: 'big' | 'little' }): BN {
  let ret
  if (buf.length === 0) {
    return BN.fromBuffer(Buffer.from([0]))
  }

  let endian: 'big' | 'little' = 'big'
  if (opts?.endian != null) {
    endian = opts.endian
  }
  if (endian === 'little') {
    buf = reversebuf(buf)
  }

  if (((buf[0] as number) & 0x80) !== 0) {
    buf[0] = (buf[0] as number) & 0x7f
    ret = BN.fromBuffer(buf)
    ret.neg().copy(ret)
  } else {
    ret = BN.fromBuffer(buf)
  }
  return ret
}

/**
 * Convert a big number into a number.
 */
BN.prototype.toNumber = function (this: BN): number {
  return parseInt(this.toString(10), 10)
}

/**
 * Convert a big number into a buffer. This is somewhat ambiguous, so there is
 * an opts parameter that let's you specify the endianness or the size.
 * opts.endian can be either 'big' or 'little' and opts.size can be any
 * sufficiently large number of bytes. If you always want to create a 32 byte
 * big endian number, then specify opts = { endian: 'big', size: 32 }
 *
 * @param {Object} opts Defaults to { endian: 'big', size: 32 }
 */
BN.prototype.toBuffer = function (this: BN, opts?: BNBufferOpts): Buffer {
  let buf: Buffer
  let hex: string
  if (opts && opts.size) {
    hex = this.toString(16, 2)
    const natlen = hex.length / 2
    buf = Buffer.from(hex, 'hex')

    if (natlen === opts.size) {
      // buf = buf
    } else if (natlen > opts.size) {
      buf = BN.trim(buf, natlen)
    } else if (natlen < opts.size) {
      buf = BN.pad(buf, natlen, opts.size)
    }
  } else {
    hex = this.toString(16, 2)
    buf = Buffer.from(hex, 'hex')
  }

  if (typeof opts !== 'undefined' && opts.endian === 'little') {
    buf = reversebuf(buf)
  }

  return buf
}

/**
 * For big numbers that are either positive or negative, you can convert to
 * "sign magnitude" format whereby the first bit specifies whether the number is
 * positive or negative.
 */
BN.prototype.toSMBigEndian = function (this: BN): Buffer {
  let buf
  if (this.cmp(BN.Zero) === -1) {
    buf = this.neg().toBuffer()
    if (((buf[0] as number) & 0x80) !== 0) {
      buf = Buffer.concat([Buffer.from([0x80]), buf])
    } else {
      buf[0] = (buf[0] as number) | 0x80
    }
  } else {
    buf = this.toBuffer()
    if (((buf[0] as number) & 0x80) !== 0) {
      buf = Buffer.concat([Buffer.from([0x00]), buf])
    }
  }

  if (buf.length === 1 && buf[0] === 0) {
    buf = Buffer.from([])
  }
  return buf
}

/**
 * For big numbers that are either positive or negative, you can convert to
 * "sign magnitude" format whereby the first bit specifies whether the number is
 * positive or negative.
 *
 * @param {Object} opts Defaults to { endian: 'big' }
 */
BN.prototype.toSM = function (this: BN, opts?: { endian?: 'big' | 'little' }): Buffer {
  const endian = opts ? opts.endian : 'big'
  let buf = this.toSMBigEndian()

  if (endian === 'little') {
    buf = reversebuf(buf)
  }
  return buf
}

/**
 * Create a BN from a "ScriptNum": This is analogous to the constructor for
 * CScriptNum in bitcoind. Many ops in bitcoind's script interpreter use
 * CScriptNum, which is not really a proper bignum. Instead, an error is thrown
 * if trying to input a number bigger than 4 bytes. We copy that behavior here.
 * A third argument, `size`, is provided to extend the hard limit of 4 bytes, as
 * some usages require more than 4 bytes.
 *
 * @param {Buffer} buf A buffer of a number.
 * @param {boolean} fRequireMinimal Whether to require minimal size encoding.
 * @param {number} size The maximum size.
 */
BN.fromScriptNumBuffer = function (buf: Buffer, fRequireMinimal?: boolean, size?: number): BN {
  const nMaxNumSize = size || 4
  $.checkArgument(buf.length <= nMaxNumSize, new Error('script number overflow'))
  if (fRequireMinimal && buf.length > 0) {
    // Check that the number is encoded with the minimum possible
    // number of bytes.
    //
    // If the most-significant-byte - excluding the sign bit - is zero
    // then we're not minimal. Note how this test also rejects the
    // negative-zero encoding, 0x80.
    if (((buf[buf.length - 1] as number) & 0x7f) === 0) {
      // One exception: if there's more than one byte and the most
      // significant bit of the second-most-significant-byte is set
      // it would conflict with the sign bit. An example of this case
      // is +-255, which encode to 0xff00 and 0xff80 respectively.
      // (big-endian).
      if (buf.length <= 1 || ((buf[buf.length - 2] as number) & 0x80) === 0) {
        throw new Error('non-minimally encoded script number')
      }
    }
  }
  return BN.fromSM(buf, {
    endian: 'little'
  })
}

/**
 * The corollary to the above, with the notable exception that we do not throw
 * an error if the output is larger than four bytes. (Which can happen if
 * performing a numerical operation that results in an overflow to more than 4
 * bytes).
 */
BN.prototype.toScriptNumBuffer = function (this: BN): Buffer {
  return this.toSM({
    endian: 'little'
  })
}

/**
 * Trims a buffer if it starts with zeros.
 *
 * @param {Buffer} buf A buffer formatted number.
 * @param {number} natlen The natural length of the number.
 */
BN.trim = function (buf: Buffer, natlen: number): Buffer {
  return buf.slice(natlen - buf.length, buf.length)
}

/**
 * Adds extra zeros to the start of a number.
 *
 * @param {Buffer} buf A buffer formatted number.
 * @param {number} natlen The natural length of the number.
 * @param {number} size How big to pad the number in bytes.
 */
BN.pad = function (buf: Buffer, natlen: number, size: number): Buffer {
  const rbuf = Buffer.alloc(size)
  for (var i = 0; i < buf.length; i++) {
    rbuf[rbuf.length - 1 - i] = buf[buf.length - 1 - i] as number
  }
  for (i = 0; i < size - natlen; i++) {
    rbuf[i] = 0
  }
  return rbuf
}
/**
 * Convert a big number into a hex string. This is somewhat ambiguous, so there
 * is an opts parameter that let's you specify the endianness or the size.
 * opts.endian can be either 'big' or 'little' and opts.size can be any
 * sufficiently large number of bytes. If you always want to create a 32 byte
 * big endian number, then specify opts = { endian: 'big', size: 32 }
 *
 * @param {Object} opts Defaults to { endian: 'big', size: 32 }
 */
BN.prototype.toHex = function (this: BN, ...args: [BNBufferOpts?]): string {
  return this.toBuffer(...args).toString('hex')
}

/**
 * Convert a hex string (such as a 256 bit binary private key) into a big
 * number. Sometimes these numbers can be formatted either as 'big endian' or
 * 'little endian', and so there is an opts parameter that lets you specify
 * which endianness is specified.
 *
 * @param {Buffer} buf A buffer number, such as a 256 bit hash or key.
 * @param {Object} opts With a property 'endian' that can be either 'big' or 'little'. Defaults big endian (most significant digit first).
 */
BN.fromHex = function (hex: string, ...args: [BNBufferOpts?]): BN {
  return BN.fromBuffer(Buffer.from(hex, 'hex'), ...args)
}

export = BN
