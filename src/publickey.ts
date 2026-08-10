'use strict'

import BN = require('./crypto/bn')
import Point = require('./crypto/point')
import Hash = require('./crypto/hash')
import JSUtil = require('./util/js')
import Network = require('./networks')
import _ = require('./util/_')
import $ = require('./util/preconditions')
import type { PublicKey, PublicKeyConstructor, PublicKeyInfo } from './publickey.types'
import type { Point as PointType } from './crypto/point.types'
import type { PrivateKey } from './privatekey.types'

/**
 * Instantiate a PublicKey from a {@link PrivateKey}, {@link Point}, `string`, or `Buffer`.
 *
 * There are two internal properties, `network` and `compressed`, that deal with importing
 * a PublicKey from a PrivateKey in WIF format. More details described on {@link PrivateKey}
 *
 * @example
 * ```javascript
 * // instantiate from a private key
 * var key = PublicKey(privateKey, true);
 *
 * // export to as a DER hex encoded string
 * var exported = key.toString();
 *
 * // import the public key
 * var imported = PublicKey.fromString(exported);
 * ```
 *
 * @param {string} data - The encoded data in various formats
 * @param {Object} extra - additional options
 * @param {Network=} extra.network - Which network should the address for this public key be for
 * @param {String=} extra.compressed - If the public key is compressed
 * @returns {PublicKey} A new valid instance of an PublicKey
 * @constructor
 */
const PublicKey = function PublicKey (this: PublicKey, data: unknown, extra?: Record<string, unknown>) {
  if (!(this instanceof PublicKey)) {
    return new (PublicKey as PublicKeyConstructor)(data, extra)
  }

  $.checkArgument(data, 'First argument is required, please include public key data.')

  if (data instanceof (PublicKey as unknown as new () => unknown)) {
    // Return copy, but as it's an immutable object, return same argument
    return data as PublicKey
  }
  const opts = extra ?? {}

  const info = this._classifyArgs(data, opts)

  // validation
  info.point.validate()

  JSUtil.defineImmutable(this, {
    point: info.point,
    compressed: info.compressed,
    network: info.network || Network.defaultNetwork
  })

  return this
} as unknown as PublicKeyConstructor

/**
 * Internal function to differentiate between arguments passed to the constructor
 * @param {*} data
 * @param {Object} extra
 */
PublicKey.prototype._classifyArgs = function (this: PublicKey, data: unknown, extra: Record<string, unknown>): PublicKeyInfo {
  // `point` is filled in by one of the branches below, so the local starts
  // partial and is asserted complete at the return.
  let info: Partial<PublicKeyInfo> = {
    compressed: _.isUndefined(extra.compressed) || extra.compressed === true
  }

  // detect type of data
  if (data instanceof Point) {
    info.point = data
  } else if ((data as { x?: unknown, y?: unknown })?.x != null && (data as { y?: unknown }).y != null) {
    info = (PublicKey as PublicKeyConstructor)._transformObject(data as { x: string, y: string, compressed?: boolean })
  } else if (typeof (data) === 'string') {
    info = (PublicKey as PublicKeyConstructor)._transformDER(Buffer.from(data, 'hex'))
  } else if ((PublicKey as PublicKeyConstructor)._isBuffer(data)) {
    info = (PublicKey as PublicKeyConstructor)._transformDER(data as Buffer)
  } else if ((PublicKey as PublicKeyConstructor)._isPrivateKey(data)) {
    info = (PublicKey as PublicKeyConstructor)._transformPrivateKey(data as PrivateKey)
  } else {
    throw new TypeError('First argument is an unrecognized data format.')
  }
  if (info.network == null) {
    info.network = _.isUndefined(extra.network)
      ? undefined
      : Network.get(extra.network as string | number)
  }
  return info as PublicKeyInfo
}

/**
 * Internal function to detect if an object is a {@link PrivateKey}
 *
 * @param {*} param - object to test
 * @returns {boolean}
 * @private
 */
PublicKey._isPrivateKey = function (param: unknown): boolean {
  const PrivateKey = require('./privatekey')
  return param instanceof PrivateKey
}

/**
 * Internal function to detect if an object is a Buffer
 *
 * @param {*} param - object to test
 * @returns {boolean}
 * @private
 */
PublicKey._isBuffer = function (param: unknown): boolean {
  return (param instanceof Buffer) || (param instanceof Uint8Array)
}

/**
 * Internal function to transform a private key into a public key point
 *
 * @param {PrivateKey} privkey - An instance of PrivateKey
 * @returns {Object} An object with keys: point and compressed
 * @private
 */
PublicKey._transformPrivateKey = function (privkey: PrivateKey): PublicKeyInfo {
  $.checkArgument((PublicKey as PublicKeyConstructor)._isPrivateKey(privkey), 'Must be an instance of PrivateKey')
  const info: Partial<PublicKeyInfo> = {}
  info.point = Point.getG().mul(privkey.bn)
  info.compressed = privkey.compressed
  info.network = privkey.network
  return info as PublicKeyInfo
}

/**
 * Internal function to transform DER into a public key point
 *
 * @param {Buffer} buf - An DER buffer
 * @param {bool=} strict - if set to false, will loosen some conditions
 * @returns {Object} An object with keys: point and compressed
 * @private
 */
PublicKey._transformDER = function (buf: Buffer, strict?: boolean): PublicKeyInfo {
  $.checkArgument((PublicKey as PublicKeyConstructor)._isBuffer(buf), 'Must be a buffer of DER encoded public key')
  let info: Partial<PublicKeyInfo> = {}

  strict = _.isUndefined(strict) ? true : strict

  let x
  let y
  let xbuf
  let ybuf

  if (buf[0] === 0x04 || (!strict && (buf[0] === 0x06 || buf[0] === 0x07))) {
    xbuf = buf.slice(1, 33)
    ybuf = buf.slice(33, 65)
    if (xbuf.length !== 32 || ybuf.length !== 32 || buf.length !== 65) {
      throw new TypeError('Length of x and y must be 32 bytes')
    }
    x = new BN(xbuf)
    y = new BN(ybuf)
    info.point = new Point(x, y)
    info.compressed = false
  } else if (buf[0] === 0x03) {
    xbuf = buf.slice(1)
    x = new BN(xbuf)
    info = (PublicKey as PublicKeyConstructor)._transformX(true, x)
    info.compressed = true
  } else if (buf[0] === 0x02) {
    xbuf = buf.slice(1)
    x = new BN(xbuf)
    info = (PublicKey as PublicKeyConstructor)._transformX(false, x)
    info.compressed = true
  } else {
    throw new TypeError('Invalid DER format public key')
  }
  return info as PublicKeyInfo
}

/**
 * Internal function to transform X into a public key point
 *
 * @param {Boolean} odd - If the point is above or below the x axis
 * @param {Point} x - The x point
 * @returns {Object} An object with keys: point and compressed
 * @private
 */
PublicKey._transformX = function (odd: boolean, x: BN): PublicKeyInfo {
  $.checkArgument(typeof odd === 'boolean', 'Must specify whether y is odd or not (true or false)')
  const info: Partial<PublicKeyInfo> = {}
  info.point = Point.fromX(odd, x)
  return info as PublicKeyInfo
}

/**
 * Internal function to transform a JSON into a public key point
 *
 * @param {String|Object} json - a JSON string or plain object
 * @returns {Object} An object with keys: point and compressed
 * @private
 */
PublicKey._transformObject = function (json: { x: string, y: string, compressed?: boolean }): PublicKeyInfo {
  const x = new BN(json.x, 'hex')
  const y = new BN(json.y, 'hex')
  const point = new Point(x, y)
  return new (PublicKey as PublicKeyConstructor)(point, {
    compressed: json.compressed
  })
}

/**
 * Instantiate a PublicKey from a PrivateKey
 *
 * @param {PrivateKey} privkey - An instance of PrivateKey
 * @returns {PublicKey} A new valid instance of PublicKey
 */
PublicKey.fromPrivateKey = function (privkey: unknown): PublicKey {
  $.checkArgument((PublicKey as PublicKeyConstructor)._isPrivateKey(privkey), 'Must be an instance of PrivateKey')
  const info = (PublicKey as PublicKeyConstructor)._transformPrivateKey(privkey as PrivateKey)
  return new (PublicKey as PublicKeyConstructor)(info.point, {
    compressed: info.compressed,
    network: info.network
  })
}

/**
 * Instantiate a PublicKey from a Buffer
 * @param {Buffer} buf - A DER buffer
 * @param {bool=} strict - if set to false, will loosen some conditions
 * @returns {PublicKey} A new valid instance of PublicKey
 */
PublicKey.fromDER = PublicKey.fromBuffer = function (buf: Buffer, strict?: boolean): PublicKey {
  $.checkArgument((PublicKey as PublicKeyConstructor)._isBuffer(buf), 'Must be a buffer of DER encoded public key')
  const info = (PublicKey as PublicKeyConstructor)._transformDER(buf, strict)
  return new (PublicKey as PublicKeyConstructor)(info.point, {
    compressed: info.compressed
  })
}

/**
 * Instantiate a PublicKey from a Point
 *
 * @param {Point} point - A Point instance
 * @param {boolean=} compressed - whether to store this public key as compressed format
 * @returns {PublicKey} A new valid instance of PublicKey
 */
PublicKey.fromPoint = function (point: PointType, compressed?: boolean): PublicKey {
  $.checkArgument(point instanceof Point, 'First argument must be an instance of Point.')
  return new (PublicKey as PublicKeyConstructor)(point, {
    compressed
  })
}

/**
 * Instantiate a PublicKey from a DER hex encoded string
 *
 * @param {string} str - A DER hex string
 * @param {String=} encoding - The type of string encoding
 * @returns {PublicKey} A new valid instance of PublicKey
 */
PublicKey.fromHex = PublicKey.fromString = function (str: string, encoding?: BufferEncoding): PublicKey {
  const buf = Buffer.from(str, encoding || 'hex')
  const info = (PublicKey as PublicKeyConstructor)._transformDER(buf)
  return new (PublicKey as PublicKeyConstructor)(info.point, {
    compressed: info.compressed
  })
}

/**
 * Instantiate a PublicKey from an X Point
 *
 * @param {Boolean} odd - If the point is above or below the x axis
 * @param {Point} x - The x point
 * @returns {PublicKey} A new valid instance of PublicKey
 */
PublicKey.fromX = function (odd: boolean, x: BN): PublicKey {
  const info = (PublicKey as PublicKeyConstructor)._transformX(odd, x)
  return new (PublicKey as PublicKeyConstructor)(info.point, {
    compressed: info.compressed
  })
}

/**
 * Check if there would be any errors when initializing a PublicKey
 *
 * @param {string} data - The encoded data in various formats
 * @returns {null|Error} An error if exists
 */
PublicKey.getValidationError = function (data: unknown): Error | undefined {
  let error
  try {
    new PublicKey(data) // eslint-disable-line
  } catch (e) {
    error = e as Error
  }
  return error
}

/**
 * Check if the parameters are valid
 *
 * @param {string} data - The encoded data in various formats
 * @returns {Boolean} If the public key would be valid
 */
PublicKey.isValid = function (data: unknown): boolean {
  return !PublicKey.getValidationError(data)
}

/**
 * @returns {Object} A plain object of the PublicKey
 */
PublicKey.prototype.toObject = PublicKey.prototype.toJSON = function toObject (this: PublicKey) {
  return {
    x: this.point.getX().toString('hex', 2),
    y: this.point.getY().toString('hex', 2),
    compressed: this.compressed
  }
}

/**
 * Will output the PublicKey to a DER Buffer
 *
 * @returns {Buffer} A DER hex encoded buffer
 */
PublicKey.prototype.toBuffer = PublicKey.prototype.toDER = function (this: PublicKey): Buffer {
  const x = this.point.getX()
  const y = this.point.getY()

  const xbuf = x.toBuffer({
    size: 32
  })
  const ybuf = y.toBuffer({
    size: 32
  })

  let prefix
  if (!this.compressed) {
    prefix = Buffer.from([0x04])
    return Buffer.concat([prefix, xbuf, ybuf])
  } else {
    // ybuf is a fixed 32-byte buffer, so the last byte is always present.
    const odd = (ybuf[ybuf.length - 1] as number) % 2
    if (odd !== 0) {
      prefix = Buffer.from([0x03])
    } else {
      prefix = Buffer.from([0x02])
    }
    return Buffer.concat([prefix, xbuf])
  }
}

/**
 * Will return a sha256 + ripemd160 hash of the serialized public key
 * @see https://github.com/bitcoin/bitcoin/blob/master/src/pubkey.h#L141
 * @returns {Buffer}
 */
PublicKey.prototype._getID = function _getID (this: PublicKey): Buffer {
  return Hash.sha256ripemd160(this.toBuffer())
}

/**
 * Will return an address for the public key
 *
 * @param {String|Network=} network - Which network should the address be for
 * @returns {Address} An address generated from the public key
 */
PublicKey.prototype.toAddress = function (this: PublicKey, network?: unknown): unknown {
  const Address = require('./address')
  return Address.fromPublicKey(this, network || this.network)
}

/**
 * Will output the PublicKey to a DER encoded hex string
 *
 * @returns {string} A DER hex encoded string
 */
PublicKey.prototype.toString = PublicKey.prototype.toHex = function (this: PublicKey): string {
  return this.toDER().toString('hex')
}

/**
 * Will return a string formatted for the console
 *
 * @returns {string} Public key
 */
PublicKey.prototype.inspect = function (this: PublicKey): string {
  return '<PublicKey: ' + this.toHex() +
    (this.compressed ? '' : ', uncompressed') + '>'
}

export = PublicKey
