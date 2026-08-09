'use strict'

import type { HDPublicKey, HDPublicKeyConstructor, HDPublicBuffers } from './hdpublickey.types'

import _ = require('./util/_')
import $ = require('./util/preconditions')

import BN = require('./crypto/bn')
import Base58 = require('./encoding/base58')
import Base58Check = require('./encoding/base58check')
import Hash = require('./crypto/hash')
import Network = require('./networks')
import Point = require('./crypto/point')
import PublicKey = require('./publickey')

import bsvErrors = require('./errors')
const errors = bsvErrors
const hdErrors = bsvErrors.HDPublicKey
import assert = require('assert')

import JSUtil = require('./util/js')

// The error tree is built dynamically; members arrive via an index signature.
type ErrCtor = new (...args: unknown[]) => Error
const err = (path: string): ErrCtor =>
  path.split('.').reduce<any>((o, k) => o[k], errors) as ErrCtor


// Lazy: hdprivatekey requires this module back. Every use below is inside a
// function, so deferring the read to call time costs nothing and keeps the
// binding out of its temporal dead zone under ESM.
const HDPrivateKey = () => require('./hdprivatekey')

/**
 * The representation of an hierarchically derived public key.
 *
 * See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 *
 * @constructor
 * @param {Object|string|Buffer} arg
 */
const HDPublicKey = function HDPublicKey (this: HDPublicKey, arg?: any): any {
  if (arg instanceof HDPublicKey) {
    return arg
  }
  if (!(this instanceof HDPublicKey)) {
    return new (HDPublicKey as unknown as HDPublicKeyConstructor)(arg)
  }
  if (arg) {
    if (_.isString(arg) || Buffer.isBuffer(arg)) {
      const error = (HDPublicKey as unknown as HDPublicKeyConstructor).getSerializedError(arg)
      if (!error) {
        return this._buildFromSerialized(arg)
      } else if (Buffer.isBuffer(arg) && !(HDPublicKey as unknown as HDPublicKeyConstructor).getSerializedError(arg.toString())) {
        return this._buildFromSerialized(arg.toString())
      } else {
        if (error instanceof err('HDPublicKey.ArgumentIsPrivateExtended')) {
          return new (HDPrivateKey())(arg).hdPublicKey
        }
        throw error
      }
    } else {
      if (_.isObject(arg)) {
        if (arg instanceof HDPrivateKey()) {
          return this._buildFromPrivate(arg)
        } else {
          return this._buildFromObject(arg)
        }
      } else {
        throw new (err('HDPublicKey.UnrecognizedArgument'))(arg)
      }
    }
  } else {
    throw new (err('HDPublicKey.MustSupplyArgument'))()
  }
} as unknown as HDPublicKeyConstructor

HDPublicKey.fromHDPrivateKey = function (hdPrivateKey: any) {
  return new HDPublicKey(hdPrivateKey)
}

/**
 * Verifies that a given path is valid.
 *
 * @param {string|number} arg
 * @return {boolean}
 */
HDPublicKey.isValidPath = function (arg: any) {
  if (_.isString(arg)) {
    const indexes = HDPrivateKey()._getDerivationIndexes(arg)
    return indexes !== null && _.every(indexes, HDPublicKey.isValidPath)
  }

  if (_.isNumber(arg)) {
    return arg >= 0 && arg < HDPublicKey.Hardened
  }

  return false
}

/**
 * WARNING: This method is deprecated. Use deriveChild instead.
 *
 *
 * Get a derivated child based on a string or number.
 *
 * If the first argument is a string, it's parsed as the full path of
 * derivation. Valid values for this argument include "m" (which returns the
 * same public key), "m/0/1/40/2/1000".
 *
 * Note that hardened keys can't be derived from a public extended key.
 *
 * If the first argument is a number, the child with that index will be
 * derived. See the example usage for clarification.
 *
 * @example
 * ```javascript
 * var parent = new HDPublicKey('xpub...');
 * var child_0_1_2 = parent.derive(0).derive(1).derive(2);
 * var copy_of_child_0_1_2 = parent.derive("m/0/1/2");
 * assert(child_0_1_2.xprivkey === copy_of_child_0_1_2);
 * ```
 *
 * @param {string|number} arg
 */
HDPublicKey.prototype.derive = function (this: HDPublicKey) {
  throw new Error('derive has been deprecated. use deriveChild or, for the old way, deriveNonCompliantChild.')
}

/**
 * WARNING: This method will not be officially supported until v1.0.0.
 *
 *
 * Get a derivated child based on a string or number.
 *
 * If the first argument is a string, it's parsed as the full path of
 * derivation. Valid values for this argument include "m" (which returns the
 * same public key), "m/0/1/40/2/1000".
 *
 * Note that hardened keys can't be derived from a public extended key.
 *
 * If the first argument is a number, the child with that index will be
 * derived. See the example usage for clarification.
 *
 * @example
 * ```javascript
 * var parent = new HDPublicKey('xpub...');
 * var child_0_1_2 = parent.deriveChild(0).deriveChild(1).deriveChild(2);
 * var copy_of_child_0_1_2 = parent.deriveChild("m/0/1/2");
 * assert(child_0_1_2.xprivkey === copy_of_child_0_1_2);
 * ```
 *
 * @param {string|number} arg
 */
HDPublicKey.prototype.deriveChild = function (this: HDPublicKey, arg: any, hardened: any) {
  if (_.isNumber(arg)) {
    return this._deriveWithNumber(arg, hardened)
  } else if (_.isString(arg)) {
    return this._deriveFromString(arg)
  } else {
    throw new (err('HDPublicKey.InvalidDerivationArgument'))(arg)
  }
}

HDPublicKey.prototype._deriveWithNumber = function (this: HDPublicKey, index: any, hardened: any) {
  if (index >= HDPublicKey.Hardened || hardened) {
    throw new (err('HDPublicKey.InvalidIndexCantDeriveHardened'))()
  }
  if (index < 0) {
    throw new (err('HDPublicKey.InvalidPath'))(index)
  }

  const indexBuffer = JSUtil.integerAsBuffer(index)
  const data = Buffer.concat([this.publicKey.toBuffer(), indexBuffer])
  const hash = Hash.sha512hmac(data, this._buffers.chainCode)
  const leftPart = BN.fromBuffer(hash.slice(0, 32), { size: 32 })
  const chainCode = hash.slice(32, 64)

  let publicKey
  try {
    publicKey = PublicKey.fromPoint(Point.getG().mul(leftPart).add(this.publicKey.point))
  } catch (e) {
    return this._deriveWithNumber(index + 1)
  }

  const derived = new HDPublicKey({
    network: this.network,
    depth: this.depth + 1,
    parentFingerPrint: this.fingerPrint,
    childIndex: index,
    chainCode,
    publicKey
  })

  return derived
}

HDPublicKey.prototype._deriveFromString = function (this: HDPublicKey, path: any) {
  if (_.includes(path, "'")) {
    throw new (err('HDPublicKey.InvalidIndexCantDeriveHardened'))()
  } else if (!HDPublicKey.isValidPath(path)) {
    throw new (err('HDPublicKey.InvalidPath'))(path)
  }

  const indexes = HDPrivateKey()._getDerivationIndexes(path)
  const derived = indexes!.reduce(function (prev: any, index: any) {
    return prev._deriveWithNumber(index)
  }, this)

  return derived
}

/**
 * Verifies that a given serialized public key in base58 with checksum format
 * is valid.
 *
 * @param {string|Buffer} data - the serialized public key
 * @param {string|Network=} network - optional, if present, checks that the
 *     network provided matches the network serialized.
 * @return {boolean}
 */
HDPublicKey.isValidSerialized = function (data: any, network: any) {
  return _.isNull(HDPublicKey.getSerializedError(data, network))
}

/**
 * Checks what's the error that causes the validation of a serialized public key
 * in base58 with checksum to fail.
 *
 * @param {string|Buffer} data - the serialized public key
 * @param {string|Network=} network - optional, if present, checks that the
 *     network provided matches the network serialized.
 * @return {errors|null}
 */
HDPublicKey.getSerializedError = function (data: any, network: any) {
  if (!(_.isString(data) || Buffer.isBuffer(data))) {
    return new (err('HDPublicKey.UnrecognizedArgument'))('expected buffer or string')
  }
  if (!Base58.validCharacters(data)) {
    return new (err('InvalidB58Char'))('(unknown)', data)
  }
  try {
    data = Base58Check.decode(data as string)
  } catch (e) {
    return new (err('InvalidB58Checksum'))(data)
  }
  if (data.length !== HDPublicKey.DataSize) {
    return new (err('HDPublicKey.InvalidLength'))(data)
  }
  if (!_.isUndefined(network)) {
    const error = HDPublicKey._validateNetwork(data, network)
    if (error) {
      return error
    }
  }
  const version = data.readUInt32BE(0)
  if (version === Network.livenet.xprivkey || version === Network.testnet.xprivkey) {
    return new (err('HDPublicKey.ArgumentIsPrivateExtended'))()
  }
  return null
}

HDPublicKey._validateNetwork = function (data: any, networkArg: any) {
  const network = Network.get(networkArg)
  if (!network) {
    return new (err('InvalidNetworkArgument'))(networkArg)
  }
  const version = data.slice(HDPublicKey.VersionStart, HDPublicKey.VersionEnd)
  if (version.readUInt32BE(0) !== network.xpubkey) {
    return new (err('InvalidNetwork'))(version)
  }
  return null
}

HDPublicKey.prototype._buildFromPrivate = function (this: HDPublicKey, arg: any) {
  const args = _.clone(arg._buffers)
  const point = Point.getG().mul(BN.fromBuffer(args.privateKey))
  args.publicKey = Point.pointToCompressed(point)
  args.version = JSUtil.integerAsBuffer(Network.get(args.version.readUInt32BE(0))!.xpubkey)
  args.privateKey = undefined
  args.checksum = undefined
  args.xprivkey = undefined
  return this._buildFromBuffers(args)
}

HDPublicKey.prototype._buildFromObject = function (this: HDPublicKey, arg: any) {
  // TODO: Type validation
  const buffers = {
    version: arg.network ? JSUtil.integerAsBuffer(Network.get(arg.network)!.xpubkey) : arg.version,
    depth: _.isNumber(arg.depth) ? Buffer.from([arg.depth & 0xff]) : arg.depth,
    parentFingerPrint: _.isNumber(arg.parentFingerPrint) ? JSUtil.integerAsBuffer(arg.parentFingerPrint) : arg.parentFingerPrint,
    childIndex: _.isNumber(arg.childIndex) ? JSUtil.integerAsBuffer(arg.childIndex) : arg.childIndex,
    chainCode: _.isString(arg.chainCode) ? Buffer.from(arg.chainCode, 'hex') : arg.chainCode,
    publicKey: _.isString(arg.publicKey)
      ? Buffer.from(arg.publicKey, 'hex')
      : Buffer.isBuffer(arg.publicKey) ? arg.publicKey : arg.publicKey.toBuffer(),
    checksum: _.isNumber(arg.checksum) ? JSUtil.integerAsBuffer(arg.checksum) : arg.checksum
  }
  return this._buildFromBuffers(buffers)
}

HDPublicKey.prototype._buildFromSerialized = function (this: HDPublicKey, arg: any) {
  const decoded = Base58Check.decode(arg)
  const buffers = {
    version: decoded.slice(HDPublicKey.VersionStart, HDPublicKey.VersionEnd),
    depth: decoded.slice(HDPublicKey.DepthStart, HDPublicKey.DepthEnd),
    parentFingerPrint: decoded.slice(HDPublicKey.ParentFingerPrintStart,
      HDPublicKey.ParentFingerPrintEnd),
    childIndex: decoded.slice(HDPublicKey.ChildIndexStart, HDPublicKey.ChildIndexEnd),
    chainCode: decoded.slice(HDPublicKey.ChainCodeStart, HDPublicKey.ChainCodeEnd),
    publicKey: decoded.slice(HDPublicKey.PublicKeyStart, HDPublicKey.PublicKeyEnd),
    checksum: decoded.slice(HDPublicKey.ChecksumStart, HDPublicKey.ChecksumEnd),
    xpubkey: arg
  }
  return this._buildFromBuffers(buffers)
}

/**
 * Receives a object with buffers in all the properties and populates the
 * internal structure
 *
 * @param {Object} arg
 * @param {buffer.Buffer} arg.version
 * @param {buffer.Buffer} arg.depth
 * @param {buffer.Buffer} arg.parentFingerPrint
 * @param {buffer.Buffer} arg.childIndex
 * @param {buffer.Buffer} arg.chainCode
 * @param {buffer.Buffer} arg.publicKey
 * @param {buffer.Buffer} arg.checksum
 * @param {string=} arg.xpubkey - if set, don't recalculate the base58
 *      representation
 * @return {HDPublicKey} this
 */
HDPublicKey.prototype._buildFromBuffers = function (this: HDPublicKey, arg: any) {
  HDPublicKey._validateBufferArguments(arg)

  JSUtil.defineImmutable(this, {
    _buffers: arg
  })

  const sequence = [
    arg.version, arg.depth, arg.parentFingerPrint, arg.childIndex, arg.chainCode,
    arg.publicKey
  ]
  const concat = Buffer.concat(sequence)
  const checksum = Base58Check.checksum(concat)
  if (!arg.checksum || !arg.checksum.length) {
    arg.checksum = checksum
  } else {
    if (arg.checksum.toString('hex') !== checksum.toString('hex')) {
      throw new (err('InvalidB58Checksum'))(concat, checksum)
    }
  }
  const network = Network.get(arg.version.readUInt32BE(0))

  let xpubkey
  xpubkey = Base58Check.encode(Buffer.concat(sequence))
  arg.xpubkey = Buffer.from(xpubkey)

  const publicKey = new PublicKey(arg.publicKey, { network })
  const size = HDPublicKey.ParentFingerPrintSize
  const fingerPrint = Hash.sha256ripemd160(publicKey.toBuffer()).slice(0, size)

  JSUtil.defineImmutable(this, {
    xpubkey,
    network,
    depth: arg.depth[0],
    publicKey,
    fingerPrint
  })

  return this
}

HDPublicKey._validateBufferArguments = function (arg: any) {
  const checkBuffer = function (name: any, size: any) {
    const buff = arg[name]
    assert(Buffer.isBuffer(buff), name + ' argument is not a buffer, it\'s ' + typeof buff)
    assert(
      buff.length === size,
      name + ' has not the expected size: found ' + buff.length + ', expected ' + size
    )
  }
  checkBuffer('version', HDPublicKey.VersionSize)
  checkBuffer('depth', HDPublicKey.DepthSize)
  checkBuffer('parentFingerPrint', HDPublicKey.ParentFingerPrintSize)
  checkBuffer('childIndex', HDPublicKey.ChildIndexSize)
  checkBuffer('chainCode', HDPublicKey.ChainCodeSize)
  checkBuffer('publicKey', HDPublicKey.PublicKeySize)
  if (arg.checksum && arg.checksum.length) {
    checkBuffer('checksum', HDPublicKey.CheckSumSize)
  }
}

HDPublicKey.fromString = function (arg: any) {
  $.checkArgument(_.isString(arg), 'No valid string was provided')
  return new HDPublicKey(arg)
}

HDPublicKey.fromObject = function (arg: any) {
  $.checkArgument(_.isObject(arg), 'No valid argument was provided')
  return new HDPublicKey(arg)
}

/**
 * Returns the base58 checked representation of the public key
 * @return {string} a string starting with "xpub..." in livenet
 */
HDPublicKey.prototype.toString = function (this: HDPublicKey) {
  return this.xpubkey
}

/**
 * Returns the console representation of this extended public key.
 * @return string
 */
HDPublicKey.prototype.inspect = function (this: HDPublicKey) {
  return '<HDPublicKey: ' + this.xpubkey + '>'
}

/**
 * Returns a plain JavaScript object with information to reconstruct a key.
 *
 * Fields are: <ul>
 *  <li> network: 'livenet' or 'testnet'
 *  <li> depth: a number from 0 to 255, the depth to the master extended key
 *  <li> fingerPrint: a number of 32 bits taken from the hash of the public key
 *  <li> fingerPrint: a number of 32 bits taken from the hash of this key's
 *  <li>     parent's public key
 *  <li> childIndex: index with which this key was derived
 *  <li> chainCode: string in hexa encoding used for derivation
 *  <li> publicKey: string, hexa encoded, in compressed key format
 *  <li> checksum: this._buffers.checksum!.readUInt32BE(0),
 *  <li> xpubkey: the string with the base58 representation of this extended key
 *  <li> checksum: the base58 checksum of xpubkey
 * </ul>
 */
HDPublicKey.prototype.toObject = HDPublicKey.prototype.toJSON = function toObject (this: HDPublicKey) {
  return {
    network: Network.get(this._buffers.version.readUInt32BE(0))!.name,
    depth: this._buffers.depth[0],
    fingerPrint: this.fingerPrint.readUInt32BE(0),
    parentFingerPrint: this._buffers.parentFingerPrint.readUInt32BE(0),
    childIndex: this._buffers.childIndex.readUInt32BE(0),
    chainCode: this._buffers.chainCode.toString('hex'),
    publicKey: this.publicKey.toString(),
    checksum: this._buffers.checksum!.readUInt32BE(0),
    xpubkey: this.xpubkey
  }
}

/**
 * Create a HDPublicKey from a buffer argument
 *
 * @param {Buffer} arg
 * @return {HDPublicKey}
 */
HDPublicKey.fromBuffer = function (arg: any) {
  return new HDPublicKey(arg)
}

/**
 * Create a HDPublicKey from a hex string argument
 *
 * @param {Buffer} arg
 * @return {HDPublicKey}
 */
HDPublicKey.fromHex = function (hex: any) {
  return HDPublicKey.fromBuffer(Buffer.from(hex, 'hex'))
}

/**
 * Return a buffer representation of the xpubkey
 *
 * @return {Buffer}
 */
HDPublicKey.prototype.toBuffer = function (this: HDPublicKey) {
  return Buffer.from(this._buffers.xpubkey!)
}

/**
 * Return a hex string representation of the xpubkey
 *
 * @return {Buffer}
 */
HDPublicKey.prototype.toHex = function (this: HDPublicKey) {
  return this.toBuffer().toString('hex')
}

HDPublicKey.Hardened = 0x80000000
HDPublicKey.RootElementAlias = ['m', 'M']

HDPublicKey.VersionSize = 4
HDPublicKey.DepthSize = 1
HDPublicKey.ParentFingerPrintSize = 4
HDPublicKey.ChildIndexSize = 4
HDPublicKey.ChainCodeSize = 32
HDPublicKey.PublicKeySize = 33
HDPublicKey.CheckSumSize = 4

HDPublicKey.DataSize = 78
HDPublicKey.SerializedByteSize = 82

HDPublicKey.VersionStart = 0
HDPublicKey.VersionEnd = HDPublicKey.VersionStart + HDPublicKey.VersionSize
HDPublicKey.DepthStart = HDPublicKey.VersionEnd
HDPublicKey.DepthEnd = HDPublicKey.DepthStart + HDPublicKey.DepthSize
HDPublicKey.ParentFingerPrintStart = HDPublicKey.DepthEnd
HDPublicKey.ParentFingerPrintEnd = HDPublicKey.ParentFingerPrintStart + HDPublicKey.ParentFingerPrintSize
HDPublicKey.ChildIndexStart = HDPublicKey.ParentFingerPrintEnd
HDPublicKey.ChildIndexEnd = HDPublicKey.ChildIndexStart + HDPublicKey.ChildIndexSize
HDPublicKey.ChainCodeStart = HDPublicKey.ChildIndexEnd
HDPublicKey.ChainCodeEnd = HDPublicKey.ChainCodeStart + HDPublicKey.ChainCodeSize
HDPublicKey.PublicKeyStart = HDPublicKey.ChainCodeEnd
HDPublicKey.PublicKeyEnd = HDPublicKey.PublicKeyStart + HDPublicKey.PublicKeySize
HDPublicKey.ChecksumStart = HDPublicKey.PublicKeyEnd
HDPublicKey.ChecksumEnd = HDPublicKey.ChecksumStart + HDPublicKey.CheckSumSize

assert(HDPublicKey.PublicKeyEnd === HDPublicKey.DataSize)
assert(HDPublicKey.ChecksumEnd === HDPublicKey.SerializedByteSize)

export = HDPublicKey
