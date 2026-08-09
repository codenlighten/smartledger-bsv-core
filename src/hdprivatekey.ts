'use strict'

import type { HDPrivateKey, HDPrivateKeyConstructor, HDBuffers, NetworkLike } from './hdprivatekey.types'
import type { HDPublicKey } from './hdpublickey.types'

import assert = require('assert')
import buffer = require('buffer')
import _ = require('./util/_')
import $ = require('./util/preconditions')

import BN = require('./crypto/bn')
import Base58 = require('./encoding/base58')
import Base58Check = require('./encoding/base58check')
import Hash = require('./crypto/hash')
import Network = require('./networks')
import Point = require('./crypto/point')
import PrivateKey = require('./privatekey')
import Random = require('./crypto/random')

import errors = require('./errors')
const hdErrors = errors.HDPrivateKey
import JSUtil = require('./util/js')

// The error tree is built dynamically; members arrive via an index signature.
type ErrCtor = new (...args: unknown[]) => Error
const err = (path: string): ErrCtor =>
  path.split('.').reduce<any>((o, k) => o[k], errors) as ErrCtor


const MINIMUM_ENTROPY_BITS = 128
const BITS_TO_BYTES = 1 / 8
const MAXIMUM_ENTROPY_BITS = 512

/**
 * Represents an instance of an hierarchically derived private key.
 *
 * More info on https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 *
 * @constructor
 * @param {string|Buffer|Object} arg
 */
const HDPrivateKey = function HDPrivateKey (this: HDPrivateKey, arg?: any): any {
  if (arg instanceof HDPrivateKey) {
    return arg
  }
  if (!(this instanceof HDPrivateKey)) {
    return new (HDPrivateKey as unknown as HDPrivateKeyConstructor)(arg)
  }
  if (!arg) {
    return this._generateRandomly()
  }

  if (Network.get(arg)) {
    return this._generateRandomly(arg)
  } else if (_.isString(arg) || Buffer.isBuffer(arg)) {
    if ((HDPrivateKey as unknown as HDPrivateKeyConstructor).isValidSerialized(arg)) {
      this._buildFromSerialized(arg as string)
    } else if (JSUtil.isValidJSON(arg)) {
      this._buildFromJSON(arg)
    } else if (Buffer.isBuffer(arg) && (HDPrivateKey as unknown as HDPrivateKeyConstructor).isValidSerialized(arg.toString())) {
      this._buildFromSerialized(arg.toString())
    } else {
      throw (HDPrivateKey as unknown as HDPrivateKeyConstructor).getSerializedError(arg)
    }
  } else if (_.isObject(arg)) {
    this._buildFromObject(arg)
  } else {
    throw new (err('HDPrivateKey.UnrecognizedArgument'))(arg)
  }
} as unknown as HDPrivateKeyConstructor

// Forward the network so `fromRandom('testnet')` generates a testnet key. The
// constructor routes a network arg to _generateRandomly(network); dropping it
// (the pre-7.0.2 `new HDPrivateKey()`) silently produced a mainnet key on a
// testnet request, with no error.
HDPrivateKey.fromRandom = function (network?: NetworkLike) {
  return new HDPrivateKey(network)
}

/**
 * Verifies that a given path is valid.
 *
 * @param {string|number} arg
 * @param {boolean?} hardened
 * @return {boolean}
 */
HDPrivateKey.isValidPath = function (arg: string | number, hardened?: boolean | null) {
  if (_.isString(arg)) {
    const indexes = HDPrivateKey._getDerivationIndexes(arg)
    return indexes !== null && _.every(indexes, (i: number) => (HDPrivateKey as unknown as HDPrivateKeyConstructor).isValidPath(i))
  }

  if (_.isNumber(arg)) {
    if (arg < HDPrivateKey.Hardened && hardened === true) {
      arg += HDPrivateKey.Hardened
    }
    return arg >= 0 && arg < HDPrivateKey.MaxIndex
  }

  return false
}

/**
 * Internal function that splits a string path into a derivation index array.
 * It will return null if the string path is malformed.
 * It does not validate if indexes are in bounds.
 *
 * @param {string} path
 * @return {Array}
 */
HDPrivateKey._getDerivationIndexes = function (path: string) {
  const steps = path.split('/')

  // Special cases:
  if (_.includes(HDPrivateKey.RootElementAlias, path)) {
    return []
  }

  if (!_.includes(HDPrivateKey.RootElementAlias, steps[0])) {
    return null
  }

  const indexes = steps.slice(1).map(function (step: any) {
    const isHardened = step.slice(-1) === '\''
    if (isHardened) {
      step = step.slice(0, -1)
    }
    if (!step || step[0] === '-') {
      return NaN
    }
    let index = +step // cast to number
    if (isHardened) {
      index += HDPrivateKey.Hardened
    }

    return index
  })

  return _.some(indexes, isNaN) ? null : indexes
}

/**
 * WARNING: This method is deprecated. Use deriveChild or deriveNonCompliantChild instead. This is not BIP32 compliant
 *
 *
 * Get a derived child based on a string or number.
 *
 * If the first argument is a string, it's parsed as the full path of
 * derivation. Valid values for this argument include "m" (which returns the
 * same private key), "m/0/1/40/2'/1000", where the ' quote means a hardened
 * derivation.
 *
 * If the first argument is a number, the child with that index will be
 * derived. If the second argument is truthy, the hardened version will be
 * derived. See the example usage for clarification.
 *
 * @example
 * ```javascript
 * var parent = new HDPrivateKey('xprv...');
 * var child_0_1_2h = parent.derive(0).derive(1).derive(2, true);
 * var copy_of_child_0_1_2h = parent.derive("m/0/1/2'");
 * assert(child_0_1_2h.xprivkey === copy_of_child_0_1_2h);
 * ```
 *
 * @param {string|number} arg
 * @param {boolean?} hardened
 */
HDPrivateKey.prototype.derive = function (this: HDPrivateKey, arg: string | number, hardened?: boolean) {
  throw new Error('derive has been deprecated. use deriveChild or, for the old way, deriveNonCompliantChild.')
}

/**
 * WARNING: This method will not be officially supported until v1.0.0.
 *
 *
 * Get a derived child based on a string or number.
 *
 * If the first argument is a string, it's parsed as the full path of
 * derivation. Valid values for this argument include "m" (which returns the
 * same private key), "m/0/1/40/2'/1000", where the ' quote means a hardened
 * derivation.
 *
 * If the first argument is a number, the child with that index will be
 * derived. If the second argument is truthy, the hardened version will be
 * derived. See the example usage for clarification.
 *
 * WARNING: The `nonCompliant` option should NOT be used, except for older implementation
 * that used a derivation strategy that used a non-zero padded private key.
 *
 * @example
 * ```javascript
 * var parent = new HDPrivateKey('xprv...');
 * var child_0_1_2h = parent.deriveChild(0).deriveChild(1).deriveChild(2, true);
 * var copy_of_child_0_1_2h = parent.deriveChild("m/0/1/2'");
 * assert(child_0_1_2h.xprivkey === copy_of_child_0_1_2h);
 * ```
 *
 * @param {string|number} arg
 * @param {boolean?} hardened
 */
HDPrivateKey.prototype.deriveChild = function (this: HDPrivateKey, arg: string | number, hardened?: boolean) {
  if (_.isNumber(arg)) {
    return this._deriveWithNumber(arg, hardened)
  } else if (_.isString(arg)) {
    return this._deriveFromString(arg)
  } else {
    throw new (err('HDPrivateKey.InvalidDerivationArgument'))(arg)
  }
}

/**
 * WARNING: This method will not be officially supported until v1.0.0
 *
 *
 * WARNING: If this is a new implementation you should NOT use this method, you should be using
 * `derive` instead.
 *
 * This method is explicitly for use and compatibility with an implementation that
 * was not compliant with BIP32 regarding the derivation algorithm. The private key
 * must be 32 bytes hashing, and this implementation will use the non-zero padded
 * serialization of a private key, such that it's still possible to derive the privateKey
 * to recover those funds.
 *
 * @param {string|number} arg
 * @param {boolean?} hardened
 */
HDPrivateKey.prototype.deriveNonCompliantChild = function (this: HDPrivateKey, arg: string | number, hardened?: boolean) {
  if (_.isNumber(arg)) {
    return this._deriveWithNumber(arg, hardened, true)
  } else if (_.isString(arg)) {
    return this._deriveFromString(arg, true)
  } else {
    throw new (err('HDPrivateKey.InvalidDerivationArgument'))(arg)
  }
}

HDPrivateKey.prototype._deriveWithNumber = function (this: HDPrivateKey, index: number, hardened?: boolean | null, nonCompliant?: boolean) {
  if (!HDPrivateKey.isValidPath(index, hardened)) {
    throw new (err('HDPrivateKey.InvalidPath'))(index)
  }

  hardened = index >= HDPrivateKey.Hardened ? true : hardened
  if (index < HDPrivateKey.Hardened && hardened === true) {
    index += HDPrivateKey.Hardened
  }

  const indexBuffer = JSUtil.integerAsBuffer(index)
  let data
  if (hardened && nonCompliant) {
    // The private key serialization in this case will not be exactly 32 bytes and can be
    // any value less, and the value is not zero-padded.
    const nonZeroPadded = this.privateKey.bn.toBuffer()
    data = Buffer.concat([buffer.Buffer.from([0]), nonZeroPadded, indexBuffer])
  } else if (hardened) {
    // This will use a 32 byte zero padded serialization of the private key
    const privateKeyBuffer = this.privateKey.bn.toBuffer({ size: 32 })
    assert(privateKeyBuffer.length === 32, 'length of private key buffer is expected to be 32 bytes')
    data = Buffer.concat([buffer.Buffer.from([0]), privateKeyBuffer, indexBuffer])
  } else {
    data = Buffer.concat([this.publicKey.toBuffer(), indexBuffer])
  }
  const hash = Hash.sha512hmac(data, this._buffers.chainCode)
  const leftPart = BN.fromBuffer(hash.slice(0, 32), {
    size: 32
  })
  const chainCode = hash.slice(32, 64)

  const privateKey = leftPart.add(this.privateKey.toBigNumber()).umod(Point.getN()).toBuffer({
    size: 32
  })

  if (!PrivateKey.isValid(privateKey)) {
    // Index at this point is already hardened, we can pass null as the hardened arg
    return this._deriveWithNumber(index + 1, null, nonCompliant)
  }

  const derived = new HDPrivateKey({
    network: this.network,
    depth: this.depth + 1,
    parentFingerPrint: this.fingerPrint,
    childIndex: index,
    chainCode,
    privateKey
  })

  return derived
}

HDPrivateKey.prototype._deriveFromString = function (this: HDPrivateKey, path: string, nonCompliant?: boolean) {
  if (!HDPrivateKey.isValidPath(path)) {
    throw new (err('HDPrivateKey.InvalidPath'))(path)
  }

  const indexes = HDPrivateKey._getDerivationIndexes(path)
  const derived = indexes!.reduce(function (prev: any, index: any) {
    return prev._deriveWithNumber(index, null, nonCompliant)
  }, this)

  return derived
}

/**
 * Verifies that a given serialized private key in base58 with checksum format
 * is valid.
 *
 * @param {string|Buffer} data - the serialized private key
 * @param {string|Network=} network - optional, if present, checks that the
 *     network provided matches the network serialized.
 * @return {boolean}
 */
HDPrivateKey.isValidSerialized = function (data: string | Buffer, network?: NetworkLike) {
  return !HDPrivateKey.getSerializedError(data, network)
}

/**
 * Checks what's the error that causes the validation of a serialized private key
 * in base58 with checksum to fail.
 *
 * @param {string|Buffer} data - the serialized private key
 * @param {string|Network=} network - optional, if present, checks that the
 *     network provided matches the network serialized.
 * @return {errors.InvalidArgument|null}
 */
HDPrivateKey.getSerializedError = function (data: string | Buffer, network?: NetworkLike) {
  if (!(_.isString(data) || Buffer.isBuffer(data))) {
    return new (err('HDPrivateKey.UnrecognizedArgument'))('Expected string or buffer')
  }
  if (!Base58.validCharacters(data)) {
    return new (err('InvalidB58Char'))('(unknown)', data)
  }
  try {
    data = Base58Check.decode(data as string)
  } catch (e) {
    return new (err('InvalidB58Checksum'))(data)
  }
  if (data.length !== HDPrivateKey.DataLength) {
    return new (err('HDPrivateKey.InvalidLength'))(data)
  }
  if (!_.isUndefined(network)) {
    const error = HDPrivateKey._validateNetwork(data, network)
    if (error) {
      return error
    }
  }
  return null
}

HDPrivateKey._validateNetwork = function (data: Buffer, networkArg?: NetworkLike) {
  const network = Network.get(networkArg)
  if (!network) {
    return new (err('InvalidNetworkArgument'))(networkArg)
  }
  const version = data.slice(0, 4)
  if (version.readUInt32BE(0) !== network.xprivkey) {
    return new (err('InvalidNetwork'))(version)
  }
  return null
}

HDPrivateKey.fromString = function (arg: string) {
  $.checkArgument(_.isString(arg), 'No valid string was provided')
  return new HDPrivateKey(arg)
}

HDPrivateKey.fromObject = function (arg: any) {
  $.checkArgument(_.isObject(arg), 'No valid argument was provided')
  return new HDPrivateKey(arg)
}

HDPrivateKey.prototype._buildFromJSON = function (this: HDPrivateKey, arg: any) {
  return this._buildFromObject(JSON.parse(arg))
}

HDPrivateKey.prototype._buildFromObject = function (this: HDPrivateKey, arg: any) {
  // TODO: Type validation
  const buffers: HDBuffers = {
    version: arg.network ? JSUtil.integerAsBuffer(Network.get(arg.network)!.xprivkey) : arg.version,
    depth: _.isNumber(arg.depth) ? Buffer.from([arg.depth & 0xff]) : arg.depth,
    parentFingerPrint: _.isNumber(arg.parentFingerPrint) ? JSUtil.integerAsBuffer(arg.parentFingerPrint) : arg.parentFingerPrint,
    childIndex: _.isNumber(arg.childIndex) ? JSUtil.integerAsBuffer(arg.childIndex) : arg.childIndex,
    chainCode: _.isString(arg.chainCode) ? Buffer.from(arg.chainCode, 'hex') : arg.chainCode,
    privateKey: (_.isString(arg.privateKey) && JSUtil.isHexa(arg.privateKey)) ? Buffer.from(arg.privateKey, 'hex') : arg.privateKey,
    checksum: arg.checksum ? (arg.checksum.length ? arg.checksum : JSUtil.integerAsBuffer(arg.checksum)) : undefined
  }
  return this._buildFromBuffers(buffers)
}

HDPrivateKey.prototype._buildFromSerialized = function (this: HDPrivateKey, arg: string) {
  const decoded = Base58Check.decode(arg)
  const buffers: HDBuffers = {
    version: decoded.slice(HDPrivateKey.VersionStart, HDPrivateKey.VersionEnd),
    depth: decoded.slice(HDPrivateKey.DepthStart, HDPrivateKey.DepthEnd),
    parentFingerPrint: decoded.slice(HDPrivateKey.ParentFingerPrintStart,
      HDPrivateKey.ParentFingerPrintEnd),
    childIndex: decoded.slice(HDPrivateKey.ChildIndexStart, HDPrivateKey.ChildIndexEnd),
    chainCode: decoded.slice(HDPrivateKey.ChainCodeStart, HDPrivateKey.ChainCodeEnd),
    privateKey: decoded.slice(HDPrivateKey.PrivateKeyStart, HDPrivateKey.PrivateKeyEnd),
    checksum: decoded.slice(HDPrivateKey.ChecksumStart, HDPrivateKey.ChecksumEnd),
    xprivkey: arg
  }
  return this._buildFromBuffers(buffers)
}

HDPrivateKey.prototype._generateRandomly = function (this: HDPrivateKey, network?: NetworkLike) {
  return HDPrivateKey.fromSeed(Random.getRandomBuffer(64), network)
}

/**
 * Generate a private key from a seed, as described in BIP32
 *
 * @param {string|Buffer} hexa
 * @param {*} network
 * @return HDPrivateKey
 */
HDPrivateKey.fromSeed = function (hexa: string | Buffer, network?: NetworkLike) {
  // Hex string or raw bytes in, bytes out — under its own name so the type
  // follows the value past the conversion.
  const seed: Buffer | string = JSUtil.isHexaString(hexa) ? Buffer.from(hexa as string, 'hex') : hexa
  if (!Buffer.isBuffer(seed)) {
    throw new (err('HDPrivateKey.InvalidEntropyArgument'))(seed)
  }
  if (seed.length < MINIMUM_ENTROPY_BITS * BITS_TO_BYTES) {
    throw new (err('HDPrivateKey.InvalidEntropyArgument.NotEnoughEntropy'))(seed)
  }
  if (seed.length > MAXIMUM_ENTROPY_BITS * BITS_TO_BYTES) {
    throw new (err('HDPrivateKey.InvalidEntropyArgument.TooMuchEntropy'))(seed)
  }
  const hash = Hash.sha512hmac(seed, buffer.Buffer.from('Bitcoin seed'))

  return new HDPrivateKey({
    network: Network.get(network) || Network.defaultNetwork,
    depth: 0,
    parentFingerPrint: 0,
    childIndex: 0,
    privateKey: hash.slice(0, 32),
    chainCode: hash.slice(32, 64)
  })
}

HDPrivateKey.prototype._calcHDPublicKey = function (this: HDPrivateKey) {
  if (!this._hdPublicKey) {
    const HDPublicKey = require('./hdpublickey')
    this._hdPublicKey = new HDPublicKey(this)
  }
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
 * @param {buffer.Buffer} arg.privateKey
 * @param {buffer.Buffer} arg.checksum
 * @param {string=} arg.xprivkey - if set, don't recalculate the base58
 *      representation
 * @return {HDPrivateKey} this
 */
HDPrivateKey.prototype._buildFromBuffers = function (this: HDPrivateKey, arg: HDBuffers) {
  HDPrivateKey._validateBufferArguments(arg)

  JSUtil.defineImmutable(this, {
    _buffers: arg
  })

  const sequence = [
    arg.version, arg.depth, arg.parentFingerPrint, arg.childIndex, arg.chainCode,
    Buffer.alloc(1), arg.privateKey
  ]
  const concat = buffer.Buffer.concat(sequence)
  if (!arg.checksum || !arg.checksum.length) {
    arg.checksum = Base58Check.checksum(concat)
  } else {
    if (arg.checksum.toString() !== Base58Check.checksum(concat).toString()) {
      throw new (err('InvalidB58Checksum'))(concat)
    }
  }

  const network = Network.get(arg.version.readUInt32BE(0))
  let xprivkey
  xprivkey = Base58Check.encode(buffer.Buffer.concat(sequence))
  arg.xprivkey = Buffer.from(xprivkey)

  const privateKey = new PrivateKey(BN.fromBuffer(arg.privateKey), network)
  const publicKey = privateKey.toPublicKey()
  const size = HDPrivateKey.ParentFingerPrintSize
  const fingerPrint = Hash.sha256ripemd160(publicKey.toBuffer()).slice(0, size)

  JSUtil.defineImmutable(this, {
    xprivkey,
    network,
    depth: arg.depth[0],
    privateKey,
    publicKey,
    fingerPrint
  })

  this._hdPublicKey = null

  Object.defineProperty(this, 'hdPublicKey', {
    configurable: false,
    enumerable: true,
    get: function () {
      this._calcHDPublicKey()
      return this._hdPublicKey
    }
  })
  Object.defineProperty(this, 'xpubkey', {
    configurable: false,
    enumerable: true,
    get: function () {
      this._calcHDPublicKey()
      return this._hdPublicKey.xpubkey
    }
  })
  return this
}

HDPrivateKey._validateBufferArguments = function (arg: HDBuffers) {
  const checkBuffer = function (name: keyof HDBuffers, size: number) {
    const buff = arg[name] as Buffer
    assert(Buffer.isBuffer(buff), name + ' argument is not a buffer')
    assert(
      buff.length === size,
      name + ' has not the expected size: found ' + buff.length + ', expected ' + size
    )
  }
  checkBuffer('version', HDPrivateKey.VersionSize)
  checkBuffer('depth', HDPrivateKey.DepthSize)
  checkBuffer('parentFingerPrint', HDPrivateKey.ParentFingerPrintSize)
  checkBuffer('childIndex', HDPrivateKey.ChildIndexSize)
  checkBuffer('chainCode', HDPrivateKey.ChainCodeSize)
  checkBuffer('privateKey', HDPrivateKey.PrivateKeySize)
  if (arg.checksum && arg.checksum.length) {
    checkBuffer('checksum', HDPrivateKey.CheckSumSize)
  }
}

/**
 * Returns the string representation of this private key (a string starting
 * with "xprv..."
 *
 * @return string
 */
HDPrivateKey.prototype.toString = function (this: HDPrivateKey) {
  return this.xprivkey
}

/**
 * Returns the console representation of this extended private key.
 * @return string
 */
HDPrivateKey.prototype.inspect = function (this: HDPrivateKey) {
  return '<HDPrivateKey: ' + this.xprivkey + '>'
}

/**
 * Returns a plain object with a representation of this private key.
 *
 * Fields include:<ul>
 * <li> network: either 'livenet' or 'testnet'
 * <li> depth: a number ranging from 0 to 255
 * <li> fingerPrint: a number ranging from 0 to 2^32-1, taken from the hash of the
 * <li>     associated public key
 * <li> parentFingerPrint: a number ranging from 0 to 2^32-1, taken from the hash
 * <li>     of this parent's associated public key or zero.
 * <li> childIndex: the index from which this child was derived (or zero)
 * <li> chainCode: an hexa string representing a number used in the derivation
 * <li> privateKey: the private key associated, in hexa representation
 * <li> xprivkey: the representation of this extended private key in checksum
 * <li>     base58 format
 * <li> checksum: the base58 checksum of xprivkey
 * </ul>
 *  @return {Object}
 */
HDPrivateKey.prototype.toObject = HDPrivateKey.prototype.toJSON = function toObject (this: HDPrivateKey) {
  return {
    network: Network.get(this._buffers.version.readUInt32BE(0), 'xprivkey')!.name,
    depth: this._buffers.depth[0],
    fingerPrint: this.fingerPrint.readUInt32BE(0),
    parentFingerPrint: this._buffers.parentFingerPrint.readUInt32BE(0),
    childIndex: this._buffers.childIndex.readUInt32BE(0),
    chainCode: this._buffers.chainCode.toString('hex'),
    privateKey: this.privateKey.toBuffer().toString('hex'),
    checksum: this._buffers.checksum!.readUInt32BE(0),
    xprivkey: this.xprivkey
  }
}

/**
 * Build a HDPrivateKey from a buffer
 *
 * @param {Buffer} arg
 * @return {HDPrivateKey}
 */
HDPrivateKey.fromBuffer = function (buf: Buffer) {
  return new HDPrivateKey(buf.toString())
}

/**
 * Build a HDPrivateKey from a hex string
 *
 * @param {string} hex
 * @return {HDPrivateKey}
 */
HDPrivateKey.fromHex = function (hex: string) {
  return HDPrivateKey.fromBuffer(Buffer.from(hex, 'hex'))
}

/**
 * Returns a buffer representation of the HDPrivateKey
 *
 * @return {string}
 */
HDPrivateKey.prototype.toBuffer = function (this: HDPrivateKey) {
  return Buffer.from(this.toString())
}

/**
 * Returns a hex string representation of the HDPrivateKey
 *
 * @return {string}
 */
HDPrivateKey.prototype.toHex = function (this: HDPrivateKey) {
  return this.toBuffer().toString('hex')
}

HDPrivateKey.DefaultDepth = 0
HDPrivateKey.DefaultFingerprint = 0
HDPrivateKey.DefaultChildIndex = 0
HDPrivateKey.Hardened = 0x80000000
HDPrivateKey.MaxIndex = 2 * HDPrivateKey.Hardened

HDPrivateKey.RootElementAlias = ['m', 'M', 'm\'', 'M\'']

HDPrivateKey.VersionSize = 4
HDPrivateKey.DepthSize = 1
HDPrivateKey.ParentFingerPrintSize = 4
HDPrivateKey.ChildIndexSize = 4
HDPrivateKey.ChainCodeSize = 32
HDPrivateKey.PrivateKeySize = 32
HDPrivateKey.CheckSumSize = 4

HDPrivateKey.DataLength = 78
HDPrivateKey.SerializedByteSize = 82

HDPrivateKey.VersionStart = 0
HDPrivateKey.VersionEnd = HDPrivateKey.VersionStart + HDPrivateKey.VersionSize
HDPrivateKey.DepthStart = HDPrivateKey.VersionEnd
HDPrivateKey.DepthEnd = HDPrivateKey.DepthStart + HDPrivateKey.DepthSize
HDPrivateKey.ParentFingerPrintStart = HDPrivateKey.DepthEnd
HDPrivateKey.ParentFingerPrintEnd = HDPrivateKey.ParentFingerPrintStart + HDPrivateKey.ParentFingerPrintSize
HDPrivateKey.ChildIndexStart = HDPrivateKey.ParentFingerPrintEnd
HDPrivateKey.ChildIndexEnd = HDPrivateKey.ChildIndexStart + HDPrivateKey.ChildIndexSize
HDPrivateKey.ChainCodeStart = HDPrivateKey.ChildIndexEnd
HDPrivateKey.ChainCodeEnd = HDPrivateKey.ChainCodeStart + HDPrivateKey.ChainCodeSize
HDPrivateKey.PrivateKeyStart = HDPrivateKey.ChainCodeEnd + 1
HDPrivateKey.PrivateKeyEnd = HDPrivateKey.PrivateKeyStart + HDPrivateKey.PrivateKeySize
HDPrivateKey.ChecksumStart = HDPrivateKey.PrivateKeyEnd
HDPrivateKey.ChecksumEnd = HDPrivateKey.ChecksumStart + HDPrivateKey.CheckSumSize

assert(HDPrivateKey.ChecksumEnd === HDPrivateKey.SerializedByteSize)

export = HDPrivateKey
