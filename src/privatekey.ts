'use strict'

import _ = require('./util/_')
import Base58Check = require('./encoding/base58check')
import BN = require('./crypto/bn')
import JSUtil = require('./util/js')
import Networks = require('./networks')
import Point = require('./crypto/point')
import Random = require('./crypto/random')
import $ = require('./util/preconditions')
import type { PrivateKey, PrivateKeyConstructor, PrivateKeyInfo } from './privatekey.types'
import type { PublicKeyConstructor } from './publickey.types'

// Runtime edges into the address <-> publickey <-> privatekey cycle, resolved
// at call time so nothing is dereferenced during module evaluation.
const publicKeyCtor = (): PublicKeyConstructor => require('./publickey')
const addressCtor = (): { fromPublicKey: (p: unknown, n?: unknown) => unknown } => require('./address')

// The marker toJSON() emits in place of the secret. _transformObject rejects it by name
// so a JSON round-trip fails loudly instead of quietly yielding a different key.
const REDACTED = '[REDACTED]'

/**
 * Instantiate a PrivateKey from a BN, Buffer or WIF string.
 *
 * @param {string} data - The encoded data in various formats
 * @param {Network|string=} network - a {@link Network} object, or a string with the network name
 * @returns {PrivateKey} A new valid instance of an PrivateKey
 * @constructor
 */
const PrivateKey = function PrivateKey (this: PrivateKey, data?: unknown, network?: unknown) {
  if (!(this instanceof PrivateKey)) {
    return new (PrivateKey as PrivateKeyConstructor)(data, network)
  }
  if (data instanceof (PrivateKey as unknown as new () => unknown)) {
    return data as PrivateKey
  }

  const info = this._classifyArguments(data, network)

  // validation
  if (info.bn == null || info.bn.cmp(new BN(0)) === 0) {
    throw new TypeError('Number can not be equal to zero, undefined, null or false')
  }
  if (!info.bn.lt(Point.getN())) {
    throw new TypeError('Number must be less than N')
  }
  if (typeof (info.network) === 'undefined') {
    throw new TypeError('Must specify the network ("livenet" or "testnet")')
  }

  JSUtil.defineImmutable(this, {
    bn: info.bn,
    compressed: info.compressed,
    network: info.network
  })

  Object.defineProperty(this, 'publicKey', {
    configurable: false,
    enumerable: true,
    get: this.toPublicKey.bind(this)
  })

  return this
} as unknown as PrivateKeyConstructor

/**
 * Internal helper to instantiate PrivateKey internal `info` object from
 * different kinds of arguments passed to the constructor.
 *
 * @param {*} data
 * @param {Network|string=} network - a {@link Network} object, or a string with the network name
 * @return {Object}
 */
PrivateKey.prototype._classifyArguments = function (this: PrivateKey, data: unknown, network?: unknown): PrivateKeyInfo {
  // Starts populated but is REASSIGNED wholesale by several branches below
  // (_transformBuffer, _transformObject, _transformWIF), so it is typed as the
  // shared partial rather than inferred from this literal.
  let info: PrivateKeyInfo = {
    compressed: true,
    network: network != null ? Networks.get(network as string | number) : Networks.defaultNetwork
  }

  // detect type of data
  if (_.isUndefined(data) || _.isNull(data)) {
    info.bn = (PrivateKey as PrivateKeyConstructor)._getRandomBN()
  } else if (data instanceof BN) {
    info.bn = data
  } else if (data instanceof Buffer || data instanceof Uint8Array) {
    info = (PrivateKey as PrivateKeyConstructor)._transformBuffer(Buffer.from(data), network)
  } else if ((data as { bn?: unknown, network?: unknown })?.bn != null && (data as { network?: unknown }).network != null) {
    info = (PrivateKey as PrivateKeyConstructor)._transformObject(data as Record<string, unknown>)
  } else if (network == null && Networks.get(data as string | number) != null) {
    info.bn = (PrivateKey as PrivateKeyConstructor)._getRandomBN()
    info.network = Networks.get(data as string | number)
  } else if (typeof (data) === 'string') {
    if (JSUtil.isHexa(data)) {
      info.bn = new BN(Buffer.from(data, 'hex'))
    } else {
      info = (PrivateKey as PrivateKeyConstructor)._transformWIF(data, network)
    }
  } else {
    throw new TypeError('First argument is an unrecognized data type.')
  }
  return info
}

/**
 * Internal function to get a random Big Number (BN)
 *
 * @returns {BN} A new randomly generated BN
 * @private
 */
PrivateKey._getRandomBN = function (): BN {
  let condition
  let bn
  do {
    const privbuf = Random.getRandomBuffer(32)
    bn = BN.fromBuffer(privbuf)
    condition = bn.lt(Point.getN())
  } while (!condition)
  return bn
}

/**
 * Internal function to transform a WIF Buffer into a private key
 *
 * @param {Buffer} buf - An WIF string
 * @param {Network|string=} network - a {@link Network} object, or a string with the network name
 * @returns {Object} An object with keys: bn, network and compressed
 * @private
 */
PrivateKey._transformBuffer = function (buf: Buffer, network?: unknown): PrivateKeyInfo {
  const info: PrivateKeyInfo = {}

  if (buf.length === 32) {
    return PrivateKey._transformBNBuffer(buf, network)
  }

  // buf is length-checked above, so byte 0 is present.
  info.network = Networks.get(buf[0] as number, 'privatekey')

  if (!info.network) {
    throw new Error('Invalid network')
  }

  if (network && info.network !== Networks.get(network as string | number)) {
    throw new TypeError('Private key network mismatch')
  }

  if (buf.length === 1 + 32 + 1 && buf[1 + 32 + 1 - 1] === 1) {
    info.compressed = true
  } else if (buf.length === 1 + 32) {
    info.compressed = false
  } else {
    throw new Error('Length of buffer must be 33 (uncompressed) or 34 (compressed)')
  }

  info.bn = BN.fromBuffer(buf.slice(1, 32 + 1))

  return info
}

/**
 * Internal function to transform a BN buffer into a private key
 *
 * @param {Buffer} buf
 * @param {Network|string=} network - a {@link Network} object, or a string with the network name
 * @returns {object} an Object with keys: bn, network, and compressed
 * @private
 */
PrivateKey._transformBNBuffer = function (buf: Buffer, network?: unknown, compressed?: boolean): PrivateKeyInfo {
  const info: PrivateKeyInfo = {}
  info.network = Networks.get(network as string | number) || Networks.defaultNetwork
  info.bn = BN.fromBuffer(buf)
  // A raw 32-byte scalar carries no compression information, so this is a choice, not a
  // reading. It used to be `false` while every other constructor path — random keys, hex
  // strings, compressed WIF — produced `true`, so `PrivateKey.fromHex(h)` and
  // `new PrivateKey(h)` returned different addresses and different WIFs for identical
  // input. Restore a key by the wrong route and you derive an address you never funded.
  // The default now matches the rest of the library; pass `false` explicitly for the
  // legacy uncompressed form.
  info.compressed = compressed === undefined ? true : !!compressed
  return info
}

/**
 * Internal function to transform a WIF string into a private key
 *
 * @param {string} buf - An WIF string
 * @returns {Object} An object with keys: bn, network and compressed
 * @private
 */
PrivateKey._transformWIF = function (str: string, network?: unknown): PrivateKeyInfo {
  return PrivateKey._transformBuffer(Base58Check.decode(str), network)
}

/**
 * Instantiate a PrivateKey from a Buffer with the DER or WIF representation
 *
 * @param {Buffer} buf
 * @param {Network} network
 * @return {PrivateKey}
 */
PrivateKey.fromBuffer = function (buf: Buffer, network?: unknown, compressed?: boolean): PrivateKey {
  if (compressed !== undefined && buf && buf.length === 32) {
    return new (PrivateKey as PrivateKeyConstructor)(PrivateKey._transformBNBuffer(buf, network, compressed))
  }
  return new (PrivateKey as PrivateKeyConstructor)(buf, network)
}

/**
 * @param {string} hex - 32-byte private key scalar, hex encoded
 * @param {Network|string=} network
 * @param {boolean=} compressed - defaults to true, matching every other constructor path
 * @return {PrivateKey}
 */
PrivateKey.fromHex = function (hex: string, network?: unknown, compressed?: boolean): PrivateKey {
  return PrivateKey.fromBuffer(Buffer.from(hex, 'hex'), network, compressed)
}

/**
 * Internal function to transform a JSON string on plain object into a private key
 * return this.
 *
 * @param {string} json - A JSON string or plain object
 * @returns {Object} An object with keys: bn, network and compressed
 * @private
 */
PrivateKey._transformObject = function (json: Record<string, unknown>): PrivateKeyInfo {
  // bn.js 4 silently SKIPS characters it cannot parse rather than failing, so any
  // malformed `bn` produced a wrong key instead of an error. The natural round-trip
  // `fromObject(JSON.parse(JSON.stringify(key)))` fed it the redaction marker that
  // `toJSON` has emitted since 7.5.1 and got a deterministic ~40-bit key back, with
  // no indication anything was wrong — funds sent to its address are trivially
  // recoverable by anyone. Validate before parsing.
  // This is reached with two different shapes: a deserialised JSON object, whose `bn`
  // is a hex string, and an internal info object built by _transformBNBuffer, whose
  // `bn` is already a BN. Only the former needs parsing, and only it can be malformed.
  if (json.bn instanceof BN) {
    return {
      bn: json.bn,
      network: Networks.get(json.network as string | number),
      compressed: json.compressed as boolean
    }
  }
  if (typeof json.bn !== 'string' || !json.bn.length) {
    throw new TypeError('Invalid private key: `bn` must be a hex string')
  }
  if (json.bn === REDACTED) {
    throw new TypeError('Invalid private key: `bn` is "' + REDACTED + '". ' +
      'JSON.stringify() redacts the secret on purpose — use toObject() for a ' +
      'round-trippable export, or toWIF().')
  }
  if (!/^[0-9a-fA-F]+$/.test(json.bn)) {
    throw new TypeError('Invalid private key: `bn` is not hexadecimal')
  }
  const bn = new BN(json.bn, 'hex')
  if (bn.isZero() || bn.gte(Point.getN())) {
    throw new TypeError('Invalid private key: outside the range of valid keys')
  }
  const network = Networks.get(json.network as string | number)
  return {
    bn,
    network,
    compressed: json.compressed as boolean
  }
}

/**
 * Instantiate a PrivateKey from a WIF string, or from a hex-encoded scalar.
 *
 * The `network` argument used to be accepted and silently discarded, so
 * `fromString(hex, 'testnet')` returned a livenet key and therefore a MAINNET address —
 * funds sent there land on the wrong network. It is now honoured. For a WIF, which
 * already encodes its own network, a conflicting `network` throws rather than being
 * quietly overridden.
 *
 * @param {string} str - WIF-encoded private key, or a hex-encoded scalar
 * @param {Network|string=} network
 * @returns {PrivateKey} A new valid instance of PrivateKey
 */
PrivateKey.fromString = PrivateKey.fromWIF = function (str: string, network?: unknown): PrivateKey {
  $.checkArgument(_.isString(str), 'First argument is expected to be a string.')
  return new (PrivateKey as PrivateKeyConstructor)(str, network)
}

/**
 * Instantiate a PrivateKey from a plain JavaScript object
 *
 * @param {Object} obj - The output from privateKey.toObject()
 */
PrivateKey.fromObject = PrivateKey.fromJSON = function (obj: Record<string, unknown>): PrivateKey {
  $.checkArgument(_.isObject(obj), 'First argument is expected to be an object.')
  return new (PrivateKey as PrivateKeyConstructor)(obj)
}

/**
 * Instantiate a PrivateKey from random bytes
 *
 * @param {string=} network - Either "livenet" or "testnet"
 * @returns {PrivateKey} A new valid instance of PrivateKey
 */
PrivateKey.fromRandom = function (network?: unknown): PrivateKey {
  const bn = PrivateKey._getRandomBN()
  return new (PrivateKey as PrivateKeyConstructor)(bn, network)
}

/**
 * Check if there would be any errors when initializing a PrivateKey
 *
 * @param {string} data - The encoded data in various formats
 * @param {string=} network - Either "livenet" or "testnet"
 * @returns {null|Error} An error if exists
 */

PrivateKey.getValidationError = function (data: unknown, network?: unknown): Error | undefined {
  let error
  try {
    new PrivateKey(data, network) // eslint-disable-line
  } catch (e) {
    error = e as Error
  }
  return error
}

/**
 * Check if the parameters are valid
 *
 * @param {string} data - The encoded data in various formats
 * @param {string=} network - Either "livenet" or "testnet"
 * @returns {Boolean} If the private key is would be valid
 */
PrivateKey.isValid = function (data: unknown, network?: unknown): boolean {
  if (!data) {
    return false
  }
  return !PrivateKey.getValidationError(data, network)
}

/**
 * Will output the PrivateKey in WIF
 *
 * @returns {string}
 */
PrivateKey.prototype.toString = function (this: PrivateKey): string {
  return this.toWIF()
}

/**
 * Will output the PrivateKey to a WIF string
 *
 * @returns {string} A WIP representation of the private key
 */
PrivateKey.prototype.toWIF = function (this: PrivateKey): string {
  const network = this.network
  const compressed = this.compressed

  let buf: Buffer
  const net = network as { privatekey: number }
  if (compressed) {
    buf = Buffer.concat([Buffer.from([net.privatekey]),
      this.bn.toBuffer({ size: 32 }),
      Buffer.from([0x01])])
  } else {
    buf = Buffer.concat([Buffer.from([net.privatekey]),
      this.bn.toBuffer({ size: 32 })])
  }

  return Base58Check.encode(buf)
}

/**
 * Will return the private key as a BN instance
 *
 * @returns {BN} A BN instance of the private key
 */
PrivateKey.prototype.toBigNumber = function (this: PrivateKey): BN {
  return this.bn
}

/**
 * Will return the private key as a BN buffer
 *
 * @returns {Buffer} A buffer of the private key
 */
PrivateKey.prototype.toBuffer = function (this: PrivateKey): Buffer {
  return this.bn.toBuffer({ size: 32 })
}

PrivateKey.prototype.toHex = function (this: PrivateKey): string {
  return this.toBuffer().toString('hex')
}

/**
 * Will return the corresponding public key
 *
 * @returns {PublicKey} A public key generated from the private key
 */
PrivateKey.prototype.toPublicKey = function (this: PrivateKey) {
  if (this._pubkey == null) {
    this._pubkey = publicKeyCtor().fromPrivateKey(this)
  }
  return this._pubkey
}

/**
 * Will return an address for the private key
 * @param {Network=} network - optional parameter specifying
 * the desired network for the address
 *
 * @returns {Address} An address generated from the private key
 */
PrivateKey.prototype.toAddress = function (this: PrivateKey, network?: unknown): unknown {
  const pubkey = this.toPublicKey()
  return addressCtor().fromPublicKey(pubkey, network || this.network)
}

/**
 * A plain object representation, including the secret scalar.
 *
 * This is the deliberate, explicit export — the round-trip partner of
 * `PrivateKey.fromObject()`. It is NOT what `JSON.stringify()` calls; see `toJSON`.
 *
 * @returns {Object} A plain object representation
 */
PrivateKey.prototype.toObject = function toObject (this: PrivateKey): Record<string, unknown> {
  return {
    bn: this.bn.toString('hex'),
    compressed: this.compressed,
    network: this.network.toString()
  }
}

/**
 * What `JSON.stringify()` calls — deliberately REDACTED.
 *
 * `toJSON` used to be the same function as `toObject`, so the secret scalar was emitted
 * by anything that stringified a key, or an object holding one: a log line, an error
 * dump, a request body. That is how a private key reached an OP_RETURN in the GDAF
 * anchor path. Serialising a key is now something you have to ask for by name.
 *
 * Use `toObject()` (or `toWIF()`) when you genuinely intend to export the secret;
 * `PrivateKey.fromObject(key.toObject())` still round-trips exactly.
 *
 * @returns {Object} A redacted representation, safe to log
 */
PrivateKey.prototype.toJSON = function toJSON (this: PrivateKey): Record<string, unknown> {
  return {
    bn: REDACTED,
    compressed: this.compressed,
    network: this.network.toString()
  }
}

/**
 * Will return a string formatted for the console
 *
 * @returns {string} Private key
 */
PrivateKey.prototype.inspect = function (this: PrivateKey): string {
  const uncompressed = !this.compressed ? ', uncompressed' : ''
  return '<PrivateKey: ' + this.toHex() + ', network: ' + this.network + uncompressed + '>'
}

export = PrivateKey
