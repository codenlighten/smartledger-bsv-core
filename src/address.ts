'use strict'

import _ = require('./util/_')
import $ = require('./util/preconditions')
import errors = require('./errors')
import Base58Check = require('./encoding/base58check')
import Networks = require('./networks')
import Hash = require('./crypto/hash')
import JSUtil = require('./util/js')
import type { Address, AddressConstructor, AddressInfo, AddressType } from './address.types'
import type { PublicKeyConstructor } from './publickey.types'

// Resolved on demand for the same reason as scriptClass() below: publickey is
// in this cycle, so capturing it at load time is order dependent.
const publicKeyClass = (): PublicKeyConstructor => require('./publickey')

/**
 * Instantiate an address from an address String or Buffer, a public key or script hash Buffer,
 * or an instance of {@link PublicKey} or {@link Script}.
 *
 * This is an immutable class, and if the first parameter provided to this constructor is an
 * `Address` instance, the same argument will be returned.
 *
 * An address has two key properties: `network` and `type`. The type is either
 * `Address.PayToPublicKeyHash` (value is the `'pubkeyhash'` string)
 * or `Address.PayToScriptHash` (the string `'scripthash'`). The network is an instance of {@link Network}.
 * You can quickly check whether an address is of a given kind by using the methods
 * `isPayToPublicKeyHash` and `isPayToScriptHash`
 *
 * @example
 * ```javascript
 * // validate that an input field is valid
 * var error = Address.getValidationError(input, 'testnet');
 * if (!error) {
 *   var address = Address(input, 'testnet');
 * } else {
 *   // invalid network or checksum (typo?)
 *   var message = error.messsage;
 * }
 *
 * // get an address from a public key
 * var address = Address(publicKey, 'testnet').toString();
 * ```
 *
 * @param {*} data - The encoded data in various formats
 * @param {Network|String|number=} network - The network: 'livenet' or 'testnet'
 * @param {string=} type - The type of address: 'script' or 'pubkey'
 * @returns {Address} A new valid and frozen instance of an Address
 * @constructor
 */
const Address = function Address (this: Address, data: unknown, network?: unknown, type?: AddressType) {
  if (!(this instanceof Address)) {
    return new (Address as AddressConstructor)(data, network, type)
  }

  if (_.isArray(data) && _.isNumber(network)) {
    return (Address as AddressConstructor).createMultisig(data as unknown[], network, type)
  }

  if (data instanceof (Address as unknown as new () => unknown)) {
    // Immutable instance
    return data as Address
  }

  $.checkArgument(data, 'First argument is required, please include address data.', 'guide/address.html')

  if (network != null && Networks.get(network as string | number) == null) {
    throw new TypeError('Second argument must be "livenet", "testnet", or "regtest".')
  }

  if (type != null && (type !== (Address as AddressConstructor).PayToPublicKeyHash && type !== (Address as AddressConstructor).PayToScriptHash)) {
    throw new TypeError('Third argument must be "pubkeyhash" or "scripthash".')
  }

  const info = this._classifyArguments(data, network, type)

  // set defaults if not set
  info.network = info.network ?? Networks.get(network as string | number) ?? Networks.defaultNetwork
  info.type = info.type ?? type ?? (Address as AddressConstructor).PayToPublicKeyHash

  JSUtil.defineImmutable(this, {
    hashBuffer: info.hashBuffer,
    network: info.network,
    type: info.type
  })

  return this
} as unknown as AddressConstructor

/**
 * Internal function used to split different kinds of arguments of the constructor
 * @param {*} data - The encoded data in various formats
 * @param {Network|String|number=} network - The network: 'livenet' or 'testnet'
 * @param {string=} type - The type of address: 'script' or 'pubkey'
 * @returns {Object} An "info" object with "type", "network", and "hashBuffer"
 */
Address.prototype._classifyArguments = function (this: Address, data: unknown, network?: unknown, type?: AddressType): AddressInfo {
  // transform and validate input data
  if ((data instanceof Buffer || data instanceof Uint8Array) && data.length === 20) {
    return (Address as AddressConstructor)._transformHash(Buffer.from(data))
  } else if ((data instanceof Buffer || data instanceof Uint8Array) && data.length === 21) {
    return (Address as AddressConstructor)._transformBuffer(Buffer.from(data), network, type)
  } else if (data instanceof (publicKeyClass() as unknown as new () => unknown)) {
    return (Address as AddressConstructor)._transformPublicKey(data)
  } else if (isScript(data)) {
    return (Address as AddressConstructor)._transformScript(data, network)
  } else if (typeof (data) === 'string') {
    return (Address as AddressConstructor)._transformString(data, network, type)
  } else if (_.isObject(data)) {
    return (Address as AddressConstructor)._transformObject(data as Record<string, unknown>)
  } else {
    throw new TypeError('First argument is an unrecognized data format.')
  }
}

/** @static */
Address.PayToPublicKeyHash = 'pubkeyhash'
/** @static */
Address.PayToScriptHash = 'scripthash'

/**
 * @param {Buffer} hash - An instance of a hash Buffer
 * @returns {Object} An object with keys: hashBuffer
 * @private
 */
Address._transformHash = function (hash: Buffer): AddressInfo {
  const info: AddressInfo = {}
  if (!(hash instanceof Buffer) && !(hash instanceof Uint8Array)) {
    throw new TypeError('Address supplied is not a buffer.')
  }
  if (hash.length !== 20) {
    throw new TypeError('Address hashbuffers must be exactly 20 bytes.')
  }
  info.hashBuffer = hash
  return info
}

/**
 * Deserializes an address serialized through `Address#toObject()`
 * @param {Object} data
 * @param {string} data.hash - the hash that this address encodes
 * @param {string} data.type - either 'pubkeyhash' or 'scripthash'
 * @param {Network=} data.network - the name of the network associated
 * @return {Address}
 */
Address._transformObject = function (data: Record<string, unknown>): AddressInfo {
  $.checkArgument(data.hash || data.hashBuffer, 'Must provide a `hash` or `hashBuffer` property')
  $.checkArgument(data.type, 'Must provide a `type` property')
  return {
    hashBuffer: data.hash != null
      ? Buffer.from(data.hash as string, 'hex')
      : data.hashBuffer as Buffer,
    network: Networks.get(data.network as string | number) ?? Networks.defaultNetwork,
    type: data.type as AddressType
  }
}

/**
 * Internal function to discover the network and type based on the first data byte
 *
 * @param {Buffer} buffer - An instance of a hex encoded address Buffer
 * @returns {Object} An object with keys: network and type
 * @private
 */
Address._classifyFromVersion = function (buffer: Buffer): AddressInfo {
  const version: AddressInfo = {}

  // The caller has already length-checked the buffer, so byte 0 is present.
  const versionByte = buffer[0] as number
  const pubkeyhashNetwork = Networks.get(versionByte, 'pubkeyhash')
  const scripthashNetwork = Networks.get(versionByte, 'scripthash')

  if (pubkeyhashNetwork != null) {
    version.network = pubkeyhashNetwork
    version.type = (Address as AddressConstructor).PayToPublicKeyHash
  } else if (scripthashNetwork != null) {
    version.network = scripthashNetwork
    version.type = (Address as AddressConstructor).PayToScriptHash
  }

  return version
}

/**
 * Internal function to transform a bitcoin address buffer
 *
 * @param {Buffer} buffer - An instance of a hex encoded address Buffer
 * @param {string=} network - The network: 'livenet' or 'testnet'
 * @param {string=} type - The type: 'pubkeyhash' or 'scripthash'
 * @returns {Object} An object with keys: hashBuffer, network and type
 * @private
 */
Address._transformBuffer = function (buffer: Buffer, network?: unknown, type?: AddressType): AddressInfo {
  const info: AddressInfo = {}
  if (!(buffer instanceof Buffer) && !(buffer instanceof Uint8Array)) {
    throw new TypeError('Address supplied is not a buffer.')
  }
  if (buffer.length !== 1 + 20) {
    throw new TypeError('Address buffers must be exactly 21 bytes.')
  }

  const networkObj = Networks.get(network as string | number)
  const bufferVersion = Address._classifyFromVersion(buffer)

  if (network && !networkObj) {
    throw new TypeError('Unknown network')
  }

  if (!bufferVersion.network || (networkObj && networkObj !== bufferVersion.network)) {
    // console.log(bufferVersion)
    throw new TypeError('Address has mismatched network type.')
  }

  if (!bufferVersion.type || (type && type !== bufferVersion.type)) {
    throw new TypeError('Address has mismatched type.')
  }

  info.hashBuffer = buffer.slice(1)
  info.network = bufferVersion.network
  info.type = bufferVersion.type
  return info
}

/**
 * Internal function to transform a {@link PublicKey}
 *
 * @param {PublicKey} pubkey - An instance of PublicKey
 * @returns {Object} An object with keys: hashBuffer, type
 * @private
 */
Address._transformPublicKey = function (pubkey: unknown): AddressInfo {
  const info: AddressInfo = {}
  if (!(pubkey instanceof (publicKeyClass() as unknown as new () => unknown))) {
    throw new TypeError('Address must be an instance of PublicKey.')
  }
  info.hashBuffer = Hash.sha256ripemd160((pubkey as { toBuffer: () => Buffer }).toBuffer())
  info.type = (Address as AddressConstructor).PayToPublicKeyHash
  return info
}

/**
 * Internal function to transform a {@link Script} into a `info` object.
 *
 * @param {Script} script - An instance of Script
 * @returns {Object} An object with keys: hashBuffer, type
 * @private
 */
Address._transformScript = function (script: any, network?: unknown): AddressInfo {
  $.checkArgument(isScript(script), 'script must be a Script instance')
  const info = script.getAddressInfo(network)
  // NOTE: getAddressInfo() returns `false` (not null/undefined) for a script
  // that is not p2pkh/p2sh, so this must stay a FALSY check. Narrowing it to
  // `info == null` lets `false` through, and the caller then tries to set
  // .network on a boolean.
  if (info === false || info == null) {
    throw new ((errors.Script as Record<string, unknown>).CantDeriveAddress as new (s: unknown) => Error)(script)
  }
  return info
}

/**
 * Creates a P2SH address from a set of public keys and a threshold.
 *
 * The addresses will be sorted lexicographically, as that is the trend in bitcoin.
 * To create an address from unsorted public keys, use the {@link Script#buildMultisigOut}
 * interface.
 *
 * @param {Array} publicKeys - a set of public keys to create an address
 * @param {number} threshold - the number of signatures needed to release the funds
 * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
 * @return {Address}
 */
Address.createMultisig = function (publicKeys: unknown[], threshold: number, network?: unknown): Address {
  const net = network ?? (publicKeys[0] as { network?: unknown })?.network ?? Networks.defaultNetwork
  return (Address as AddressConstructor).payingTo(scriptClass().buildMultisigOut(publicKeys, threshold), net)
}

/**
 * Internal function to transform a bitcoin cash address string
 *
 * @param {string} data
 * @param {String|Network=} network - either a Network instance, 'livenet', or 'testnet'
 * @param {string=} type - The type: 'pubkeyhash' or 'scripthash'
 * @returns {Object} An object with keys: hashBuffer, network and type
 * @private
 */
Address._transformString = function (data: string, network?: unknown, type?: AddressType): AddressInfo {
  if (typeof (data) !== 'string') {
    throw new TypeError('data parameter supplied is not a string.')
  }
  if (data.length < 27) {
    throw new Error('Invalid Address string provided')
  }
  data = data.trim()
  const networkObj = Networks.get(network as string | number)

  if (network && !networkObj) {
    throw new TypeError('Unknown network')
  }

  const addressBuffer = Base58Check.decode(data)
  return Address._transformBuffer(addressBuffer, network, type)
}

/**
 * Instantiate an address from a PublicKey instance
 *
 * @param {PublicKey} data
 * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
 * @returns {Address} A new valid and frozen instance of an Address
 */
Address.fromPublicKey = function (data: unknown, network?: unknown): Address {
  const info = Address._transformPublicKey(data)
  network = network || Networks.defaultNetwork
  return new (Address as AddressConstructor)(info.hashBuffer, network, info.type)
}

/**
 * Instantiate an address from a PrivateKey instance
 *
 * @param {PrivateKey} privateKey
 * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
 * @returns {Address} A new valid and frozen instance of an Address
 */
Address.fromPrivateKey = function (privateKey: any, network?: unknown): Address {
  const publicKey = publicKeyClass().fromPrivateKey(privateKey)
  network = network || privateKey.network || Networks.defaultNetwork
  return Address.fromPublicKey(publicKey, network)
}

/**
 * Instantiate an address from a ripemd160 public key hash
 *
 * @param {Buffer} hash - An instance of buffer of the hash
 * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
 * @returns {Address} A new valid and frozen instance of an Address
 */
Address.fromPublicKeyHash = function (hash: Buffer, network?: unknown): Address {
  const info = Address._transformHash(hash)
  return new (Address as AddressConstructor)(info.hashBuffer, network, Address.PayToPublicKeyHash)
}

/**
 * Instantiate an address from a ripemd160 script hash
 *
 * @param {Buffer} hash - An instance of buffer of the hash
 * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
 * @returns {Address} A new valid and frozen instance of an Address
 */
Address.fromScriptHash = function (hash: Buffer, network?: unknown): Address {
  $.checkArgument(hash, 'hash parameter is required')
  const info = Address._transformHash(hash)
  return new (Address as AddressConstructor)(info.hashBuffer, network, Address.PayToScriptHash)
}

/**
 * Builds a p2sh address paying to script. This will hash the script and
 * use that to create the address.
 * If you want to extract an address associated with a script instead,
 * see {{Address#fromScript}}
 *
 * @param {Script} script - An instance of Script
 * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
 * @returns {Address} A new valid and frozen instance of an Address
 */
Address.payingTo = function (script: any, network?: unknown): Address {
  $.checkArgument(script, 'script is required')
  $.checkArgument(isScript(script), 'script must be instance of Script')

  return Address.fromScriptHash(Hash.sha256ripemd160(script.toBuffer()), network)
}

/**
 * Extract address from a Script. The script must be of one
 * of the following types: p2pkh input, p2pkh output, p2sh input
 * or p2sh output.
 * This will analyze the script and extract address information from it.
 * If you want to transform any script to a p2sh Address paying
 * to that script's hash instead, use {{Address#payingTo}}
 *
 * @param {Script} script - An instance of Script
 * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
 * @returns {Address} A new valid and frozen instance of an Address
 */
Address.fromScript = function (script: any, network?: unknown): Address {
  $.checkArgument(isScript(script), 'script must be a Script instance')
  const info = Address._transformScript(script, network)
  return new (Address as AddressConstructor)(info.hashBuffer, network, info.type)
}

/**
 * Instantiate an address from a buffer of the address
 *
 * @param {Buffer} buffer - An instance of buffer of the address
 * @param {String|Network=} network - either a Network instance, 'livenet', or 'testnet'
 * @param {string=} type - The type of address: 'script' or 'pubkey'
 * @returns {Address} A new valid and frozen instance of an Address
 */
Address.fromBuffer = function (buffer: Buffer, network?: unknown, type?: AddressType): Address {
  const info = Address._transformBuffer(buffer, network, type)
  return new (Address as AddressConstructor)(info.hashBuffer, info.network, info.type)
}

Address.fromHex = function (hex: string, network?: unknown, type?: AddressType): Address {
  return Address.fromBuffer(Buffer.from(hex, 'hex'), network, type)
}

/**
 * Instantiate an address from an address string
 *
 * @param {string} str - An string of the bitcoin address
 * @param {String|Network=} network - either a Network instance, 'livenet', or 'testnet'
 * @param {string=} type - The type of address: 'script' or 'pubkey'
 * @returns {Address} A new valid and frozen instance of an Address
 */
Address.fromString = function (str: string, network?: unknown, type?: AddressType): Address {
  const info = Address._transformString(str, network, type)
  return new (Address as AddressConstructor)(info.hashBuffer, info.network, info.type)
}

/**
 * Instantiate an address from an Object
 *
 * @param {string} json - An JSON string or Object with keys: hash, network and type
 * @returns {Address} A new valid instance of an Address
 */
Address.fromObject = function fromObject (obj: Record<string, unknown>): Address {
  $.checkState(
    JSUtil.isHexa(obj.hash),
    'Unexpected hash property, "' + obj.hash + '", expected to be hex.'
  )
  const hashBuffer = Buffer.from(obj.hash as string, 'hex')
  return new (Address as AddressConstructor)(hashBuffer, obj.network, obj.type as AddressType)
}

/**
 * Will return a validation error if exists
 *
 * @example
 * ```javascript
 * // a network mismatch error
 * var error = Address.getValidationError('15vkcKf7gB23wLAnZLmbVuMiiVDc1Nm4a2', 'testnet');
 * ```
 *
 * @param {string} data - The encoded data
 * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
 * @param {string} type - The type of address: 'script' or 'pubkey'
 * @returns {null|Error} The corresponding error message
 */
Address.getValidationError = function (data: unknown, network?: unknown, type?: AddressType): Error | undefined {
  let error: Error | undefined
  try {
    new (Address as AddressConstructor)(data, network, type) // eslint-disable-line no-new
  } catch (e) {
    error = e as Error
  }
  return error
}

/**
 * Will return a boolean if an address is valid
 *
 * @example
 * ```javascript
 * assert(Address.isValid('15vkcKf7gB23wLAnZLmbVuMiiVDc1Nm4a2', 'livenet'));
 * ```
 *
 * @param {string} data - The encoded data
 * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
 * @param {string} type - The type of address: 'script' or 'pubkey'
 * @returns {boolean} The corresponding error message
 */
Address.isValid = function (data: unknown, network?: unknown, type?: AddressType): boolean {
  return !Address.getValidationError(data, network, type)
}

/**
 * Returns true if an address is of pay to public key hash type
 * @return boolean
 */
Address.prototype.isPayToPublicKeyHash = function (this: Address): boolean {
  return this.type === Address.PayToPublicKeyHash
}

/**
 * Returns true if an address is of pay to script hash type
 * @return boolean
 */
Address.prototype.isPayToScriptHash = function (this: Address): boolean {
  return this.type === Address.PayToScriptHash
}

/**
 * Will return a buffer representation of the address
 *
 * @returns {Buffer} Bitcoin address buffer
 */
Address.prototype.toBuffer = function (this: Address): Buffer {
  const version = Buffer.from([this.network[this.type]])
  const buf = Buffer.concat([version, this.hashBuffer])
  return buf
}

Address.prototype.toHex = function (this: Address): string {
  return this.toBuffer().toString('hex')
}

/**
 * @returns {Object} A plain object with the address information
 */
Address.prototype.toObject = Address.prototype.toJSON = function toObject (this: Address): Record<string, unknown> {
  return {
    hash: this.hashBuffer.toString('hex'),
    type: this.type,
    network: this.network.toString()
  }
}

/**
 * Will return a string formatted for the console
 *
 * @returns {string} Bitcoin address
 */
Address.prototype.inspect = function (this: Address): string {
  return '<Address: ' + this.toString() + ', type: ' + this.type + ', network: ' + this.network + '>'
}

/**
 * Will return a the base58 string representation of the address
 *
 * @returns {string} Bitcoin address
 */
Address.prototype.toString = function (this: Address): string {
  return Base58Check.encode(this.toBuffer())
}

export = Address

// Resolved on demand rather than captured at load time.
//
// This used to be `var Script = require('./script')` placed after
// `module.exports` — the CommonJS idiom for breaking a cycle by exporting
// before requiring the partner. It only works if address is loaded FIRST.
// Require lib/script before lib/address and this captured a partially
// initialized module, making `x instanceof Script` throw
// "Right-hand side of 'instanceof' is not callable". That is reachable in the
// wild, since deep imports are public API. Resolving at call time instead
// always yields the finished module.
function scriptClass (): any {
  return require('./script')
}

// Structural test for a Script, used instead of `instanceof`.
//
// Constructor identity is exactly what is unreliable across a require cycle,
// and every caller here immediately uses the object as a Script. Testing for
// the capability being relied upon is both load-order independent and a more
// honest statement of the requirement.
function isScript (v: unknown): boolean {
  const o = v as { toBuffer?: unknown, getAddressInfo?: unknown, chunks?: unknown }
  return o != null &&
    typeof o.toBuffer === 'function' &&
    typeof o.getAddressInfo === 'function' &&
    Array.isArray(o.chunks)
}
