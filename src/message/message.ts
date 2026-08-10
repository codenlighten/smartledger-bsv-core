'use strict'

import Hash = require('../crypto/hash')
import _ = require('../util/_')
import PrivateKey = require('../privatekey')
import PublicKey = require('../publickey')
import Address = require('../address')
import BufferWriter = require('../encoding/bufferwriter')
import ECDSA = require('../crypto/ecdsa')
import Signature = require('../crypto/signature')
const sha256sha256 = Hash.sha256sha256
import JSUtil = require('../util/js')
import $ = require('../util/preconditions')
import type { Message, MessageConstructor } from './types'
import type { Signature as SignatureType } from '../crypto/signature.types'

/**
 * constructs a new message to sign and verify.
 *
 * @param {String} message
 * @returns {Message}
 */
const Message = function Message (this: Message, message?: string | Buffer): any {
  if (!(this instanceof Message)) {
    return new (Message as unknown as MessageConstructor)(message as string | Buffer)
  }

  $.checkArgument(_.isString(message) || Buffer.isBuffer(message), 'First argument should be a string or Buffer')

  if (_.isString(message)) {
    this.messageBuffer = Buffer.from(message)
  }

  if (Buffer.isBuffer(message)) {
    this.messageBuffer = message
  }
  return this
} as unknown as MessageConstructor

Message.sign = function (message: string | Buffer, privateKey: PrivateKey) {
  return new Message(message).sign(privateKey)
}

Message.verify = function (message: string | Buffer, address: Address | string, signature: string) {
  return new Message(message).verify(address, signature)
}

Message.MAGIC_BYTES = Buffer.from('Bitcoin Signed Message:\n')

Message.prototype.magicHash = function magicHash (this: Message) {
  const prefix1 = BufferWriter.varintBufNum(Message.MAGIC_BYTES.length)
  const prefix2 = BufferWriter.varintBufNum(this.messageBuffer.length)
  const buf = Buffer.concat([prefix1, Message.MAGIC_BYTES, prefix2, this.messageBuffer])
  const hash = sha256sha256(buf)
  return hash
}

Message.prototype._sign = function _sign (this: Message, privateKey: PrivateKey) {
  $.checkArgument(privateKey instanceof PrivateKey,
    'First argument should be an instance of PrivateKey')
  const hash = this.magicHash()
  return ECDSA.signWithCalcI(hash, privateKey)
}

/**
 * Will sign a message with a given bitcoin private key.
 *
 * @param {PrivateKey} privateKey - An instance of PrivateKey
 * @returns {String} A base64 encoded compact signature
 */
Message.prototype.sign = function sign (this: Message, privateKey: PrivateKey) {
  const signature = this._sign(privateKey)
  return signature.toCompact().toString('base64')
}

Message.prototype._verify = function _verify (this: Message, publicKey: PublicKey, signature: SignatureType) {
  $.checkArgument(publicKey instanceof PublicKey, 'First argument should be an instance of PublicKey')
  $.checkArgument(signature instanceof Signature, 'Second argument should be an instance of Signature')
  const hash = this.magicHash()
  const verified = ECDSA.verify(hash, signature, publicKey)
  if (!verified) {
    this.error = 'The signature was invalid'
  }
  return verified
}

/**
 * Will return a boolean of the signature is valid for a given bitcoin address.
 * If it isn't the specific reason is accessible via the "error" member.
 *
 * @param {Address|String} bitcoinAddress - A bitcoin address
 * @param {String} signatureString - A base64 encoded compact signature
 * @returns {Boolean}
 */
Message.prototype.verify = function verify (this: Message, bitcoinAddress: Address | string, signatureString: string) {
  $.checkArgument(bitcoinAddress)
  $.checkArgument(signatureString && _.isString(signatureString))

  if (_.isString(bitcoinAddress)) {
    bitcoinAddress = Address.fromString(bitcoinAddress)
  }
  const signature = Signature.fromCompact(Buffer.from(signatureString, 'base64'))

  // recover the public key
  const ecdsa = new ECDSA()
  ecdsa.hashbuf = this.magicHash()
  ecdsa.sig = signature
  const publicKey = ecdsa.toPublicKey()

  const signatureAddress = Address.fromPublicKey(publicKey, bitcoinAddress.network)

  // check that the recovered address and specified address match
  if (bitcoinAddress.toString() !== signatureAddress.toString()) {
    this.error = 'The signature did not match the message digest'
    return false
  }

  return this._verify(publicKey, signature)
}

/**
 * Instantiate a message from a message string
 *
 * @param {String} str - A string of the message
 * @returns {Message} A new instance of a Message
 */
Message.fromString = function (str: string | Buffer) {
  return new Message(str)
}

/**
 * Instantiate a message from JSON
 *
 * @param {String} json - An JSON string or Object with keys: message
 * @returns {Message} A new instance of a Message
 */
Message.fromJSON = function fromJSON (json: string | { messageHex: string }) {
  // A JSON string or the already-parsed object; normalize to the object under
  // its own name rather than writing back over the parameter.
  const obj = JSUtil.isValidJSON(json) ? JSON.parse(json as string) : json
  return Message.fromObject(obj as { messageHex: string })
}

/**
 * @returns {Object} A plain object with the message information
 */
Message.prototype.toObject = function toObject (this: Message) {
  return {
    messageHex: this.messageBuffer.toString('hex')
  }
}

Message.fromObject = function (obj: { messageHex: string }) {
  const messageBuffer = Buffer.from(obj.messageHex, 'hex')
  return new Message(messageBuffer)
}

/**
 * @returns {String} A JSON representation of the message information
 */
Message.prototype.toJSON = function toJSON (this: Message) {
  return JSON.stringify(this.toObject())
}

/**
 * Will return a the string representation of the message
 *
 * @returns {String} Message
 */
Message.prototype.toString = function (this: Message) {
  return this.messageBuffer.toString()
}

/**
 * Will return a string formatted for the console
 *
 * @returns {String} Message
 */
Message.prototype.inspect = function (this: Message) {
  return '<Message: ' + this.toString() + '>'
}

export = Message
