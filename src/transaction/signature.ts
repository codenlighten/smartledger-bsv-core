'use strict'

import _ = require('../util/_')
import $ = require('../util/preconditions')
import inherits = require('inherits')
import JSUtil = require('../util/js')
import errors = require('../errors')
import Signature = require('../crypto/signature')
import type {
  TransactionSignature,
  TransactionSignatureObj,
  TransactionSignatureConstructor
} from './types'
import type { PublicKeyConstructor } from '../publickey.types'

// Runtime edge into the cycle. Required lazily at call time rather than at
// module scope so nothing is dereferenced during evaluation — see
// scripts/check-cycle-safety.js for why that distinction matters under ESM.
const publicKeyCtor = (): PublicKeyConstructor => require('../publickey')

/**
 * @desc
 * Wrapper around Signature with fields related to signing a transaction specifically
 *
 * @param {Object|string|TransactionSignature} arg
 * @constructor
 */
const TransactionSignature = function TransactionSignature (this: TransactionSignature, arg: TransactionSignatureObj | TransactionSignature) {
  if (!(this instanceof TransactionSignature)) {
    return new (TransactionSignature as TransactionSignatureConstructor)(arg)
  }
  if (arg instanceof TransactionSignature) {
    return arg
  }
  if (_.isObject(arg)) {
    return this._fromObject(arg as TransactionSignatureObj)
  }
  throw new (errors.InvalidArgument as new (m: string) => Error)('TransactionSignatures must be instantiated from an object')
} as unknown as TransactionSignatureConstructor
inherits(TransactionSignature, Signature)

TransactionSignature.prototype._fromObject = function (this: TransactionSignature, arg: TransactionSignatureObj): TransactionSignature {
  this._checkObjectArgs(arg)
  this.publicKey = new (publicKeyCtor())(arg.publicKey)
  this.prevTxId = Buffer.isBuffer(arg.prevTxId) ? arg.prevTxId : Buffer.from(arg.prevTxId, 'hex')
  this.outputIndex = arg.outputIndex
  this.inputIndex = arg.inputIndex
  this.signature = (arg.signature instanceof (Signature as unknown as new () => Signature))
    ? arg.signature as Signature
    : Buffer.isBuffer(arg.signature)
      ? Signature.fromBuffer(arg.signature)
      : Signature.fromString(arg.signature as string)
  this.sigtype = arg.sigtype
  return this
}

TransactionSignature.prototype._checkObjectArgs = function (arg: TransactionSignatureObj): void {
  $.checkArgument(publicKeyCtor()(arg.publicKey), 'publicKey')
  $.checkArgument(!_.isUndefined(arg.inputIndex), 'inputIndex')
  $.checkArgument(!_.isUndefined(arg.outputIndex), 'outputIndex')
  $.checkState(_.isNumber(arg.inputIndex), 'inputIndex must be a number')
  $.checkState(_.isNumber(arg.outputIndex), 'outputIndex must be a number')
  $.checkArgument(arg.signature, 'signature')
  $.checkArgument(arg.prevTxId, 'prevTxId')
  $.checkState(arg.signature instanceof Signature ||
               Buffer.isBuffer(arg.signature) ||
               JSUtil.isHexa(arg.signature), 'signature must be a buffer or hexa value')
  $.checkState(Buffer.isBuffer(arg.prevTxId) ||
               JSUtil.isHexa(arg.prevTxId), 'prevTxId must be a buffer or hexa value')
  $.checkArgument(arg.sigtype, 'sigtype')
  $.checkState(_.isNumber(arg.sigtype), 'sigtype must be a number')
}

/**
 * Serializes a transaction to a plain JS object
 * @return {Object}
 */
TransactionSignature.prototype.toObject = TransactionSignature.prototype.toJSON = function toObject (this: TransactionSignature): Record<string, unknown> {
  return {
    publicKey: this.publicKey.toString(),
    prevTxId: this.prevTxId.toString('hex'),
    outputIndex: this.outputIndex,
    inputIndex: this.inputIndex,
    signature: this.signature.toString(),
    sigtype: this.sigtype
  }
}

/**
 * Builds a TransactionSignature from an object
 * @param {Object} object
 * @return {TransactionSignature}
 */
TransactionSignature.fromObject = function (object: TransactionSignatureObj): TransactionSignature {
  $.checkArgument(object)
  return new (TransactionSignature as TransactionSignatureConstructor)(object)
}

export = TransactionSignature
