'use strict'

import inherits = require('inherits')

const $ = require('../../util/preconditions')

import Input = require('./input')
import OutputImpl = require('../output')
import Sighash = require('../sighash')
import type { Script, ScriptConstructor } from '../../script/script.types'
import type { SigningInput, SigningInputConstructor } from '../types'
import type { Output as OutputType } from '../types'

// script is in this cycle, so it is resolved on demand.
const scriptClass = (): ScriptConstructor => require('../../script')
import Signature = require('../../crypto/signature')
import TransactionSignature = require('../signature')
import type { Transaction } from '../types'
import type { PrivateKey } from '../../privatekey.types'
import type { PublicKey } from '../../publickey.types'
import type { BufferReader, BufferWriter } from '../../encoding/types'

/**
 * Represents a special kind of input of PayToPublicKey kind.
 * @constructor
 */
const PublicKeyInput = function PublicKeyInput (this: SigningInput) {
  Input.apply(this, arguments as unknown as [])
} as unknown as SigningInputConstructor
inherits(PublicKeyInput, Input)

/**
 * @param {Transaction} transaction - the transaction to be signed
 * @param {PrivateKey} privateKey - the private key with which to sign the transaction
 * @param {number} index - the index of the input in the transaction input vector
 * @param {number=} sigtype - the type of signature, defaults to Signature.SIGHASH_ALL
 * @return {Array} of objects that can be
 */
PublicKeyInput.prototype.getSignatures = function (this: SigningInput, transaction: Transaction, privateKey: PrivateKey, index: number, sigtype?: number): unknown[] {
  $.checkState(this.output instanceof (OutputImpl as unknown as new () => unknown))
  sigtype = sigtype || (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)
  const publicKey = privateKey.toPublicKey()
  if (publicKey.toString() === (this.output as OutputType).script.getPublicKey().toString('hex')) {
    return [new TransactionSignature({
      publicKey,
      prevTxId: this.prevTxId,
      outputIndex: this.outputIndex,
      inputIndex: index,
      signature: Sighash.sign(transaction, privateKey, sigtype, index, (this.output as OutputType).script, (this.output as OutputType).satoshisBN),
      sigtype
    })]
  }
  return []
}

/**
 * Add the provided signature
 *
 * @param {Object} signature
 * @param {PublicKey} signature.publicKey
 * @param {Signature} signature.signature
 * @param {number=} signature.sigtype
 * @return {PublicKeyInput} this, for chaining
 */
PublicKeyInput.prototype.addSignature = function (this: SigningInput, transaction: Transaction, signature: TransactionSignature): SigningInput {
  $.checkState(this.isValidSignature(transaction, signature), 'Signature is invalid')
  this.setScript(scriptClass().buildPublicKeyIn(
    signature.signature.toDER(),
    signature.sigtype
  ))
  return this
}

/**
 * Clear the input's signature
 * @return {PublicKeyHashInput} this, for chaining
 */
PublicKeyInput.prototype.clearSignatures = function (this: SigningInput): SigningInput {
  this.setScript(scriptClass().empty())
  return this
}

/**
 * Query whether the input is signed
 * @return {boolean}
 */
PublicKeyInput.prototype.isFullySigned = function (this: SigningInput): boolean {
  return (this.script as Script).isPublicKeyIn()
}

// 32   txid
// 4    output index
// ---
// 1    script size (VARINT)
// 1    signature size (OP_PUSHDATA)
// <=72 signature (DER + SIGHASH type)
// ---
// 4    sequence number
PublicKeyInput.SCRIPT_MAX_SIZE = 74

PublicKeyInput.prototype._estimateSize = function (this: SigningInput): number {
  return Input.BASE_SIZE + (PublicKeyInput.SCRIPT_MAX_SIZE as number)
}

export = PublicKeyInput
