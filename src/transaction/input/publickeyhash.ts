'use strict'

import inherits = require('inherits')

const $ = require('../../util/preconditions')

import Hash = require('../../crypto/hash')
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
 * Represents a special kind of input of PayToPublicKeyHash kind.
 * @constructor
 */
const PublicKeyHashInput = function PublicKeyHashInput (this: SigningInput) {
  Input.apply(this, arguments as unknown as [])
} as unknown as SigningInputConstructor
inherits(PublicKeyHashInput, Input)

/**
 * @param {Transaction} transaction - the transaction to be signed
 * @param {PrivateKey} privateKey - the private key with which to sign the transaction
 * @param {number} index - the index of the input in the transaction input vector
 * @param {number=} sigtype - the type of signature, defaults to Signature.SIGHASH_ALL
 * @param {Buffer=} hashData - the precalculated hash of the public key associated with the privateKey provided
 * @return {Array} of objects that can be
 */
PublicKeyHashInput.prototype.getSignatures = function (this: SigningInput, transaction: Transaction, privateKey: PrivateKey, index: number, sigtype?: number, hashData?: Buffer): unknown[] {
  $.checkState(this.output instanceof (OutputImpl as unknown as new () => unknown))
  hashData = hashData || Hash.sha256ripemd160(privateKey.publicKey.toBuffer())
  sigtype = sigtype || (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

  // The dispatcher (Transaction._fromNonP2SH) may have routed a "P2PKH +
  // trailing data" script here via isPublicKeyHashOutPrefix() — in which
  // case the strict getPublicKeyHash() would throw. Read the 20-byte hash
  // directly from chunks[2] (validated by the prefix check at dispatch).
  const chunk = (this.output as OutputType).script.chunks[2]
  const scriptPkh = chunk?.buf
  if (scriptPkh != null && hashData.equals(scriptPkh)) {
    return [new TransactionSignature({
      publicKey: privateKey.publicKey,
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
 * @return {PublicKeyHashInput} this, for chaining
 */
PublicKeyHashInput.prototype.addSignature = function (this: SigningInput, transaction: Transaction, signature: TransactionSignature): SigningInput {
  $.checkState(this.isValidSignature(transaction, signature), 'Signature is invalid')

  this.setScript(scriptClass().buildPublicKeyHashIn(
    signature.publicKey,
    signature.signature.toDER(),
    signature.sigtype
  ))
  return this
}

/**
 * Clear the input's signature
 * @return {PublicKeyHashInput} this, for chaining
 */
PublicKeyHashInput.prototype.clearSignatures = function (this: SigningInput): SigningInput {
  this.setScript(scriptClass().empty())
  return this
}

/**
 * Query whether the input is signed
 * @return {boolean}
 */
PublicKeyHashInput.prototype.isFullySigned = function (this: SigningInput): boolean {
  return (this.script as Script).isPublicKeyHashIn()
}

// 32   txid
// 4    output index
// --- script ---
// 1    script size (VARINT)
// 1    signature size (OP_PUSHDATA)
// <=72 signature (DER + SIGHASH type)
// 1    public key size (OP_PUSHDATA)
// 33   compressed public key
//
// 4    sequence number
PublicKeyHashInput.SCRIPT_MAX_SIZE = 108

PublicKeyHashInput.prototype._estimateSize = function (this: SigningInput): number {
  return Input.BASE_SIZE + (PublicKeyHashInput.SCRIPT_MAX_SIZE as number)
}

export = PublicKeyHashInput
