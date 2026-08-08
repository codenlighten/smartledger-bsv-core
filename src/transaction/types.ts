/**
 * Shapes for the transaction modules.
 *
 * Separate from the implementations because those use `export =` to keep their
 * CommonJS require() shape, and TypeScript forbids an export assignment
 * alongside other exported members.
 */
import type Signature = require('../crypto/signature')
import type { PublicKey } from '../publickey.types'

/** The plain-object form of a transaction signature. */
export interface TransactionSignatureObj {
  publicKey: PublicKey | string
  prevTxId: Buffer | string
  outputIndex: number
  inputIndex: number
  signature: Signature | Buffer | string
  sigtype: number
}

/** A signature together with the input it signs. Extends crypto/Signature. */
export interface TransactionSignature extends Signature {
  publicKey: PublicKey
  prevTxId: Buffer
  outputIndex: number
  inputIndex: number
  signature: Signature
  sigtype: number

  _fromObject: (arg: TransactionSignatureObj) => TransactionSignature
  _checkObjectArgs: (arg: TransactionSignatureObj) => void
  toObject: () => Record<string, unknown>
  toJSON: () => Record<string, unknown>
}

export interface TransactionSignatureConstructor {
  new (arg: TransactionSignatureObj | TransactionSignature): TransactionSignature
  (arg: TransactionSignatureObj | TransactionSignature): TransactionSignature
  fromObject: (object: TransactionSignatureObj) => TransactionSignature
}
