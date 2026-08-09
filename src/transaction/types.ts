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

/** A spendable output, as accepted by Transaction#from(). */
export interface UnspentOutput {
  readonly address?: unknown
  readonly txId: string
  readonly outputIndex: number
  readonly script: import('../script/script.types').Script
  readonly satoshis: number

  inspect: () => string
  toString: () => string
  toObject: () => Record<string, unknown>
  toJSON: () => Record<string, unknown>
}

/** The loose object form UnspentOutput accepts; field names vary by source. */
export interface UnspentOutputData {
  address?: unknown
  txid?: string
  txId?: string
  vout?: number
  outputIndex?: number
  scriptPubKey?: unknown
  script?: unknown
  amount?: number
  satoshis?: number
}

export interface UnspentOutputConstructor {
  new (data: UnspentOutputData): UnspentOutput
  (data: UnspentOutputData): UnspentOutput
  fromObject: (data: UnspentOutputData) => UnspentOutput
}

/**
 * A transaction output.
 *
 * `script`, `satoshis` and `satoshisBN` are accessors, not data properties:
 * the script is parsed lazily from `_scriptBuffer` on first read, and setting
 * `satoshis` keeps `_satoshisBN` in sync (and vice versa). The private
 * backing fields are part of the declared shape because the accessors and
 * several methods read them directly.
 */
export interface Output {
  // null (not undefined) when the buffer failed to parse — see setScriptFromBuffer.
  _script?: import('../script/script.types').Script | null
  _scriptBuffer?: Buffer
  _satoshis?: number
  _satoshisBN?: import('bn.js')

  readonly script: import('../script/script.types').Script
  satoshis: number | string | import('bn.js')
  satoshisBN: import('bn.js')

  invalidSatoshis: () => string | false
  toObject: () => Record<string, unknown>
  toJSON: () => Record<string, unknown>
  setScriptFromBuffer: (buffer: Buffer) => void
  setScript: (script: unknown) => Output
  inspect: () => string
  toBufferWriter: (writer?: unknown) => unknown
  getSize: () => number
}

export interface OutputConstructor {
  new (args: { satoshis?: unknown, script?: unknown }): Output
  (args: { satoshis?: unknown, script?: unknown }): Output
  fromObject: (data: Record<string, unknown>) => Output
  fromBufferReader: (br: unknown) => Output
}

/**
 * A transaction input.
 *
 * `script` is an accessor: it parses `_scriptBuffer` lazily, and returns null
 * for a null (coinbase) input rather than an empty Script.
 */
export interface Input {
  prevTxId: Buffer
  outputIndex: number
  sequenceNumber: number
  _script?: import('../script/script.types').Script | null
  _scriptBuffer?: Buffer
  output?: Output | undefined

  readonly script: import('../script/script.types').Script | null

  _fromObject: (params: Record<string, unknown>) => Input
  toObject: () => Record<string, unknown>
  toJSON: () => Record<string, unknown>
  toBufferWriter: (writer?: unknown) => unknown
  setScript: (script: unknown) => Input
  getSignatures: (...args: unknown[]) => unknown[]
  isFullySigned: () => boolean
  isFinal: () => boolean
  addSignature: (...args: unknown[]) => Input
  /** See SigningInput: the return value is not uniform across subclasses. */
  clearSignatures: () => Input | void
  isValidSignature: (transaction: unknown, signature: unknown) => boolean
  isNull: () => boolean
  _estimateSize: () => number
}

export interface InputConstructor {
  new (params?: Record<string, unknown>): Input
  (params?: Record<string, unknown>): Input
  MAXINT: number
  DEFAULT_SEQNUMBER: number
  DEFAULT_LOCKTIME_SEQNUMBER: number
  DEFAULT_RBF_SEQNUMBER: number
  BASE_SIZE: number
  fromObject: (obj: Record<string, unknown>) => Input
  fromBufferReader: (br: unknown) => Input

  // Attached by transaction/input/index, not by input/input itself.
  PublicKey: SigningInputConstructor
  PublicKeyHash: SigningInputConstructor
  MultiSig: MultiSigInputConstructor
  MultiSigScriptHash: MultiSigInputConstructor
}

/**
 * An input subclass that knows how to sign itself.
 *
 * The four variants (PublicKey, PublicKeyHash, MultiSig, MultiSigScriptHash)
 * all extend Input via `inherits` and override the same four members. Their
 * signatures differ in arity — MultiSig-family getSignatures takes no
 * hashData — so the shared type is deliberately permissive there rather than
 * inventing a union that no caller uses.
 */
export interface SigningInput extends Input {
  getSignatures: (...args: unknown[]) => unknown[]
  addSignature: (...args: unknown[]) => SigningInput
  /**
   * Return value is NOT uniform across the four subclasses: PublicKey and
   * PublicKeyHash return `this`, the two MultiSig variants return undefined.
   * Declared as the union rather than picking one, because that is what the
   * implementations actually do. Unifying them would be an API change.
   */
  clearSignatures: () => SigningInput | void
  isFullySigned: () => boolean
  _estimateSize: () => number
}

export interface SigningInputConstructor {
  new (params?: Record<string, unknown>): SigningInput
  (params?: Record<string, unknown>): SigningInput
  SCRIPT_MAX_SIZE?: number
}

/**
 * A multisig signing input.
 *
 * Extends SigningInput with the m-of-n bookkeeping: the sorted public keys,
 * an index from key string to position, the threshold, and a sparse
 * signatures array whose slots line up with publicKeys by index.
 */
export interface MultiSigInput extends SigningInput {
  publicKeys: Array<import('../publickey.types').PublicKey>
  publicKeyIndex: Record<string, number>
  threshold: number
  /** Sparse: index i holds the signature for publicKeys[i], or is empty. */
  signatures: Array<unknown | undefined>

  _deserializeSignatures: (signatures: unknown[]) => Array<unknown | undefined>
  _serializeSignatures: () => Array<unknown | undefined>
  /** Returns undefined, unlike the PublicKey/PublicKeyHash inputs. */
  clearSignatures: () => void
  _updateScript: () => MultiSigInput
  _createSignatures: () => Buffer[]
  countMissingSignatures: () => number
  countSignatures: () => number
  publicKeysWithoutSignature: () => Array<import('../publickey.types').PublicKey>
  isValidSignature: (transaction: unknown, signature: unknown) => boolean
}

/**
 * The P2SH variant additionally carries the redeem script whose hash the
 * output commits to.
 */
export interface MultiSigScriptHashInput extends MultiSigInput {
  redeemScript: import('../script/script.types').Script
}

export interface MultiSigInputConstructor {
  new (input: Record<string, unknown>, pubkeys?: unknown[], threshold?: number, signatures?: unknown[]): MultiSigInput
  (input: Record<string, unknown>, pubkeys?: unknown[], threshold?: number, signatures?: unknown[]): MultiSigInput
  SIGNATURE_SIZE?: number
  OPCODES_SIZE?: number
  PUBKEY_SIZE?: number
  normalizeSignatures?: (transaction: unknown, input: unknown, inputIndex: number, signatures: unknown[], publicKeys: unknown[]) => unknown[]
}
