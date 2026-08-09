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

/** A transaction. */
export interface Transaction {
  inputs: Input[]
  outputs: Output[]
  version: number
  nLockTime: number
  // All optional-and-explicitly-undefined: the constructor and the fee
  // machinery clear them by assignment, which exactOptionalPropertyTypes
  // distinguishes from absence.
  _inputAmount?: number | undefined
  _outputAmount?: number | undefined
  _changeScript?: import('../script/script.types').Script | undefined
  _changeIndex?: number | undefined
  _fee?: number | undefined
  _feePerKb?: number | undefined
  _hash?: string | undefined

  readonly hash: string
  readonly id: string
  readonly inputAmount: number
  readonly outputAmount: number

  // Generated from the prototype assignments in transaction.ts. Typed loosely
  // on purpose: this is the widest surface in the library, and inventing 64
  // signatures during a behaviour-preserving conversion would mean 64 chances
  // to be wrong about one. Tightening them, method by method against their
  // tests, is API-pass work.
  _addOutput: (...args: any[]) => any
  _checkConsistency: (...args: any[]) => any
  _clearSignatures: (...args: any[]) => any
  _estimateFee: (...args: any[]) => any
  _estimateSize: (...args: any[]) => any
  _fromMultisigUtxo: (...args: any[]) => any
  _fromNonP2SH: (...args: any[]) => any
  _getHash: (...args: any[]) => any
  _getInputAmount: (...args: any[]) => any
  _getOutputAmount: (...args: any[]) => any
  _getUnspentValue: (...args: any[]) => any
  _hasDustOutputs: (...args: any[]) => any
  _hasFeeError: (...args: any[]) => any
  _isMissingSignatures: (...args: any[]) => any
  _missingChange: (...args: any[]) => any
  _newOutputOrder: (...args: any[]) => any
  _newTransaction: (...args: any[]) => any
  _removeOutput: (...args: any[]) => any
  _updateChangeOutput: (...args: any[]) => any
  addData: (...args: any[]) => any
  addInput: (...args: any[]) => any
  addOutput: (...args: any[]) => any
  addSafeData: (...args: any[]) => any
  applySignature: (...args: any[]) => any
  change: (...args: any[]) => any
  checkedSerialize: (...args: any[]) => any
  clearOutputs: (...args: any[]) => any
  fee: (...args: any[]) => any
  feePerKb: (...args: any[]) => any
  from: (...args: any[]) => any
  fromBuffer: (...args: any[]) => any
  fromBufferReader: (...args: any[]) => any
  fromObject: (...args: any[]) => any
  fromString: (...args: any[]) => any
  getChangeOutput: (...args: any[]) => any
  getFee: (...args: any[]) => any
  getLockTime: (...args: any[]) => any
  getSerializationError: (...args: any[]) => any
  getSignatures: (...args: any[]) => any
  hasAllUtxoInfo: (...args: any[]) => any
  inspect: (...args: any[]) => any
  invalidSatoshis: (...args: any[]) => any
  isCoinbase: (...args: any[]) => any
  isFullySigned: (...args: any[]) => any
  isValidSignature: (...args: any[]) => any
  lockUntilBlockHeight: (...args: any[]) => any
  lockUntilDate: (...args: any[]) => any
  removeInput: (...args: any[]) => any
  removeOutput: (...args: any[]) => any
  serialize: (...args: any[]) => any
  shuffleOutputs: (...args: any[]) => any
  sighash: (...args: any[]) => any
  sign: (...args: any[]) => any
  sort: (...args: any[]) => any
  sortInputs: (...args: any[]) => any
  sortOutputs: (...args: any[]) => any
  to: (...args: any[]) => any
  toBuffer: (...args: any[]) => any
  toBufferWriter: (...args: any[]) => any
  toObject: (...args: any[]) => any
  uncheckedAddInput: (...args: any[]) => any
  uncheckedSerialize: (...args: any[]) => any
  verify: (...args: any[]) => any
  verifySignature: (...args: any[]) => any
}

export interface TransactionConstructor {
  new (serialized?: unknown): Transaction
  (serialized?: unknown): Transaction

  // Enumerated rather than reached through an index signature: an index
  // signature would have to be `unknown` (the constructor carries both numbers
  // and functions), which forces a cast at every use — including the fee and
  // dust thresholds, where a wrong value is a real-money bug.
  shallowCopy: (tx: Transaction) => Transaction
  DUST_AMOUNT: number
  FEE_SECURITY_MARGIN: number
  MAX_MONEY: number
  NLOCKTIME_BLOCKHEIGHT_LIMIT: number
  NLOCKTIME_MAX_VALUE: number
  FEE_PER_KB: number
  CHANGE_OUTPUT_MAX_SIZE: number

  /** Attached by transaction/index, not by transaction/transaction itself. */
  Input?: unknown
  Output?: unknown
  UnspentOutput?: unknown
  Signature?: unknown
  Sighash?: unknown
  sighash?: unknown
}
