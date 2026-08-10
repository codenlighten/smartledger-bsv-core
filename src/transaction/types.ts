/**
 * Shapes for the transaction modules.
 *
 * Separate from the implementations because those use `export =` to keep their
 * CommonJS require() shape, and TypeScript forbids an export assignment
 * alongside other exported members.
 */
import type Signature = require('../crypto/signature')
import type { PublicKey } from '../publickey.types'
import type { Address } from '../address.types'
import type { Script } from '../script/script.types'
import type { PrivateKey } from '../privatekey.types'
import type { BufferReader, BufferWriter } from '../encoding/types'
import type BN = require('../crypto/bn')

/**
 * The serialization checks, each of which can be waived individually.
 *
 * `disableAll` is not one flag among five — it short-circuits before any of
 * the others are read, so `{ disableAll: true, disableDustOutputs: false }`
 * still skips the dust check.
 */
export interface SerializeOptions {
  disableAll?: boolean
  disableLargeFees?: boolean
  disableIsFullySigned?: boolean
  disableDustOutputs?: boolean
  disableMoreOutputThanInput?: boolean
}

/** What toObject()/toJSON() emit and fromObject() accepts. */
export interface TransactionObject {
  hash?: string
  version: number
  inputs: Input[]
  outputs: Output[]
  nLockTime: number
  changeScript?: string
  changeIndex?: number
  fee?: number
}

/** One leg of the batch form of `to()`. */
export interface Payment {
  address: Address | string
  satoshis: number
}

/** Anything `from()` accepts as a UTXO: an UnspentOutput or its plain form. */
export type UnspentOutputLike = UnspentOutput | UnspentOutputData

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
  toObject: () => TransactionSignatureObj
  toJSON: () => TransactionSignatureObj
}

export interface TransactionSignatureConstructor {
  new (arg: TransactionSignatureObj | TransactionSignature): TransactionSignature
  (arg: TransactionSignatureObj | TransactionSignature): TransactionSignature
  fromObject: (object: TransactionSignatureObj) => TransactionSignature
}

/** A spendable output, as accepted by Transaction#from(). */
export interface UnspentOutput {
  readonly address?: Address
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
  /**
   * BOTH spellings are accepted, and so are both index spellings and both
   * amount spellings — this shape absorbs the two competing UTXO conventions
   * (bitcoind's `txid`/`vout`/`amount` in BTC, and this library's
   * `txId`/`outputIndex`/`satoshis`). They are all optional because a given
   * payload supplies one spelling of each, never both.
   */
  txid?: string
  txId?: string
  vout?: number
  outputIndex?: number
  scriptPubKey?: string | Script
  script?: string | Script
  /** BTC, not satoshis — multiplied by 1e8 on the way in. */
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
  /**
   * Read and write types differ, and deliberately: the SETTER coerces a
   * number, a decimal string or a BN into satoshis, while the GETTER always
   * returns the coerced number. Declaring one union for both would force every
   * arithmetic use of `output.satoshis` to re-narrow a value that is already a
   * number.
   */
  get satoshis (): number
  set satoshis (value: number | string | import('bn.js'))
  get satoshisBN (): import('bn.js')
  set satoshisBN (value: import('bn.js'))

  invalidSatoshis: () => string | false
  toObject: () => Record<string, unknown>
  toJSON: () => Record<string, unknown>
  setScriptFromBuffer: (buffer: Buffer) => void
  setScript: (script: Script | Buffer | string) => Output
  inspect: () => string
  toBufferWriter: (writer?: BufferWriter) => BufferWriter
  getSize: () => number
}

export interface OutputConstructor {
  new (args: { satoshis?: unknown, script?: unknown }): Output
  (args: { satoshis?: unknown, script?: unknown }): Output
  fromObject: (data: Record<string, unknown>) => Output
  fromBufferReader: (br: BufferReader) => Output
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
  toBufferWriter: (writer?: BufferWriter) => BufferWriter
  setScript: (script: Script | Buffer | string) => Input
  getSignatures: (...args: unknown[]) => TransactionSignature[]
  isFullySigned: () => boolean
  isFinal: () => boolean
  addSignature: (...args: unknown[]) => Input
  /** See SigningInput: the return value is not uniform across subclasses. */
  clearSignatures: () => Input | void
  isValidSignature: (transaction: Transaction, signature: TransactionSignature) => boolean
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
  fromBufferReader: (br: BufferReader) => Input

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
  getSignatures: (...args: unknown[]) => TransactionSignature[]
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
  signatures: Array<TransactionSignature | undefined>

  _deserializeSignatures: (signatures: Array<TransactionSignatureObj | TransactionSignature | undefined>) => Array<TransactionSignature | undefined>
  _serializeSignatures: () => Array<TransactionSignatureObj | undefined>
  /** Returns undefined, unlike the PublicKey/PublicKeyHash inputs. */
  clearSignatures: () => void
  _updateScript: () => MultiSigInput
  _createSignatures: () => Buffer[]
  countMissingSignatures: () => number
  countSignatures: () => number
  publicKeysWithoutSignature: () => Array<import('../publickey.types').PublicKey>
  isValidSignature: (transaction: Transaction, signature: TransactionSignature) => boolean
}

/**
 * The P2SH variant additionally carries the redeem script whose hash the
 * output commits to.
 */
export interface MultiSigScriptHashInput extends MultiSigInput {
  redeemScript: import('../script/script.types').Script
}

export interface MultiSigInputConstructor {
  new (input: Record<string, unknown>, pubkeys?: PublicKey[], threshold?: number, signatures?: Array<TransactionSignature | Buffer>): MultiSigInput
  (input: Record<string, unknown>, pubkeys?: PublicKey[], threshold?: number, signatures?: Array<TransactionSignature | Buffer>): MultiSigInput
  SIGNATURE_SIZE?: number
  OPCODES_SIZE?: number
  PUBKEY_SIZE?: number
  normalizeSignatures?: (transaction: Transaction, input: Input, inputIndex: number, signatures: Buffer[], publicKeys: PublicKey[]) => Array<TransactionSignature | null>
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

  // ---- prototype -----------------------------------------------------------
  //
  // Signatures taken from the implementations, not guessed: every return type
  // below was read off the actual `return` statements in transaction.ts, and
  // the union types are unions because the function genuinely returns more
  // than one shape.

  _getHash: () => Buffer

  /**
   * `unsafe` is ALSO accepted as an options object, in which case it is passed
   * to checkedSerialize as the opts — so `serialize({ disableDustOutputs: true })`
   * runs the checks with that option, while `serialize(true)` skips them all.
   * The two are not variations of one flag.
   */
  serialize: (unsafe?: boolean | SerializeOptions) => string
  uncheckedSerialize: () => string
  checkedSerialize: (opts?: SerializeOptions) => string
  toString: () => string
  inspect: () => string

  invalidSatoshis: () => boolean

  /** The first failing check, or undefined when the transaction serializes. */
  getSerializationError: (opts?: SerializeOptions) => Error | undefined
  _hasFeeError: (opts: SerializeOptions, unspent: number) => Error | undefined
  _missingChange: () => boolean
  _hasDustOutputs: (opts: SerializeOptions) => Error | undefined
  _isMissingSignatures: (opts: SerializeOptions) => Error | undefined

  toBuffer: () => Buffer
  toBufferWriter: (writer: BufferWriter) => BufferWriter
  fromBuffer: (buffer: Buffer) => Transaction
  fromBufferReader: (reader: BufferReader) => Transaction
  toObject: () => TransactionObject
  toJSON: () => TransactionObject
  fromObject: (arg: TransactionObject | Transaction) => Transaction
  fromString: (string: string) => void
  _checkConsistency: (arg?: TransactionObject | Transaction) => void
  _newTransaction: () => void

  lockUntilDate: (time: Date | number) => Transaction
  lockUntilBlockHeight: (height: number) => Transaction

  /**
   * Three outcomes with three meanings: a Date when nLockTime is a timestamp
   * (>= 5e8), a number when it is a block height, and null when nLockTime is 0
   * — i.e. no lock at all, which is NOT "locked until block 0".
   */
  getLockTime: () => Date | number | null

  from: (utxo: UnspentOutputLike | UnspentOutputLike[], pubkeys?: PublicKey[], threshold?: number) => Transaction
  _fromNonP2SH: (utxo: UnspentOutputLike) => void
  _fromMultisigUtxo: (utxo: UnspentOutputLike, pubkeys: PublicKey[], threshold: number) => void
  addInput: (input: Input, outputScript?: Script | string, satoshis?: number) => Transaction
  uncheckedAddInput: (input: Input) => Transaction
  hasAllUtxoInfo: () => boolean
  removeInput: (txId: string | number, outputIndex?: number) => void

  fee: (amount: number) => Transaction
  feePerKb: (amount: number) => Transaction
  getFee: () => number
  _estimateFee: () => number
  _estimateSize: () => number
  _getUnspentValue: () => number
  _getOutputAmount: () => number
  _getInputAmount: () => number

  change: (address: Address | string) => Transaction
  /** null when no change output is set — not an empty Output. */
  getChangeOutput: () => Output | null
  _updateChangeOutput: () => void

  /**
   * Also accepts a BATCH: an array of `{ address, satoshis }`, in which case
   * `amount` is ignored and each entry becomes its own output. Undocumented in
   * the original JSDoc and easy to miss, since the array form reads like a
   * mistake at the call site.
   */
  to: (address: Address | string | Payment[], amount?: number) => Transaction
  addData: (value: string | Buffer | Array<string | Buffer>) => Transaction
  addSafeData: (value: string | Buffer | Array<string | Buffer>) => Transaction
  addOutput: (output: Output) => Transaction
  _addOutput: (output: Output) => void
  clearOutputs: () => Transaction
  _removeOutput: (index: number) => void
  removeOutput: (index: number) => void

  sort: () => Transaction
  shuffleOutputs: () => Transaction
  sortOutputs: (sortingFunction: (outputs: Output[]) => Output[]) => Transaction
  sortInputs: (sortingFunction: (inputs: Input[]) => Input[]) => Transaction
  _newOutputOrder: (newOutputs: Output[]) => Transaction

  /** Accepts one key or an array; the array form recurses. */
  sign: (privateKey: PrivateKey | string | Array<PrivateKey | string>, sigtype?: number) => Transaction
  getSignatures: (privKey: PrivateKey | string, sigtype?: number) => TransactionSignature[]
  applySignature: (signature: TransactionSignature) => Transaction
  isFullySigned: () => boolean
  isValidSignature: (signature: TransactionSignature) => boolean
  _clearSignatures: () => void
  /** `satoshisBN` is optional here only because Sighash accepts it that way
   *  — it is REQUIRED for a correct BIP-143 preimage, and omitting it signs
   *  over the wrong amount rather than failing. */
  verifySignature: (sig: Signature, pubkey: PublicKey, nin: number, subscript: Script, satoshisBN?: BN, flags?: number) => boolean
  sighash: (inputIndex: number, sighashType: number, subscript: Script, satoshisBN?: BN, flags?: number) => Buffer

  /**
   * `true` when valid, otherwise a STRING describing the failure — so
   * `if (tx.verify())` is truthy in BOTH cases and silently accepts an invalid
   * transaction. Callers must compare against `true`.
   *
   * This is the same shape ECDSA.verify had until 7.0, where it was changed
   * for exactly this reason (see crypto/ecdsa.ts). Transaction#verify was not
   * changed with it. The union type is here so the compiler forces the
   * comparison rather than letting the footgun stay invisible.
   */
  verify: () => true | string

  isCoinbase: () => boolean

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
