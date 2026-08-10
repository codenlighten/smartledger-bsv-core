/**
 * Shape of Script.
 *
 * Declared separately so modules inside the script <-> transaction and
 * address <-> publickey cycles can refer to Script as a TYPE without adding a
 * runtime import edge. `import type` is erased, so it costs nothing at runtime
 * and cannot create a temporal-dead-zone hazard.
 */

/** One parsed element: an opcode, optionally carrying pushed data. */
import type Opcode = require('../opcode')
import type { PublicKey } from '../publickey.types'
import type { Address } from '../address.types'
import type { Network } from '../networks.types'
import type { Signature } from '../crypto/signature.types'

/**
 * Everything `add`/`prepend` dispatch on, in the order _addByType tests them:
 * a string or number opcode name/value, an Opcode instance, a Buffer pushdata,
 * another Script (whose chunks are concatenated), or a chunk object.
 */
export type ScriptAddable = string | number | Opcode | Buffer | Script | ScriptChunk

/** Anything the builders accept where a public key is meant. */
export type PublicKeyLike = PublicKey | Buffer | string
/** Anything accepted where a payment destination is meant. */
export type AddressLike = Address | PublicKey | string
/** A network, or the name/magic that Networks.get() resolves to one. */
export type NetworkLike = Network | string | number

/** Shared shape of the multisig builders' trailing options argument. */
export interface MultisigOpts {
  /** Skip the lexicographic public-key sort. Changes the resulting script,
   *  and therefore the address — not a cosmetic flag. */
  noSorting?: boolean
  /** Emit a P2SH-wrapped form where the builder supports it. */
  cachedMultisig?: Script
}

export interface ScriptChunk {
  opcodenum: number
  buf?: Buffer
  len?: number
}

/** What the address helpers return, or false when no address is derivable. */
export interface ScriptAddressInfo {
  hashBuffer: Buffer
  /** Only ever 'pubkeyhash' or 'scripthash' — the two forms a script yields. */
  type: 'pubkeyhash' | 'scripthash'
  network?: NetworkLike | undefined
}

export interface Script {
  chunks: ScriptChunk[]
  /** Set by transaction/input when parsed as an unlocking script. */
  _isInput?: boolean
  /** Set by transaction/output when parsed as a locking script. */
  _isOutput?: boolean
  _network?: Network

  set: (obj: { chunks: ScriptChunk[] }) => Script
  toBuffer: () => Buffer
  toASM: () => string
  toString: () => string
  toHex: () => string
  inspect: () => string
  _chunkToString: (chunk: ScriptChunk, type?: string) => string

  isPublicKeyHashOut: () => boolean
  isPublicKeyHashOutPrefix: () => boolean
  isPublicKeyOut: () => boolean
  isScriptHashOut: () => boolean
  isMultisigOut: () => boolean
  isDataOut: () => boolean
  isSafeDataOut: () => boolean
  isPublicKeyHashIn: () => boolean
  isPublicKeyIn: () => boolean
  isScriptHashIn: () => boolean
  isMultisigIn: () => boolean

  getPublicKey: () => Buffer
  getPublicKeyHash: () => Buffer
  getData: () => Buffer
  isPushOnly: () => boolean

  classify: () => string
  classifyOutput: () => string
  classifyInput: () => string
  isStandard: () => boolean

  prepend: (obj: ScriptAddable) => Script
  equals: (script: Script) => boolean
  add: (obj: ScriptAddable) => Script
  _addByType: (obj: ScriptAddable, prepend: boolean) => Script
  _insertAtPosition: (op: ScriptChunk, prepend: boolean) => Script
  _addOpcode: (opcode: number | string | Opcode, prepend: boolean) => Script
  _addBuffer: (buf: Buffer, prepend: boolean) => Script
  removeCodeseparators: () => Script

  toScriptHashOut: () => Script
  getAddressInfo: (opts?: { network?: NetworkLike }) => ScriptAddressInfo | false
  _getOutputAddressInfo: () => ScriptAddressInfo | false
  _getInputAddressInfo: () => ScriptAddressInfo | false
  /** `false`, not null and not a throw, when the script has no address form. */
  toAddress: (network?: NetworkLike) => Address | false

  findAndDelete: (script: Script) => Script
  checkMinimalPush: (i: number) => boolean
  _decodeOP_N: (opcode: number) => number
  getSignatureOperationsCount: (accurate?: boolean) => number
}

export interface ScriptConstructor {
  new (from?: unknown): Script
  (from?: unknown): Script

  fromBuffer: (buffer: Buffer) => Script
  fromASM: (str: string) => Script
  fromHex: (str: string) => Script
  fromString: (str: string) => Script
  fromAddress: (address: AddressLike) => Script
  empty: () => Script

  buildMultisigOut: (publicKeys: PublicKeyLike[], threshold: number, opts?: MultisigOpts) => Script
  buildMultisigIn: (pubkeys: PublicKeyLike[], threshold: number, signatures: Array<Buffer | Signature>, opts?: MultisigOpts) => Script
  buildP2SHMultisigIn: (pubkeys: PublicKeyLike[], threshold: number, signatures: Array<Buffer | Signature>, opts?: MultisigOpts) => Script
  buildPublicKeyHashOut: (to: AddressLike) => Script
  buildPublicKeyOut: (pubkey: PublicKey) => Script
  buildDataOut: (data?: string | Buffer | Array<string | Buffer | undefined>, encoding?: BufferEncoding) => Script
  buildSafeDataOut: (data?: string | Buffer | Array<string | Buffer | undefined>, encoding?: BufferEncoding) => Script
  /** Accepts a Script to hash, OR an Address that is ALREADY P2SH — in which
   *  case its hashBuffer is used directly and nothing is hashed. */
  buildScriptHashOut: (script: Script | Address) => Script
  buildPublicKeyIn: (signature: Buffer | Signature, sigtype?: number) => Script
  buildPublicKeyHashIn: (publicKey: PublicKeyLike, signature: Buffer | Signature, sigtype?: number) => Script

  types: Record<string, string>
  OP_RETURN_STANDARD_SIZE: number
  outputIdentifiers: Record<string, () => boolean>
  inputIdentifiers: Record<string, () => boolean>

  /** Attached by script/index, not by script/script itself. */
  Interpreter: unknown
}
