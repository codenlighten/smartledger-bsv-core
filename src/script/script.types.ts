/**
 * Shape of Script.
 *
 * Declared separately so modules inside the script <-> transaction and
 * address <-> publickey cycles can refer to Script as a TYPE without adding a
 * runtime import edge. `import type` is erased, so it costs nothing at runtime
 * and cannot create a temporal-dead-zone hazard.
 */

/** One parsed element: an opcode, optionally carrying pushed data. */
export interface ScriptChunk {
  opcodenum: number
  buf?: Buffer
  len?: number
}

/** What the address helpers return, or false when no address is derivable. */
export interface ScriptAddressInfo {
  hashBuffer: Buffer
  type: string
  network?: unknown
}

export interface Script {
  chunks: ScriptChunk[]
  /** Set by transaction/input when parsed as an unlocking script. */
  _isInput?: boolean
  /** Set by transaction/output when parsed as a locking script. */
  _isOutput?: boolean
  _network?: unknown

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

  prepend: (obj: unknown) => Script
  equals: (script: Script) => boolean
  add: (obj: unknown) => Script
  _addByType: (obj: unknown, prepend: boolean) => Script
  _insertAtPosition: (op: ScriptChunk, prepend: boolean) => Script
  _addOpcode: (opcode: unknown, prepend: boolean) => Script
  _addBuffer: (buf: Buffer, prepend: boolean) => Script
  removeCodeseparators: () => Script

  toScriptHashOut: () => Script
  getAddressInfo: (opts?: unknown) => ScriptAddressInfo | false
  _getOutputAddressInfo: () => ScriptAddressInfo | false
  _getInputAddressInfo: () => ScriptAddressInfo | false
  toAddress: (network?: unknown) => unknown

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
  fromAddress: (address: unknown) => Script
  empty: () => Script

  buildMultisigOut: (publicKeys: unknown[], threshold: number, opts?: unknown) => Script
  buildMultisigIn: (pubkeys: unknown[], threshold: number, signatures: unknown[], opts?: unknown) => Script
  buildP2SHMultisigIn: (pubkeys: unknown[], threshold: number, signatures: unknown[], opts?: unknown) => Script
  buildPublicKeyHashOut: (to: unknown) => Script
  buildPublicKeyOut: (pubkey: unknown) => Script
  buildDataOut: (data: unknown, encoding?: BufferEncoding) => Script
  buildSafeDataOut: (data: unknown, encoding?: BufferEncoding) => Script
  buildScriptHashOut: (script: Script) => Script
  buildPublicKeyIn: (signature: unknown, sigtype?: number) => Script
  buildPublicKeyHashIn: (publicKey: unknown, signature: unknown, sigtype?: number) => Script

  types: Record<string, string>
  OP_RETURN_STANDARD_SIZE: number
  outputIdentifiers: Record<string, () => boolean>
  inputIdentifiers: Record<string, () => boolean>

  /** Attached by script/index, not by script/script itself. */
  Interpreter: unknown
}
