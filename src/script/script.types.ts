/**
 * Shape of Script, declared separately so modules inside the
 * script <-> transaction cycle can refer to it as a TYPE without adding a
 * runtime import edge. `import type` is erased, so this costs nothing at
 * runtime and cannot create a temporal-dead-zone hazard.
 *
 * Deliberately partial for now: it covers what the already-converted members
 * of SCC-19 need. It grows as script/script itself is converted, at which
 * point that module becomes the single source of truth.
 */
export interface Script {
  /** Set by transaction/output when a script is parsed as a locking script. */
  _isOutput?: boolean
  chunks: Array<{ opcodenum: number, buf?: Buffer, len?: number }>

  toBuffer: () => Buffer
  toHex: () => string
  toString: () => string
  toASM: () => string
  add: (obj: unknown) => Script
  classify: () => string
  isPublicKeyHashOut: () => boolean
  isScriptHashOut: () => boolean
  isPublicKeyOut: () => boolean
  isDataOut: () => boolean
  getData: () => Buffer
  toAddress: (network?: unknown) => unknown
  equals: (script: Script) => boolean
  inspect: () => string
}

export interface ScriptConstructor {
  new (from?: unknown): Script
  (from?: unknown): Script
  fromBuffer: (buf: Buffer) => Script
  fromHex: (hex: string) => Script
  fromString: (str: string) => Script
  fromASM: (asm: string) => Script
  fromAddress: (address: unknown) => Script
  empty: () => Script
  buildPublicKeyHashOut: (to: unknown) => Script
  buildScriptHashOut: (script: Script) => Script
  buildDataOut: (data: unknown, encoding?: string) => Script
  buildSafeDataOut: (data: unknown, encoding?: string) => Script
  /** Attached by script/index, not by script/script itself. */
  Interpreter: unknown
}
