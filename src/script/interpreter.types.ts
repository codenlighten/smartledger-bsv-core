/**
 * Shapes for the script interpreter.
 *
 * Separate module because interpreter.ts uses `export =` to keep its CommonJS
 * require() shape, and TypeScript forbids an export assignment alongside other
 * exported members.
 */
import type BN = require('../crypto/bn')
import type { Script } from './script.types'

/**
 * Consensus and policy flags, plus the script limits.
 *
 * Enumerated rather than reached through an index signature, for the same
 * reason as the opcode constants: an index signature would have to be
 * `unknown` (the constructor also carries functions), which would force a cast
 * on every flag test — and these are the flags that decide whether a
 * transaction is valid.
 *
 * NOT readonly, deliberately. The limits are MUTABLE GLOBAL STATE:
 * useGenesisLimits() and setLimits() reassign MAX_SCRIPT_ELEMENT_SIZE and
 * friends on the constructor itself, so enabling Genesis limits anywhere
 * changes them for every interpreter in the process. Declaring them readonly
 * would have been a tidier-looking lie.
 */
export interface InterpreterFlags {
  LOCKTIME_THRESHOLD: number
  MAXIMUM_ELEMENT_SIZE: number
  MAX_OPS_PER_SCRIPT: number
  MAX_SCRIPT_ELEMENT_SIZE: number
  MAX_SCRIPT_SIZE: number
  SCRIPT_ENABLE_MAGNETIC_OPCODES: number
  SCRIPT_ENABLE_MONOLITH_OPCODES: number
  SCRIPT_ENABLE_REPLAY_PROTECTION: number
  SCRIPT_ENABLE_SIGHASH_FORKID: number
  SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY: number
  SCRIPT_VERIFY_CHECKSEQUENCEVERIFY: number
  SCRIPT_VERIFY_CLEANSTACK: number
  SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE: number
  SCRIPT_VERIFY_DERSIG: number
  SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS: number
  SCRIPT_VERIFY_LOW_S: number
  SCRIPT_VERIFY_MINIMALDATA: number
  SCRIPT_VERIFY_MINIMALIF: number
  SCRIPT_VERIFY_NONE: number
  SCRIPT_VERIFY_NULLDUMMY: number
  SCRIPT_VERIFY_NULLFAIL: number
  SCRIPT_VERIFY_P2SH: number
  SCRIPT_VERIFY_SIGPUSHONLY: number
  SCRIPT_VERIFY_STRICTENC: number
  SEQUENCE_LOCKTIME_DISABLE_FLAG: number
  SEQUENCE_LOCKTIME_MASK: number
  SEQUENCE_LOCKTIME_TYPE_FLAG: number
  /** BN form of LOCKTIME_THRESHOLD, for comparison against script numbers. */
  LOCKTIME_THRESHOLD_BN: BN
}

/** The mutable evaluation state. */
export interface Interpreter {
  stack: Buffer[]
  altstack: Buffer[]
  pc: number
  pbegincodehash: number
  nOpCount: number
  vfExec: boolean[]
  errstr: string
  flags: number

  script?: Script
  tx?: any
  nin?: number
  satoshisBN?: BN

  initialize: (obj?: unknown) => void
  set: (obj: Record<string, unknown>) => void
  verify: (scriptSig: Script, scriptPubkey: Script, tx?: any, nin?: number, flags?: number, satoshisBN?: BN) => boolean
  evaluate: () => boolean
  step: () => boolean
  _callbackStep: (...args: unknown[]) => void
  checkSignatureEncoding: (buf: Buffer) => boolean
  checkPubkeyEncoding: (buf: Buffer) => boolean
  checkLockTime: (nLockTime: BN) => boolean
  checkSequence: (nSequence: BN) => boolean

  /**
   * Optional debugging hook, invoked after each step with clones of the
   * stacks. Set by callers (the script debugger); never by the interpreter.
   */
  stepListener?: (step: unknown, stack: Buffer[], altstack: Buffer[]) => void
}

export interface InterpreterConstructor extends InterpreterFlags {
  new (obj?: unknown): Interpreter
  (obj?: unknown): Interpreter

  true: Buffer
  false: Buffer

  useGenesisLimits: (max?: number) => void
  getLimits: () => Record<string, number>
  setLimits: (limits: Record<string, number>) => void

  castToBool: (buf: Buffer) => boolean
  _isMinimallyEncoded: (buf: Buffer, maxNumSize?: number) => boolean
  _minimallyEncode: (buf: Buffer) => Buffer
}
