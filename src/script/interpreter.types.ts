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
import type Transaction = require('../transaction')

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

/**
 * What the constructor, initialize() and set() accept — a partial snapshot of
 * the evaluation state, applied over the defaults. Not the same as
 * `Interpreter`: every field is optional here because a caller may set only
 * `flags`, or only `script` and `tx`.
 */
export interface InterpreterState {
  stack?: Buffer[] | undefined
  altstack?: Buffer[] | undefined
  pc?: number | undefined
  pbegincodehash?: number | undefined
  nOpCount?: number | undefined
  vfExec?: boolean[] | undefined
  errstr?: string | undefined
  flags?: number | undefined
  script?: Script | undefined
  tx?: Transaction | undefined
  nin?: number | undefined
  satoshisBN?: BN | undefined
  stepListener?: (step: StepInfo, stack: Buffer[], altstack: Buffer[]) => void
}

/**
 * The four limits setLimits() can move, in the spelling IT uses — not the
 * spelling of the constants they write to.
 */
export interface ScriptLimits {
  maxScriptElementSize?: number
  maximumElementSize?: number
  maxOpsPerScript?: number
  maxScriptSize?: number
}

/** One evaluation step, handed to a stepListener. */
export interface StepInfo {
  pc: number
  opcode: unknown
  fExec?: boolean
  [key: string]: unknown
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

  script?: Script | undefined
  tx?: Transaction | undefined
  nin?: number | undefined
  satoshisBN?: BN | undefined

  initialize: (obj?: InterpreterState) => void
  set: (obj: InterpreterState) => void
  verify: (scriptSig: Script, scriptPubkey: Script, tx?: Transaction, nin?: number, flags?: number, satoshisBN?: BN) => boolean
  evaluate: () => boolean
  step: () => boolean
  _callbackStep: (thisStep: StepInfo) => void
  checkSignatureEncoding: (buf: Buffer) => boolean
  checkPubkeyEncoding: (buf: Buffer) => boolean
  checkLockTime: (nLockTime: BN) => boolean
  checkSequence: (nSequence: BN) => boolean

  /**
   * Optional debugging hook, invoked after each step with clones of the
   * stacks. Set by callers (the script debugger); never by the interpreter.
   */
  stepListener?: (step: StepInfo, stack: Buffer[], altstack: Buffer[]) => void
}

export interface InterpreterConstructor extends InterpreterFlags {
  new (obj?: InterpreterState): Interpreter
  (obj?: InterpreterState): Interpreter

  true: Buffer
  false: Buffer

  useGenesisLimits: (max?: number) => void
  getLimits: () => Record<string, number>
  /**
   * Partial by design: pass only the limits you want to move; anything omitted
   * keeps its current value.
   *
   * Note the KEYS ARE camelCase and do not match the SCREAMING_SNAKE constants
   * they write to — `maxScriptElementSize` sets MAX_SCRIPT_ELEMENT_SIZE. Only
   * these four can be set this way; the other limits on the constructor are
   * not reachable through setLimits at all.
   */
  setLimits: (limits?: ScriptLimits) => InterpreterConstructor

  castToBool: (buf: Buffer) => boolean
  _isMinimallyEncoded: (buf: Buffer, nMaxNumSize?: number) => boolean
  _minimallyEncode: (buf: Buffer) => Buffer
}
