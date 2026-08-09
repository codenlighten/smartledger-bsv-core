/**
 * Shapes for the Opcode constructor.
 *
 * Separate module because opcode.ts uses `export =` to keep its CommonJS
 * require() shape, and TypeScript forbids an export assignment alongside
 * other exported members.
 */
/**
 * A Bitcoin script opcode.
 *
 * Constructor function rather than a class: callable with and without `new`
 * (Opcode.smallInt relies on the bare form).
 */
export interface Opcode {
  readonly num: number
  toHex: () => string
  toBuffer: () => Buffer
  toNumber: () => number
  toString: () => string
  inspect: () => string
}

export interface OpcodeConstructor extends OpcodeConstants {
  new (num: number | string): Opcode
  (num: number | string): Opcode
  map: Record<string, number>
  reverseMap: string[]
  fromBuffer: (buf: Buffer) => Opcode
  fromNumber: (num: number) => Opcode
  fromString: (str: string) => Opcode
  smallInt: (n: number) => Opcode
  isSmallIntOp: (opcode: Opcode | number) => boolean
}

/**
 * The opcode constants copied onto the constructor by
 * `_.extend(Opcode, Opcode.map)`, so `Opcode.OP_DUP` works alongside
 * `Opcode.map.OP_DUP`.
 *
 * Enumerated rather than reached through an index signature. An index
 * signature would have to be `unknown`, since the constructor also carries
 * functions and objects — which makes every `Opcode.OP_X` unusable without a
 * cast, on consensus-critical comparisons. Generated from Opcode.map, so the
 * list cannot drift from the implementation without the build failing.
 */
export interface OpcodeConstants {
  readonly OP_0: number
  readonly OP_0NOTEQUAL: number
  readonly OP_1: number
  readonly OP_10: number
  readonly OP_11: number
  readonly OP_12: number
  readonly OP_13: number
  readonly OP_14: number
  readonly OP_15: number
  readonly OP_16: number
  readonly OP_1ADD: number
  readonly OP_1NEGATE: number
  readonly OP_1SUB: number
  readonly OP_2: number
  readonly OP_2DIV: number
  readonly OP_2DROP: number
  readonly OP_2DUP: number
  readonly OP_2MUL: number
  readonly OP_2OVER: number
  readonly OP_2ROT: number
  readonly OP_2SWAP: number
  readonly OP_3: number
  readonly OP_3DUP: number
  readonly OP_4: number
  readonly OP_5: number
  readonly OP_6: number
  readonly OP_7: number
  readonly OP_8: number
  readonly OP_9: number
  readonly OP_ABS: number
  readonly OP_ADD: number
  readonly OP_AND: number
  readonly OP_BIN2NUM: number
  readonly OP_BOOLAND: number
  readonly OP_BOOLOR: number
  readonly OP_CAT: number
  readonly OP_CHECKLOCKTIMEVERIFY: number
  readonly OP_CHECKMULTISIG: number
  readonly OP_CHECKMULTISIGVERIFY: number
  readonly OP_CHECKSEQUENCEVERIFY: number
  readonly OP_CHECKSIG: number
  readonly OP_CHECKSIGVERIFY: number
  readonly OP_CODESEPARATOR: number
  readonly OP_DEPTH: number
  readonly OP_DIV: number
  readonly OP_DROP: number
  readonly OP_DUP: number
  readonly OP_ELSE: number
  readonly OP_ENDIF: number
  readonly OP_EQUAL: number
  readonly OP_EQUALVERIFY: number
  readonly OP_FALSE: number
  readonly OP_FROMALTSTACK: number
  readonly OP_GREATERTHAN: number
  readonly OP_GREATERTHANOREQUAL: number
  readonly OP_HASH160: number
  readonly OP_HASH256: number
  readonly OP_IF: number
  readonly OP_IFDUP: number
  readonly OP_INVALIDOPCODE: number
  readonly OP_INVERT: number
  readonly OP_LEFT: number
  readonly OP_LESSTHAN: number
  readonly OP_LESSTHANOREQUAL: number
  readonly OP_LSHIFT: number
  readonly OP_MAX: number
  readonly OP_MIN: number
  readonly OP_MOD: number
  readonly OP_MUL: number
  readonly OP_NEGATE: number
  readonly OP_NIP: number
  readonly OP_NOP: number
  readonly OP_NOP1: number
  readonly OP_NOP10: number
  readonly OP_NOP2: number
  readonly OP_NOP3: number
  readonly OP_NOP4: number
  readonly OP_NOP5: number
  readonly OP_NOP6: number
  readonly OP_NOP7: number
  readonly OP_NOP8: number
  readonly OP_NOP9: number
  readonly OP_NOT: number
  readonly OP_NOTIF: number
  readonly OP_NUM2BIN: number
  readonly OP_NUMEQUAL: number
  readonly OP_NUMEQUALVERIFY: number
  readonly OP_NUMNOTEQUAL: number
  readonly OP_OR: number
  readonly OP_OVER: number
  readonly OP_PICK: number
  readonly OP_PUBKEY: number
  readonly OP_PUBKEYHASH: number
  readonly OP_PUSHDATA1: number
  readonly OP_PUSHDATA2: number
  readonly OP_PUSHDATA4: number
  readonly OP_RESERVED: number
  readonly OP_RESERVED1: number
  readonly OP_RESERVED2: number
  readonly OP_RETURN: number
  readonly OP_RIGHT: number
  readonly OP_RIPEMD160: number
  readonly OP_ROLL: number
  readonly OP_ROT: number
  readonly OP_RSHIFT: number
  readonly OP_SHA1: number
  readonly OP_SHA256: number
  readonly OP_SIZE: number
  readonly OP_SPLIT: number
  readonly OP_SUB: number
  readonly OP_SUBSTR: number
  readonly OP_SWAP: number
  readonly OP_TOALTSTACK: number
  readonly OP_TRUE: number
  readonly OP_TUCK: number
  readonly OP_VER: number
  readonly OP_VERIF: number
  readonly OP_VERIFY: number
  readonly OP_VERNOTIF: number
  readonly OP_WITHIN: number
  readonly OP_XOR: number
}
