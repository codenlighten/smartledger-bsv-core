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

export interface OpcodeConstructor {
  new (num: number | string): Opcode
  (num: number | string): Opcode
  map: Record<string, number>
  reverseMap: string[]
  fromBuffer: (buf: Buffer) => Opcode
  fromNumber: (num: number) => Opcode
  fromString: (str: string) => Opcode
  smallInt: (n: number) => Opcode
  isSmallIntOp: (opcode: Opcode | number) => boolean
  /**
   * Every opcode name is also copied onto the constructor by the
   * `_.extend(Opcode, Opcode.map)` below, so `Opcode.OP_DUP` works alongside
   * `Opcode.map.OP_DUP`. They are reached through this index signature rather
   * than being enumerated: the list is long, lives in the map literal, and
   * duplicating it in a type would be a second copy to keep in sync.
   */
  [name: string]: unknown
}
