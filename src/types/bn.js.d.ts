/**
 * Declarations for bn.js AS THIS LIBRARY EXPOSES IT.
 *
 * Two things make this file necessary rather than `@types/bn.js`:
 *
 * 1. Those types describe bn.js v5. This package pins `bn.js` to `=4.12.3`
 *    deliberately — the v4 -> v5 upgrade was reviewed and rejected on semantic
 *    grounds, and the pin is load-bearing. Shipping v5 types over a v4 runtime
 *    would describe behavior we do not have, which is worse than no types
 *    because it typechecks. If the pin ever moves to v5, delete this file.
 *
 * 2. `crypto/bn` augments the class in place — adding Bitcoin-specific
 *    conversions and REPLACING `toBuffer` with an options-object signature
 *    incompatible with the native `(endian, length)` form. Every consumer does
 *    `require('../crypto/bn')` and uses native and added members on the same
 *    object, so both are declared together here. The native `toBuffer` is
 *    deliberately absent: declaring it would let call sites typecheck against
 *    a signature this library does not expose.
 *
 * The native surface below was enumerated from actual usage across src/, not
 * copied wholesale, so anything missing is genuinely unused.
 */
declare module 'bn.js' {
  type Endianness = 'le' | 'be'
  type BNInput = number | string | number[] | Uint8Array | Buffer | BN

  namespace BN {
    /** Options for the Buffer conversions installed by crypto/bn. */
    interface BufferOpts {
      endian?: 'big' | 'little'
      size?: number
    }
    interface EndianOpts {
      endian?: 'big' | 'little'
    }
  }

  class BN {
    constructor (value?: BNInput, base?: number | 'hex', endian?: Endianness)

    /** Number of 26-bit words. Read by crypto/point's range checks. */
    length: number

    clone: () => BN
    copy: (dest: BN) => void

    toString: (base?: number | 'hex', padding?: number) => string
    toNumber: () => number
    toArray: (endian?: Endianness, length?: number) => number[]

    byteLength: () => number
    isZero: () => boolean
    isNeg: () => boolean

    add: (b: BN) => BN
    sub: (b: BN) => BN
    mul: (b: BN) => BN
    div: (b: BN) => BN
    mod: (b: BN) => BN
    umod: (b: BN) => BN
    pow: (b: BN) => BN
    neg: () => BN
    invm: (b: BN) => BN
    shrn: (b: number) => BN
    /** Bitwise AND. Used by the CSV sequence-mask checks. */
    and: (b: BN) => BN

    cmp: (b: BN) => -1 | 0 | 1
    lt: (b: BN) => boolean
    lte: (b: BN) => boolean
    gt: (b: BN) => boolean
    gte: (b: BN) => boolean
    eq: (b: BN) => boolean

    // --- installed by crypto/bn -------------------------------------------
    toBuffer: (opts?: BN.BufferOpts) => Buffer
    toSMBigEndian: () => Buffer
    toSM: (opts?: BN.EndianOpts) => Buffer
    toScriptNumBuffer: () => Buffer
    toHex: (opts?: BN.BufferOpts) => string

    static isBN: (b: unknown) => b is BN
    static wordSize: number

    // --- installed by crypto/bn (statics) ---------------------------------
    static Zero: BN
    static One: BN
    static Minus1: BN
    static fromNumber: (n: number) => BN
    static fromString: (str: string, base?: number) => BN
    static fromBuffer: (buf: Buffer, opts?: BN.BufferOpts) => BN
    static fromSM: (buf: Buffer, opts?: BN.EndianOpts) => BN
    static fromScriptNumBuffer: (buf: Buffer, fRequireMinimal?: boolean, size?: number) => BN
    static fromHex: (hex: string, opts?: BN.BufferOpts) => BN
    static trim: (buf: Buffer, natlen: number) => Buffer
    static pad: (buf: Buffer, natlen: number, size: number) => Buffer
  }

  export = BN
}
