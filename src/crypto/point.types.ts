/**
 * Shapes for the secp256k1 Point wrapper.
 *
 * Separate module because point.ts uses `export =` to keep its CommonJS
 * require() shape, and TypeScript forbids an export assignment alongside
 * other exported members.
 */
import type BN = require('bn.js')

/**
 * The underlying @noble curve point.
 *
 * Derived from the library rather than restated, so it tracks @noble's own
 * type across upgrades instead of drifting from it.
 *
 * Three details of HOW it is derived, each of which was a consumer-visible bug:
 *
 *  - It is a **type-position** `import(...)`, not a top-level import. A top-level value
 *    import is emitted into the generated .d.ts as a module a consumer must `require`,
 *    and @noble/curves is ESM-only — so every CommonJS consumer compiling with
 *    `moduleResolution: node16`/`nodenext` got TS1479 from a declaration file they never
 *    asked for. Shipped that way through 1.0.x and 1.1.0.
 *  - A plain `import type` does not fix it either: TypeScript then asks for TS1541/TS1542,
 *    because resolving an ESM module's types from a CJS file is the thing it objects to,
 *    not the require() alone.
 *  - Hence **`resolution-mode: 'import'`**, which tells the consumer's compiler to resolve
 *    this one specifier as ESM. That syntax needs TypeScript >= 5.3 to PARSE, and the cost is
 *    not zero — measured, after first assuming it was. A consumer on TS 5.2 with
 *    `skipLibCheck: true` compiled against 1.1.0 and does not against this, because
 *    skipLibCheck suppresses errors reported INSIDE a .d.ts but the file is still parsed, and
 *    a syntax it cannot parse is fatal either way:
 *
 *        TS 5.2, skipLibCheck true  : 1.1.0 -> 0 errors, this -> 7 (parse)
 *        TS 5.6, skipLibCheck false : 1.1.0 -> 16,       this -> 15 (the 15 are @types/node)
 *        TS 5.9, skipLibCheck false : 1.1.0 -> 1,        this -> 0
 *
 *    Accepted deliberately: the alternative is hand-mirroring @noble's point API in our own
 *    declarations, which trades a known, narrow, old-toolchain break for silent drift against
 *    a curve implementation. TS 5.2 predates the Node 20.19 floor this package already has,
 *    and such a consumer gets no checking of these declarations anyway.
 *
 * The trade accepted here: our public declarations still reference @noble's types, so a
 * consumer's typechecker must resolve them. Restating the shape locally would decouple it
 * at the cost of silent drift from the real curve API, and `_p` is internal, so the
 * tracking is worth more than the decoupling. `check:consumer-types` now compiles a
 * consumer in all three resolution modes, so a regression here fails before release.
 */
export type NoblePoint = ReturnType<typeof import('@noble/curves/secp256k1.js', { with: { 'resolution-mode': 'import' } }).secp256k1.Point.fromHex>

/** Anything the coordinate coercion (`toBig`) accepts. */
export type CoordLike = BN | bigint | number | string

export interface Point {
  /**
   * The wrapped @noble point. Internal — this class exists to hide it — but
   * typed properly rather than as `unknown`, so the wrapper's own arithmetic
   * is checked instead of casting at every call site.
   */
  _p: NoblePoint

  getX: () => BN
  getY: () => BN
  mul: (k: BN | bigint | number) => Point
  add: (p: Point) => Point
  mulAdd: (k1: BN | bigint | number, p2: Point, k2: BN | bigint | number) => Point
  eq: (p: Point) => boolean
  isInfinity: () => boolean
  validate: () => Point
  toBuffer: () => Buffer
  toHex: () => string
}

export interface PointConstructor {
  new (x: CoordLike, y: CoordLike, isRed?: boolean): Point
  (x: CoordLike, y: CoordLike, isRed?: boolean): Point
  fromX: (odd: boolean, x: CoordLike) => Point
  getG: () => Point
  getN: () => BN
  pointToCompressed: (point: Point) => Buffer
  pointFromCompressed: (buf: Buffer) => Point
  fromBuffer: (buf: Buffer) => Point
  fromHex: (hex: string) => Point
}
