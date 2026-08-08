/**
 * Shapes for Shamir secret sharing.
 *
 * Separate module because shamir.ts uses `export =` to keep its CommonJS
 * require() shape, and TypeScript forbids an export assignment alongside
 * other exported members.
 */

/** A v2 share, as produced by split(). */
export interface Share {
  v: number
  /** 1-based index of this share within the split. */
  id: number
  threshold: number
  /** Total shares generated. */
  shares: number
  /** Byte length of the original secret, used to trim on recombination. */
  length: number
  /** Identifies the split a share came from, so mixed sets are detectable. */
  splitId: string
  /** The raw secrets.js share string. */
  share: string
  /** Truncated SHA-256 of the secret; null unless explicitly enabled. */
  checksum: string | null
}

/**
 * A pre-v2 share.
 *
 * combine() still accepts these: it detects them by `bytes` being an array
 * while `share` is undefined. Kept as a distinct type so the legacy path is
 * visible in the signatures rather than hidden behind `any`.
 */
export interface LegacyShare {
  /** Per-byte share values. Its presence (with `share` absent) is the discriminant. */
  bytes: number[]
  id: number
  threshold: number
  shares: number
  /** Byte length of the original secret. */
  length: number
  share?: undefined
}

/** Either share format accepted by combine(). */
export type AnyShare = Share | LegacyShare

export interface SplitOptions {
  /**
   * Embed a truncated SHA-256 of the secret in every share.
   *
   * OFF BY DEFAULT and deliberately so: the checksum is a hash of the secret
   * present in EVERY share, so a single shareholder below the threshold can
   * brute-force a low-entropy secret offline by matching it — defeating the
   * threshold. splitId already detects mixed share sets without disclosing
   * anything about the secret.
   */
  checksum?: boolean
}

/** One byte's worth of a legacy share: an (x, y) point in the legacy field. */
export interface LegacyBytePoint {
  x: number
  y: string
}
