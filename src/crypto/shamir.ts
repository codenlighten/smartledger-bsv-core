'use strict'

import BN = require('./bn')
import Random = require('./random')
import Hash = require('./hash')
import type { Share, LegacyShare, AnyShare, SplitOptions, LegacyBytePoint } from './shamir.types'

interface ShamirConstructor {
  new (options?: Record<string, unknown>): { options: Record<string, unknown> }
  (options?: Record<string, unknown>): { options: Record<string, unknown> }
  split: (secret: Buffer | string, threshold: number, shares: number, options?: SplitOptions) => Share[]
  combine: (shares: AnyShare[]) => Buffer
  verifyShare: (share: AnyShare) => boolean
  generateTestVectors: () => unknown
  _combineLegacy: (shares: AnyShare[]) => Buffer
  _combineByteLegacy: (shares: LegacyBytePoint[]) => number
  _modInverseLegacy: (a: BN, m: BN) => BN
  _extendedGCDLegacy: (a: BN, b: BN) => { gcd: BN, x: BN, y: BN }
  _verifyLegacyShare: (share: unknown) => boolean
}

// secrets.js-grempe is loaded lazily and wired to use the library's own vetted
// Random (Node CSPRNG / window.crypto), so it never depends on the bundler's
// `crypto` resolution for randomness. Lazy loading also means simply requiring
// this module (e.g. loading the full bsv bundle) never runs secrets.js's
// auto-init, which would otherwise throw in a bundle that mocks node `crypto`.
let _secrets: typeof import('secrets.js-grempe') | null = null
function secretsLib (): typeof import('secrets.js-grempe') {
  if (_secrets != null) return _secrets
  const s = require('secrets.js-grempe') as typeof import('secrets.js-grempe')
  s.setRNG(function (bits: number): string {
    // secrets.js's RNG contract requires ALWAYS returning a string of exactly
    // `bits` random 1's and 0's — it has no null/re-draw protocol. An all-zero
    // draw is rejected by secrets.js (a zero polynomial coefficient would leak
    // the secret), so we re-draw internally until non-zero rather than returning
    // null. Returning null would otherwise either crash secrets.js validation
    // (`rng(bits).length` → TypeError) or silently corrupt a share coefficient
    // (`parseInt(null, 2)` → NaN). With a CSPRNG a re-draw is astronomically rare.
    // Bounded rejection sampling. Each all-zero draw has probability 2^-bits
    // (~1/256 for the default 8-bit field), so a redraw is rare and terminates in
    // ~1 iteration with a real CSPRNG. The cap converts a broken/stubbed RNG that
    // returns all-zero forever (e.g. a bundle that mocks crypto to Buffer.alloc)
    // from an unrecoverable hang into a clear, fail-fast error.
    const MAX_REDRAWS = 64
    for (let attempt = 0; attempt < MAX_REDRAWS; attempt++) {
      const bytes = Random.getRandomBuffer(Math.ceil(bits / 8))
      let str = ''
      for (let i = 0; i < bytes.length; i++) {
        str += ('00000000' + (bytes[i] as number).toString(2)).slice(-8)
      }
      str = str.slice(0, bits)
      if (/1/.test(str)) return str
    }
    throw new Error('shamir: CSPRNG returned all-zero draws ' + MAX_REDRAWS +
      ' times in a row — refusing to hang on a degenerate/stubbed random source')
  })
  _secrets = s
  return _secrets
}

/**
 * Shamir Secret Sharing.
 *
 * The split/combine math is provided by `secrets.js-grempe`, a vetted GF(2^8)
 * implementation (the same field/approach used by hardware wallets), rather
 * than a hand-rolled finite field. On top of it this module adds:
 *
 *   - a per-split nonce (`splitId`) so shares from different splits can't be
 *     silently mixed into a wrong-but-plausible reconstruction;
 *   - an integrity `checksum` (truncated SHA-256 of the secret) so a tampered
 *     share set is detected at combine time instead of returning garbage.
 *
 * Share objects produced here are format v2. Shares produced by <= 4.x (which
 * carried a `bytes` array of {x, y} points over a 31-bit prime field) are still
 * accepted by `combine()` for recovery only — see `_combineLegacy`.
 */

// Marker byte prepended to the secret before sharing. Guarantees a non-zero
// leading byte so leading zero bytes of the secret survive the hex round-trip,
// and lets combine() recover the exact original length.
const MARKER = 'ff'

const SHARE_VERSION = 2

/**
 * Shamir Secret Sharing constructor (kept for API compatibility).
 * @param {Object} options
 */
const Shamir = function Shamir (this: { options: Record<string, unknown> }, options?: Record<string, unknown>) {
  if (!(this instanceof Shamir)) {
    return new (Shamir as ShamirConstructor)(options)
  }
  this.options = options ?? {}
  return this
} as unknown as ShamirConstructor

/**
 * Split a secret into shares.
 * @param {Buffer|String} secret - The secret to split
 * @param {Number} threshold - Minimum shares needed to reconstruct (>= 2)
 * @param {Number} shares - Total shares to generate (>= threshold, <= 255)
 * @param {Object} [options]
 * @param {Boolean} [opts.checksum=false] - embed a truncated SHA-256 of the
 *   secret in each share so combine() can detect a wrong/tampered share set.
 *   OFF BY DEFAULT: the checksum is a hash of the secret present in EVERY share,
 *   so a single shareholder (below threshold) can brute-force a low-entropy secret
 *   offline by matching it — defeating the threshold. Enable only for high-entropy
 *   secrets where tamper-detection outweighs that leak. (splitId already detects
 *   mixing shares from different splits without disclosing anything about the secret.)
 * @returns {Array} Array of v2 share objects
 */
Shamir.split = function (secret: Buffer | string, threshold: number, shares: number, options?: SplitOptions): Share[] {
  const opts: SplitOptions = options ?? {}

  if (secret === undefined || secret === null) {
    throw new Error('Secret is required')
  }
  if (threshold < 2) {
    throw new Error('Threshold must be at least 2')
  }
  if (shares < threshold) {
    throw new Error('Number of shares must be at least threshold')
  }
  if (threshold > 255 || shares > 255) {
    throw new Error('Threshold and shares must be <= 255')
  }

  const secretBuffer = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8')

  const markedHex = MARKER + secretBuffer.toString('hex')
  const rawShares = secretsLib().share(markedHex, shares, threshold)

  const splitId = Random.getRandomBuffer(8).toString('hex')
  const useChecksum = opts.checksum === true
  const checksum = useChecksum
    ? Hash.sha256(secretBuffer).slice(0, 4).toString('hex')
    : null

  const result: Share[] = []
  for (let i = 0; i < rawShares.length; i++) {
    result.push({
      v: SHARE_VERSION,
      id: i + 1,
      threshold,
      shares,
      length: secretBuffer.length,
      splitId,
      share: rawShares[i] as string,
      checksum
    })
  }
  return result
}

/**
 * Combine shares to reconstruct the original secret.
 * @param {Array} shares - Array of share objects (v2 or legacy)
 * @returns {Buffer} The reconstructed secret
 */
Shamir.combine = function (shares: AnyShare[]): Buffer {
  if (shares == null || shares.length === 0) {
    throw new Error('Shares array is required')
  }

  // Route legacy (<= 4.x) shares to the retained recovery-only combiner.
  const first = shares[0]
  if (first != null && Array.isArray((first as LegacyShare).bytes) && (first as LegacyShare).share === undefined) {
    return Shamir._combineLegacy(shares)
  }

  // Past the legacy branch every share is v2. The discriminant is a runtime
  // shape check that TypeScript cannot use to narrow the array itself, so the
  // narrowing is asserted once here rather than at each access below.
  const v2 = shares as Share[]
  const head = v2[0] as Share

  const threshold = head.threshold
  const splitId = head.splitId

  if (v2.length < threshold) {
    throw new Error('Insufficient shares: need ' + threshold + ', got ' + v2.length)
  }

  const rawShares = []
  for (let i = 0; i < v2.length; i++) {
    const s = v2[i] as Share
    if (!s || typeof s.share !== 'string') {
      throw new Error('Invalid share at index ' + i)
    }
    // All shares must come from the same split.
    if (splitId !== undefined && s.splitId !== splitId) {
      throw new Error('Shares are from different splits (splitId mismatch)')
    }
    if (s.threshold !== threshold) {
      throw new Error('Shares have inconsistent threshold')
    }
    rawShares.push(s.share)
  }

  const markedHex = secretsLib().combine(rawShares)
  if (markedHex.slice(0, MARKER.length) !== MARKER) {
    // Wrong/insufficient/corrupt shares produced an unmarked result.
    throw new Error('Reconstruction failed: invalid or insufficient shares')
  }
  const secretBuffer = Buffer.from(markedHex.slice(MARKER.length), 'hex')

  // Integrity check: a tampered share or a mismatched set reconstructs to the
  // wrong secret; the embedded checksum catches it instead of silently
  // returning garbage.
  const expected = head.checksum
  if (expected) {
    const actual = Hash.sha256(secretBuffer).slice(0, 4).toString('hex')
    if (actual !== expected) {
      throw new Error('Integrity check failed: shares are inconsistent or tampered')
    }
  }

  return secretBuffer
}

/**
 * Verify a share is structurally valid.
 * @param {Object} share
 * @returns {Boolean}
 */
Shamir.verifyShare = function (share: AnyShare): boolean {
  try {
    if (!share || typeof share !== 'object') {
      return false
    }

    // Legacy share shape (recovery only).
    if (Array.isArray((share as LegacyShare).bytes) && (share as LegacyShare).share === undefined) {
      return Shamir._verifyLegacyShare(share)
    }

    const v2share = share as Share
    if (v2share.v !== SHARE_VERSION) {
      return false
    }
    if (typeof share.share !== 'string' || !/^[0-9a-fA-F]+$/.test(share.share)) {
      return false
    }
    if (typeof share.threshold !== 'number' || typeof share.shares !== 'number') {
      return false
    }
    if (share.threshold < 2 || share.shares < share.threshold || share.shares > 255) {
      return false
    }
    if (share.id < 1 || share.id > share.shares) {
      return false
    }
    if (share.checksum !== null && share.checksum !== undefined &&
        !/^[0-9a-fA-F]{8}$/.test(share.checksum)) {
      return false
    }
    // secrets.js validates the internal share structure (throws on garbage).
    secretsLib().extractShareComponents(share.share)
    return true
  } catch (e) {
    return false
  }
}

/**
 * Generate test vectors for validation.
 * @returns {Object}
 */
Shamir.generateTestVectors = function (): unknown {
  const secret = 'Hello, Bitcoin SV!'
  const threshold = 3
  const shares = 5

  const splitShares = Shamir.split(secret, threshold, shares)
  const reconstructed = Shamir.combine(splitShares.slice(0, threshold))

  return {
    secret,
    threshold,
    totalShares: shares,
    shares: splitShares,
    reconstructed: reconstructed.toString('utf8'),
    valid: reconstructed.toString('utf8') === secret
  }
}

// ---------------------------------------------------------------------------
// Legacy recovery (shares produced by <= 4.x). Read-only; do NOT use to split.
// These reconstruct over the old 31-bit prime field. Retained so secrets split
// with older versions remain recoverable.
// ---------------------------------------------------------------------------

const LEGACY_PRIME = new BN(2147483647) // 2^31 - 1

Shamir._combineLegacy = function (shares: AnyShare[]): Buffer {
  // combine() routes here only after confirming the legacy shape, so the
  // narrowing is asserted once rather than at each access.
  const ls = shares as LegacyShare[]
  const head = ls[0] as LegacyShare
  const threshold = head.threshold
  const totalShares = head.shares
  const secretLength = head.length

  if (ls.length < threshold) {
    throw new Error('Insufficient shares: need ' + threshold + ', got ' + ls.length)
  }
  for (let i = 0; i < ls.length; i++) {
    const s = ls[i] as LegacyShare
    if (s.threshold !== threshold || s.shares !== totalShares) {
      throw new Error('Shares have inconsistent parameters')
    }
    if (s.length !== secretLength) {
      throw new Error('Shares have different secret lengths')
    }
  }

  const reconstructedBytes: number[] = []
  for (let j = 0; j < secretLength; j++) {
    const byteShares: LegacyBytePoint[] = []
    for (let k = 0; k < Math.min(ls.length, threshold); k++) {
      byteShares.push((ls[k] as LegacyShare).bytes[j] as unknown as LegacyBytePoint)
    }
    reconstructedBytes.push(Shamir._combineByteLegacy(byteShares))
  }
  return Buffer.from(reconstructedBytes)
}

Shamir._combineByteLegacy = function (shares: LegacyBytePoint[]): number {
  let result = new BN(0)
  for (let i = 0; i < shares.length; i++) {
    const pi = shares[i] as LegacyBytePoint
    const xi = new BN(pi.x)
    const yi = new BN(pi.y, 16)
    let numerator = new BN(1)
    let denominator = new BN(1)

    for (let j = 0; j < shares.length; j++) {
      if (i !== j) {
        const xj = new BN((shares[j] as LegacyBytePoint).x)
        let numFactor = new BN(0).sub(xj)
        if (numFactor.lt(new BN(0))) {
          numFactor = numFactor.add(LEGACY_PRIME)
        }
        numerator = numerator.mul(numFactor).mod(LEGACY_PRIME)

        let denFactor = xi.sub(xj)
        if (denFactor.lt(new BN(0))) {
          denFactor = denFactor.add(LEGACY_PRIME)
        }
        denominator = denominator.mul(denFactor).mod(LEGACY_PRIME)
      }
    }

    const inverse = Shamir._modInverseLegacy(denominator, LEGACY_PRIME)
    const lagrange = numerator.mul(inverse).mod(LEGACY_PRIME)
    result = result.add(yi.mul(lagrange)).mod(LEGACY_PRIME)
  }
  return result.mod(LEGACY_PRIME).mod(new BN(256)).toNumber()
}

Shamir._modInverseLegacy = function (a: BN, m: BN): BN {
  if (a.lt(new BN(0))) {
    a = a.mod(m).add(m)
  }
  const g = Shamir._extendedGCDLegacy(a, m)
  if (!g.gcd.eq(new BN(1))) {
    throw new Error('Modular inverse does not exist')
  }
  return g.x.mod(m).add(m).mod(m)
}

Shamir._extendedGCDLegacy = function (a: BN, b: BN): { gcd: BN, x: BN, y: BN } {
  if (a.eq(new BN(0))) {
    return { gcd: b, x: new BN(0), y: new BN(1) }
  }
  const g = Shamir._extendedGCDLegacy(b.mod(a), a)
  return {
    gcd: g.gcd,
    x: g.y.sub(b.div(a).mul(g.x)),
    y: g.x
  }
}

Shamir._verifyLegacyShare = function (share: unknown): boolean {
  const s = share as Partial<LegacyShare>
  if (s?.id == null || s.threshold == null || s.shares == null || s.bytes == null || typeof s.length !== 'number') {
    return false
  }
  if (s.threshold < 2 || s.shares < s.threshold) {
    return false
  }
  if (!Array.isArray(s.bytes) || s.bytes.length !== s.length) {
    return false
  }
  for (let i = 0; i < s.bytes.length; i++) {
    const byteShare = s.bytes[i] as LegacyBytePoint | undefined
    if (byteShare?.x == null || byteShare.y == null) {
      return false
    }
    if (byteShare.x < 1 || byteShare.x > s.shares) {
      return false
    }
    if (!/^[0-9a-fA-F]+$/.test(byteShare.y)) {
      return false
    }
  }
  return true
}

export = Shamir
