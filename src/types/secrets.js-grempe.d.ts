/**
 * Declarations for secrets.js-grempe, which ships no types.
 *
 * Scoped to the API crypto/shamir uses, enumerated from that file rather than
 * copied wholesale — anything missing here is genuinely unused.
 */
declare module 'secrets.js-grempe' {
  /**
   * Install a custom randomness source.
   *
   * CONTRACT (this is why crypto/shamir wraps it carefully): the function must
   * ALWAYS return a string of exactly `bits` characters, each '0' or '1'.
   * There is no null / re-draw protocol — returning null crashes the library's
   * own validation or silently corrupts a share coefficient.
   */
  export function setRNG (rng: (bits: number) => string): void
  export function share (secret: string, numShares: number, threshold: number, padLength?: number): string[]
  export function combine (shares: string[]): string
  export function str2hex (str: string, bytesPerChar?: number): string
  export function hex2str (hex: string, bytesPerChar?: number): string
  export function extractShareComponents (share: string): { bits: number, id: number, data: string }
}
