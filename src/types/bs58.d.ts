/**
 * Minimal declarations for bs58@4, which ships no types of its own.
 *
 * Pinned at `=4.0.1` deliberately (v5 changed the encode/decode signatures to
 * Uint8Array), so these declarations describe v4's Buffer-based API and must
 * be revisited if that pin moves.
 */
declare module 'bs58' {
  export function encode (buf: Buffer | Uint8Array | number[]): string
  export function decode (str: string): Buffer
}
