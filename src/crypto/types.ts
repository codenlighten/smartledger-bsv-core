/**
 * Shared shapes for the crypto modules.
 *
 * Separate from the implementations because those use `export =` to keep their
 * CommonJS `require()` shape, and TypeScript forbids an export assignment
 * alongside other exported members.
 */

/**
 * A hash function usable as the inner primitive of HMAC.
 *
 * `blocksize` is in BITS (512 for SHA-256, 1024 for SHA-512) and is required:
 * `Hash.hmac` divides it by 8 to get the pad width.
 */
export interface HashFunction {
  (buf: Buffer): Buffer
  blocksize?: number
}

export interface HashModule {
  sha1: HashFunction
  sha256: HashFunction
  sha256sha256: (buf: Buffer) => Buffer
  ripemd160: (buf: Buffer) => Buffer
  sha256ripemd160: (buf: Buffer) => Buffer
  sha512: HashFunction
  hmac: (hashf: HashFunction, data: Buffer, key: Buffer) => Buffer
  sha256hmac: (data: Buffer, key: Buffer) => Buffer
  sha512hmac: (data: Buffer, key: Buffer) => Buffer
}
