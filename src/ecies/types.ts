/**
 * Shapes for the two ECIES implementations.
 *
 * There are two because there are two incompatible wire formats in the wild
 * and both are in use:
 *
 *   BIE1 (electrum-ecies) — magic bytes 'BIE1', ephemeral pubkey, AES-256-CBC
 *   with the IV DERIVED from the shared secret, HMAC-SHA256 over the payload.
 *
 *   bitcore (bitcore-ecies) — no magic bytes, IV passed in or zero, and a
 *   different split of the SHA-512 output.
 *
 * They are NOT given a common base interface, even though the method names
 * line up. Their derived state differs in a way that decides which ciphertexts
 * they can read: electrum splits sha512 as iv|kE|kM (16|16|32) and bitcore
 * splits it as kE|kM (32|32). Declaring one interface with both sets of
 * properties would type-check code that reads `iv` off a bitcore instance,
 * where it is undefined — and a wrong IV does not throw, it silently produces
 * garbage plaintext. Two interfaces make the choice visible at the call site.
 */
import type { PrivateKey } from '../privatekey.types'
import type { PublicKey } from '../publickey.types'

/**
 * Fixed-key AES-CBC helper, exposed on both modules for testing.
 *
 * Rest-typed because the ARITY differs: BIE1 derives its IV from the shared
 * secret and passes it to both directions, while bitcore's decrypt reads the
 * IV from the head of the ciphertext and takes two arguments. Pinning one
 * signature here would misdescribe whichever module it did not come from.
 */
export interface AESCBCStatic {
  encrypt: (...args: Buffer[]) => Buffer
  decrypt: (...args: Buffer[]) => Buffer
}

export interface ECIESOptions {
  /** Omit the ephemeral public key from the payload; the peer must know it. */
  noKey?: boolean
  /** Emit a 4-byte tag instead of the full 32. Weaker, and readable only by a
   *  peer configured the same way. */
  shortTag?: boolean
  /** Set by the constructor/privateKey(): the private key was generated here
   *  rather than supplied, so the public key in the payload is ephemeral. */
  ephemeralKey?: boolean
  /** Set by publicKey(): a counterparty key was pinned. Only used to warn when
   *  decrypt() is about to override it with the key found in the message. */
  fixedPublicKey?: boolean
}

/** BIE1. Splits sha512(S) as iv | kE | kM = 16 | 16 | 32. */
export interface ElectrumECIES {
  opts: ECIESOptions
  _privateKey?: PrivateKey | undefined
  _publicKey?: PublicKey | undefined

  privateKey: (privateKey: PrivateKey) => ElectrumECIES
  publicKey: (publicKey: PublicKey) => ElectrumECIES

  /** Derived lazily and cached on first read. */
  readonly Rbuf: Buffer
  readonly ivkEkM: Buffer
  readonly iv: Buffer
  readonly kE: Buffer
  readonly kM: Buffer

  encrypt: (message: string | Buffer) => Buffer
  decrypt: (encbuf: Buffer) => Buffer
}

/** bitcore. Splits sha512(S) as kE | kM = 32 | 32; the IV is a parameter. */
export interface BitcoreECIES {
  opts: ECIESOptions
  _privateKey?: PrivateKey | undefined
  _publicKey?: PublicKey | undefined

  privateKey: (privateKey: PrivateKey) => BitcoreECIES
  publicKey: (publicKey: PublicKey) => BitcoreECIES

  readonly Rbuf: Buffer
  readonly kEkM: Buffer
  readonly kE: Buffer
  readonly kM: Buffer

  encrypt: (message: string | Buffer, ivbuf?: Buffer) => Buffer
  decrypt: (encbuf: Buffer) => Buffer
}

export interface BitcoreECIESConstructor {
  new (opts?: ECIESOptions): BitcoreECIES
  (opts?: ECIESOptions): BitcoreECIES
  prototype: BitcoreECIES
}

export interface ElectrumECIESConstructor {
  new (opts?: ECIESOptions, algorithm?: string): ElectrumECIES
  (opts?: ECIESOptions, algorithm?: string): ElectrumECIES
  prototype: ElectrumECIES
  /** The other wire format, reachable from the default export. */
  bitcoreECIES: BitcoreECIESConstructor
}
