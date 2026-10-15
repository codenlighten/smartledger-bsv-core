/**
 * Shape of Message — Bitcoin Signed Message (the "Bitcoin Signed Message:\n"
 * magic-hash scheme), not transaction signing.
 *
 * `sign`/`verify` exist as both statics and prototype methods, and they are
 * NOT interchangeable: the statics take the message as their first argument
 * and construct internally, while the methods sign the instance they are
 * called on. Both are declared because both are shipped API.
 */
import type { PrivateKey } from '../privatekey.types'
import type { PublicKey } from '../publickey.types'
import type { Address } from '../address.types'
import type { Signature as SignatureType } from '../crypto/signature.types'

/**
 * Options for `verify`. `lowS` refuses a non-canonical (high-s) signature: for any signature
 * this library produces there is a second, different base64 string that verifies for the same
 * key and message, so the bytes are not a unique name for a statement.
 *
 * It is opt-in because the signatures it refuses are valid ECDSA and other implementations may
 * legitimately emit them; 2.0.0 makes the refusal the default. Note that before 1.8.0 the
 * argument was ACCEPTED AND IGNORED, so probe for the behaviour rather than trusting a version
 * range — see the sibling package's docs/RELIED-UPON-PROPERTIES.md.
 */
export interface MessageVerifyOptions {
  lowS?: boolean
}

export interface Message {
  /**
   * The message as BYTES, not a string. The constructor accepts either and
   * stores a Buffer, and toObject()/fromObject() round-trip it as `messageHex`
   * rather than as text — so a message that is not valid UTF-8 survives. That
   * is why there is no `message: string` field: it would invite `m.message`,
   * which is undefined, and lossy re-encoding if it were added.
   */
  messageBuffer: Buffer
  /** Set by verify() when verification FAILS; the reason is not thrown. */
  error?: string | null

  magicHash: () => Buffer
  _sign: (privateKey: PrivateKey) => SignatureType
  sign: (privateKey: PrivateKey) => string
  _verify: (publicKey: PublicKey, signature: SignatureType) => boolean
  verify: (bitcoinAddress: Address | string, signatureString: string, opts?: MessageVerifyOptions) => boolean
  toObject: () => { messageHex: string }
  toJSON: () => string
  toString: () => string
  inspect: () => string
}

export interface MessageConstructor {
  new (message: string | Buffer): Message
  (message: string | Buffer): Message
  prototype: Message

  /** Static form: message first, then the key. */
  sign: (message: string | Buffer, privateKey: PrivateKey) => string
  verify: (message: string | Buffer, address: Address | string, signature: string, opts?: MessageVerifyOptions) => boolean

  fromString: (str: string | Buffer) => Message
  fromJSON: (json: string | { messageHex: string }) => Message
  fromObject: (obj: { messageHex: string }) => Message

  MAGIC_BYTES: Buffer
}
