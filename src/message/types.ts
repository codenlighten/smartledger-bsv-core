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
  verify: (bitcoinAddress: Address | string, signatureString: string) => boolean
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
  verify: (message: string | Buffer, address: Address | string, signature: string) => boolean

  fromString: (str: string | Buffer) => Message
  fromJSON: (json: string) => Message
  fromObject: (obj: { messageHex: string }) => Message

  MAGIC_BYTES: Buffer
}
