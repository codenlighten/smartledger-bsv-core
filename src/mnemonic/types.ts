/**
 * Shape of Mnemonic — BIP39.
 *
 * `phrase` and `wordlist` are installed with Object.defineProperty and are
 * non-writable, so they are readonly here and that is not a convention: the
 * phrase determines the seed, and a mutable phrase on a live object would let
 * a caller change which key a wallet derives without changing the seed already
 * handed out.
 */
import type { HDPrivateKey } from '../hdprivatekey.types'

/** One BIP39 wordlist: exactly 2048 words. */
export type Wordlist = string[]

export interface Mnemonic {
  readonly phrase: string
  readonly wordlist: Wordlist

  /**
   * PBKDF2-HMAC-SHA512, 2048 rounds, salt 'mnemonic' + passphrase.
   * The passphrase is NOT the wordlist password — an empty passphrase and an
   * omitted one give the same seed, which is why it is optional here.
   */
  toSeed: (passphrase?: string) => Buffer
  toHDPrivateKey: (passphrase?: string, network?: unknown) => HDPrivateKey
  toString: () => string
  inspect: () => string
}

export interface MnemonicConstructor {
  new (data?: string | Buffer | number | Wordlist, wordlist?: Wordlist): Mnemonic
  (data?: string | Buffer | number | Wordlist, wordlist?: Wordlist): Mnemonic
  prototype: Mnemonic

  fromRandom: (wordlist?: Wordlist, ent?: number) => Mnemonic
  fromString: (mnemonic: string, wordlist?: Wordlist) => Mnemonic
  fromSeed: (seed: Buffer, wordlist?: Wordlist) => Mnemonic

  /**
   * Validity is CHECKSUM validity, not "these are all real words". A phrase
   * of 12 dictionary words with a bad checksum is invalid; one with a good
   * checksum is valid even if it is nonsense to a human.
   */
  isValid: (mnemonic: string, wordlist?: Wordlist) => boolean
  _belongsToWordlist: (mnemonic: string, wordlist: Wordlist) => boolean
  /**
   * Three outcomes, and they are not the same: `null` for a falsy argument,
   * `undefined` when no wordlist matched (the loop falls off the end without
   * an explicit return), and a Wordlist on a hit. The constructor calls this
   * with a possibly-undefined phrase, so the argument is optional too.
   */
  _getDictionary: (mnemonic?: string) => Wordlist | null | undefined
  _mnemonic: (ENT: number, wordlist: Wordlist) => string
  _entropy2mnemonic: (entropy: Buffer, wordlist: Wordlist) => string
  _entropyChecksum: (entropy: Buffer) => string

  Words: Record<string, Wordlist>
}
