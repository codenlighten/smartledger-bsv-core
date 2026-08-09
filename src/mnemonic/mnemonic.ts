'use strict'

import HDPrivateKey = require('../hdprivatekey')
import BN = require('../crypto/bn')
import unorm = require('unorm')
import _ = require('../util/_')

import pbkdf2 = require('./pbkdf2')
import errors = require('./errors')
// Named bsvErrors, not errors: `errors` above is this module's OWN error set.
// The library-wide errors module is a different object and must not shadow it.
import bsvErrors = require('../errors')

import Hash = require('../crypto/hash')
import Random = require('../crypto/random')

import $ = require('../util/preconditions')
import type { Mnemonic, MnemonicConstructor, Wordlist } from './types'

// TWO error trees, deliberately kept apart. `./errors` holds the BIP39-specific
// ones (UnknownWordlist, InvalidMnemonic, InvalidEntropy); `../errors` holds the
// library-wide ones (InvalidArgument). Both are built dynamically, so members
// arrive via an index signature and need a cast.
//
// Routing all of them through one tree is a real bug, not a tidiness question:
// the wrong tree yields undefined, and `new undefined(...)` throws a TypeError
// from the line that was supposed to throw a meaningful error. Two helpers.
type ErrCtor = new (...args: unknown[]) => Error
const err = (path: string): ErrCtor =>
  path.split('.').reduce<any>((o, k) => o[k], errors) as ErrCtor
const bsvErr = (path: string): ErrCtor =>
  path.split('.').reduce<any>((o, k) => o[k], bsvErrors) as ErrCtor

/**
 * This is an immutable class that represents a BIP39 Mnemonic code.
 * See BIP39 specification for more info: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * A Mnemonic code is a a group of easy to remember words used for the generation
 * of deterministic wallets. A Mnemonic can be used to generate a seed using
 * an optional passphrase, for later generate a HDPrivateKey.
 *
 * @example
 * // generate a random mnemonic
 * var mnemonic = new Mnemonic();
 * var phrase = mnemonic.phrase;
 *
 * // use a different language
 * var mnemonic = new Mnemonic(Mnemonic.Words.SPANISH);
 * var xprivkey = mnemonic.toHDPrivateKey();
 *
 * @param {*=} data - a seed, phrase, or entropy to initialize (can be skipped)
 * @param {Array=} wordlist - the wordlist to generate mnemonics from
 * @returns {Mnemonic} A new instance of Mnemonic
 * @constructor
 */
const Mnemonic = function Mnemonic (this: Mnemonic, data?: any, wordlist?: any): any {
  if (!(this instanceof Mnemonic)) {
    return new (Mnemonic as unknown as MnemonicConstructor)(data, wordlist)
  }

  if (_.isArray(data)) {
    wordlist = data
    data = null
  }

  // handle data overloading
  let ent, phrase, seed
  if (Buffer.isBuffer(data)) {
    seed = data
  } else if (_.isString(data)) {
    phrase = unorm.nfkd(data)
  } else if (_.isNumber(data)) {
    ent = data
  } else if (data) {
    throw new (bsvErr('InvalidArgument'))('data', 'Must be a Buffer, a string or an integer')
  }
  ent = ent || 128

  // check and detect wordlist
  wordlist = wordlist || (Mnemonic as unknown as MnemonicConstructor)._getDictionary(phrase)
  if (phrase && !wordlist) {
    throw new (err('UnknownWordlist'))(phrase)
  }
  wordlist = wordlist || (Mnemonic as unknown as MnemonicConstructor).Words.ENGLISH

  if (seed) {
    phrase = (Mnemonic as unknown as MnemonicConstructor)._entropy2mnemonic(seed, wordlist)
  }

  // validate phrase and ent
  if (phrase && !(Mnemonic as unknown as MnemonicConstructor).isValid(phrase, wordlist)) {
    throw new (err('InvalidMnemonic'))(phrase)
  }
  if (ent % 32 !== 0 || ent < 128) {
    throw new (bsvErr('InvalidArgument'))('ENT', 'Values must be ENT > 128 and ENT % 32 == 0')
  }

  phrase = phrase || (Mnemonic as unknown as MnemonicConstructor)._mnemonic(ent, wordlist)

  Object.defineProperty(this, 'wordlist', {
    configurable: false,
    value: wordlist
  })

  Object.defineProperty(this, 'phrase', {
    configurable: false,
    value: phrase
  })
} as unknown as MnemonicConstructor

/**
 * Generate a random Mnemonic with the given wordlist and entropy.
 *
 * A number in either argument position is the entropy in bits (128, 160, 192,
 * 224 or 256 — higher = more words); an array is the wordlist. So every form
 * below works AND honours the requested strength:
 *   fromRandom()              -> ENGLISH, 128-bit (12 words)
 *   fromRandom(wordlist)      -> wordlist, 128-bit
 *   fromRandom(wordlist, 256) -> wordlist, 256-bit (24 words)
 *   fromRandom(256)           -> ENGLISH, 256-bit
 *   fromRandom(256, wordlist) -> wordlist, 256-bit
 *
 * Prior to 7.0.1 the second argument was silently dropped, so the documented
 * `fromRandom(wordlist, 256)` form returned a weaker 12-word (128-bit) phrase
 * with no error — a security foot-gun this fix closes. Invalid entropy still
 * throws (must be a multiple of 32 and >= 128).
 *
 * @param {Array<string>|number} [wordlist] - wordlist, or entropy bits
 * @param {number|Array<string>} [ent] - entropy bits, or wordlist
 * @returns {Mnemonic}
 */
Mnemonic.fromRandom = function (wordlist: any, ent: any) {
  // A number in the first position is the entropy; normalise so `ent` holds it
  // and `wordlist` holds the array (either argument order is accepted).
  if (_.isNumber(wordlist)) {
    const swapped = ent
    ent = wordlist
    wordlist = swapped
  }
  wordlist = wordlist || Mnemonic.Words.ENGLISH
  ent = ent || 128
  return new Mnemonic(ent, wordlist)
}

Mnemonic.fromString = function (mnemonic: any, wordlist: any = Mnemonic.Words.ENGLISH) {
  return new Mnemonic(mnemonic, wordlist)
}

Mnemonic.Words = require('./words')

/**
 * Will return a boolean if the mnemonic is valid
 *
 * @example
 *
 * var valid = Mnemonic.isValid('lab rescue lunch elbow recall phrase perfect donkey biology guess moment husband');
 * // true
 *
 * @param {String} mnemonic - The mnemonic string
 * @param {String} [wordlist] - The wordlist used
 * @returns {boolean}
 */
Mnemonic.isValid = function (mnemonic: any, wordlist: any) {
  mnemonic = unorm.nfkd(mnemonic)
  wordlist = wordlist || Mnemonic._getDictionary(mnemonic)

  if (!wordlist) {
    return false
  }

  const words = mnemonic.split(' ')
  let bin = ''
  for (var i = 0; i < words.length; i++) {
    const ind = wordlist.indexOf(words[i])
    if (ind < 0) return false
    bin = bin + ('00000000000' + ind.toString(2)).slice(-11)
  }

  const cs = bin.length / 33
  const hashBits = bin.slice(-cs)
  const nonhashBits = bin.slice(0, bin.length - cs)
  const buf = Buffer.alloc(nonhashBits.length / 8)
  for (i = 0; i < nonhashBits.length / 8; i++) {
    buf.writeUInt8(parseInt(bin.slice(i * 8, (i + 1) * 8), 2), i)
  }
  const expectedHashBits = Mnemonic._entropyChecksum(buf)
  return expectedHashBits === hashBits
}

/**
 * Internal function to check if a mnemonic belongs to a wordlist.
 *
 * @param {String} mnemonic - The mnemonic string
 * @param {String} wordlist - The wordlist
 * @returns {boolean}
 */
Mnemonic._belongsToWordlist = function (mnemonic: any, wordlist: any) {
  const words = unorm.nfkd(mnemonic).split(' ')
  for (let i = 0; i < words.length; i++) {
    const ind = wordlist.indexOf(words[i])
    if (ind < 0) return false
  }
  return true
}

/**
 * Internal function to detect the wordlist used to generate the mnemonic.
 *
 * @param {String} mnemonic - The mnemonic string
 * @returns {Array} the wordlist or null
 */
Mnemonic._getDictionary = function (mnemonic: any) {
  if (!mnemonic) return null

  const dicts = Object.keys(Mnemonic.Words)
  for (let i = 0; i < dicts.length; i++) {
    const key = dicts[i]!
    if (Mnemonic._belongsToWordlist(mnemonic, Mnemonic.Words[key]!)) {
      return Mnemonic.Words[key]
    }
  }
  return null
}

/**
 * Will generate a seed based on the mnemonic and optional passphrase. Note that
 * this seed is absolutely NOT the seed that is output by .toSeed(). These are
 * two different seeds. The seed you want to put in here, if any, is just some
 * random byte string. Normally you should rely on the .fromRandom() method.
 *
 * @param {String} [passphrase]
 * @returns {Buffer}
 */
Mnemonic.prototype.toSeed = function (this: Mnemonic, passphrase: any) {
  passphrase = passphrase || ''
  return pbkdf2(unorm.nfkd(this.phrase), unorm.nfkd('mnemonic' + passphrase), 2048, 64)
}

/**
 * Will generate a Mnemonic object based on a seed.
 *
 * @param {Buffer} [seed]
 * @param {string} [wordlist]
 * @returns {Mnemonic}
 */
Mnemonic.fromSeed = function (seed: any, wordlist: any) {
  $.checkArgument(Buffer.isBuffer(seed), 'seed must be a Buffer.')
  $.checkArgument(_.isArray(wordlist) || _.isString(wordlist), 'wordlist must be a string or an array.')
  return new Mnemonic(seed, wordlist)
}

/**
 *
 * Generates a HD Private Key from a Mnemonic.
 * Optionally receive a passphrase and bitcoin network.
 *
 * @param {String=} [passphrase]
 * @param {Network|String|number=} [network] - The network: 'livenet' or 'testnet'
 * @returns {HDPrivateKey}
 */
Mnemonic.prototype.toHDPrivateKey = function (this: Mnemonic, passphrase: any, network: any) {
  const seed = this.toSeed(passphrase)
  return HDPrivateKey.fromSeed(seed, network)
}

/**
 * Will return a the string representation of the mnemonic
 *
 * @returns {String} Mnemonic
 */
Mnemonic.prototype.toString = function (this: Mnemonic) {
  return this.phrase
}

/**
 * Will return a string formatted for the console
 *
 * @returns {String} Mnemonic
 */
Mnemonic.prototype.inspect = function (this: Mnemonic) {
  return '<Mnemonic: ' + this.toString() + ' >'
}

/**
 * Internal function to generate a random mnemonic
 *
 * @param {Number} ENT - Entropy size, defaults to 128
 * @param {Array} wordlist - Array of words to generate the mnemonic
 * @returns {String} Mnemonic string
 */
Mnemonic._mnemonic = function (ENT: any, wordlist: any) {
  const buf = Random.getRandomBuffer(ENT / 8)
  return Mnemonic._entropy2mnemonic(buf, wordlist)
}

/**
 * Internal function to generate mnemonic based on entropy
 *
 * @param {Number} entropy - Entropy buffer
 * @param {Array} wordlist - Array of words to generate the mnemonic
 * @returns {String} Mnemonic string
 */
Mnemonic._entropy2mnemonic = function (entropy: any, wordlist: any) {
  let bin = ''
  for (var i = 0; i < entropy.length; i++) {
    bin = bin + ('00000000' + entropy[i].toString(2)).slice(-8)
  }

  bin = bin + Mnemonic._entropyChecksum(entropy)
  if (bin.length % 11 !== 0) {
    throw new (err('InvalidEntropy'))(bin)
  }
  const mnemonic = []
  for (i = 0; i < bin.length / 11; i++) {
    const wi = parseInt(bin.slice(i * 11, (i + 1) * 11), 2)
    mnemonic.push(wordlist[wi])
  }
  let ret
  if (wordlist === Mnemonic.Words.JAPANESE) {
    ret = mnemonic.join('\u3000')
  } else {
    ret = mnemonic.join(' ')
  }
  return ret
}

/**
 * Internal function to create checksum of entropy
 *
 * @param entropy
 * @returns {string} Checksum of entropy length / 32
 * @private
 */
Mnemonic._entropyChecksum = function (entropy: any) {
  const hash = Hash.sha256(entropy)
  const bits = entropy.length * 8
  const cs = bits / 32

  let hashbits = new BN(hash.toString('hex'), 16).toString(2)

  // zero pad the hash bits
  while (hashbits.length % 256 !== 0) {
    hashbits = '0' + hashbits
  }

  const checksum = hashbits.slice(0, cs)

  return checksum
}

export = Mnemonic
