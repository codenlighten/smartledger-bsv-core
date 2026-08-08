'use strict'

import { randomBytes } from 'crypto'

/**
 * Cryptographically secure random bytes.
 *
 * Kept as a namespace object with static methods rather than free functions:
 * the JavaScript original was `bsv.crypto.Random.getRandomBuffer(...)`, and
 * this is a behavior-preserving conversion, not an API change.
 */

// `process.browser` is set by bundlers (browserify/webpack define it); it is
// absent in Node, where the expression is simply undefined. Not part of
// @types/node, hence the explicit widening rather than a cast at each use.
declare const process: NodeJS.Process & { browser?: boolean }

/**
 * The subset of the Web Crypto API this module needs.
 *
 * Typed explicitly instead of reaching for `lib: ["DOM"]`: pulling the whole
 * DOM library into a Bitcoin library's global scope would let genuinely
 * browser-only APIs typecheck inside code that also runs in Node.
 */
interface RandomSource {
  getRandomValues: (array: Uint8Array) => Uint8Array
}

declare const window: {
  crypto?: RandomSource
  /** Internet Explorer's prefixed implementation; retained from the original. */
  msCrypto?: RandomSource
} | undefined

function getRandomBufferNode (size: number): Buffer {
  return randomBytes(size)
}

function getRandomBufferBrowser (size: number): Buffer {
  if (typeof window === 'undefined' || (window.crypto == null && window.msCrypto == null)) {
    throw new Error('window.crypto not available')
  }

  let source: RandomSource
  if (window.crypto?.getRandomValues != null) {
    source = window.crypto
  } else if (window.msCrypto?.getRandomValues != null) {
    source = window.msCrypto
  } else {
    throw new Error('window.crypto.getRandomValues not available')
  }

  const bbuf = new Uint8Array(size)
  source.getRandomValues(bbuf)
  return Buffer.from(bbuf)
}

/** Secure random bytes. Throws if the platform has no usable entropy source. */
function getRandomBuffer (size: number): Buffer {
  return process.browser === true
    ? getRandomBufferBrowser(size)
    : getRandomBufferNode(size)
}

const Random = {
  getRandomBuffer,
  getRandomBufferNode,
  getRandomBufferBrowser
}

export = Random
