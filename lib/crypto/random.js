'use strict'

function Random () {
}

/* secure random bytes that sometimes throws an error due to lack of entropy */
Random.getRandomBuffer = function (size) {
  if (process.browser) { return Random.getRandomBufferBrowser(size) } else { return Random.getRandomBufferNode(size) }
}

Random.getRandomBufferNode = function (size) {
  const crypto = require('crypto')
  return crypto.randomBytes(size)
}

Random.getRandomBufferBrowser = function (size) {
  if (!window.crypto && !window.msCrypto) {
    throw new Error('window.crypto not available')
  }
  let crypto

  if (window.crypto && window.crypto.getRandomValues) {
    crypto = window.crypto
  } else if (window.msCrypto && window.msCrypto.getRandomValues) { // internet explorer
    crypto = window.msCrypto
  } else {
    throw new Error('window.crypto.getRandomValues not available')
  }

  const bbuf = new Uint8Array(size)
  crypto.getRandomValues(bbuf)
  const buf = Buffer.from(bbuf)

  return buf
}

module.exports = Random
