'use strict'

/**
 * Browser-compatible PBKDF2 implementation using BSV crypto
 * Credit to: https://github.com/stayradiated/pbkdf2-sha512
 * Copyright (c) 2014, JP Richardson Copyright (c) 2010-2011 Intalio Pte, All Rights Reserved
 */

// Import BSV crypto instead of Node.js crypto
import Hash = require('../crypto/hash')

function pbkdf2 (key: string | Buffer, salt: string | Buffer, iterations: number, dkLen: number): Buffer {
  const hLen = 64 // SHA512 Mac length
  if (dkLen > (Math.pow(2, 32) - 1) * hLen) {
    throw Error('Requested key length too long')
  }

  if (typeof key !== 'string' && !Buffer.isBuffer(key)) {
    throw new TypeError('key must a string or Buffer')
  }

  if (typeof salt !== 'string' && !Buffer.isBuffer(salt)) {
    throw new TypeError('salt must a string or Buffer')
  }

  if (typeof key === 'string') {
    key = Buffer.from(key)
  }

  if (typeof salt === 'string') {
    salt = Buffer.from(salt)
  }

  const DK = Buffer.alloc(dkLen)
  let U: Buffer = Buffer.alloc(hLen)
  const T = Buffer.alloc(hLen)
  const block1 = Buffer.alloc(salt.length + 4)

  const l = Math.ceil(dkLen / hLen)
  const r = dkLen - (l - 1) * hLen

  salt.copy(block1, 0, 0, salt.length)
  for (let i = 1; i <= l; i++) {
    block1[salt.length + 0] = (i >> 24 & 0xff)
    block1[salt.length + 1] = (i >> 16 & 0xff)
    block1[salt.length + 2] = (i >> 8 & 0xff)
    block1[salt.length + 3] = (i >> 0 & 0xff)

    // Use BSV's browser-compatible HMAC instead of Node.js crypto
    U = Hash.sha512hmac(block1, key)
    U.copy(T, 0, 0, hLen)

    for (let j = 1; j < iterations; j++) {
      U = Hash.sha512hmac(U, key)

      for (let k = 0; k < hLen; k++) {
        T[k] = (T[k] as number) ^ (U[k] as number)
      }
    }

    const destPos = (i - 1) * hLen
    const len = (i === l ? r : hLen)
    T.copy(DK, destPos, 0, len)
  }

  return DK
}

export = pbkdf2
