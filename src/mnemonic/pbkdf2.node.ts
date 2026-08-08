'use strict'

import { createHmac } from 'crypto'

/**
 * PBKDF2-HMAC-SHA512, the key-derivation function BIP39 uses to turn a
 * mnemonic phrase into a seed.
 *
 * Credit to: https://github.com/stayradiated/pbkdf2-sha512
 * Copyright (c) 2014, JP Richardson  Copyright (c) 2010-2011 Intalio Pte,
 * All Rights Reserved.
 *
 * Correctness here is load-bearing: the published BIP39 vectors in the
 * conformance corpus pin this output exactly.
 */
function pbkdf2 (
  key: string | Buffer,
  salt: string | Buffer,
  iterations: number,
  dkLen: number
): Buffer {
  const hLen = 64 // SHA-512 MAC length
  if (dkLen > (Math.pow(2, 32) - 1) * hLen) {
    throw Error('Requested key length too long')
  }

  if (typeof key !== 'string' && !Buffer.isBuffer(key)) {
    throw new TypeError('key must a string or Buffer')
  }

  if (typeof salt !== 'string' && !Buffer.isBuffer(salt)) {
    throw new TypeError('salt must a string or Buffer')
  }

  const keyBuf: Buffer = typeof key === 'string' ? Buffer.from(key) : key
  const saltBuf: Buffer = typeof salt === 'string' ? Buffer.from(salt) : salt

  const DK = Buffer.alloc(dkLen)

  let U = Buffer.alloc(hLen)
  const T = Buffer.alloc(hLen)
  const block1 = Buffer.alloc(saltBuf.length + 4)

  const l = Math.ceil(dkLen / hLen)
  const r = dkLen - (l - 1) * hLen

  saltBuf.copy(block1, 0, 0, saltBuf.length)
  for (let i = 1; i <= l; i++) {
    block1[saltBuf.length + 0] = (i >> 24 & 0xff)
    block1[saltBuf.length + 1] = (i >> 16 & 0xff)
    block1[saltBuf.length + 2] = (i >> 8 & 0xff)
    block1[saltBuf.length + 3] = (i >> 0 & 0xff)

    U = createHmac('sha512', keyBuf).update(block1).digest()

    U.copy(T, 0, 0, hLen)

    for (let j = 1; j < iterations; j++) {
      U = createHmac('sha512', keyBuf).update(U).digest()

      for (let k = 0; k < hLen; k++) {
        // Both buffers are allocated at exactly hLen above, so k is always in
        // range; the assertions satisfy noUncheckedIndexedAccess without
        // weakening it elsewhere.
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
