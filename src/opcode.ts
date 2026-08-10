'use strict'

import _ = require('./util/_')
import $ = require('./util/preconditions')
import JSUtil = require('./util/js')

import type { Opcode, OpcodeConstructor } from './opcode.types'

const Opcode = function Opcode (this: Opcode, num: number | string) {
  if (!(this instanceof Opcode)) {
    return new (Opcode as OpcodeConstructor)(num)
  }

  let value: number | undefined

  if (_.isNumber(num)) {
    value = num
  } else if (_.isString(num)) {
    value = (Opcode as OpcodeConstructor).map[num]
  } else {
    throw new TypeError('Unrecognized num type: "' + typeof (num) + '" for Opcode')
  }

  JSUtil.defineImmutable(this, {
    num: value
  })

  return this
} as unknown as OpcodeConstructor

Opcode.fromBuffer = function (buf: Buffer): Opcode {
  $.checkArgument(Buffer.isBuffer(buf))
  return new Opcode(Number('0x' + buf.toString('hex')))
}

Opcode.fromNumber = function (num: number): Opcode {
  $.checkArgument(_.isNumber(num))
  return new Opcode(num)
}

Opcode.fromString = function (str: string): Opcode {
  $.checkArgument(_.isString(str))
  const value = Opcode.map[str]
  if (typeof value === 'undefined') {
    throw new TypeError('Invalid opcodestr')
  }
  return new Opcode(value)
}

Opcode.prototype.toHex = function (this: Opcode): string {
  return this.num.toString(16)
}

Opcode.prototype.toBuffer = function (this: Opcode): Buffer {
  return Buffer.from(this.toHex(), 'hex')
}

Opcode.prototype.toNumber = function (this: Opcode): number {
  return this.num
}

Opcode.prototype.toString = function (this: Opcode): string {
  const str = Opcode.reverseMap[this.num]
  if (typeof str === 'undefined') {
    throw new Error('Opcode does not have a string representation')
  }
  return str
}

Opcode.smallInt = function (n: number): Opcode {
  $.checkArgument(_.isNumber(n), 'Invalid Argument: n should be number')
  $.checkArgument(n >= 0 && n <= 16, 'Invalid Argument: n must be between 0 and 16')
  if (n === 0) {
    return (Opcode as OpcodeConstructor)('OP_0')
  }
  return new (Opcode as OpcodeConstructor)((Opcode.map.OP_1 as number) + n - 1)
}

Opcode.map = {
  // push value
  OP_FALSE: 0,
  OP_0: 0,
  OP_PUSHDATA1: 76,
  OP_PUSHDATA2: 77,
  OP_PUSHDATA4: 78,
  OP_1NEGATE: 79,
  OP_RESERVED: 80,
  OP_TRUE: 81,
  OP_1: 81,
  OP_2: 82,
  OP_3: 83,
  OP_4: 84,
  OP_5: 85,
  OP_6: 86,
  OP_7: 87,
  OP_8: 88,
  OP_9: 89,
  OP_10: 90,
  OP_11: 91,
  OP_12: 92,
  OP_13: 93,
  OP_14: 94,
  OP_15: 95,
  OP_16: 96,

  // control
  OP_NOP: 97,
  OP_VER: 98,
  OP_IF: 99,
  OP_NOTIF: 100,
  OP_VERIF: 101,
  OP_VERNOTIF: 102,
  OP_ELSE: 103,
  OP_ENDIF: 104,
  OP_VERIFY: 105,
  OP_RETURN: 106,

  // stack ops
  OP_TOALTSTACK: 107,
  OP_FROMALTSTACK: 108,
  OP_2DROP: 109,
  OP_2DUP: 110,
  OP_3DUP: 111,
  OP_2OVER: 112,
  OP_2ROT: 113,
  OP_2SWAP: 114,
  OP_IFDUP: 115,
  OP_DEPTH: 116,
  OP_DROP: 117,
  OP_DUP: 118,
  OP_NIP: 119,
  OP_OVER: 120,
  OP_PICK: 121,
  OP_ROLL: 122,
  OP_ROT: 123,
  OP_SWAP: 124,
  OP_TUCK: 125,

  // splice ops
  OP_CAT: 126,
  OP_SPLIT: 127,
  OP_NUM2BIN: 128,
  OP_BIN2NUM: 129,
  OP_SIZE: 130,

  // bit logic
  OP_INVERT: 131,
  OP_AND: 132,
  OP_OR: 133,
  OP_XOR: 134,
  OP_EQUAL: 135,
  OP_EQUALVERIFY: 136,
  OP_RESERVED1: 137,
  OP_RESERVED2: 138,

  // numeric
  OP_1ADD: 139,
  OP_1SUB: 140,
  OP_2MUL: 141,
  OP_2DIV: 142,
  OP_NEGATE: 143,
  OP_ABS: 144,
  OP_NOT: 145,
  OP_0NOTEQUAL: 146,

  OP_ADD: 147,
  OP_SUB: 148,
  OP_MUL: 149,
  OP_DIV: 150,
  OP_MOD: 151,
  OP_LSHIFT: 152,
  OP_RSHIFT: 153,

  OP_BOOLAND: 154,
  OP_BOOLOR: 155,
  OP_NUMEQUAL: 156,
  OP_NUMEQUALVERIFY: 157,
  OP_NUMNOTEQUAL: 158,
  OP_LESSTHAN: 159,
  OP_GREATERTHAN: 160,
  OP_LESSTHANOREQUAL: 161,
  OP_GREATERTHANOREQUAL: 162,
  OP_MIN: 163,
  OP_MAX: 164,

  OP_WITHIN: 165,

  // crypto
  OP_RIPEMD160: 166,
  OP_SHA1: 167,
  OP_SHA256: 168,
  OP_HASH160: 169,
  OP_HASH256: 170,
  OP_CODESEPARATOR: 171,
  OP_CHECKSIG: 172,
  OP_CHECKSIGVERIFY: 173,
  OP_CHECKMULTISIG: 174,
  OP_CHECKMULTISIGVERIFY: 175,

  OP_CHECKLOCKTIMEVERIFY: 177,
  OP_CHECKSEQUENCEVERIFY: 178,

  // expansion
  OP_NOP1: 176,
  OP_NOP2: 177,
  OP_NOP3: 178,

  // Chronicle takes over the upper NOP range. Each of these bytes WAS a NOP;
  // the spec names which one, and that is what fixes the numbering:
  //
  //   179  OP_SUBSTR      was OP_NOP4
  //   180  OP_LEFT        was OP_NOP5
  //   181  OP_RIGHT       was OP_NOP6
  //   182  OP_LSHIFTNUM   was OP_NOP7
  //   183  OP_RSHIFTNUM   was OP_NOP8
  //
  // So OP_NOP4..OP_NOP8 no longer exist, and OP_NOP9/OP_NOP10 keep their own
  // consensus bytes rather than being shifted up. An earlier version of this
  // map slid the NOP names upward instead, which put OP_NOP4/OP_NOP5 on the
  // shift opcodes' bytes and invented OP_NOP8..OP_NOP10 at 186-188 — three
  // bytes that are not valid opcodes at all.
  OP_SUBSTR: 179,
  OP_LEFT: 180,
  OP_RIGHT: 181,
  OP_LSHIFTNUM: 182,
  OP_RSHIFTNUM: 183,

  // The only NOPs left above OP_NOP3.
  OP_NOP9: 184,
  OP_NOP10: 185,

  // template matching params
  OP_PUBKEYHASH: 253,
  OP_PUBKEY: 254,
  OP_INVALIDOPCODE: 255
}

Opcode.reverseMap = []

for (const k in Opcode.map) {
  Opcode.reverseMap[Opcode.map[k] as number] = k
}

// Easier access to opcodes
_.extend(Opcode, Opcode.map)

/**
 * @returns true if opcode is one of OP_0, OP_1, ..., OP_16
 */
Opcode.isSmallIntOp = function (opcode: Opcode | number): boolean {
  const n = typeof opcode === 'number' ? opcode : opcode.toNumber()
  return ((n === Opcode.map.OP_0) ||
    ((n >= (Opcode.map.OP_1 as number)) && (n <= (Opcode.map.OP_16 as number))))
}

/**
 * Will return a string formatted for the console
 *
 * @returns {string} Script opcode
 */
Opcode.prototype.inspect = function (this: Opcode): string {
  return '<Opcode: ' + this.toString() + ', hex: ' + this.toHex() + ', decimal: ' + this.num + '>'
}

export = Opcode
