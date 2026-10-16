'use strict'

/* global describe, it */

/**
 * `chunks.slice(this.pbegincodehash)` must be the node's BYTE POINTER suffix.
 *
 * The node holds the scriptCode start as a byte pointer into the raw script
 * (`CScript scriptCode(pbegincodehash, pend)`); both packages hold it as a CHUNK INDEX and slice
 * `script.chunks`. Those agree only if the chunks before the slice point re-serialize to exactly
 * the bytes they were parsed from -- so this is a parse-level property the interpreter depends on
 * at OP_CHECKSIG and OP_CHECKMULTISIG, and nothing asserted it.
 *
 * The cases that matter are the ones where an EAGER parser diverges from the node's GetOp walk: a
 * push whose declared length exceeds the bytes available. If such a chunk re-serialized to
 * anything but its original bytes, every byte offset after it would shift and the signed scriptCode
 * would differ from the network's -- the same class as the digest divergence fixed in 9.37.0.
 *
 * The twin of @smartledger/bsv's test/script/chunk_index_is_byte_pointer.js. This package
 * slices the same way, at src/script/interpreter.ts:2631 and :2730.
 *
 * Written 2026-10-16 after a review of go-sdk reached the same conclusion for that library by a
 * structural argument (its scriptCodeStart indexes a parser that is byte-faithful to the node's
 * walk, so index and byte pointer stay in lockstep by construction). The argument applies here
 * only as far as byte-faithfulness holds, and byte-faithfulness is exactly what these bodies
 * stress, so it is measured rather than argued.
 */
require('chai').should() // the should-style assertion extension; not referenced by name here
var bsv = require('../..')
var Script = bsv.Script

// Bodies with separators, truncated pushes, and separator bytes in operand/length positions.
var BODIES = [
  '4dab', '6a4dab', 'ab6a4dab', 'ab4dab', '6a4eab0000', 'ab6a4eababab',
  '4c02ab', '4eababab', '51abab6a4eababab', 'ab6a4c050102', '6a4c050102',
  '5102ab516a', '51ab52ab6a0401020304', 'ab', 'abab', 'ab4dab00', '4d01ab'
]

function bytesOf (chunks) {
  return new Script().set({ chunks: chunks }).toBuffer()
}

describe('a chunk index is the node\'s byte pointer', function () {
  BODIES.forEach(function (hex) {
    it(hex + ': every chunk-index slice equals the raw byte suffix', function () {
      var raw = Buffer.from(hex, 'hex')
      var s = Script.fromBuffer(raw)

      // Byte-faithful re-serialization is the premise the whole equivalence rests on.
      s.toBuffer().toString('hex').should.equal(hex,
        hex + ' does not re-serialize to its own bytes, so no chunk index is a byte pointer in it')

      for (var i = 0; i <= s.chunks.length; i++) {
        var head = bytesOf(s.chunks.slice(0, i))
        var tail = bytesOf(s.chunks.slice(i))
        // The split is exact: no byte is lost or duplicated at the boundary.
        ;(head.length + tail.length).should.equal(raw.length, hex + ' @' + i + ' split is not exact')
        // And the tail is the raw suffix at the head's length -- the byte pointer.
        tail.toString('hex').should.equal(raw.slice(head.length).toString('hex'),
          hex + ' @' + i + ': chunk slice is not the byte suffix')
      }
    })
  })

  it('exercises bodies whose parse stops early (otherwise the premise is untested)', function () {
    // An undecodable trailing push is the only shape where an eager parser can disagree with the
    // node's walk, so the list must contain some. If these ever became parseable-to-the-end, this
    // file would still pass while testing nothing of interest.
    var truncated = BODIES.filter(function (hex) {
      var s = Script.fromBuffer(Buffer.from(hex, 'hex'))
      return s.chunks.some(function (c) {
        return c.opcodenum >= 0x4c && c.opcodenum <= 0x4e &&
          (!c.buf || c.buf.length < (c.len === undefined ? 0 : c.len))
      }) || /4[cde]/.test(hex)
    })
    truncated.length.should.be.above(5,
      'no truncated-push bodies left in the list — the interesting half is untested')
  })
})
