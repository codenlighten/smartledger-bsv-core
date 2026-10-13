'use strict'

import type { ScriptChunk } from './script.types'

/**
 * Is this chunk a push whose data runs past the end of the script?
 *
 * The node has no such predicate, because it never builds a chunk it cannot decode. It
 * parses on demand with `GetOp`, and a push that runs past the end simply makes the parse
 * FAIL:
 *
 *     if (end() - pc < 0 || (unsigned int)(end() - pc) < nSize)
 *         return false;                                      // script.h, GetOp2
 *
 * This library parses eagerly instead, and keeps the broken push as a chunk carrying the
 * DECLARED length in `len` and the bytes actually present in `buf`. That is a reasonable
 * representation — it is what lets `toBuffer` round-trip a malformed script byte for byte —
 * but it means every place that would have called `GetOp` must test for the condition
 * itself, and `GetOp` is called from more than one place in the node:
 *
 *   - `EvalScript` reads each instruction with it (interpreter.cpp:450), and a failure there
 *     is `SCRIPT_ERR_BAD_OPCODE`;
 *   - `CScript::IsPushOnly` walks the script with it, and a failure there means NOT push-only.
 *
 * The check lived inline in the interpreter alone, so `isPushOnly` did not have it and said
 * a truncated push was a push. Under `SCRIPT_VERIFY_SIGPUSHONLY` the node then rejects the
 * scriptSig before it is ever evaluated (VerifyScript checks IsPushOnly above EvalScript,
 * interpreter.cpp:2329), reporting `SCRIPT_ERR_SIG_PUSHONLY`, while this library passed the
 * push-only gate, went on to evaluate, and reported `SCRIPT_ERR_BAD_OPCODE` from the
 * instruction read. Both reject, so only an error-NAME comparison could see it.
 *
 * It is one definition in one place now because a duplicated predicate drifts. That is not
 * hypothetical here: `lib/ltp/proof.js` kept a private copy of the GDAF field encoding and
 * kept its defects through two rounds of fixes to the original (see lib/util/field-commit.js),
 * and the wrapper in lib/gdaf fell behind its delegate the same way.
 *
 * THE TEST IS `<`, NOT `!==`, and that distinction is load-bearing. `GetOp2` fails when the
 * script has FEWER bytes left than the push declares, and nothing else. A chunk whose buffer
 * is LONGER than its declared length is not a truncated push at all — it is a chunk that
 * disagrees with its own serialization, which the eager parser cannot produce but a caller
 * assembling chunks by hand can, and the extra bytes are simply the instructions that follow:
 *
 *     { opcodenum: 1, len: 1, buf: <aa51> }   serializes to   01 aa 51
 *     and 01 aa 51 parses back as             push <aa>, OP_1
 *
 * Both of those are push-only, so the node parsing those bytes answers TRUE. `!==` answered
 * FALSE — a FALSE REJECT, in a predicate whose whole job is to decide whether a scriptSig may
 * be evaluated. That was measured, not reasoned about, and it is the reason this is `<`.
 *
 * So the guarantee is stated narrowly: for a script PARSED FROM BYTES, this returns true for
 * exactly the pushes `GetOp` fails on, because the parser assigns the bytes present and
 * records the length declared. For a chunk list assembled by hand, no per-chunk predicate can
 * give the node's answer, since the node's answer is a function of the SERIALIZATION — a
 * caller who builds chunks directly and wants node semantics should round-trip them through
 * `Script.fromBuffer(script.toBuffer())` first.
 *
 * @param {object} chunk a parsed script chunk
 * @returns {boolean} true if the chunk is a push declaring more bytes than it carries
 */
function isUndecodablePush (chunk: ScriptChunk): boolean {
  // A zero-length buffer is not nullish, so `01` — a one-byte push with no byte after it —
  // is caught here rather than slipping through as "no buffer at all".
  return chunk.buf != null && chunk.len !== undefined && chunk.buf.length < chunk.len
}

export { isUndecodablePush }
