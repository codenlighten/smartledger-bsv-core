# BUG: the Chronicle fixtures pin fail-closed behaviour the node does not have

**Files:** `conformance/fixtures/chronicle.json` (4 cases),
`conformance/fixtures/interpreter.json` (2 cases), and the reasoning in
`CHRONICLE.md` §Gaps 1
**Affects:** `@smartledger/bsv-core` 0.1.0 (current `main`)
**Severity:** Not a crash — a **baseline that has frozen an incorrect assumption**,
which is worse in a corpus than in code, because it now actively defends the
wrong answer.
**Status:** Unfixed there. Corrected in `@smartledger/bsv` 7.8.0, which can be
used as the reference.

## Summary

`CHRONICLE.md` concludes that bytes 182/183 should fail closed until the shift
semantics are implemented:

> ```
> byte 182 -> SCRIPT_ERR_BAD_OPCODE
> byte 183 -> SCRIPT_ERR_BAD_OPCODE
> ```
> Refusing to validate is safe; validating wrongly is not.

That reasoning is sound in the absence of a specification. It is also **not what
SV Node does**, and the fixtures have since frozen it as the expected result.

## The node source

`src/script/interpreter.cpp`, `case OP_LSHIFTNUM` and `case OP_RSHIFTNUM`, both
open with:

```cpp
if(!utxo_after_chronicle)
{
    if(IsDiscourageUpgradableNops(flags))
        return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
    else
        break;          // no-op
}
```

Before Chronicle activates for the UTXO these bytes are **upgradable NOPs**, not
errors. So a library that rejects them refuses scripts the network accepts.

This is worth stating precisely, because it cuts against the framing in
`CHRONICLE.md` (and in the note I received, and in my own 7.6.0 release):
**byte 182 behaving as a no-op was correct pre-Chronicle.** The genuine defect
was that it would have *stayed* a no-op *after* activation — silently skipping a
shift. Fail-closed traded a wrong answer in one regime for a wrong answer in the
other.

## Cases that need regenerating

Run against `@smartledger/bsv@7.8.0`:

```
[value] byte 182 with shift operands on the stack
  fixture: {"errstr":"SCRIPT_ERR_BAD_OPCODE","stack":["04","01"],"verified":false}
  run:     {"errstr":"",                     "stack":["04","01"],"verified":true}

[value] byte 182 (OP_LSHIFTNUM in Chronicle) evaluated alone
  fixture: {"errstr":"SCRIPT_ERR_BAD_OPCODE","stack":[],"verified":false}
  run:     {"errstr":"SCRIPT_ERR_EVAL_FALSE_NO_RESULT","stack":[],"verified":false}
```

…and the same pair for byte 183. In `interpreter.json`, `bitcoind script_tests
(all)` and `bitcoind script_tests: divergence from Core is exactly the known set`
also move — the divergence set **shrinks**, because bytes 182/183 behaving as
NOPs is what Core does too.

`bytes 184..188 evaluated alone` is unaffected and already agrees.

## The shift semantics, which are now fully determined

`CHRONICLE.md` lists four things the one-sentence spec leaves open. The
implementation answers all four, so they no longer have to stay unimplemented:

1. **Operand order** — the node's own comment is `// (x n -- out)`. The shift
   **count is on top**, the value beneath. Both popped, result pushed.
2. **"Preserving sign"** — `CScriptNum` is sign-magnitude, and the right shift
   **truncates toward zero**. From `script_num.cpp`:

   > `// Mathematical division by 2^bit_shift, rounding toward zero`
   > `// C++ arithmetic right shift rounds toward negative infinity,`
   > `// but we want division semantics (round toward zero)`
   > `// For negative values: n / 2^k = -((-n) >> k)`

   So `-5 1 OP_RSHIFTNUM` is **-2, not -3**. A two's-complement arithmetic shift
   would floor — which is the more natural guess, and wrong. The bignum path
   agrees: `bsv::bint` is OpenSSL `BN_rshift` on a sign-magnitude value. This is
   the same convention as your `OP_2DIV`, so `x 1 OP_RSHIFTNUM`, `x OP_2DIV` and
   `x 2 OP_DIV` should all agree — worth a case, since that is where a rounding
   change hides.
3. **Out-of-range counts** — `if(n < 0) return SCRIPT_ERR_INVALID_NUMBER_RANGE`.
   Right shift past the bit length is `0`, not an error. Left shift raises
   overflow, and `CScriptNum::operator<<=` bounds it **before** shifting
   (`current_size + shift_bytes > max_length`), so a huge count cannot allocate a
   huge number on the way to being rejected.
4. **Result encoding** — `values.getvch()`, minimal, bounded by
   `params.MaxScriptNumLength()`.

## Why the corpus did not catch this

For the reason your own note taught me, now pointing the other way: the corpus
**freezes current behaviour**, so it detects a *change* and is silent on a
*pre-existing wrong assumption*. Both fail-closed implementations agreed with
each other, and agreement between two libraries that made the same inference is
not evidence.

Worth adding to `conformance/README.md`'s "Design" section, next to the
rejections-are-first-class note: a fixture recording behaviour the maintainer
believes is wrong should say so at the point of recording. The `chronicle.js`
header already does this well for the *numbering* — "pins today's behaviour, the
correct parts and the wrong parts alike" — but nothing distinguishes, in the
fixture itself, a value that is pinned because it is right from one pinned
because it is merely current.

## Suggested order

1. Change the pre-activation path to the upgradable-NOP behaviour above.
2. Regenerate the six cases (`--suite=chronicle`, `--suite=interpreter`) — noting
   that the `--suite=X` manifest bug you already fixed is what makes this safe to
   do per-suite now.
3. Implement the shifts; the four answers above are enough.
4. Update `CHRONICLE.md` §Gaps 1 — it is the record of what should happen, and
   it currently records the guess.

Reference implementation and tests: `@smartledger/bsv` 7.8.0,
`lib/script/interpreter.js` (`case Opcode.OP_LSHIFTNUM`) and
`test/script/chronicle.js`, where each case is mapped to the line of C++ it came
from.

Happy to open this as a GitHub issue instead if that suits you better — I left it
as a file because that is how the last two notes reached me.
