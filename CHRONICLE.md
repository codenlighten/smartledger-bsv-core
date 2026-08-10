# Chronicle opcode conformance

Audit of this library's script surface against the BSV **Chronicle** release,
checked August 2026 against the SV Node documentation.

Everything below was verified by running the built library, not read off the
source.

## What is already correct

Chronicle restores `OP_SUBSTR`, `OP_LEFT` and `OP_RIGHT` at **new** opcode
numbers — 179/180/181 (0xb3–0xb5), not their original 127/128/129, because
those bytes now belong to `OP_SPLIT`, `OP_NUM2BIN` and `OP_BIN2NUM` from the
Magnetic upgrade. This library uses the new numbers and implements the original
Satoshi semantics:

```
'hello' OP_1 OP_3 OP_SUBSTR  ->  'ell'
'hello' OP_2 OP_LEFT         ->  'he'
```

`OP_VER` (98), `OP_VERIF` (101), `OP_VERNOTIF` (102), `OP_2MUL` (141) and
`OP_2DIV` (142) are all present in the opcode map at the correct numbers.

The full Genesis-restored set — `OP_CAT`, `OP_SPLIT`, `OP_AND`, `OP_OR`,
`OP_XOR`, `OP_INVERT`, `OP_LSHIFT`, `OP_RSHIFT`, `OP_MUL`, `OP_DIV`, `OP_MOD`,
`OP_NUM2BIN`, `OP_BIN2NUM` — is present and implemented in the interpreter.

## Gaps

### 1. `OP_LSHIFTNUM` / `OP_RSHIFTNUM` — numbering FIXED, semantics still missing

**Fixed.** The opcode map now reads:

```
179  OP_SUBSTR      was OP_NOP4
180  OP_LEFT        was OP_NOP5
181  OP_RIGHT       was OP_NOP6
182  OP_LSHIFTNUM   was OP_NOP7
183  OP_RSHIFTNUM   was OP_NOP8
184  OP_NOP9
185  OP_NOP10
186+ unassigned
```

The spec fixes this itself by naming which NOP each reassigned byte used to
be. An earlier version of the map slid the NOP names upward instead, which put
`OP_NOP4`/`OP_NOP5` on the shift opcodes' bytes and invented `OP_NOP8`–
`OP_NOP10` at 186–188 — three bytes that are not valid opcodes at all.

The consequence of that was the worst kind of bug: byte 182 parsed as a NOP
and **verified as true with both operands still on the stack**. A shift that
never happened, reported as success. It now fails closed:

```
byte 182 -> SCRIPT_ERR_BAD_OPCODE
byte 183 -> SCRIPT_ERR_BAD_OPCODE
byte 184 -> no-op (OP_NOP9)
byte 185 -> no-op (OP_NOP10)
byte 186..188 -> SCRIPT_ERR_BAD_OPCODE
```

Refusing to validate is safe; validating wrongly is not. Until the semantics
are implemented, rejecting is the correct posture for a validation library.

**Still missing: the semantics.** They are deliberately not implemented,
because the specification does not contain enough to implement them
correctly. The
[Chronicle spec](https://github.com/bitcoin-sv-specs/protocol/blob/master/updates/chronicle-spec.md)
says, in full:

> `OP_LSHIFTNUM` — Performs a numerical shift to left, preserving sign.
> Inputs: a, b. Output: Shifts a left b bits

That leaves at least four things undetermined, each of which changes the
result:

1. **Operand order.** Which of `a`/`b` is on top of the stack?
2. **What "preserving sign" means.** Script numbers are sign-magnitude — the
   sign lives in the high bit of the last byte — not two's complement. An
   arithmetic shift in one encoding is not the other.
3. **Negative or oversized shift counts.** Error, clamp, or wrap?
4. **Result encoding.** Minimally encoded, and subject to which element-size
   limit?

Guessing any of these produces a library that computes confident wrong
answers, which is precisely the failure mode this section began with. These
need the node implementation or a clarified spec before they are written.

### 2. `OP_2MUL` / `OP_2DIV` — DONE

Implemented, behind `SCRIPT_ENABLE_CHRONICLE`. Default behaviour is unchanged:
both remain `SCRIPT_ERR_DISABLED_OPCODE`, and "disabled" is stronger than
"unimplemented" — a disabled opcode fails the script even in an **unexecuted**
branch, which is why the gate lives in `isOpcodeDisabled` rather than in the
evaluation switch.

`OP_2DIV` truncates toward zero: `-5 OP_2DIV` is `-2`, not `-3`. That matches
the existing `OP_DIV`, so `x OP_2DIV` and `x 2 OP_DIV` agree — pinned as its
own conformance case over negative and odd values, which is where a rounding
change would otherwise hide. (`bn.js` `shrn` is unusable here: it asserts on
negative values.)

### 3. `OP_VER` / `OP_VERIF` / `OP_VERNOTIF` — DONE

Implemented, behind the same flag.

`OP_VER` pushes the executing transaction's version. `OP_VERIF` is an `IF`
whose condition is "top of stack equals the transaction version", closed by
`OP_ENDIF`; `OP_VERNOTIF` is its negation.

Two things worth recording:

- Before Chronicle, `OP_VERIF`/`OP_VERNOTIF` are invalid **even in an
  unexecuted branch** — a rule Bitcoin applies to no other opcode. The flag
  check deliberately sits outside the `fExec` guard so that this survives when
  Chronicle is off.
- The spec describes the comparison but not the stack effect. `OP_VERIF`
  **pops** its operand, mirroring `OP_IF`: the `OP_VERIF ... OP_ENDIF` form the
  spec documents is an `IF`, and an `IF` that left its condition on the stack
  would unbalance every script using it. That is an inference, and it is pinned
  by its own conformance case so a correction shows as a diff.

### 4. OTDA — DONE, and my earlier assessment of it was wrong

This section previously said "transactions that need the original digest
cannot be signed or verified with this library." That was false, and worth
recording as an error rather than quietly rewriting.

**The Original Transaction Digest Algorithm was already implemented.** It is
the path `sighashPreimage` takes whenever `SIGHASH_FORKID` is absent — blank
the other inputs' scripts, strip code separators, handle NONE/SINGLE. It even
reproduces the SIGHASH_SINGLE bug, returning the constant

```
0000000000000000000000000000000000000000000000000000000000000001
```

for an input with no corresponding output, which is the definitive fingerprint
of the original algorithm and is now pinned by its own conformance case.

What was missing was never the algorithm. It was the **selector**. Now added:

- `Signature.SIGHASH_CHRONICLE = 0x20`
- `Interpreter.SCRIPT_ENABLE_CHRONICLE`, and the routing that connects them.

Two design points worth stating, because neither is obvious:

**The flag overrides `SIGHASH_FORKID` rather than coexisting with it.** FORKID
is set on essentially every BSV signature written since 2018, so a CHRONICLE
bit that only took effect when FORKID was absent could never select OTDA in
practice and would mean nothing. The spec says OTDA usage "requires the
CHRONICLE sighash flag", which only has content if the flag decides the
routing.

**`SCRIPT_ENABLE_CHRONICLE` is off by default, and that gate is not caution
for its own sake.** Before Chronicle the 0x20 bit carries no meaning, so
BIP-143 signatures already exist whose sighash type happens to set it.
Honouring the bit unconditionally reinterprets every one of them as OTDA. That
was tried: it broke 252 of this repository's own tests. The gate follows the
shape already used for `SCRIPT_ENABLE_SIGHASH_FORKID` and `useGenesisLimits()`
— pre-upgrade rules stay the default, callers opt in.

One subtlety the conformance suite exists to catch: the sighash type byte is
committed *inside* the preimage, so setting 0x20 changes the digest **even
when it does not change the algorithm**. Comparing digests alone cannot tell
you which algorithm ran. The suite pins the algorithm, by holding the type
byte constant and varying only the routing.

## Status and remaining priority

Chronicle shipped in SV Node **v1.2.0** (January 2026), with mainnet activation
scheduled at height 943,816 — around 7 April 2026. Confirm the current chain
height before treating any of this as future work rather than a live gap.

Done:

- **Opcode numbering**, including the fail-closed behaviour for the two shift
  opcodes and for bytes 186–188. This was priority 1 because it was the only
  gap producing silently wrong results rather than errors.

- **The `CHRONICLE` sighash flag and OTDA routing.** The algorithm was already
  present; only the selector was missing.

- **`OP_2MUL`/`OP_2DIV` and the `OP_VER` family**, behind
  `SCRIPT_ENABLE_CHRONICLE`.

Remaining:

1. **`OP_LSHIFTNUM`/`OP_RSHIFTNUM` semantics** — the only gap left, and blocked
   on the four questions above rather than on effort. Needs the node
   implementation or a clarified spec. The numbering and the fail-closed
   behaviour are already in place, so scripts using them are rejected rather
   than mis-evaluated in the meantime.

Everything Chronicle changes is opt-in via `SCRIPT_ENABLE_CHRONICLE`, which is
off by default. Pre-Chronicle behaviour is byte-identical — verified by the
conformance fixtures, where enabling the feature added cases without altering
a single pre-existing outcome.

Every one of these needs conformance fixtures before implementation, so the
corpus records the current behaviour and the change lands as a deliberate
outcome flip. `conformance/suites/chronicle.js` already covers all four.

## Sources

- [Chronicle Release — BSV Skills Center](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)
- [Chronicle Update FAQ — BSV Blockchain](https://bsvblockchain.org/news/chronicle-update-faq/)
