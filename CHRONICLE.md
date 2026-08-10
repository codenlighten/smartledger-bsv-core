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

### 2. `OP_2MUL` / `OP_2DIV` are hard-coded as permanently disabled

```
OP_2MUL  ->  SCRIPT_ERR_DISABLED_OPCODE
OP_2DIV  ->  SCRIPT_ERR_DISABLED_OPCODE
```

The interpreter has them in a branch commented "Permanently disabled opcodes."
Chronicle restores both. They need real implementations (multiply/divide the
top stack item by two), gated the same way the other restored opcodes are.

### 3. `OP_VER` / `OP_VERIF` / `OP_VERNOTIF` are unimplemented

```
OP_VER  ->  SCRIPT_ERR_BAD_OPCODE
```

They are in the opcode map at the right numbers, but the interpreter's switch
has no cases for them, so they fall through to the bad-opcode default. Under
Chronicle, `OP_VER` pushes the transaction version onto the stack, and
`OP_VERIF`/`OP_VERNOTIF` compare against it.

### 4. No `CHRONICLE` sighash flag, no OTDA

Chronicle reintroduces the Original Transaction Digest Algorithm alongside
BIP-143, selected by a new sighash flag `CHRONICLE = 0x20`. The library's
signature flags are:

```
SIGHASH_ALL = 0x1   SIGHASH_NONE = 0x2   SIGHASH_SINGLE = 0x3
SIGHASH_FORKID = 0x40   SIGHASH_ANYONECANPAY = 0x80
```

There is no 0x20 flag and no OTDA digest path. Transactions that need the
original digest cannot be signed or verified with this library.

## Status and remaining priority

Chronicle shipped in SV Node **v1.2.0** (January 2026), with mainnet activation
scheduled at height 943,816 — around 7 April 2026. Confirm the current chain
height before treating any of this as future work rather than a live gap.

Done:

- **Opcode numbering**, including the fail-closed behaviour for the two shift
  opcodes and for bytes 186–188. This was priority 1 because it was the only
  gap producing silently wrong results rather than errors.

Remaining, in order:

1. **The `CHRONICLE` sighash flag and OTDA** — blocks a class of transaction
   outright, and unlike the rest cannot be worked around by a caller.
2. **`OP_LSHIFTNUM`/`OP_RSHIFTNUM` semantics** — blocked on the four questions
   above, not on effort.
3. **`OP_2MUL`/`OP_2DIV`**, then the **`OP_VER` family**. These fail loudly, so
   they are visible rather than deceptive.

Every one of these needs conformance fixtures before implementation, so the
corpus records the current behaviour and the change lands as a deliberate
outcome flip. `conformance/suites/chronicle.js` already covers all four.

## Sources

- [Chronicle Release — BSV Skills Center](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)
- [Chronicle Update FAQ — BSV Blockchain](https://bsvblockchain.org/news/chronicle-update-faq/)
