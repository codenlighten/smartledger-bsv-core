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

### 1. `OP_LSHIFTNUM` / `OP_RSHIFTNUM` — DONE

Implemented from SV Node's `src/script/interpreter.cpp`, behind
`SCRIPT_ENABLE_CHRONICLE`. This section previously said the semantics were
blocked on the specification, which gives only:

> `OP_LSHIFTNUM` — Performs a numerical shift to left, preserving sign.
> Inputs: a, b. Output: Shifts a left b bits

That settles none of the four things an implementation needs. The node source
settles all of them:

- **Operand order** is `(x n -- out)`: the shift COUNT is on top, the value
  beneath.
- **"Preserving sign"** means shift the MAGNITUDE and carry the sign. Script
  numbers are sign-magnitude, so `-5 1 OP_RSHIFTNUM` is `-2`, **not** `-3` —
  division truncating toward zero, matching `OP_DIV` and `OP_2DIV`. A
  two's-complement arithmetic shift would floor to `-3`. (`bn.js` `shrn`/`shln`
  assert on negatives, so working on `abs()` is forced anyway.)
- **Negative counts** are `SCRIPT_ERR_INVALID_NUMBER_RANGE`. Left shifts are
  bounded BEFORE shifting, as `CScriptNum` does, so an enormous count cannot
  allocate an enormous number on the way to being rejected. Right shifts by at
  least the bit length are zero.
- **Result encoding** is a script number bounded by `MAXIMUM_ELEMENT_SIZE`.

And it corrects something this library had wrong. With Chronicle off, bytes
182/183 are **upgradable NOPs on the network, not errors**:

```
if(!utxo_after_chronicle) {
  if(IsDiscourageUpgradableNops(flags))
    return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
  else break;
}
```

An earlier build here returned `SCRIPT_ERR_BAD_OPCODE`, which made this library
**refuse scripts the network accepts** — the mirror image of the bug that made
them silently succeed, and no better. Both are now wrong-answer-free: NOP by
default, honouring `DISCOURAGE_UPGRADABLE_NOPS`, and a real shift once
Chronicle is enabled.

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

- **`OP_LSHIFTNUM`/`OP_RSHIFTNUM`**, ported from the node source.

The gating and the shift opcodes are done. Five divergences from the node
remain in the opcodes restored earlier — see "Divergences from SV Node still
outstanding" below.

Everything Chronicle changes is opt-in via `SCRIPT_ENABLE_CHRONICLE`, which is
off by default. Pre-Chronicle behaviour is byte-identical — verified by the
conformance fixtures, where enabling the feature added cases without altering
a single pre-existing outcome.

Every one of these needs conformance fixtures before implementation, so the
corpus records the current behaviour and the change lands as a deliberate
outcome flip. `conformance/suites/chronicle.js` already covers all four.

## Divergences from SV Node still outstanding

Checked against `src/script/interpreter.cpp` at tag **v1.2.0**. The first two
were confirmed against verbatim source; the rest follow from them or come from
a reading of the same file and should be re-confirmed line-by-line before the
fix lands, because these are consensus paths.

### A. `OP_SUBSTR`/`OP_LEFT`/`OP_RIGHT` run unconditionally

The node gates them exactly like the shift opcodes:

```cpp
case OP_SUBSTR:
{
    if(!utxo_after_chronicle)
    {
        if(flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
        else
            break;
    }
```

This library runs them with no flag check at all, so with Chronicle off
`'hello' 1 3 OP_SUBSTR` consumes three stack items and yields `ell`, where the
network performs a no-op. Same class of bug as the 182/183 one already fixed,
and it reaches further: bytes 179–181 are live upgradable NOPs today.

### B. `OP_VER` pushes the wrong bytes

```cpp
const auto tx_version{checker.Version()};
std::vector<uint8_t> val(sizeof(tx_version));
to_le(tx_version, val.data());
stack.push_back(std::move(val));
```

Four bytes, little-endian. This library pushes a minimally-encoded script
number: `01` for version 1, where the node pushes `01000000`. Any script that
consumes the value diverges immediately.

(The pre-Chronicle guard here IS correct — the node returns
`SCRIPT_ERR_BAD_OPCODE`, unlike the string opcodes.)

### C. `OP_VERIF` compares numerically instead of byte-wise

The node requires the top item to be exactly four bytes and compares it to the
little-endian version. This library does a numeric `BN` comparison, so
`OP_2 OP_VERIF` against version 2 is TRUE here and FALSE on the node.

### D. `OP_VERIF`/`OP_VERNOTIF` in an unexecuted branch

```cpp
if(!utxo_after_chronicle) { if(utxo_after_genesis && !fExec) break; else return SCRIPT_ERR_BAD_OPCODE; }
```

Post-Genesis, pre-Chronicle, in a non-executed branch, the node BREAKS. This
library returns `SCRIPT_ERR_BAD_OPCODE` regardless, so it rejects a script the
network accepts. The comment here claiming these are "invalid even in an
unexecuted branch" is true of pre-Genesis Bitcoin and not of BSV.

### E. `OP_SUBSTR`/`OP_LEFT`/`OP_RIGHT` clamp where the node errors

```cpp
if(offset < 0 || offset >= size || len < 0 || len > size - offset)
    return SCRIPT_ERR_INVALID_NUMBER_RANGE;
```

This library checks only for negatives. Measured:

```
'hi' 1 9 OP_SUBSTR  ->  library: 'i', script SUCCEEDS   node: INVALID_NUMBER_RANGE
'hi' 9 OP_LEFT      ->  library: 'hi', script SUCCEEDS  node: INVALID_NUMBER_RANGE
```

This is the dangerous shape again — a wrong answer rather than an error. A
script the node rejects validates here.

## Sources

- [Chronicle Release — BSV Skills Center](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)
- [Chronicle Update FAQ — BSV Blockchain](https://bsvblockchain.org/news/chronicle-update-faq/)
