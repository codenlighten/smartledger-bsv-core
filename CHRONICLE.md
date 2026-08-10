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

### 1. `OP_LSHIFTNUM` and `OP_RSHIFTNUM` are missing — and byte 182 silently misreads

Chronicle adds two opcodes:

| opcode | byte | was |
| --- | --- | --- |
| `OP_LSHIFTNUM` | 182 (0xb6) | `OP_NOP7` |
| `OP_RSHIFTNUM` | 183 (0xb7) | `OP_NOP8` |

Neither name exists in this library. Worse, the library's own NOP renumbering
already claims those bytes:

```
byte 182 -> OP_NOP4
byte 183 -> OP_NOP5
byte 184 -> OP_NOP6
byte 185 -> OP_NOP7
byte 186 -> OP_NOP8      <- 0xba, not a valid opcode in consensus
byte 187 -> OP_NOP9      <- 0xbb
byte 188 -> OP_NOP10     <- 0xbc
```

So a Chronicle script containing `OP_LSHIFTNUM` is read by this library as
`OP_NOP4` and evaluates as a **no-op that succeeds**:

```
OP_NOP4 (byte 182)  ->  verify() = true, stack unchanged
```

This is the dangerous class of divergence: the library reports a script valid
without performing the shift, so a result that differs from what a node
computes is never surfaced as an error. It is not a crash, it is a wrong
answer.

The three bytes above 185 are a separate problem: 0xba–0xbc are invalid
opcodes in consensus, and this library names them `OP_NOP8`–`OP_NOP10` and
treats them as upgradable NOPs.

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

## Priority

1. `OP_LSHIFTNUM`/`OP_RSHIFTNUM` and the NOP renumbering, because that one
   produces silently wrong validation results rather than an error.
2. The `CHRONICLE` sighash flag and OTDA, because it blocks a class of
   transaction outright.
3. `OP_2MUL`/`OP_2DIV`, then the `OP_VER` family — these fail loudly, so they
   are visible rather than deceptive.

Each of these needs conformance fixtures before implementation, so that the
corpus records the current (wrong) behaviour as a deliberate change rather
than an accident.

## Sources

- [Chronicle Release — BSV Skills Center](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)
- [Chronicle Update FAQ — BSV Blockchain](https://bsvblockchain.org/news/chronicle-update-faq/)
