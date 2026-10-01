# Changelog

All notable changes to `@smartledger/bsv-core` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this package
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with one clause above it:
if BSV mainnet consensus changes, this package follows the network in a minor rather than
waiting for a major. See **Stability** in the README.

## [1.0.3] - 2026-10-01

Seven divergences from the reference node. Five came from a differential fuzzer run against
`@smartledger/bsv` by a second session; two more came from that session's review of the first
fixes. **Six are fail-closed — wrong in the direction of refusal — and one is a false accept**,
the empty-operand shift count described below. Each was invisible to the node's 1483-row corpus,
which this package passes completely before and after.

### Fixed — four decode sites kept the 4-byte script-number limit after Genesis

`OP_PICK`/`OP_ROLL`'s index, the `OP_1ADD` family's operand, `OP_LSHIFT`/`OP_RSHIFT`'s count and
`OP_SPLIT`'s position. In the node every operand decode takes `params.MaxScriptNumLength()`;
**only** `nLockTime` and `nSequence` (5 bytes) and the two `OP_CHECKMULTISIG` counts (4 bytes) are
era-independent. Post-Genesis arithmetic on a number wider than four bytes — ordinary bignum
contract work — was refused.

The audit that found these proposed changing the multisig counts too. That would have made this
package **more permissive than the node**, so those two stay at four, and a test now pins them in
all three eras.

### Fixed — `OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY` were enforced after Genesis

Genesis reverted both to upgradable NOPs for outputs created after it. The node reads
`if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) || utxo_after_genesis)`, and
`DISCOURAGE_UPGRADABLE_NOPS` still fires inside that branch — so the fix is not simply to skip
the opcode.

### Fixed — `OP_CHECKSEQUENCEVERIFY` could not succeed at all

`nSequence.and(nLockTimeMask)` passed a plain number to bn.js, which throws
`num.clone is not a function`; the evaluator reported `SCRIPT_ERR_UNKNOWN_ERROR`. Every spend that
reached the comparison — a version 2 or greater transaction with the disable bit clear, which is
precisely what CSV exists for — failed with an error pointing at the script rather than at this
line. It was marked "BUG, PRESERVED" in the source, carried so the port matched the library at the
time of the carve; the library has since fixed it, so preserving it stopped being fidelity.

### Fixed — a missing input threw instead of returning a verdict

`checkLockTime` and `checkSequence` reached `this.tx!.inputs[this.nin!]!`. TypeScript's non-null
assertion silences the compiler and emits nothing, so it read as checked and threw at runtime.

### Security — an invalid shift count was accepted whenever the operand was empty

`OP_LSHIFT` and `OP_RSHIFT` short-circuited when the value being shifted was empty, popping the
count without decoding it — and therefore without any of its three checks. A negative count, a
count too wide for the era, and a non-minimally-encoded count were all accepted, where the node
refuses each by name. **A false accept**, and the only place in that block where the operand's
length decided whether the count was validated at all. The node's sole guard before the decode is
`stack.size() < 2`.

Found by the reviewing session's own red-team of the fix plan, after my first attempt at the shift
rewrite preserved the early-out.

### Fixed — `OP_NUM2BIN`'s size was not bounded by INT32_MAX

The node caps it in every era, **before** the element-size test:

```cpp
if(n < 0 || n > std::numeric_limits<int32_t>::max()) return SCRIPT_ERR_PUSH_SIZE;
const auto size{n.to_size_t_limited()};
if(!utxo_after_genesis && (size > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
    return SCRIPT_ERR_PUSH_SIZE;
```

The era only widens the second test. Without the first, a size above INT32_MAX passed the
post-Genesis element check, which is effectively unbounded, and the allocation that followed was
proportional to the operand's **value** rather than its length — work paid before any verdict was
reached. A size the node refuses without allocating is now refused the same way.

**The cap matches the node; it does not make the opcode cheap.** A size just under `INT32_MAX` is
consensus-valid and still requests an allocation approaching 2 GB, from a script of a few bytes, so
a limit on script size does not address it. This release adds no execution or allocation budget and
this package enforces none — see the note on `OP_DIV` at the end.

### Changed — the shift opcodes cost one pass over the operand

`OP_LSHIFT` and `OP_RSHIFT` now test the count as a big integer and, where it reaches the
operand's full width, return that many zero bytes directly — the node's shape:

```cpp
if(n < 0) return SCRIPT_ERR_INVALID_NUMBER_RANGE;
if(n >= values.size() * bits_per_byte) fill(begin(values), end(values), 0);
else { ... LShift(values, n.getint()) ... }
```

Its `LShift` allocates `valtype result(x.size(), 0x00)` and loops over `x.size()`; nothing it
allocates is proportional to the count. The previous implementation built the shifted value as a
big integer first and then truncated, so work grew with the count rather than the operand: `ushln`
allocates a value of the shifted width, which is the count's magnitude, not the operand's. Past a
certain count the implied length is not a valid array length and it raised a `RangeError`, which
the evaluator reported as `SCRIPT_ERR_UNKNOWN_ERROR`. **That is a false reject as well as a cost
problem**: the node returns zero bytes for the same script, so this package refused spends the node
accepts. Verified identical to the previous
implementation on 719,360 operand-and-count pairs — every value at operand lengths 1 to 4, sampled
above 4096 per length, at every count from 0 to 8·len+4, both directions. That equivalence covers
the **valid counts for which the previous implementation completed**, and over those the output is
byte-identical; it deliberately does not cover the counts that previously threw, or the
empty-operand counts above, where the verdict changes on purpose. Both have their own tests, and
the shipped tests assert the cost bound as well as the verdicts.

### Note on `OP_DIV` and `OP_MOD`

Both are quadratic in operand length. **This is not a consensus divergence and is not changed in
this release.** The node shares the shape: `OP_DIV`/`OP_MOD` are bounded only by
`params.MaxScriptNumLength()` and its `bsv::bint` division is also schoolbook, so verdicts and
bounds match and changing ours would diverge from consensus.

Parity settles the verdict, not the cost. **Quadratic CPU exhaustion remains a risk when evaluating
attacker-controlled scripts.** The node's practical protection is policy rather than consensus —
`DEFAULT_MAX_SCRIPT_SIZE_POLICY_AFTER_GENESIS` of 500 KB and
`DEFAULT_STACK_MEMORY_USAGE_POLICY_AFTER_GENESIS` of 100 MB — neither of which is a CPU-time bound,
and this package enforces neither. Measured here: 320 KB of operand takes about 18 seconds, growing
by roughly 4× per doubling. Evaluating untrusted scripts needs a bound on execution resources, not
just on input size: run it in a process whose memory and CPU time are capped. An opt-in budget is
under consideration and will not change default behaviour.

## [1.0.2] - 2026-10-01

### Fixed — the Magnetic opcodes needed a flag the node does not have

`OP_MUL`, `OP_LSHIFT`, `OP_RSHIFT` and `OP_INVERT` were refused unless
`SCRIPT_ENABLE_MAGNETIC_OPCODES` was set, "for backwards compatibility". The reference node has
no such flag: `IsOpcodeDisabled` (`src/script/interpreter.cpp`) disables `OP_2MUL` and `OP_2DIV`
and nothing else, so those four execute in every era it can validate.

Ported from `@smartledger/bsv`, where it was fixed first, and **1.0.0 and 1.0.1 both shipped
with the gate**. A second session audited this package independently and measured the cost under
the node's own per-row flags: **66 false rejects and 11 rows failing for the wrong reason**, no
false accepts. Fail-closed throughout, so nothing was ever wrongly accepted, but they are spends
the network accepts.

Its full list, kept because it is more useful than the total: `OP_INVERT` rows 920–928,
`OP_LSHIFT` 932–948, `OP_RSHIFT` 952–968, `OP_MUL` 976 and 978–999; and eleven rows where the
node gives `INVALID_STACK_OPERATION`, `INVALID_NUMBER_RANGE`, `SCRIPTNUM_OVERFLOW` or
`SCRIPTNUM_MINENCODE` and this package said `DISABLED_OPCODE`.

The gate was invisible to the default gate because the harness grants both library-only opcode
bits to every row so the report is not dominated by that difference. With them withheld the score
is now **1483/1483 with no false accepts, no false rejects and no wrong-reason rows** — the
acceptance test the auditing session set before the fix was written.

Two regression cases came from its mutation probe and pin the other direction, that the fix did
not remove too much: a Magnetic opcode in an **unexecuted** branch now runs in both eras, where
it was `DISABLED_OPCODE` pre-Genesis, and `OP_2MUL` in an unexecuted branch is still
`DISABLED_OPCODE` pre-Genesis and harmless after it — the node's rule being
`IsOpcodeDisabled && (!utxo_after_genesis || fExec)`.

The twelve Bitcoin Core rows expecting `DISABLED_OPCODE` are recorded as divergences. They
describe Core's permanent disablement, which BSV abandoned in 2018; the node's own corpus uses
these opcodes in 77 rows and expects `OK` on 66.

Both flag constants remain exported and accepted, since they are public API. Setting either is
now redundant.

## [1.0.1] - 2026-09-30

### Fixed — the starting figure quoted in 1.0.0 was not a real measurement

1.0.0 said the corpus "began at 1429 of 1483 with 29 false accepts". Both numbers were real; the
pair was not. Re-measured at the branch point with the harness as it now stands, the true figure
is **1424 of 1483 with 30 false accepts**.

The 1429 came from *after* the first of the nine fixes had already landed — the opcode cap — and
the 29 came from a run with the harness **before** it mirrored `DoTest`'s
`if(flags & SCRIPT_VERIFY_CLEANSTACK) flags |= SCRIPT_VERIFY_P2SH`. Without that rule the
`UTXO_AFTER_GENESIS,CLEANSTACK` row ran under a flag set `VerifyScript` refuses outright, so it
was not testing clean stacks at all and its false accept went uncounted. Fixing the harness
revealed a thirtieth.

For the record, the 30 grouped by cause: **14** multiple `OP_ELSE` after Genesis, **8**
`OP_VERIF`/`OP_VERNOTIF` era gating, **7** Chronicle `OP_SUBSTR`/`OP_LEFT`/`OP_RIGHT` range and
stack checks, and **1** `CLEANSTACK` judged against the wrong stack. All 30 are rows of
`script_tests.json`. The two defects found later — `LOW_S` masking the `STRICTENC` checks, and
Chronicle's malleability relaxations — are **not** among them and are not reachable by that
corpus at all.

Nothing in the code changed. This is a release because the figure ships in the README and the
changelog, and a package whose argument is measurement should not carry a number that was never
measured.

### Added

- `test/data/blind-spot-vectors.json` in `@smartledger/bsv` — nine portable vectors covering the
  two blind spots, in raw bytes with the node's flag names, for other implementations to replay.

## [1.0.0] - 2026-09-30

First stable release. The TypeScript port is complete, and the script engine agrees with the
reference node on every row of the node's own test vectors.

### The headline: exact agreement with the reference node

`bitcoin-sv` v1.2.2's `src/test/data/script_tests.json`, copied verbatim and replayed
unmodified: **1483 of 1483**, with **no false accepts, no false rejects and no wrong reasons** —
the same verdict as the node, for the same stated reason, on every row. Its `sighash.json` is
likewise 1000 of 1000 across both digest columns.

It began at **1424 of 1483 with 30 false accepts**: 30 ways to call a spend valid that the
network would refuse. Closing them took nine fixes, each measured rather than inspected:

- **the pre-Genesis opcode cap is BSV's 500, not Core's 201** (`consensus.h:40`). Inherited from
  Bitcoin Core, it rejected scripts BSV has accepted since 2020.
- **the digest is chosen by the signature's Chronicle bit, not by a flag.** The node routes on
  the bit alone, so `tx.sign()` had been producing signatures this package's own verifier
  rejected.
- **one `OP_ELSE` per `OP_IF` after Genesis** (`vfElse`), where a repeat had been allowed.
- **`OP_VERIF` and `OP_VERNOTIF` gate on the era of the output being spent**, not on this
  package's opt-in flag. An unexecuted one is harmless only when the UTXO is post-Genesis.
- **the Chronicle string and shift opcodes gate on the same era.** Under the node's own flag
  sets `OP_LEFT`, `OP_RIGHT`, `OP_SUBSTR`, `OP_VER`, `OP_LSHIFTNUM` and `OP_RSHIFTNUM` fell
  through to the upgradable-NOP path: they consumed nothing, execution continued, and an
  out-of-range argument raised no error at all.
- **four faults in `VerifyScript`**: Genesis removed P2SH, so a P2SH-shaped output made after it
  is an ordinary script whose redeem script is never run; `CLEANSTACK` judged a stack snapshot
  taken before the scriptPubkey ran; `CLEANSTACK` without `P2SH` threw an internal error instead
  of reporting a bad flag set; and `SIGPUSHONLY` is a rule of an era rather than of the flag.
- **`LOW_S` masked every `STRICTENC` signature check.** Three independent `if`s had been chained
  with `else if`, so on the default flags an undefined sighash type, a signature missing the
  FORKID bit where FORKID is required, and one requesting the Chronicle digest outside Chronicle
  were all **accepted**.
- **Chronicle's malleability relaxations were never applied.** A transaction with version above 1
  opts into malleability, and the node then stops enforcing `LOW_S`, `MINIMALDATA`, `MINIMALIF`,
  `NULLFAIL` (both `CHECKSIG` and `CHECKMULTISIG`), `NULLDUMMY`, `SIGPUSHONLY` and `CLEANSTACK`.
  All seven were enforced regardless, so valid transactions were refused.
- **four failures named the wrong reason**: `OP_DIV` and `OP_MOD` compared a BN against the
  number `0`, so neither zero-guard ever fired; a truncated `PUSHDATA` threw past the evaluator;
  and `OP_NUM2BIN` had no lower bound on its size.

Neither of the last two was visible to any corpus. Every one of the node's 1483 rows carries
transaction version 1, and not one pairs `LOW_S` with a hash-type expectation. Both were found by
transcribing the node's whole function against the C++ rather than reading the line under repair.

### Fixed — the package was unusable from TypeScript, which nothing was checking

Found by compiling as a *consumer* against the packed tarball, which is the only place these
are visible. `npm run typecheck` compiles this package's own source, where every type resolves
from devDependencies; a consumer installs only what `dependencies` ships.

- **`dist/index.d.ts` was `declare const bsv: Record<string, any>`.** Every member of the
  package root was `any`, so a TypeScript consumer got no checking at all from the package root
  — while the per-module `dist/*.d.ts` beside it carried real types the whole time. The root now
  exports an interface whose members are `typeof` the modules they come from, so the types are
  the modules' own and cannot drift from them.
- **`ScriptConstructor` declared `Interpreter: unknown`**, making
  `bsv.Script.Interpreter.mainnetFlags()` a TS18046 error for everyone. It was `unknown` to
  avoid a type cycle, but `import type` is erased, so there was no runtime edge to avoid. This
  was the consensus-critical class in the package and the one least excusable to ship untyped.
- **`@types/bn.js` and `@types/node` were devDependencies**, while the shipped declarations
  reference `bn.js` and `Buffer`. A consumer got TS7016 on import. They are dependencies now.

`npm run check:consumer-types` installs the tarball into a throwaway directory with nothing
added by hand and compiles a strict consumer against it. CI runs it, so this class of defect
cannot ship again unnoticed.

### Added

- **CI.** Nothing previously ran on a push or a pull request. Five jobs now do, and the corpus
  is a gate: a single false accept, false reject or wrong reason fails the build, as does a
  summary the job cannot parse.
- `Interpreter#enforceNonMalleability()`, beside `isAfterGenesis()` and `isAfterChronicle()`.
- The node's own vectors and the harnesses that run them, with provenance and hashes recorded in
  `test/data/bitcoin-sv/README.md`. They are not shipped in the tarball.

### Notes

The 455-case conformance corpus recorded from `@smartledger/bsv` is a **compatibility** gate, not
a correctness one. It reproduced several of that library's consensus bugs faithfully, which is
why the node's vectors were brought in beside it.

Two of the fixes here — the `LOW_S` masking and the malleability relaxations — were found in this
package's work and ported back to `@smartledger/bsv`, released there as 9.15.0.
