# Changelog

All notable changes to `@smartledger/bsv-core` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this package
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with one clause above it:
if BSV mainnet consensus changes, this package follows the network in a minor rather than
waiting for a major. See **Stability** in the README.

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
