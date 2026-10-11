# Changelog

All notable changes to `@smartledger/bsv-core` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this package
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with one clause above it:
if BSV mainnet consensus changes, this package follows the network in a minor rather than
waiting for a major. See **Stability** in the README.

## [1.4.0] - 2026-10-11

Additive, ported from `@smartledger/bsv` 9.31.0. No behaviour changes: `errstr` is untouched
and every script verifies exactly as it did in 1.3.0.

### Added — `nodeErrstr`, `Interpreter.toNodeErrorName()` and `Interpreter.NODE_ERROR_NAMES`

Most of this package's error names are the node's, spelled identically. Eight are not, and a
caller comparing a verdict against a node — or against a corpus recording `script_error.h`
names — had to work that out alone.

Four are deliberately finer: the node has one `SCRIPT_ERR_EVAL_FALSE` where this package
distinguishes `EVAL_FALSE_IN_STACK`, `EVAL_FALSE_NO_RESULT`, `EVAL_FALSE_IN_P2SH_STACK` and
`EVAL_FALSE_NO_P2SH_STACK`. The other four differ only in spelling and are kept because
changing `errstr` breaks anyone matching on it:

```
SCRIPT_ERR_NULLFAIL                -> SCRIPT_ERR_SIG_NULLFAIL
SCRIPT_ERR_SIG_DER_HIGH_S          -> SCRIPT_ERR_SIG_HIGH_S
SCRIPT_ERR_SIG_DER_INVALID_FORMAT  -> SCRIPT_ERR_SIG_DER
SCRIPT_ERR_UNDEFINED_OPCODE        -> SCRIPT_ERR_BAD_OPCODE
```

Each was confirmed at its emit site, not matched by name.

```ts
interp.errstr      // 'SCRIPT_ERR_EVAL_FALSE_NO_RESULT'  — what went wrong, precisely
interp.nodeErrstr  // 'SCRIPT_ERR_EVAL_FALSE'            — what the node would call it
```

**A derived read, not a mode**: no switch to set and nothing to restore, which keeps it clear
of the trap the process-wide limits statics set. `toNodeErrorName()` is the same translation as
a pure function and is safe on any string.

### What it closed

Against the 24,568-row bsv-lean-proofs corpus, whose expectations are `script_error.h` names
validated on a compiled bitcoin-sv v1.2.3, reading `nodeErrstr` instead of `errstr` takes the
error-name comparison from 456 mismatches to **0 across all 21,978 rows where both reject**.
With 1.3.0's 24,568 of 24,568 outcome agreement, this package now matches that corpus on every
verdict and every reason.

### The guard

`test/script/node_error_names.js` scans `src/script/interpreter.ts` for every `'SCRIPT_ERR_*'`
literal it can assign to `errstr` and fails if any neither appears in `script_error.h` nor has
a mapping, so adding a novel name without deciding the node's spelling breaks the build. It
also asserts the map has no dead entries and that every target exists in the header.

## [1.3.0] - 2026-10-11

**Two consensus fixes, and together they refuse scripts 1.2.x accepted.** A minor rather than a
major because consensus tracking overrides the versioning policy (see **Stability** in the
README): the scripts this now refuses were never valid on the network.

### Fixed — the Chronicle opcodes followed the BLOCK's era instead of the OUTPUT's

Ported from `@smartledger/bsv` 9.30.0. `isAfterChronicle()` accepted either
`SCRIPT_UTXO_AFTER_CHRONICLE` or `SCRIPT_ENABLE_CHRONICLE`, which are different eras:

```
SCRIPT_CHRONICLE (bit 20)             era of the BLOCK. Gates the malleability relaxations.
  == SCRIPT_ENABLE_CHRONICLE
SCRIPT_UTXO_AFTER_CHRONICLE (bit 21)  era of the OUTPUT being spent. Gates the restored
                                      opcodes and the per-era limits.
```

The node gates every restored Chronicle opcode on `utxo_after_chronicle` alone, at all eight
sites, and derives its limits era from the same bit. Accepting bit 20 made those opcodes live
when spending a pre-Chronicle output in a post-Chronicle block — the ordinary mainnet case,
and precisely the combination a correct caller must express.

**The comment above this function already said "never on SCRIPT_ENABLE_CHRONICLE alone". The
code accepted it anyway.** The comment was right and the implementation was not.

Measured against 24,568 node-validated rows of the bsv-lean-proofs corpus: the old reading
disagreed on 571, this one on none.

#### What a caller must change

`mainnetFlags()` sets both bits, so the default path is unchanged. A caller who passed
`SCRIPT_ENABLE_CHRONICLE` alone must add `SCRIPT_UTXO_AFTER_GENESIS |
SCRIPT_UTXO_AFTER_CHRONICLE`.

### Fixed — `Covenant.Helpers.flags()` omitted all three era flags

Exposed by the fix above and wrong on its own. The hand-assembled list returned `0x111e4f`
where `Interpreter.mainnetFlags()` returns `0x3d586f`: no `SCRIPT_GENESIS`, no
`SCRIPT_UTXO_AFTER_GENESIS`, no `SCRIPT_UTXO_AFTER_CHRONICLE`.

The era flags are what the interpreter derives its data limits from, so **every covenant
verified through this helper was judged under pre-Genesis rules** — a 520-byte element cap BSV
removed in February 2020. An OP_PUSH_TX preimage is around 585 bytes, so the package's
flagship feature could not verify against its own harness, and `enableGenesis()` papered over
it by raising process-wide statics. That treats the symptom: raising the statics cannot enable
post-Genesis arithmetic, and it weakens pre-Genesis validation.

It was invisible for the same reason the first fix was needed: while `isAfterChronicle()`
accepted bit 20, the string opcodes ran and only the *limits* were wrong.

Now delegates to `Interpreter.mainnetFlags()`, as `@smartledger/bsv` has since 8.4.0, so the
covenant path tracks consensus automatically. `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY` and
`SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` are deliberately gone (Genesis reverted OP_CLTV/OP_CSV to
upgradable NOPs for outputs created after it, so with the era flags present they change
nothing) and `SCRIPT_VERIFY_NULLFAIL` is gained, which is strictly stricter.

### Verification

The conformance corpus **was not regenerated.** Its Chronicle suite passed bit 20 alone, so 17
of its 455 cases changed; giving the suite the era word it should always have had reproduces
every frozen value exactly. That is the evidence these fixes touched the era gating and
nothing else — a regenerated fixture would have proved nothing, which is why
`conformance/generate.js` demands `--force`.

455 of 455 conformance cases match, 4,425 tests pass, 100.000% agreement with the external
corpus, and two tests that asserted the old permissive contract — "accepts the opt-in flag as
well, since both mean Chronicle applies" and "accepts either Chronicle flag" — now assert its
negation.

## [1.2.2] - 2026-10-11

Error-name only, ported from `@smartledger/bsv` 9.29.2. No outcome changes.

### Fixed — an undecodable push was reported as MINIMALDATA, or not noticed at all

A push declaring more bytes than the script carries is a decode failure, which the node finds
while reading the instruction (`GetOp` returning false, `SCRIPT_ERR_BAD_OPCODE`,
interpreter.cpp:450-451) — above the push-size, op-count, disabled-opcode and minimal-push
checks, and above the `fExec` logic. This package had the check inside
`if (fExec && isPush)` and after the minimal-push test, so a truncated push that was also
non-minimal reported `MINIMALDATA`, and one inside a branch that never executes was skipped
entirely, the script running on to report `UNBALANCED_CONDITIONAL`.

Hoisted to instruction-read time and made unconditional, matching the node and
`@smartledger/bsv`.

Established by a compiled bitcoin-sv v1.2.3 oracle replaying all 3,835 `BAD_OPCODE` rows of
the bsv-lean-proofs corpus (3,835 agree, 0 differ), so the node and that corpus were right and
both our libraries were wrong. The verdict was reject either way, which is why only an
error-name comparison could see it.

## [1.2.1] - 2026-10-11

Error-name only, ported from `@smartledger/bsv` 9.29.1. No outcome changes.

### Fixed — the 1.2.0 guard ran one step too early in the node's order of checks

The node's `CScriptNum` span constructor applies three checks in order: size against
`max_length`, then minimal encoding, then the int64 fit. 1.2.0 placed the int64 test before
the bignum read, which performs the first two, so an operand that is both non-minimal and
wider than nine bytes reported `SCRIPTNUM_OVERFLOW` where the node reports
`SCRIPTNUM_MINENCODE` — the same reject for the wrong reason.

Found by comparing error names rather than verdicts across a 24,568-row corpus, which an
accept/reject comparison cannot do. Pinned by a test asserting both directions.

## [1.2.0] - 2026-10-11

A minor rather than a patch because consensus tracking overrides the versioning policy (see
**Stability** in the README): scripts that verified under 1.1.0 and earlier are refused here,
and they were never valid on the network.

### Fixed — OP_LEFT / OP_RIGHT / OP_SUBSTR accepted an operand the network rejects

Ported from `@smartledger/bsv` 9.29.0, where it was found. The length and offset operands of
the Chronicle string opcodes were read as big numbers bounded only by `maxScriptNumLength()`,
which post-Chronicle is 32,000,000 — so a 600-byte operand passed, while a compiled
bitcoin-sv v1.2.3 rejects it with `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`.

`MaxScriptNumLength()` is not the only bound. `CScriptNum`'s span constructor takes a fourth
argument, `big_int`, which **defaults to false** (`src/script/script_num.h`), and when it is
false the value must survive `bsv::deserialize<int64_t>` or the constructor throws.
`deserialize<int64_t>` tests the **encoded length, not the value**: more than 9 bytes always
fails, and at exactly 9 the top byte must carry nothing but the sign. An all-zero 600-byte
operand is numerically 0 and still overflows.

The node's asymmetry is deliberate, and porting "the same as the neighbouring opcodes" is what
produced the bug in both libraries:

```
OP_SPLIT, OP_NUM2BIN          big number after Genesis (passes utxo_after_genesis as big_int).
                              Unchanged; it was correct.
OP_SUBSTR, OP_LEFT, OP_RIGHT  int64 in every era, post-Chronicle included. Fixed.
OP_CHECKMULTISIG counts        4 bytes. Already correct.
```

Found by `script-20261008-14051` from the bsv-lean-proofs corpus. This package accepted it;
the second row (`...-22371`) it already rejected, but as `SCRIPT_ERR_INVALID_NUMBER_RANGE` —
the right outcome for the wrong reason. Both now report the node's code.

Seven regression tests in `test/script/string_ops.js`, matching the ones added upstream, so
the two libraries are pinned to the same rule by the same cases. The guard is written
byte-wise rather than with BigInt so both ports read identically.

### Fixed — the shipped declarations broke CommonJS consumers on `node16`/`nodenext`

The declaration half of this release. The emitted JavaScript is byte-identical to 1.1.0 — verified by
hashing the built `dist/**/*.js` tree before and after the change — so no runtime behaviour
moves. Only `.d.ts` output and the release gate differ.

### Fixed — the shipped declarations broke CommonJS consumers on `node16`/`nodenext`

`dist/crypto/point.types.d.ts` carried a top-level import of `@noble/curves`, which is
ESM-only, because the source derived a type from it with a value import:

```ts
import { secp256k1 } from '@noble/curves/secp256k1.js'
export type NoblePoint = ReturnType<typeof secp256k1.Point.fromHex>
```

TypeScript emits that import into the declaration file, so a **CommonJS** consumer compiling
with `moduleResolution: node16` or `nodenext` got `TS1479` ("the referenced file is an
ECMAScript module and cannot be imported with 'require'") from a declaration they never asked
for. Present in every 1.0.x and in 1.1.0. Runtime was never affected: the package is CommonJS
on Node >= 20.19, where `require(esm)` resolves @noble at runtime, which is what that `engines`
floor is for.

Scope, measured rather than assumed — only one consumer configuration failed:

```
CJS + moduleResolution node16/nodenext   TS1479
CJS + moduleResolution node (legacy)     clean
bundler, and ESM consumers               clean
```

The type is still **derived** from @noble rather than restated, now via a type-position import
carrying `resolution-mode: 'import'`. Restating the shape locally would have decoupled the
public declarations from @noble's module format, at the cost of hand-mirroring a curve
implementation's point API where drift is silent; `_p` is internal, so the tracking is worth
more than the decoupling.

**One narrow compatibility cost, stated because it is real.** The `resolution-mode` attribute
needs TypeScript >= 5.3 to parse. `skipLibCheck: true` does not help: it suppresses errors
reported inside a declaration file, but the file is still parsed. Measured against the
published 1.1.0:

```
TS 5.2, skipLibCheck true    1.1.0 -> 0 errors    1.2.0 -> 7 (parse)
TS 5.6, skipLibCheck false   1.1.0 -> 16          1.2.0 -> 15
TS 5.9, skipLibCheck false   1.1.0 -> 1           1.2.0 -> 0
```

So a consumer on TypeScript 5.2 who had `skipLibCheck: true` compiled against 1.1.0 and does
not compile against 1.2.0. TypeScript 5.2 predates the Node 20.19 floor this package already
required, and the 15 errors remaining at 5.6 are `@types/node` serving a non-generic `Buffer`
to 5.6 and below — unchanged from 1.1.0, not introduced here.

### Added — the release gate now tests five consumer configurations, not one

`check:consumer-types` compiled a consumer against the packed tarball, which is the right
shape and caught three real defects at 1.0.0. It pinned `"moduleResolution": "node"` — the one
mode in which TypeScript does **not** enforce ESM/CJS import legality — so it stayed green
through every release carrying the defect above. A gate that tests one resolution mode cannot
see that whole class of defect.

It now compiles in `node`/commonjs, `node16`, `bundler`/esnext and `nodenext`, plus a real
`"type": "module"` consumer in its own directory with an `.mts` entry and
`skipLibCheck: false`, because a compiler flag alone cannot reproduce how ESM resolution treats
this package. The ESM rows needed their own smoke file: the existing
`import bsv = require(...)` is illegal when targeting ES modules, so reusing it would have
tested the smoke file's syntax instead of the package. Both smokes now also touch
`crypto.Point`, so the rows exercise the declaration that carried the defect rather than only
importing the package root.

### Documentation

README gains a **Requirements** section stating both TypeScript floors (>= 5.3 to parse the
declarations, >= 5.7 to type-check against them cleanly) and why Node >= 20.19 is required.
The package previously documented no TypeScript minimum, so a consumer on 5.6 met ~15 errors
with nothing pointing at the cause.

## [1.1.0] - 2026-10-11

Parity with `@smartledger/bsv` 9.17.0–9.28.0. A measured comparison found this package level
with the published library on everything both implement — 455 of 455 conformance cases, in
outcome *and* error message — once the five items below landed. Nothing here is a false
accept; the security work in bsv 9.19.0–9.27.0 was confined to modules this package does not
have (`gdaf/`, `notaryhash/`), which was checked by diffing the changed file list against
this tree rather than inferred from the changelog.

### Fixed — `checkArgument`/`checkState` accepted NaN

The TypeScript conversion replaced `if (!condition)` with an enumerated falsy list,
`condition === false || condition == null || condition === 0 || condition === ''`. The list
looks exhaustive and is not: it omits NaN, so `checkArgument(NaN)` passed a guard that exists
to stop it. Reachable through `PublicKey(NaN)` and `Address(NaN)`, which skipped the guard and
were then refused downstream with a `TypeError` instead of the declared
`ErrorInvalidArgument` — fail-closed, but by accident rather than by the guard.

Restored to `!condition`, which is the whole falsy set in one operator and cannot drift out of
step with it. The test now asserts the set (`false, 0, -0, '', null, undefined, NaN`) rather
than passing `true` once; "throws no false negative" had only ever tried `true`.

`checkState`'s `message` parameter is widened to `unknown`, matching `checkArgument`'s second
parameter, because callers pass an `Error` as well as a string.

### Fixed — the library printed to stderr during ordinary operation

`ECDSA.prototype.calci` tried all four recovery ids inside a `try`/`catch` and ran
`console.error(e)` on each failure. Most ids do not yield a point, so the throw IS the signal
that the id is wrong and `continue` is the handling — which meant ordinary message signing
wrote exceptions to stderr. Nothing is swallowed in the sense that matters: if no id works the
loop falls through and the caller is told.

`electrum-ecies`' `fixedPublicKey` notice fired on every decrypt through a bare `console.log`
that could not be turned off. It is now a `console.warn` once per process, silenceable with
`ECIES.notices = false` or `BSV_NO_ECIES_NOTICE=1`.

### Added — `util.deprecate`, and the first API marked with it

A semver major is a promise that the consumer's code breaks. This separates the moment we say
an API is wrong from the moment we break callers: a minor marks it and callers keep working,
a major removes it on a schedule already in the consumer's logs. Marking is therefore
non-breaking and belongs in a minor. Nothing in it ever throws on the consumer's path.

`Script.fromHex()` is the first user. `Buffer.from(str, 'hex')` stops at the first character
it cannot decode and returns what it had, so a malformed string yields a SHORTER script, or
none, instead of an error — and a caller that builds an output from the result pays to a
truncated script with nothing to tell it. `Script.fromString` has always refused that;
`fromHex` never did. Truncation can only drop a suffix, so an address derived from the result
is always the one the input's leading bytes named, which bounds the damage without making it
correct. **Behaviour is unchanged in 1.1.0** — it warns, and 2.0.0 will throw. Callers wanting
the strict behaviour now should check the round trip:
`Script.fromHex(h).toHex() === h.toLowerCase()`.

### Changed — signing many inputs no longer recomputes the shared digests per input

A FORKID preimage's `hashPrevouts`, `hashSequence` and `hashOutputs` are identical for every
input of a transaction, and each costs a pass over all inputs or all outputs, so signing *n*
inputs did that work *n* times. `getSignatures` (and `sign`, for the apply loop) now opens a
cache for the duration of its pass and removes it in a `finally`.

**No speedup is claimed at any size measured here.** The change removes work that was
provably redundant — the three digests are identical for every input — but on this machine
the effect stayed below the noise floor up to 5,000 inputs: per-input ECDSA dominates, and
run-order drift (whichever of two sequential runs goes second is slower) exceeded the
difference, in both directions, across repeated pairs. The same build with the midstate slot
neutered measured 92.6 s at 5,000 inputs against 101.8 s with it active, and reversing the
order reversed the sign — which is the definition of a measurement that says nothing.

So this is an algorithmic fix on the strength of the argument, not the stopwatch: it deletes
an O(n²) term from a path that is O(n) in ECDSA besides. Signing remains superlinear, and the
dominant remaining term is the re-verify inside `applySignature`, which this does not address.
Anyone quoting a figure for it should measure on a quiet machine, alternating the order.

Nothing survives the call, so there is no invalidation to get wrong. Widening the window over
the apply loop is safe because the only thing that loop changes is each input's *script*, and
none of the three digests covers a script. The SIGHASH_SINGLE output digest is deliberately
NOT cached: it hashes the one output at the input's index, so it differs per input and is O(1)
anyway.

### Added — `Covenant.PushTx.valueCovenantSingle`

An output covenant under SIGHASH_SINGLE: the spend is valid only if the output at the spending
input's own index is the one pinned. Unlike `valueCovenant` it says nothing about the other
outputs, which is what makes it composable — several such locks can be spent in one
transaction, each pinning its own output.

It is not sugar. Two things are easy to get wrong, and both are now refused or pinned by test:

* **The order.** `pushTxCore` consumes the preimage copy it checks, so the sighash flag has to
  be asserted while a copy is still on the stack. Composing this the obvious way —
  `valueCovenant(hashOutputs([pinned]))` with `assertSighashType` appended afterwards — builds
  a lock that fails the HONEST spend, at the same byte count, so size gives no clue.
* **An all-zero pin.** 32 zero bytes is not a digest; it is what BIP-143 puts in `hashOutputs`
  when the input's index is out of range under SIGHASH_SINGLE, i.e. when there is no output
  there. A lock pinned to it is satisfied by a spend with no outputs at all, so it pins nothing
  while looking like it pins something. Refused at construction.

The documented hazard is asserted rather than tolerated: this covenant binds ONE output and
leaves the rest free, because that is what SIGHASH_SINGLE means. Use `valueCovenant` to bind
every output.

These are this package's first covenant tests; `valueCovenant`, `pushTxCore` and `grind` had
none.

### Fixed — the AssertionError text differed from `@smartledger/bsv` for the same failure

`encoding/bufferwriter` imported `assert` as an ESM default, which `tsc` emits as
`(0, assert_1.default)(expr)`. Node's `assert` builds its message by reading the call-site
source, and from that shape it recovers only `(expr)` — so the same failing assertion reported
different text in the two libraries. Now imported as `import assert = require('assert')`, the
form every other import here uses, which emits a plain `assert(expr)` call.

`conformance/fixtures/sighash.json` is regenerated for that one case, and only that one; the
manifest's per-suite stamps are refreshed from the fixture files, which had drifted.

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
