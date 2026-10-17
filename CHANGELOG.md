# Changelog

All notable changes to `@smartledger/bsv-core` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this package
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with one clause above it:
if BSV mainnet consensus changes, this package follows the network in a minor rather than
waiting for a major. See **Stability** in the README.

## [Unreleased]

### Added — the sibling's OP_PUSH_TX vector, so a divergence fails a test

No behaviour change. Both packages implement the same in-script signature construction
(`a = 1`, `k = 1`, so `r = Gx` and `P = 02||Gx`), and "both implement it" is worth nothing
unless something fails when they drift. `test/data/pushtx-authenticator-vector.json` is an
artifact built by `@smartledger/bsv` — locking script, spending transaction, the grind nonce
that made the s-value canonical, and the preimage — and `test/covenant/pushtx_vector.js`
recomputes each field with **this** package's code rather than comparing the file to itself.

Measured on adding it: this package emits a **byte-identical 377-byte** locking script from
`Covenant.PushTx.authenticator()`, reproduces the same preimage from the same transaction with
its own `rawPreimage`, accepts the same s-value under `sFromPreimage`, and **verifies the
sibling-built spend under its own interpreter**. A one-byte mutation of the preimage is refused,
which is what makes it a vector rather than a snapshot.

Kept as a copy in each repository rather than a shared fixture, deliberately: a copy in each is
what makes a future divergence fail a test instead of going unnoticed.

Worth recording for anyone looking for the covenant surface here: the OP_PUSH_TX primitives are
exported as **`bsv.Covenant.PushTx`** (21 members, the same names the sibling exposes under
`SmartContract.PushTx`) with the BIP-143 helpers under `bsv.Covenant.Helpers`. What this package
does **not** have is the application layer above them — no `SmartContract` namespace, no `Token`,
`Authorizers`, `Locks`, `DSL` or covenant templates.

### Changed — `ordLock` cancel: the `sighashType` override now carries its hazard in the docstring

No behaviour change. `buildCancel`'s documented `params.sighashType` is the only place either
package's shipped surface invites a caller to sign something other than `SIGHASH_ALL|FORKID`. The
CANCEL branch is a plain P2PKH gate that constrains no output, so a cancel signed `SIGHASH_NONE`
commits to nothing and anyone holding it before broadcast can redirect the ordinal. That is the
generic `SIGHASH_NONE` hazard every P2PKH shares rather than a covenant defect — the PURCHASE
branch pins its flag with `assertSighashType` — but the parameter is where a caller would reach
for it, so the note belongs there.

Ported from the sibling `@smartledger/bsv`, where a surface audit for exactly this went looking
after its Token covenant was found to **accept** a `SIGHASH_NONE` authorization while its security
argument depended on `SIGHASH_ALL` (fixed in 9.40.0 with an opt-in script-level pin). **This
package has no Token-style covenant**, so that defect does not exist here — checked rather than
assumed: `SmartContract`, `Token`, `Authorizers` and `PushTx` are all absent from the built
surface, and `src/covenant` carries only `pushtx` and `helpers`.

## [1.8.1] - 2026-10-17

### Fixed — named ESM imports did not exist: `import { PrivateKey }` threw on every published version

`import { PrivateKey } from '@smartledger/bsv-core'` type-checked clean and threw
`Named export 'PrivateKey' not found` when it ran. Not one name worked: measured against
installed, published **1.8.0** on Node 22.23.3 with tsc 5.6.3, **28 of 28** root names were
accepted by the compiler and **0** were importable by name. Only the default import
(`import bsv from '@smartledger/bsv-core'`) and `require` ever worked.

**Why "every published version" and not just the one measured.** All 16 published versions carry
the identical root export map — `types`, `default`, `require`, no `import` — read from the
registry packument, so Node's loader has always resolved `dist/index.js` for an ESM consumer. The
named import was run directly against installed 1.2.0 and 1.8.0 and fails identically at both.
What this broke is **Node's own ESM loader**: esbuild 0.28.2 emitting CommonJS applies its own
interop and serves the names from 1.2.0, 1.8.0 and this release alike, all three producing the
same address from a WIF round-trip — so a bundled consumer was not affected either way.

`dist/index.js` assembles its API object at run time — `const bsv = {}; bsv.PrivateKey = ...;
module.exports = typed` — and Node's CJS named-export detection is a **static scan of the
source**, so it found nothing to expose. The package had no `import` condition and no ESM
entry, so every ESM consumer got that one object and no bindings.

**The declarations could not have reported it.** `export = typed` over an object type lets
TypeScript accept named imports, and TypeScript does not model Node's lexer, so the compiler
promises names the runtime never had. The names have to exist.

`dist/index.mjs` is now generated by `scripts/gen-esm-wrapper.js` as part of `npm run build`
(after `tsc`, so it cannot describe a previous build) and the `import` condition resolves to it.
It default-imports the CJS build and re-exports each member as a genuine ESM binding.
`dist/index.js` is untouched, so `require()` returns the same object as before — verified
against a packed tarball: 28 of 28 names import and are defined, the ESM default **is** the
object `require` returns, and a named export **is** the same class the CJS member is, so
`instanceof` cannot disagree between an ESM and a CJS consumer. Accessor and underscore-prefixed
members are deliberately not re-exported; they stay reachable through the default export.

Three properties recorded rather than claimed. **Liveness:** a named export captures its member
when the wrapper is evaluated, so it is not a live binding onto `module.exports`; the default
export holds the same object reference, so mutations of that object are visible through it, while
a later reassignment of `module.exports` would not be. Nothing here supports replacing root
members, and the sibling package's `index.mjs` has always behaved this way. **Toolchains:** the
figures above are Node 22.23.3 and tsc 5.6.3 under `node16`/`nodenext`/`bundler` resolution.
esbuild 0.28.2 is the only bundler exercised at run time (CommonJS output: the named import runs
before and after); Webpack, Rollup and Vite are untested rather than confirmed. Bundling this
package to **ESM output** with esbuild fails at run time with `Dynamic require of "..." is not
supported` — measured identically on 1.2.0, 1.8.0 and this release, so it is a pre-existing
property of the library's internal `require` calls and not something this change introduces.
**CJS consumers:** `dist/index.js` is byte-identical to published 1.8.0 and the `require`
condition is unchanged, so no CommonJS consumer's resolution moves; the other `dist/` changes in
this release are the fixes recorded below.

The same defect in the sibling `@smartledger/bsv` was confined to three subpath entries, because
its root has shipped a real `index.mjs` for some time. `@smartledger/notaryhash`,
`/crypto`, `/keys` and `/envelope` were checked at 2.5.0, 3.3.0, 4.1.0 and 3.0.1 and are **not
affected** — each ships a real dual build, and its ESM named-export count equals its CJS surface.

### Changed — `npm publish` ran no build and no checks

`dist/` is gitignored and there was no `prepublishOnly`, `prepare` or `prepack`, so a publish
shipped whatever happened to be sitting in `dist/` — stale, partial, or from another branch —
with the test suite, the conformance run and the API snapshot all unexercised.

**The risk was latent, not realised.** Published 1.8.0 was checked against its own tag: building
`v1.8.0` in a throwaway worktree reproduces the published `dist/` with **0 differences** across
103 emitted files, their maps and their declarations. So no published artifact is known to
disagree with the commit it claims; what was missing was anything that would have caught it. `prepublishOnly`
is now `npm run build && npm run check`, so the published artifact is built from the tree being
published and has passed lint, 4,829 tests, the conformance corpus, the cycle-safety check, the
`any` budget and the API surface snapshot.

### Changed — the consumer-types gate compiled but never ran anything

`scripts/check-consumer-types.sh` compiles a consumer against the packed tarball in five
resolution modes, which is why it has caught real defects. But **every row used a default
import, and nothing executed** — so the missing named exports above stayed green through 1.8.0
in the one gate positioned to see them. A gate that only compiles cannot catch a declaration
that lies about the runtime, because the lie is precisely that it compiles.

Two rows are added: the named import type-checks for a real `"type": "module"` consumer, and
then it **runs** — asserting no binding is undefined, exercising each one rather than merely
importing it, and checking that the ESM default and a named export are identical to the CJS
module and its member. Removing the `import` condition was confirmed to fail the new row with
an actionable message before it was kept.

`test/properties/esm_wrapper.js` (8 tests) holds the wrapper to the CJS surface: no drift from
the generator, generated after `tsc` in `build`, resolved by the `import` condition with `types`
ordered first, covering the whole exportable surface, every member importable by name, identity
with the CJS objects, no internal or accessor members, and a key round-tripped through a named
import to an address cross-checked against the independent `@smartledger/bsv` implementation.


### Checked — a chunk index is the node's byte pointer

No behaviour change. This package slices the scriptCode by CHUNK INDEX at
`src/script/interpreter.ts:2631` and `:2730` where the node uses a byte pointer into the raw
script. The two agree only while the chunks before the slice point re-serialize to exactly the
bytes they were parsed from. Measured over 17 bodies with separators, truncated pushes and `0xab`
in operand and length positions, 60 slices in all: every slice equals the raw byte suffix, and
every body re-serializes to its own bytes. Pinned in
`test/script/chunk_index_is_byte_pointer.js`, the twin of bsv's, with a guard that the body list
still contains truncated pushes — the only shape where an eager parser can diverge from the node's
`GetOp` walk.


### Changed — `OP_NUM2BIN` compares its size as a BN before narrowing, matching @smartledger/bsv

No behaviour change: measured identical on all 91 operand-edge cases before and after. This package
tested the `INT32_MAX` bound on the value **after** `toNumber()`, where bsv tests it on the BN
first. Our `BN.toNumber()` does not throw above 2^53 the way `bn.js`'s does — it returns a lossy
float, 2^151 coming back as `2.85e+45` — so a bound tested on the narrowed value is a bound on an
approximation. It gives the right verdict here only because the bound is `INT32_MAX`, far below
2^53 where doubles are exact; that is a property of this bound, not of the pattern. The node
compares the script number itself, so this now does too.

Prompted by an upstream library that panicked on a large `OP_SPLIT` index (a slice-bounds crash from
exactly that narrow-then-compare shape). Neither package has that defect:
`test/script/oversized_scriptnum_operands.js` — the twin of bsv's, with the same generated table —
covers 7 opcodes × 13 operands including the buffer-length boundary, and asserts that **no operand
makes an exception escape to the caller and none is answered with a flattened
`SCRIPT_ERR_UNKNOWN_ERROR`**. The two packages agree on all 91; keeping a copy in each is what makes
a future divergence fail a test instead of going unnoticed.

The boundary operands matter: a sabotage turning `position > buf1.length` into `>=` left an earlier
70-case table entirely green because no operand equalled the buffer length. The opcodes also
disagree there — `OP_LEFT` accepts `n == len` while `OP_SUBSTR` refuses `beg == len` — so it is
pinned per opcode.


### Added — `docs/RELEASE-2.0.0.md`, the list of breaking changes this package has promised

No behaviour change. Three `deprecate()` calls in `src/` carry `removeIn: '2.0.0'`, and until now
that promise was recorded nowhere but in those three files and in consumers' logs: there was no
list of it to plan a major from, and no stability document here mentions 2.0.0 at all. The sibling
package published six majors in 82 days before writing its commitments down, which is the outcome
this file exists to avoid.

Each registration gains a `plan:` id — a new optional field on `DeprecationOptions`, never printed
and not part of the dedup key — and `test/properties/release_2_plan.js` pairs the plan and the code
by that id in **both** directions: a registration with no row fails, and a row with no live
registration fails. `since` and the registering file are checked as fields of the matched row, so
a commitment whose version or location moved without the plan being updated is caught, and every
`since` must name a version with a `CHANGELOG` entry.

The id is not keyed on `since` or on the file for reasons the sibling package measured: matching on
the version alone silently accepted any new commitment whose version an existing row already
mentioned, including the ordinary case of a deprecation added in the version being shipped, and
keying on the file would reject two deprecations landing in one file in one release while reading a
file move as a different commitment. Seven sabotages were run against the new test and all seven
fail; the legitimate two-in-one-file case passes.

The three ids are the same strings `@smartledger/bsv` uses for the same commitments, so the two
plans can be compared directly — all three are ports, and a commitment honoured in one package and
forgotten in the other is how the two drift.


### Added — the first separator-bearing scriptCode a node has judged for this package

No behaviour change; ported from `@smartledger/bsv`. Forty-eight rows authored in the sibling
package with no expected values, judged by a compiled bitcoin-sv v1.2.3 and an independent Rust
node, and joined against a fresh run of this package: **0 preimage differences, 0 digest
differences** over 96 comparisons. Vendored at `test/data/sighash-codesep-undecodable.json` with
the caveat that the two emitters' output files are byte-identical, so the two-witness claim rests
on their distinct binary hashes rather than the column bytes.

Also carried over, and now judged too: twenty-four rows over six bodies where a naive count of
`0xab` bytes diverges from the walk's separator count (`6a4dab`, `ab6a4dab`, `4dab`, `ab4dab`,
`6a4eab0000`, `ab6a4eababab`), at `test/data/sighash-codesep-count-path.json`, joined at 48
comparisons with 0 differences. `ab6a4eababab` declares 5, not the 2 a byte scan would give.

They exist because a sabotage substituting the naive count left all 48 of the other fixture's rows
green. The declared length has two derivations — set explicitly as `len(suffix) - separators` when
the walk stops early, taken from the stripped script's own length when it reaches the end — and no
body in that fixture has a `0xab` in a length field *and* an early stop, so all of its rows take
the stripped-length route for that question. The cross-sabotage matrix is in the test: a naive
byte count fails 12 of 12 here and 0 of 48 there; a byte-level excision fails 4 there and 0 here.

### Added — tests for what a signature commits to when `OP_CODESEPARATOR` is in the script

No behaviour change; ported from `@smartledger/bsv`. Twenty rows computed outside this package
(their own reference implementation and a Rust node, reported byte-identical) are vendored at
`test/data/sighash-codesep-executed.json`; `1.8.0` reproduces all 20 preimages and all 20
digests and routes each row to the algorithm it labels. Two things that had no coverage here
either: the **BIP-143** rule that the separators remaining in the signed suffix are kept rather
than excised, and **where** the separator is as opposed to what is done with the suffix — the
node tracks it as a byte pointer, this package as a chunk index, and eighteen cases now compare
the scriptCode handed to signature verification against the byte suffix a node would take,
across every push encoding and nested conditionals.

Behaviour confirmed identical to `@smartledger/bsv` on the two sharp cases: a `0xab` inside a
push operand or serving as a `PUSHDATA` length byte is data, not a separator; and a hand-built
`chunks` list whose `len` disagrees with its `buf` fails closed with `SCRIPT_ERR_BAD_OPCODE`
rather than executing past the bad push, while its serialised bytes verify as the single push a
parser reads them to be.

## [1.8.0] - 2026-10-15

### Added — `Message#verify(address, sig, { lowS: true })`, which 1.7.0 accepted and ignored

A `Message` signature has a second encoding that verifies identically for the same key and message:
flip the recovery id in the header and replace `s` with `n − s`. So the bytes are **not a unique
name for a statement**, and anything keyed on them has a forgeable twin. `bsv` added an opt-in
refusal in 9.38.0; this package did not have it — and that was worse than it sounds, because
JavaScript does not object to an extra argument:

```js
// @smartledger/bsv-core@1.7.0, measured
Message.prototype.verify.length            // 2 — the option was not a parameter
Message(m).verify(addr, twin, { lowS: true })  // true. No error, no warning, no protection.
```

The sibling package's `docs/RELIED-UPON-PROPERTIES.md` told integrators to make exactly that call,
so a consumer following our own guidance on this package got a strictness option that did nothing
while sitting in their code as evidence the hazard was handled. Now:

```js
bsv.Message(text).verify(address, sig, { lowS: true })   // false for the twin
bsv.Message.verify(text, address, sig, { lowS: true })   // the static form forwards it
```

`message.error` then reads "The signature is not canonical: s is above half the curve order".
Accepting a high-s signature emits a one-time deprecation notice (`since: '1.8.0'`,
`removeIn: '2.0.0'`), fired only on the **accept** — a canonical signature raises nothing and a
refusal raises nothing.

**Two limits, stated because the option invites overreading it.** It refuses ONE twin: the same `r`
with `s` replaced by `n − s`. It does **not** make a signature unique per `(key, message)` — the set
of valid low-s signatures over a message is as large as the nonce space, and a test here asserts
that four distinct low-s signatures all pass the option. And **probe for the behaviour rather than
trusting a version range**: an arity check passes on a build that wires the parameter and ignores
it, which is precisely what 1.7.0 did.

Opt-in rather than default because the signatures it refuses are **valid ECDSA** and other
implementations may legitimately emit them; `sign()` has only ever emitted low-s, since
`ECDSA.toLowS` runs unconditionally in `_findSignature`. 2.0.0 flips the default.

Seven tests in `test/message/low_s_option.js`. The half-order comparison is spelled with BN
operands (`2s > n − 1`) rather than `muln`/`subn`, which this package's BN typing does not declare.

## [1.7.0] - 2026-10-15

### Added — a notice when a mutated output script is not the one that will serialize

Ported from `bsv` 9.39.0, because this package has the identical shape. `output.script` hands out
the live `Script` object, while `Output#toBufferWriter` writes `_scriptBuffer` — the bytes the
output was *set from*:

```js
tx.outputs[0].script.add(bsv.Opcode.OP_NOP)   // dropped from the broadcast bytes
tx.outputs[0].getSize()                        // but measured here: 35 against a 34-byte output
tx.outputs[0].setScript(tx.outputs[0].script)  // the remedy, one line
```

So the mutation never reaches the transaction while `getSize()` measures it, and the fee is
computed for an output that will not be broadcast. `getSize()` now compares the two byte strings it
has just computed — a `Buffer.equals`, never a second serialization — and emits a one-time
deprecation notice when they differ. Re-setting changes the output, so the txid changes and any
signature already made over it must be remade; building the script before setting it avoids the
question.

The notice has no false positives: nothing but a mutation can make an output's two byte strings
differ, because parsing a script and re-encoding it is byte-faithful — measured in the JS library
over every script of three bytes or fewer (16,843,009, exhaustive) plus 400,000 push-biased random
ones, 0 divergences, and pinned here in `test/transaction/output_inplace_mutation.js`.

Coverage is partial and stated as partial: `getSize()` is the only place the comparison is free, so
a mutation followed by serialization with no size enquiry is still silent, and `Input` has the same
drop with nowhere free to see it. The behaviour itself is unchanged; `2.0.0` decides between
re-syncing on mutation, refusing to hand out a mutable parsed script, and an additive pre-broadcast
check that covers inputs as well.

### Checked — nothing other than an undecodable output script reaches the null-script path

The sibling package’s `docs/NPM_RELEASES.md` has carried this as a **stated-unchecked claim** since the deprecation
round: the nine deprecation messages say "some chain transactions" rather than naming a cause,
because nobody had established whether anything *else* could leave a script unreadable. It is
checked now, and the answer is no.

Two accessors in this library can yield a non-Script, and each has exactly one cause:
`Output#script` is null only from the `Script.InvalidBuffer` catch in `setScriptFromBuffer`,
which the total parser made unreachable from bytes, and `Input#script` is null only for the
coinbase. Measured rather than read: **12 states a caller can build from bytes** — every shape
that used to throw, the empty script, a `PUSHDATA4` declaring 4,294,967,295 bytes, a separator
before a cut-off push — against **11 consumers**: `Output#script`, `getSize`, `toObject`,
`inspect`, `toBufferWriter`, `isDataOut`, `classify`, and at the transaction level `serialize`,
`getSerializationError` (the dust path), `_estimateSize` and `sign`. No state reachable from
bytes produced a null script or an untyped throw.

### Fixed — `Output#setScriptFromBuffer` assigned before validating, poisoning the output

The audit above found one thing worth fixing. The method assigned `_scriptBuffer` and *then*
parsed, so a caller passing a string or `undefined` left the output holding a non-Buffer: the
throw came from inside the parser, and **every later read of `.script` threw too**, with a
message — `Invalid hex string`, or a property of `undefined` — naming neither the method nor the
argument. It now checks the argument first, so a bad call fails at the call and the output is
left exactly as it was.

That also makes an invariant the rest of the library depends on true by construction. The
null-script guards read `_scriptBuffer.length` and `_scriptBuffer.toString('hex')`, so they
assume every `_scriptBuffer` is a Buffer. Of the ten assignments in `src/`, eight pass
`.toBuffer()`, `Buffer.from(...)` or a `BufferReader` read, one is inside
`if (Buffer.isBuffer(args.script))`, and this public method was the tenth.

Both halves are self-enforcing in `test/transaction/null_script_deref_registry.js`, which already
ratcheted the dereference **sites** and now also pins the **states** and the `_scriptBuffer`
invariant — the last of those by reading every assignment in the source, so a new one has to be
classified deliberately rather than trusted. It caught an omission in its own allow-list while
being written, which is the behaviour wanted from it.

This is API-misuse hardening and a closed open question, not a reachable defect: no version
behaves differently on any input a caller can supply as bytes. It is therefore **not a release on
its own** and will ride with the next one.

## [1.6.0] - 2026-10-15

Ported from `@smartledger/bsv` 9.35.0, with the text-reader fix released there as 9.37.0 folded
in rather than left for a second port. `Script.fromBuffer` is now **total**: every byte string
parses, as the node's `CScript` does, and a decode failure surfaces at USE.

That is an argument over the code rather than a fuzzing result. `fromBuffer` had exactly four
reads that can fail, and all four are now guarded: the opcode read, by `while (!br.finished())`,
and the three length-field reads, by `pushLenPrefix`. `BufferReader.read(len)` cannot fail at
all — it slices, so a declared length longer than the remaining bytes yields a short buffer
rather than a `RangeError`, which is the case that was already handled. `readUInt8`,
`readUInt16LE` and `readUInt32LE` were the only throw sources, and nothing calls them
unguarded. Measured alongside: a `PUSHDATA4` declaring 4,294,967,295 bytes with none present
parses and round-trips exactly, as do all 196,608 three-byte scripts opening with a pushdata
opcode, in this package and in `@smartledger/bsv` alike, with zero throws.

### Fixed — the original-algorithm signature digest signed bytes the node does not sign

**A consensus divergence, and the one the 9.35.0 parser change opened the door to.** When a
scriptCode ends in a push the node cannot decode, the node does **not** serialize all of it into
the original-algorithm digest. `CTransactionSignatureSerializer::SerializeScriptCode` writes

    ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);

and then the bytes up to the iterator left by the **last, failed** `GetOp` — and `GetOp2`
advances `pc` past the opcode, and past a complete length field, *before* testing whether the
rest is present:

    unsigned int opcode = *pc++;
    ...
    } else if (opcode == OP_PUSHDATA2) { if (end() - pc < 2) return false; nSize = ReadLE16(&pc[0]); pc += 2; }
    if (end() - pc < 0 || (unsigned int)(end() - pc) < nSize) return false;

So the opcode and whatever length field it read are written, the partial operand after them is
dropped, **and the length prefix still counts it**. The node hashes a field that declares more
bytes than it contains. This library wrote the scriptCode in full, and so computed a different
digest: a signature valid on the network did not verify here, and one made here would not verify
there.

Measured against a compiled **bitcoin-sv v1.2.3**, over a 55-row reference corpus now vendored
as `test/data/sighash-scriptcode-tail.json`: **45 of 55 rows agreed before this release, and all
55 agree after it** — preimage and digest both. The ten that differed are
`6a4d01`, `6a4e0100`, `6a4c050102`, `6a4d030001ff` and `6a050102`, each at both
original-algorithm hash types.

**`6a4c` is not one of them**, and that row is why this is a model rather than a guess: its
cut-off prefix is **empty**, so the node writes the whole script and nothing is dropped. A fix
that dropped "the undecodable chunk" instead of "the bytes past where the walk stopped" would
pass the five scripts above and break this one.

**Confirmed after release, on the rows that could have caught the shortcut.** The three shapes a
parse cannot produce — `4c05aabb51` (an undecodable push with an `OP_1` after it), `ab6a4c050102`
(a separator before one) and `4c05aabbab` (a separator byte *inside* the dropped operand) — were
emitted for all five hash types by a compiled bitcoin-sv v1.2.3 and, independently and
byte-identically, by a Rust node implementation. The published artifacts of this release, read
from the registry, match both columns on all 15 rows, which are now vendored beside the other 55
as `handAssembledRows`. Three consequences of the rule are pinned from outside rather than
argued: the trailing `OP_1` is dropped with the operand; the declared length subtracts only the
separators the walk **reached**; and a `0xab` inside the dropped operand is operand bytes, not a
separator. The earlier chunk-list shortcut would have failed the first of those three.

The implementation is the node's walk itself, over the **bytes**, counting the separators it
passes and recording where it stops — not a reading of this library's chunk list. A first
version did read the chunk list, on the ground that a parse always leaves an undecodable push
last. That is true of a parse and **not** of the public chunk representation: a list assembled
by hand can put one in the middle, and then the node stops there and drops everything after it,
while a last-chunk rule sees a well-formed opcode and drops nothing. `4c05aabb51` is the case —
`PUSHDATA1` declaring five bytes, two present, then `OP_1`. Asking the bytes is both correct for
that and literally what the node does, so it replaced the shortcut.

**Reachable today.** `SignatureHash` takes the original algorithm whenever
`enabledSighashForkid && sigHashType.hasForkId() && !sigHashType.hasChronicle()` is false — so
for any non-FORKID hash type, and for **`0x61`, FORKID|CHRONICLE**, which is post-Chronicle and
current. **BIP-143 is untouched**: its scriptCode goes through the plain `CScript` serializer
with no walk, and all 33 BIP-143 rows of the corpus matched before and after. The 1,000-row
sighash vector report still passes 1000/1000, the script vectors 1483/1483 with zero false
accepts and zero false rejects, the tx vectors 161/161 and the conformance corpus 455/455.

`Input` gained a private `_scriptCodeLength`, the length its script field *declares* when that
differs from the bytes present. Only this digest sets it, on its own throwaway copy of the
transaction. A real transaction serialized that way would not parse, which is why the field is
documented as off limits everywhere else.

**What this corrects on our side as well.** A claim carried in the sibling package's notes since 9.35.0 — that
the library's signed bytes had been confirmed byte-exact against the reference on a 55-row
corpus — rested on a comparison that turned out to be vacuous, and the session that produced it
withdrew it. The honest version is the one above: 45 of 55 before, 55 of 55 after. The lesson is
the one this changelog has recorded before in other words: **a confirmation is only as good as
the column it was compared against, and "it matched" is worth nothing until something is known
to be capable of failing.**

### Fixed — three output scripts the node accepts and mines could not be parsed at all

A locking script ending in `6a4c`, `6a4d01` or `6a4e0100` — `OP_RETURN` followed by a push whose
LENGTH FIELD is cut off — is valid post-Genesis, because an executed top-level `OP_RETURN`
terminates evaluation as successful before the remainder is read. One is on livenet, in
`ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767`. **1.5.2 fixed the three
crashes those bytes caused; this release removes the cause.** The parser threw
`Script.InvalidBuffer` on them in both eras, so there was no `Script` to evaluate and no verdict
to give — a false REJECT, for an output the network accepts.

The node's `GetOp2` tests the length field before reading it:

    else if (opcode == OP_PUSHDATA1) { if (end()-pc < 1) return false; nSize = *pc++; }

so it fails the parse exactly as it does for a push whose DATA runs out — a case this package
already handled and already agreed on. The asymmetry was ours.

The parser now keeps the bytes it did read in a chunk's `lenPrefix`, with no `len` and no `buf`
because there is no declared length to record, and `toBuffer` writes them back unchanged. The
shared `isUndecodablePush` predicate answers true for that shape, so both of the node's `GetOp`
callers give the answers they already gave for truncated data: not-push-only from `IsPushOnly`,
`BAD_OPCODE` from the instruction read.

**The interpreter is untouched.** Confining leniency to a top-level `OP_RETURN` needed no new
logic: it falls out of those scripts parsing and the interpreter deciding, which is also why an
unconditionally permissive parser grants no leniency where the node gives none. The three shapes
inside an `IF` are still `BAD_OPCODE`, and all three are still `OP_RETURN` pre-Genesis.

### Why this is a minor

Stability's own rule decides it: a consensus bug "is fixed in a **patch** when it only refuses
what the network refuses, and in a **minor** when it changes what is accepted." This changes what
is accepted. `ScriptChunk` also gains an optional `lenPrefix` member, and additions are minors.

The digest correction above lands in the same release under the same clause, and it is the
stronger case for a minor: it changes which signatures verify in both directions, accepting ones
this package refused and refusing ones it accepted, for the scripts it covers. It affects no
signature over a scriptCode whose pushes all decode, which is every well-formed script.

No well-formed script changes verdict. The 455-case conformance corpus is unchanged, and the
node's own 1,483 `script_tests.json` vectors still pass 1,483/1,483 with zero false accepts and
zero false rejects.

### Evidence

`test/script/optrue_return_truncated_tail.js`, ported with the fix — 46 tests:

* **all 22 rows judged on a compiled bitcoin-sv v1.2.3** by the op-codes lab, in both eras;
* `fromBuffer` total and byte-exact over every 1- and 2-byte script;
* the **sighash** path, which is where a parser change of this kind can become a consensus
  defect no accept/reject test would see: a malformed tail can be UNEXECUTED and still be part
  of the bytes a signature covers. The preimage carries the full locking script with the varint
  declaring its true length; a signature over it verifies end to end; a tail inside an `IF`
  **after** the `OP_RETURN` is signed but never read, and only the full-lock signature verifies
  (`NULLFAIL` otherwise), with a no-tail control proving the signal comes from the tail;
* `removeCodeseparators` and `findAndDelete` both keep the chunk, and an undecodable push is
  always the **final** chunk — measured over 22,635 parsed byte strings, 17,141 of which
  contained one — which is what keeps `findAndDelete` from diverging from the node's
  stop-at-first-`GetOp`-failure loop;
* `isScriptHashIn` used the parse THROW to answer false, so its answer now comes from
  `classify()`; none of the newly parseable shapes classifies as a known type.

**Cross-checked against `@smartledger/bsv` directly**: 22 interpreter verdicts, 65,792 byte
strings through parse and round-trip, and 13 shapes through every text form, predicate,
`classify()` and chunk shape — **zero differences** against published 9.36.0. Repeated against
9.37.0, which carries the text-reader fix below, over 655,616 byte strings and eight observables
each — chunks, `toBuffer`, `toASM`, `toString`, `fromASM(toASM())`, `fromString(toString())`,
`isPushOnly` and `classify()` — **zero differences**.

What that evidence is and is not: strong tested agreement with the node on the rows a compiled
node judged, and strong tested agreement with the sibling package, over exhaustive short
scripts and sampled longer ones. It is not an exhaustive equivalence proof over every script
length or every downstream caller. The totality argument above is the one claim here that is
structural rather than sampled.

### The text forms read back too, which took a second pass

The text forms write a cut-off prefix as raw bytes, so `6a4d` and `6a4d01` stay distinct rather
than both printing as `OP_RETURN OP_PUSHDATA2`. **Nothing could read that text back.**
`rawOpcodeToken` deliberately refuses a push byte, so `Script.fromString(script.toString())`
threw `Invalid script` on a script `toString` had just written, as did
`Script.fromASM(script.toASM())` — a public pair of functions where one emits what the other
refuses. `lenPrefixToken` now reads the token, and the chunk it returns is the chunk
`fromBuffer` gives for the same bytes. `PUSH_LEN_FIELD_SIZE` holds the 1/2/4 length-field sizes
in one table that both the byte parser and the text reader read, so the two cannot come to
disagree about where a prefix is incomplete.

Measured over every 1- and 2-byte script plus every 3-byte script opening with a pushdata opcode
— 590,080 parsed, of which **382,540 carry an undecodable push** — `fromString(toString())` went
from **69,448 throws** to **0 throws, 0 byte differences and 0 `isPushOnly` changes**, and
`fromASM(toASM())` is exact for every cut-off-prefix script.

What is still not fixed, stated because the same sweep measures it: a push whose length prefix is
*complete* and whose *data* is short has no ASM form at all, because ASM writes a push as its
bare hex and that hex reads back as a push of exactly that many bytes. 313,095 scripts come back
from `fromASM` with different bytes and 256,693 change `isPushOnly` from `false` to `true`.
Published `@smartledger/bsv` 9.36.0 gives the same two figures, so this is older than the
cut-off-prefix work and independent of it. For a malformed script, `toBuffer`/`fromBuffer` is
the authoritative round trip and `toString`/`fromString` is now exact; ASM is a display format
and cannot carry one.

That last point is a decision, not a limit of the mechanism, and it was taken with the
alternative built and measured. Writing such a chunk as raw bytes in ASM too — the same escape —
makes `fromASM(toASM())` exact for **all 721,152** scripts in the sweep, with **zero** change to
the ASM text of any script whose ASM already round-tripped. It also rewrites the ASM of 378,633
scripts whose text was lossy, and **13 existing tests assert that old text**, including three
that pin `4c00` printing as the minimal `0` and one that documents ASM as deliberately minimal.
So it overturns a documented position about what ASM is for, on a published package, and that is
not a port's decision to make. The patch is small and the numbers above are what it costs and
buys.

`Output#setScriptFromBuffer`'s null path is now unreachable from bytes. Its guards are **kept** —
a guard deleted because nothing currently reaches it is how the next parse failure becomes a
crash — and the tests that cover them construct that state directly instead of through a parse
failure.

## [1.5.2] - 2026-10-13

Crash fixes only, ported from `@smartledger/bsv` 9.33.2. No verdict changes.

### Fixed — two raw TypeErrors on an output script the node accepts and mines

A locking script of `OP_RETURN` followed by a push whose LENGTH FIELD is cut off — `6a4c`,
`6a4d01`, `6a4e0100` — is valid, because post-Genesis a top-level `OP_RETURN` terminates
evaluation as successful before the remainder is read. Two independent harnesses confirmed this
against a compiled node on 2026-10-13, one of them by funding each lock on live nodes,
broadcasting the spends and mining them.

The eager `Script` parser throws on those bytes, and `Output#setScriptFromBuffer` turns the
throw into `_script = null` while keeping the raw bytes in `_scriptBuffer`. Two call sites
dereferenced it without asking:

* `Transaction#_hasDustOutputs` — `TypeError: ... (reading 'isDataOut')`, below the dust
  threshold only; reached from `getSerializationError()` and `serialize()`.
* `Output#getSize` — `TypeError: ... (reading 'toBuffer')`; reached from
  `Transaction#_estimateSize()`, so fee estimation could not run at all.

A third site of the same class was found by enumerating every `.script.` dereference in
`src/` rather than grepping for the shape already fixed: `Transaction#sort()`'s BIP69 output
comparator falls through to the script when two outputs have equal satoshis, and threw
`TypeError: ... (reading 'toBuffer')`. Output ordering for well-formed scripts is unchanged.

All were untyped and so unclassifiable by a consumer's `instanceof` check.

The enumeration is self-enforcing rather than prose: all 14 `.script.<prop>` dereferences in
`src/` are listed in `test/transaction/null_script_deref_registry.js` with the reason each
receiver cannot be null, and a new dereference fails the suite until it is classified.

`Output#inspect` and `Input#toObject` were already guarded with `if (this.script)`, so the
convention existed and these crashes were inconsistency with it.

The same enumeration turned up a second null-returning accessor that is NOT a defect and is
now pinned: `Input#script` returns null for the coinbase input (`isNull()`), and every path
exercised on a coinbase transaction already handles it.

The dust check now asks whether the script is `null` first. A script that did not parse cannot
satisfy either data-output test, so the result is the typed `Transaction.DustOutputs` the
expression already gave for any non-data output. This preserves **this package's**
dust-exemption rule — the analogue of the node's parsing `Solver`/TX_NULL_DATA classification —
and is deliberately not a claim of parity with the node's dust policy. The node does have
OP_RETURN tests that need no parse (`IsUnspendable`, `IsKnownOpReturn` — pure prefix tests on
raw bytes), so a prefix-based rule could classify `6a4c` where ours cannot; which test governs
the node's dust call site is not established, and a regtest probe could not discriminate it
because no dust limit was enforced on any shape.

`getSize()` falls back to `_scriptBuffer.length` only when the script is `null`; a parsed
script keeps the existing calculation.

### Known — `getSize()` measures the Script object, which serialization does not

`output.script` hands out the live `Script` object while `toBufferWriter` writes
`_scriptBuffer`, so an in-place mutation is visible to `getSize()` but dropped from the
serialized transaction. Both sides are pinned in
`test/transaction/output_unparseable_script.js`. Not changed here: either resolution alters
observable behaviour for well-formed scripts. Use `setScript()`, which is honoured correctly.

## [1.5.1] - 2026-10-13

Error-name and check-order only. No script that verified before verifies differently now, and
no script that was refused is accepted. Ported from `@smartledger/bsv` 9.33.1.

### Fixed

- **A truncated push counted as a push, so the push-only gate let it through.**
  `Script#isPushOnly()` tested only each chunk's opcode number, so a push declaring more
  bytes than the script carries counted as a push — `4c50` followed by ten bytes is
  `OP_PUSHDATA1` declaring eighty. The gate passed, the scriptSig was evaluated, and the
  failure surfaced from the instruction read as `SCRIPT_ERR_BAD_OPCODE`.

  The node refuses it before evaluating. `VerifyScript` puts the push-only gate above
  `EvalScript` (interpreter.cpp:2329), and `CScript::IsPushOnly` walks the script with
  `GetOp`, which **fails** on a push running past the end. So on today's mainnet flags the
  node reports `SCRIPT_ERR_SIG_PUSHONLY` and never runs the script. Both reject, which is why
  only an error-NAME comparison could see it — the fifth divergence of that family, and the
  first found by someone outside the project.

  Six shapes were wrong rather than the one reported: `OP_PUSHDATA1`/`2`/`4` declaring more
  than they carry, a direct push opcode doing the same, and `01` — one byte of declared push
  with nothing after it, whose buffer is present but **empty**.

  The condition already existed in the interpreter, added in 1.2.2 for a different divergence
  of the same family, and the node calls one `GetOp` from both places while this package had
  the test in only one. It now lives in `src/script/push-decode.ts` and both callers use it.

  `isDataOut()` and `isSafeDataOut()` move with it, as `Solver`'s `TX_NULL_DATA`
  classification does, using the same `IsPushOnly` on the script after the `OP_RETURN`.

- **Latent since 1.2.2: the interpreter's copy of the test compared `len !== buf.length`,**
  which is not the condition `GetOp2` fails on. A chunk holding MORE bytes than it declares is
  not a truncated push but a chunk disagreeing with its own serialization, and the extra bytes
  are the instructions that follow: `{opcodenum: 1, len: 1, buf: <aa51>}` serializes to
  `01 aa 51`, which parses back as a one-byte push and `OP_1`, both push-only. We answered
  false where the node answers true — a **false reject** in the predicate that decides whether
  a scriptSig may be evaluated at all. The test is now `<`.

### Known, not fixed

- A push whose **length field** is truncated (`4c`, `4d01`, `4e0100`) has no verdict here.
  The node parses the script object and refuses it at evaluation; this package parses eagerly
  and has nothing to put in `len`, so `Script.fromBuffer` throws. Both sides reject and the
  throw is fail-closed, so nothing is wrongly accepted. Giving the parser a representation for
  an instruction it could not decode changes what `fromBuffer` may return, which is a design
  decision with its own false-accept risk — recorded in the `@smartledger/bsv` repository's
  `docs/NODE_DIVERGENCES.md`, with containment pinned by test here.

Reported by the op-codes lab against `@smartledger/bsv` 9.33.0 and this package at 1.5.0,
from 24 vectors judged by a compiled `bitcoin-sv` v1.2.3. Reproduced in both packages before
being accepted, and `IsPushOnly`, `GetOp2`, `VerifyScript` and `Solver` were read at v1.2.3
to confirm the mechanism rather than the symptom.

## [1.5.0] - 2026-10-13

### Fixed

- **`OP_RSHIFTNUM` accepted a shift count the node refuses — a FALSE ACCEPT.**
  `<v> <2^32+1> OP_RSHIFTNUM OP_DROP OP_1` verified here and fails on the
  network: a lock this library calls spendable that no miner will accept, so
  coins sent to it stay there.

  The node hands the count straight to `CScriptNum::operator>>=` as a
  `CScriptNum` — `interpreter.cpp` does `values >>= n;` with no `getint()`,
  unlike the bitwise `OP_RSHIFT`, which calls `n.getint()` and chunks by
  `INT32_MAX`. That operator narrows the count to a 32-bit shift and raises
  `bsv::big_int_error` above `INT32_MAX`, surfacing as `SCRIPT_ERR_BIG_INT`.
  This library had no bound: the count fell through to the
  `shiftBy >= bitLength()` short-circuit and the opcode pushed an empty result.

  Measured against a compiled bitcoin-sv v1.2.3 under flags `0x3d586f`: counts
  at and above 2^31 abort with `SCRIPT_ERR_BIG_INT`, counts at or below 2^31-1
  shift, and the value is irrelevant because the count is narrowed before
  anything is shifted.

  The bound is tested on the `BN` **before** `toNumber()`, which here is
  `parseInt(toString(10))` and does not throw past 2^53 — a 26-byte count
  narrowed to `4.1e62`. Both operands are read first, in the node's order, so a
  value failing its own validation still reports *its* error: a non-minimal
  value with a 2^32+1 count gives `SCRIPT_ERR_SCRIPTNUM_MINENCODE`.
  `OP_LSHIFTNUM` is deliberately exempt — its result-size bound runs first and
  fires whatever the value is, including zero, and it cannot reach the
  `big_int` path at all.

  Pre-Chronicle behaviour is asserted unchanged: for a pre-Chronicle UTXO these
  bytes are upgradable NOPs, and the new error must not refuse a script the
  network accepts.

  Found by an outside lab building a locking-script catalogue on 1.4.0, with
  reference verdicts from a compiled node — not by this suite, whose existing
  shift-count cases all sit far below the boundary. The same defect was present
  in `@smartledger/bsv` and is fixed in 9.33.0.

### Documentation

- `valueCovenant`'s doc comment never mentioned change. It pins the digest of
  the **entire output set** under SIGHASH_ALL — count, order, values and
  scripts — so a lock built from `hashOutputs([payout])` rejects the spend
  `[payout, change]`. Pinning change fixes its *amount*, not the fee.
  `valueCovenantSingle` is the one-output form, pinning the output at the
  spending **input's** index.

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
