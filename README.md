# @smartledger/bsv-core

Bitcoin SV primitives: keys, addresses, script, transactions, encoding, block
headers, SPV, ECIES, message signing, BIP39 mnemonics, 1Sat Ordinals, and
OP_PUSH_TX covenants.

Carved from [`@smartledger/bsv`](https://github.com/codenlighten/smartledger-bsv),
which remains maintained. This package is the primitives layer only —
application protocols (Legal Token Protocol, the attestation framework, the
smart-contract authoring tooling) live in sibling packages that depend on it.

```js
const bsv = require('@smartledger/bsv-core')

const key = bsv.PrivateKey.fromRandom()
const tx = new bsv.Transaction()
  .from(utxo)
  .to(bsv.Address.fromString(address), 90000)
  .change(key.toAddress())
  .sign(key)
```

## Why a separate package

The monolith was ~35,500 lines, of which ~16,600 were application protocols at
roughly a 0.11 test-LOC-per-source-LOC ratio. The Bitcoin primitives sat at
~0.8. Splitting lets the primitives be small, auditable and fully covered,
without gating them on protocol work.

## Verification

Four gates, all green, and one of them is the reason to use this package.

| Gate | Result |
|---|---|
| **SV Node script vectors** | **1483 / 1483** — no false accepts, no false rejects, no wrong reasons |
| SV Node sighash vectors | 1000 / 1000, both digest columns |
| Test suite | 4,336 passing |
| Conformance corpus | 455 cases match |

The first is the one that matters, and it is worth being exact about what it is.
`test/data/bitcoin-sv/script_tests.json` is the reference node's **own** test file, copied
verbatim from `bitcoin-sv` v1.2.2 and replayed unmodified. Every row matches on acceptance or
rejection and, where the row specifies one, on the expected error label. Those labels are the
node's own `ScriptError` names as its own test asserts them — they are fixtures from a release
tag, not a comparison against a live node. A false accept, meaning a script the node rejects
that this package calls valid, fails the build; that is enforced in CI on every pull request
rather than measured by hand.

This is a stronger claim than passing our own tests, and it was not free. The corpus started at
1429 / 1483 with **29 false accepts** — 29 ways to call a spend valid that the network would
refuse — and closing them took nine fixes to the interpreter and the sighash digest. What they
were is in the git history and in `CHANGELOG.md`.

### What the conformance corpus does and does not prove

The 455-case conformance corpus was recorded from `@smartledger/bsv` before any code moved. All
455 match, which checks compatibility **on those cases only** — it establishes neither general
compatibility nor consensus correctness. The difference is not academic: the corpus faithfully
reproduced several of that library's own consensus bugs, which is precisely why the node's
vectors were brought in beside it. And where a bug has since been fixed in both, this package is
deliberately *not* bug-for-bug compatible with older releases of the monolith.

A frozen corpus detects a change. It can never detect a pre-existing wrong assumption.

Two blind spots worth knowing about, because they cost two real bugs that 1483/1483 stayed green
through: every row in the node's script corpus carries transaction version 1, and not one pairs
`LOW_S` with a hash-type expectation. So neither corpus sees Chronicle's malleability rules nor
the signature-encoding checks that `LOW_S` can mask.

```bash
npm test             # mocha
npm run conformance  # replay the compatibility corpus
npm run vectors:sv   # the node's own script vectors
npm run check        # lint + test + conformance
```

Corpus internals, the provenance of the vendored vectors, and which gate enforces what are in
[`conformance/README.md`](conformance/README.md) and
[`test/data/bitcoin-sv/README.md`](test/data/bitcoin-sv/README.md).

## Differences from `@smartledger/bsv`

Deliberate, and small. Full detail in [`CARVE.md`](CARVE.md).

- **`bsv.Covenant`** — `{ PushTx, Helpers }`, the OP_PUSH_TX primitives.
  Previously reachable only via `SmartContract.PushTx` /
  `SmartContract.CovenantHelpers`.
- **No `bsv.deps`** — modules import directly; nothing reads a shared namespace
  off the package root, so load order is not load-bearing and there are no
  require cycles.
- **No `global._bsv` version guard** — it detected duplicate instances by
  mutating a global, which is itself an import-time side effect.
- **No `isHardened` / `securityFeatures`** — the previous values advertised
  protections that the default verify path did not apply. `bsv.crypto.SmartVerify`
  still provides them explicitly; making them the default is tracked work, and
  `CARVE.md` says so plainly rather than restating the claim.

## Stability

**1.0.0.** The supported surface is the **630 names recorded in
[`test/fixtures/api-surface.json`](test/fixtures/api-surface.json)**, and `npm run check:api`
fails the build if a 1.x change removes one or alters its type. Additions are minors. That
snapshot exists so this is a measured promise rather than an assertion: a surface nobody has
enumerated cannot be promised to hold still.

Not covered, and changeable in a patch: anything prefixed `_`, anything reached by deep-importing
past `dist/index.js`, and the exact wording of error *messages* — the error **codes** are covered.

### Consensus tracking overrides the above

This package tracks BSV mainnet. A library that stayed API-compatible with a rule the network no
longer enforces would be worse than useless: it would be confidently wrong in the direction that
costs money. So:

- **A network activation** that changes what this package accepts or rejects ships in a **minor**,
  with the activation and the affected behaviour named in `CHANGELOG.md`. Such a change may well
  be breaking in practice, and calling it a minor does not make it harmless — pin an exact
  version if you need the pre-activation behaviour.
- **A consensus bug**, where this package and the network already disagree, is fixed in a
  **patch** when it only refuses what the network refuses, and in a **minor** when it changes what
  is accepted. 1.0.0 itself came out of nine such fixes.

The node's vectors, not this package's opinion, decide what correct means here.

### What this release is, plainly

New code. The TypeScript port is complete and `dist/` ships generated declarations, with the
`any` budget counted rather than open-ended (29 of 29, so a new one requires removing one).

The package is a CommonJS `export =` module, so from TypeScript:

```ts
import bsv = require('@smartledger/bsv-core')          // values are fully typed
const flags: number = bsv.Script.Interpreter.mainnetFlags()
const addr: InstanceType<typeof bsv.Address> = key.toAddress()   // annotate via InstanceType
```

`bsv.Address` as a bare type annotation is not available — an `export =` module exports values,
not type aliases — and exporting the instance types under their own names is tracked for a
minor. `npm run check:consumer-types` compiles that snippet against the packed tarball in a
throwaway directory with nothing added by hand, and CI runs it, because this package's own
`typecheck` cannot see what a consumer sees: at 1.0.0 that gap had hidden an all-`any` root
declaration, type packages that were devDependencies rather than dependencies, and
`Script.Interpreter` declared `unknown`.

But
the interpreter was carrying 29 false accepts a week before 1.0.0, and CI first ran on
2026-09-30. The corpora, the CI gates and the regression tests for every fix are in the repository
to be checked rather than taken on trust — see
[`test/script/chronicle_malleability.js`](test/script/chronicle_malleability.js) and
[`test/script/verify_script_eras.js`](test/script/verify_script_eras.js), which pin the two bug
classes no corpus could see. Read them before relying on this for value.

## License

MIT
