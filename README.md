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

Three independent gates, all green:

| Gate | Result |
|---|---|
| Test suite | **4358 passing** |
| Conformance corpus | **371/371 cases match** |
| Published vectors | **27/27 reproduce** |

The conformance corpus is the interesting one. It was built against
`@smartledger/bsv` *before* any code moved, freezing that library's observable
behavior across 371 cases — including all **1000 Bitcoin Core sighash vectors**
and **1329 script_tests**. It then replays against this package unmodified.

Because it passes, this package is behaviorally identical to the monolith at
the primitive level. That is a provable compatibility claim, not an aspiration,
and it is what makes migrating off `@smartledger/bsv` safe.

```bash
npm test           # mocha
npm run conformance # replay the corpus
npm run check      # lint + test + conformance
```

Corpus internals, and the rules for not undermining it, are in
[`conformance/README.md`](conformance/README.md).

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

## Status

Early. The API is not yet stable: this is the JavaScript carve, and a
TypeScript rewrite with generated types is next. The conformance corpus is the
gate that rewrite must pass.

## License

MIT
