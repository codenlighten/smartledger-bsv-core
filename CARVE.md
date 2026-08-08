# Carve record

`@smartledger/bsv-core` was carved from `@smartledger/bsv` v7.5.5. This file
records what came across, what did not, and where the omissions went — so that
nothing is lost by silence.

## Method

The file set was not chosen by hand. It is the **dependency closure** of the
core public surface: start from the Bitcoin primitives (keys, addresses,
script, transactions, encoding, block, SPV, ECIES, message, mnemonic, ordinals,
covenant) and follow every `require()`. That guarantees nothing needed is
missing and nothing unneeded is included.

Result: **74 library files**, with **zero** references into
`lib/{ltp,gdaf,smart_contract,vcjwt,didweb,statuslist,anchor}`.

## Proof the carve preserved behavior

The conformance corpus from the source repo was replayed against this package
**unmodified** — same suites, same fixtures, no edits:

```
selfcheck: 27/27 published vectors reproduce
PASS: 371 cases match the corpus
```

That includes all **1000 Bitcoin Core sighash vectors** and **1329
script_tests**. The core is behaviorally identical to the monolith it came
from. This is the reason the corpus was built before anything moved, and the
reason its suites take the library as an argument rather than importing it.

Test suite: **4358 passing**.

## Not carried, and where it went

| Module | Why | Disposition |
|---|---|---|
| `lib/util/id.js` + `test/util/id.js` | Used **only** by LTP (`claim`, `obligation`, `registry`, `right`). Not reachable from the core surface. | **Must move to the LTP package with its test.** The test guards the predictable-token-id fix (`5c71aa8`) and is listed in the security inventory — it must not be dropped there. |
| `lib/crypto/elliptic-fixed.js` + its test | An `elliptic`-**shaped** compatibility wrapper (`keyFromPrivate`/`sign`/`verify`/`recoverPubKey`) backed by `@noble` since the migration away from `elliptic`. Used only by the old `index.js`; nothing in `lib/` calls it. | **Dropped.** A clean break sheds a compatibility surface for a library we no longer use. Its properties remain covered on the real path: low-S has 38 assertions across the crypto tests plus the corpus, and the recovery bit is pinned by a hardcoded compact signature in `test/crypto/ecdsa.js:305`. |
| `lib/smartutxo.js`, `lib/smartminer.js`, `lib/browser-utxo-manager*.js`, `lib/custom-script-helper.js`, `lib/covenant-interface.js` | Development simulators and helper surfaces, not primitives. Not reachable from the core surface. | Left in the source package. |
| `lib/{ltp,gdaf,smart_contract,vcjwt,didweb,statuslist,anchor}` | The application layer. | Become sibling packages depending on this one. |

## Carried, but unfinished

**`lib/crypto/smartledger_verify.js`** (`bsv.crypto.SmartVerify`) is carried so
its seven security assertions keep running, but it remains **opt-in** — nothing
in `lib/` calls it. It enforces low-S, rejects zero/out-of-range components,
and validates hash length; the default `ECDSA.verify` path does none of that.

Folding these checks into the default verify path, or deleting the module, is
an API-design decision for the next phase. What is *not* carried is the old
root-namespace advertisement (`isHardened`, `hardenedBy`, `securityFeatures`),
which claimed these protections were active while the default path bypassed
them.

**`lib/covenant/helpers.js`** is not uniformly primitive. `flags()`,
`signInput()`, `rawPreimage()`, `sighashDigest()` and `scriptNum()` are genuine
primitives; `fundAndSpend()` and `p2pkhOutput()` are test scaffolding that
should not sit in core. Splitting them is deferred to the API pass.

## Deliberate API differences from `@smartledger/bsv`

- **No `bsv.deps`.** Modules import directly; load order is not load-bearing.
- **No `global._bsv` version guard.** It detected duplicate instances by
  mutating a global — itself an import-time side effect.
- **No `Mnemonic.bsv`** back-reference to the whole library.
- **No `isHardened` / `securityFeatures`.** See above.
- **`bsv.Covenant`** is new: `{ PushTx, Helpers }`, previously reachable only
  as `SmartContract.PushTx` / `SmartContract.CovenantHelpers`.
- `Signature`, `Input`, `Output`, `UnspentOutput` remain top-level.

## Known state

- Lint under `standard@17`: **4 errors, ~4300 `no-var` warnings** in `lib/`.
  The warnings disappear wholesale in the TypeScript migration; fixing them as
  JavaScript first would be wasted work.
- One real defect was found and removed during the carve: `lib/crypto/ecdsa.js`
  contained `this.sig = this.sig`. Verified a genuine no-op (`sig` is a plain
  data property; only `k` has a setter) before deleting.
- `test/script/script.js:1077` uses the literal `0xffffffffffffffff`, which
  exceeds `Number.MAX_SAFE_INTEGER` and silently becomes
  `18446744073709552000`. Pre-existing; the assertion still holds, but the test
  is not testing the value it appears to. Left as-is, noted here.
