# TypeScript migration

Status and order of the JavaScript → TypeScript conversion.

## How the build works during the migration

Two configs, because they want different things:

- **`tsconfig.json`** compiles the whole tree, `allowJs: true`, and produces a
  complete runnable `dist/`. Every unconverted `.js` still ships, so the test
  suite and the conformance corpus run at every step.
- **`tsconfig.types.json`** emits declarations from **`.ts` files only**.

Declarations are deliberately *not* generated from the JavaScript. Asking `tsc`
to do that produces a wall of `any`, real `TS9005` errors ("declaration emit
requires using private name", in `src/errors/index.js`), and an outright
compiler crash in the full-project build. The point of this migration is to
replace a hand-maintained 66 KB `.d.ts` with types somebody actually wrote —
auto-derived `any` would be the same problem in a new costume.

Consequence: **the published type surface grows as the migration proceeds**,
and everything in it is real. When the last `.js` is gone the two configs
collapse into one.

`strict: true` from the first commit, plus `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes` and `noImplicitOverride`. Retrofitting strict onto
an already-converted codebase costs far more than starting with it.

Tests and the corpus run against `dist/`, not `src/` — they exercise what
ships.

## The gate

Every conversion must leave all three green:

```
npm test            # 4358 passing
npm run conformance # 371/371 cases match
npx tsc -p tsconfig.types.json   # strict, clean
```

The corpus is the one that matters. It was frozen against `@smartledger/bsv`
before any of this started, so it detects a behavior change introduced by a
conversion, which tests written against the same code cannot always do.

## Order

Computed, not chosen: a topological sort of the internal `require()` graph.

### The acyclic portion — 36 files, 9 layers — **COMPLETE**

Converted bottom-up; a layer was only started once every layer below it was
done. All 36 are now TypeScript, `strict` clean, with generated declarations.

| Layer | Files | Status |
|---|---|---|
| 0 | `crypto/random`, `encoding/bufferwriter`, `errors/spec`, `mnemonic/pbkdf2.node`, `mnemonic/words/{chinese,english,french,italian,japanese,spanish}` | ✅ done |
| 1 | `mnemonic/words/index`, `util/_` | ✅ done |
| 2 | `encoding/base58`, `errors/index` | ✅ done |
| 3 | `ecies/errors`, `mnemonic/errors`, `util/preconditions` | ✅ done |
| 4 | `crypto/bn`, `crypto/hash.browser`, `crypto/hash.node`, `util/js` | ✅ done |
| 5 | `crypto/hash`, `crypto/point`, `encoding/bufferreader`, `networks`, `opcode` | ✅ done |
| 6 | `block/blockheader`, `crypto/shamir`, `crypto/signature`, `encoding/base58check`, `encoding/varint`, `mnemonic/pbkdf2.browser` | ✅ done |
| 7 | `mnemonic/pbkdf2`, `spv/headerchain`, `spv/merkleproof` | ✅ done |
| 8 | `spv/index` | ✅ done |

### The remaining work, by structure (computed via Tarjan SCC)

The "cyclic cluster" is not one blob. Of the 40 remaining `.js` files:

- **21 are in true cycles** — one SCC of 19 (the core object graph) plus
  `hdprivatekey ↔ hdpublickey`.
- **19 are merely downstream** of those, and are orderable exactly like the
  acyclic set was.

#### SCC-19 — must convert as a single unit (7,612 lines)

```
address            privatekey         publickey          crypto/ecdsa
script/{index, script, interpreter}
transaction/{index, transaction, sighash, output, unspentoutput, signature}
transaction/input/{index, input, publickey, publickeyhash, multisig, multisigscripthash}
```

Three files are 57% of it: `script/interpreter` (1932), `transaction/transaction`
(1264), `script/script` (1172) — the most consensus-critical code in the
library.

**Why it cannot be done incrementally:** `tsconfig.types.json` sets
`allowJs: false`, so a `.ts` file cannot import an unconverted `.js` sibling.
Since these 19 are mutually recursive, converting any one of them breaks
declaration emit for all of them.

**Consequence to plan around:** only DECLARATION EMIT waits for the last of the
19. Type checking does not — `tsc --noEmit` uses the main config, which has
`allowJs`, so every `.ts` file is fully checked while importing unconverted
`.js` siblings. The conversion is therefore gated throughout by

    npm run typecheck && npm test && npm run conformance \
      && node scripts/check-cycle-safety.js

which is a far better position than "tests only".

**What makes the cycle tractable:** `import type` is erased. Type-level
references across the cycle cost nothing at runtime and cannot create a
temporal-dead-zone hazard, so only genuine RUNTIME edges need care. The
pattern is:

- cross-cycle TYPES -> `import type` from a `.types` module
- cross-cycle RUNTIME -> a lazy accessor called at use time, e.g.
  `const publicKeyCtor = () => require('../publickey')`

**CAVEAT — the lazy accessor is not always sufficient.** `address.js` cannot
use it for its `instanceof` checks. It relies on a different CommonJS idiom:

```js
module.exports = Address          // export FIRST
var Script = require('./script')  // require AFTER, hoisted `var`
```

Exporting before requiring the partner means that when `script` requires
`address` back, it gets a COMPLETE Address. Replacing that with a call-time
`require('./script')` returns a PARTIALLY INITIALIZED module on some load
paths, so `data instanceof Script` silently evaluates to false. Node warns
("Accessing non-existent property 'Symbol(Symbol.hasInstance)' of module
exports inside circular dependency"), and the conformance corpus caught it as
91 differences.

`export =` cannot express "export, then require", so converting address needs
a deliberate choice — most likely a memoized accessor primed after export, or
replacing the `instanceof` checks with structural predicates that do not
depend on constructor identity. Settle this before converting address,
script, or transaction, all of which use the same idiom.

The alternative — ambient `any` declarations to bridge the unconverted files —
is rejected: it reintroduces exactly the `any`-riddled surface this migration
exists to eliminate, and it would typecheck while being wrong.

**One pattern needing a decision, not a rewrite:** the three barrel files
assign and then mutate their exports:

```js
module.exports = require('./script')
module.exports.Interpreter = require('./interpreter')
```

`export =` does not express "assign then augment". Options are a merged object
literal, or `Object.assign`, and the choice affects the emitted type surface —
worth settling deliberately before starting.

#### SCC-2 — `hdprivatekey ↔ hdpublickey`

Depends on SCC-19, so it follows.

#### Downstream 19 — orderable, convert last

```
block/{index, block, merkleblock}      ecies/{index, bitcore-ecies, electrum-ecies}
covenant/{index, helpers, pushtx}      message/{index, message}
mnemonic/{index, mnemonic}             ordinals/{index, inscription, ordlock, bsv20}
crypto/smartledger_verify              index
```

### Why the cycles themselves are no longer a blocker

They form 24 distinct circular dependencies:

- `address → publickey → privatekey → address`
- `hdprivatekey ↔ hdpublickey`
- `script → interpreter → transaction → sighash → script`, plus every
  `transaction/input/*` variant of the same loop

These are not accidents; they follow the domain model (an Address is derived
from a PublicKey, and a PublicKey yields an Address). They survive under
CommonJS because every access is deferred to call time.

Removing the *package-root* cycles — the 45 files that reached back through
`index.js` — did not touch these. That work was still required, and was the
harder problem, but it was a different one.

**These cycles are now ESM-safe** — see `scripts/check-cycle-safety.js`. The
hazard was never the cycles themselves but evaluation-time dereference of a
cyclic import, which was true of only three modules and has been fixed. So the
cluster is an ordinary (if large) conversion, not an API-design problem.

Historical note on the original framing:

- TypeScript itself is fine with circular imports; types are erased and
  resolved across the cycle. So this cluster **can** be converted, but it must
  be converted as a unit rather than incrementally, and `import type` should be
  preferred wherever only the type is needed.
- The real exposure is **ESM output**, where live bindings and TDZ make cycles
  genuinely fragile. That lands in the packaging phase, not here.
- Breaking the cycles properly means extracting the shared shapes each pair
  disagrees about — most likely interfaces plus a small number of factory
  functions. That is an API-design decision and belongs with the API pass, not
  buried inside a mechanical conversion.

The 36 acyclic files are done. **The cluster's fate is now the open decision**
— convert-as-a-unit, or break the cycles first and then convert. Breaking them
is the better long-term answer and is what unblocks ESM output, but it is API
design work, so it belongs with the API pass rather than being decided by
default inside a mechanical conversion.

## Bugs found by the conversion

Strict typing surfaced three defects the 4361-test suite and the 371-case
corpus both missed. Two were harmless by accident; one was not.

| Where | Defect | Impact |
|---|---|---|
| `networks` | `STN.cashAddrPrefixToArray()` — STN is a plain object with no such method | **Live bug.** `enableStn()` then reading `testnet.cashAddrPrefixArray` throws. Reproduced against published 7.5.5, fixed, 3 regression tests added. |
| `crypto/hash` | `key < blocksize` compares a Buffer to a number, always false | Latent. Short HMAC keys were never zero-padded, but the XOR indexes past the key and `x ^ undefined === x ^ 0`, which is what padding produces. |
| `crypto/bn` | `buf.length === 1 & buf[0] === 0` — bitwise `&` on booleans | Latent. `===` binds tighter and `true & true` is truthy, so it worked. |

The corpus proved the two latent fixes were behavior-neutral. It could not
have caught the live one: no case calls `enableStn()`.

## Conventions established

Worth knowing before continuing, because they recur:

- **Dual-callable constructors stay constructor functions, not classes.**
  `BufferWriter`, `Base58` and others are invoked both as `new X()` and bare
  `X()`. An ES2020 `class` throws when called without `new`, so converting them
  would be an API break disguised as a refactor.
- **Shared interfaces live in a per-directory `types.ts`.** Modules keeping
  their CommonJS `require()` shape use `export =`, and TypeScript forbids an
  export assignment alongside other exported members.
- **Untyped dependencies get local declarations** in `src/types/`. `bs58@4`
  ships none; the declaration there documents that the `=4.0.1` pin is load
  bearing, since v5 changed to Uint8Array signatures.
- **`noUncheckedIndexedAccess` stays on.** Byte-level code needs a few
  assertions where a loop bound provably guarantees the index; that is worth
  the safety it gives everywhere else.
- The error tree is built dynamically and is typed with an index signature
  rather than a fabricated mapped type. Precise per-error types change what
  consumers can reference, so that belongs with the API pass.

## Progress

| | Count |
|---|---|
| Converted | **36 — the entire acyclic set** |
| Acyclic, remaining | 0 | `spv/index` | ✅ done |
| Cyclic cluster | ~39 |
