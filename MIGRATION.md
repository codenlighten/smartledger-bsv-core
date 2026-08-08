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

### The cyclic cluster — the remaining ~39 files

**There is no valid leaf-first order for these.** They form 24 distinct
circular dependencies:

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

Implications:

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
