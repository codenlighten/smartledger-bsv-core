# Contributing to @smartledger/bsv-core

## This is BSV. It is not Bitcoin Core, and it is not BCH.

The single most important thing to know before judging any script or sighash
behaviour here: **BSV's consensus rules diverge from Bitcoin Core's**, and the
divergence decides whether a given behaviour is a bug, a deliberate choice, or
a gap.

"Bitcoin does X" is not evidence about what this library should do. Neither is
a Bitcoin Core reference, a BIP that BSV did not adopt, or an opcode table
copied from a BTC source — **opcode numbers are not portable**.

Establish which BSV upgrade governs the behaviour first.

### Genesis (February 2020)

- Restored `OP_MUL`, `OP_DIV`, `OP_MOD`, `OP_LSHIFT`, `OP_RSHIFT`, `OP_INVERT`,
  `OP_CAT`, `OP_AND`, `OP_OR`, `OP_XOR`.
- Removed the 201-opcode limit and the 10,000-byte script size limit. See
  `Interpreter.useGenesisLimits()`; the pre-Genesis defaults are still the
  out-of-the-box behaviour, opt in deliberately.
- **Reverted `OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY` to
  `OP_NOP2`/`OP_NOP3`.** They are not enforced on BSV. This library still
  implements them behind the `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY` /
  `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` flags, which are off by default, for
  callers emulating pre-Genesis rules.

### Chronicle

- Restores `OP_VER` (98), `OP_VERIF` (101), `OP_VERNOTIF` (102), `OP_2MUL`
  (141), `OP_2DIV` (142).
- Re-enables the string opcodes at **new numbers**: `OP_SUBSTR` 179,
  `OP_LEFT` 180, `OP_RIGHT` 181 — *not* their original 127/128/129, which now
  carry `OP_SPLIT`/`OP_NUM2BIN`/`OP_BIN2NUM` from the Magnetic upgrade. This
  library already uses the new numbers.
- Adds `OP_LSHIFTNUM` (182) and `OP_RSHIFTNUM` (183), taking the bytes that
  were `OP_NOP7`/`OP_NOP8`.
- Adds the Original Transaction Digest Algorithm, selected by a new
  `CHRONICLE = 0x20` sighash flag.

Current conformance against Chronicle — including the gaps — is in
[CHRONICLE.md](CHRONICLE.md). Today's behaviour, wrong parts included, is
pinned by `conformance/suites/chronicle.js`.

## The corpus is the arbiter, not the test suite

`conformance/` records the outcome of every case, **including throws**. Suites
take the library as an argument and never `require()` it, so the same suite
runs against this library and against any reimplementation.

The test suite and the corpus catch different things, and neither subsumes the
other. 4,361 tests have passed through a silent mis-binding, a 500 KB bundle
regression, an `instanceof` break, and a dropped default parameter that changed
which error a caller sees. The corpus caught those. The corpus has also missed
things the tests caught. Run both.

`node conformance/verify.js` ranks outcome flips — was-rejected-now-succeeds —
above every other kind of difference. If you see one, it is not noise.

## Rules that exist because something went wrong

- **Never write a test vector by hand.** Derive it. A fabricated BIP39 seed got
  into this corpus once; `conformance/selfcheck.js` now runs as a hard gate
  before any fixture is written.
- **Fault-inject every guard before trusting it.** Two guards in this repo were
  found to be fake this way — they passed while the thing they checked was
  broken.
- **Pin behaviour before changing it,** including behaviour known to be wrong.
  A fixture recording only correct behaviour lets the incorrect behaviour move
  in either direction unobserved.
- **This codebase omits semicolons.** Any edit that makes a line start with `(`
  is parsed as a call on the previous line. That has bitten a mechanical edit
  here already.
- **Watch for parameter defaults when rewriting signatures.** A default value is
  behaviour, not decoration; dropping one changed which error
  `Mnemonic.fromString` produces.

## `any` is on a ratchet

`scripts/check-any-budget.js` pins the count of `any` in `src/` and fails if it
rises. `any` is not banned — a dynamically built error tree, or a JSON payload
whose shape is defined by an external spec, is honestly `any`. Drift is banned.
Lowering the budget is a normal part of a commit that removes some; raising it
needs a reason in the commit message.

## Gates

```
npx tsc --noEmit                    # types
npx tsc -p tsconfig.types.json      # declaration emit
npm run build                       # dist
npx mocha --recursive test          # 4,361 tests
node conformance/verify.js          # 424 corpus cases
node scripts/check-cycle-safety.js  # no evaluation-time deref of a cyclic import
node scripts/check-any-budget.js    # the ratchet
```

`npm run check` runs lint, tests, conformance, cycle-safety and the ratchet. It
currently exits non-zero on pre-existing lint findings in `test/` — 50 warnings
and 12 errors, none in `src/`.

## Attribution

Commits, pull requests, issues and files carry no attribution to any authoring
tool — no trailer, no footer, no note. Work here is attributed to its human
author alone.
