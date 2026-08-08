# Conformance corpus

A frozen record of what this library actually does, used as the safety net for
the TypeScript rewrite.

The rewrite touches consensus-critical code — sighash, script evaluation,
ECDSA. A subtle regression there is a fund-loss bug, not a bug report. This
corpus is the mitigation: it captures current behavior across 371 cases before
anything moves, so any change to observable behavior surfaces as a diff.

## Usage

```bash
node conformance/generate.js              # record fixtures (refuses to overwrite)
node conformance/generate.js --force      # move the baseline deliberately
node conformance/verify.js                # replay against the current library
node conformance/verify.js --lib=../core  # replay against the rewrite
node conformance/verify.js --errors=full  # also compare error wording
node conformance/verify.js --suite=script # one suite only
```

`verify.js` exits non-zero on any difference, so it drops straight into CI.

## Design

**Suites take the library as an argument.** No suite calls `require()` on the
library. That is the whole point — the same suite runs against today's
CommonJS package and against the TypeScript rewrite without modification:

```js
module.exports = {
  name: 'script',
  cases: {
    'parse p2pkh': (bsv) => bsv.Script.fromHex('76a914...').toASM()
  }
}
```

**Rejections are first-class.** Every case records its outcome, success or
throw alike. This library's history is largely fixes of the form "reject
malformed input instead of silently doing something else" (`f187821`,
`9b5673e`, `3ff983e`). A rewrite that *stops* rejecting bad input is exactly
the regression that matters most, so `verify.js` ranks outcome flips — a case
that threw and now succeeds — above every other diff class.

**Errors compare by name, not message, by default.** Rewording an error is not
a behavior change; a rejection turning into a success is. Use `--errors=full`
when you do want wording pinned.

**Fixtures are not regenerated casually.** `generate.js` refuses to overwrite
without `--force`, because a corpus that silently rewrites its own baseline
certifies whatever the code currently does — including a regression.

## Vector provenance

`vectors.js` holds only inputs, never library-derived values. Where a published
vector exists it is used in preference to an invented constant, so a
disagreement points at us rather than at an arbitrary number:

- **BIP32** test vectors 1, 2, 3. Vector 3 exists specifically to catch
  implementations that strip leading zeros from a derived key.
- **BIP39** Trezor reference vectors (passphrase `TREZOR`), 12/18/24 words.
- **Bitcoin Core** `sighash.json` (1000 vectors) and `script_tests.json`
  (1329 vectors), shipped in `test/data/`.
- **Real mainnet transactions**, including the block 1 coinbase.
- **Secret key = 1** addresses, compressed and uncompressed — the two most
  widely published address constants in Bitcoin.

`selfcheck.js` validates every published vector against the library *before*
any fixture is written, and `generate.js` hard-fails if one disagrees. This
gate exists because a fabricated constant was caught during construction: a
mis-transcribed BIP39 seed would have been faithfully recorded, and the corpus
would have certified the wrong value forever.

## Consensus vector agreement

| Corpus | Vectors | Result |
|---|---|---|
| Bitcoin Core sighash | 1000 | **1000 match exactly** |
| Bitcoin Core script_tests | 1329 | 1315 agree, 14 diverge |

All 14 divergences are deliberate BSV behavior, and the exact set is pinned as
its own case so that accidentally enabling or disabling an opcode shows up as a
diff rather than hiding inside a summary count:

- 13 restored opcodes Core disabled: `CAT`, `SPLIT`, `NUM2BIN`, `BIN2NUM`,
  `AND`, `OR`, `XOR`, `DIV`, `MOD`
- 1 boundary change: `0xba` is no longer the first undefined opcode

## Relationship to the test suite

The corpus does **not** replace the mocha suite, and cannot:

- The corpus records what the library *does*. If a bug existed today, the
  corpus would faithfully freeze the bug.
- The tests state what the library *should* do.

See `SECURITY_TESTS.md` for the security regression tests that must be ported
first and must never go red.

## Files

```
conformance/
  generate.js         record fixtures
  verify.js           replay and diff
  selfcheck.js        validate published vectors against the library
  vectors.js          inputs only — never library-derived
  lib/serialize.js    canonical, diff-friendly value encoding
  lib/harness.js      suite loading, running, comparison
  lib/bitcoind.js     Bitcoin Core data-format helpers
  suites/*.js         the cases
  fixtures/*.json     the frozen baseline
```

`lib/bitcoind.js` deliberately re-implements the Core script-string parser that
currently lives monkey-patched onto `Script` inside
`test/script/interpreter.js`. That patch disappears the moment those tests are
rewritten — precisely when the vectors matter most.
