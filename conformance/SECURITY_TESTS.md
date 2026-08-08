# Security regression test inventory

These test files encode security fixes shipped in v6.2.2 through v7.5.5. They
are the highest-value tests in the repository: each one exists because a real
defect reached a release.

**Rule for the rewrite:** these are ported *first*, before any feature work in
their module, and they are never allowed to go red. If a test here cannot be
ported because the API changed, the replacement must be written and reviewed
before the old one is deleted — not after.

Derived from the fix commits, not from guesswork; the commit column is the
provenance for each entry.

## Core (moves to the new core package)

| Test file | Guards against | Commit |
|---|---|---|
| `test/crypto/ecdsa.js` | ECDSA nonce reuse | `5c71aa8` |
| `test/crypto/signature.js` | Signature malleability bypass, non-canonical DER | `5c71aa8` |
| `test/crypto/security.js` | Combined crypto hardening suite | `5c71aa8` |
| `test/script/script.js` | Script-level malleability surface | `5c71aa8` |
| `test/util/id.js` | Predictable token/id generation | `5c71aa8` |
| `test/privatekey.js` | Malformed `bn` deriving a *different* key; key material leak | `f187821`, `dff5e1d` |
| `test/mnemonic/mnemonic.js` | `fromRandom` ignoring the entropy argument (weak phrases) | `558a584` |
| `test/encoding/base58check.js` | Silent-argument footgun | `9b5673e` |
| `test/hdprivatekey.js` | Silent-argument footgun | `9b5673e` |
| `test/ecies/bitcore-ecies.js` | Silent-argument footgun | `9b5673e` |
| `test/script/genesis_limits.js` | Script size cap not configurable for Genesis | `9096149` |
| `test/ordinals/inscription.js` | Silent-argument sweep; lock lost on spec-legal parse | `3ff983e`, `9096149` |
| `test/ordinals/ordlock.js` | OrdLock covenant verification | `20b7fe1`, `9096149` |
| `test/ordinals/bsv20.js` | BSV-20 spec conformance | `20b7fe1` |

## Protocol packages (move with their module)

| Test file | Guards against | Commit |
|---|---|---|
| `test/gdaf/anchor_no_key_leak.js` | **Private key published on chain**; key material detected by value not field name | `dff5e1d`, `41af9a5` |
| `test/ltp/ids.js` | Predictable token ids | `5c71aa8` |
| `test/smart_contract/preimage.js` | Dishonest errors on malformed preimage input | `ac88b1d` |
| `test/smart_contract/*.js` (covenants, dsl_debugger, ordinal_transfer, sighash_marketplace, token_generalized) | Script size cap regressions | `9096149` |

## Build / API-honesty tests

These are not security tests in the cryptographic sense, but they prevent the
package from *lying about itself*, which is how several of the above shipped.

| Test file | Guards against | Commit |
|---|---|---|
| `test/types/dts_drift.js` | Type declarations disagreeing with the code | `2c3900f` |
| `test/types/surface_honesty.js` | Exported surface not matching documentation | `2c3900f` |
| `test/build/esm_wrapper.js` | ESM wrapper drifting from CJS entry | `5c71aa8` |

## Coverage relationship to the conformance corpus

The corpus and these tests overlap deliberately but are not redundant:

- The **tests** assert specific values their authors reasoned about.
- The **corpus** records everything the library actually does, including
  behavior nobody wrote a test for.

The corpus cannot replace these tests, because a corpus records current
behavior — if a security bug were present today, the corpus would faithfully
freeze the bug. These tests are the statement of what the behavior *should* be.
Both gates must pass.
