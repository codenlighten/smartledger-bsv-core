# IP records

Evidence of authorship, registered through [iptrust.org](https://iptrust.org) with the
`iptrust2` CLI. Each record is signed on the author's machine with their own key and anchored on
BSV (through NotaryHash) and on Bitcoin (through OpenTimestamps).

A record is **evidence** that the committed content existed by the time of the block, and that
the signer made the statement it carries. It does not create or register any right; formal
registration is a separate thing.

Registrations are **hash-only**. The content and its blinding value never leave the machine.

| date | covers | type | record | signer | tag |
| --- | --- | --- | --- | --- | --- |
| 2026-10-11 | `src/` at v1.3.0 — the 1.3.0 release: two consensus fixes. The Chronicle opcodes now follow the OUTPUT's era as the node does rather than the block's, and `Covenant.Helpers.flags()` gains the three era flags it omitted, which had every covenant verified under pre-Genesis limits | software, published to npm as [`@smartledger/bsv-core@1.3.0`](https://www.npmjs.com/package/@smartledger/bsv-core/v/1.3.0) (shasum `3a236859…bbf0`) | [`cb4074f6…7c09`](https://iptrust.org/v/cb4074f61189f4710a9a547396451de4139560d93d016e30f485f7e7be017c09) | Gregory J. Ward | `ip-2026-10-11-3` |
| 2026-10-11 | `src/` at v1.2.0 — the 1.2.0 release: the same consensus false accept as bsv 9.29.0 (`OP_LEFT`/`OP_RIGHT`/`OP_SUBSTR` operands must deserialize as an int64, not a big number bounded by `maxScriptNumLength()`), plus shipped declarations that failed to resolve for CommonJS consumers on `node16`/`nodenext` | software, published to npm as [`@smartledger/bsv-core@1.2.0`](https://www.npmjs.com/package/@smartledger/bsv-core/v/1.2.0) (shasum `e77377d7…8f2a`) | [`13fbc3c7…24c8`](https://iptrust.org/v/13fbc3c7af86fa6f775c28df4c1fa7a1fc40263c2f4f92092ae5f84d5cb524c8) | Gregory J. Ward | `ip-2026-10-11-2` |
| 2026-10-11 | `src/` at v1.1.0 — the 1.1.0 release: parity with @smartledger/bsv across its 9.17-9.28 releases (the deprecation mechanism, the sighash midstate cache, `valueCovenantSingle` and this package's first covenant tests), a NaN that passed the argument guards, and the stderr noise in ordinary message signing | software, unpublished at registration; published to npm 2026-10-11 as [`@smartledger/bsv-core@1.1.0`](https://www.npmjs.com/package/@smartledger/bsv-core/v/1.1.0) (shasum `2ba4e8c8…8e28`) | [`2bb5512d…52692`](https://iptrust.org/v/2bb5512d80c50fb9206364dc8732d3e3836f76915105dbb791826b0beba52692) | Gregory J. Ward | `ip-2026-10-11` |
| 2026-10-01 | `src/` at v1.0.3 — the 1.0.3 release: era-dependent operand decoding, locktime gating, and the shift opcodes' cost and count validation | software, published | [`430fe9db…6086`](https://iptrust.org/v/430fe9db01189c1271c3ee0599f8f60b5478081e91c6af371ff23ca7f5426086) | Gregory J. Ward | `ip-2026-10-01` |
| 2026-09-30 | `src/` at v1.0.0 — the 1.0.0 release: exact agreement with the reference node's script vectors | software, published | [`0212e6cd…c086`](https://iptrust.org/v/0212e6cd83e9e0702f93dd90a814dcab787f3b19f7494679eaa0f92446c7c086) | Gregory J. Ward | `ip-2026-09-30` |

Authors on every record for this project: Gregory J. Ward, Bryan W. Daugherty, Shawn M. Ryan.

## Why the records cover `src/` rather than the whole tree

`test/data/bitcoin-sv/` and `test/data/bitcoind/` are the reference implementations' own test
vectors, copied verbatim and MIT licensed. They are not ours to register, so the records are
scoped to `src/` — this package's own TypeScript. The git tag fixes the state of the whole tree
at the same commit, so nothing is lost by the narrower scope.

`IP.md` sits outside the registered set, so recording a hash here cannot affect verification of
the registered content.

## Verifying a record

The evidence lives in `.iptrust/v2/<recordHash>/`. `opening.json` and `manifest.json` are the
private half: **a registration cannot be proven without them**, so they are never deleted, and
neither is an `ip-*` tag.

Verification runs in a separate worktree, so the working copy is never touched:

```sh
git worktree add /tmp/at-tag-smartledger-bsv-core ip-2026-09-30 && cp -r .iptrust /tmp/at-tag-smartledger-bsv-core/
(cd /tmp/at-tag-smartledger-bsv-core && iptrust2 verify 0212e6cd83e9e0702f93dd90a814dcab787f3b19f7494679eaa0f92446c7c086 --fetch-headers)
git worktree remove --force /tmp/at-tag-smartledger-bsv-core
```

Expect `verdict: valid` and `content: matched`. Block headers can come from any source, so the
check does not depend on iptrust being reachable.

Anchoring completes after the record is accepted — BSV in about an hour, Bitcoin in a few hours —
so `iptrust2 status <recordHash>` may read `certified` / `stamp-pending` for a while before both
chains read `anchored`.
