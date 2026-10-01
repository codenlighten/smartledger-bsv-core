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
git worktree add /tmp/at-tag ip-2026-09-30 && cp -r .iptrust /tmp/at-tag/
(cd /tmp/at-tag && iptrust2 verify 0212e6cd83e9e0702f93dd90a814dcab787f3b19f7494679eaa0f92446c7c086 --fetch-headers)
git worktree remove --force /tmp/at-tag
```

Expect `verdict: valid` and `content: matched`. Block headers can come from any source, so the
check does not depend on iptrust being reachable.

Anchoring completes after the record is accepted — BSV in about an hour, Bitcoin in a few hours —
so `iptrust2 status <recordHash>` may read `certified` / `stamp-pending` for a while before both
chains read `anchored`.
