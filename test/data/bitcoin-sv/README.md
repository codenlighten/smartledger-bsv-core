# SV Node consensus vectors

Test vectors copied verbatim from the reference node implementation. They are
the specification this package is measured against, so do not hand-edit them. To
update them, re-copy from a node tag and record the new provenance here.

| field | value |
| --- | --- |
| source | [`bitcoin-sv/bitcoin-sv`](https://github.com/bitcoin-sv/bitcoin-sv) `src/test/data` |
| tag | `v1.2.2` (tag object `6849d709cca0ba64e79c1b16f3640b926aeca7c6`) |
| commit | `879fc8b42168dd0e608dafd51b39c6dabad37d4d` (2026-04-28) |
| retrieved | 2026-09-29, checked against the tag on GitHub with `git ls-remote` |
| licence | MIT |

Both files are byte-identical to the copies in `@smartledger/bsv`'s
`test/data/bitcoin-sv/`, which were taken at `v1.2.0`. The corpus did not change
between those tags.

| file | sha256 | rows | used by |
| --- | --- | --- | --- |
| `script_tests.json` | `a77f8b94412ef61e9ee59980ebc682a64212b47a16f06d87f809d91770ba496d` | 1483 | `tools/sv-vector-harness.js` |
| `sighash.json` | `9c1afcaf81e8482f818345efa8a3f0610f6541b975023b58550d50ad2a557f63` | 1000 | `tools/sv-sighash-harness.js` |

These supersede `test/data/bitcoind/script_tests.json` and
`test/data/sighash.json`. Those are Bitcoin Core-era files, so they encode the
201-opcode cap, and they compute a BIP-143 digest for every FORKID hash type,
including the `0x20` types that the node now routes to the original algorithm.
They are kept only so that the conformance fixtures recorded against them stay
readable while the port catches up. Where they disagree with the files in this
folder, these win.

## Measuring the gap

    npm run vectors:sv                                   # this package against the node
    npm run vectors:sv -- --verbose                      # plus each failing script
    npm run vectors:sv-delta -- --lib=../smartledger-bsv # row-by-row against the library

Both commands build first and measure `dist/`. They report and always exit 0.
They become a gate once the port reaches parity.

False accepts are listed apart from false rejects. Accepting a script that the
node rejects is the direction that can cost money.

The delta names every row where this package and `@smartledger/bsv` disagree,
grouped by the error the node expects. It also lists the rows where both reject
but only one gives the node's reason. Both packages are scored by the same
harness with the same flags, so a row listed there differs because the
implementations differ, not the harness.

As of 2026-09-29 both pass the whole corpus — 1483 of 1483, no false accepts, no
false rejects, no wrong reasons — so the delta is empty. It stays as the guard
that keeps them level.

## Row layout

The layout is defined by `script_json_test` in the node's
`src/test/script_tests.cpp`:

    [ [nValue]?, txnVersion, scriptSig, scriptPubKey, flags, expected, comment? ]

`txnVersion` is the spending transaction's version, and every row carries it.
Chronicle relaxes its malleability rules only for versions above 1, so this
column affects consensus. It is not padding and it is not an amount.

## MONOLITH and MAGNETIC

The node has no such flags. It enables those opcodes unconditionally. Its
`IsOpcodeDisabled` disables only `2MUL` and `2DIV`, and only before Chronicle.
This package (and the library) still gate them, so the harness grants both flags
to every row, as the library's harness does. The two reports therefore line up.

`--node-flags-only` withdraws that allowance and shows the gating as it is. In
that mode 66 rows (MUL, LSHIFT, RSHIFT, INVERT) fail in both packages.
