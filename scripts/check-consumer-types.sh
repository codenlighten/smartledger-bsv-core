#!/usr/bin/env bash
# Compiles a consumer's TypeScript against the PACKED TARBALL, installed into a throwaway
# directory with nothing added by hand.
#
# This exists because `npm run typecheck` cannot see the failure it catches. That compiles this
# package's own source, where every type resolves from devDependencies; a consumer installs only
# what `dependencies` ships. At 1.0.0 that gap had hidden three real defects:
#
#   - dist/index.d.ts was `declare const bsv: Record<string, any>`, so every member of the
#     package root was `any` and consumers got no checking at all;
#   - the shipped declarations reference bn.js and Buffer, whose types were devDependencies, so
#     a consumer got TS7016 on import;
#   - ScriptConstructor declared `Interpreter: unknown`, making the consensus-critical class
#     TS18046 for everyone.
#
# All three were invisible until someone compiled as a consumer. So that is what this does.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"
npm run build >/dev/null
TARBALL="$(npm pack --silent | tail -1)"
trap 'rm -rf "$WORK"; rm -f "$ROOT/$TARBALL"' EXIT

cd "$WORK"
npm init -y >/dev/null 2>&1
npm install --no-audit --no-fund "$ROOT/$TARBALL" >/dev/null 2>&1
npm install --no-save --no-audit --no-fund typescript@5 >/dev/null 2>&1

cat > smoke.ts <<'EOF'
import bsv = require('@smartledger/bsv-core')

const key = new bsv.PrivateKey()
const addr = key.toAddress()
const address: string = addr.toString()
const tx = new bsv.Transaction()
const flags: number = bsv.Script.Interpreter.mainnetFlags()
const bn = new bsv.crypto.BN(100)
const script = bsv.Script.fromASM('OP_1')

// The consensus surface, which is the reason this package exists.
const interp = new bsv.Script.Interpreter()
const ok: boolean = interp.verify(new bsv.Script(), script, tx, 0, flags, bn)
const err: string = interp.errstr

// Annotation via InstanceType, the form an `export =` module supports.
const a2: InstanceType<typeof bsv.Address> = addr
const v: string = bsv.version

void [address, ok, err, a2, v]
EOF

cat > tsconfig.json <<'EOF'
{
  "compilerOptions": {
    "target": "es2020", "module": "commonjs", "moduleResolution": "node",
    "strict": true, "noEmit": true, "esModuleInterop": true
  },
  "include": ["smoke.ts"]
}
EOF

if ./node_modules/.bin/tsc --noEmit -p tsconfig.json; then
  echo "consumer-types: OK — a strict consumer compiles against the tarball with no added @types"
else
  echo "consumer-types: FAILED — see the errors above." >&2
  echo "A consumer installs only what \`dependencies\` ships. If a type comes from a" >&2
  echo "devDependency, or a declaration resolves to any/unknown, it fails here and not in" >&2
  echo "\`npm run typecheck\`." >&2
  exit 1
fi
