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
#
# It compiles the consumer under SEVERAL moduleResolution modes, because one is not enough. Until
# 2026-10-11 this gate ran `"moduleResolution": "node"` alone — the one mode in which TypeScript
# does NOT enforce ESM/CJS import legality. That blind spot hid a real defect through 1.0.x and
# 1.1.0: the shipped declarations re-exported a type from the ESM-only `@noble/curves`, so a CJS
# consumer on `node16`/`nodenext` got TS1479 while this gate stayed green. A gate that tests one
# resolution mode will keep missing that whole class, so it now tests the modes consumers use.
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

// Touch the declaration that carried the TS1479/TS1541 defect, so this row exercises the
// affected public type and not merely the package root.
const g = bsv.crypto.Point.getG()
const px: string = g.getX().toString()

void [address, ok, err, a2, v, px]
EOF

# A second smoke file in ESM syntax. The CJS one above uses `import bsv = require(...)`, an import
# assignment, which is illegal when targeting ES modules — so reusing it for the bundler/esnext row
# would test this file's syntax rather than the package. An ESM consumer of an `export =` package
# writes a default import under esModuleInterop, so that is what this checks.
cat > smoke.esm.ts <<'EOF'
import bsv from '@smartledger/bsv-core'

const key = new bsv.PrivateKey()
const address: string = key.toAddress().toString()
const tx = new bsv.Transaction()
const flags: number = bsv.Script.Interpreter.mainnetFlags()
const bn = new bsv.crypto.BN(100)
const script = bsv.Script.fromASM('OP_1')

const interp = new bsv.Script.Interpreter()
const ok: boolean = interp.verify(new bsv.Script(), script, tx, 0, flags, bn)
const err: string = interp.errstr
const v: string = bsv.version

void [address, ok, err, v]
EOF

# A genuine ESM consumer, not merely an ESM-ish compiler setting: its own directory with
# `"type": "module"`, so TypeScript resolves this package the way a real ESM consumer does. The
# compiler-flag rows above cannot establish this, because the enclosing package.json is CommonJS.
mkdir -p esm-consumer
cat > esm-consumer/package.json <<'EOF'
{ "name": "esm-consumer", "version": "1.0.0", "type": "module" }
EOF
cat > esm-consumer/smoke.mts <<'EOF'
import bsv from '@smartledger/bsv-core'

const key = new bsv.PrivateKey()
const address: string = key.toAddress().toString()
const tx = new bsv.Transaction()
const flags: number = bsv.Script.Interpreter.mainnetFlags()
const bn = new bsv.crypto.BN(100)
const script = bsv.Script.fromASM('OP_1')
const interp = new bsv.Script.Interpreter()
const ok: boolean = interp.verify(new bsv.Script(), script, tx, 0, flags, bn)

// Touch the declaration that carried the TS1479/TS1541 defect, so these rows exercise the
// affected public type rather than merely importing the package root.
const g = bsv.crypto.Point.getG()
const px: string = g.getX().toString()
const pt: typeof g = g.mul(bn)

void [address, ok, px, pt, bsv.version]
EOF

run_mode () {
  local name="$1" resolution="$2" module="$3" smoke="${4:-smoke.ts}"
  cat > "tsconfig.$name.json" <<EOF
{
  "compilerOptions": {
    "target": "es2020", "module": "$module", "moduleResolution": "$resolution",
    "strict": true, "noEmit": true, "esModuleInterop": true
  },
  "include": ["$smoke"]
}
EOF
  if ./node_modules/.bin/tsc --noEmit -p "tsconfig.$name.json"; then
    echo "  OK      moduleResolution=$resolution module=$module"
    return 0
  fi
  echo "  FAILED  moduleResolution=$resolution module=$module" >&2
  return 1
}

# The modes a real consumer picks. `node` is the legacy default, `node16` is what a modern CJS
# consumer on a current tsconfig gets, and `bundler` is what Vite/webpack users get. A failure in
# ANY of them is a failure: consumers do not all share our tsconfig.
failed=0
run_mode legacy  node     commonjs || failed=1
run_mode node16  node16   node16   || failed=1
run_mode bundler bundler  esnext   smoke.esm.ts || failed=1
run_mode nodenext nodenext nodenext || failed=1

# The real ESM consumer, compiled in its own directory so its package.json applies.
cat > esm-consumer/tsconfig.json <<'EOF'
{
  "compilerOptions": {
    "target": "es2020", "module": "nodenext", "moduleResolution": "nodenext",
    "strict": true, "noEmit": true, "esModuleInterop": true, "skipLibCheck": false
  },
  "include": ["smoke.mts"]
}
EOF
if (cd esm-consumer && ../node_modules/.bin/tsc --noEmit -p tsconfig.json); then
  echo '  OK      a real "type": "module" consumer (.mts, nodenext, skipLibCheck false)'
else
  echo '  FAILED  a real "type": "module" consumer (.mts, nodenext, skipLibCheck false)' >&2
  failed=1
fi

if [ "$failed" -eq 0 ]; then
  echo "consumer-types: OK — a strict consumer compiles against the tarball in every resolution mode, with no added @types"
else
  echo "consumer-types: FAILED — see the errors above." >&2
  echo "A consumer installs only what \`dependencies\` ships. If a type comes from a" >&2
  echo "devDependency, or a declaration resolves to any/unknown, it fails here and not in" >&2
  echo "\`npm run typecheck\`." >&2
  echo "A failure in node16/bundler only usually means a shipped .d.ts imports an ESM-only" >&2
  echo "package (TS1479). Use \`import type\` so no require() is emitted, or restate the type." >&2
  exit 1
fi
