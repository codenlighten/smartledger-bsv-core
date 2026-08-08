/**
 * Platform dispatcher for the hash primitives.
 *
 * The requires stay lazy and inside the branch on purpose: bundlers rewrite
 * `process.browser` to a literal and dead-code-eliminate the unused arm, which
 * is what keeps Node's `crypto` out of browser bundles. Importing both at the
 * top and selecting afterwards would defeat that.
 */
import type { HashModule } from './types'

declare const process: NodeJS.Process & { browser?: boolean }

// eslint-disable-next-line @typescript-eslint/no-var-requires
const Hash: HashModule = process.browser === true
  ? require('./hash.browser')
  : require('./hash.node')

export = Hash
