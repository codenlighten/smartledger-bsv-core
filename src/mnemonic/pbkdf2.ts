/**
 * Platform dispatcher for PBKDF2-HMAC-SHA512.
 *
 * Lazy, in-branch requires for the same reason as crypto/hash: bundlers
 * eliminate the unused arm via the `process.browser` literal.
 */
declare const process: NodeJS.Process & { browser?: boolean }

type Pbkdf2 = (key: string | Buffer, salt: string | Buffer, iterations: number, dkLen: number) => Buffer

// eslint-disable-next-line @typescript-eslint/no-var-requires
const pbkdf2: Pbkdf2 = process.browser === true
  ? require('./pbkdf2.browser')
  : require('./pbkdf2.node')

export = pbkdf2
