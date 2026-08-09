/**
 * Declarations for unorm, which ships no types.
 *
 * Only nfkd is used, and only for one thing: BIP39 says the mnemonic phrase
 * and the passphrase must both be NFKD-normalized before PBKDF2. Skipping it
 * makes a phrase containing composed accents derive a different seed from the
 * same phrase written with combining marks — the same words, a different
 * wallet. The other three forms are declared because the module exports them,
 * not because anything here should be reaching for them.
 */
declare module 'unorm' {
  export function nfd (str: string): string
  export function nfkd (str: string): string
  export function nfc (str: string): string
  export function nfkc (str: string): string
}
