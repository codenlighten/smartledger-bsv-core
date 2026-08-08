'use strict'

// Fixed inputs shared across conformance suites.
//
// Everything here is deterministic and, wherever a published vector exists, is
// taken from the spec rather than invented — BIP32/BIP39 vectors and real
// mainnet transactions can be checked against an independent implementation,
// so a corpus disagreement points at us rather than at an arbitrary constant.
//
// NEVER regenerate these values from the library under test. They are inputs.

/* eslint-disable max-len */

// --- Keys -------------------------------------------------------------------
// Well-known throwaway keys. Not funded, not secret, and deliberately spanning
// both compression flags and both networks.
const KEYS = {
  // 32 x 0x01 — the canonical "smallest interesting" secret.
  oneWIFCompressed: 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
  oneWIFUncompressed: '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf',
  oneHex: '0000000000000000000000000000000000000000000000000000000000000001',

  mainnetCompressed: 'L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy',
  mainnetCompressed2: 'KwF9LjRraetZuEjR8VqEq539z137LW5anYDUnVK11vM3mNMHTWb4',
  mainnetUncompressed: '5JxgQaFM1FMd38cd14e3mbdxsdSa9iM2BV6DHBYsvGzxkTNQ7Un',
  testnetCompressed: 'cSdkPxkAjA4HDr5VHgsebAPDEh9Gyub4HK8UJr2DFGGqKKy4K5sG',

  // Highest valid secret: n - 1.
  maxValidHex: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
  // Invalid: equal to the curve order n, and zero. Both must be rejected.
  orderHex: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  zeroHex: '0000000000000000000000000000000000000000000000000000000000000000'
}

// --- BIP32 ------------------------------------------------------------------
// Seeds from BIP32's published test vectors 1, 2 and 3. Vector 3 exists
// specifically to catch implementations that trim leading zeros in a derived
// key — a real historical bug class, so it earns its place here.
const BIP32 = {
  seed1: '000102030405060708090a0b0c0d0e0f',
  seed2: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
  seed3: '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
  // Paths exercising both hardened and non-hardened derivation, and the
  // 0x80000000 boundary.
  paths: [
    'm',
    "m/0'",
    "m/0'/1",
    "m/0'/1/2'",
    "m/0'/1/2'/2",
    "m/0'/1/2'/2/1000000000",
    'm/0',
    'm/2147483647',
    "m/2147483647'"
  ],
  // A published xprv/xpub pair (BIP32 vector 1, chain m).
  xprv: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
  xpub: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
}

// --- BIP39 ------------------------------------------------------------------
// From the Trezor BIP39 reference vectors (passphrase "TREZOR").
const BIP39 = {
  passphrase: 'TREZOR',
  entries: [
    {
      entropy: '00000000000000000000000000000000',
      mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      seed: 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'
    },
    {
      entropy: '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f',
      mnemonic: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
      seed: '2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607'
    },
    {
      entropy: '80808080808080808080808080808080',
      mnemonic: 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
      seed: 'd71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8'
    },
    {
      entropy: 'ffffffffffffffffffffffffffffffff',
      mnemonic: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
      seed: 'ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069'
    },
    {
      entropy: '000000000000000000000000000000000000000000000000',
      mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent',
      seed: '035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa'
    },
    {
      entropy: '0000000000000000000000000000000000000000000000000000000000000000',
      mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art',
      seed: 'bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8'
    }
  ]
}

// --- Transactions -----------------------------------------------------------
// Real mainnet transactions, verified to round-trip through this library.
const TXS = {
  // Coinbase with an OP_RETURN-style push in the scriptSig; version 2.
  coinbaseV2: '02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2e039b1e1304c0737c5b68747470733a2f2f6769746875622e636f6d2f62636578742f01000001c096020000000000ffffffff014a355009000000001976a91448b20e254c0677e760bab964aec16818d6b7134a88ac00000000',
  // Block 1 coinbase — pay-to-pubkey, the oldest output form.
  block1Coinbase: '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000',
  // Standard signed P2PKH spend — exercises DER signature parsing on input.
  p2pkhSpend: '01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000006a473044022013fa3089327b50263029265572ae1b022a91d10ac80eb4f32f291c914533670b02200d8a5ed5f62634a7e1a0dc9188a3cc460a986267ae4d58faf50c79105431327501210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5effffffff0150690f00000000001976a9147821c0a3768aa9d1a37e16cf76002aef5373f1a888ac00000000'
}

// --- Scripts ----------------------------------------------------------------
const SCRIPTS = {
  p2pkh: '76a91448b20e254c0677e760bab964aec16818d6b7134a88ac',
  p2sh: 'a914e8c300c87986efa94c37c0519929019ef86eb5b487',
  p2pk: '410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac',
  opReturn: '006a0568656c6c6f',
  multisig: '52210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5e210496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee52ae',
  empty: '',
  // Push-opcode boundaries: OP_PUSHDATA1/2/4 thresholds are a classic
  // off-by-one site in script serializers.
  asm: [
    'OP_0',
    'OP_1 OP_2 OP_ADD OP_3 OP_EQUAL',
    'OP_DUP OP_HASH160 48b20e254c0677e760bab964aec16818d6b7134a OP_EQUALVERIFY OP_CHECKSIG',
    'OP_RETURN 68656c6c6f',
    'OP_1NEGATE',
    'OP_16'
  ]
}

// --- Byte-string edge cases -------------------------------------------------
const BUFFERS = {
  empty: '',
  one: '00',
  ff: 'ff',
  // Varint size boundaries: 0xfc/0xfd, 0xffff/0x10000, 0xffffffff/0x100000000.
  varintBoundaries: [0, 1, 252, 253, 254, 65535, 65536, 4294967295, 4294967296],
  hello: '68656c6c6f',
  // 520 bytes — the classic MAX_SCRIPT_ELEMENT_SIZE boundary.
  long520: 'ab'.repeat(520),
  long521: 'ab'.repeat(521)
}

// --- Addresses --------------------------------------------------------------
const ADDRESSES = {
  mainnetP2PKH: '17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem',
  mainnetP2SH: '3NukJ6fYZJ5Kk8bPjycAnruZkE5Q7UW7i8',
  testnetP2PKH: 'mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW',

  // The two most widely published address constants in Bitcoin: the P2PKH
  // addresses for secret key = 1, compressed and uncompressed. Any independent
  // implementation agrees on these, which makes them a strong external anchor
  // for the whole pubkey -> hash160 -> base58check pipeline.
  keyOneCompressed: '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH',
  keyOneUncompressed: '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm',
  // Malformed: last character altered, so the base58check checksum fails.
  badChecksum: '17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhen',
  tooShort: '1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62',
  invalidChars: '17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYh0O'
}

module.exports = { KEYS, BIP32, BIP39, TXS, SCRIPTS, BUFFERS, ADDRESSES }
