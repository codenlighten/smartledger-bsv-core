/**
 * ECIES. The default export is the BIE1 (electrum) implementation, which is
 * the interoperable one; the bitcore format is reachable as `.bitcoreECIES`.
 */
import ECIES = require('./electrum-ecies')

export = ECIES
