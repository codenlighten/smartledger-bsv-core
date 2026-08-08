import chinese = require('./chinese')
import english = require('./english')
import french = require('./french')
import italian = require('./italian')
import japanese = require('./japanese')
import spanish = require('./spanish')

/** The BIP39 wordlists this library ships. Each is exactly 2048 words. */
const words = {
  CHINESE: chinese,
  ENGLISH: english,
  FRENCH: french,
  ITALIAN: italian,
  JAPANESE: japanese,
  SPANISH: spanish
}

export = words
