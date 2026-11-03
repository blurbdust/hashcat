#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# sha512crypt reference for the bench: the digest bytes the gateware returns at C2H bytes 4.., and
# the values of the algorithm's extra registers.
#
# The algorithm is hashcat's own test oracle (tools/test_modules/lib/shacrypt.py, which m01800.py
# uses), not the core: crypt_bin () gives the $6$ string's last field, and sha512crypt_decode ()
# turns it back into the 64 raw bytes the way module_01800.c's parser does. The unit returns those
# 64 bytes in SHA-512 output order, so hashcat's digest_buf as bytes is the result as it comes.
#
#   ./sha512crypt_ref.py      checks the reference against known hashes (and libc crypt () if present)

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", ".."))

sys.path.insert(0, os.path.join(TREE, "tools", "test_modules"))

from lib import shacrypt

PW_MAX       = 64
RESULT_LEN   = 64
DIGEST_OFF   = 0
DIGEST_BYTES = 16

# A salt and a cost the core takes. A thread finishes one SHA-512 block every 352 cycles at best,
# and a round is one or two blocks, so the bench keeps the rounds low.
SALT   = b"saltstring"
ROUNDS = 20

# The bridge's canary password (CANARY_PW in its bridge, bcrypt's "hcfpga-ztex-canary").
CANARY_PW = b"hcfpga-ztex-canary"[:PW_MAX]

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def _sha512(m):
  return hashlib.sha512(m).digest()

def sha512crypt_decode(b64):
  """The 64 raw bytes of a $6$ hash's last field, as module_01800.c's sha512crypt_decode () does."""
  d = [0] * 64
  v = [ITOA64.index(c) for c in b64]
  i = 0
  for k in range(21):
    l = v[4*k] | (v[4*k+1] << 6) | (v[4*k+2] << 12) | (v[4*k+3] << 18)
    d[i], d[(i + 21) % 63], d[(i + 42) % 63] = (l >> 16) & 0xff, (l >> 8) & 0xff, l & 0xff
    i = (i + 22) % 63
  l = v[84] | (v[85] << 6)
  d[63] = l & 0xff
  return bytes(d)

def sha512crypt(pw, salt, rounds=5000):
  """The $6$ string, as module_01800.c's encoder writes it."""
  r = "" if rounds == 5000 else "rounds=%d$" % rounds
  return "$6$%s%s$%s" % (r, salt.decode("latin-1"), shacrypt.crypt_bin(_sha512, 512, pw, salt, rounds))

def sha512crypt_raw(pw, salt, rounds):
  """The 64 bytes sha512crypt ends with, in SHA-512 output order (hashcat's digest_buf as bytes)."""
  return sha512crypt_decode(shacrypt.crypt_bin(_sha512, 512, pw, salt, rounds))

def sha512crypt_digest(pw, salt, rounds):
  """The DIGEST_BYTES the device returns for pw under salt and rounds, in C2H order."""
  return sha512crypt_raw(pw, salt, rounds)[DIGEST_OFF:DIGEST_OFF + DIGEST_BYTES]

def extra_regs(salt, rounds):
  """The extra registers from 0x3c, in EXTRA_CSRS order, as the bridge's send_config writes them."""
  return [len(salt)]

if __name__ == "__main__":
  # Mode 1800's example hash, the older LiteX port's hash, and John the Ripper's ZTEX format's
  # vectors at the device's limits (salt 1 and 16, keys of 48 and 56 bytes).
  known = [
    (b"hashcat", b"72820166", 5000,
     "$6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wVl0jRFX40/KnYVvK4829kD1"),
    (b"hashcat", b"qdMgClgO2dQWB37F", 5000,
     "$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacxFkwWLDZ0ViF8Ur3WcHashcatVp2WShcEILi8QZCbt/"),
    (b"sha512crypt-ztex test #1 (salt=16,key_len=48) ..", b"salt_length_is16", 1000,
     "$6$rounds=1000$salt_length_is16$qwDPvfL2spXBiDQOmqNOLJn6JNTPbQg"
     "UYa2RtxIKDDAR9m3Cso.AtkXb2iksEP7PLEBuPVD8wIMwGpFPEMieH/"),
    (b"sha512crypt-ztex test #3 (salt_len=1, A0>200) .z", b"1", 1001,
     "$6$rounds=1001$1$lZlt6XW1lySUVFdntw7D/iZNZ7yOKpFVkIBnZyj2Mt85lr"
     "V34Hjk6tr1J8FAw2N5gk5ceJfv3wG6fzQTWpT/h0"),
    (b"sha512crypt-ztex test #4 (salt_len=16, key_len=56) .....", b"1234567890aBcdef", 1013,
     "$6$rounds=1013$1234567890aBcdef$StfD5z1XXAuXkuUWkV3EMaG/y1Gp46u"
     "keHLcCoXl7ANC1.h4AeP.RJW5Mui4Ngh50cVMe1AoL2pr0gCo71HXo1"),
  ]
  for pw, salt, rounds, want in known:
    got = sha512crypt(pw, salt, rounds)
    assert got == want, (got, want)
    assert sha512crypt_decode(want.rsplit("$", 1)[1]) == sha512crypt_raw(pw, salt, rounds)

  # libc's crypt () as a second, independent oracle (it clamps rounds to 1000..999999999, so 1000).
  try:
    import warnings
    warnings.simplefilter("ignore", DeprecationWarning)
    import crypt
  except ImportError:
    crypt = None
  if crypt is not None:
    for pw, salt in ((b"hashcat", b"saltstring"), (CANARY_PW, b"x"), (b"a" * 64, b"0123456789abcdef")):
      libc = crypt.crypt(pw.decode(), "$6$rounds=1000$%s" % salt.decode())
      assert libc == sha512crypt(pw, salt, 1000), (libc, sha512crypt(pw, salt, 1000))
  print("sha512crypt_ref: OK" + (" (libc crypt () agrees)" if crypt is not None else ""))
