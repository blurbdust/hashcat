#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# sha256crypt reference for the bench: the digest bytes the gateware returns at C2H bytes 4.., and
# the values of the algorithm's extra registers.
#
# The algorithm is hashcat's own test oracle (tools/test_modules/lib/shacrypt.py, which m07400.py
# uses), not the core: crypt_bin () gives the $5$ string's last field, and sha256crypt_decode ()
# turns it back into the 32 raw bytes the way module_07400.c's parser does. The unit returns those
# 32 bytes in SHA-256 output order, so hashcat's digest_buf as bytes is the result as it comes.
#
#   ./sha256crypt_ref.py      checks the reference against known hashes (and libc crypt () if present)

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", ".."))

sys.path.insert(0, os.path.join(TREE, "tools", "test_modules"))

from lib import shacrypt

PW_MAX       = 32
RESULT_LEN   = 32
DIGEST_OFF   = 0
DIGEST_BYTES = 16

# A salt and a cost the core takes. A thread finishes one SHA-256 block every 288 cycles at best,
# and a round is one or two blocks, so the bench keeps the rounds low.
SALT   = b"saltstring"
ROUNDS = 20

# The bridge's canary password (hcfpga_algo_t.canary_pw, default "hcfpga-ztex-canary").
CANARY_PW = b"hcfpga-ztex-canary"[:PW_MAX]

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def _sha256(m):
  return hashlib.sha256(m).digest()

def sha256crypt_decode(b64):
  """The 32 raw bytes of a $5$ hash's last field, as module_07400.c's sha256crypt_decode () does."""
  d = [0] * 32
  v = [ITOA64.index(c) for c in b64]
  i = 0
  for k in range(10):
    l = v[4*k] | (v[4*k+1] << 6) | (v[4*k+2] << 12) | (v[4*k+3] << 18)
    d[i], d[(i + 10) % 30], d[(i + 20) % 30] = (l >> 16) & 0xff, (l >> 8) & 0xff, l & 0xff
    i = (i + 21) % 30
  l = v[40] | (v[41] << 6) | (v[42] << 12)
  d[31], d[30] = (l >> 8) & 0xff, l & 0xff
  return bytes(d)

def sha256crypt(pw, salt, rounds=5000):
  """The $5$ string, as module_07400.c's encoder writes it."""
  r = "" if rounds == 5000 else "rounds=%d$" % rounds
  return "$5$%s%s$%s" % (r, salt.decode("latin-1"), shacrypt.crypt_bin(_sha256, 256, pw, salt, rounds))

def sha256crypt_raw(pw, salt, rounds):
  """The 32 bytes sha256crypt ends with, in SHA-256 output order (hashcat's digest_buf as bytes)."""
  return sha256crypt_decode(shacrypt.crypt_bin(_sha256, 256, pw, salt, rounds))

def sha256crypt_digest(pw, salt, rounds):
  """The DIGEST_BYTES the device returns for pw under salt and rounds, in C2H order."""
  return sha256crypt_raw(pw, salt, rounds)[DIGEST_OFF:DIGEST_OFF + DIGEST_BYTES]

def extra_regs(salt, rounds):
  """The extra registers from 0x3c, in EXTRA_CSRS order, as the bridge's config_extra writes them."""
  return [len(salt)]

if __name__ == "__main__":
  # Mode 7400's example hash, the older LiteX port's hash, and John the Ripper's ZTEX format's
  # vectors at both ends of the device's limits (salt 1 and 16, key 32).
  known = [
    (b"hashcat",  b"7777657035274252", 5000, "$5$7777657035274252$XftMj84MW.New1/ViLY5V4CM4Y7EBvfETaZsCW9vcJ8"),
    (b"testpw",   b"abcdsalt",         1000, "$5$rounds=1000$abcdsalt$yfziOgfoH86GH0s1Vh6oyLldzpxZYJtVbGO8/BOKLr8"),
    (b"Hello world!", b"saltstring",   5000, "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
    (b"salt1,key11", b"=",             5000, "$5$=$Qh125aRhMbwg8Phe/jIjQwos/v9I.vR/e7R1rjiYfBC"),
    (b"test #3: salt_len=16, key_len=32", b"012/45.7/9ab/def", 5000,
     "$5$012/45.7/9ab/def$wz2Bni8S/YVASQHPTNWPiUd17QwYow5qLbmSUvgZhd1"),
  ]
  for pw, salt, rounds, want in known:
    got = sha256crypt(pw, salt, rounds)
    assert got == want, (got, want)
    assert sha256crypt_decode(want.rsplit("$", 1)[1]) == sha256crypt_raw(pw, salt, rounds)

  # libc's crypt () as a second, independent oracle (it clamps rounds to 1000..999999999, so 1000).
  try:
    import warnings
    warnings.simplefilter("ignore", DeprecationWarning)
    import crypt
  except ImportError:
    crypt = None
  if crypt is not None:
    for pw, salt in ((b"hashcat", b"saltstring"), (CANARY_PW, b"x"), (b"a" * 32, b"0123456789abcdef")):
      libc = crypt.crypt(pw.decode(), "$5$rounds=1000$%s" % salt.decode())
      assert libc == sha256crypt(pw, salt, 1000), (libc, sha256crypt(pw, salt, 1000))
  print("sha256crypt_ref: OK" + (" (libc crypt () agrees)" if crypt is not None else ""))
