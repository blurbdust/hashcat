#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# scrypt reference for the bench: the digest bytes the gateware returns at C2H bytes 4.., and the
# values of the algorithm's extra registers.
#
# The device computes scrypt with r = 1 and p = 1 (the unit's PBKDF2 is built for 128-byte blocks),
# N a power of two from 2 to 2^N_LOG2_MAX, a key of at most 64 bytes and a salt of at most 32, and
# returns the first 16 bytes of the 32-byte derived key in order. The algorithm is Python's
# hashlib.scrypt, as hashcat's tools/test_modules/m08900.py uses it; mode 8900's parser stores the
# base64-decoded key as digest_buf, so these bytes are hashcat's digest_buf words 0..3, little-endian.

import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hcfpga_bench as hb

PW_MAX       = 64
RESULT_LEN   = 32
DIGEST_OFF   = 0
DIGEST_BYTES = 16

SALT_MAX   = 32
N_LOG2_MAX = 15

# A salt that reaches into salt4 (bytes 16..31), and a cost that keeps a bench run short.
SALT   = b"hcfpga-scrypt-salt-20"
ROUNDS = 16

# The bridge's canary password (CANARY_PW in its bridge, bcrypt's "hcfpga-ztex-canary").
CANARY_PW = b"hcfpga-ztex-canary"[:PW_MAX]

def scrypt_dk(pw, salt, n):
  """The 32-byte derived key with r = 1, p = 1."""
  return hashlib.scrypt(pw, salt=salt, n=n, r=1, p=1, dklen=32, maxmem=128 * n * 4 + (1 << 20))

def scrypt_digest(pw, salt, rounds):
  """The DIGEST_BYTES the device returns for pw under salt and rounds (N), in C2H order."""
  return scrypt_dk(pw, salt, rounds)[DIGEST_OFF:DIGEST_OFF + DIGEST_BYTES]

def salt_regs(salt):
  """salt0..3, as the bridge writes them: hashcat's salt_buf[0..3], raw bytes."""
  return hb.salt_words(salt[:16])

def extra_regs(salt, rounds):
  """The extra registers from 0x3c, in EXTRA_CSRS order, as the bridge's send_config writes them:
  salt_len, then salt4..7 (salt_buf[4..7], bytes 16..31)."""
  s = salt.ljust(SALT_MAX, b"\x00")[:SALT_MAX]
  return [len(salt)] + list(struct.unpack("<4I", s[16:32]))
