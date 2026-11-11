#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# wpa2 reference for the bench: the digest bytes the gateware returns at C2H bytes 4.., and the
# values of the algorithm's extra registers.
#
# The device computes the WPA PMK, PBKDF2-HMAC-SHA1 (passphrase, ESSID, 4096 iterations, 32 bytes),
# as hashcat's tools/test_modules/m22000.py does (_pmk, hashlib.pbkdf2_hmac), and returns its 32
# bytes in order: bytes 0..23 in the first C2H record, 24..31 in the second. Mode 22000's parser
# stores the ESSID as salt_buf (0 to 32 bytes) and 4095 as salt_iter; the count is fixed, so the
# device does not read it.
#
#   ./wpa2_ref.py        checks the reference against mode 22000's example hash and against a
#                        SHA-1 written out here, the way the device computes the PMK

import hashlib
import hmac
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hcfpga_bench as hb

PW_MAX       = 63
RESULT_LEN   = 32
DIGEST_OFF   = 0
DIGEST_BYTES = 32

# C2H records per candidate: digest bytes 24k..24k+23 in record k.
PARTS        = 2

# Candidates in flight in one pipe (the engine's SLOTS; the wrapper's SLOTS_PER_PIPE).
SLOTS        = 42

# The ESSID is 0 to 32 bytes: salt0..3 hold bytes 0..15, salt4..7 bytes 16..31.
SALT_MAX = 32

# A salt that reaches into salt4, and mode 22000's salt_iter.
SALT   = b"hcfpga-wpa2-essid-20"
ROUNDS = 4095

# The bridge's canary password (CANARY_PW in its bridge, bcrypt's "hcfpga-ztex-canary").
CANARY_PW = b"hcfpga-ztex-canary"[:PW_MAX]

def wpa2_pmk(pw, essid):
  """The 32-byte PMK, as m22000.py's _pmk."""
  return hashlib.pbkdf2_hmac("sha1", pw, essid, 4096, 32)

def wpa2_digest(pw, salt, rounds):
  """The DIGEST_BYTES the device returns for pw under salt (the ESSID), in C2H order."""
  assert rounds == ROUNDS, "mode 22000's salt_iter is 4095; the device's count is fixed"
  return wpa2_pmk(pw, salt)[DIGEST_OFF:DIGEST_OFF + DIGEST_BYTES]

def salt_regs(salt):
  """salt0..3, as the bridge writes them: hashcat's salt_buf[0..3], raw bytes."""
  return hb.salt_words(salt[:16])

def extra_regs(salt, rounds):
  """The extra registers from 0x3c, in EXTRA_CSRS order, as the bridge's send_config writes them:
  salt_len, then salt4..7 (salt_buf[4..7], ESSID bytes 16..31)."""
  s = salt.ljust(SALT_MAX, b"\x00")[:SALT_MAX]
  return [len(salt)] + list(struct.unpack("<4I", s[16:32]))

# The device's way: the HMAC setup in SHA-1 compressions, then the PBKDF2 loop on the setup.

IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

def _rol(x, n):
  return ((x << n) | (x >> (32 - n))) & 0xffffffff

def sha1_compress(state, words):
  w = list(words)
  for t in range(16, 80):
    w.append(_rol(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1))
  a, b, c, d, e = state
  for t in range(80):
    if t < 20:
      f, k = (b & c) | (~b & d), 0x5A827999
    elif t < 40:
      f, k = b ^ c ^ d, 0x6ED9EBA1
    elif t < 60:
      f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
    else:
      f, k = b ^ c ^ d, 0xCA62C1D6
    a, b, c, d, e = (_rol(a, 5) + (f & 0xffffffff) + e + k + w[t]) & 0xffffffff, a, _rol(b, 30), c, d
  return tuple((x + y) & 0xffffffff for x, y in zip(state, (a, b, c, d, e)))

def _words(data):
  return list(struct.unpack(">%dI" % (len(data) // 4), data))

def device_pmk(pw, essid):
  k = pw.ljust(64, b"\x00")
  ipad = sha1_compress(IV, _words(bytes(x ^ 0x36 for x in k)))
  opad = sha1_compress(IV, _words(bytes(x ^ 0x5c for x in k)))
  out = b""
  for i in (1, 2):
    m = essid + struct.pack(">I", i)
    inner = sha1_compress(ipad, _words(m + b"\x80" + b"\x00" * (55 - len(m)) + struct.pack(">Q", (64 + len(m)) * 8)))
    u = sha1_compress(opad, list(inner) + [0x80000000] + [0] * 9 + [0x2a0])
    t = list(u)
    for _ in range(4095):
      inner = sha1_compress(ipad, list(u) + [0x80000000] + [0] * 9 + [0x2a0])
      u = sha1_compress(opad, list(inner) + [0x80000000] + [0] * 9 + [0x2a0])
      t = [x ^ y for x, y in zip(t, u)]
    out += struct.pack(">5I", *t)
  return out[:32]

if __name__ == "__main__":
  # Mode 22000's example hash: WPA*01*<PMKID>*<AP MAC>*<STA MAC>*<ESSID hex>, password hashcat!.
  pmk = wpa2_pmk(b"hashcat!", bytes.fromhex("686173686361742d6573736964"))
  pmkid = hmac.new(pmk, b"PMK Name" + bytes.fromhex("fc690c158264") + bytes.fromhex("f4747f87f9f4"), hashlib.sha1).hexdigest()[:32]
  ok = pmkid == "4d4fe7aac3a2cecab195321ceb99a7d0"
  print("example hash PMKID %s %s" % (pmkid, "OK" if ok else "WRONG"))
  for pw, essid in ((b"hashcat!", b"hashcat-essid"), (CANARY_PW, b""), (b"x" * 63, b"y" * 32), (b"\x00\xff" * 4, SALT)):
    same = device_pmk(pw, essid) == wpa2_pmk(pw, essid)
    ok &= same
    print("device way %-22s %-22s %s" % (pw[:20], essid[:20], "OK" if same else "WRONG"))
  sys.exit(0 if ok else 1)
