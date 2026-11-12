#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Reference for the DES known-plaintext engine (hash mode 75700, mode 14000's format): one block of
# DES-ECB, the 8-byte candidate as key, the 8-byte salt as plaintext. Written from the tables of
# FIPS 46-3, not from the gateware or from hashcat's kernels, and checked against OpenSSL by the bench
# and by running this file.
#
# The engine's view of a batch:
#
#   job        one 8-byte base word; the amplifier positions (the first amp_cnt bytes) are zero
#   amplifier  amp_cnt <= AMP_MAX per-position charsets, enumerated by the device: item i takes digit
#              d_p = (i / (len_0 * .. * len_{p-1})) % len_p of position p, the character tab_p[d_p]
#   hit        (job, item, target): the item's key encrypts the plaintext to that target ciphertext.
#              A job reports the first item for each target only.
#
#   ./des_kpa_ref.py     self-check against FIPS 81's example, hashcat's mode 14000 example and OpenSSL

import struct
import subprocess
import sys

AMP_MAX     = 4
NUM_TARGETS = 4

# FIPS 46-3 tables, bit numbers from 1 (the most significant bit of the block).

IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25]

E = [32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
      8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1]

P = [16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
      2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25]

PC1 = [57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
       10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
       14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4]

PC2 = [14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
       23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

SBOX = [
  [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
    0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
    4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
   15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
  [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
   13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
  [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
   13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
   13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
    1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
  [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
   13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
   10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
    3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
  [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
   14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
   11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3],
  [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
   10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
  [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
   13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
    1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
    6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
  [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
    1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
    7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
    2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
]

def permute(v, table, n_in):
  """Output bit i (from 1, most significant first) is input bit table[i - 1] of an n_in-bit value."""
  out = 0
  for t in table:
    out = (out << 1) | ((v >> (n_in - t)) & 1)
  return out

def subkeys(key64):
  cd = permute(key64, PC1, 64)
  c, d = cd >> 28, cd & 0xfffffff
  ks = []
  for s in SHIFTS:
    c = ((c << s) | (c >> (28 - s))) & 0xfffffff
    d = ((d << s) | (d >> (28 - s))) & 0xfffffff
    ks.append(permute((c << 28) | d, PC2, 56))
  return ks

def feistel(r, k):
  x = permute(r, E, 32) ^ k
  s = 0
  for i in range(8):
    six = (x >> (42 - 6 * i)) & 0x3f
    row = ((six >> 4) & 2) | (six & 1)
    col = (six >> 1) & 0xf
    s = (s << 4) | SBOX[i][row * 16 + col]
  return permute(s, P, 32)

def des_encrypt(key, pt):
  """DES-ECB of one 8-byte block."""
  ks = subkeys(int.from_bytes(key, "big"))
  b = permute(int.from_bytes(pt, "big"), IP, 64)
  l, r = b >> 32, b & 0xffffffff
  for k in ks:
    l, r = r, l ^ feistel(r, k)
  return permute((r << 32) | l, FP, 64).to_bytes(8, "big")

def odd_parity(b):
  """The byte with its low bit set so that it has an odd number of ones (charsets/DES_full.hcchr)."""
  hi = b & 0xfe
  return hi | (1 - (bin(hi).count("1") & 1))

# hashcat's view: mode 14000's hash is ct:pt in hex, and the salt words are the plaintext's bytes
# little-endian (hex_to_u32), which is what the bridge writes to salt0/salt1.

def hash_line(key, pt):
  return "%s:%s" % (des_encrypt(key, pt).hex(), pt.hex())

def salt_words(pt):
  return list(struct.unpack("<2I", pt)) + [0, 0]

# The device's amplifier and the jobs it runs over it.

def amp_total(tabs):
  n = 1
  for t in tabs:
    n *= len(t)
  return n

def amp_key(base, tabs, item):
  """The key of amplifier item `item` over base word `base` (the device's order: position 0 fastest)."""
  key = bytearray(base)
  for p, t in enumerate(tabs):
    key[p] = t[item % len(t)]
    item //= len(t)
  return bytes(key)

def job_hits(base, tabs, pt, targets):
  """Every hit the device reports for one job: (item, target index), the first item per target."""
  want = {ct: k for k, ct in enumerate(targets)}
  seen = {}
  for item in range(amp_total(tabs)):
    ct = des_encrypt(amp_key(base, tabs, item), pt)
    k = want.get(ct)
    if (k is not None) and (k not in seen):
      seen[k] = item
  return sorted((item, k) for k, item in seen.items())

def openssl_des(key, pt):
  """The same block through OpenSSL's DES-ECB (OpenSSL 3 keeps DES in its legacy provider)."""
  cmd = ["openssl", "enc", "-des-ecb", "-nopad", "-K", key.hex(), "-provider", "legacy", "-provider", "default"]
  r = subprocess.run(cmd, input=pt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
  return r.stdout[:8]

def selfcheck():
  ok = True
  # FIPS 81's example and mode 14000's own example hash and password.
  vectors = [(bytes.fromhex("0123456789abcdef"), bytes.fromhex("4e6f772069732074"), bytes.fromhex("3fa40e8a984d4815")),
             (bytes.fromhex("133457799bbcdff1"), bytes.fromhex("0123456789abcdef"), bytes.fromhex("85e813540f0ab405")),
             (b"hashcat1",                       bytes.fromhex("1412781058343178"), bytes.fromhex("53b325182924b356"))]
  for key, pt, ct in vectors:
    got = des_encrypt(key, pt)
    print("%s %s -> %s %s" % (key.hex(), pt.hex(), got.hex(), "ok" if got == ct else "WANT " + ct.hex()))
    ok &= (got == ct)
  # Parity bits do not reach DES: flipping every low bit leaves the block unchanged.
  key, pt = b"hashcat1", bytes.fromhex("1412781058343178")
  flip = bytes(b ^ 1 for b in key)
  ok &= (des_encrypt(flip, pt) == des_encrypt(key, pt))
  # OpenSSL agrees on random blocks.
  import random
  rng = random.Random(1)
  for _ in range(32):
    key = bytes(rng.randrange(256) for _ in range(8))
    pt  = bytes(rng.randrange(256) for _ in range(8))
    if des_encrypt(key, pt) != openssl_des(key, pt):
      print("OpenSSL disagrees on %s %s" % (key.hex(), pt.hex()))
      ok = False
  print("32 random blocks vs OpenSSL %s" % ("ok" if ok else "FAIL"))
  return ok

if __name__ == "__main__":
  sys.exit(0 if selfcheck() else 1)
