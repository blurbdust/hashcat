#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# descrypt reference for the bench: the digest bytes the gateware returns at C2H bytes 4.., and
# the values of the algorithm's extra registers (none).
#
# crypt(3)'s traditional DES, written from the DES tables, not from the core: the key is the low 7
# bits of each of up to 8 password bytes, the 12-bit salt swaps E-box bits, and the zero block is
# encrypted 25 times. hashcat does not keep the 13-character string: module_01500.c's parser
# base64-decodes the 11 hash characters into the 8 output bytes, loads them as two little-endian
# words and applies DES_IP. That pair, digest_buf[0..1], is what the device returns, little-endian,
# at C2H bytes 4..11.
#
#   ./descrypt_ref.py      checks the reference against known hashes and libc's crypt ()

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", ".."))

PW_MAX       = 8
RESULT_LEN   = 8
DIGEST_OFF   = 0
DIGEST_BYTES = 8

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def salt_buf(chars):
  """hashcat's salt_buf[0] for a 2-character salt, as bytes: the 12-bit salt, then the characters."""
  s = ITOA64.index(chars[0]) | (ITOA64.index(chars[1]) << 6)
  return bytes([s & 0xff, s >> 8, ord(chars[0]), ord(chars[1])])

# A salt (mode 1500's example hash's) and the count, which is crypt(3)'s 25 and fixed in the core.
SALT   = salt_buf("24")
ROUNDS = 25

# The bridge's canary password (hcfpga_algo_t.canary_pw): the default cut to 8 bytes.
CANARY_PW = b"hcfpga-ztex-canary"[:PW_MAX]

# DES tables, FIPS 46 numbering (bit 1 is the most significant).

PC1 = [57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35, 27, 19, 11,  3,
       60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37,
       29, 21, 13,  5, 28, 20, 12,  4]

PC2 = [14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10, 23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

E = [32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1]

P = [16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
      2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25]

FP = [40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30,
      37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
      34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25]

SBOX = [
  [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
   4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
   0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
   13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
   10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
   4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
   9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
   1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
   7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]

def _bits(v, n):
  """v as a list of n bits, most significant first (FIPS bit 1 first)."""
  return [(v >> (n - 1 - i)) & 1 for i in range(n)]

def _val(bits):
  v = 0
  for b in bits:
    v = (v << 1) | b
  return v

def des_crypt_block(pw, salt12):
  """crypt(3)'s 64-bit output block (after the final permutation) for pw and the 12-bit salt."""
  key = bytearray(8)
  for i, c in enumerate(pw[:8]):
    key[i] = ((c & 0x7f) << 1) & 0xff
  kb = _bits(int.from_bytes(bytes(key), "big"), 64)
  cd = [kb[p - 1] for p in PC1]
  c, d = cd[:28], cd[28:]
  subkeys = []
  for s in SHIFTS:
    c = c[s:] + c[:s]
    d = d[s:] + d[:s]
    subkeys.append([(c + d)[p - 1] for p in PC2])
  # The salt: bit i set swaps E-box output bits i and i + 24.
  e = list(E)
  for i in range(12):
    if (salt12 >> i) & 1:
      e[i], e[i + 24] = e[i + 24], e[i]
  # IP of the zero block is zero; between encryptions FP and IP cancel, so only FP at the end.
  l, r = [0] * 32, [0] * 32
  for _ in range(25):
    for k in subkeys:
      x = [r[p - 1] ^ kbit for p, kbit in zip(e, k)]
      f = []
      for s in range(8):
        six = x[6 * s:6 * s + 6]
        f += _bits(SBOX[s][16 * ((six[0] << 1) | six[5]) + _val(six[1:5])], 4)
      f = [f[p - 1] for p in P]
      l, r = r, [a ^ b for a, b in zip(l, f)]
    l, r = r, l
  pre = l + r
  return _val([pre[p - 1] for p in FP])

def des_crypt(pw, chars):
  """The 13-character crypt(3) string."""
  salt12 = ITOA64.index(chars[0]) | (ITOA64.index(chars[1]) << 6)
  v = des_crypt_block(pw, salt12) << 2
  return chars + "".join(ITOA64[(v >> (60 - 6 * i)) & 0x3f] for i in range(11))

def _perm_op(a, b, n, m):
  t = ((a >> n) ^ b) & m
  return a ^ ((t << n) & 0xffffffff), b ^ t

def des_ip(l, r):
  """hashcat's DES_IP macro (OpenCL/inc_cipher_des.h) on two words."""
  r, l = _perm_op(r, l, 4, 0x0f0f0f0f)
  l, r = _perm_op(l, r, 16, 0x0000ffff)
  r, l = _perm_op(r, l, 2, 0x33333333)
  l, r = _perm_op(l, r, 8, 0x00ff00ff)
  r, l = _perm_op(r, l, 1, 0x55555555)
  return l, r

def hash_decode(h):
  """module_01500.c's module_hash_decode: digest_buf[0..1] of a 13-character hash."""
  v = [ITOA64.index(ch) for ch in h[2:13]] + [0]
  out = bytearray()
  for i in range(0, 12, 4):
    f = v[i:i + 4]
    out += bytes([((f[0] << 2) & 0xfc) | (f[1] >> 4), ((f[1] << 4) & 0xf0) | (f[2] >> 2), ((f[2] << 6) & 0xc0) | f[3]])
  return des_ip(int.from_bytes(out[0:4], "little"), int.from_bytes(out[4:8], "little"))

def descrypt_digest(pw, salt, rounds=ROUNDS):
  """The DIGEST_BYTES the device returns for pw under salt (hashcat's salt_buf bytes; only the
  12-bit salt in bytes 0..1 counts), in C2H order. rounds is crypt(3)'s 25 and is not used."""
  salt12 = (salt[0] | (salt[1] << 8)) & 0xfff
  chars = ITOA64[salt12 & 0x3f] + ITOA64[salt12 >> 6]
  d0, d1 = hash_decode(des_crypt(pw, chars))
  return d0.to_bytes(4, "little") + d1.to_bytes(4, "little")

def extra_regs(salt, rounds):
  """The extra registers from 0x3c, in EXTRA_CSRS order: descrypt has none."""
  return []

if __name__ == "__main__":
  # Mode 1500's example hash and John the Ripper's ZTEX format's vectors (src/ztex_descrypt.c).
  known = [
    (b"hashcat", "24leDr0hHfb3A"), (b"U*U*U*U*", "CCNf8Sbh3HDfQ"), (b"U*U***U", "CCX.K.MFy4Ois"),
    (b"U*U***U*", "CC4rMpbg9AMZ."), (b"*U*U*U*U", "XXxzOu6maQKqQ"), (b"", "SDbsugeBiC58A"),
    (b"12345678", "wH6YCxz1hfT9g"), (b"1", "6ZPJCnzzwFT46"), (b"", "..X8NBuQ4l6uQ"),
    (b"########", "bbc1MMnm9AB52"), (b"00000000", "..4Xmrg11Z3jU"), (b"-/<0S]", "////////FevBg"),
    (b"i*]cYae", "///.......Lb2"), (b"#?Ez|?r", "//..////..8/c"), (b"==*d2{^6", "35LSBeq/uVetI"),
  ]
  for pw, want in known:
    got = des_crypt(pw, want[:2])
    assert got == want, (pw, got, want)

  # libc's crypt () as a second oracle (hashcat's own, tools/test_modules/lib/libcrypt.py).
  sys.path.insert(0, os.path.join(TREE, "tools", "test_modules"))
  try:
    from lib import libcrypt
  except (ImportError, OSError):
    libcrypt = None
  if libcrypt is not None:
    import random
    rng = random.Random(1)
    for _ in range(200):
      pw = bytes(rng.randrange(0x20, 0x7f) for _ in range(rng.randrange(0, 9)))
      chars = rng.choice(ITOA64) + rng.choice(ITOA64)
      assert libcrypt.crypt(pw.decode(), chars) == des_crypt(pw, chars), pw

  # Bytes above 0x7f lose their top bit, as in crypt(3).
  assert des_crypt(b"\xe8\xe1\xf3\xe8\xe3\xe1\xf4", "24") == "24leDr0hHfb3A"

  # The example hash decoded as module_01500 does (DES_IP of the base64-decoded block).
  assert descrypt_digest(b"hashcat", SALT) == bytes.fromhex("ee6416f5ad2baa65")

  print("descrypt_ref: OK" + (" (libc crypt () agrees)" if libcrypt is not None else ""))
