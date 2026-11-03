#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# md5crypt reference for the md5crypt benches and tools: the raw 16-byte result as the gateware
# returns it, and the $1$ string as hashcat prints it.

import hashlib

ITOA64 = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def md5crypt_raw(pw, salt, rounds=1000, magic=b"$1$"):
  """The 16 bytes md5crypt ends with, in MD5 output order (hashcat's digest_buf as bytes)."""
  alt = hashlib.md5(pw + salt + pw).digest()

  ctx = pw + magic + salt

  n = len(pw)
  while n > 0:
    ctx += alt[:min(16, n)]
    n -= 16

  i = len(pw)
  while i:
    ctx += b"\x00" if (i & 1) else pw[:1]
    i >>= 1

  final = hashlib.md5(ctx).digest()

  for i in range(rounds):
    c = pw if (i & 1) else final
    if i % 3: c += salt
    if i % 7: c += pw
    c += final if (i & 1) else pw
    final = hashlib.md5(c).digest()

  return final

def md5crypt_encode(d):
  """The 22 characters after the salt, as module_00500.c's md5crypt_encode writes them."""
  out = b""
  for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
    v = (d[a] << 16) | (d[b] << 8) | d[c]
    for _ in range(4):
      out += ITOA64[v & 0x3f:(v & 0x3f) + 1]
      v >>= 6
  v = d[11]
  for _ in range(2):
    out += ITOA64[v & 0x3f:(v & 0x3f) + 1]
    v >>= 6
  return out

def md5crypt(pw, salt, rounds=1000):
  s = b"$1$" if rounds == 1000 else b"$1$rounds=%d$" % rounds
  return s + salt + b"$" + md5crypt_encode(md5crypt_raw(pw, salt, rounds))

def md5crypt_decode(h22):
  """Inverse of md5crypt_encode."""
  d = [0] * 16
  vals = [ITOA64.index(c) for c in h22]
  for k, (a, b, c) in enumerate(((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5))):
    v = vals[4*k] | (vals[4*k+1] << 6) | (vals[4*k+2] << 12) | (vals[4*k+3] << 18)
    d[a], d[b], d[c] = (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff
  d[11] = (vals[20] | (vals[21] << 6)) & 0xff
  return bytes(d)

if __name__ == "__main__":
  for pw, salt, want in ((b"hashcat", b"ehAsHC4t", b"$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1"),
                         (b"hashcat", b"38652870", b"$1$38652870$DUjsu4TTlTsOe/xxZ05uf/"),
                         (b"key_len=64.....567890123456789012345678901234567890123456789abcd", b"abcd0000",
                          b"$1$abcd0000$nNTpR9XboutDDILjNSXMC/")):
    got = md5crypt(pw, salt)
    assert got == want, (got, want)
    assert md5crypt_decode(want.split(b"$")[3]) == md5crypt_raw(pw, salt)
  print("md5crypt_ref: OK")
