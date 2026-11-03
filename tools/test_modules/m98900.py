#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# scrypt computed on an FPGA (fpga_scrypt bridge). The oracle is mode 8900's; the constraints
# are the device's: passwords up to 64 bytes, and module_generate_hash makes only what the device
# computes, p = 1 and r from 1 to 8, with N = 16 by default so that a run on a 1 MHz simulated board
# stays short (the device takes N from 2 to 32768). Unless given, r follows the salt's length
# (1 + length mod 8), so a multi-hash run has salts of different r.

import base64
import binascii
import hashlib

# scrypt: SCRYPT:N:r:p:base64(salt):base64(key).


def module_constraints():
  # [pure pw, pure salt, optimized pw, optimized salt, combined]. The salt entry is mode 8900's: salt
  # strings of 1 to 15 characters, latin-1, so 1 to 15 bytes, inside the device's 0 to 32.
  return [[0, 64], [1, 15], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, n=16, r=None, p=1):
  salt_bytes = salt.encode("latin-1")

  if r is None:
    r = 1 + len(salt_bytes) % 8

  # OpenSSL wants some room beyond the V table, which matters at small N.
  key = hashlib.scrypt(word, salt=salt_bytes, n=n, r=r, p=p, dklen=32, maxmem=(128 * n * r * 2) + (1 << 20))

  return "SCRYPT:%d:%d:%d:%s:%s" % (n, r, p, base64.b64encode(salt_bytes).decode(), base64.b64encode(key).decode())


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  fields = hash_in.split(":")

  if len(fields) != 6 or fields[0] != "SCRYPT":
    return None

  try:
    n, r, p = int(fields[1]), int(fields[2]), int(fields[3])
    salt = base64.b64decode(fields[4]).decode("latin-1")
  except (ValueError, binascii.Error):
    return None

  return (module_generate_hash(word, salt, None, n, r, p), word)
