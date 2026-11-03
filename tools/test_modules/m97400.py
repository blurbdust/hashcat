#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# sha256crypt computed on an FPGA (fpga_sha256crypt bridge). The oracle is mode 7400's; the constraints
# are the device's. HCFPGA-TODO: module_generate_hash must only produce what the device computes (salt
# lengths, rounds), or test.py feeds the bridge hashes it refuses.

import hashlib

from lib import shacrypt

# sha256crypt $5$, SHA256 (Unix), see lib/shacrypt.py. The perl module used a salt up to 20 bytes and
# did not truncate it, unlike libc crypt which stops at 16, so this hashes the whole salt.


def sha256(data):
  return hashlib.sha256(data).digest()


def module_constraints():
  # HCFPGA-TODO: the device's limits: [pure pw, pure salt, optimized pw, optimized salt, combined].
  return [[0, 32], [1, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  if iterations is None:
    return "$5$%s$%s" % (salt, shacrypt.crypt_bin(sha256, 256, word, salt.encode(), 5000))

  rounds = min(max(int(iterations), 1000), 999999999)

  return "$5$rounds=%d$%s$%s" % (rounds, salt, shacrypt.crypt_bin(sha256, 256, word, salt.encode(), rounds))


def module_verify_hash(line):
  parsed = shacrypt.parse(line, 30)

  if parsed is None:
    return None

  _, salt, rounds, word = parsed

  return (module_generate_hash(word, salt, rounds), word)
