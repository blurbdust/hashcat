#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# sha512crypt computed on an FPGA (fpga_sha512crypt bridge). The oracle is mode 1800's; the constraints
# are the device's: passwords up to 64 bytes, salts of 1 to 16. The rounds module_generate_hash
# writes (5000, or 1000 to 999999999) are all ones the device computes (1 to 999999999).

import hashlib

from lib import shacrypt

# sha512crypt $6$, SHA512 (Unix), see lib/shacrypt.py. A rounds field is clamped to what the format
# allows, 1000 to 999999999, and printed; without one the count is the default 5000.


def sha512(data):
  return hashlib.sha512(data).digest()


def module_constraints():
  return [[0, 64], [1, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt = salt[:16]

  if iterations is None:
    return "$6$%s$%s" % (salt, shacrypt.crypt_bin(sha512, 512, word, salt.encode(), 5000))

  rounds = min(max(int(iterations), 1000), 999999999)

  return "$6$rounds=%d$%s$%s" % (rounds, salt, shacrypt.crypt_bin(sha512, 512, word, salt.encode(), rounds))


def module_verify_hash(line):
  parsed = shacrypt.parse(line)

  if parsed is None:
    return None

  _, salt, rounds, word = parsed

  return (module_generate_hash(word, salt, rounds), word)
