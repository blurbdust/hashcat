#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import md5crypt, shacrypt

# md5crypt computed on an FPGA (fpga_md5crypt bridge). The oracle is mode 500's; the constraints
# are the device's: passwords up to 64 bytes, salts of 1 to 8.


def module_constraints():
  return [[0, 64], [1, 8], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  rounds = 1000

  if iterations is not None and int(iterations) > 0:
    rounds = int(iterations)

  return md5crypt.md5_crypt(b"$1$", rounds, word, salt.encode("latin-1"))


def module_verify_hash(line):
  parsed = shacrypt.parse(line)

  if parsed is None:
    return None

  _, salt, rounds, word = parsed

  return (module_generate_hash(word, salt, rounds), word)
