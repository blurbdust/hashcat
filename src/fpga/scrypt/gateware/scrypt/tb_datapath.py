#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# scrypt's datapath bench: the shared bench (src/fpga/common/hcfpga_bench.py, rtl/tb_hcfpga.v)
# around hcfpga_scrypt_top (tb_dut.vh), each batch checked against scrypt_ref.py: every
# returned digest, the records the comparator should and should not let through, the retired
# count, the end-of-batch record and the frame status.
#
#   ./tb_datapath.py                      all cases
#   ./tb_datapath.py --case lengths       one case
#   ./tb_datapath.py --case cycles        cycles of one candidate at N = 1024, 16384 and r = 1, R_MAX
#   ./tb_datapath.py --case example       mode 8900's example hash (N = 16384, r = 8)
#   ./tb_datapath.py --r-max 1 --n-log2-max 10    another build (each has its own directory)
#   SIM_WORK=<dir> ./tb_datapath.py       where to build (default ../../build/tb_datapath)

import argparse
import base64
import os
import random
import shutil
import struct
import sys
import time

sys.dont_write_bytecode = True

HERE   = os.path.dirname(os.path.abspath(__file__))
COMMON = os.path.join(HERE, "..", "..", "..", "common")

sys.path.insert(0, HERE)
sys.path.insert(0, COMMON)

import hcfpga_bench as hb

from scrypt_ref import scrypt_digest, PW_MAX, DIGEST_BYTES, SALT, SALT_MAX, ROUNDS, N_LOG2_MAX, R_MAX, CANARY_PW, salt_regs, extra_regs

# LiteX-Scrypt's unit and what it instantiates (see PROVENANCE.md), and util/'s FIFO.
CORE = os.path.join(HERE, "scrypt")
UTIL = os.path.join(HERE, "util")

SOURCES = [os.path.join(HERE, f) for f in [
  "hcfpga_scrypt_top.sv", "hcfpga_scrypt_engine.v",
]] + [os.path.join(CORE, f) for f in [
  "scrypt_unit.v", "romix.v", "v_table_bram.v", "blockmix.v", "salsa20_8.v", "pbkdf2_sha256.v", "hmac_sha256.v", "sha256_core.v",
]] + [os.path.join(UTIL, "fifo_sync.v")] + hb.RTL_TAIL + [os.path.join(hb.RTL, "hcfpga_jtr_unit_collect.v")]

INCLUDES = [HERE, CORE, UTIL]

# Mode 8900's example hash: N = 16384, r = 8, p = 1, password "hashcat".
EXAMPLE = "SCRYPT:16384:8:1:OTEyNzU0ODg=:Cc8SPjRH1hFQhuIPCdF51uNGtJ2aOY/isuoMlMUsJ8c="

def build_params(work, n_log2_max, r_max):
  """The top's build parameters, as tb_dut.vh includes them; rewritten only when they change."""
  path = os.path.join(work, "tb_scrypt_build.vh")
  text = "`define TB_SCRYPT_N_LOG2_MAX %d\n`define TB_SCRYPT_R_MAX %d\n" % (n_log2_max, r_max)
  os.makedirs(work, exist_ok=True)
  if not os.path.isfile(path) or open(path).read() != text:
    with open(path, "w") as f:
      f.write(text)

def run_batch(exe, work, salt, rounds, cands, bitmap, gaps=1, pad_recs=1, r=1):
  return hb.run_batch(exe, work, salt_regs(salt), rounds, cands, bitmap, gaps=gaps, pad_recs=pad_recs,
                      extra=extra_regs(salt, rounds, r))

def check(name, salt, rounds, cands, bitmap_idx, recs, done, errs, pad, pad_recs=1, r=1):
  want = {cid: scrypt_digest(pw, salt, rounds, r) for cid, pw in cands}
  return hb.check(name, cands, want, bitmap_idx, recs, done, errs, pad, pad_recs=pad_recs,
                  digest_bytes=DIGEST_BYTES, core_name="units")

def main():
  ap = argparse.ArgumentParser(description="scrypt datapath bench")
  ap.add_argument("--case", default="all")
  ap.add_argument("--units", type=int, default=2)
  ap.add_argument("--rounds", type=int, default=ROUNDS)
  ap.add_argument("--n-log2-max", type=int, default=N_LOG2_MAX, help="the build's N_LOG2_MAX")
  ap.add_argument("--r-max", type=int, default=R_MAX, help="the build's R_MAX")
  ap.add_argument("--rebuild", action="store_true")
  args = ap.parse_args()

  work = os.environ.get("SIM_WORK", os.path.join(HERE, "..", "..", "build", "tb_datapath"))
  work = os.path.abspath(os.path.join(work, "u%d_n%d_r%d" % (args.units, args.n_log2_max, args.r_max)))
  if args.rebuild and os.path.isdir(work):
    shutil.rmtree(work)
  build_params(work, args.n_log2_max, args.r_max)
  exe = hb.build(work, SOURCES, INCLUDES + [work], {"NUM_UNITS": args.units, "WITH_CMP": 1}, HERE)
  print("build: %d units, N_LOG2_MAX %d, R_MAX %d" % (args.units, args.n_log2_max, args.r_max))

  rng = random.Random(7)
  salt = SALT
  R = args.rounds

  def rnd(n):
    return bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))

  def rbin(n):
    return bytes(rng.randrange(256) for _ in range(n))

  results = []

  # The unit takes the key zero filled to 64 bytes (HMAC's own padding), so every length is one
  # class to the core; the intake's word boundaries, PW_MAX, zero and top-bit bytes are the cases.
  if args.case in ("all", "lengths"):
    lens = [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 55, 56, 63, 64]
    cands = [(i, rnd(n)) for i, n in enumerate(lens)]
    cands += [(100 + i, rbin(n)) for i, n in enumerate([1, 13, 64])]
    cands += [(200, b"a\x00b"), (201, b"\x00"), (202, b"hashcat"), (hb.CANARY_ID, CANARY_PW)]
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4)
    results.append(check("lengths", salt, R, cands, None, recs, done, errs, pad))

  # Every salt length the core takes: the expand step's message moves with it, and bytes 16..31
  # come from salt4..7.
  if args.case in ("all", "salts"):
    ok = True
    for n in range(0, SALT_MAX + 1):
      s = rbin(n)
      cands = [(0, b"hashcat"), (1, rnd(9))]
      recs, done, errs, pad = run_batch(exe, work, s, R, cands, [0xffffffff] * 4)
      ok &= check("salt%d" % n, s, R, cands, None, recs, done, errs, pad)
    results.append(ok)

  # The cost at both ends: N = 2, and N = 2^N_LOG2_MAX, the whole V table.
  if args.case in ("all", "costs"):
    for n in (2, 1 << args.n_log2_max):
      cands = [(i, rnd(6 + i)) for i in range(args.units)]
      recs, done, errs, pad = run_batch(exe, work, salt, n, cands, [0xffffffff] * 4)
      results.append(check("n%d" % n, salt, n, cands, None, recs, done, errs, pad))

  # Every r the build takes, each with its own salt length (4 r bytes: PBKDF2's 4 r expand blocks
  # with the message at every length class up to 32), the longest key and the canary.
  if args.case in ("all", "rs"):
    for r in range(1, args.r_max + 1):
      s = rbin(min(4 * r, SALT_MAX))
      cands = [(0, b"hashcat"), (1, rbin(PW_MAX)), (2, rnd(9)), (hb.CANARY_ID, CANARY_PW)]
      recs, done, errs, pad = run_batch(exe, work, s, R, cands, [0xffffffff] * 4, r=r)
      results.append(check("r%d" % r, s, R, cands, None, recs, done, errs, pad, r=r))

  # r = R_MAX at both ends of N, and r = 1 right after it (a unit that ran r = R_MAX runs r = 1).
  if args.case in ("all", "rcosts"):
    for n, r in ((2, args.r_max), (1024, args.r_max), (16, 1)):
      if n > (1 << args.n_log2_max):
        continue
      cands = [(i, rnd(6 + i)) for i in range(args.units)]
      recs, done, errs, pad = run_batch(exe, work, salt, n, cands, [0xffffffff] * 4, r=r)
      results.append(check("n%d_r%d" % (n, r), salt, n, cands, None, recs, done, errs, pad, r=r))

  # Cycles for one candidate on one unit (the batch: intake, the unit, the collector, EOB).
  if args.case == "cycles":
    for n in (1024, 16384):
      for r in (1, args.r_max):
        if n > (1 << args.n_log2_max):
          continue
        t0 = time.time()
        cands = [(0, b"hashcat")]
        recs, done, errs, pad = run_batch(exe, work, salt, n, cands, [0xffffffff] * 4, r=r)
        results.append(check("n%d_r%d" % (n, r), salt, n, cands, None, recs, done, errs, pad, r=r))
        print("           N = %d, r = %d: %s cycles, %.1f s" % (n, r, done[2] if done else "?", time.time() - t0))

  # Mode 8900's example hash: the device's 16 bytes against the hash's key, and the time it takes.
  if args.case == "example":
    f = EXAMPLE.split(":")
    n, r, s, key = int(f[1]), int(f[2]), base64.b64decode(f[4]), base64.b64decode(f[5])
    t0 = time.time()
    cands = [(0, b"hashcat")]
    recs, done, errs, pad = run_batch(exe, work, s, n, cands, [0xffffffff] * 4, r=r)
    results.append(check("example", s, n, cands, None, recs, done, errs, pad, r=r))
    got = [x[4:4 + DIGEST_BYTES] for x in recs if struct.unpack("<H", x[30:32])[0] == 0]
    print("           key %s, returned %s, %s cycles, %.1f s" % (key[:DIGEST_BYTES].hex(), got[0].hex() if got else "nothing",
                                                              done[2] if done else "?", time.time() - t0))
    results.append(bool(got) and got[0] == key[:DIGEST_BYTES])

  # Several wrong candidates and one right one, the bitmap holding only the target's index:
  # the comparator has to pass the target and drop (but retire) everything that misses.
  if args.case in ("all", "cmp"):
    target = scrypt_digest(b"hashcat", salt, R)
    cands = [(i, rnd(8)) for i in range(29)]
    cands.insert(17, (29, b"hashcat"))
    idx = {hb.cmp_index(target)}
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, hb.bitmap_words(idx))
    results.append(check("cmp", salt, R, cands, idx, recs, done, errs, pad))
    hit = [r for r in recs if struct.unpack("<I", r[0:4])[0] == 29]
    print("           target %s, returned %s" % (target.hex(), hit[0][4:4 + DIGEST_BYTES].hex() if hit else "nothing"))

  # Wrong salt: the same candidates under another salt return nothing that matches the target.
  if args.case in ("all", "salt"):
    target = scrypt_digest(b"hashcat", salt, R)
    cands = [(i, rnd(6)) for i in range(5)] + [(5, b"hashcat")]
    idx = {hb.cmp_index(target)}
    wrong = salt[:-1] + bytes([salt[-1] ^ 1])
    recs, done, errs, pad = run_batch(exe, work, wrong, R, cands, hb.bitmap_words(idx))
    results.append(check("salt", wrong, R, cands, idx, recs, done, errs, pad))
    match = [r for r in recs if r[4:4 + DIGEST_BYTES] == target]
    print("           records matching the right-salt target: %d (want 0)" % len(match))
    results.append(len(match) == 0)

  # Granule padding: EOB records repeat until the record count is a multiple of pad_recs.
  if args.case in ("all", "pad"):
    cands = [(i, rnd(5)) for i in range(3)]
    recs, done, errs, pad = run_batch(exe, work, salt, 8, cands, [0xffffffff] * 4, pad_recs=4)
    results.append(check("pad", salt, 8, cands, None, recs, done, errs, pad, pad_recs=4))

  print("ALL PASS" if all(results) else "*** FAIL ***")
  return 0 if all(results) else 1

if __name__ == "__main__":
  sys.exit(main())
