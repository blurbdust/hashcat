#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# descrypt's datapath bench: the shared bench (hcfpga_bench.py, tb_hcfpga.v)
# around hcfpga_descrypt_top (tb_dut.vh), each batch checked against descrypt_ref.py: every
# returned digest, the records the comparator should and should not let through, the retired
# count, the end-of-batch record and the frame status.
#
#   ./tb_datapath.py                      all cases
#   ./tb_datapath.py --case lengths       one case
#   SIM_WORK=<dir> ./tb_datapath.py       where to build (default ../../build/tb_datapath)

import argparse
import os
import random
import shutil
import struct
import sys

sys.dont_write_bytecode = True

HERE   = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)

import hcfpga_bench as hb

from descrypt_ref import descrypt_digest, salt_buf, PW_MAX, DIGEST_BYTES, SALT, ROUNDS, CANARY_PW, extra_regs

CORE = os.path.join(HERE, "descrypt_core")

# The top, the engine, and John the Ripper's DES pipeline and key preparation.
SOURCES = [os.path.join(HERE, f) for f in [
  "hcfpga_descrypt_top.sv", "hcfpga_descrypt_engine.v",
]] + hb.RTL_TAIL + [os.path.join(CORE, f) for f in [
  "descrypt16.v", "descrypt_round.v", "rotate_1or2_pc2.v", "des_loop.v", "Eblock.v", "SP_v2.v", "IP1.v",
  "crypt3_ascii2bin.v", "pc1.v",
]]

INCLUDES = [HERE, CORE]

def run_batch(exe, work, salt, rounds, cands, bitmap, gaps=1, pad_recs=1):
  return hb.run_batch(exe, work, hb.salt_words(salt), rounds, cands, bitmap, gaps=gaps, pad_recs=pad_recs,
                      extra=extra_regs(salt, rounds))

def check(name, salt, rounds, cands, bitmap_idx, recs, done, errs, pad, pad_recs=1):
  want = {cid: descrypt_digest(pw, salt, rounds) for cid, pw in cands}
  return hb.check(name, cands, want, bitmap_idx, recs, done, errs, pad, pad_recs=pad_recs,
                  digest_bytes=DIGEST_BYTES, core_name="cores")

def main():
  ap = argparse.ArgumentParser(description="descrypt datapath bench")
  ap.add_argument("--case", default="all")
  ap.add_argument("--units", type=int, default=2)
  ap.add_argument("--rounds", type=int, default=ROUNDS)
  ap.add_argument("--rebuild", action="store_true")
  args = ap.parse_args()

  work = os.environ.get("SIM_WORK", os.path.join(HERE, "..", "..", "build", "tb_datapath"))
  work = os.path.abspath(os.path.join(work, "u%d" % args.units))
  if args.rebuild and os.path.isdir(work):
    shutil.rmtree(work)
  exe = hb.build(work, SOURCES, INCLUDES, {"NUM_UNITS": args.units, "WITH_CMP": 1}, HERE)

  rng = random.Random(7)
  salt = SALT
  R = args.rounds

  def rnd(n):
    return bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))

  results = []

  # Every key length 0..8 (DES takes 8 bytes and nothing branches on the length), bytes with the
  # top bit set (dropped, as crypt(3) drops it), a zero byte inside a key, and the canary.
  if args.case in ("all", "lengths"):
    cands = [(i, rnd(n)) for i, n in enumerate(range(PW_MAX + 1))]
    cands += [(9, b"hashcat"), (10, b"\xe8\xe1\xf3\xe8\xe3\xe1\xf4"), (11, b"a\x00b\x80c"),
              (12, bytes(range(0x80, 0x88))), (13, b"\xff" * 8), (hb.CANARY_ID, CANARY_PW)]
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4)
    results.append(check("lengths", salt, R, cands, None, recs, done, errs, pad))

  # More candidates than the rings hold at once: full rings of 16 on every core, both result banks
  # of each core in use, and a short last ring.
  if args.case in ("all", "rings"):
    cands = [(i, rnd(rng.randrange(0, PW_MAX + 1))) for i in range(16 * 4 * args.units + 5)]
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4)
    results.append(check("rings", salt, R, cands, None, recs, done, errs, pad))

  # The 12-bit salt at both ends and in between, one batch each.
  if args.case in ("all", "salts"):
    for chars in ["..", "zz", "./", "/.", "Az", "24"]:
      s = salt_buf(chars)
      cands = [(i, rnd(rng.randrange(0, PW_MAX + 1))) for i in range(5)] + [(5, b"hashcat")]
      recs, done, errs, pad = run_batch(exe, work, s, R, cands, [0xffffffff] * 4)
      results.append(check("salt " + chars, s, R, cands, None, recs, done, errs, pad))

  # Several wrong candidates and one right one, the bitmap holding only the target's index:
  # the comparator has to pass the target and drop (but retire) everything that misses.
  if args.case in ("all", "cmp"):
    target = descrypt_digest(b"hashcat", salt, R)
    cands = [(i, rnd(8)) for i in range(29)]
    cands.insert(17, (29, b"hashcat"))
    idx = {hb.cmp_index(target)}
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, hb.bitmap_words(idx))
    results.append(check("cmp", salt, R, cands, idx, recs, done, errs, pad))
    hit = [r for r in recs if struct.unpack("<I", r[0:4])[0] == 29]
    print("           target %s, returned %s" % (target.hex(), hit[0][4:4 + DIGEST_BYTES].hex() if hit else "nothing"))

  # Wrong salt: the same candidates under another 12-bit salt return nothing that matches the
  # target. The salt characters in bytes 2..3 do not reach the core, so the change is in byte 0.
  if args.case in ("all", "salt"):
    target = descrypt_digest(b"hashcat", salt, R)
    cands = [(i, rnd(6)) for i in range(5)] + [(5, b"hashcat")]
    idx = {hb.cmp_index(target)}
    wrong = bytes([salt[0] ^ 1]) + salt[1:]
    recs, done, errs, pad = run_batch(exe, work, wrong, R, cands, hb.bitmap_words(idx))
    results.append(check("salt", wrong, R, cands, idx, recs, done, errs, pad))
    match = [r for r in recs if r[4:4 + DIGEST_BYTES] == target]
    print("           records matching the right-salt target: %d (want 0)" % len(match))
    results.append(len(match) == 0)

  # Granule padding: EOB records repeat until the record count is a multiple of pad_recs.
  if args.case in ("all", "pad"):
    cands = [(i, rnd(5)) for i in range(3)]
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4, pad_recs=4)
    results.append(check("pad", salt, R, cands, None, recs, done, errs, pad, pad_recs=4))

  print("ALL PASS" if all(results) else "*** FAIL ***")
  return 0 if all(results) else 1

if __name__ == "__main__":
  sys.exit(main())
