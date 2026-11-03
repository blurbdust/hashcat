#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# md5crypt's datapath bench: the shared bench (src/fpga/common/hcfpga_bench.py, rtl/tb_hcfpga.v)
# around hcfpga_md5crypt_top (tb_dut.vh), each batch checked against md5crypt_ref.py: every returned
# digest, the records the comparator should and should not let through, the retired count, the
# end-of-batch record and the frame status.
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
COMMON = os.path.join(HERE, "..", "..", "..", "common")

sys.path.insert(0, HERE)
sys.path.insert(0, COMMON)

import hcfpga_bench as hb

from md5crypt_ref import md5crypt_raw

CANARY_ID = hb.CANARY_ID

SOURCES = [os.path.join(HERE, f) for f in [
  "hcfpga_md5crypt_top.sv",
  "md5unit.v", "unit_ctrl.v", "core_ctrl.v", "unit_input_async.v", "uob16pq.v",
  "cpu/cpu.v", "cpu/cpu_flags.v", "cpu/cpu_state.v", "cpu/ff16.v", "cpu/instruction.v",
  "cpu/integer_ops.v", "cpu/registers_bram.v", "cpu/thread_number.v",
  "md5core/add3.v", "md5core/add3_unreg.v", "md5core/ff32.v", "md5core/md5core.v",
  "md5core/md5core_type1.v", "md5core/md5core_type2.v", "md5core/md5_Kt_bram.v", "md5core/md5_Kt_dram.v",
  "md5core/shreg.v", "md5core/shreg_ff.v",
  "md5engine/core_input.v", "md5engine/create_blk.v", "md5engine/engine.v", "md5engine/memory.v",
  "md5engine/next_thread_num.v", "md5engine/procb_buf.v", "md5engine/procb_saved_state.v",
  "md5engine/process_bytes.v", "md5engine/realign4_pad.v", "md5engine/thread_state.v",
  "util/sync.v", "util/delay.v", "util/asymm_bram.v",
]] + hb.RTL_TAIL + hb.RTL_JTR

INCLUDES = [HERE, os.path.join(HERE, "util"), os.path.join(HERE, "cpu")]

bitmap_words = hb.bitmap_words
cmp_index    = hb.cmp_index

def run_batch(exe, work, salt, rounds, cands, bitmap, gaps=1, pad_recs=1, salt_len=None):
  return hb.run_batch(exe, work, hb.salt_words(salt), rounds, cands, bitmap, gaps=gaps, pad_recs=pad_recs,
                      extra=[len(salt) if salt_len is None else salt_len])

def check(name, salt, rounds, cands, bitmap_idx, recs, done, errs, pad, ref_salt=None, pad_recs=1):
  ref_salt = salt if ref_salt is None else ref_salt
  want = {cid: md5crypt_raw(pw, ref_salt, rounds) for cid, pw in cands}
  return hb.check(name, cands, want, bitmap_idx, recs, done, errs, pad, pad_recs=pad_recs)

def main():
  ap = argparse.ArgumentParser(description="md5crypt datapath bench")
  ap.add_argument("--case", default="all")
  ap.add_argument("--units", type=int, default=2)
  ap.add_argument("--rounds", type=int, default=1000)
  ap.add_argument("--rebuild", action="store_true")
  args = ap.parse_args()

  work = os.environ.get("SIM_WORK", os.path.join(HERE, "..", "..", "build", "tb_datapath"))
  work = os.path.abspath(os.path.join(work, "u%d" % args.units))
  if args.rebuild and os.path.isdir(work):
    shutil.rmtree(work)
  exe = hb.build(work, SOURCES, INCLUDES, {"NUM_UNITS": args.units, "WITH_CMP": 1}, HERE)

  rng = random.Random(7)
  salt = b"ehAsHC4t"
  R = args.rounds

  def rnd(n):
    return bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))

  results = []

  # Every length class the CPU program branches on: empty, short, one MD5 block, two, the 64 maximum.
  if args.case in ("all", "lengths"):
    lens = [0, 1, 3, 4, 7, 15, 16, 17, 31, 32, 33, 55, 56, 57, 63, 64]
    cands = [(i, rnd(n)) for i, n in enumerate(lens)] + [(len(lens), b"hashcat"), (CANARY_ID, b"hcfpga-ztex-canary")]
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4)
    results.append(check("lengths", salt, R, cands, None, recs, done, errs, pad))

  # Several wrong candidates and one right one, the bitmap holding only the target's index:
  # the comparator has to pass the target and drop (but retire) everything that misses.
  if args.case in ("all", "cmp"):
    target = md5crypt_raw(b"hashcat", salt, R)
    cands = [(i, rnd(8)) for i in range(29)]
    cands.insert(17, (29, b"hashcat"))
    idx = {cmp_index(target)}
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, bitmap_words(idx))
    results.append(check("cmp", salt, R, cands, idx, recs, done, errs, pad))
    hit = [r for r in recs if struct.unpack("<I", r[0:4])[0] == 29]
    print("           target %s, returned %s" % (target.hex(), hit[0][4:20].hex() if hit else "nothing"))

  # Wrong salt: the same candidates under another salt return nothing that matches the target.
  if args.case in ("all", "salt"):
    target = md5crypt_raw(b"hashcat", salt, R)
    cands = [(i, rnd(6)) for i in range(5)] + [(5, b"hashcat")]
    idx = {cmp_index(target)}
    wrong = b"ehAsHC4u"
    recs, done, errs, pad = run_batch(exe, work, wrong, R, cands, bitmap_words(idx))
    results.append(check("salt", wrong, R, cands, idx, recs, done, errs, pad))
    match = [r for r in recs if r[4:20] == target]
    print("           records matching the right-salt target: %d (want 0)" % len(match))
    results.append(len(match) == 0)

  # Granule padding: EOB records repeat until the record count is a multiple of pad_recs.
  if args.case in ("all", "pad"):
    cands = [(i, rnd(5)) for i in range(3)]
    recs, done, errs, pad = run_batch(exe, work, salt, 7, cands, [0xffffffff] * 4, pad_recs=4)
    results.append(check("pad", salt, 7, cands, None, recs, done, errs, pad, pad_recs=4))

  print("ALL PASS" if all(results) else "*** FAIL ***")
  return 0 if all(results) else 1

if __name__ == "__main__":
  sys.exit(main())
