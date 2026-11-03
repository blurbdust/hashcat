#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# sha256crypt's datapath bench: the shared bench (hcfpga_bench.py, tb_hcfpga.v)
# around hcfpga_sha256crypt_top (tb_dut.vh), each batch checked against sha256crypt_ref.py: every
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

from sha256crypt_ref import sha256crypt_digest, PW_MAX, DIGEST_BYTES, SALT, ROUNDS, CANARY_PW, extra_regs

# The top, John the Ripper's sha256crypt unit (see PROVENANCE.md) and the shared JtR adapter.
SOURCES = [os.path.join(HERE, f) for f in [
  "hcfpga_sha256crypt_top.sv",
  "unit/sha256unit.v", "unit/unit_ctrl.v", "unit/core_ctrl.v", "unit/unit_input.v", "unit/uob.v",
  "cpu/cpu.v", "cpu/cpu_flags.v", "cpu/cpu_state.v", "cpu/instruction.v", "cpu/integer_ops.v",
  "cpu/registers_bram.v", "cpu/thread_number.v",
  "sha256core/add3.v", "sha256core/add3_unreg.v", "sha256core/ff16.v", "sha256core/ff32.v",
  "sha256core/sha256block.v", "sha256core/sha256core.v", "sha256core/sha256ctx.v",
  "sha256core/sha256_Kt_bram.v", "sha256core/shreg.v",
  "sha256engine/core_input.v", "sha256engine/create_blk.v", "sha256engine/engine.v", "sha256engine/memory.v",
  "sha256engine/next_thread_num.v", "sha256engine/procb_buf.v", "sha256engine/procb_saved_state.v",
  "sha256engine/process_bytes.v", "sha256engine/realign4_pad.v", "sha256engine/thread_state.v",
  "util/sync.v", "util/delay.v", "util/asymm_bram.v",
]] + hb.RTL_TAIL + hb.RTL_JTR

# sha256.vh and log2.vh, and cpu/program.vh, which cpu/instruction.v includes.
INCLUDES = [HERE, os.path.join(HERE, "util"), os.path.join(HERE, "cpu")]

def run_batch(exe, work, salt, rounds, cands, bitmap, gaps=1, pad_recs=1):
  return hb.run_batch(exe, work, hb.salt_words(salt), rounds, cands, bitmap, gaps=gaps, pad_recs=pad_recs,
                      extra=extra_regs(salt, rounds))

def check(name, salt, rounds, cands, bitmap_idx, recs, done, errs, pad, pad_recs=1):
  want = {cid: sha256crypt_digest(pw, salt, rounds) for cid, pw in cands}
  return hb.check(name, cands, want, bitmap_idx, recs, done, errs, pad, pad_recs=pad_recs,
                  digest_bytes=DIGEST_BYTES, core_name="units")

def main():
  ap = argparse.ArgumentParser(description="sha256crypt datapath bench")
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

  # Every key length the unit takes, 0 to PW_MAX (32). The program branches on the key length's
  # bits (alternate sum or key), builds the P sequence from key_len copies of the key, and a round
  # is one SHA-256 block up to 55 bytes and two beyond (32 + salt + 2 * key_len bytes or so), so
  # every length covers each block boundary with this salt. Two waves of 24 threads.
  if args.case in ("all", "lengths"):
    lens = list(range(PW_MAX + 1))
    cands = [(i, rnd(n)) for i, n in enumerate(lens)] + [(len(lens), b"hashcat"), (hb.CANARY_ID, CANARY_PW)]
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4)
    results.append(check("lengths", salt, R, cands, None, recs, done, errs, pad))

  # Every salt length the unit takes, 1 to 16, each with short, middle and longest keys: the S
  # sequence is 16 + alt_result[0] copies of the salt, and the salt length moves the round's
  # block boundary.
  if args.case in ("all", "salts"):
    ok = True
    for n in range(1, 17):
      s = rnd(n)
      cands = [(0, rnd(0)), (1, rnd(7)), (2, rnd(19)), (3, rnd(PW_MAX))]
      recs, done, errs, pad = run_batch(exe, work, s, R, cands, [0xffffffff] * 4)
      ok &= check("salt%d" % n, s, R, cands, None, recs, done, errs, pad)
    results.append(ok)

  # Round counts: 1 (the least the program takes), and 65537, whose count needs the upper of the
  # two 16-bit count registers (the program borrows from it when the lower one runs out).
  if args.case in ("all", "rounds"):
    for rounds in (1, 65537):
      cands = [(0, b"hashcat"), (1, rnd(PW_MAX))]
      recs, done, errs, pad = run_batch(exe, work, salt, rounds, cands, [0xffffffff] * 4)
      results.append(check("rounds%d" % rounds, salt, rounds, cands, None, recs, done, errs, pad))

  # Several wrong candidates and one right one, the bitmap holding only the target's index:
  # the comparator has to pass the target and drop (but retire) everything that misses.
  if args.case in ("all", "cmp"):
    target = sha256crypt_digest(b"hashcat", salt, R)
    cands = [(i, rnd(8)) for i in range(29)]
    cands.insert(17, (29, b"hashcat"))
    idx = {hb.cmp_index(target)}
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, hb.bitmap_words(idx))
    results.append(check("cmp", salt, R, cands, idx, recs, done, errs, pad))
    hit = [r for r in recs if struct.unpack("<I", r[0:4])[0] == 29]
    print("           target %s, returned %s" % (target.hex(), hit[0][4:4 + DIGEST_BYTES].hex() if hit else "nothing"))

  # Wrong salt: the same candidates under another salt return nothing that matches the target.
  if args.case in ("all", "salt"):
    target = sha256crypt_digest(b"hashcat", salt, R)
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
    recs, done, errs, pad = run_batch(exe, work, salt, 7, cands, [0xffffffff] * 4, pad_recs=4)
    results.append(check("pad", salt, 7, cands, None, recs, done, errs, pad, pad_recs=4))

  print("ALL PASS" if all(results) else "*** FAIL ***")
  return 0 if all(results) else 1

if __name__ == "__main__":
  sys.exit(main())
