#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# wpa2's datapath bench: the shared bench (hcfpga_bench.py, tb_hcfpga.v)
# around hcfpga_wpa2_top (tb_dut.vh), each batch checked against wpa2_ref.py: every returned PMK in
# its two C2H records, the records the comparator should and should not let through, the retired
# count, the end-of-batch record and the frame status.
#
#   ./tb_datapath.py                      all cases
#   ./tb_datapath.py --case lengths       one case
#   SIM_WORK=<dir> ./tb_datapath.py       where to build (default ../../build/tb_datapath)
#
# A candidate takes about 680,000 cycles on a pair, so the cases keep their candidate counts low.

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

from wpa2_ref import wpa2_digest, PW_MAX, DIGEST_BYTES, PARTS, SALT, SALT_MAX, ROUNDS, CANARY_PW, salt_regs, extra_regs

# OpenCiphers' cores (see PROVENANCE.md), in upstream's directories.
WPAPSK = os.path.join(HERE, "wpapsk")
SHA1   = os.path.join(HERE, "sha1")

SOURCES = [os.path.join(HERE, f) for f in [
  "hcfpga_wpa2_top.sv", "hcfpga_wpa2_engine.v",
]] + [os.path.join(WPAPSK, f) for f in [
  "PBKDF2.v", "Sha1.v", "Sha1BRAM.v", "R.v", "Add32.v",
]] + [os.path.join(SHA1, "Sha1.v")] + hb.RTL_TAIL

INCLUDES = [HERE]

# The comparator looks at PMK byte 3, the low byte of the bridge's digest[0] (hcfpga_digest_swap32).
CMP_BYTE = 3

def run_batch(exe, work, salt, rounds, cands, bitmap, gaps=1, pad_recs=1):
  return hb.run_batch(exe, work, salt_regs(salt), rounds, cands, bitmap, gaps=gaps, pad_recs=pad_recs,
                      extra=extra_regs(salt, rounds))

def check(name, salt, rounds, cands, bitmap_idx, recs, done, errs, pad, pad_recs=1):
  want = {cid: wpa2_digest(pw, salt, rounds) for cid, pw in cands}
  return hb.check(name, cands, want, bitmap_idx, recs, done, errs, pad, pad_recs=pad_recs,
                  digest_bytes=DIGEST_BYTES, parts=PARTS, cmp_byte=CMP_BYTE, core_name="pairs")

def main():
  ap = argparse.ArgumentParser(description="wpa2 datapath bench")
  ap.add_argument("--case", default="all")
  ap.add_argument("--units", type=int, default=2)
  ap.add_argument("--rebuild", action="store_true")
  args = ap.parse_args()

  base = os.environ.get("SIM_WORK", os.path.join(HERE, "..", "..", "build", "tb_datapath"))
  work = os.path.abspath(os.path.join(base, "u%d" % args.units))
  if args.rebuild and os.path.isdir(work):
    shutil.rmtree(work)
  exe = hb.build(work, SOURCES, INCLUDES, {"NUM_UNITS": args.units, "WITH_CMP": 1}, HERE)

  rng = random.Random(7)
  salt = SALT
  R = ROUNDS

  def rnd(n):
    return bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))

  def rbin(n):
    return bytes(rng.randrange(256) for _ in range(n))

  results = []

  # The key is one 64-byte block whatever its length; the setup unit reads it a word at a time and
  # zeroes every byte from rec_len on. So: every byte position of a word, the word boundaries,
  # PW_MAX, zero and top-bit bytes, and lengths below WPA's 8 (the device takes them).
  if args.case in ("all", "lengths"):
    lens = [0, 1, 2, 3, 4, 5, 8, 9, 15, 16, 17, 31, 32, 33, 62, 63]
    cands = [(i, rnd(n)) for i, n in enumerate(lens)]
    cands += [(100 + i, rbin(n)) for i, n in enumerate([8, 63])]
    cands += [(200, b"pass\x00wor"), (201, b"hashcat!"), (hb.CANARY_ID, CANARY_PW)]
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4)
    results.append(check("lengths", salt, R, cands, None, recs, done, errs, pad))

  # Every ESSID length the device takes: the inner message's INT (i), padding and length move with
  # it, and bytes 16..31 come from salt4..7. One candidate each, binary ESSIDs.
  if args.case in ("all", "essids"):
    ok = True
    for n in range(0, SALT_MAX + 1):
      s = rbin(n)
      cands = [(n, rnd(8 + n % 5))]
      recs, done, errs, pad = run_batch(exe, work, s, R, cands, [0xffffffff] * 4)
      ok &= check("essid%d" % n, s, R, cands, None, recs, done, errs, pad)
    results.append(ok)

  # Several wrong candidates and one right one, the bitmap holding only the target's index: the
  # comparator passes the target (both records) and drops, but retires, everything that misses.
  # Filtered candidates free their pair at once, so pairs are restarted back to back here.
  if args.case in ("all", "cmp"):
    target = wpa2_digest(b"hashcat!", salt, R)
    cands = [(i, rnd(8)) for i in range(15)]
    cands.insert(9, (15, b"hashcat!"))
    idx = {hb.cmp_index(target, CMP_BYTE)}
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, hb.bitmap_words(idx))
    results.append(check("cmp", salt, R, cands, idx, recs, done, errs, pad))
    hit = b"".join(r[4:28] for r in recs if struct.unpack("<I", r[0:4])[0] == 15 and r[30:32] != b"\x00\x80")
    print("           target %s, returned %s" % (target.hex(), hit[:DIGEST_BYTES].hex() if hit else "nothing"))

  # Wrong salt: the last ESSID byte flipped (the device uses every byte); nothing matches.
  if args.case in ("all", "salt"):
    target = wpa2_digest(b"hashcat!", salt, R)
    cands = [(i, rnd(9)) for i in range(3)] + [(3, b"hashcat!")]
    idx = {hb.cmp_index(target, CMP_BYTE)}
    wrong = salt[:-1] + bytes([salt[-1] ^ 1])
    recs, done, errs, pad = run_batch(exe, work, wrong, R, cands, hb.bitmap_words(idx))
    results.append(check("salt", wrong, R, cands, idx, recs, done, errs, pad))
    match = [r for r in recs if r[4:28] == target[:24]]
    print("           records matching the right-salt target: %d (want 0)" % len(match))
    results.append(len(match) == 0)

  # Granule padding: EOB records repeat until the record count (two per candidate) is a multiple
  # of pad_recs.
  if args.case in ("all", "pad"):
    cands = [(i, rnd(8)) for i in range(3)]
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4, pad_recs=4)
    results.append(check("pad", salt, R, cands, None, recs, done, errs, pad, pad_recs=4))

  # hashcat's build: WITH_CMP = 0 returns every candidate, whatever the bitmap holds.
  if args.case in ("all", "nocmp"):
    work0 = os.path.abspath(os.path.join(base, "u%d_nocmp" % args.units))
    exe0 = hb.build(work0, SOURCES, INCLUDES, {"NUM_UNITS": args.units, "WITH_CMP": 0}, HERE)
    cands = [(i, rnd(10)) for i in range(4)]
    recs, done, errs, pad = run_batch(exe0, work0, salt, R, cands, [0, 0, 0, 0])
    results.append(check("nocmp", salt, R, cands, None, recs, done, errs, pad))

  print("ALL PASS" if all(results) else "*** FAIL ***")
  return 0 if all(results) else 1

if __name__ == "__main__":
  sys.exit(main())
