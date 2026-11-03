#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Builds tb_datapath.v with Verilator and runs batches through hcfpga_md5crypt_top, each checked
# against md5crypt_ref.py: every returned digest, the records the comparator should and should not
# let through, the retired count, the end-of-batch record and the frame status.
#
#   ./tb_datapath.py                      all cases
#   ./tb_datapath.py --case lengths       one case
#   SIM_WORK=<dir> ./tb_datapath.py       where to build (default ../../build/tb_datapath)

import argparse
import os
import random
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)

from md5crypt_ref import md5crypt_raw

CANARY_ID = 0xfffffffe

SOURCES = [
  "hcfpga_md5crypt_top.sv", "hcfpga_md5crypt_feed.v", "hcfpga_md5crypt_collect.v", "hcfpga_c2h_eob.v",
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
]

def h2c_records(cands):
  """The bridge's fill_batch: header, id, password big-endian, zero filled; batch padded to 32 B."""
  words = []
  for cid, pw in cands:
    words.append((0xbc << 24) | len(pw))
    words.append(cid)
    for i in range(0, len(pw), 4):
      chunk = pw[i:i+4].ljust(4, b"\x00")
      words.append(struct.unpack(">I", chunk)[0])
  pad = (-len(words)) % 8
  return words + [0] * pad, pad

def salt_words(salt):
  s = salt.ljust(16, b"\x00")
  return list(struct.unpack("<4I", s))

def bitmap_words(indexes):
  bm = [0, 0, 0, 0]
  for idx in indexes:
    bm[idx // 32] |= 1 << (idx % 32)
  return bm

def cmp_index(digest):
  return digest[0] & 0x7f

def build(work, units, with_cmp):
  exe = os.path.join(work, "obj_dir", "Vtb_datapath")
  if os.path.isfile(exe):
    return exe
  os.makedirs(work, exist_ok=True)
  cmd = ["verilator", "--binary", "-j", "0", "-O3", "--x-initial", "unique",
         "-Wno-fatal", "-Wno-WIDTH", "-Wno-CASEINCOMPLETE", "-Wno-UNOPTFLAT", "-Wno-PINMISSING",
         "-Wno-UNSIGNED", "-Wno-REDEFMACRO", "-Wno-IMPLICIT", "-Wno-TIMESCALEMOD", "-Wno-MULTIDRIVEN",
         "-I" + HERE, "-I" + os.path.join(HERE, "util"), "-I" + os.path.join(HERE, "cpu"),
         "-GNUM_UNITS=%d" % units, "-GWITH_CMP=%d" % with_cmp,
         "--top-module", "tb_datapath", "--Mdir", os.path.join(work, "obj_dir"),
         os.path.join(HERE, "tb_datapath.v")] + [os.path.join(HERE, f) for f in SOURCES]
  r = subprocess.run(cmd, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  if r.returncode != 0:
    sys.stdout.write(r.stdout.decode(errors="replace")[-4000:])
    raise SystemExit("verilator build failed")
  return exe

def run_batch(exe, work, salt, rounds, cands, bitmap, gaps=1, pad_recs=1, salt_len=None):
  words, pad = h2c_records(cands)
  cfg = salt_words(salt) + [rounds, len(salt) if salt_len is None else salt_len] + bitmap
  cfg += [len(cands), pad_recs, len(words), gaps, 0, 0]
  with open(os.path.join(work, "cfg.hex"), "w") as f:
    f.write("\n".join("%08x" % w for w in cfg) + "\n")
  with open(os.path.join(work, "h2c.hex"), "w") as f:
    f.write("\n".join("%08x" % w for w in words) + "\n")
  r = subprocess.run([exe], cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  out = r.stdout.decode(errors="replace").splitlines()
  recs = []
  done = None
  errs = []
  for line in out:
    if line.startswith("REC "):
      recs.append(bytes.fromhex(line[4:]))
    elif line.startswith("DONE "):
      done = line.split()[1:]
    elif line.startswith("ERR"):
      errs.append(line)
  return recs, done, errs, pad

def check(name, salt, rounds, cands, bitmap_idx, recs, done, errs, pad, ref_salt=None, pad_recs=1):
  ok = True
  ref_salt = salt if ref_salt is None else ref_salt
  want = {cid: md5crypt_raw(pw, ref_salt, rounds) for cid, pw in cands}
  bitmap_all = bitmap_idx is None
  expect_ret = {cid for cid, d in want.items() if bitmap_all or cmp_index(d) in bitmap_idx}
  got = {}
  eob = []
  for r in recs:
    flags = struct.unpack("<H", r[30:32])[0]
    if flags == 0x8000:
      eob.append(struct.unpack("<I", r[0:4])[0])
      continue
    cid  = struct.unpack("<I", r[0:4])[0]
    core = struct.unpack("<H", r[28:30])[0]
    dig  = r[4:20]
    if r[20:28] != b"\x00" * 8:
      print("  %s: id %08x bytes 20..27 not zero" % (name, cid)); ok = False
    if flags != 0:
      print("  %s: id %08x flags %04x" % (name, cid, flags)); ok = False
    if cid in got:
      print("  %s: id %08x returned twice" % (name, cid)); ok = False
    got[cid] = (dig, core)
  for cid, (dig, core) in sorted(got.items()):
    if cid not in want:
      print("  %s: unknown id %08x" % (name, cid)); ok = False; continue
    if dig != want[cid]:
      print("  %s: id %08x digest %s want %s" % (name, cid, dig.hex(), want[cid].hex())); ok = False
  if set(got) != expect_ret:
    print("  %s: returned %s, expected %s" % (name, sorted("%x" % c for c in got), sorted("%x" % c for c in expect_ret))); ok = False
  total = len(got) + len(eob)
  if len(eob) < 1 or (total % max(pad_recs, 1)) != 0:
    print("  %s: %d EOB records, %d records in all, pad_recs %d" % (name, len(eob), total, pad_recs)); ok = False
  if any(e != len(cands) for e in eob):
    print("  %s: EOB counts %s, want %d" % (name, eob, len(cands))); ok = False
  if done is None:
    print("  %s: no DONE line" % name); ok = False
  else:
    retired, status, cycles = int(done[0]), int(done[1], 16), int(done[2])
    if retired != len(cands):
      print("  %s: retired %d of %d" % (name, retired, len(cands))); ok = False
    slips = (status >> 8) & 0xff
    if (status & 2) == 0 or slips != pad or (status >> 16) != 0:
      print("  %s: frame status %08x, want last_seen, %d slips, no unit errors" % (name, status, pad)); ok = False
  for e in errs:
    print("  %s: %s" % (name, e)); ok = False
  cores = sorted({c for _, c in got.values()})
  print("%-10s %s  %d candidates, %d returned, %d filtered, units %s, %s cycles" %
        (name, "PASS" if ok else "FAIL", len(cands), len(got), len(cands) - len(got), cores,
         done[2] if done else "?"))
  return ok

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
  exe = build(work, args.units, 1)

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
