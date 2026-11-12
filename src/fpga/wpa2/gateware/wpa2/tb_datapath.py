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
# A candidate takes 8191 * 2 * SLOTS cycles in a pipe's slot (about 688,000 with a round a stage and
# 42 slots, 360,000 with two and 22), and a pipe holds SLOTS of them at once, so a batch of up to
# SLOTS * units candidates takes that long, and one more takes twice.

import argparse
import os
import random
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True

HERE   = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)

import hcfpga_bench as hb

from wpa2_ref import wpa2_digest, PW_MAX, DIGEST_BYTES, PARTS, SALT, SALT_MAX, ROUNDS, CANARY_PW, slots, salt_regs, extra_regs, xadc_code

SOURCES = [os.path.join(HERE, f) for f in [
  "hcfpga_wpa2_top.sv", "hcfpga_wpa2_engine.v", "hcfpga_wpa2_pipe.v", "hcfpga_wpa2_round.v", "hcfpga_wpa2_sha1.v",
]] + hb.RTL_TAIL

INCLUDES = [HERE]

# The comparator looks at PMK byte 3, the low byte of the bridge's digest[0] (hcfpga_digest_swap32).
CMP_BYTE = 3

def run_batch(exe, work, salt, rounds, cands, bitmap, gaps=1, pad_recs=1, heat=None):
  """heat: (t1, t2, t3, celsius1, celsius2), the die at celsius1 from cycle t1 and celsius2 from t2,
  cold again from t3 (tb_dut.vh); None keeps it cold."""
  extra = extra_regs(salt, rounds)
  if heat is not None:
    t1, t2, t3, c1, c2 = heat
    extra = extra + [t1, t2, t3] + [0] * 4 + [xadc_code(c1), xadc_code(c2)]
  return hb.run_batch(exe, work, salt_regs(salt), rounds, cands, bitmap, gaps=gaps, pad_recs=pad_recs,
                      extra=extra)

def check(name, salt, rounds, cands, bitmap_idx, recs, done, errs, pad, pad_recs=1):
  want = {cid: wpa2_digest(pw, salt, rounds) for cid, pw in cands}
  return hb.check(name, cands, want, bitmap_idx, recs, done, errs, pad, pad_recs=pad_recs,
                  digest_bytes=DIGEST_BYTES, parts=PARTS, cmp_byte=CMP_BYTE, core_name="slots")

def build_restart(work, units, rps):
  """tb_restart.v around the same top, the way hb.build builds tb_hcfpga.v."""
  exe = os.path.join(work, "obj_dir", "Vtb_restart")
  hdl = SOURCES + [os.path.join(HERE, f) for f in ("tb_restart.v", "tb_dut.vh")]
  if os.path.isfile(exe) and os.path.getmtime(exe) >= max(os.path.getmtime(f) for f in hdl):
    return exe
  os.makedirs(work, exist_ok=True)
  cmd = ["verilator", "--binary", "-j", "0", "-O3", "--x-initial", "unique"] + hb.VERILATOR_WARNINGS
  cmd += ["-I" + d for d in [HERE, hb.IFACE]]
  cmd += ["-GNUM_UNITS=%d" % units, "-GWITH_CMP=1", "-GRPS=%d" % rps]
  cmd += ["--top-module", "tb_restart", "--Mdir", os.path.join(work, "obj_dir"), os.path.join(HERE, "tb_restart.v")]
  cmd += SOURCES
  r = subprocess.run(cmd, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  if r.returncode != 0:
    sys.stdout.write(r.stdout.decode(errors="replace")[-4000:])
    raise SystemExit("verilator build failed")
  return exe

def run_restart(exe, work, salt, rounds, cands_a, cands_b, abort_at, mode):
  """Batch A abandoned abort_at cycles into its stream (mode 1: a framing reset, 2: B armed without
  one), then batch B. Returns B's records as hb.run_batch does, and the ABORT line."""
  words_a, _ = hb.h2c_records(cands_a)
  words_b, pad_b = hb.h2c_records(cands_b)
  cfg = [0] * 32
  cfg[0:4]   = salt_regs(salt)
  cfg[4]     = rounds
  cfg[6:10]  = [0xffffffff] * 4
  cfg[10:14] = [len(cands_b), 1, len(words_b), 0]
  for i, v in enumerate(extra_regs(salt, rounds)):
    cfg[16 + i] = v
  cfg[24:28] = [len(cands_a), len(words_a), abort_at, mode]
  with open(os.path.join(work, "cfg.hex"), "w") as f:
    f.write("\n".join("%08x" % (w & 0xffffffff) for w in cfg) + "\n")
  for name, words in (("h2c_a.hex", words_a), ("h2c.hex", words_b)):
    with open(os.path.join(work, name), "w") as f:
      f.write("\n".join("%08x" % w for w in words) + "\n")
  r = subprocess.run([exe], cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  recs, done, errs, abort = [], None, [], ""
  for line in r.stdout.decode(errors="replace").splitlines():
    if line.startswith("REC "):
      recs.append(bytes.fromhex(line[4:]))
    elif line.startswith("DONE "):
      done = line.split()[1:]
    elif line.startswith("ERR"):
      errs.append(line)
    elif line.startswith("ABORT"):
      abort = line
  return recs, done, errs, pad_b, abort

def main():
  ap = argparse.ArgumentParser(description="wpa2 datapath bench")
  ap.add_argument("--case", default="all")
  ap.add_argument("--units", type=int, default=2)
  ap.add_argument("--rps", type=int, default=2, choices=(1, 2), help="SHA-1 rounds a pipe stage")
  ap.add_argument("--rebuild", action="store_true")
  args = ap.parse_args()

  base = os.environ.get("SIM_WORK", os.path.join(HERE, "..", "..", "build", "tb_datapath"))
  work = os.path.abspath(os.path.join(base, "u%d_r%d" % (args.units, args.rps)))
  if args.rebuild and os.path.isdir(work):
    shutil.rmtree(work)
  exe = hb.build(work, SOURCES, INCLUDES, {"NUM_UNITS": args.units, "WITH_CMP": 1, "RPS": args.rps}, HERE)
  SLOTS = slots(args.rps)

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

  # More candidates than slots: every slot of every pipe is taken, and the last candidates wait for
  # slots to free and run in them again. Ids out of order, a few ESSID-length passwords.
  if args.case in ("all", "full"):
    n = SLOTS * args.units + 13
    cands = [(1000 + 7 * i, rnd(8 + i % 56)) for i in range(n)]
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4)
    results.append(check("full", salt, R, cands, None, recs, done, errs, pad))

  # Batches abandoned with candidates in flight, as hashcat's board restart does after a failed
  # batch, and a batch armed while the last one still runs: whatever was in flight never comes
  # back, and the next batch returns whole. A framing reset while A's candidates are being set up,
  # one while they run in the pipes, and B armed without a reset while A's run (A's results then
  # come back under the old generation and are dropped).
  if args.case in ("all", "restart"):
    rwork = os.path.abspath(os.path.join(base, "u%d_r%d_restart" % (args.units, args.rps)))
    rexe = build_restart(rwork, args.units, args.rps)
    s2 = rbin(11)
    for name, abort_at, mode, na in (("rst_setup", 1500, 1, 30), ("rst_run", 300000, 1, 30), ("arm_run", 100000, 2, 20)):
      cands_a = [(5000 + i, rnd(9)) for i in range(na)]
      cands_b = [(i, rnd(8 + i % 3)) for i in range(SLOTS * args.units - na + 4)]
      cands_b.insert(5, (77, b"hashcat!"))
      recs, done, errs, pad, abort = run_restart(rexe, rwork, s2, R, cands_a, cands_b, abort_at, mode)
      print("           %s" % abort)
      # Without a reset the intake's slip count runs on from A's pad words.
      if mode == 2:
        pad += hb.h2c_records(cands_a)[1]
      results.append(check(name, s2, R, cands_b, None, recs, done, errs, pad))

  # The thermal stop. A die at 90 C from early in the batch, then at 80 C (between the thresholds,
  # so the stop holds), then cold: the candidates started before the stop finish, the others wait,
  # every one comes back exact and once, and the batch ends a slot's run after the die cooled. A
  # reading of 90 C for a few cycles only, shorter than the filter, changes nothing.
  if args.case in ("all", "hot"):
    slot_run = 8191 * 2 * SLOTS
    cands = [(i, rnd(8 + i % 9)) for i in range(SLOTS * args.units - 14)]
    t1, t2, t3 = 3000, 3000 + slot_run, 3000 + 2 * slot_run
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4, heat=(t1, t2, t3, 90, 80))
    ok = check("hot", salt, R, cands, None, recs, done, errs, pad)
    cyc = int(done[2]) if done else 0
    print("           %d cycles, the die cold again at %d, a slot's run %d" % (cyc, t3, slot_run))
    ok &= cyc > t3 + slot_run
    recs, done, errs, pad = run_batch(exe, work, salt, R, cands, [0xffffffff] * 4, heat=(3000, 3010, 3010, 90, 0))
    ok &= check("hot_blip", salt, R, cands, None, recs, done, errs, pad)
    cyc = int(done[2]) if done else 0
    print("           %d cycles with a 10-cycle reading of 90 C (want under %d)" % (cyc, slot_run + 20000))
    ok &= cyc < slot_run + 20000
    results.append(ok)

  # hashcat's build: WITH_CMP = 0 returns every candidate, whatever the bitmap holds.
  if args.case in ("all", "nocmp"):
    work0 = os.path.abspath(os.path.join(base, "u%d_r%d_nocmp" % (args.units, args.rps)))
    exe0 = hb.build(work0, SOURCES, INCLUDES, {"NUM_UNITS": args.units, "WITH_CMP": 0, "RPS": args.rps}, HERE)
    cands = [(i, rnd(10)) for i in range(4)]
    recs, done, errs, pad = run_batch(exe0, work0, salt, R, cands, [0, 0, 0, 0])
    results.append(check("nocmp", salt, R, cands, None, recs, done, errs, pad))

  print("ALL PASS" if all(results) else "*** FAIL ***")
  return 0 if all(results) else 1

if __name__ == "__main__":
  sys.exit(main())
