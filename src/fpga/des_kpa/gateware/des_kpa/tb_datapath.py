#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# des_kpa's datapath bench: the shared bench (hcfpga_bench.py, tb_hcfpga.v) around hcfpga_des_kpa_top
# (tb_dut.vh), each batch checked against des_kpa_ref.py: every hit record (job, amplifier item,
# target), that nothing else comes back, the retired count, the end-of-batch record and the frame
# status. The reference walks every key of every job, so a missed or an extra key shows; the large
# case plants its keys and checks those.
#
#   ./tb_datapath.py                      all cases
#   ./tb_datapath.py --case amp2          one case
#   SIM_WORK=<dir> ./tb_datapath.py       where to build (default ../../build/tb_datapath)

import argparse
import os
import random
import shutil
import struct
import sys

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)

import hcfpga_bench as hb

from des_kpa_ref import des_encrypt, odd_parity, amp_total, amp_key, job_hits, salt_words, openssl_des, AMP_MAX, NUM_TARGETS

SOURCES = [os.path.join(HERE, f) for f in ["hcfpga_des_kpa_top.sv", "hcfpga_des_kpa_engine.v", "hcfpga_des_kpa_core.v"]] + hb.RTL_TAIL

INCLUDES = [HERE]

# charsets/DES_full.hcchr: one byte per 7-bit value, odd parity.
DES_FULL = [odd_parity(v << 1) for v in range(128)]

def therm_code(c):
  """The XADC code the host reads as c degrees."""
  return int(round((c + 273.15) * 4096 / 503.975))

def extra_regs(tabs, targets, mask=None, temp=None):
  """cfg[16..31]: amp_cnt, amp_lens, amp_tab, tgt_mask, the targets, the temperature profile."""
  lens = 0
  for p, t in enumerate(tabs):
    lens |= (len(t) - 1) << (8 * p)
  regs = [len(tabs), lens, 0, mask if mask is not None else (1 << len(targets)) - 1]
  for k in range(NUM_TARGETS):
    ct = targets[k] if k < len(targets) else bytes(8)
    regs += list(struct.unpack("<2I", ct))
  regs += list(temp) if temp else [0, 0, 0, 0]
  return regs

def write_tabs(work, tabs):
  words = []
  for p, t in enumerate(tabs):
    for i, ch in enumerate(t):
      words.append((p << 16) | (i << 8) | ch)
  with open(os.path.join(work, "amp.hex"), "w") as f:
    f.write("\n".join("%08x" % w for w in [len(words)] + words) + "\n")

def run(exe, work, pt, tabs, targets, jobs, mask=None, temp=None, pad_recs=1, gaps=1):
  """One batch: jobs is [(id, 8-byte base word)]."""
  write_tabs(work, tabs)
  return hb.run_batch(exe, work, salt_words(pt), 0, jobs, [0, 0, 0, 0], gaps=gaps, pad_recs=pad_recs,
                      extra=extra_regs(tabs, targets, mask, temp))

def check(name, pt, tabs, targets, jobs, recs, done, errs, pad, units, mask=None, want=None, pad_recs=1,
          status_bits=0):
  """want: {(id, item, target)}; computed from the reference unless given."""
  ok = True
  def bad(msg):
    nonlocal ok
    ok = False
    print("  %s: %s" % (name, msg))
  if mask is None:
    mask = (1 << len(targets)) - 1
  live = [ct if (mask >> k) & 1 else None for k, ct in enumerate(targets)]
  if want is None:
    want = set()
    for cid, base in jobs:
      b = bytearray(base.ljust(8, b"\x00")[:8])
      for p in range(len(tabs)):
        b[p] = 0
      for item, k in job_hits(bytes(b), tabs, pt, live):
        want.add((cid, item, k))
  got = set()
  eob = []
  n_res = 0
  for r in recs:
    flags = struct.unpack("<H", r[30:32])[0]
    if flags == 0x8000:
      eob.append(struct.unpack("<I", r[0:4])[0])
      continue
    n_res += 1
    cid, item = struct.unpack("<II", r[0:8])
    k, core = r[8], struct.unpack("<H", r[28:30])[0]
    if flags != 0:
      bad("id %08x flags %04x" % (cid, flags))
    if r[9:28] != bytes(19):
      bad("id %08x bytes 9..27 not zero" % cid)
    if core >= units:
      bad("id %08x from core %d" % (cid, core))
    if (cid, item, k) in got:
      bad("id %08x item %d target %d twice" % (cid, item, k))
    got.add((cid, item, k))
  # Every reported key is checked through OpenSSL as well.
  bases = dict(jobs)
  for cid, item, k in sorted(got):
    if cid not in bases or k >= len(targets):
      bad("unknown hit %08x %d %d" % (cid, item, k)); continue
    b = bytearray(bases[cid].ljust(8, b"\x00")[:8])
    for p in range(len(tabs)):
      b[p] = 0
    key = amp_key(bytes(b), tabs, item)
    if openssl_des(key, pt) != targets[k]:
      bad("id %08x item %d: key %s does not give target %d" % (cid, item, key.hex(), k))
  if got != want:
    bad("hits %s, want %s" % (sorted(got - want), sorted(want - got)))
  if len(eob) < 1 or ((n_res + len(eob)) % max(pad_recs, 1)) != 0:
    bad("%d EOB records, %d records in all, pad_recs %d" % (len(eob), n_res + len(eob), pad_recs))
  if any(e != len(jobs) for e in eob):
    bad("EOB counts %s, want %d" % (eob, len(jobs)))
  if done is None:
    bad("no DONE line")
  else:
    retired, status = int(done[0]), int(done[1], 16)
    if retired != len(jobs):
      bad("retired %d of %d" % (retired, len(jobs)))
    if (status & 2) == 0 or ((status >> 8) & 0xff) != pad or (status >> 16) != status_bits:
      bad("frame status %08x, want last_seen, %d slips, bits 31:16 %x" % (status, pad, status_bits))
  for e in errs:
    bad(e)
  print("%-10s %s  %d jobs x %d items, %d hits, %s cycles" % (name, "PASS" if ok else "FAIL", len(jobs),
        amp_total(tabs), len(got), done[2] if done else "?"))
  return ok

def main():
  ap = argparse.ArgumentParser(description="des_kpa datapath bench")
  ap.add_argument("--case", default="all")
  ap.add_argument("--units", type=int, default=3)
  ap.add_argument("--rebuild", action="store_true")
  args = ap.parse_args()

  work = os.environ.get("SIM_WORK", os.path.join(HERE, "..", "..", "build", "tb_datapath"))
  work = os.path.abspath(os.path.join(work, "u%d" % args.units))
  if args.rebuild and os.path.isdir(work):
    shutil.rmtree(work)
  exe = hb.build(work, SOURCES, INCLUDES, {"NUM_UNITS": args.units, "WITH_CMP": 1}, HERE)

  U = args.units
  rng = random.Random(14000)

  def rkey():
    return bytes(rng.randrange(256) for _ in range(8))

  def plant(base, tabs, item):
    """A base word with key `item` of the amplifier on it, as the device builds it."""
    b = bytearray(base)
    for p in range(len(tabs)):
      b[p] = 0
    return amp_key(bytes(b), tabs, item)

  def case(name):
    return args.case in ("all", name)

  results = []

  # Known answers, one key per job (no amplifier): FIPS 81's example, mode 14000's example hash and
  # password, the same password with every parity bit flipped (the same DES key, so it hits too),
  # keys one bit away in a key bit (they must not), and random keys.
  if case("vectors"):
    pt = bytes.fromhex("1412781058343178")
    t0 = bytes.fromhex("53b325182924b356")
    assert des_encrypt(b"hashcat1", pt) == t0
    k1 = rkey()
    targets = [t0, des_encrypt(k1, pt)]
    jobs = [(0, b"hashcat1"), (1, bytes(c ^ 1 for c in b"hashcat1")), (2, b"hashcat3"), (3, b"hbshcat1"),
            (4, k1), (5, bytes(c ^ 2 for c in k1))] + [(6 + i, rkey()) for i in range(10)]
    recs, done, errs, pad = run(exe, work, pt, [], targets, jobs)
    results.append(check("vectors", pt, [], targets, jobs, recs, done, errs, pad, U))
    pt2 = bytes.fromhex("4e6f772069732074")
    targets = [bytes.fromhex("3fa40e8a984d4815")]
    jobs = [(7, bytes.fromhex("0123456789abcdef")), (8, bytes.fromhex("0123456789abcdee")), (9, bytes.fromhex("0123456789abcdf1"))]
    recs, done, errs, pad = run(exe, work, pt2, [], targets, jobs)
    results.append(check("fips81", pt2, [], targets, jobs, recs, done, errs, pad, U))

  # One amplifier position over all 128 DES keys bytes (DES_full), keys planted at the first item,
  # the last and in between, in more jobs than cores (two waves of both parities and a short one).
  if case("amp1"):
    pt = rkey()
    tabs = [DES_FULL]
    bases = [rkey() for _ in range(2 * U + 1)]
    keys = [plant(bases[0], tabs, 0), plant(bases[U], tabs, 127), plant(bases[2 * U], tabs, 64)]
    targets = [des_encrypt(k, pt) for k in keys]
    jobs = [(100 + i, b) for i, b in enumerate(bases)]
    recs, done, errs, pad = run(exe, work, pt, tabs, targets, jobs)
    results.append(check("amp1", pt, tabs, targets, jobs, recs, done, errs, pad, U))

  # Two positions, the second with three characters: the carry from position 0 at item 127 -> 128,
  # the first and the last item, and a key one past the last (the next base word) that must not hit.
  if case("amp2"):
    pt = rkey()
    tabs = [DES_FULL, [0x31, 0x40, 0xfe]]
    bases = [rkey() for _ in range(U)]
    keys = [plant(bases[0], tabs, 127), plant(bases[0], tabs, 128), plant(bases[1 % U], tabs, 3 * 128 - 1),
            plant(bases[2 % U], tabs, 0)]
    targets = [des_encrypt(k, pt) for k in keys]
    jobs = [(200 + i, b) for i, b in enumerate(bases)]
    recs, done, errs, pad = run(exe, work, pt, tabs, targets, jobs)
    results.append(check("amp2", pt, tabs, targets, jobs, recs, done, errs, pad, U))

  # All four positions at small radices (3 * 2 * 5 * 4 = 120 items): every carry, the last item and
  # wrap; position 1 holds both parities of one byte, so every key in the job comes twice and the
  # device reports the first. One target is disabled by the mask and must stay silent.
  if case("amp4"):
    pt = rkey()
    tabs = [[0x10, 0x20, 0x30], [0x41, 0x40], [0x01, 0x7f, 0x80, 0xc2, 0xfe], [0x00, 0x55, 0xaa, 0xff]]
    bases = [rkey() for _ in range(U + 2)]
    keys = [plant(bases[0], tabs, 119), plant(bases[1], tabs, 0), plant(bases[U + 1], tabs, 61),
            plant(bases[2], tabs, 7)]
    targets = [des_encrypt(k, pt) for k in keys]
    jobs = [(300 + i, b) for i, b in enumerate(bases)]
    recs, done, errs, pad = run(exe, work, pt, tabs, targets, jobs, mask=0b1011)
    results.append(check("amp4", pt, tabs, targets, jobs, recs, done, errs, pad, U, mask=0b1011))

  # Many single-key jobs, a few waves of them, and a batch with nothing to find.
  if case("waves"):
    pt = rkey()
    keys = [rkey() for _ in range(5 * U + 2)]
    targets = [des_encrypt(keys[1], pt), des_encrypt(keys[3 * U], pt)]
    jobs = [(400 + i, k) for i, k in enumerate(keys)]
    recs, done, errs, pad = run(exe, work, pt, [], targets, jobs)
    results.append(check("waves", pt, [], targets, jobs, recs, done, errs, pad, U))
    jobs = [(500 + i, rkey()) for i in range(4)]
    recs, done, errs, pad = run(exe, work, pt, [DES_FULL], targets, jobs)
    results.append(check("nohit", pt, [DES_FULL], targets, jobs, recs, done, errs, pad, U))

  # Granule padding: EOB records repeat until the record count is a multiple of pad_recs (two hits,
  # then two EOB records).
  if case("pad"):
    pt = rkey()
    tabs = [DES_FULL]
    bases = [rkey() for _ in range(2)]
    targets = [des_encrypt(plant(bases[1], tabs, 5), pt), des_encrypt(plant(bases[0], tabs, 77), pt)]
    jobs = [(600 + i, b) for i, b in enumerate(bases)]
    recs, done, errs, pad = run(exe, work, pt, tabs, targets, jobs, pad_recs=4)
    results.append(check("pad", pt, tabs, targets, jobs, recs, done, errs, pad, U, pad_recs=4))

  # Thermal stop: the die reads 90 C from cycle 3000 to 9000 and 60 C after. The generator holds
  # while it is hot and the wave finishes with every hit once it cools; the status bit is clear at
  # the end.
  if case("therm"):
    pt = rkey()
    tabs = [DES_FULL, DES_FULL[:40]]
    bases = [rkey() for _ in range(U)]
    keys = [plant(bases[0], tabs, 1000), plant(bases[U - 1], tabs, 128 * 40 - 1)]
    targets = [des_encrypt(k, pt) for k in keys]
    jobs = [(700 + i, b) for i, b in enumerate(bases)]
    temp = [3000, therm_code(90), 9000, therm_code(60)]
    recs, done, errs, pad = run(exe, work, pt, tabs, targets, jobs, temp=temp)
    ok = check("therm", pt, tabs, targets, jobs, recs, done, errs, pad, U)
    cycles = int(done[2]) if done else 0
    print("           %d cycles with the stop (a cold wave takes about %d)" % (cycles, 128 * 40 + 1000))
    results.append(ok and cycles > 128 * 40 + 6000)

  # Full size: three positions of 128 (2^21 keys per job, a whole mode 14000 mask past the base
  # word), keys planted at the first and the last item and in the middle. Too many keys for the
  # reference to walk, so the hits are the planted ones.
  if case("full"):
    pt = rkey()
    tabs = [DES_FULL] * 3
    n = amp_total(tabs)
    bases = [rkey() for _ in range(U)]
    plan = [(0, 0), (1 % U, n - 1), (2 % U, n // 2 + 12345)]
    keys = [plant(bases[j], tabs, it) for j, it in plan]
    targets = [des_encrypt(k, pt) for k in keys]
    jobs = [(800 + i, b) for i, b in enumerate(bases)]
    want = {(800 + j, it, k) for k, (j, it) in enumerate(plan)}
    recs, done, errs, pad = run(exe, work, pt, tabs, targets, jobs, gaps=0)
    results.append(check("full", pt, tabs, targets, jobs, recs, done, errs, pad, U, want=want))

  print("ALL PASS" if all(results) else "*** FAIL ***")
  return 0 if all(results) else 1

if __name__ == "__main__":
  sys.exit(main())
