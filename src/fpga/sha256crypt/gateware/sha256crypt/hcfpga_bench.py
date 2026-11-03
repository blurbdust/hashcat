#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The datapath bench every hcfpga algorithm shares: build rtl/tb_hcfpga.v around the algorithm's
# top with Verilator, run batches through it, check what comes back.
#
# An algorithm's bench (src/fpga/<algo>/gateware/<algo>/tb_datapath.py) supplies the sources, a
# tb_dut.vh that instantiates its top, a reference function and its cases. This module supplies
# what is the same everywhere: the H2C records exactly as the bridge's fill_batch builds them, the
# config words, the run, and the checks of the C2H stream (ids, digests, comparator filtering,
# retired count, end-of-batch records, granule padding, frame status).

import os
import struct
import subprocess
import sys

# This file sits with the algorithm's RTL and the shared RTL, in src/fpga/<algo>/gateware/<algo>/;
# hcfpga_iface.vh is at the top of the algorithm's directory, src/fpga/<algo>/.

RTL   = os.path.dirname(os.path.abspath(__file__))
IFACE = os.path.normpath(os.path.join(RTL, "..", ".."))

CANARY_ID = 0xfffffffe

# The shared RTL, for a bench's source list (the stub only until the core replaces it).
RTL_TAIL = [os.path.join(RTL, f) for f in ["hcfpga_c2h_eob.v", "hcfpga_gen.v", "hcfpga_h2c_intake.v"]]
RTL_JTR  = [os.path.join(RTL, f) for f in ["hcfpga_jtr_unit_feed.v", "hcfpga_jtr_unit_collect.v"]]
RTL_STUB = [os.path.join(RTL, "hcfpga_jtr_unit_stub.v")]

VERILATOR_WARNINGS = ["-Wno-fatal", "-Wno-WIDTH", "-Wno-CASEINCOMPLETE", "-Wno-UNOPTFLAT", "-Wno-PINMISSING",
                      "-Wno-UNSIGNED", "-Wno-REDEFMACRO", "-Wno-IMPLICIT", "-Wno-TIMESCALEMOD", "-Wno-MULTIDRIVEN"]

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
  """salt0..3 as the bridge writes them by default: hashcat's salt_buf[0..3], raw bytes."""
  s = salt.ljust(16, b"\x00")
  return list(struct.unpack("<4I", s))

def bitmap_words(indexes):
  bm = [0, 0, 0, 0]
  for idx in indexes:
    bm[idx // 32] |= 1 << (idx % 32)
  return bm

def cmp_index(digest, cmp_byte=0):
  """The bitmap index the device uses: the low 7 bits of forwarded digest byte cmp_byte."""
  return digest[cmp_byte] & 0x7f

def toy_result(pw, salt, iter_count, result_len):
  """The toy hash of rtl/hcfpga_jtr_unit_stub.v and of a scaffolded engine stub, byte j of result_len:
  pw[j % len] ^ salt[j % 16] ^ ((iter_count + j) & 0xff), with pw[...] = 0 for an empty password."""
  s = salt.ljust(16, b"\x00")[:16]
  out = bytearray()
  for j in range(result_len):
    k = pw[j % len(pw)] if pw else 0
    out.append(k ^ s[j % 16] ^ ((iter_count + j) & 0xff))
  return bytes(out)

def build(work, sources, includes, params, tb_dir):
  """Verilate tb_hcfpga.v with the algorithm's tb_dut.vh (in tb_dir); again whenever an HDL file changed."""
  exe = os.path.join(work, "obj_dir", "Vtb_hcfpga")
  hdl = list(sources) + [os.path.join(RTL, "tb_hcfpga.v")]
  for d in [tb_dir, RTL, IFACE] + list(includes):
    hdl += [os.path.join(d, f) for f in os.listdir(d) if f.endswith((".v", ".vh", ".sv", ".svh"))]
  if os.path.isfile(exe) and os.path.getmtime(exe) >= max(os.path.getmtime(f) for f in hdl):
    return exe
  os.makedirs(work, exist_ok=True)
  cmd = ["verilator", "--binary", "-j", "0", "-O3", "--x-initial", "unique"] + VERILATOR_WARNINGS
  cmd += ["-I" + d for d in [tb_dir, RTL, IFACE] + list(includes)]
  cmd += ["-G%s=%d" % (k, v) for k, v in params.items()]
  cmd += ["--top-module", "tb_hcfpga", "--Mdir", os.path.join(work, "obj_dir"), os.path.join(RTL, "tb_hcfpga.v")]
  cmd += list(sources)
  r = subprocess.run(cmd, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  if r.returncode != 0:
    sys.stdout.write(r.stdout.decode(errors="replace")[-4000:])
    raise SystemExit("verilator build failed")
  return exe

def run_batch(exe, work, salt_cfg, iter_count, cands, bitmap, gaps=1, pad_recs=1, extra=()):
  """One batch. salt_cfg: the four salt register words. extra: the registers from 0x3c on."""
  words, pad = h2c_records(cands)
  cfg = [0] * 32
  cfg[0:4]   = salt_cfg
  cfg[4]     = iter_count
  cfg[6:10]  = bitmap
  cfg[10:14] = [len(cands), pad_recs, len(words), gaps]
  for i, v in enumerate(extra):
    cfg[16 + i] = v
  with open(os.path.join(work, "cfg.hex"), "w") as f:
    f.write("\n".join("%08x" % (w & 0xffffffff) for w in cfg) + "\n")
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

def parts_for(digest_bytes):
  """C2H records per candidate for a device returning digest_bytes: one per 24 (hcfpga_iface.vh)."""
  return max(1, (digest_bytes + 23) // 24)

def check(name, cands, want, bitmap_idx, recs, done, errs, pad, pad_recs=1, digest_bytes=16, cmp_byte=0,
          core_name="units", parts=None, quiet=False):
  """Check one batch.

  want: candidate id -> the digest bytes the candidate must return (digest_bytes of them; with
  several parts, part k carries bytes 24k..24k+23 at C2H bytes 4..27).
  bitmap_idx: the set of bitmap indexes loaded, or None for all ones (every result returns).
  parts: C2H records per candidate, default parts_for(digest_bytes). A returned candidate's parts
  come in a row, same id, part index k in flag bits 8..11; a filtered candidate sends none.
  """
  parts = parts or parts_for(digest_bytes)
  ok = True
  def bad(msg):
    nonlocal ok
    ok = False
    if not quiet:
      print("  %s: %s" % (name, msg))
  bitmap_all = bitmap_idx is None
  expect_ret = {cid for cid, d in want.items() if bitmap_all or cmp_index(d, cmp_byte) in bitmap_idx}
  got = {}
  eob = []
  n_res = 0
  cur = None   # [id, core, [24-byte fields]] of the candidate being read
  for r in recs:
    flags = struct.unpack("<H", r[30:32])[0]
    if flags == 0x8000:
      if cur is not None:
        bad("id %08x ends after %d of %d parts" % (cur[0], len(cur[2]), parts)); cur = None
      eob.append(struct.unpack("<I", r[0:4])[0])
      continue
    n_res += 1
    cid  = struct.unpack("<I", r[0:4])[0]
    core = struct.unpack("<H", r[28:30])[0]
    part = (flags >> 8) & 0xf
    if flags & ~0x0f00:
      bad("id %08x flags %04x" % (cid, flags))
    expect = 0 if cur is None else len(cur[2])
    if part != expect or (cur is not None and cid != cur[0]):
      bad("id %08x part %d where id %s part %d was due" % (cid, part, "%08x" % cur[0] if cur else "(any)", expect))
      cur = None
      if part != 0:
        continue
    if cur is None:
      cur = [cid, core, []]
    cur[2].append(r[4:28])
    if len(cur[2]) < parts:
      continue
    field = b"".join(cur[2])
    cid, core = cur[0], cur[1]
    cur = None
    if field[digest_bytes:] != b"\x00" * (24 * parts - digest_bytes):
      bad("id %08x digest bytes %d.. not zero" % (cid, digest_bytes))
    if cid in got:
      bad("id %08x returned twice" % cid)
    got[cid] = (field[:digest_bytes], core)
  if cur is not None:
    bad("id %08x ends after %d of %d parts" % (cur[0], len(cur[2]), parts))
  for cid, (dig, core) in sorted(got.items()):
    if cid not in want:
      bad("unknown id %08x" % cid); continue
    if dig != want[cid]:
      bad("id %08x digest %s want %s" % (cid, dig.hex(), want[cid].hex()))
  if set(got) != expect_ret:
    bad("returned %s, expected %s" % (sorted("%x" % c for c in got), sorted("%x" % c for c in expect_ret)))
  if n_res != parts * len(got):
    bad("%d result records for %d candidates of %d parts" % (n_res, len(got), parts))
  total = n_res + len(eob)
  if len(eob) < 1 or (total % max(pad_recs, 1)) != 0:
    bad("%d EOB records, %d records in all, pad_recs %d" % (len(eob), total, pad_recs))
  if any(e != len(cands) for e in eob):
    bad("EOB counts %s, want %d" % (eob, len(cands)))
  if done is None:
    bad("no DONE line")
  else:
    retired, status = int(done[0]), int(done[1], 16)
    if retired != len(cands):
      bad("retired %d of %d" % (retired, len(cands)))
    slips = (status >> 8) & 0xff
    if (status & 2) == 0 or slips != pad or (status >> 16) != 0:
      bad("frame status %08x, want last_seen, %d slips, no unit errors" % (status, pad))
  for e in errs:
    bad(e)
  cores = sorted({c for _, c in got.values()})
  if not quiet:
    print("%-10s %s  %d candidates, %d returned%s, %d filtered, %s %s, %s cycles" %
          (name, "PASS" if ok else "FAIL", len(cands), len(got), " in %d records" % n_res if parts > 1 else "",
           len(cands) - len(got), core_name, cores, done[2] if done else "?"))
  return ok

def selftest_parts(parts=2, digest_bytes=40):
  """The checker against hand-made C2H streams: a good batch with a filtered candidate passes; a
  missing part, a repeated part, parts out of order and parts of two candidates mixed fail."""
  def rec(cid, part, field, flags=None):
    f = (part << 8) if flags is None else flags
    return struct.pack("<I", cid) + field + struct.pack("<HH", 0, f)
  def eob(n):
    return struct.pack("<I", n) + bytes(24) + struct.pack("<HH", 0, 0x8000)
  def fields(d):
    d = d.ljust(24 * parts, b"\x00")
    return [d[24 * k:24 * k + 24] for k in range(parts)]
  want = {1: bytes(range(1, 1 + digest_bytes)), 2: bytes(range(101, 101 + digest_bytes)),
          3: bytes([0x7f] * digest_bytes)}
  cands = [(c, b"x") for c in sorted(want)]
  idx = {cmp_index(want[1]), cmp_index(want[2])}           # 3 is filtered: index 0x7f is not loaded
  assert cmp_index(want[3]) not in idx
  good = [rec(1, k, f) for k, f in enumerate(fields(want[1]))] + [rec(2, k, f) for k, f in enumerate(fields(want[2]))]
  done = ["3", "00000002", "0"]
  def run(name, recs, expect):
    r = check(name, cands, want, idx, recs + [eob(3)], done, [], 0, digest_bytes=digest_bytes, parts=parts, quiet=True)
    print("parts %-12s %s (checker says %s, wants %s)" % (name, "PASS" if r == expect else "FAIL", "ok" if r else "broken", "ok" if expect else "broken"))
    return r == expect
  p1 = parts                                              # first record of candidate 2
  res = [run("good", good, True)]
  res.append(run("missing", good[:1] + good[2:], False))
  res.append(run("repeated", good[:1] + good[:1] + good[1:], False))
  res.append(run("swapped", [good[1], good[0]] + good[2:], False))
  res.append(run("mixed", [good[0], good[p1], good[1]] + good[p1 + 1:], False))
  res.append(run("unfiltered", good + [rec(3, k, f) for k, f in enumerate(fields(want[3]))], False))
  return all(res)

if __name__ == "__main__":
  ok = all(selftest_parts(p, 24 * p - 5) for p in (2, 3, 4))
  print("ALL PASS" if ok else "*** FAIL ***")
  sys.exit(0 if ok else 1)
