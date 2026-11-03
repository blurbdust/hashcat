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

COMMON = os.path.dirname(os.path.abspath(__file__))
RTL    = os.path.join(COMMON, "rtl")

CANARY_ID = 0xfffffffe

# The shared RTL, for a bench's source list.
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
  """Verilate tb_hcfpga.v with the algorithm's tb_dut.vh (in tb_dir) once per work directory."""
  exe = os.path.join(work, "obj_dir", "Vtb_hcfpga")
  if os.path.isfile(exe):
    return exe
  os.makedirs(work, exist_ok=True)
  cmd = ["verilator", "--binary", "-j", "0", "-O3", "--x-initial", "unique"] + VERILATOR_WARNINGS
  cmd += ["-I" + d for d in [tb_dir, RTL] + list(includes)]
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

def check(name, cands, want, bitmap_idx, recs, done, errs, pad, pad_recs=1, digest_bytes=16, cmp_byte=0,
          core_name="units"):
  """Check one batch.

  want: candidate id -> the digest bytes the record must carry (C2H bytes 4..4+digest_bytes-1).
  bitmap_idx: the set of bitmap indexes loaded, or None for all ones (every result returns).
  """
  ok = True
  bitmap_all = bitmap_idx is None
  expect_ret = {cid for cid, d in want.items() if bitmap_all or cmp_index(d, cmp_byte) in bitmap_idx}
  got = {}
  eob = []
  for r in recs:
    flags = struct.unpack("<H", r[30:32])[0]
    if flags == 0x8000:
      eob.append(struct.unpack("<I", r[0:4])[0])
      continue
    cid  = struct.unpack("<I", r[0:4])[0]
    core = struct.unpack("<H", r[28:30])[0]
    dig  = r[4:4 + digest_bytes]
    if r[4 + digest_bytes:28] != b"\x00" * (24 - digest_bytes):
      print("  %s: id %08x bytes %d..27 not zero" % (name, cid, 4 + digest_bytes)); ok = False
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
    retired, status = int(done[0]), int(done[1], 16)
    if retired != len(cands):
      print("  %s: retired %d of %d" % (name, retired, len(cands))); ok = False
    slips = (status >> 8) & 0xff
    if (status & 2) == 0 or slips != pad or (status >> 16) != 0:
      print("  %s: frame status %08x, want last_seen, %d slips, no unit errors" % (name, status, pad)); ok = False
  for e in errs:
    print("  %s: %s" % (name, e)); ok = False
  cores = sorted({c for _, c in got.values()})
  print("%-10s %s  %d candidates, %d returned, %d filtered, %s %s, %s cycles" %
        (name, "PASS" if ok else "FAIL", len(cands), len(got), len(cands) - len(got), core_name, cores,
         done[2] if done else "?"))
  return ok
