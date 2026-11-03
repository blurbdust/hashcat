#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Scaffold a new FPGA algorithm on the shared template.
#
#   src/fpga/common/new_fpga_algo.py --name sha256crypt --mode 7400 --core jtr-unit --pw-max 32 --result-len 32
#
# --mode is the upstream hashcat mode N whose hash format the FPGA mode takes; the FPGA mode is
# 90000 + N (unofficial modes live in 90000..99998). Writes, in the hashcat tree:
#
#   src/fpga/<name>/README.md, PROVENANCE.md                  skeletons
#   src/fpga/<name>/gateware/<name>_dma_wrapper.py            an HcfpgaDmaWrapper
#   src/fpga/<name>/gateware/<name>/hcfpga_<name>_top.sv      the top, with a stub core
#   src/fpga/<name>/gateware/<name>/hcfpga_<name>_engine.v    (--core custom) the engine stub
#   src/fpga/<name>/gateware/<name>/tb_dut.vh, tb_datapath.py, <name>_ref.py   the bench
#   src/bridges/bridge_fpga_<name>.c, .mk                     the bridge hooks
#   src/bridges/fpga/hcfpga_<name>_ref.h                      the canary's reference
#   src/modules/module_<90000+N>.c                            from module_<N>.c, bridged
#   OpenCL/m<90000+N>-pure.cl                                 the pass-through kernel
#   tools/test_modules/m<90000+N>.py                          from m<N>.py, constraints narrowed
#
# and adds the mode to tools/test.py's HARDWARE_MODES, the bench to src/fpga/Makefile and a row to
# docs/hashcat-fpga-setup.md's mode table.
#
# --core jtr-unit: John the Ripper's crypt-family units (md5crypt, sha256crypt, sha512crypt) on the
# shared JtR unit feeder and collector; the top starts with hcfpga_jtr_unit_stub.v in place of the
# unit. --core custom: any other core, behind the shared H2C intake and end-of-batch tail; the top
# starts with a one-candidate engine stub. Either way the generated tree builds, lints and passes
# its bench before the real core is in, with a toy hash its references compute too.
#
# A C2H record carries 24 digest bytes. A custom core that returns more (WPA's 32-byte PMK) sends a
# candidate's result in --parts records of 24 bytes each, up to 4; --digest-bytes above 24 sets it.
#
# Every place the port has to decide or fill in is marked HCFPGA-TODO; grep for it. The procedure
# around this is AGENTS.md in the LiteX hashcat Guide.

import argparse
import os
import re
import ast
import sys
import textwrap

COMMON   = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(COMMON, "template")
TREE     = os.path.normpath(os.path.join(COMMON, "..", "..", ".."))

TODO = "HCFPGA-TODO"

# Module functions that belong to the upstream kernel, or that the bridged module answers itself.
MODULE_DROP = [
  "module_deep_comp_kernel", "module_jit_build_options",
  "module_kernel_accel_min", "module_kernel_accel_max", "module_kernel_loops_min", "module_kernel_loops_max",
  "module_kernel_threads_min", "module_kernel_threads_max", "module_unstable_warning", "module_extra_tmp_size",
  "module_tmp_size", "module_pw_max", "module_salt_min", "module_salt_max",
]

# OPTS_TYPE flags that describe the upstream kernel's flow, which the pass-through kernel does not have.
# SELF_TEST_DISABLE goes too: the device computes the upstream example hash, and the self-test is how
# the bridge proves it does.
OPTS_DROP = re.compile(r"OPTS_TYPE_(DEEP_COMP_KERNEL|HOOK\d+|INIT2|LOOP2|LOOP_PREPARE|LOOP_EXTENDED|AUX\d+|MP_MULTI_DISABLE|NATIVE_THREADS|AUTODETECT_DISABLE|SELF_TEST_DISABLE)$")

def die(msg):
  raise SystemExit("new_fpga_algo: " + msg)

# Files --------------------------------------------------------------------------------------------

class Writer:
  def __init__(self, root, force, dry):
    self.root  = root
    self.force = force
    self.dry   = dry
    self.done  = []

  def path(self, rel):
    return os.path.join(self.root, rel)

  def write(self, rel, text, mode=0o644):
    p = self.path(rel)
    if os.path.exists(p) and not self.force:
      die(f"{rel} exists; pass --force to overwrite")
    self.done.append((rel, text.count(TODO)))
    if self.dry:
      return
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
      f.write(text)
    os.chmod(p, mode)

  def edit(self, rel, fn, what):
    p = self.path(rel)
    text = open(p).read()
    new  = fn(text)
    if new == text:
      print(f"  unchanged  {rel} ({what} already there)")
      return
    self.done.append((rel + f" (edited: {what})", 0))
    if not self.dry:
      with open(p, "w") as f:
        f.write(new)

def fill(template, subs):
  text = open(os.path.join(TEMPLATE, template)).read()
  for k, v in subs.items():
    text = text.replace("@@" + k + "@@", str(v))
  left = re.findall(r"@@[A-Z0-9_]+@@", text)
  if left:
    die(f"{template}: unfilled {sorted(set(left))}")
  return text

# Module -------------------------------------------------------------------------------------------

def drop_function(text, name):
  """Remove a top-level function definition (to its closing brace at column 0) and its registration."""
  lines = text.split("\n")
  out   = []
  i     = 0
  found = False
  head  = re.compile(r"^[A-Za-z_][\w \*]*\b" + re.escape(name) + r"\s*\(")
  while i < len(lines):
    if head.match(lines[i]) and not lines[i].rstrip().endswith(";"):
      found = True
      if lines[i].rstrip().endswith("}"):
        i += 1
      else:
        while i < len(lines) and lines[i] != "}":
          i += 1
        i += 1
      if (i < len(lines)) and (lines[i].strip() == "") and out and (out[-1].strip() == ""):
        i += 1
      continue
    if re.match(r"^\s*module_ctx->" + re.escape(name) + r"\s*=", lines[i]):
      i += 1
      continue
    out.append(lines[i])
    i += 1
  return "\n".join(out), found

def bridged_module(text, a):
  notes = []

  def sub(pattern, repl, what, flags=0):
    nonlocal text
    new, n = re.subn(pattern, repl, text, count=1, flags=flags)
    if n != 1:
      die(f"upstream module: could not {what}")
    text = new

  fast_dropped = []
  if "ATTACK_EXEC_INSIDE_KERNEL" in text:
    # A fast hash upstream (descrypt). The bridge replaces the loop of the slow-hash flow, so the bridged
    # mode takes that shape: init, the loop, comp. The upstream kernel's own build options go with it.
    sub(r"ATTACK_EXEC_INSIDE_KERNEL", "ATTACK_EXEC_OUTSIDE_KERNEL", "switch ATTACK_EXEC")
    for fn in ("module_jit_cache_disable",):
      text, found = drop_function(text, fn)
      if found:
        fast_dropped.append(fn)
    for pat in (r"\n\s*\|\s*OPTI_TYPE_REGISTER_LIMIT\b", r"\bOPTI_TYPE_REGISTER_LIMIT\s*\n\s*\|\s*"):
      text, n = re.subn(pat, "", text, count=1)
      if n:
        fast_dropped.append("OPTI_TYPE_REGISTER_LIMIT")
        break
    text = re.sub(r"(OPTI_TYPE\s*=\s*)OPTI_TYPE_REGISTER_LIMIT;", r"\g<1>0;", text)
    notes.append(f"// Mode {a.mode} is a fast hash (ATTACK_EXEC_INSIDE_KERNEL); this mode has the slow-hash shape the bridge\n"
                 f"// needs (ATTACK_EXEC_OUTSIDE_KERNEL)." + ("\n// Dropped with the upstream fast kernel: " + ", ".join(fast_dropped) + "." if fast_dropped else "") + "\n"
                 f"// {TODO}: a fast mode's parser may leave salt->salt_iter at 0. The bridge spreads candidates over\n"
                 f"// hashcat's loop calls by it, so module_hash_decode sets it to the device's count.")
  elif "ATTACK_EXEC_OUTSIDE_KERNEL" not in text:
    notes.append(f"// {TODO}: the upstream mode's ATTACK_EXEC is neither OUTSIDE_KERNEL nor INSIDE_KERNEL; the bridged\n"
                 f"// mode must be ATTACK_EXEC_OUTSIDE_KERNEL.")

  # KERN_BITS names the upstream kernel's extra kernels (loop prepare, loop extended, init2, hooks, TM).
  # The pass-through kernel has only init, loop and comp, so they go. AUX kernels are comp variants a
  # mode may still need (WPA's per key version); those stay, flagged.
  aux = []
  m = re.search(r"static const u64\s+KERN_BITS\s*=\s*([^;]*);\n", text)
  if m:
    bits = re.findall(r"KERN_BIT_\w+", m.group(1))
    aux  = [b for b in bits if re.match(r"KERN_BIT_AUX\d+$", b)]
    gone = [b for b in bits if b not in aux]
    if aux:
      indent = " " * (m.group(0).index("=") + 2)
      text = text[:m.start()] + "static const u64   KERN_BITS      = " + ("\n" + indent[:-2] + "| ").join(aux) + ";\n" + text[m.end():]
      notes.append(textwrap.fill(f"{TODO}: KERN_BITS keeps the upstream AUX kernels ({', '.join(aux)}); the scaffold's "
                                 f"pass-through kernel has none. Give m{a.fpga_mode}-pure.cl the upstream comp and aux kernels, "
                                 f"reading the digest from the bridge's tmp struct.", width=100,
                                 initial_indent="// ", subsequent_indent="// "))
    else:
      text = text[:m.start()] + text[m.end():]
      text, _ = drop_function(text, "module_kern_bits")
    if gone:
      notes.append("// Dropped from KERN_BITS with the upstream kernel: " + ", ".join(gone) + ".")

  # OPTI_TYPE flags that describe the upstream init and loop kernels, which the bridge replaces.
  simd_gone = []
  for flag in ("OPTI_TYPE_SLOW_HASH_SIMD_INIT", "OPTI_TYPE_SLOW_HASH_SIMD_LOOP", "OPTI_TYPE_SLOW_HASH_SIMD_LOOP2"):
    for pat in (r"\n\s*\|\s*" + flag + r"\b", r"\b" + flag + r"\s*\n\s*\|\s*", r"(?<=OPTI_TYPE      = )" + flag + r"(?=;)"):
      text, n = re.subn(pat, "0" if pat.startswith("(?<=") else "", text, count=1)
      if n:
        simd_gone.append(flag)
        break
  if simd_gone:
    notes.append("// Dropped from OPTI_TYPE with the upstream init and loop kernels: " + ", ".join(simd_gone) + ".")

  sub(r"(\*/\n)", r"\1\n// @@@INTRO@@@\n", "find the license header")

  sub(r'(static const char \*HASH_NAME\s*=\s*")([^"]*)(";)', r'\1\2 [Bridged: FPGA]\3', "find HASH_NAME")
  sub(r"(static const u64\s+KERN_TYPE\s*=\s*)\d+;", r"\g<1>%d;" % a.fpga_mode, "find KERN_TYPE")

  m = re.search(r"(static const u64\s+OPTS_TYPE\s*=\s*)([^;]*);", text)
  if m is None:
    die("upstream module: could not find OPTS_TYPE")
  flags   = re.findall(r"OPTS_TYPE_\w+", m.group(2))
  # A mode that keeps upstream's AUX comp kernels runs them from the deep comp kernel: keep that flag.
  drop    = lambda f: OPTS_DROP.match(f) and not (aux and f == "OPTS_TYPE_DEEP_COMP_KERNEL")
  dropped = [f for f in flags if drop(f)]
  kept    = [f for f in flags if not drop(f)] + ["OPTS_TYPE_NATIVE_THREADS", "OPTS_TYPE_AUTODETECT_DISABLE"]
  indent  = " " * (len(m.group(1)) - 2)
  opts    = m.group(1) + ("\n" + indent + "| ").join(kept) + ";"
  text    = text[:m.start()] + opts + text[m.end():]
  dropped = [f for f in dropped if f not in ("OPTS_TYPE_NATIVE_THREADS", "OPTS_TYPE_AUTODETECT_DISABLE")]
  if dropped:
    notes.append("// Dropped from OPTS_TYPE with the upstream kernel: " + ", ".join(dropped) + ".")

  sub(r"(static const u32\s+SALT_TYPE\s*=\s*[^;]*;\n)",
      r"\1static const u64   BRIDGE_TYPE    = BRIDGE_TYPE_REPLACE_LOOP\n"
      r"                                  | BRIDGE_TYPE_LOOP_CHUNKED;\n"
      r'static const char *BRIDGE_NAME    = "fpga_%s";\n' % a.name, "find SALT_TYPE")

  dropped_fns = []
  for fn in MODULE_DROP:
    if aux and fn == "module_deep_comp_kernel":
      continue
    text, found = drop_function(text, fn)
    if found:
      dropped_fns.append(fn)

  # The upstream tmp struct is the upstream kernel's; nothing references it once module_tmp_size is gone.
  for m in list(re.finditer(r"typedef struct \w+\n\{\n.*?\n\} (\w+);\n\n?", text, re.S)):
    tname = m.group(1)
    if tname.endswith("_tmp_t") and text.count(tname) == 1:
      text = text.replace(m.group(0), "")
      dropped_fns.append("typedef " + tname)

  limits = f"""
// The device's limits, see src/fpga/{a.name}/README.md. {TODO}: check each against the core.

static const u32   FPGA_PW_MAX    = {a.pw_max};
static const u32   FPGA_SALT_MIN  = {a.salt_min};
static const u32   FPGA_SALT_MAX  = {a.salt_max}; // 0: no limit beyond the upstream parser's
static const u32   FPGA_ITER_MIN  = {a.iter_min};
static const u32   FPGA_ITER_MAX  = {a.iter_max}; // 0: no limit beyond the upstream parser's

const char *module_bridge_name    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) {{ return BRIDGE_NAME;     }}
u64         module_bridge_type    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) {{ return BRIDGE_TYPE;     }}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{{
  const u32 kernel_loops_max = (FPGA_ITER_MAX > 0) ? FPGA_ITER_MAX : (1u << 20);

  return kernel_loops_max;
}}

// The tmp struct the kernel (m{a.fpga_mode}-pure.cl) and the bridge (bridge_fpga_{a.name}.c) share.

typedef struct {a.name}_bridge_tmp
{{
  u32 pw_len;

  u32 pw_buf[{a.pw_words}];

  u32 digest[{a.digest_words}];

}} {a.name}_bridge_tmp_t;

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{{
  const u64 tmp_size = (const u64) sizeof ({a.name}_bridge_tmp_t);

  return tmp_size;
}}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{{
  const u32 pw_max = FPGA_PW_MAX;

  return pw_max;
}}

u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{{
  const u32 salt_min = FPGA_SALT_MIN;

  return salt_min;
}}

u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{{
  const u32 salt_max = (FPGA_SALT_MAX > 0) ? FPGA_SALT_MAX : SALT_MAX;

  return salt_max;
}}
"""
  sub(r'(#include "hooks_common.c"\n)', lambda m: m.group(1) + limits, "find the hooks_common.c include")

  # The device's limits at parse time, before the decoder's last return.
  m = re.search(r"\nint module_hash_decode \(.*?\n\}\n", text, re.S)
  if m is None:
    die("upstream module: could not find module_hash_decode")
  body = m.group(0)
  k = body.rfind("  return (PARSER_OK);")
  if k < 0:
    die("upstream module: module_hash_decode does not end in return (PARSER_OK)")
  check = (f"  // The device's limits. {TODO}: place these where the parser has set what they check, and add\n"
           f"  // anything else the device cannot compute.\n\n"
           f"  if (salt->salt_len < FPGA_SALT_MIN) return (PARSER_SALT_LENGTH);\n"
           f"  if ((FPGA_SALT_MAX > 0) && (salt->salt_len > FPGA_SALT_MAX)) return (PARSER_SALT_LENGTH);\n\n"
           f"  if (salt->salt_iter < FPGA_ITER_MIN) return (PARSER_SALT_ITERATION);\n"
           f"  if ((FPGA_ITER_MAX > 0) && (salt->salt_iter > FPGA_ITER_MAX)) return (PARSER_SALT_ITERATION);\n\n")
  body = body[:k] + check + body[k:]
  text = text[:m.start()] + body + text[m.end():]

  # module_init: the upstream registrations that are left, plus the bridged module's, in order.
  m = re.search(r"void module_init \(module_ctx_t \*module_ctx\)\n\{\n((?:.*\n)*?)\}\n", text)
  if m is None:
    die("upstream module: could not find module_init")
  regs = {sl: sl for sl in re.findall(r"^\s*module_ctx->(\w+)\s*=\s*\1;", m.group(1), re.M)}
  # Registrations of shared helpers (scrypt_common.c, wpa_common.c): those about the upstream kernel's
  # memory and tuning go, the module's own (options, benchmark cost) stay.
  kernel_slots = set(MODULE_DROP) | {"module_extra_buffer_size", "module_extra_tuningdb_block",
                                     "module_jit_cache_disable", "module_kern_bits"}
  helpers = [(sl, fn) for sl, fn in re.findall(r"^\s*module_ctx->(\w+)\s*=\s*(\w+);", m.group(1), re.M)
             if fn != sl and fn != "MODULE_DEFAULT"]
  gone = [fn for sl, fn in helpers if sl in kernel_slots]
  for sl, fn in helpers:
    if sl not in kernel_slots:
      regs[sl] = fn
  if gone:
    listed = textwrap.fill(", ".join(gone) + ".", width=96, initial_indent="// ", subsequent_indent="// ")
    notes.append(f"// Dropped with the upstream kernel (its memory and tuning): the registrations of\n" + listed)
  kept_helpers = [fn for sl, fn in helpers if sl not in kernel_slots]
  if kept_helpers:
    notes.append(textwrap.fill(f"{TODO}: the module keeps these upstream helper registrations: "
                               + ", ".join(kept_helpers) + ". Check them.", width=100,
                               initial_indent="// ", subsequent_indent="// "))
  if helpers:
    notes.append("// Drop a helper's #include if nothing uses it any more.")
  for sl in ("module_bridge_name", "module_bridge_type", "module_kernel_loops_max", "module_pw_max",
             "module_salt_max", "module_salt_min", "module_tmp_size"):
    regs[sl] = sl
  other = [l for l in m.group(1).split("\n") if l.strip() and not re.match(r"^\s*module_ctx->\w+\s*=", l)]
  body  = "\n".join(other) + "\n\n" + "".join("  module_ctx->%-31s = %s;\n" % (sl, regs[sl]) for sl in sorted(regs))
  text  = text[:m.start(1)] + body + text[m.end(1):]

  intro = (f"{a.name} computed on an FPGA through the fpga_{a.name} bridge (src/fpga/{a.name}). Generated by\n"
           f"// src/fpga/common/new_fpga_algo.py from module_{a.up5}.c: hash format, example hash and self-test are\n"
           f"// mode {a.mode}'s; the kernel is a pass-through and the bridge replaces the loop.")
  if dropped_fns:
    intro += "\n// Dropped with the upstream kernel: " + ", ".join(dropped_fns) + "."
  for n in notes:
    intro += "\n" + n
  text = text.replace("// @@@INTRO@@@\n", "// " + intro + "\n")
  return text

def bridged_test_module(text, a):
  # The salt entry is the length of the salt string module_generate_hash gets, which is not hashcat's
  # salt_len (descrypt: 2 characters, salt_len 4), so the upstream entry is kept for the port to narrow.
  def constraints(m):
    up = re.search(r"return\s*(\[\[.*\]\])", m.group(2))
    try:
      up_pw, up_salt = ast.literal_eval(up.group(1))[:2]
    except Exception:
      up_pw, up_salt = [0, 256], [0, 256]
    pw = [up_pw[0], min(up_pw[1], a.pw_max)]
    return (m.group(1) + f"  # {TODO}: the device's limits: [pure pw, pure salt, optimized pw, optimized salt, combined].\n"
                         f"  # The salt entry is mode {a.mode}'s (a salt string length); narrow it to the salt strings the device takes.\n"
                         f"  return [{pw}, {list(up_salt)}, [-1, -1], [-1, -1], [-1, -1]]\n")
  text, n = re.subn(r"(def module_constraints\(\):\n)((?:[ \t]+.*\n)+)", constraints, text, count=1)
  if n != 1:
    text += f"\n\n# {TODO}: module_constraints() with the device's limits.\n"
  head = (f"\n# {a.name} computed on an FPGA (fpga_{a.name} bridge). The oracle is mode {a.mode}'s; the constraints\n"
          f"# are the device's. {TODO}: module_generate_hash must only produce what the device computes (salt\n"
          f"# lengths, rounds), or test.py feeds the bridge hashes it refuses.\n")
  m = re.search(r"\n##\n\n", text)
  if m:
    text = text[:m.end()] + head.lstrip("\n") + "\n" + text[m.end():]
  else:
    text = head + text
  return text

# Main ---------------------------------------------------------------------------------------------

def main():
  ap = argparse.ArgumentParser(description="Scaffold a new hcfpga algorithm in the hashcat tree.")
  ap.add_argument("--name", required=True, help="algorithm name: lower case, digits, underscore (sha256crypt)")
  ap.add_argument("--mode", required=True, type=int, help="the upstream hashcat mode whose format it takes; the FPGA mode is 90000 + this")
  ap.add_argument("--fpga-mode", type=int, default=None, help="the FPGA mode, when 90000 + mode does not fit 90000..99998 (WPA: --mode 22000 --fpga-mode 92500)")
  ap.add_argument("--core", choices=["jtr-unit", "custom"], default="jtr-unit",
                  help="jtr-unit: John the Ripper crypt-family units on the shared feeder/collector; custom: any other core")
  ap.add_argument("--pw-max", type=int, default=64, help="longest password the core takes (bytes)")
  ap.add_argument("--digest-words", type=int, default=4, help="32-bit digest words in the tmp struct, at least DGST_POS3 + 1 (max 6 per C2H part)")
  ap.add_argument("--digest-bytes", type=int, default=None, help="digest bytes the device returns (default 4 * digest-words; 24 per C2H part, max 96)")
  ap.add_argument("--parts", type=int, default=None, help="custom: C2H records per candidate, 1 to 4, 24 digest bytes each (default: what --digest-bytes needs)")
  ap.add_argument("--result-len", type=int, default=None, help="jtr-unit: JtR's RESULT_LEN, result bytes after the IDs (default digest-bytes)")
  ap.add_argument("--key-align", type=int, choices=[4, 8], default=4, help="jtr-unit: key alignment in the unit packet (sha512crypt: 8)")
  ap.add_argument("--cores-per-unit", type=int, default=1, help="jtr-unit: cores per unit as the identity counts them (stub: 1)")
  ap.add_argument("--grain", type=int, default=1, help="candidates in flight per identity core (stub: 1)")
  ap.add_argument("--salt-min", type=int, default=0, help="shortest salt the core takes")
  ap.add_argument("--salt-max", type=int, default=0, help="longest salt the core takes, 0 for no limit")
  ap.add_argument("--iter-min", type=int, default=1, help="lowest iteration count the core takes")
  ap.add_argument("--iter-max", type=int, default=0, help="highest iteration count the core takes, 0 for no limit")
  ap.add_argument("--root", default=TREE, help="hashcat tree to write into (default: the one this script is in)")
  ap.add_argument("--force", action="store_true", help="overwrite files that exist")
  ap.add_argument("--dry-run", action="store_true", help="say what would be written")
  a = ap.parse_args()

  if not re.match(r"^[a-z][a-z0-9_]*$", a.name):
    die("--name: lower case letters, digits and underscore, starting with a letter")
  if a.name == "bcrypt" or a.name == "common":
    die(f"--name {a.name} is taken")
  if a.mode < 0:
    die("--mode: an upstream hashcat mode")
  if a.fpga_mode is None:
    if a.mode > 9998:
      die(f"--mode {a.mode}: 90000 + mode is past 99998, where unofficial modes end. Give --fpga-mode\n"
          "(the number is the project owner's choice; WPA's 22000 became 92500)")
    a.fpga_mode = 90000 + a.mode
  if not (90000 <= a.fpga_mode <= 99998):
    die("--fpga-mode: unofficial modes are 90000 to 99998")
  a.up5       = "%05d" % a.mode
  if not (1 <= a.digest_words <= 24):
    die("--digest-words: 1 to 24 (a C2H record carries 24 digest bytes, a candidate up to 4 records)")
  a.digest_bytes = a.digest_bytes or 4 * a.digest_words
  if not (1 <= a.digest_bytes <= min(96, 4 * a.digest_words)):
    die("--digest-bytes: 1 to 4 * digest-words, at most 96 (4 C2H records of 24)")
  need = (a.digest_bytes + 23) // 24
  a.parts = a.parts or need
  if not (1 <= a.parts <= 4) or a.parts < need:
    die(f"--parts: 1 to 4 C2H records per candidate, at least {need} for {a.digest_bytes} digest bytes")
  if a.digest_words > 6 * a.parts:
    die(f"--digest-words: at most 6 per C2H part ({6 * a.parts} with --parts {a.parts})")
  if a.parts > 1 and a.core != "custom":
    die("--parts above 1 (more than 24 digest bytes) needs --core custom: hcfpga_jtr_unit_collect.v sends one\n"
        "C2H record per candidate")
  a.result_len = a.result_len or a.digest_bytes
  if a.iter_min < 1:
    die("--iter-min: at least 1. The bridge spreads candidates over hashcat's loop calls by the iteration\n"
        "count; a fixed-count algorithm gives its count (descrypt: --iter-min 25 --iter-max 25)")
  if a.result_len < a.digest_bytes or a.result_len % 2:
    die("--result-len: even, and at least digest-bytes")
  if not (1 <= a.pw_max <= 124):
    die("--pw-max: 1 to 124")
  a.pw_words = (a.pw_max + 3) // 4

  root = os.path.abspath(a.root)
  for need in ["src/modules", "src/bridges/fpga/hcfpga_bridge.h", "src/fpga/common", "tools/test.py"]:
    if not os.path.exists(os.path.join(root, need)):
      die(f"{root} is not a hashcat tree with the FPGA template ({need} missing)")

  up_module = os.path.join(root, "src", "modules", f"module_{a.up5}.c")
  if not os.path.isfile(up_module):
    die(f"no upstream module {up_module}")
  up_test = os.path.join(root, "tools", "test_modules", f"m{a.up5}.py")

  jtr = (a.core == "jtr-unit")

  subs = dict(
    ALGO=a.name, ALGO_UC=a.name.upper(), CLASS=a.name.capitalize(), MODE=a.fpga_mode, UPMODE=a.mode, UPMODE5=a.up5,
    PW_MAX=a.pw_max, PW_WORDS=a.pw_words, DIGEST_WORDS=a.digest_words, DIGEST_BYTES=a.digest_bytes,
    RESULT_LEN=a.result_len, KEY_ALIGN=a.key_align, GRAIN=a.grain, CORES_PER_UNIT=a.cores_per_unit, PARTS=a.parts,
    SALT_MIN=a.salt_min, SALT_MAX=a.salt_max, ITER_MIN=a.iter_min, ITER_MAX=a.iter_max,
    CORE_NAME=("unit" if jtr else "core"), FLAVOUR=a.core,
    SCAFFOLD_ARGS=" ".join(sys.argv[1:]),
    STUB_SOURCES=("hb.RTL_STUB" if jtr else "the engine stub"),
    RTL_SOURCES=("hb.RTL_JTR + hb.RTL_STUB" if jtr else f"[os.path.join(HERE, \"hcfpga_{a.name}_engine.v\")]"),
    EXTRA_REGS=("[len(salt)]" if jtr else "[]"),
    CANARY_PW=("NULL" if a.pw_max >= 18 else '"%s"' % "hcfpga-ztex-canary"[:a.pw_max]),
  )
  if jtr:
    subs["CONFIG_EXTRA"] = (
      "// The registers beyond the shared block, in the wrapper's EXTRA_CSRS order. The JtR unit packet\n"
      "// carries the salt length. " + TODO + ": any other register the core needs.\n\n"
      "#define CSR_SALT_LEN  HCFPGA_CSR_EXTRA (0)\n\n"
      f"static bool {a.name}_config_extra (hcfpga_cfg_t *cfg, const salt_t *salt)\n"
      "{\n"
      "  return hcfpga_cfg_write (cfg, CSR_SALT_LEN, salt->salt_len, \"salt_len\");\n"
      "}\n")
    subs["CONFIG_EXTRA_FN"] = f"{a.name}_config_extra"
  else:
    subs["CONFIG_EXTRA"] = (
      "// " + TODO + ": the registers beyond the shared block, in the wrapper's EXTRA_CSRS order, written\n"
      "// by a config_extra hook with hcfpga_cfg_write (cfg, HCFPGA_CSR_EXTRA (n), value, \"name\").\n")
    subs["CONFIG_EXTRA_FN"] = "NULL"

  w = Writer(root, a.force, a.dry_run)

  algo_dir = f"src/fpga/{a.name}"
  gw       = f"{algo_dir}/gateware/{a.name}"
  flav     = "jtr" if jtr else "custom"

  w.write(f"{algo_dir}/README.md",     fill("README.md.in", subs))
  w.write(f"{algo_dir}/PROVENANCE.md", fill("PROVENANCE.md.in", subs))
  w.write(f"{algo_dir}/gateware/{a.name}_dma_wrapper.py", fill(f"gateware/wrapper_{flav}.py.in", subs))
  w.write(f"{gw}/hcfpga_{a.name}_top.sv", fill(f"gateware/top_{flav}.sv.in", subs))
  if not jtr:
    w.write(f"{gw}/hcfpga_{a.name}_engine.v", fill("gateware/engine_custom.v.in", subs))
  w.write(f"{gw}/tb_dut.vh",          fill(f"gateware/tb_dut_{flav}.vh.in", subs))
  w.write(f"{gw}/tb_datapath.py",     fill("gateware/tb_datapath.py.in", subs), 0o755)
  w.write(f"{gw}/{a.name}_ref.py",    fill("gateware/ref.py.in", subs))

  w.write(f"src/bridges/bridge_fpga_{a.name}.c",  fill("bridge.c.in", subs))
  w.write(f"src/bridges/bridge_fpga_{a.name}.mk", fill("bridge.mk.in", subs))
  w.write(f"src/bridges/fpga/hcfpga_{a.name}_ref.h", fill("ref.h.in", subs))
  w.write(f"OpenCL/m{a.fpga_mode}-pure.cl", fill("kernel.cl.in", subs))

  w.write(f"src/modules/module_{a.fpga_mode}.c", bridged_module(open(up_module).read(), a))

  if os.path.isfile(up_test):
    w.write(f"tools/test_modules/m{a.fpga_mode}.py", bridged_test_module(open(up_test).read(), a), 0o755)
  else:
    print(f"  no tools/test_modules/m{a.up5}.py upstream: write tools/test_modules/m{a.fpga_mode}.py by hand ({TODO})")

  def add_hw_mode(text):
    m = re.search(r"HARDWARE_MODES = \{([^}]*)\}", text)
    if m is None:
      die("tools/test.py has no HARDWARE_MODES")
    modes = {int(x) for x in re.findall(r"\d+", m.group(1))} | {a.fpga_mode}
    return text[:m.start()] + "HARDWARE_MODES = {" + ", ".join(str(x) for x in sorted(modes)) + "}" + text[m.end():]
  w.edit("tools/test.py", add_hw_mode, f"mode {a.fpga_mode} in HARDWARE_MODES")

  def add_sim(text):
    if f"SIM_SCRIPT_{a.name} " in text:
      return text
    anchor = "SIM_SCRIPT      := $(SIM_SCRIPT_$(ALGO))"
    if anchor not in text:
      die("src/fpga/Makefile: no SIM_SCRIPT line to add the bench before")
    block = f"SIM_SCRIPT_{a.name} := {a.name}/gateware/{a.name}/tb_datapath.py\n\nSIM_TOOL_{a.name} := verilator\n\n"
    return text.replace(anchor, block + anchor, 1)
  w.edit("src/fpga/Makefile", add_sim, f"the {a.name} bench")

  def add_doc(text):
    if f"`fpga_{a.name}`" in text:
      return text
    m = re.search(r"(## Hash modes\n\n\| Mode .*\n\|[-| ]+\n(?:\|.*\n)*)", text)
    if m is None:
      print(f"  docs/hashcat-fpga-setup.md: no mode table found, add mode {a.fpga_mode} by hand ({TODO})")
      return text
    # In mode order: the new row goes before the first row with a higher mode.
    row  = "| %-5d | %-9s | %-15s |\n" % (a.fpga_mode, a.name, f"`fpga_{a.name}`")
    rows = list(re.finditer(r"^\| (\d+) +\|.*\n", m.group(1), re.M))
    at   = m.end()
    for r in rows:
      if int(r.group(1)) > a.fpga_mode:
        at = m.start() + r.start()
        break
    return text[:at] + row + text[at:]
  if os.path.isfile(os.path.join(root, "docs/hashcat-fpga-setup.md")):
    w.edit("docs/hashcat-fpga-setup.md", add_doc, f"mode {a.fpga_mode} in the mode table")

  print(("Would write" if a.dry_run else "Wrote") + f" {a.name}, mode {a.fpga_mode} from mode {a.mode}, core {a.core}, into {root}:")
  for rel, todos in w.done:
    print("  %-62s %s" % (rel, f"{todos} {TODO}" if todos else ""))
  print(f"""
Next, from {root}:
  make -C src/fpga sim ALGO={a.name}                      the bench (stub core: passes before the core is in)
  make bridges/bridge_fpga_{a.name}.so modules/module_{a.fpga_mode}.so
  src/fpga/common/hcfpga_sim.py --algo {a.name} --bridge uartbone --build-only
  grep -rn {TODO} {algo_dir} src/bridges/bridge_fpga_{a.name}.c src/bridges/fpga/hcfpga_{a.name}_ref.h src/modules/module_{a.fpga_mode}.c tools/test_modules/m{a.fpga_mode}.py
Then follow AGENTS.md in the LiteX hashcat Guide.""")

if __name__ == "__main__":
  main()
