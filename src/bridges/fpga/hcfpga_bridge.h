/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_FPGA_HCFPGA_BRIDGE_H
#define HC_FPGA_HCFPGA_BRIDGE_H

// The FPGA bridge every algorithm after bcrypt shares (hcfpga_bridge.c), and the hooks an algorithm
// fills in. bcrypt keeps its own bridge (bridge_fpga_bcrypt.c), which this one was derived from.
//
// An algorithm's bridge is one small file, src/bridges/bridge_fpga_<algo>.c: its tmp struct (the
// same one its module and kernel use), its hook functions, one hcfpga_algo_t, and
//
//   void bridge_init (bridge_ctx_t *bridge_ctx) { hcfpga_bridge_init (bridge_ctx, &ALGO); }
//
// Everything around a batch is shared: board discovery and sessions, units and the worker pool,
// H2C records, the comparator bitmap, arming, the end-of-batch record, timeouts, retries, fault
// injection, known-answer canaries, timing, temperature and link reporting. What differs between
// algorithms is in hcfpga_algo_t.
//
// The device side is src/fpga/common: the register block (HcfpgaDmaWrapper), the H2C record
// (hcfpga_h2c_intake.v), the C2H record and its end-of-batch tail (hcfpga_c2h_eob.v).

#include <stddef.h>

#include "common.h"
#include "types.h"
#include "bridges.h"

#include "fpga/hcfpga.h"

// Registers. The algorithm bank is at 0; these are the offsets every algorithm shares.

#define HCFPGA_CSR_CTRL          0x00
#define HCFPGA_CSR_SALT0         0x04
#define HCFPGA_CSR_SALT1         0x08
#define HCFPGA_CSR_SALT2         0x0c
#define HCFPGA_CSR_SALT3         0x10
#define HCFPGA_CSR_ITER_COUNT    0x14
#define HCFPGA_CSR_STATUS        0x18
#define HCFPGA_CSR_CORE_COUNT    0x1c
#define HCFPGA_CSR_CMP_BM0       0x20
#define HCFPGA_CSR_CMP_BM1       0x24
#define HCFPGA_CSR_CMP_BM2       0x28
#define HCFPGA_CSR_CMP_BM3       0x2c
#define HCFPGA_CSR_BATCH_TARGET  0x30
#define HCFPGA_CSR_PAD_RECS      0x34
#define HCFPGA_CSR_RETIRED       0x38

// An algorithm's own registers follow, in the order of its wrapper's EXTRA_CSRS.

#define HCFPGA_CSR_EXTRA(n)      (0x3c + (4 * (n)))

// A C2H record has room for 24 digest bytes (bytes 4..27). A device that returns more sends up to
// HCFPGA_C2H_PARTS_MAX records per candidate (hcfpga_algo_t.c2h_parts), 24 digest bytes each.

#define HCFPGA_C2H_PART_WORDS    6
#define HCFPGA_C2H_PARTS_MAX     4

#define HCFPGA_DIGEST_WORDS_MAX  (HCFPGA_C2H_PART_WORDS * HCFPGA_C2H_PARTS_MAX)

// Batch timeout and fixed tuning, per board: cycles = cycles_per_iter * iterations + cycles_per_wave
// at the identity's clock, launch_usec on top. Rows are measured on hardware with the Guide's
// debug/hcfpga_step.py --wave-model. A board without a row is autotuned by hashcat.

typedef struct hcfpga_wave_model
{
  const char *board;

  u32 cores;

  u32 cycles_per_iter;
  u32 cycles_per_wave;
  u32 launch_usec;

} hcfpga_wave_model_t;

// Handed to the config_extra hook: hcfpga_cfg_write () writes one register and reads it back,
// retrying as the shared registers are written. The hook returns false if a write fails.

typedef struct hcfpga_cfg hcfpga_cfg_t;

bool hcfpga_cfg_write (hcfpga_cfg_t *cfg, const u32 addr, const u32 val, const char *name);

typedef struct hcfpga_algo
{
  // Identity: the algo= the device reports, and the bridge's name in messages.

  const char *name;

  // The tmp struct the module, its kernel and this bridge share, by HCFPGA_TMP_LAYOUT (type):
  //
  //   typedef struct { u32 pw_len; u32 pw_buf[N]; u32 digest[M]; } <algo>_bridge_tmp_t;
  //
  // The kernel's init copies the candidate in, the bridge fills digest, the kernel's comp compares
  // digest[DGST_R0..3]. M is the number of 32-bit words the device returns from C2H byte 4, at
  // most HCFPGA_C2H_PART_WORDS per C2H part (c2h_parts below), and they are hashcat's digest_buf
  // words 0..M-1.

  size_t tmp_size;
  size_t tmp_pw_len_off;
  size_t tmp_pw_buf_off;
  size_t tmp_digest_off;
  u32    tmp_pw_words;
  u32    digest_words;

  // C2H records per candidate. 0 or 1: one record, digest bytes 0..23. P = 2 to
  // HCFPGA_C2H_PARTS_MAX: P records in a row with the same id, record k carrying digest bytes
  // 24k..24k+23 at C2H bytes 4..27 and its part index k in flag bits 8..11. The device's
  // comparator decides on the candidate from the first part; a filtered candidate sends no record,
  // and the candidate retires once, after its last part, so the end-of-batch count stays a
  // candidate count. The identity says parts=P when P > 1; a board that disagrees is refused.
  // A missing, repeated or out-of-order part fails the batch, which is redone.

  u32    c2h_parts;

  // The longest password the device takes (the H2C record's len, at most tmp_pw_words * 4), and
  // the module's module_pw_max.

  u32 pw_max;

  // Candidates in flight per core the identity's cores= counts: the batch grain. bcrypt 1,
  // md5crypt 4 (a unit runs 4 threads per MD5 core).

  u32 grain_per_core;

  // What C2H core_id names, for messages: "core", or "unit" when the device cannot tell its cores
  // apart.

  const char *core_name;

  // What the device computes, checked before a salt is launched. A zero max means no limit. The
  // module should refuse anything outside these at parse time, so this is the last line.

  u32 salt_len_min;
  u32 salt_len_max;
  u32 iter_min;
  u32 iter_max;

  // Batch timeout: generous cycles for one iteration of one wave, at the identity's clock.

  u32 wait_cycles_per_iter;

  // Fixed tuning rows, terminated by a row with board NULL. NULL: every board is autotuned.

  const hcfpga_wave_model_t *wave_models;

  // The password the known-answer canary uses. NULL: "hcfpga-ztex-canary". It must fit pw_max.

  const char *canary_pw;

  // Hooks. Only canary_digest is mandatory.

  // The digest the device returns for pw under salt, as hashcat's digest_buf words 0..M-1: the
  // known-answer canary's reference, computed on the host once per salt.

  void (*canary_digest) (const u8 *pw, const u32 pw_len, const salt_t *salt, u32 *digest);

  // The values of salt0..3 and iter_count. NULL: salt_buf[0..3] and salt_iter unchanged.

  void (*config_regs) (const salt_t *salt, u32 salt_regs[4], u32 *iter_count);

  // Writes the algorithm's extra registers (HCFPGA_CSR_EXTRA (n)) for salt. NULL: none.

  bool (*config_extra) (hcfpga_cfg_t *cfg, const salt_t *salt);

  // hashcat's digest_buf words from the C2H record's words 1..M (little-endian as received; with
  // several parts, part k's words 1..6 follow part k-1's, so c2h[6k + j] is part k's word j + 1).
  // NULL: unchanged. The device's comparator indexes its bitmap with the low 7 bits of the
  // resulting digest[0], so the gateware has to pick the byte that becomes those bits.

  void (*digest_from_c2h) (const u32 *c2h, u32 *digest);

  // A check beyond the limits above. Returns false and writes why into buf when the device cannot
  // compute salt. NULL: the limits only.

  bool (*salt_check) (const salt_t *salt, char *buf, const size_t len);

  // A line for a board that is dropped: how to diagnose it. NULL: a generic one.

  const char *diag_hint;

} hcfpga_algo_t;

#define HCFPGA_TMP_LAYOUT(type)                                             \
  .tmp_size       = sizeof (type),                                          \
  .tmp_pw_len_off = offsetof (type, pw_len),                                \
  .tmp_pw_buf_off = offsetof (type, pw_buf),                                \
  .tmp_digest_off = offsetof (type, digest),                                \
  .tmp_pw_words   = (u32) (sizeof (((type *) 0)->pw_buf) / sizeof (u32)),   \
  .digest_words   = (u32) (sizeof (((type *) 0)->digest) / sizeof (u32))

// Ready-made digest_from_c2h for big-endian device words (bcrypt's convention).

void hcfpga_digest_swap32 (const u32 *c2h, u32 *digest);

// Called from the algorithm's bridge_init.

void hcfpga_bridge_init (bridge_ctx_t *bridge_ctx, const hcfpga_algo_t *algo);

#endif // HC_FPGA_HCFPGA_BRIDGE_H
