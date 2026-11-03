/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// scrypt on an FPGA (hash mode 98900): the hooks of the shared FPGA bridge,
// src/bridges/fpga/hcfpga_bridge.c. The gateware is src/fpga/scrypt, see its README for every
// value below.

#include "common.h"
#include "types.h"
#include "bridges.h"

#include "fpga/hcfpga_bridge.h"
#include "fpga/hcfpga_scrypt_ref.h"

// The module's and the kernel's tmp struct (module_98900.c, m98900-pure.cl): the password,
// the digest words the device returns. All three files keep the same struct.

typedef struct scrypt_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[16];

  u32 digest[4];

} scrypt_bridge_tmp_t;

// HCFPGA-TODO: the registers beyond the shared block, in the wrapper's EXTRA_CSRS order, written
// by a config_extra hook with hcfpga_cfg_write (cfg, HCFPGA_CSR_EXTRA (n), value, "name").

// The canary's reference: the digest the device returns for pw under salt, as hashcat's
// digest_buf words.

static void scrypt_canary_digest (const u8 *pw, const u32 pw_len, const salt_t *salt, u32 *digest)
{
  const u32 salt_len = MIN (salt->salt_len, (u32) sizeof (salt->salt_buf));

  hcfpga_scrypt (pw, pw_len, (const u8 *) salt->salt_buf, salt_len, salt->salt_iter, digest);
}

static const hcfpga_algo_t SCRYPT =
{
  .name = "scrypt",

  HCFPGA_TMP_LAYOUT (scrypt_bridge_tmp_t),

  // HCFPGA-TODO: the longest password the core takes.
  .pw_max = 64,

  // HCFPGA-TODO: candidates in flight per core the identity's cores= counts.
  .grain_per_core = 1,

  // HCFPGA-TODO: what the C2H core_id names.
  .core_name = "core",

  // HCFPGA-TODO: what the core computes. The module refuses anything else at parse time too.
  .salt_len_min = 0,
  .salt_len_max = 32,
  .iter_min     = 2,
  .iter_max     = 32768,

  // HCFPGA-TODO: generous cycles for one iteration of one wave, for the batch timeout.
  .wait_cycles_per_iter = 1000,

  // No board measured yet: every board is autotuned. Rows come from hcfpga_step --wave-model.
  .wave_models = NULL,

  // The known-answer canary's password, at most pw_max bytes (NULL: "hcfpga-ztex-canary").
  .canary_pw = NULL,

  .canary_digest   = scrypt_canary_digest,
  .config_regs     = NULL,
  .config_extra    = NULL,
  .digest_from_c2h = NULL,   // HCFPGA-TODO: hcfpga_digest_swap32 or a function, if C2H order is not digest_buf's
  .salt_check      = NULL,
  .diag_hint       = NULL,
};

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  hcfpga_bridge_init (bridge_ctx, &SCRYPT);
}
