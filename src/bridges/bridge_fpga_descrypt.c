/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// descrypt on an FPGA (hash mode 91500): the hooks of the shared FPGA bridge,
// src/bridges/fpga/hcfpga_bridge.c. The gateware is src/fpga/descrypt, see its README for every
// value below.

#include "common.h"
#include "types.h"
#include "bridges.h"

#include "fpga/hcfpga_bridge.h"
#include "fpga/hcfpga_descrypt_ref.h"

// The module's and the kernel's tmp struct (module_91500.c, m91500-pure.cl): the password,
// the digest words the device returns. All three files keep the same struct.

typedef struct descrypt_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[2];

  u32 digest[4];

} descrypt_bridge_tmp_t;

// HCFPGA-TODO: the registers beyond the shared block, in the wrapper's EXTRA_CSRS order, written
// by a config_extra hook with hcfpga_cfg_write (cfg, HCFPGA_CSR_EXTRA (n), value, "name").

// The canary's reference: the digest the device returns for pw under salt, as hashcat's
// digest_buf words.

static void descrypt_canary_digest (const u8 *pw, const u32 pw_len, const salt_t *salt, u32 *digest)
{
  const u32 salt_len = MIN (salt->salt_len, (u32) sizeof (salt->salt_buf));

  hcfpga_descrypt (pw, pw_len, (const u8 *) salt->salt_buf, salt_len, salt->salt_iter, digest);
}

static const hcfpga_algo_t DESCRYPT =
{
  .name = "descrypt",

  HCFPGA_TMP_LAYOUT (descrypt_bridge_tmp_t),

  // HCFPGA-TODO: the longest password the core takes.
  .pw_max = 8,

  // HCFPGA-TODO: candidates in flight per core the identity's cores= counts.
  .grain_per_core = 16,

  // HCFPGA-TODO: what the C2H core_id names.
  .core_name = "core",

  // HCFPGA-TODO: what the core computes. The module refuses anything else at parse time too.
  .salt_len_min = 4,
  .salt_len_max = 4,
  .iter_min     = 25,
  .iter_max     = 25,

  // HCFPGA-TODO: generous cycles for one iteration of one wave, for the batch timeout.
  .wait_cycles_per_iter = 1000,

  // No board measured yet: every board is autotuned. Rows come from hcfpga_step --wave-model.
  .wave_models = NULL,

  // The known-answer canary's password, at most pw_max bytes (NULL: "hcfpga-ztex-canary").
  .canary_pw = "hcfpga-z",

  .canary_digest   = descrypt_canary_digest,
  .config_regs     = NULL,
  .config_extra    = NULL,
  .digest_from_c2h = NULL,   // HCFPGA-TODO: hcfpga_digest_swap32 or a function, if C2H order is not digest_buf's
  .salt_check      = NULL,
  .diag_hint       = NULL,
};

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  hcfpga_bridge_init (bridge_ctx, &DESCRYPT);
}
