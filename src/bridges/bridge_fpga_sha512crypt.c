/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// sha512crypt on an FPGA (hash mode 91800): the hooks of the shared FPGA bridge,
// src/bridges/fpga/hcfpga_bridge.c. The gateware is src/fpga/sha512crypt, see its README for every
// value below.

#include "common.h"
#include "types.h"
#include "bridges.h"

#include "fpga/hcfpga_bridge.h"
#include "fpga/hcfpga_sha512crypt_ref.h"

// The module's and the kernel's tmp struct (module_91800.c, m91800-pure.cl): the password,
// the digest words the device returns. All three files keep the same struct.

typedef struct sha512crypt_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[16];

  u32 digest[4];

} sha512crypt_bridge_tmp_t;

// The registers beyond the shared block, in the wrapper's EXTRA_CSRS order. The JtR unit packet
// carries the salt length. HCFPGA-TODO: any other register the core needs.

#define CSR_SALT_LEN  HCFPGA_CSR_EXTRA (0)

static bool sha512crypt_config_extra (hcfpga_cfg_t *cfg, const salt_t *salt)
{
  return hcfpga_cfg_write (cfg, CSR_SALT_LEN, salt->salt_len, "salt_len");
}

// The canary's reference: the digest the device returns for pw under salt, as hashcat's
// digest_buf words.

static void sha512crypt_canary_digest (const u8 *pw, const u32 pw_len, const salt_t *salt, u32 *digest)
{
  const u32 salt_len = MIN (salt->salt_len, (u32) sizeof (salt->salt_buf));

  hcfpga_sha512crypt (pw, pw_len, (const u8 *) salt->salt_buf, salt_len, salt->salt_iter, digest);
}

static const hcfpga_algo_t SHA512CRYPT =
{
  .name = "sha512crypt",

  HCFPGA_TMP_LAYOUT (sha512crypt_bridge_tmp_t),

  // HCFPGA-TODO: the longest password the core takes.
  .pw_max = 64,

  // HCFPGA-TODO: candidates in flight per core the identity's cores= counts.
  .grain_per_core = 4,

  // HCFPGA-TODO: what the C2H core_id names.
  .core_name = "unit",

  // HCFPGA-TODO: what the core computes. The module refuses anything else at parse time too.
  .salt_len_min = 1,
  .salt_len_max = 16,
  .iter_min     = 1,
  .iter_max     = 999999999,

  // HCFPGA-TODO: generous cycles for one iteration of one wave, for the batch timeout.
  .wait_cycles_per_iter = 1000,

  // No board measured yet: every board is autotuned. Rows come from hcfpga_step --wave-model.
  .wave_models = NULL,

  // The known-answer canary's password, at most pw_max bytes (NULL: "hcfpga-ztex-canary").
  .canary_pw = NULL,

  .canary_digest   = sha512crypt_canary_digest,
  .config_regs     = NULL,
  .config_extra    = sha512crypt_config_extra,
  .digest_from_c2h = NULL,   // HCFPGA-TODO: hcfpga_digest_swap32 or a function, if C2H order is not digest_buf's
  .salt_check      = NULL,
  .diag_hint       = NULL,
};

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  hcfpga_bridge_init (bridge_ctx, &SHA512CRYPT);
}
