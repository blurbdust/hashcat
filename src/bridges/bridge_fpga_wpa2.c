/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// wpa2 on an FPGA (hash mode 92500): the hooks of the shared FPGA bridge,
// src/bridges/fpga/hcfpga_bridge.c. The gateware is src/fpga/wpa2, see its README for every
// value below.

#include "common.h"
#include "types.h"
#include "bridges.h"

#include "fpga/hcfpga_bridge.h"
#include "fpga/hcfpga_wpa2_ref.h"

// The module's and the kernel's tmp struct (module_92500.c, m92500-pure.cl): the password,
// the digest words the device returns. All three files keep the same struct.

typedef struct wpa2_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[16];

  u32 digest[8];

} wpa2_bridge_tmp_t;

// The registers beyond the shared block, in the wrapper's EXTRA_CSRS order: the ESSID length, and
// ESSID bytes 16..31 (salt0..3 carry bytes 0..15; mode 22000's salt_buf is the ESSID).

#define CSR_SALT_LEN  HCFPGA_CSR_EXTRA (0)
#define CSR_SALT4     HCFPGA_CSR_EXTRA (1)

static bool wpa2_config_extra (hcfpga_cfg_t *cfg, const salt_t *salt)
{
  static const char *names[4] = { "salt4", "salt5", "salt6", "salt7" };

  if (hcfpga_cfg_write (cfg, CSR_SALT_LEN, salt->salt_len, "salt_len") == false) return false;

  for (u32 i = 0; i < 4; i++)
  {
    if (hcfpga_cfg_write (cfg, CSR_SALT4 + (4 * i), salt->salt_buf[4 + i], names[i]) == false) return false;
  }

  return true;
}

// The canary's reference: the PMK the device returns for pw under the ESSID, as hashcat's
// digest_buf words (mode 22000's tmps out[0..7]).

static void wpa2_canary_digest (const u8 *pw, const u32 pw_len, const salt_t *salt, u32 *digest)
{
  const u32 salt_len = MIN (salt->salt_len, 32u);

  hcfpga_wpa2 (pw, pw_len, (const u8 *) salt->salt_buf, salt_len, salt->salt_iter, digest);
}

static const hcfpga_algo_t WPA2 =
{
  .name = "wpa2",

  HCFPGA_TMP_LAYOUT (wpa2_bridge_tmp_t),

  // C2H records per candidate, 24 digest bytes each: the gateware's PARTS, the identity's parts=.
  .c2h_parts = 2,

  // A WPA passphrase is at most 63 bytes: the HMAC key is one block.
  .pw_max = 63,

  // The identity's cores= counts PBKDF2 pairs, one candidate each.
  .grain_per_core = 1,

  .core_name = "pair",

  // The ESSID, 0 to 32 bytes; mode 22000's salt_iter is always 4095, the count after U1 (the
  // device's count is fixed at 4096).
  .salt_len_min = 0,
  .salt_len_max = 32,
  .iter_min     = 4095,
  .iter_max     = 4095,

  // An iteration is two SHA-1 compressions of 83 cycles; 1000 leaves room for a slow simulator.
  .wait_cycles_per_iter = 1000,

  // No board measured yet: every board is autotuned. Rows come from hcfpga_step --wave-model.
  .wave_models = NULL,

  // The known-answer canary's password, at most pw_max bytes (NULL: "hcfpga-ztex-canary").
  .canary_pw = NULL,

  .canary_digest   = wpa2_canary_digest,
  .config_regs     = NULL,
  .config_extra    = wpa2_config_extra,
  .digest_from_c2h = hcfpga_digest_swap32,   // the PMK in byte order; digest_buf words are big-endian
  .salt_check      = NULL,
  .diag_hint       = NULL,
};

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  hcfpga_bridge_init (bridge_ctx, &WPA2);
}
