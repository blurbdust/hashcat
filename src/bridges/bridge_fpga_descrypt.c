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

// The module's and the kernel's tmp struct (module_91500.c, m91500-pure.cl): an 8-byte password,
// and mode 1500's 4 digest words, of which the device returns 0 and 1 (2 and 3 are zero, as the
// parser leaves them). All three files keep the same struct.

typedef struct descrypt_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[2];

  u32 digest[4];

} descrypt_bridge_tmp_t;

// No register beyond the shared block: salt0 is hashcat's salt_buf[0], whose bits 11:0 are the
// 12-bit salt the core takes, and the count is fixed.

// The canary's reference: crypt(3)'s DES on the host, as hashcat's digest_buf words (the output
// block through DES_IP, as module_01500's parser stores a hash). The device returns the same words
// little-endian, so the C2H words need no swap.

static void descrypt_canary_digest (const u8 *pw, const u32 pw_len, const salt_t *salt, u32 *digest)
{
  const u32 salt_len = MIN (salt->salt_len, (u32) sizeof (salt->salt_buf));

  hcfpga_descrypt (pw, pw_len, (const u8 *) salt->salt_buf, salt_len, salt->salt_iter, digest);
}

static const hcfpga_algo_t DESCRYPT =
{
  .name = "descrypt",

  HCFPGA_TMP_LAYOUT (descrypt_bridge_tmp_t),

  // A DES key is 8 bytes; the engine packs the low 7 bits of each.
  .pw_max = 8,

  // A core is a ring of 16 DES rounds holding 16 candidates, and the identity's cores= counts rings.
  .grain_per_core = 16,

  // The engine knows which ring computed a candidate.
  .core_name = "core",

  // Every hash mode 1500 parses: salt_len 4 (the 12-bit salt and its 2 characters) and crypt(3)'s
  // 25 encryptions, which the module sets.
  .salt_len_min = 4,
  .salt_len_max = 4,
  .iter_min     = 25,
  .iter_max     = 25,

  // A ring runs one encryption of its 16 candidates in 16 cycles, and sending 16 unfiltered results
  // takes 512 cycles more. Generous, it only sets the batch timeout.
  .wait_cycles_per_iter = 100,

  // No board measured yet: every board is autotuned. Rows come from hcfpga_step --wave-model.
  .wave_models = NULL,

  // The known-answer canary's password, at most pw_max bytes (NULL: "hcfpga-ztex-canary").
  .canary_pw = "hcfpga-z",

  .canary_digest   = descrypt_canary_digest,
  .config_regs     = NULL,
  .config_extra    = NULL,
  .digest_from_c2h = NULL,
  .salt_check      = NULL,
  .diag_hint       = NULL,
};

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  hcfpga_bridge_init (bridge_ctx, &DESCRYPT);
}
