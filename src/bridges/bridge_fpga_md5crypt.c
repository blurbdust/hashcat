/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// md5crypt on an FPGA (hash mode 90500): the hooks of the shared FPGA bridge,
// src/bridges/fpga/hcfpga_bridge.c. The gateware is src/fpga/md5crypt (John the Ripper's md5crypt
// unit), see its README for every value below.

#include "common.h"
#include "types.h"
#include "bridges.h"

#include "fpga/hcfpga_bridge.h"
#include "fpga/hcfpga_md5crypt_ref.h"

// The module's and the kernel's tmp struct (module_90500.c, m90500-pure.cl): a 64-byte password,
// the 16 bytes md5crypt ends with.

typedef struct md5crypt_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[16];

  u32 digest[4];

} md5crypt_bridge_tmp_t;

// md5crypt's only register beyond the shared block: the salt is 1 to 8 bytes, not 16.

#define CSR_SALT_LEN  HCFPGA_CSR_EXTRA (0)

static bool md5crypt_config_extra (hcfpga_cfg_t *cfg, const salt_t *salt)
{
  return hcfpga_cfg_write (cfg, CSR_SALT_LEN, salt->salt_len, "salt_len");
}

// The canary's reference: md5crypt on the host, the 16 bytes in MD5 output order, which is
// hashcat's digest_buf. The device returns them the same way, so the C2H words need no swap.

static void md5crypt_canary_digest (const u8 *pw, const u32 pw_len, const salt_t *salt, u32 *digest)
{
  const u32 salt_len = MIN (salt->salt_len, (u32) sizeof (salt->salt_buf));

  hcfpga_md5crypt (pw, pw_len, (const u8 *) salt->salt_buf, salt_len, salt->salt_iter, digest);
}

static const hcfpga_algo_t MD5CRYPT =
{
  .name = "md5crypt",

  HCFPGA_TMP_LAYOUT (md5crypt_bridge_tmp_t),

  // The unit's thread memory holds the key in words 10 to 25.
  .pw_max = 64,

  // A computing unit runs 4 threads per MD5 core, and the identity's cores= counts MD5 cores.
  .grain_per_core = 4,

  // The unit picks the thread, so the collector can name the unit and no finer.
  .core_name = "unit",

  // md5crypt's own salt is 1 to 8 bytes and the unit cannot do an empty one; its CPU counts
  // rounds in 16 bits.
  .salt_len_min = 1,
  .salt_len_max = 8,
  .iter_min     = 1,
  .iter_max     = 0xffff,

  // One round for every thread of a unit: 4 interleaved MD5 blocks per core take 288 cycles, and
  // the CPU adds a little. Generous, it only sets the batch timeout.
  .wait_cycles_per_iter = 400,

  // No md5crypt board has been measured yet, so every md5crypt board is autotuned.
  .wave_models = NULL,

  .canary_pw = NULL,

  .canary_digest   = md5crypt_canary_digest,
  .config_regs     = NULL,
  .config_extra    = md5crypt_config_extra,
  .digest_from_c2h = NULL,
  .salt_check      = NULL,
  .diag_hint       = NULL,
};

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  hcfpga_bridge_init (bridge_ctx, &MD5CRYPT);
}
