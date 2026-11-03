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

// The module's and the kernel's tmp struct (module_91800.c, m91800-pure.cl): a 64-byte password,
// the first 16 of the 64 bytes sha512crypt ends with (hashcat compares digest words 0..3). All
// three files keep the same struct.

typedef struct sha512crypt_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[16];

  u32 digest[4];

} sha512crypt_bridge_tmp_t;

// sha512crypt's only register beyond the shared block: the salt is 1 to 16 bytes, and the JtR unit
// packet carries its length.

#define CSR_SALT_LEN  HCFPGA_CSR_EXTRA (0)

static bool sha512crypt_config_extra (hcfpga_cfg_t *cfg, const salt_t *salt)
{
  return hcfpga_cfg_write (cfg, CSR_SALT_LEN, salt->salt_len, "salt_len");
}

// The canary's reference: sha512crypt on the host, the first 16 result bytes in SHA-512 output
// order, which is hashcat's digest_buf. The device returns them the same way, so the C2H words need
// no swap.

static void sha512crypt_canary_digest (const u8 *pw, const u32 pw_len, const salt_t *salt, u32 *digest)
{
  const u32 salt_len = MIN (salt->salt_len, (u32) sizeof (salt->salt_buf));

  hcfpga_sha512crypt (pw, pw_len, (const u8 *) salt->salt_buf, salt_len, salt->salt_iter, digest);
}

static const hcfpga_algo_t SHA512CRYPT =
{
  .name = "sha512crypt",

  HCFPGA_TMP_LAYOUT (sha512crypt_bridge_tmp_t),

  // The unit's thread memory holds the key in 64-bit words 5 to 12, and the program writes the P
  // byte sequence over it.
  .pw_max = 64,

  // A computing unit runs 4 threads per SHA-512 core, and the identity's cores= counts SHA-512 cores.
  .grain_per_core = 4,

  // The unit picks the thread, so the collector can name the unit and no finer.
  .core_name = "unit",

  // The unit keeps 16 salt bytes and cannot do an empty salt; its CPU counts rounds in 32 bits from
  // 1, and 999999999 is sha512crypt's own limit. The module refuses anything else at parse time.
  .salt_len_min = 1,
  .salt_len_max = 16,
  .iter_min     = 1,
  .iter_max     = 999999999,

  // One round for every thread of a unit: at most two SHA-512 blocks (64 + 16 + 64 + 64 bytes), 4
  // interleaved blocks per core take 352 cycles, and the CPU adds a little. Generous, it only sets
  // the batch timeout.
  .wait_cycles_per_iter = 1000,

  // No board measured yet: every board is autotuned. Rows come from hcfpga_step --wave-model.
  .wave_models = NULL,

  // The known-answer canary's password, at most pw_max bytes (NULL: "hcfpga-ztex-canary").
  .canary_pw = NULL,

  .canary_digest   = sha512crypt_canary_digest,
  .config_regs     = NULL,
  .config_extra    = sha512crypt_config_extra,
  .digest_from_c2h = NULL,
  .salt_check      = NULL,
  .diag_hint       = NULL,
};

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  hcfpga_bridge_init (bridge_ctx, &SHA512CRYPT);
}
