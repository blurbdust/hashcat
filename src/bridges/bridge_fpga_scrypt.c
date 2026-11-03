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

// The module's and the kernel's tmp struct (module_98900.c, m98900-pure.cl): the password, and the
// 4 digest words the device returns (the derived key's first 16 bytes). All three files keep the
// same struct.

typedef struct scrypt_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[16];

  u32 digest[4];

} scrypt_bridge_tmp_t;

// The registers beyond the shared block, in the wrapper's EXTRA_CSRS order: the salt length, and
// salt bytes 16..31 (salt0..3 carry bytes 0..15). The cost needs none: iter_count is N.

#define CSR_SALT_LEN  HCFPGA_CSR_EXTRA (0)
#define CSR_SALT4     HCFPGA_CSR_EXTRA (1)

static bool scrypt_config_extra (hcfpga_cfg_t *cfg, const salt_t *salt)
{
  static const char *names[4] = { "salt4", "salt5", "salt6", "salt7" };

  if (hcfpga_cfg_write (cfg, CSR_SALT_LEN, salt->salt_len, "salt_len") == false) return false;

  for (u32 i = 0; i < 4; i++)
  {
    if (hcfpga_cfg_write (cfg, CSR_SALT4 + (4 * i), salt->salt_buf[4 + i], names[i]) == false) return false;
  }

  return true;
}

// What the iteration and salt limits do not say: the unit computes r = 1 and p = 1 only, and takes
// N as log2 (N), so N has to be a power of two. The module refuses anything else at parse time.

static bool scrypt_salt_check (const salt_t *salt, char *buf, const size_t len)
{
  if (salt->scrypt_r != 1)
  {
    snprintf (buf, len, "r = %u, the device computes r = 1 only", salt->scrypt_r);

    return false;
  }

  if (salt->scrypt_p != 1)
  {
    snprintf (buf, len, "p = %u, the device computes p = 1 only", salt->scrypt_p);

    return false;
  }

  if ((salt->scrypt_N & (salt->scrypt_N - 1)) != 0)
  {
    snprintf (buf, len, "N = %u is not a power of two", salt->scrypt_N);

    return false;
  }

  return true;
}

// The canary's reference: scrypt on the host (r = 1, p = 1, N = salt_iter), the derived key's first
// 16 bytes as hashcat's digest_buf words. The device returns the same bytes in order, so the C2H
// words need no swap.

static void scrypt_canary_digest (const u8 *pw, const u32 pw_len, const salt_t *salt, u32 *digest)
{
  const u32 salt_len = MIN (salt->salt_len, (u32) sizeof (salt->salt_buf));

  hcfpga_scrypt (pw, pw_len, (const u8 *) salt->salt_buf, salt_len, salt->salt_iter, digest);
}

static const hcfpga_algo_t SCRYPT =
{
  .name = "scrypt",

  HCFPGA_TMP_LAYOUT (scrypt_bridge_tmp_t),

  // The unit keeps a 64-byte key: HMAC-SHA256 takes a key of up to one block as it is, and a longer
  // one would have to be hashed first, which the unit does not do.
  .pw_max = 64,

  // A unit computes one candidate at a time, and the identity's cores= counts units.
  .grain_per_core = 1,

  // The C2H core_id is the unit that computed the candidate.
  .core_name = "unit",

  // Salts of 0 to 32 bytes (the unit's salt register), N from 2 to 2^15 (the V table's depth,
  // N_LOG2_MAX in the gateware). salt_iter is N.
  .salt_len_min = 0,
  .salt_len_max = 32,
  .iter_min     = 2,
  .iter_max     = 32768,

  // One N step is two BlockMix calls, about 64 cycles; a candidate also spends about 2000 cycles
  // in PBKDF2 and its packets, which this has to cover at N = 2 too. Generous, it only sets the
  // batch timeout.
  .wait_cycles_per_iter = 1000,

  // No board measured yet: every board is autotuned. Rows come from hcfpga_step --wave-model.
  .wave_models = NULL,

  // The known-answer canary's password, at most pw_max bytes (NULL: "hcfpga-ztex-canary").
  .canary_pw = NULL,

  .canary_digest   = scrypt_canary_digest,
  .config_regs     = NULL,
  .config_extra    = scrypt_config_extra,
  .digest_from_c2h = NULL,
  .salt_check      = scrypt_salt_check,
  .diag_hint       = NULL,
};

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  hcfpga_bridge_init (bridge_ctx, &SCRYPT);
}
