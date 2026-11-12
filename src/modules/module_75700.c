/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// DES (PT = $salt, key = $pass) computed on an FPGA through the fpga_des_kpa bridge (src/fpga/des_kpa).
// Made from module_14000.c: hash format, example hash, self-test, length limits and benchmark mask are
// mode 14000's; the kernel is a pass-through and the bridge replaces the loop.
// Dropped with the upstream kernel: module_jit_build_options, module_kernel_loops_min, module_unstable_warning.
//
// Mode 14000 is a fast hash (ATTACK_EXEC_INSIDE_KERNEL, a bitsliced kernel with its own TM kernel
// bits); this mode is the bridged slow-hash shape instead: ATTACK_EXEC_OUTSIDE_KERNEL, so that
// hashcat runs init, the loop the bridge replaces, and comp. Also dropped with the upstream kernel:
// KERN_BIT_TM (module_kern_bits). The parser sets salt_iter to 1, the one DES encryption, which mode
// 14000 leaves at 0: hashcat runs a slow hash's loop salt_iter times.
//
// The bridge walks an attack mode 3 mask's amplifier on the device (BRIDGE_TYPE_MASK_AMP): a launch
// then holds base words, the device tests each with every item of the amplifier, and a crack comes
// back as the base word's work item and the item's il_pos. Every other launch holds one key per work
// item, as mode 14000's do.

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "emu_inc_cipher_des.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_CIPHER_KPA;
static const char *HASH_NAME      = "DES (PT = $salt, key = $pass) [Bridged: FPGA]";
static const u64   KERN_TYPE      = 75700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_ST_HEX
                                  | OPTS_TYPE_AUTODETECT_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const u64   BRIDGE_TYPE    = BRIDGE_TYPE_REPLACE_LOOP
                                  | BRIDGE_TYPE_MASK_AMP;
static const char *BRIDGE_NAME    = "fpga_des_kpa";
static const char *ST_PASS        = "hashcat1";
static const char *ST_HASH        = "53b325182924b356:1412781058343178";

#include "hooks_common.c"

// The device's limits, mode 14000's: an 8-byte key and an 8-byte plaintext, one encryption.

static const u32   FPGA_PW_MIN    = 8;
static const u32   FPGA_PW_MAX    = 8;
static const u32   FPGA_SALT_MIN  = 8;
static const u32   FPGA_SALT_MAX  = 8;
static const u32   FPGA_ITER      = 1;

// Hits a work item can report in one launch: one key cracks one hash, and a base word covers a whole
// amplifier, so this is how many of one plaintext's hashes a base word can crack at once.

#define DES_KPA_HITS 16

const char *module_bridge_name    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BRIDGE_NAME;     }
u64         module_bridge_type    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BRIDGE_TYPE;     }

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = FPGA_ITER;

  return kernel_loops_max;
}

// The tmp struct the kernel (m75700-pure.cl) and the bridge (bridge_fpga_des_kpa.c) share. init puts
// the work item's key or base word in pw; the bridge writes hit_cnt hits, each the digest of the hash
// it cracks and the amplifier item it was found at (0 for a launch of whole keys), and comp marks them.

typedef struct des_kpa_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[2];

  u32 hit_cnt;

  u32 hit_il[DES_KPA_HITS];

  u32 hit_digest[DES_KPA_HITS][2];

} des_kpa_bridge_tmp_t;

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (des_kpa_bridge_tmp_t);

  return tmp_size;
}

u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_min = FPGA_SALT_MIN; // Underlaying DES min

  return salt_min;
}

u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_max = FPGA_SALT_MAX; // Underlaying DES max

  return salt_max;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = FPGA_PW_MIN; // Underlaying DES min

  return pw_min;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = FPGA_PW_MAX; // Underlaying DES max

  return pw_max;
}

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?b?b?b?b?b?b?bx";

  return mask;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 2;

  token.sep[0]     = hashconfig->separator;
  token.len[0]     = 16;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]     = 16;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];

  salt->salt_buf[0] = hex_to_u32 (salt_pos + 0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos + 8);
  salt->salt_buf[2] = 0;
  salt->salt_buf[3] = 0;

  salt->salt_len = 8;

  salt->salt_buf_pc[0] = salt->salt_buf[0];
  salt->salt_buf_pc[1] = salt->salt_buf[1];

  DES_IP (salt->salt_buf_pc[0], salt->salt_buf_pc[1]);

  // the one DES encryption: hashcat's loop count, which the bridge replaces.

  salt->salt_iter = FPGA_ITER;

  // hash

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos + 0);
  digest[1] = hex_to_u32 (hash_pos + 8);
  digest[2] = 0;
  digest[3] = 0;

  DES_IP (digest[0], digest[1]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u32 tmp[4];

  tmp[0] = digest[0];
  tmp[1] = digest[1];
  tmp[2] = 0;
  tmp[3] = 0;

  DES_FP (tmp[1], tmp[0]);

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  u32_to_hex (tmp[0], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[1], out_buf + out_len); out_len += 8;

  out_buf[out_len] = hashconfig->separator;

  out_len++;

  u32_to_hex (salt->salt_buf[0], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[1], out_buf + out_len); out_len += 8;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_bridge_name              = module_bridge_name;
  module_ctx->module_bridge_type              = module_bridge_type;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_salt_max                 = module_salt_max;
  module_ctx->module_salt_min                 = module_salt_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
