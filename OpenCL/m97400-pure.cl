/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

// sha256crypt on an FPGA (fpga_sha256crypt bridge): init hands the candidate to the bridge, the bridge
// replaces the loop and writes back the digest words the device returns, comp compares them.

typedef struct sha256crypt_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[8];

  u32 digest[4];

} sha256crypt_bridge_tmp_t;

KERNEL_FQ KERNEL_FA void m97400_init (KERN_ATTR_TMPS (sha256crypt_bridge_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].pw_len = pws[gid].pw_len;

  for (u32 i = 0; i < 8; i++)
  {
    tmps[gid].pw_buf[i] = pws[gid].i[i];
  }

  for (u32 i = 0; i < 4; i++)
  {
    tmps[gid].digest[i] = 0;
  }
}

KERNEL_FQ KERNEL_FA void m97400_loop (KERN_ATTR_TMPS (sha256crypt_bridge_tmp_t))
{
}

KERNEL_FQ KERNEL_FA void m97400_comp (KERN_ATTR_TMPS (sha256crypt_bridge_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 r0 = tmps[gid].digest[DGST_R0];
  const u32 r1 = tmps[gid].digest[DGST_R1];
  const u32 r2 = tmps[gid].digest[DGST_R2];
  const u32 r3 = tmps[gid].digest[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
