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

// DES (PT = $salt, key = $pass) on an FPGA (fpga_des_kpa bridge): init hands the key, or the base word
// of a mask the device amplifies, to the bridge; the bridge replaces the loop and writes back the hits
// the device found, each with the digest it cracks and its amplifier item; comp marks every one.

#define DES_KPA_HITS 16

typedef struct des_kpa_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[2];

  u32 hit_cnt;

  u32 hit_il[DES_KPA_HITS];

  u32 hit_digest[DES_KPA_HITS][2];

} des_kpa_bridge_tmp_t;

KERNEL_FQ KERNEL_FA void m75700_init (KERN_ATTR_TMPS (des_kpa_bridge_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].pw_len = pws[gid].pw_len;

  for (u32 i = 0; i < 2; i++)
  {
    tmps[gid].pw_buf[i] = pws[gid].i[i];
  }

  tmps[gid].hit_cnt = 0;
}

KERNEL_FQ KERNEL_FA void m75700_loop (KERN_ATTR_TMPS (des_kpa_bridge_tmp_t))
{
}

KERNEL_FQ KERNEL_FA void m75700_comp (KERN_ATTR_TMPS (des_kpa_bridge_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 hit_cnt = (tmps[gid].hit_cnt < DES_KPA_HITS) ? tmps[gid].hit_cnt : DES_KPA_HITS;

  for (u32 h = 0; h < hit_cnt; h++)
  {
    const u32 il_pos = tmps[gid].hit_il[h];

    const u32 r0 = tmps[gid].hit_digest[h][0];
    const u32 r1 = tmps[gid].hit_digest[h][1];
    const u32 r2 = 0;
    const u32 r3 = 0;

    #ifdef KERNEL_STATIC
    #include COMPARE_M
    #endif
  }
}
