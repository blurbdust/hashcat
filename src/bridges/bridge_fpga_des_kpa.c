/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>

#include "common.h"
#include "types.h"
#include "event.h"
#include "bridges.h"
#include "memory.h"
#include "shared.h"
#include "bitops.h"
#include "thread.h"

#include "fpga/hcfpga.h"
#include "fpga/hcfpga_pool.h"
#include "fpga/hcfpga_des_kpa_ref.h"

// DES (PT = $salt, key = $pass) on an FPGA (hash mode 75700): bcrypt's bridge with the DES
// known-plaintext engine's specifics. The gateware is src/fpga/des_kpa.
//
// The device compares on its own: a batch carries the salt's plaintext and up to TGT_USER of the
// salt's hashes as targets, every record is a job, and only hits come back, each the job, the
// amplifier item and the target. A launch of whole keys (launch_loop) sends one key per job. A mask
// launch (launch_loop_amp, BRIDGE_TYPE_MASK_AMP) sends base words, and the device walks the whole
// amplifier over each one; the amplifier's charsets go into the device's tables once per mask.
// Every hit is encrypted again on the host before hashcat sees it.
//
// Registers beyond the shared block, from 0x3c: amp_cnt, amp_lens, amp_tab (a table write),
// tgt_mask and tgt0_lo .. tgt3_hi.

#define ALGO_NAME "des_kpa"

#define CSR_CTRL        0x00
#define CSR_SALT0       0x04
#define CSR_SALT1       0x08
#define CSR_SALT2       0x0c
#define CSR_SALT3       0x10
#define CSR_ITER_COUNT  0x14
#define CSR_STATUS      0x18
#define CSR_CORE_COUNT  0x1c

#define CSR_CMP_BM0     0x20
#define CSR_CMP_BM1     0x24
#define CSR_CMP_BM2     0x28
#define CSR_CMP_BM3     0x2c

#define CSR_BATCH_TARGET 0x30

#define CSR_PAD_RECS    0x34

#define CSR_RETIRED     0x38

#define CSR_AMP_CNT     0x3c
#define CSR_AMP_LENS    0x40
#define CSR_AMP_TAB     0x44
#define CSR_TGT_MASK    0x48
#define CSR_TGT_LO(k)   (0x4c + (8 * (k)))
#define CSR_TGT_HI(k)   (0x50 + (8 * (k)))

// des_kpa's bits of the status register (the shared frame status keeps bits 15:0): the device's
// thermal stop holds its generator while the die is too hot, and a core had a hit its FIFO could not
// take, which loses that hit.
#define STATUS_THERM_STOP  (1u << 16)
#define STATUS_LOST_HIT    (1u << 17)

// How long one batch may stay held by the thermal stop before it counts as quiet after all.
#define THERM_WAIT_MS_MAX  600000

#define CSR_PCIE_LINK_STATUS  0x2800
#define CSR_XADC_TEMPERATURE  0x4000

#define CTRL_FRAMING_RESET  0x00000001

#define C2H_REC_WORDS     8

// Every hash mode 14000 parses: an 8-byte plaintext, one encryption, which the module sets.
#define FPGA_SALT_MIN     8
#define FPGA_SALT_MAX     8
#define FPGA_ITER_MIN     1
#define FPGA_ITER_MAX     1

#define C2H_FLAG_EOB      0x8000u

// A DES key is 8 bytes; the engine takes the high 7 bits of each.
#define FPGA_PW_MAX       8

// The device's targets: TGT_CNT comparators, one of them kept for the canary, and its amplifier: up
// to AMP_POS_MAX positions of up to 256 characters. A mask's amplifier is made at least AMP_MIN
// candidates where the mask allows, so that every job keeps a core busy for a while.
#define TGT_CNT           4
#define TGT_USER          (TGT_CNT - 1)
#define TGT_CANARY        (TGT_CNT - 1)

#define AMP_POS_MAX       4
#define AMP_MIN           (1ull << 21)

// Hits one work item can carry back to the kernel (module_75700.c, m75700-pure.cl).
#define DES_KPA_HITS      16

#define H2C_TAG           0xbcu
#define H2C_HDR_BYTES     8
#define H2C_REC_BYTES(len) (H2C_HDR_BYTES + ((((len) + 3) / 4) * 4))
#define H2C_REC_BYTES_MAX H2C_REC_BYTES (FPGA_PW_MAX)

#define H2C_BATCH_ALIGN 32

#define FPGA_CFG_ATTEMPTS   3

#define CANARY_IDX      0xfffffffeu

#define CANARY_WAVES  128

#define CANARY_ARM_LAUNCHES  16

#define MEMBER_FATAL_STREAK  3

#define MEMBER_FATAL_ATTEMPTS  (MEMBER_FATAL_STREAK * (FPGA_POOL_RETRIES + 1))

#define MEMBER_FATAL_RUN  (MEMBER_FATAL_ATTEMPTS * 2)

// Every core runs one key per cycle, all of them the same amplifier item. A wave is a job per core and
// lasts the amplifier's items plus the pipeline, the collector's sweep and the retire, a few cycles a
// core. Generous, it only sets the batch timeout.
#define WAVE_CYCLES_FIXED  2048
#define WAVE_CYCLES_CORE   16

#define WAIT_SLACK      4

#define WAIT_MS_MIN     30000

#define WAIT_SLICE_MS   2

#define WORKITEM_MULTIPLE(cores)  (cores)

#define FPGA_CHUNKS_DEFAULT  2

// The module's and the kernel's tmp struct (module_75700.c, m75700-pure.cl): the key or the base
// word, and the hits the bridge writes back, each the cracked hash's digest words 0..1 (mode 14000's,
// the ciphertext through DES_IP) and the amplifier item. All three files keep the same struct.
typedef struct
{
  u32 pw_len;

  u32 pw_buf[2];

  u32 hit_cnt;

  u32 hit_il[DES_KPA_HITS];

  u32 hit_digest[DES_KPA_HITS][2];

} des_kpa_bridge_tmp_t;

// The canary's key: a job built on it has to report the canary target at a known item.
static const u8 CANARY_KEY[8] = { 'h', 'c', 'f', 'p', 'g', 'a', '-', 'z' };

typedef enum member_fault_kind
{
  MEMBER_FAULT_NONE       = 0,
  MEMBER_FAULT_REFRESH    = 1,
  MEMBER_FAULT_CONFIG     = 2,
  MEMBER_FAULT_BEGIN      = 3,
  MEMBER_FAULT_SEND       = 4,
  MEMBER_FAULT_SHORT      = 5,
  MEMBER_FAULT_TIMEOUT    = 6,
  MEMBER_FAULT_INCOMPLETE = 7,
  MEMBER_FAULT_NOCANARY   = 8,
  MEMBER_FAULT_CANARY     = 9,
  MEMBER_FAULT_OVERSIZE   = 10,

} member_fault_t;

typedef struct
{
  fpga_dev_t *dev;

  char    name[24];

  char    info[320];

  u32     grain;
  u32     cands_max;

  bool    dormant;

  u32    *h2c;

  fpga_dialect_t dialect;

  u32     h2c_rec_bytes;
  u32     c2h_rec_bytes;

  u32    *slot_id;

  u64     out_capacity;

  bool    configured;
  u32     cfg_salt_buf[4];
  u32     cfg_salt_iter;

  u32     cfg_tgt_mask;
  u8      cfg_tgt_ct[TGT_CNT][8];

  bool    cfg_amp_valid;
  u32     cfg_amp_cnt;
  u32     cfg_amp_lens;
  u8      cfg_amp_tab[AMP_POS_MAX][256];

  fpga_timing_t timing;

  u32     canary_want;

  bool    reported;

  member_fault_t fault_last;
  u32            fault_sig;
  u32            fault_streak;
  u32            fault_run;

  u64            fails;

  u64            fails_canary;

  u64            batches;

  bool           needs_refresh;

  bool           noisy_reported;

  u64            hits_dropped;

} member_t;

typedef struct
{
  char    unit_info_buf[1024];

  char    unit_class_buf[1024];

  int     member_idx[FPGA_MAX_DEVICES];
  int     members_cnt;

  u64     workitem_count;
  u32     workitem_multiple;

  u32     chunks;

  fpga_pool_t *pool;

  u64     canary_waves;
  u32     canary_arm;
  u64     fails_seen;

  bool    dead_reported;

} unit_t;

typedef struct
{
  hashcat_ctx_t     *hashcat_ctx;

  struct bridge_fpga_des_kpa *ctx;

  unit_t            *unit_buf;

  int                unit_idx;

  des_kpa_bridge_tmp_t *tmps;

  const salt_t      *salt;
  hashes_t          *hashes;
  hashconfig_t      *hashconfig;

  // The amplifier the device walks over every job, amp_cnt 0 for a launch of whole keys: the
  // positions' lengths and characters, as the device's registers and tables take them.

  const bridge_amp_t *amp;

  u32                amp_cnt;
  u32                amp_lens;
  u64                amp_items;
  u8                 amp_tab[AMP_POS_MAX][256];

  // This pass's targets: tgt_cnt of the salt's hashes not cracked yet, slot k the salt's hash
  // tgt_digest[k], and the canary's ciphertext in slot TGT_CANARY.

  u32                tgt_digest[TGT_CNT];
  u32                tgt_cnt;
  u32                tgt_mask;
  u8                 tgt_ct[TGT_CNT][8];

  // The canary job: its base word, and the amplifier item at which it has to hit TGT_CANARY.

  u8                 canary_base[8];
  u32                canary_item;

  bool               canary_on;

} launch_t;

typedef struct bridge_fpga_des_kpa
{
  unit_t      units_buf[FPGA_MAX_UNITS];
  int         units_cnt;

  member_t    members_buf[FPGA_MAX_DEVICES];
  int         members_cnt;

  int         devs_cnt;

  fpga_dev_t  devs[FPGA_MAX_DEVICES];

  hc_thread_mutex_t say_mux;
  char              say_last[256];
  u64               say_repeat;
  int               say_level;

  hc_thread_mutex_t canary_mux;

} bridge_fpga_des_kpa_t;

static const char *fault_name (const int fault)
{
  switch (fault)
  {
    case MEMBER_FAULT_REFRESH:    return "could not be brought back up";
    case MEMBER_FAULT_CONFIG:     return "would not take its salt and cost";
    case MEMBER_FAULT_BEGIN:      return "would not start a batch";
    case MEMBER_FAULT_SEND:       return "would not take the candidates";
    case MEMBER_FAULT_SHORT:      return "ended the batch early";
    case MEMBER_FAULT_TIMEOUT:    return "went quiet";
    case MEMBER_FAULT_INCOMPLETE: return "returned an incomplete batch";
    case MEMBER_FAULT_NOCANARY:   return "returned no canary";
    case MEMBER_FAULT_CANARY:     return "returned a wrong canary";
    case MEMBER_FAULT_OVERSIZE:   return "was given a range bigger than it can hold";
  }

  return "failed";
}

#define SAY_INFO     0
#define SAY_WARNING  1
#define SAY_ERROR    2

static void say_emit (hashcat_ctx_t *hashcat_ctx, const int level, const char *msg)
{
  if (level == SAY_ERROR)
  {
    event_log_error (hashcat_ctx, "%s", msg);

    return;
  }

  if (level == SAY_WARNING)
  {
    event_log_warning (hashcat_ctx, "%s", msg);

    return;
  }

  event_log_info (hashcat_ctx, "%s", msg);
}

static void say_flush_locked (hashcat_ctx_t *hashcat_ctx, bridge_fpga_des_kpa_t *ctx)
{
  if (ctx->say_repeat == 0) return;

  char buf[256];

  snprintf (buf, sizeof (buf), "FPGA bridge: last message repeated %" PRIu64 " times.", ctx->say_repeat);

  say_emit (hashcat_ctx, ctx->say_level, buf);

  ctx->say_repeat  = 0;
  ctx->say_last[0] = 0;
}

static void fpga_say_flush (hashcat_ctx_t *hashcat_ctx, bridge_fpga_des_kpa_t *ctx)
{
  if (ctx == NULL) return;

  hc_thread_mutex_lock (ctx->say_mux);

  say_flush_locked (hashcat_ctx, ctx);

  hc_thread_mutex_unlock (ctx->say_mux);
}

static void fpga_say (hashcat_ctx_t *hashcat_ctx, bridge_fpga_des_kpa_t *ctx, const int level, const char *fmt, ...)
{
  char buf[256];

  va_list ap;

  va_start (ap, fmt);
  vsnprintf (buf, sizeof (buf), fmt, ap);
  va_end (ap);

  if (ctx == NULL)
  {
    say_emit (hashcat_ctx, level, buf);

    return;
  }

  hc_thread_mutex_lock (ctx->say_mux);

  if (strcmp (ctx->say_last, buf) == 0)
  {
    ctx->say_repeat++;

    hc_thread_mutex_unlock (ctx->say_mux);

    return;
  }

  say_flush_locked (hashcat_ctx, ctx);

  say_emit (hashcat_ctx, level, buf);

  snprintf (ctx->say_last, sizeof (ctx->say_last), "%s", buf);

  ctx->say_level = level;

  hc_thread_mutex_unlock (ctx->say_mux);
}

static bool csr_write_verified (fpga_dev_t *dev, const u32 addr, const u32 val, const char *name, const char *who)
{
  for (u32 attempt = 0; attempt < FPGA_CFG_ATTEMPTS; attempt++)
  {
    if (dev->transport->csr_write (dev, addr, val) == false) return false;

    if ((attempt > 0) && (getenv ("HCFPGA_DEBUG") != NULL))
    {
      fprintf (stderr, "[hcfpga] board %s %s did not take, attempt %u\n", who, name, attempt + 1);
    }

    if (dev->transport->csr_read == NULL) return true;

    if (dev->transport->csr_read (dev, addr) == val) return true;

    if (dev->transport->csr_read (dev, addr) == val) return true;
  }

  fprintf (stderr, "FPGA bridge: board %s would not take its %s register after %u attempts.\n", who, name, FPGA_CFG_ATTEMPTS);

  return false;
}

static u32 ct_word (const u8 *ct, const u32 w)
{
  return (u32) ct[4 * w] | ((u32) ct[4 * w + 1] << 8) | ((u32) ct[4 * w + 2] << 16) | ((u32) ct[4 * w + 3] << 24);
}

// The batch's plaintext, targets and amplifier, each written only when it differs from what the board
// holds: a mask's tables take up to 1024 register writes, and they stay for the whole mask.

static bool send_config (fpga_dev_t *dev, member_t *member_buf, const launch_t *lc)
{
  const salt_t *salt = lc->salt;

  const bool full = (member_buf->configured == false) ? true : false;

  bool salt_changed = full;

  if (member_buf->cfg_salt_iter != salt->salt_iter) salt_changed = true;

  for (u32 i = 0; i < 4; i++)
  {
    if (member_buf->cfg_salt_buf[i] != salt->salt_buf[i]) salt_changed = true;
  }

  if (salt_changed == true)
  {
    if (csr_write_verified (dev, CSR_SALT0, salt->salt_buf[0], "salt0", member_buf->name) == false) return false;
    if (csr_write_verified (dev, CSR_SALT1, salt->salt_buf[1], "salt1", member_buf->name) == false) return false;
    if (csr_write_verified (dev, CSR_SALT2, salt->salt_buf[2], "salt2", member_buf->name) == false) return false;
    if (csr_write_verified (dev, CSR_SALT3, salt->salt_buf[3], "salt3", member_buf->name) == false) return false;

    if (csr_write_verified (dev, CSR_ITER_COUNT, salt->salt_iter, "iter_count", member_buf->name) == false) return false;

    for (u32 i = 0; i < 4; i++) member_buf->cfg_salt_buf[i] = salt->salt_buf[i];

    member_buf->cfg_salt_iter = salt->salt_iter;
  }

  if (full == true)
  {
    const u32 pad_recs = (dev->transport->in_granule > 0) ? (dev->transport->in_granule / member_buf->c2h_rec_bytes) : 1;

    if (csr_write_verified (dev, CSR_PAD_RECS, pad_recs, "pad_recs", member_buf->name) == false) return false;
  }

  for (u32 k = 0; k < TGT_CNT; k++)
  {
    if ((full == false) && (memcmp (member_buf->cfg_tgt_ct[k], lc->tgt_ct[k], 8) == 0)) continue;

    if (csr_write_verified (dev, CSR_TGT_LO (k), ct_word (lc->tgt_ct[k], 0), "tgt_lo", member_buf->name) == false) return false;
    if (csr_write_verified (dev, CSR_TGT_HI (k), ct_word (lc->tgt_ct[k], 1), "tgt_hi", member_buf->name) == false) return false;

    memcpy (member_buf->cfg_tgt_ct[k], lc->tgt_ct[k], 8);
  }

  if ((full == true) || (member_buf->cfg_tgt_mask != lc->tgt_mask))
  {
    if (csr_write_verified (dev, CSR_TGT_MASK, lc->tgt_mask, "tgt_mask", member_buf->name) == false) return false;

    member_buf->cfg_tgt_mask = lc->tgt_mask;
  }

  const bool amp_full = ((full == true) || (member_buf->cfg_amp_valid == false)) ? true : false;

  if ((amp_full == true) || (member_buf->cfg_amp_cnt != lc->amp_cnt))
  {
    if (csr_write_verified (dev, CSR_AMP_CNT, lc->amp_cnt, "amp_cnt", member_buf->name) == false) return false;

    member_buf->cfg_amp_cnt = lc->amp_cnt;
  }

  if ((amp_full == true) || (member_buf->cfg_amp_lens != lc->amp_lens))
  {
    if (csr_write_verified (dev, CSR_AMP_LENS, lc->amp_lens, "amp_lens", member_buf->name) == false) return false;

    member_buf->cfg_amp_lens = lc->amp_lens;
  }

  for (u32 p = 0; p < lc->amp_cnt; p++)
  {
    const u32 len = ((lc->amp_lens >> (8 * p)) & 0xff) + 1;

    for (u32 i = 0; i < len; i++)
    {
      const u8 c = lc->amp_tab[p][i];

      if ((amp_full == false) && (member_buf->cfg_amp_tab[p][i] == c)) continue;

      if (csr_write_verified (dev, CSR_AMP_TAB, (p << 16) | (i << 8) | c, "amp_tab", member_buf->name) == false) return false;

      member_buf->cfg_amp_tab[p][i] = c;
    }
  }

  member_buf->cfg_amp_valid = true;
  member_buf->configured    = true;

  if (getenv ("HCFPGA_DEBUG") != NULL)
  {
    fprintf (stderr, "[hcfpga] config: pt %08x%08x targets %u mask %x amp %u x %" PRIu64 "\n",
      salt->salt_buf[0], salt->salt_buf[1], lc->tgt_cnt, lc->tgt_mask, lc->amp_cnt, lc->amp_items);
  }

  return true;
}

static bool reset_framing (fpga_dev_t *dev, const char *who)
{
  if (dev->transport->csr_write == NULL) return true;

  dev->transport->csr_write (dev, CSR_CTRL, CTRL_FRAMING_RESET);

  const bool released = csr_write_verified (dev, CSR_CTRL, 0, "ctrl", who);

  return released;
}

void platform_term (hashcat_ctx_t *hashcat_ctx, void *platform_context);

static int member_label (const bridge_fpga_des_kpa_t *ctx, const int unit_idx, const int member_idx);

static void member_name (member_t *member_buf, const fpga_dev_t *dev)
{
  if (dev->ident.serial[0] != 0)
  {
    snprintf (member_buf->name, sizeof (member_buf->name), "%s", dev->ident.serial);

    return;
  }

  const char *slash = strrchr (dev->path, '/');

  snprintf (member_buf->name, sizeof (member_buf->name), "%s", (slash) ? slash + 1 : dev->path);
}

static bool unit_selected (const user_options_t *user_options, const int unit_idx)
{
  if (user_options->backend_devices == NULL) return true;

  char *devices = hcstrdup (user_options->backend_devices);

  if (devices == NULL) return true;

  bool selected = false;

  char *saveptr = NULL;

  for (char *next = strtok_r (devices, ",", &saveptr); next != NULL; next = strtok_r (NULL, ",", &saveptr))
  {
    const long id = strtol (next, NULL, 10);

    if (id != (long) (unit_idx + 1)) continue;

    selected = true;

    break;
  }

  hcfree (devices);

  return selected;
}

void *platform_init (hashcat_ctx_t *hashcat_ctx)
{
  MAYBE_UNUSED folder_config_t *folder_config = hashcat_ctx->folder_config;

  bridge_fpga_des_kpa_t *ctx = (bridge_fpga_des_kpa_t *) hcmalloc (sizeof (bridge_fpga_des_kpa_t));

  if (ctx == NULL) return NULL;

  hc_thread_mutex_init (ctx->say_mux);
  hc_thread_mutex_init (ctx->canary_mux);

  fpga_status_t status = FPGA_STATUS_OK;

  fpga_reject_t *rejects = (fpga_reject_t *) hccalloc (FPGA_MAX_REJECTS, sizeof (fpga_reject_t));

  if (rejects == NULL)
  {
    hc_thread_mutex_delete (ctx->say_mux);
    hc_thread_mutex_delete (ctx->canary_mux);

    hcfree (ctx);

    return NULL;
  }

  int rejects_cnt = 0;

  const int cnt = fpga_units_open (hashcat_ctx, ctx->devs, FPGA_MAX_DEVICES, ALGO_NAME, &fpga_csr_map_no_cpu, true, &status, rejects, &rejects_cnt);

  fpga_reject_report_all (hashcat_ctx, rejects, rejects_cnt, ALGO_NAME);

  if (cnt == 0)
  {
    fpga_status_report (hashcat_ctx, status, ALGO_NAME, 0, 0, fpga_reject_worst_ident (rejects, rejects_cnt, status), fpga_reject_worst_transport (rejects, rejects_cnt, status));

    hcfree (rejects);

    hc_thread_mutex_delete (ctx->say_mux);
    hc_thread_mutex_delete (ctx->canary_mux);

    hcfree (ctx);

    return NULL;
  }

  if (cnt == FPGA_MAX_DEVICES)
  {
    event_log_warning (hashcat_ctx, "FPGA bridge: this build supports at most %d boards.", FPGA_MAX_DEVICES);
    event_log_warning (hashcat_ctx, "Boards beyond this limit will not be used. Raise FPGA_MAX_DEVICES and rebuild.");
    event_log_warning (hashcat_ctx, NULL);
  }

  ctx->devs_cnt = cnt;

  const bool one_class = (getenv ("HCFPGA_ONE_CLASS") != NULL) ? true : false;

  int boards_per_unit = 1;

  const char *bpu_env = getenv ("HCFPGA_BOARDS_PER_UNIT");

  if (bpu_env)
  {
    const int want = atoi (bpu_env);

    if (want > 0) boards_per_unit = want;

    if (want == 0) boards_per_unit = 0;
  }

  const bool units_are_boards = ((boards_per_unit == 1) && (one_class == false)) ? true : false;

  const int late_first = rejects_cnt;

  for (int i = 0; i < cnt; i++)
  {
    fpga_dev_t *dev = &ctx->devs[i];

    const bool used = ((units_are_boards == false) || (unit_selected (hashcat_ctx->user_options, ctx->members_cnt) == true)) ? true : false;

    if ((used == true) && (fpga_unit_program_pending (hashcat_ctx, dev, ALGO_NAME, rejects, &rejects_cnt) != FPGA_STATUS_OK)) continue;

    if ((used == true) && (dev->transport->session_open (dev) == false))
    {
      event_log_error (hashcat_ctx, "FPGA bridge: could not open a session on %s.", dev->path);

      const char *data_link = dev->transport->data_link;

      char link[64];

      if ((data_link != NULL) && (strcmp (data_link, "Ethernet") == 0) && (dev->transport->link_str != NULL) && (dev->transport->link_str (dev, link, sizeof (link)) == true))
      {
        const char *addr = (strncmp (link, "Eth:", 4) == 0) ? &link[4] : link;

        event_log_info (hashcat_ctx, "The board did not answer at %s. This host needs an interface that routes to that address,", addr);
        event_log_info (hashcat_ctx, "and nothing else on the network may use it. HCFPGA_ARTYZ7_IP selects another address.");
      }
      else
      {
        event_log_info (hashcat_ctx, "Another process may still be holding the device.");
      }

      if (strcmp (dev->transport->name, "litepcie") == 0)
      {
        event_log_info (hashcat_ctx, "The litepcie driver may also predate one-shot DMA support. Rebuild it: make -C src/fpga driver");
      }

      event_log_info (hashcat_ctx, NULL);

      continue;
    }

    member_t *member_buf = &ctx->members_buf[ctx->members_cnt];

    ctx->members_cnt++;

    member_buf->dev = dev;

    member_name (member_buf, dev);

    if (used == false)
    {
      if (dev->transport->release != NULL) dev->transport->release (dev);

      member_buf->dormant   = true;
      member_buf->grain     = (dev->ident.cores > 0) ? WORKITEM_MULTIPLE (dev->ident.cores) : 32;
      member_buf->cands_max = member_buf->grain;

      continue;
    }

    member_buf->dialect = dev->transport->dialect;

    if (member_buf->dialect != FPGA_DIALECT_HCFPGA)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: %s speaks a framing this des_kpa bridge does not, and is not used.", member_buf->name);
      event_log_info (hashcat_ctx, NULL);

      dev->transport->session_close (dev);

      ctx->members_cnt--;

      continue;
    }

    member_buf->h2c_rec_bytes = H2C_REC_BYTES_MAX;
    member_buf->c2h_rec_bytes = C2H_REC_WORDS * 4;

    member_buf->out_capacity = dev->transport->out_capacity (dev);

    member_buf->cands_max = (u32) (member_buf->out_capacity / member_buf->h2c_rec_bytes);

    // The results come back into a buffer of the same capacity: up to one C2H record per target for
    // every job, the end-of-batch record and up to a granule of padding.

    const u64 c2h_cand_bytes = (u64) member_buf->c2h_rec_bytes * TGT_CNT;
    const u64 c2h_slack      = (u64) member_buf->c2h_rec_bytes + dev->transport->in_granule;
    const u64 c2h_cands      = (member_buf->out_capacity > c2h_slack) ? ((member_buf->out_capacity - c2h_slack) / c2h_cand_bytes) : 0;

    if (c2h_cands < member_buf->cands_max) member_buf->cands_max = (u32) c2h_cands;

    if (member_buf->cands_max == 0)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: %s cannot take a single candidate (%" PRIu64 " bytes of capacity).", member_buf->name, member_buf->out_capacity);
      event_log_info (hashcat_ctx, NULL);

      dev->transport->session_close (dev);

      ctx->members_cnt--;

      continue;
    }

    u32 grain = (dev->ident.cores > 0) ? WORKITEM_MULTIPLE (dev->ident.cores) : 32;

    if (grain > member_buf->cands_max) grain = member_buf->cands_max;

    member_buf->grain = grain;

    member_buf->canary_want = dev->ident.cores;

    const char *canary_env = getenv ("HCFPGA_CANARIES");

    if (canary_env)
    {
      char *end = NULL;

      const long want = strtol (canary_env, &end, 10);

      if ((end != canary_env) && (end[0] == 0) && (want >= 0) && (((u64) want + grain) <= member_buf->cands_max))
      {
        member_buf->canary_want = (u32) want;
      }
      else
      {
        event_log_warning (hashcat_ctx, "FPGA bridge: HCFPGA_CANARIES=%s is not a count that fits a batch on board %s, so it is ignored and %u canaries stay in force.", canary_env, member_buf->name, member_buf->canary_want);
      }
    }

    if (member_buf->canary_want >= member_buf->cands_max) member_buf->canary_want = 0;

    member_buf->cands_max = (u32) (((member_buf->cands_max - member_buf->canary_want) / grain) * grain);

    if (reset_framing (dev, member_buf->name) == false) member_buf->needs_refresh = true;

    member_buf->h2c = (u32 *) hcmalloc (member_buf->out_capacity + H2C_BATCH_ALIGN);

    member_buf->slot_id = (u32 *) hcmalloc (((size_t) member_buf->cands_max + member_buf->canary_want) * sizeof (u32));

    if ((member_buf->h2c == NULL) || (member_buf->slot_id == NULL))
    {
      event_log_error (hashcat_ctx, "FPGA bridge: no memory for the staging buffers of %s.", member_buf->name);
      event_log_info (hashcat_ctx, NULL);

      hcfree (member_buf->h2c);
      hcfree (member_buf->slot_id);

      member_buf->h2c     = NULL;
      member_buf->slot_id = NULL;

      dev->transport->session_close (dev);

      ctx->members_cnt--;

      continue;
    }
  }

  const fpga_reject_t *late_rejects = &rejects[late_first];

  const int late_rejects_cnt = rejects_cnt - late_first;

  fpga_reject_report_all (hashcat_ctx, late_rejects, late_rejects_cnt, ALGO_NAME);

  if (ctx->members_cnt == 0)
  {
    fpga_status_t late = FPGA_STATUS_OK;

    for (int i = 0; i < late_rejects_cnt; i++) late = MAX (late, late_rejects[i].status);

    if (late != FPGA_STATUS_OK)
    {
      fpga_status_report (hashcat_ctx, late, ALGO_NAME, 0, 0, fpga_reject_worst_ident (late_rejects, late_rejects_cnt, late), fpga_reject_worst_transport (late_rejects, late_rejects_cnt, late));
    }
    else
    {
      event_log_error (hashcat_ctx, "FPGA bridge: no detected device accepted a session.");
    }

    fpga_units_close (ctx->devs, cnt);

    hcfree (rejects);

    hc_thread_mutex_delete (ctx->say_mux);
    hc_thread_mutex_delete (ctx->canary_mux);

    hcfree (ctx);

    return NULL;
  }

  hcfree (rejects);

  for (int i = 0; i < ctx->members_cnt; i++)
  {
    member_t *member_buf = &ctx->members_buf[i];

    const fpga_dev_t *dev = member_buf->dev;

    char class_buf[1024];

    if (one_class == true)
    {
      snprintf (class_buf, sizeof (class_buf), "%s", "mixed fpga des_kpa (HCFPGA_ONE_CLASS)");
    }
    else if (dev->ident.clk_mhz > 0)
    {
      snprintf (class_buf, sizeof (class_buf), "%s %s, %u cores @ %u MHz",
        dev->ident.board, dev->ident.algo, dev->ident.cores, dev->ident.clk_mhz);
    }
    else
    {
      snprintf (class_buf, sizeof (class_buf), "%s %s, %u cores",
        dev->ident.board, dev->ident.algo, dev->ident.cores);
    }

    unit_t *unit_buf = NULL;

    for (int u = 0; u < ctx->units_cnt; u++)
    {
      if (strcmp (ctx->units_buf[u].unit_class_buf, class_buf) != 0) continue;

      if (boards_per_unit > 0)
      {
        if (ctx->units_buf[u].members_cnt >= boards_per_unit) continue;
      }

      unit_buf = &ctx->units_buf[u];

      break;
    }

    if (unit_buf == NULL)
    {
      if (ctx->units_cnt == FPGA_MAX_UNITS)
      {
        event_log_error (hashcat_ctx, "FPGA bridge: this build supports at most %d units. Board %s cannot be assigned.", FPGA_MAX_UNITS, member_buf->name);
        event_log_info  (hashcat_ctx, "A unit is one board unless HCFPGA_BOARDS_PER_UNIT groups them. Raise FPGA_MAX_DEVICES and rebuild, or group the boards.");

        continue;
      }

      unit_buf = &ctx->units_buf[ctx->units_cnt];

      ctx->units_cnt++;

      snprintf (unit_buf->unit_class_buf, sizeof (unit_buf->unit_class_buf), "%s", class_buf);
    }

    unit_buf->member_idx[unit_buf->members_cnt] = i;

    unit_buf->members_cnt++;
  }

  for (int u = 0; u < ctx->units_cnt; u++)
  {
    unit_t *unit_buf = &ctx->units_buf[u];

    u32 grain[FPGA_MAX_DEVICES];
    u32 capacity[FPGA_MAX_DEVICES];

    u64 multiple = 0;
    u64 count    = 0;

    for (int m = 0; m < unit_buf->members_cnt; m++)
    {
      const member_t *member_buf = &ctx->members_buf[unit_buf->member_idx[m]];

      grain[m]    = member_buf->grain;
      capacity[m] = member_buf->cands_max;

      multiple += member_buf->grain;
      count    += member_buf->cands_max;
    }

    u32 chunks = 1;

    if (unit_buf->members_cnt > 1)
    {
      chunks = FPGA_CHUNKS_DEFAULT;

      const char *chunks_env = getenv ("HCFPGA_CHUNKS");

      if (chunks_env)
      {
        const int want = atoi (chunks_env);

        if (want > 0) chunks = (u32) want;
      }
    }

    unit_buf->chunks = chunks;

    unit_buf->workitem_multiple = (u32) multiple;

    unit_buf->workitem_count = (multiple > 0) ? ((count / multiple) * multiple) : 0;

    unit_buf->canary_waves = CANARY_WAVES;

    if (unit_buf->workitem_count == 0)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: %s cannot stage one wave of %u candidates.", unit_buf->unit_class_buf, (u32) multiple);

      platform_term (hashcat_ctx, ctx);

      return NULL;
    }

    snprintf (unit_buf->unit_info_buf, sizeof (unit_buf->unit_info_buf), "%s x %d board%s",
      unit_buf->unit_class_buf, unit_buf->members_cnt, (unit_buf->members_cnt == 1) ? "" : "s");

    unit_buf->pool = fpga_pool_create (unit_buf->members_cnt, grain, capacity, unit_buf->chunks);

    if (unit_buf->pool == NULL)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: could not start the workers for %s.", unit_buf->unit_class_buf);

      platform_term (hashcat_ctx, ctx);

      return NULL;
    }
  }

  return ctx;
}

static void report_failures (hashcat_ctx_t *hashcat_ctx, bridge_fpga_des_kpa_t *ctx)
{
  bool any = false;

  for (int u = 0; u < ctx->units_cnt; u++)
  {
    unit_t *unit_buf = &ctx->units_buf[u];

    for (int m = 0; m < unit_buf->members_cnt; m++)
    {
      const member_t *member_buf = &ctx->members_buf[unit_buf->member_idx[m]];

      if (member_buf->fails == 0) continue;

      if (fpga_pool_alive (unit_buf->pool, m) == false) continue;

      any = true;
    }
  }

  if (any == false) return;

  bool lost = false;

  for (int u = 0; u < ctx->units_cnt; u++)
  {
    if (ctx->units_buf[u].dead_reported == true) lost = true;
  }

  event_log_info (hashcat_ctx, NULL);

  if (lost == true)
  {
    event_log_info (hashcat_ctx, "FPGA bridge: boards with batch failures. A launch failed during this run, so some candidates were not computed.");
  }
  else
  {
    event_log_info (hashcat_ctx, "FPGA bridge: boards with recovered batch failures. All failed batches were recomputed. No candidates were skipped.");
  }

  for (int u = 0; u < ctx->units_cnt; u++)
  {
    unit_t *unit_buf = &ctx->units_buf[u];

    for (int m = 0; m < unit_buf->members_cnt; m++)
    {
      member_t *member_buf = &ctx->members_buf[unit_buf->member_idx[m]];

      if (member_buf->fails == 0) continue;

      if (fpga_pool_alive (unit_buf->pool, m) == false) continue;

      if (member_buf->fails_canary > 0)
      {
        event_log_info (hashcat_ctx, "  Board #%02d (%s)  %6" PRIu64 " failure%s, %" PRIu64 " of them a wrong answer, still in use", member_label (ctx, u, m), member_buf->name, member_buf->fails, (member_buf->fails == 1) ? "" : "s", member_buf->fails_canary);

        continue;
      }

      event_log_info (hashcat_ctx, "  Board #%02d (%s)  %6" PRIu64 " failure%s, none a wrong answer, still in use", member_label (ctx, u, m), member_buf->name, member_buf->fails, (member_buf->fails == 1) ? "" : "s");
    }
  }
}

void platform_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  if (ctx == NULL) return;

  fpga_say_flush (hashcat_ctx, ctx);

  report_failures (hashcat_ctx, ctx);

  hc_thread_mutex_delete (ctx->say_mux);
  hc_thread_mutex_delete (ctx->canary_mux);


  for (int u = 0; u < ctx->units_cnt; u++)
  {
    fpga_pool_destroy (ctx->units_buf[u].pool);

    ctx->units_buf[u].pool = NULL;
  }

  for (int i = 0; i < ctx->members_cnt; i++)
  {
    hcfree (ctx->members_buf[i].h2c);
    hcfree (ctx->members_buf[i].slot_id);
  }

  for (int i = 0; i < ctx->members_cnt; i++)
  {
    if (ctx->members_buf[i].dormant == true) continue;

    fpga_dev_t *dev = ctx->members_buf[i].dev;

    dev->transport->session_close (dev);
  }

  fpga_units_close (ctx->devs, ctx->devs_cnt);

  hcfree (ctx);
}

int get_unit_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  return ctx->units_cnt;
}

int get_workitem_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  return (int) ctx->units_buf[unit_idx].workitem_count;
}

int get_workitem_multiple (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  return (int) ctx->units_buf[unit_idx].workitem_multiple;
}

typedef struct wave_model
{
  const char *board;

  u32 cores;

  u32 cycles_per_iter;
  u32 cycles_per_wave;
  u32 launch_usec;

} wave_model_t;

// Rows are measured on hardware with hcfpga_step --wave-model, as bcrypt's are. No des_kpa board has
// been measured yet, so every des_kpa board is autotuned.
static const wave_model_t WAVE_MODELS[] =
{
  { NULL,         0,     0,     0,    0 },
};

#define TUNE_SPEED_SHARE      0.99

#define TUNE_LAUNCH_MSEC_MAX  3000

static const wave_model_t *wave_model_find (const fpga_dev_t *dev)
{
  for (u32 i = 0; WAVE_MODELS[i].board != NULL; i++)
  {
    const wave_model_t *model = &WAVE_MODELS[i];

    if (strcmp (model->board, dev->ident.board) != 0) continue;

    if (model->cores != dev->ident.cores) continue;

    return model;
  }

  return NULL;
}

static double wave_model_usec (const wave_model_t *model, const fpga_dev_t *dev, const u32 iters)
{
  const double cycles = ((double) model->cycles_per_iter * (double) iters) + (double) model->cycles_per_wave;

  const double usec = cycles / (double) dev->ident.clk_mhz;

  return usec;
}

bool get_unit_tuning (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx, MAYBE_UNUSED const hashconfig_t *hashconfig, const hashes_t *hashes, MAYBE_UNUSED const double target_msec, u32 *kernel_accel, u32 *kernel_loops)
{
  const bridge_fpga_des_kpa_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  const bool dbg = (getenv ("HCFPGA_DEBUG") != NULL);

  u32 iters_min = 0xffffffff;
  u32 iters_max = 0;

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    const u32 iters = hashes->salts_buf[salt_pos].salt_iter;

    iters_min = MIN (iters_min, iters);
    iters_max = MAX (iters_max, iters);
  }

  if (iters_max == 0) return false;

  iters_min = MAX (iters_min, 1);

  double wave_usec_min = 0;
  double wave_usec_max = 0;
  double launch_usec   = 0;

  for (int m = 0; m < unit_buf->members_cnt; m++)
  {
    const fpga_dev_t *dev = ctx->members_buf[unit_buf->member_idx[m]].dev;

    const wave_model_t *model = wave_model_find (dev);

    if ((model == NULL) || (dev->ident.clk_mhz == 0))
    {
      if (dbg == true) fprintf (stderr, "[hcfpga] unit #%02d: no wave model for %s, autotuned\n", unit_idx + 1, unit_buf->unit_class_buf);

      return false;
    }

    wave_usec_min = MAX (wave_usec_min, wave_model_usec (model, dev, iters_min));
    wave_usec_max = MAX (wave_usec_max, wave_model_usec (model, dev, iters_max));
    launch_usec   = MAX (launch_usec,   (double) model->launch_usec);
  }

  if (wave_usec_min <= 0) return false;

  const double need = (TUNE_SPEED_SHARE / (1 - TUNE_SPEED_SHARE)) * launch_usec / wave_usec_min;
  const double room = ((TUNE_LAUNCH_MSEC_MAX * 1000.0) - launch_usec) / wave_usec_max;

  const u32 waves_need = (u32) MIN (need + 1, 1e6);
  const u32 waves_room = (u32) MAX (room,     1);

  *kernel_accel = MAX (MIN (waves_need, waves_room), 1);
  *kernel_loops = iters_max;

  if (dbg == true) fprintf (stderr, "[hcfpga] unit #%02d: fixed tuning, %u waves of %.1f ms at %u iterations\n", unit_idx + 1, *kernel_accel, wave_usec_max / 1000, iters_max);

  return true;
}

char *get_unit_info (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  return ctx->units_buf[unit_idx].unit_info_buf;
}

char *get_unit_class (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  return ctx->units_buf[unit_idx].unit_class_buf;
}

static int member_temperature (const member_t *member_buf);

static int member_label (const bridge_fpga_des_kpa_t *ctx, const int unit_idx, const int member_idx)
{
  if (ctx->units_buf[unit_idx].members_cnt < 2) return unit_idx + 1;

  const int label = ((unit_idx + 1) * 100) + (member_idx + 1);

  return label;
}

static int class_alive_cnt (const bridge_fpga_des_kpa_t *ctx, const char *unit_class_buf)
{
  int alive = 0;

  for (int u = 0; u < ctx->units_cnt; u++)
  {
    const unit_t *unit_buf = &ctx->units_buf[u];

    if (strcmp (unit_buf->unit_class_buf, unit_class_buf) != 0) continue;

    if (ctx->members_buf[unit_buf->member_idx[0]].dormant == true) continue;

    alive += fpga_pool_alive_cnt (unit_buf->pool);
  }

  return alive;
}

int get_unit_member_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  return ctx->units_buf[unit_idx].members_cnt;
}

static void member_link_str (const member_t *member_buf, char *buf, const size_t len)
{
  fpga_dev_t *dev = member_buf->dev;

  if (dev->transport->link_str)
  {
    if (dev->transport->link_str (dev, buf, len) == true) return;
  }

  if (dev->transport->csr_read)
  {
    const u32 status = dev->transport->csr_read (dev, CSR_PCIE_LINK_STATUS);

    snprintf (buf, len, "PCIe:%d", 1 << ((status >> 2) & 0x3));

    return;
  }

  snprintf (buf, len, "Link:N/A");
}

static void member_sensor_str (const member_t *member_buf, char *buf, const size_t len)
{
  size_t off = 0;

  if (member_temperature (member_buf) >= 0) off += snprintf (buf + off, len - off, "%sTemp", (off == 0) ? "" : "/");

  if (off == 0) snprintf (buf, len, "N/A");
}

char *get_unit_member_info (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx, const int member_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  if (member_idx >= unit_buf->members_cnt) return NULL;

  member_t *member_buf = &ctx->members_buf[unit_buf->member_idx[member_idx]];

  const fpga_dev_t *dev = member_buf->dev;

  const bool alive = fpga_pool_alive (unit_buf->pool, member_idx);

  char link[64];

  member_link_str (member_buf, link, sizeof (link));

  char sensors[64];

  member_sensor_str (member_buf, sensors, sizeof (sensors));

  char line[320];

  char fails[48];

  fails[0] = 0;

  if (member_buf->fails > 0) snprintf (fails, sizeof (fails), ", Errors:%" PRIu64, member_buf->fails);

  snprintf (line, sizeof (line), "Board #%02d: Path:%.120s, %s, ID:%s, Sensors:%s%s%s",
    member_label (ctx, unit_idx, member_idx), dev->path, link,
    (dev->ident.serial[0] != 0) ? dev->ident.serial : "N/A", sensors, fails,
    (alive == true) ? "" : ", DROPPED");

  memcpy (member_buf->info, line, sizeof (member_buf->info));

  return member_buf->info;
}

static int member_temperature (const member_t *member_buf)
{
  fpga_dev_t *dev = member_buf->dev;

  if (dev == NULL) return -1;

  if (dev->transport->temperature) return dev->transport->temperature (dev);

  if (dev->transport->csr_read == NULL) return -1;

  const u32 raw = dev->transport->csr_read (dev, CSR_XADC_TEMPERATURE);

  const int celsius = (int) ((((double) raw) * 503.975) / 4096.0 - 273.15);

  if (celsius > 125) return -1;
  if (celsius < -40) return -1;

  return celsius;
}

int get_unit_temperature_unwatched (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  int cnt = 0;

  for (int m = 0; m < unit_buf->members_cnt; m++)
  {
    const member_t *member_buf = &ctx->members_buf[unit_buf->member_idx[m]];

    if (member_temperature (member_buf) >= 0) continue;

    cnt++;
  }

  return cnt;
}

#define TEMP_SHOW  5

bool get_unit_temperature_str (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx, char *buf, const size_t len)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  if (unit_buf->members_cnt == 0) return false;

  int hot_temp[TEMP_SHOW];
  int hot_member[TEMP_SHOW];

  int hot_cnt = 0;

  int unwatched = 0;

  for (int m = 0; m < unit_buf->members_cnt; m++)
  {
    const member_t *member_buf = &ctx->members_buf[unit_buf->member_idx[m]];

    const int celsius = member_temperature (member_buf);

    if (celsius < 0)
    {
      unwatched++;

      continue;
    }

    int at = hot_cnt;

    while (at > 0)
    {
      if (hot_temp[at - 1] >= celsius) break;

      if (at < TEMP_SHOW)
      {
        hot_temp[at]   = hot_temp[at - 1];
        hot_member[at] = hot_member[at - 1];
      }

      at--;
    }

    if (at >= TEMP_SHOW) continue;

    hot_temp[at]   = celsius;
    hot_member[at] = m;

    if (hot_cnt < TEMP_SHOW) hot_cnt++;
  }

  if (hot_cnt == 0)
  {
    snprintf (buf, len, "N/A");

    return true;
  }

  int off = 0;

  for (int i = 0; i < hot_cnt; i++)
  {
    off += snprintf (buf + off, len - off, "%s#%02d:%dc", (i == 0) ? "" : " ", member_label (ctx, unit_idx, hot_member[i]), hot_temp[i]);
  }

  if (unwatched > 0) snprintf (buf + off, len - off, " +%d N/A", unwatched);

  return true;
}

u32 get_unit_temperature_abort (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  u32 limit = 0;

  for (int m = 0; m < unit_buf->members_cnt; m++)
  {
    const member_t *member_buf = &ctx->members_buf[unit_buf->member_idx[m]];

    const fpga_transport_t *transport = member_buf->dev->transport;

    u32 own = 80;

    if (transport->temperature != NULL)
    {
      if (transport->temperature_is_die == false) own = 75;
      else if (transport->temperature_abort > 0) own = transport->temperature_abort;
    }

    limit = (limit == 0) ? own : MIN (limit, own);
  }

  if (limit == 0) limit = 80;

  return limit;
}

int get_unit_temperature (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  int hottest = -1;

  for (int m = 0; m < unit_buf->members_cnt; m++)
  {
    const member_t *member_buf = &ctx->members_buf[unit_buf->member_idx[m]];

    const int celsius = member_temperature (member_buf);

    hottest = MAX (hottest, celsius);
  }

  return hottest;
}

int get_unit_corespeed (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  if (unit_buf->members_cnt == 0) return -1;

  const u32 clk_mhz = ctx->members_buf[unit_buf->member_idx[0]].dev->ident.clk_mhz;

  if (clk_mhz == 0) return -1;

  const int mhz = (int) clk_mhz;

  return mhz;
}

bool get_unit_buslanes_str (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx, char *buf, const size_t len)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  if (unit_buf->members_cnt == 0) return false;

  fpga_dev_t *dev = ctx->members_buf[unit_buf->member_idx[0]].dev;

  if (dev == NULL) return false;

  if (dev->transport->link_str == NULL) return false;

  const bool result = dev->transport->link_str (dev, buf, len);

  return result;
}

int get_unit_buslanes (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  if (unit_buf->members_cnt == 0) return -1;

  fpga_dev_t *dev = ctx->members_buf[unit_buf->member_idx[0]].dev;

  if (dev->transport->link_str) return -1;

  if (dev->transport->csr_read == NULL) return -1;

  const u32 status = dev->transport->csr_read (dev, CSR_PCIE_LINK_STATUS);

  const int lanes = 1 << ((status >> 2) & 0x3);

  return lanes;
}

static u64 fill_batch (member_t *member_buf, const des_kpa_bridge_tmp_t *tmps, const u64 pws_cnt, const u32 canary_want, const u8 *canary_base, u64 *h2c_bytes)
{
  const u64 recs = pws_cnt + canary_want;

  u8 *h2c8 = (u8 *) member_buf->h2c;

  u64 acc  = 0;
  u64 ci   = 0;
  u64 used = 0;

  const u8 *canary_pw  = canary_base;
  const u32 canary_len = 8;

  for (u64 slot = 0; slot < recs; slot++)
  {
    acc += canary_want;

    u32 ekid = 0;

    const u8 *pw  = NULL;
    u32       len = 0;

    if (acc >= recs)
    {
      acc -= recs;

      ekid = CANARY_IDX;

      pw  = canary_pw;
      len = canary_len;
    }
    else
    {
      ekid = (u32) ci;

      pw  = (const u8 *) tmps[ci].pw_buf;
      len = MIN (tmps[ci].pw_len, (u32) FPGA_PW_MAX);

      ci++;
    }

    member_buf->slot_id[slot] = ekid;

    u32 *rec = (u32 *) (void *) &h2c8[used];

    rec[0] = (H2C_TAG << 24) | len;
    rec[1] = ekid;

    const u32 words = (len + 3) / 4;

    for (u32 i = 0; i < words; i++)
    {
      u32 val = 0;

      for (u32 k = 0; k < 4; k++)
      {
        const u32 at = (i * 4) + k;

        const u8 c = (at < len) ? pw[at] : 0;

        val = (val << 8) | c;
      }

      rec[2 + i] = val;
    }

    used += H2C_REC_BYTES (len);
  }

  const u64 tail = used % H2C_BATCH_ALIGN;

  if (tail != 0)
  {
    const u64 pad = H2C_BATCH_ALIGN - tail;

    memset ((u8 *) member_buf->h2c + used, 0, pad);

    used += pad;
  }

  if (h2c_bytes != NULL) *h2c_bytes = used;

  return recs;
}

static u64 batch_wait_ms (const fpga_dev_t *dev, const u64 amp_items, const u64 recs)
{
  const u32 cores = (dev->ident.cores   > 0) ? WORKITEM_MULTIPLE (dev->ident.cores) : 1;
  const u32 mhz   = (dev->ident.clk_mhz > 0) ? dev->ident.clk_mhz : 100;

  const u64 waves  = (recs + cores - 1) / cores;
  const u64 cycles = waves * (MAX (amp_items, 1) + WAVE_CYCLES_FIXED + ((u64) cores * WAVE_CYCLES_CORE));

  const u64 expect_ms = cycles / ((u64) mhz * 1000);

  const u64 result = MAX ((u64) WAIT_MS_MIN, expect_ms * WAIT_SLACK);

  return result;
}

typedef struct
{
  u64 in_ns;
  u64 fill_ns;
  u64 send_ns;
  u64 recv_ns;
  u64 gap_ns;
  u64 last_end_ns;
  u64 calls;
  u64 cands;

} pipe_stat_t;

static pipe_stat_t g_pipe[FPGA_MAX_DEVICES];

static void pipe_report (const bridge_fpga_des_kpa_t *ctx, const int member_idx)
{
  pipe_stat_t *p = &g_pipe[member_idx];

  if (p->calls == 0) return;

  const double in  = (double) p->in_ns  / 1.0e6;
  const double gap = (double) p->gap_ns / 1.0e6;

  const double total = in + gap;

  if (total <= 0.0) return;

  fprintf (stderr, "[pipe] board %s: %" PRIu64 " ranges, in-bridge %.0f ms (%.1f%%) [fill %.0f send %.0f recv %.0f], host gap %.0f ms (%.1f%%), device-only %.0f H/s, effective %.0f H/s\n",
    ctx->members_buf[member_idx].name, p->calls, in, 100.0 * in / total,
    (double) p->fill_ns / 1.0e6, (double) p->send_ns / 1.0e6, (double) p->recv_ns / 1.0e6,
    gap, 100.0 * gap / total,
    (double) p->cands / (in / 1000.0), (double) p->cands / (total / 1000.0));
}

static bool member_fault_forced (void)
{
  const char *env = getenv ("HCFPGA_FAULT_STREAK");

  if (env == NULL) return false;

  return (atoi (env) != 0) ? true : false;
}

typedef struct inject
{
  bool  on;

  int   board;
  int   fault;
  u64   period;
  u64   burst;
  bool  sticky;

} inject_t;

#define INJECT_FAULT_NONE   0
#define INJECT_FAULT_CONFIG 1
#define INJECT_FAULT_CANARY 2
#define INJECT_FAULT_SEND   3
#define INJECT_FAULT_LOSE   4

static u64 inject_u64 (const char *name, const u64 dflt)
{
  const char *env = getenv (name);

  if (env == NULL) return dflt;

  return (u64) strtoull (env, NULL, 10);
}

static const inject_t *inject_cfg (void)
{
  static inject_t cfg;
  static bool     done = false;

  if (done == true) return &cfg;

  const char *what = getenv ("HCFPGA_INJECT_FAULT");

  if (what == NULL)
  {
    done = true;

    return &cfg;
  }

  if (strcmp (what, "config") == 0) cfg.fault = INJECT_FAULT_CONFIG;
  if (strcmp (what, "canary") == 0) cfg.fault = INJECT_FAULT_CANARY;
  if (strcmp (what, "send")   == 0) cfg.fault = INJECT_FAULT_SEND;
  if (strcmp (what, "lose")   == 0) cfg.fault = INJECT_FAULT_LOSE;

  if (cfg.fault == INJECT_FAULT_NONE)
  {
    done = true;

    return &cfg;
  }

  cfg.board  = (int) inject_u64 ("HCFPGA_INJECT_BOARD", 0);
  cfg.period = inject_u64 ("HCFPGA_INJECT_PERIOD", 10);
  cfg.burst  = inject_u64 ("HCFPGA_INJECT_BURST", 1);
  cfg.sticky = (inject_u64 ("HCFPGA_INJECT_STICKY", 0) != 0) ? true : false;

  if (cfg.period == 0) cfg.period = 1;
  if (cfg.burst  == 0) cfg.burst  = 1;

  cfg.on = true;

  done = true;

  return &cfg;
}

static bool inject_due (const inject_t *cfg, const int member_idx, const int fault, const u64 batch_num)
{
  if (cfg->on == false) return false;
  if (cfg->fault != fault) return false;

  if ((cfg->board != 0) && (cfg->board != (member_idx + 1))) return false;

  const u64 phase = batch_num % cfg->period;

  return (phase < cfg->burst) ? true : false;
}

static fpga_pool_verdict_t member_fault (launch_t *lc, const int member_idx, member_t *member_buf, const member_fault_t fault, const u32 sig)
{
  hashcat_ctx_t *hashcat_ctx = lc->hashcat_ctx;

  member_buf->fails++;

  if (fault == MEMBER_FAULT_CANARY) member_buf->fails_canary++;

  member_buf->needs_refresh = true;

  if (member_fault_forced () == true)
  {
    member_buf->fault_streak = MEMBER_FATAL_ATTEMPTS;
  }
  else if ((fault == member_buf->fault_last) && (sig == member_buf->fault_sig))
  {
    member_buf->fault_streak++;
  }
  else
  {
    member_buf->fault_last   = fault;
    member_buf->fault_sig    = sig;
    member_buf->fault_streak = 1;
  }

  member_buf->fault_run++;

  if (fault == MEMBER_FAULT_OVERSIZE) return FPGA_POOL_DEAD;

  const u32 fatal_at = (fault == MEMBER_FAULT_CANARY) ? MEMBER_FATAL_STREAK : MEMBER_FATAL_ATTEMPTS;

  const bool streak_fatal = (member_buf->fault_streak >= fatal_at) ? true : false;
  const bool run_fatal    = (member_buf->fault_run >= MEMBER_FATAL_RUN) ? true : false;

  if ((streak_fatal == true) || (run_fatal == true))
  {
    fpga_say_flush (hashcat_ctx, lc->ctx);

    if (streak_fatal == true)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: board #%02d (%s) %s %u times in a row and is being dropped.", member_label (lc->ctx, lc->unit_idx, member_idx), member_buf->name, fault_name (fault), member_buf->fault_streak);
    }
    else
    {
      event_log_error (hashcat_ctx, "FPGA bridge: board #%02d (%s) failed %u times in a row without completing a range and is being dropped. Most recently it %s.", member_label (lc->ctx, lc->unit_idx, member_idx), member_buf->name, member_buf->fault_run, fault_name (fault));
    }

    const fpga_board_t *info = fpga_board_find (member_buf->dev->ident.board);

    const bool usb = ((info) && (strcmp (info->bus, "USB") == 0)) ? true : false;

    const char *data_link = member_buf->dev->transport->data_link;

    if ((data_link != NULL) && (strcmp (data_link, "Ethernet") == 0))
    {
      event_log_info (hashcat_ctx, "Check the board's power, its network cable and switch port, and that this host still reaches the board's address.");
    }
    else if (usb == true)
    {
      event_log_info (hashcat_ctx, "Check the board's power, USB cable, and other devices sharing its hub.");
    }
    else
    {
      event_log_info (hashcat_ctx, "Check that the card is seated, auxiliary power is connected, and the PCIe slot is operational.");
    }

    event_log_info (hashcat_ctx, NULL);

    event_log_info (hashcat_ctx, "des_kpa has no board diagnostic of its own yet. HCFPGA_DEBUG=1 prints every batch and register read.");
    event_log_info (hashcat_ctx, NULL);

    return FPGA_POOL_DEAD;
  }

  bool report = false;

  if (member_buf->noisy_reported == false) report = true;

  for (u64 mark = 10; mark <= member_buf->fails; mark *= 10)
  {
    if (member_buf->fails == mark) report = true;
  }

  if (report == true)
  {
    if (member_buf->noisy_reported == false)
    {
      member_buf->noisy_reported = true;

      fpga_say (hashcat_ctx, lc->ctx, SAY_WARNING, "Board #%02d (%s) %s. It is being restarted and given the work again.", member_label (lc->ctx, lc->unit_idx, member_idx), member_buf->name, fault_name (fault));
      fpga_say (hashcat_ctx, lc->ctx, SAY_WARNING, "No candidate is skipped: the batch is redone. A repeat of a line is counted, not printed.");
    }
    else
    {
      fpga_say (hashcat_ctx, lc->ctx, SAY_WARNING, "Board #%02d (%s) has now failed %" PRIu64 " batches, each redone. This board is worth checking.", member_label (lc->ctx, lc->unit_idx, member_idx), member_buf->name, member_buf->fails);
    }
  }

  return FPGA_POOL_RETRY;
}

// The key of amplifier item `item` over a job's base word, as the device builds it: position p takes
// the character of digit p of the item, position 0 the fastest.

static void amp_key (const launch_t *lc, const u8 *base, const u64 item, u8 key[8])
{
  memcpy (key, base, 8);

  u64 v = item;

  for (u32 p = 0; p < lc->amp_cnt; p++)
  {
    const u32 len = ((lc->amp_lens >> (8 * p)) & 0xff) + 1;

    key[p] = lc->amp_tab[p][v % len];

    v /= len;
  }
}

typedef struct
{
  u32 idx;
  u32 il_pos;
  u32 digest[2];

} hit_t;

static fpga_pool_verdict_t run_range (launch_t *lc, const int member_idx, const u64 from, const u64 cnt)
{
  hashcat_ctx_t *hashcat_ctx = lc->hashcat_ctx;

  bridge_fpga_des_kpa_t *ctx = lc->ctx;

  const int global_idx = lc->unit_buf->member_idx[member_idx];

  member_t *member_buf = &ctx->members_buf[global_idx];

  fpga_dev_t *dev = member_buf->dev;

  const salt_t *salt = lc->salt;

  des_kpa_bridge_tmp_t *tmps = lc->tmps + from;

  const bool pipe_on = (getenv ("HCFPGA_PIPE") != NULL) ? true : false;

  const u64 pipe_t0 = fpga_now_ns ();

  const bool retrying = member_buf->needs_refresh;

  member_buf->batches++;

  if (member_buf->needs_refresh == true)
  {
    member_buf->needs_refresh = false;

    member_buf->configured = false;

    if (dev->transport->session_refresh == NULL)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: board %s cannot be restarted safely after a failed batch.", member_buf->name);

      const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_REFRESH, 0);

      return verdict;
    }

    // Hold the datapath in its framing reset while the transport empties its rings, and release it
    // after (reset_framing). A core still computing the failed batch would otherwise put results
    // into the emptied C2H ring, where the next batch would read them as its own; a fast core does
    // that within the refresh. The first write is not verified: the link is resynchronised by
    // session_refresh, and reset_framing verifies the release.

    if (dev->transport->csr_write != NULL) dev->transport->csr_write (dev, CSR_CTRL, CTRL_FRAMING_RESET);

    if ((dev->transport->session_refresh (dev) == false) || (reset_framing (dev, member_buf->name) == false))
    {
      event_log_error (hashcat_ctx, "FPGA bridge: board %s could not be restarted after a failure.", member_buf->name);

      const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_REFRESH, 0);

      return verdict;
    }
  }

  // The device compares on its own and returns only hits, so it has to say when a batch is done.

  if ((dev->transport->batch_done == NULL) || (dev->transport->csr_write == NULL))
  {
    event_log_error (hashcat_ctx, "FPGA bridge: board %s is reached through a transport that cannot end a batch on the device's word.", member_buf->name);

    return FPGA_POOL_DEAD;
  }

  const bool cfg = send_config (dev, member_buf, lc);

  const bool cfg_injected = inject_due (inject_cfg (), member_idx, INJECT_FAULT_CONFIG, member_buf->batches);

  if ((cfg == false) || (cfg_injected == true))
  {
    event_log_error (hashcat_ctx, "FPGA bridge: board %s refused its plaintext, target or amplifier configuration.", member_buf->name);

    member_buf->configured = false;

    const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_CONFIG, 0);

    return verdict;
  }

  if (cnt > member_buf->cands_max)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: range of %" PRIu64 " candidates exceeds the limit of %u for board %s.", cnt, member_buf->cands_max, member_buf->name);

    const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_OVERSIZE, 0);

    return verdict;
  }

  // A canary job walks the whole amplifier like any other, so a mask batch carries one. A batch of
  // whole keys carries one per core.

  const u32 canary_cnt  = (lc->amp_cnt > 0) ? MIN (member_buf->canary_want, 1u) : member_buf->canary_want;
  const u32 canary_want = ((lc->canary_on == true) || (retrying == true)) ? canary_cnt : 0;

  u64 canary_seen = 0;
  u64 canary_bad  = 0;
  u16 canary_bad_core = 0;

  u32 canary_bad_sig = 0;

  u64 recv = 0;

  u64 false_hits = 0;
  u16 false_core = 0;

  hit_t *hits     = NULL;
  u64    hits_cnt = 0;
  u64    hits_max = 0;

  bool ok = true;

  member_fault_t fault = MEMBER_FAULT_NONE;

  u32 fault_sig = 0;

  const int dbg = (getenv ("HCFPGA_DEBUG") != NULL);

  fpga_timing_begin (&member_buf->timing);

  u64 fill_bytes = 0;

  const u64 t_fill = fpga_now_ns ();

  const u64 recs = fill_batch (member_buf, tmps, cnt, canary_want, lc->canary_base, &fill_bytes);

  if (pipe_on == true) g_pipe[global_idx].fill_ns += fpga_now_ns () - t_fill;

  if (recs == 0) return FPGA_POOL_DONE;

  const u64 h2c_bytes = fill_bytes;

  // Room for every job to hit every target, the end-of-batch record and a granule of padding.

  u64 c2h_bytes = (recs * TGT_CNT * member_buf->c2h_rec_bytes) + member_buf->c2h_rec_bytes;

  if (dev->transport->in_granule > 0)
  {
    const u64 gran = dev->transport->in_granule;

    c2h_bytes = ((c2h_bytes + gran - 1) / gran) * gran;
  }

  bool armed = csr_write_verified (dev, CSR_BATCH_TARGET, (u32) recs, "batch_target", member_buf->name);

  if ((armed == true) && (dev->transport->csr_read != NULL) && (dev->transport->retired_reads_zero == false))
  {
    armed = false;

    for (u32 attempt = 0; attempt < FPGA_CFG_ATTEMPTS; attempt++)
    {
      if (dev->transport->csr_read (dev, CSR_RETIRED) == 0)
      {
        armed = true;

        break;
      }

      dev->transport->csr_write (dev, CSR_BATCH_TARGET, (u32) recs);
    }
  }

  if (armed == false)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: board %s refused a batch size of %" PRIu64 ".", member_buf->name, recs);

    const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_CONFIG, 0);

    return verdict;
  }

  const u64 wait_ms = batch_wait_ms (dev, lc->amp_items, recs);

  dev->batch_wait_ms = wait_ms;

  if (dev->transport->batch_begin (dev, h2c_bytes, c2h_bytes, member_buf->c2h_rec_bytes, (u32) recs) == false)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: board %s could not begin a batch of %" PRIu64 " records.", member_buf->name, recs);

    const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_BEGIN, 0);

    return verdict;
  }

  const u64 t_send = fpga_now_ns ();

  const bool sent_ok = dev->transport->batch_send (dev, member_buf->h2c, h2c_bytes);

  if (pipe_on == true) g_pipe[global_idx].send_ns += fpga_now_ns () - t_send;

  const bool send_injected = inject_due (inject_cfg (), member_idx, INJECT_FAULT_SEND, member_buf->batches);

  if ((sent_ok == false) || (send_injected == true))
  {
    dev->transport->batch_end (dev);

    const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_SEND, 0);

    return verdict;
  }

  if (dbg) fprintf (stderr, "[hcfpga] %s batch: recs=%" PRIu64 " h2c=%" PRIu64 " B c2h=%" PRIu64 " B canaries=%u amp=%" PRIu64 "\n", member_buf->name, recs, h2c_bytes, c2h_bytes, canary_want, lc->amp_items);

  const char *dbuf = (const char *) lc->hashes->digests_buf;

  u64 in_done = 0;

  u64 quiet_since_ns = fpga_now_ns ();

  const u64 t_recv = fpga_now_ns ();

  u64 therm_ms = 0;

  while (in_done < c2h_bytes)
  {
    u32 processed = 0;

    if (dev->transport->batch_done (dev, &processed) == true)
    {
      if (processed != recs)
      {
        event_log_error (hashcat_ctx, "FPGA bridge: board %s reports %u jobs processed of %" PRIu64 " sent.", member_buf->name, processed, recs);

        ok = false;

        fault = MEMBER_FAULT_SHORT;
      }

      break;
    }

    u64 bytes = 0;

    const u32 *rxbuf = (const u32 *) dev->transport->batch_recv (dev, &bytes, WAIT_SLICE_MS);

    if (rxbuf == NULL)
    {
      if ((dev->transport->batch_failed != NULL) && (dev->transport->batch_failed (dev) == true))
      {
        event_log_error (hashcat_ctx, "FPGA bridge: board %s failed the batch rather than timing out (%" PRIu64 " hits).", member_buf->name, recv);

        ok = false;

        fault = MEMBER_FAULT_INCOMPLETE;

        break;
      }

      if ((fpga_now_ns () - quiet_since_ns) > (wait_ms * 1000000ull))
      {
        // A board that is quiet because its thermal stop holds the generator is cooling, not stuck:
        // wait for it, up to THERM_WAIT_MS_MAX.
        if ((dev->transport->csr_read != NULL) && (therm_ms < THERM_WAIT_MS_MAX) && ((dev->transport->csr_read (dev, CSR_STATUS) & STATUS_THERM_STOP) != 0))
        {
          if (therm_ms == 0) event_log_warning (hashcat_ctx, "FPGA bridge: board %s is too hot and holds its keys back until it cools; the batch waits for it.", member_buf->name);

          therm_ms += wait_ms;

          quiet_since_ns = fpga_now_ns ();

          continue;
        }

        if ((dev->transport->csr_read != NULL) && (dev->transport->retired_reads_zero == false))
        {
          const u32 retired = dev->transport->csr_read (dev, CSR_RETIRED);

          event_log_error (hashcat_ctx, "FPGA bridge: board %s stopped responding after %" PRIu64 " ms (%" PRIu64 " hits, %" PRIu64 " of %" PRIu64 " bytes, device retired %u of %" PRIu64 ").", member_buf->name, wait_ms, recv, in_done, c2h_bytes, retired, recs);

          if (dbg == true) hcfpga_debug_window (dev);
        }
        else
        {
          event_log_error (hashcat_ctx, "FPGA bridge: board %s stopped responding after %" PRIu64 " ms (%" PRIu64 " hits, %" PRIu64 " of %" PRIu64 " bytes).", member_buf->name, wait_ms, recv, in_done, c2h_bytes);

          if ((dbg == true) && (dev->transport->csr_read != NULL)) hcfpga_debug_window (dev);
        }

        ok = false;

        fault = MEMBER_FAULT_TIMEOUT;

        break;
      }

      continue;
    }

    quiet_since_ns = fpga_now_ns ();

    in_done += bytes;

    for (u64 boff = 0; boff < bytes; boff += member_buf->c2h_rec_bytes)
    {
      const u32 *f = &rxbuf[boff / 4];

      if ((f[7] >> 16) == C2H_FLAG_EOB) continue;

      // A hit: the job's id, the amplifier item, the target slot, and the core that found it.

      const u32 idx     = f[0];
      const u32 item    = f[1];
      const u32 tgt     = f[2] & 0xff;
      const u16 core_id = (u16) (f[7] & 0xffff);

      fpga_timing_first (&member_buf->timing);

      if (dbg) fprintf (stderr, "[hcfpga] %s hit: job %08x item %u target %u core %u\n", member_buf->name, idx, item, tgt, core_id);

      if (idx == CANARY_IDX)
      {
        if (inject_due (inject_cfg (), member_idx, INJECT_FAULT_LOSE, member_buf->batches) == true) continue;

        u32 got_item = item;

        if (inject_due (inject_cfg (), member_idx, INJECT_FAULT_CANARY, member_buf->batches) == true)
        {
          got_item ^= (inject_cfg ()->sticky == true) ? 0xdeadbeef : (u32) (member_buf->batches | 1);
        }

        canary_seen++;

        if ((got_item != lc->canary_item) || (tgt != TGT_CANARY))
        {
          canary_bad++;
          canary_bad_core = core_id;

          if (canary_bad == 1) canary_bad_sig = got_item;

          if (dbg) fprintf (stderr, "[hcfpga] canary bad: item %u target %u, want item %u target %u\n", got_item, tgt, lc->canary_item, (u32) TGT_CANARY);
        }

        continue;
      }

      if (idx >= cnt) continue;

      // A job whose key is the canary's (bar parity) hits the canary's target too. That is not a hash
      // of the salt's.

      if (tgt == TGT_CANARY) continue;

      // Every hit is encrypted again here, so that a wrong key never reaches hashcat.

      u8 key[8];

      amp_key (lc, (const u8 *) tmps[idx].pw_buf, item, key);

      u8 ct[8];

      hcfpga_deskpa_encrypt (key, (const u8 *) salt->salt_buf, ct);

      u64 il_pos = 0;

      bool good = ((tgt < lc->tgt_cnt) && (memcmp (ct, lc->tgt_ct[tgt], 8) == 0)) ? true : false;

      if ((good == true) && (lc->amp != NULL)) good = bridge_amp_rank (lc->amp, key, &il_pos);

      if (good == false)
      {
        false_hits++;
        false_core = core_id;

        continue;
      }

      if (hits_cnt == hits_max)
      {
        hits = (hit_t *) hcrealloc (hits, hits_max * sizeof (hit_t), 64 * sizeof (hit_t));

        hits_max += 64;
      }

      const u32 *d = (const u32 *) (const void *) &dbuf[(salt->digests_offset + lc->tgt_digest[tgt]) * lc->hashconfig->dgst_size];

      hits[hits_cnt].idx       = idx;
      hits[hits_cnt].il_pos    = (u32) il_pos;
      hits[hits_cnt].digest[0] = d[0];
      hits[hits_cnt].digest[1] = d[1];

      hits_cnt++;

      recv++;
    }
  }

  if (pipe_on == true) g_pipe[global_idx].recv_ns += fpga_now_ns () - t_recv;

  dev->transport->batch_end (dev);

  if ((ok == true) && (dev->transport->csr_read != NULL) && ((dev->transport->csr_read (dev, CSR_STATUS) & STATUS_LOST_HIT) != 0))
  {
    event_log_error (hashcat_ctx, "FPGA bridge: board %s found more hits in one job than it could hold, so the batch will be recomputed.", member_buf->name);

    ok = false;

    fault = MEMBER_FAULT_INCOMPLETE;
  }

  if ((ok == true) && (canary_want > 0) && (canary_seen < canary_want))
  {
    event_log_error (hashcat_ctx, "FPGA bridge: board %s returned %" PRIu64 " of its %u canaries.", member_buf->name, canary_seen, canary_want);
    event_log_info (hashcat_ctx, "This indicates incorrect computation or a lost batch. The results are untrusted and the batch will be recomputed.");

    ok = false;

    fault = MEMBER_FAULT_NOCANARY;
  }

  if (canary_bad > 0)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: board %s returned a wrong answer for a known-answer canary from core %u (%" PRIu64 " of %" PRIu64 " bad).", member_buf->name, canary_bad_core, canary_bad, canary_seen);
    event_log_info (hashcat_ctx, "The batch will be recomputed. A transfer fault is as likely as a faulty core. Power-cycle and");
    event_log_info (hashcat_ctx, "retest the board to tell the two apart.");

    ok = false;

    fault = MEMBER_FAULT_CANARY;

    fault_sig = canary_bad_sig;
  }

  if (false_hits > 0)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: board %s reported %" PRIu64 " key%s that do not encrypt to its target, the last from core %u.", member_buf->name, false_hits, (false_hits == 1) ? "" : "s", false_core);
    event_log_info (hashcat_ctx, "The batch will be recomputed.");

    ok = false;

    fault = MEMBER_FAULT_CANARY;

    fault_sig = 0xfa15e000u | false_core;
  }

  if (member_fault_forced () == true)
  {
    ok = false;

    fault = MEMBER_FAULT_SHORT;

    fault_sig = 0;
  }

  fpga_timing_end (&member_buf->timing, "TIMING", recs, recv, cnt);

  if (pipe_on == true)
  {
    pipe_stat_t *p = &g_pipe[global_idx];

    const u64 now = fpga_now_ns ();

    if (p->last_end_ns > 0) p->gap_ns += pipe_t0 - p->last_end_ns;

    p->in_ns += now - pipe_t0;
    p->last_end_ns = now;
    p->calls++;
    p->cands += cnt;

    if ((p->calls % 50) == 0) pipe_report (ctx, global_idx);
  }

  if (ok == false)
  {
    hcfree (hits);

    const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, fault, fault_sig);

    return verdict;
  }

  // The batch is good: hand its hits to the kernel. A work item holds DES_KPA_HITS of them over all
  // of a launch's target groups.

  for (u64 h = 0; h < hits_cnt; h++)
  {
    des_kpa_bridge_tmp_t *t = &tmps[hits[h].idx];

    if (t->hit_cnt >= DES_KPA_HITS)
    {
      if (member_buf->hits_dropped++ == 0) event_log_warning (hashcat_ctx, "FPGA bridge: one base word cracked more than %u hashes of one plaintext at once; the others crack when the mask is run again.", (u32) DES_KPA_HITS);

      continue;
    }

    t->hit_il[t->hit_cnt]        = hits[h].il_pos;
    t->hit_digest[t->hit_cnt][0] = hits[h].digest[0];
    t->hit_digest[t->hit_cnt][1] = hits[h].digest[1];

    t->hit_cnt++;
  }

  hcfree (hits);

  member_buf->fault_last   = MEMBER_FAULT_NONE;
  member_buf->fault_sig    = 0;
  member_buf->fault_streak = 0;
  member_buf->fault_run    = 0;

  return FPGA_POOL_DONE;
}

static fpga_pool_verdict_t launch_work (void *arg, const int member, const u64 from, const u64 cnt)
{
  launch_t *lc = (launch_t *) arg;

  const fpga_pool_verdict_t result = run_range (lc, member, from, cnt);

  return result;
}

static void report_dropped (hashcat_ctx_t *hashcat_ctx, bridge_fpga_des_kpa_t *ctx, const int unit_idx, unit_t *unit_buf)
{
  const int alive = fpga_pool_alive_cnt (unit_buf->pool);

  for (int m = 0; m < unit_buf->members_cnt; m++)
  {
    member_t *member_buf = &ctx->members_buf[unit_buf->member_idx[m]];

    if (fpga_pool_alive (unit_buf->pool, m) == true) continue;

    if (member_buf->reported == true) continue;

    member_buf->reported = true;

    if (alive > 0)
    {
      event_log_warning (hashcat_ctx, "Board #%02d (%s) failed and was removed. Its work was reassigned to the other %d board%s in this unit.", member_label (ctx, unit_idx, m), member_buf->name, alive, (alive == 1) ? "" : "s");
    }

  }
}

// One run of jobs that share one salt. The device takes one plaintext per batch and compares against
// TGT_USER of its hashes at a time, so a salt with more hashes than that runs the jobs once per group of
// them. amp is the mask's amplifier the device walks over every job, NULL for jobs of whole keys.

static bool launch_run (hashcat_ctx_t *hashcat_ctx, bridge_fpga_des_kpa_t *ctx, hc_device_param_t *device_param, hashconfig_t *hashconfig, hashes_t *hashes, const u32 salt_pos, des_kpa_bridge_tmp_t *run_tmps, const u64 pw_cnt, const bridge_amp_t *amp)
{
  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &ctx->units_buf[unit_idx];

  const salt_t *salt = &hashes->salts_buf[salt_pos];

  if ((salt->salt_len < FPGA_SALT_MIN) || (salt->salt_len > FPGA_SALT_MAX) || (salt->salt_iter < FPGA_ITER_MIN) || (salt->salt_iter > FPGA_ITER_MAX))
  {
    event_log_error (hashcat_ctx, "FPGA bridge: a salt of %u bytes with %u iterations is outside what the device computes (%u to %u bytes, %u to %u iterations).", salt->salt_len, salt->salt_iter, (u32) FPGA_SALT_MIN, (u32) FPGA_SALT_MAX, (u32) FPGA_ITER_MIN, (u32) FPGA_ITER_MAX);

    return false;
  }

  launch_t lc;

  memset (&lc, 0, sizeof (lc));

  lc.hashcat_ctx = hashcat_ctx;
  lc.ctx         = ctx;
  lc.unit_buf    = unit_buf;
  lc.unit_idx    = unit_idx;
  lc.tmps        = run_tmps;
  lc.salt        = salt;
  lc.hashes      = hashes;
  lc.hashconfig  = hashconfig;
  lc.amp         = amp;

  // The amplifier as the device's registers and tables take it.

  lc.amp_items = 1;

  if (amp != NULL)
  {
    if ((amp->pos_cnt > AMP_POS_MAX) || (amp->cnt > 0xffffffffull))
    {
      event_log_error (hashcat_ctx, "FPGA bridge: an amplifier of %u positions and %" PRIu64 " candidates is larger than the device walks.", amp->pos_cnt, amp->cnt);

      return false;
    }

    lc.amp_cnt = amp->pos_cnt;

    for (u32 p = 0; p < amp->pos_cnt; p++)
    {
      const cs_t *cs = &amp->css[p];

      if ((cs->cs_len == 0) || (cs->cs_len > 256)) return false;

      lc.amp_lens |= (cs->cs_len - 1) << (8 * p);

      for (u32 i = 0; i < cs->cs_len; i++) lc.amp_tab[p][i] = (u8) cs->cs_buf[i];

      lc.amp_items *= cs->cs_len;
    }
  }

  // The canary: a job on CANARY_KEY that has to hit TGT_CANARY at a known item, in the middle of
  // the amplifier. Its ciphertext must not be one of the salt's hashes, or the device would report
  // that hash instead.

  const char *dbuf = (const char *) hashes->digests_buf;

  // The self test's salt carries no digest count, and its one hash is not the user's: digests_shown
  // belongs to the user's hashes.

  const bool self_test = (hashes->digests_buf == hashes->st_digests_buf) ? true : false;

  const u32 digests_cnt = (salt->digests_cnt > 0) ? salt->digests_cnt : 1;

  u8 canary_ct[8];

  memcpy (lc.canary_base, CANARY_KEY, 8);

  for (u32 p = 0; p < lc.amp_cnt; p++) lc.canary_base[p] = 0;

  for (u32 attempt = 0; ; attempt++)
  {
    lc.canary_item = (u32) (((lc.amp_items / 2) + attempt) % lc.amp_items);

    u8 key[8];

    amp_key (&lc, lc.canary_base, lc.canary_item, key);

    if (lc.amp_cnt == 0) key[7] ^= (u8) (attempt << 1);

    if (lc.amp_cnt == 0) lc.canary_base[7] = key[7];

    hcfpga_deskpa_encrypt (key, (const u8 *) salt->salt_buf, canary_ct);

    bool clash = false;

    for (u32 i = 0; i < digests_cnt; i++)
    {
      const u32 *d = (const u32 *) (const void *) &dbuf[(salt->digests_offset + i) * hashconfig->dgst_size];

      u8 ct[8];

      hcfpga_deskpa_digest_ct (d, ct);

      if (memcmp (ct, canary_ct, 8) == 0) clash = true;
    }

    if (clash == false) break;
  }

  memcpy (lc.tgt_ct[TGT_CANARY], canary_ct, 8);

  const u64 waves = CEILDIV (pw_cnt, (u64) MAX (unit_buf->workitem_multiple, 1));

  if (unit_buf->canary_arm > 0)
  {
    unit_buf->canary_arm--;

    lc.canary_on = true;

    unit_buf->canary_waves = 0;
  }
  else
  {
    unit_buf->canary_waves += waves;

    lc.canary_on = (unit_buf->canary_waves >= CANARY_WAVES) ? true : false;

    if (lc.canary_on == true) unit_buf->canary_waves = 0;
  }

  // The salt's hashes still to crack, TGT_USER at a time.

  u32 next = 0;

  bool ok = true;

  while (ok == true)
  {
    lc.tgt_cnt  = 0;
    lc.tgt_mask = 1u << TGT_CANARY;

    for (; (next < digests_cnt) && (lc.tgt_cnt < TGT_USER); next++)
    {
      if ((self_test == false) && (hashes->digests_shown != NULL) && (hashes->digests_shown[salt->digests_offset + next] == 1)) continue;

      const u32 *d = (const u32 *) (const void *) &dbuf[(salt->digests_offset + next) * hashconfig->dgst_size];

      hcfpga_deskpa_digest_ct (d, lc.tgt_ct[lc.tgt_cnt]);

      lc.tgt_digest[lc.tgt_cnt] = next;

      lc.tgt_mask |= 1u << lc.tgt_cnt;

      lc.tgt_cnt++;
    }

    if (lc.tgt_cnt == 0) break;

    if (getenv ("HCFPGA_DEBUG") != NULL) fprintf (stderr, "[hcfpga] launch: %" PRIu64 " jobs, %u targets of %u, amp %u x %" PRIu64 "\n", pw_cnt, lc.tgt_cnt, digests_cnt, lc.amp_cnt, lc.amp_items);

    for (u32 k = lc.tgt_cnt; k < TGT_USER; k++) memset (lc.tgt_ct[k], 0, 8);

    ok = fpga_pool_run (unit_buf->pool, pw_cnt, launch_work, &lc);

    // The canary rides along with the first group only.

    lc.canary_on = false;
  }

  report_dropped (hashcat_ctx, ctx, unit_idx, unit_buf);

  u64 fails_now = 0;

  for (int m = 0; m < unit_buf->members_cnt; m++) fails_now += ctx->members_buf[unit_buf->member_idx[m]].fails;

  if (fails_now > unit_buf->fails_seen) unit_buf->canary_arm = CANARY_ARM_LAUNCHES;

  unit_buf->fails_seen = fails_now;

  if (ok == false)
  {
    if (fpga_pool_alive_cnt (unit_buf->pool) == 0) device_param->skipped_warning = true;

    if (unit_buf->dead_reported == false)
    {
      unit_buf->dead_reported = true;

      if (fpga_pool_alive_cnt (unit_buf->pool) == 0)
      {
        const int class_left = class_alive_cnt (ctx, unit_buf->unit_class_buf);

        if (class_left > 0)
        {
          event_log_warning (hashcat_ctx, "FPGA bridge: unit #%02d has no board left and is out of the run. %d board%s of %s still working. Grouping boards into one unit is what lets a failure be absorbed, see HCFPGA_BOARDS_PER_UNIT.", unit_idx + 1, class_left, (class_left == 1) ? "" : "s", unit_buf->unit_class_buf);
        }
        else
        {
          event_log_error (hashcat_ctx, "FPGA bridge: no board of %s is left to take the work.", unit_buf->unit_class_buf);
        }
      }
      else
      {
        event_log_error (hashcat_ctx, "FPGA bridge: work on %s could not be placed on any board.", unit_buf->unit_class_buf);
      }
    }
  }

  return ok;
}

// Attack mode 9 pairs every candidate with its own hash, so candidate i of the launch takes
// salts_buf[pws_pos + i] (bridge_salt_pos), while hashcat hands salt_pos 0. The device takes one salt
// per batch, so the range is cut into runs of candidates on one salt, one batch each. In any other mode
// bridge_salt_pos returns salt_pos for every candidate and the range is one run.

bool launch_loop (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  des_kpa_bridge_tmp_t *tmps = (des_kpa_bridge_tmp_t *) device_param->h_tmps;

  if (hashconfig->pw_max > FPGA_PW_MAX)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: this mode accepts passwords up to %u bytes, but the device supports up to %u.", hashconfig->pw_max, (u32) FPGA_PW_MAX);

    return false;
  }

  u64 run_from = 0;

  while (run_from < pws_cnt)
  {
    const u32 run_salt_pos = bridge_salt_pos (hashcat_ctx, device_param, hashes, salt_pos, run_from);

    u64 run_to = run_from + 1;

    while ((run_to < pws_cnt) && (bridge_salt_pos (hashcat_ctx, device_param, hashes, salt_pos, run_to) == run_salt_pos))
    {
      run_to++;
    }

    if (launch_run (hashcat_ctx, ctx, device_param, hashconfig, hashes, run_salt_pos, &tmps[run_from], run_to - run_from, NULL) == false) return false;

    run_from = run_to;
  }

  return true;
}

// How much of a mask the device walks: its AMP_POS_MAX tables, and enough positions to keep a core
// busy for a while on every job.

bool get_mask_amp (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, u32 *pos_max, u64 *amp_min)
{
  *pos_max = AMP_POS_MAX;
  *amp_min = AMP_MIN;

  return true;
}

// A mask launch: the pws_cnt work items are base words, and the device tests each with every item of
// the amplifier. Attack mode 3 has one salt per launch.

bool launch_loop_amp (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt, const bridge_amp_t *amp)
{
  bridge_fpga_des_kpa_t *ctx = platform_context;

  des_kpa_bridge_tmp_t *tmps = (des_kpa_bridge_tmp_t *) device_param->h_tmps;

  if (pws_cnt == 0) return true;

  const bool ok = launch_run (hashcat_ctx, ctx, device_param, hashconfig, hashes, salt_pos, tmps, pws_cnt, amp);

  return ok;
}

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  bridge_ctx->bridge_context_size      = BRIDGE_CONTEXT_SIZE_CURRENT;
  bridge_ctx->bridge_interface_version = BRIDGE_INTERFACE_VERSION_CURRENT;

  bridge_ctx->platform_init         = platform_init;
  bridge_ctx->platform_term         = platform_term;
  bridge_ctx->get_unit_count        = get_unit_count;
  bridge_ctx->get_unit_info         = get_unit_info;
  bridge_ctx->get_unit_class        = get_unit_class;
  bridge_ctx->get_unit_member_count = get_unit_member_count;
  bridge_ctx->get_unit_member_info  = get_unit_member_info;
  bridge_ctx->get_workitem_count    = get_workitem_count;
  bridge_ctx->get_workitem_multiple = get_workitem_multiple;
  bridge_ctx->get_unit_tuning       = get_unit_tuning;
  bridge_ctx->launch_loop           = launch_loop;
  bridge_ctx->get_mask_amp          = get_mask_amp;
  bridge_ctx->launch_loop_amp       = launch_loop_amp;

  bridge_ctx->get_unit_temperature     = get_unit_temperature;
  bridge_ctx->get_unit_temperature_str = get_unit_temperature_str;
  bridge_ctx->get_unit_temperature_abort = get_unit_temperature_abort;
  bridge_ctx->get_unit_temperature_unwatched = get_unit_temperature_unwatched;
  bridge_ctx->get_unit_corespeed   = get_unit_corespeed;
  bridge_ctx->get_unit_buslanes    = get_unit_buslanes;
  bridge_ctx->get_unit_buslanes_str = get_unit_buslanes_str;
}
