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
#include "fpga/hcfpga_bridge.h"

// The bridge every algorithm after bcrypt shares. It started as a copy of bridge_fpga_bcrypt.c
// (by way of the first port, md5crypt), with every algorithm-specific value moved into the
// algorithm's hcfpga_algo_t (hcfpga_bridge.h) and bcrypt's ZTEX pkt_comm dialect left out. An
// algorithm links this file and supplies the hooks in its own bridge_fpga_<algo>.c.

static const hcfpga_algo_t *ALGO = NULL;

#define ALGO_NAME (ALGO->name)

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

#define CSR_PCIE_LINK_STATUS  0x2800
#define CSR_XADC_TEMPERATURE  0x4000

#define CTRL_FRAMING_RESET  0x00000001

#define DIGEST_WORDS      HCFPGA_DIGEST_WORDS_MAX
#define C2H_REC_WORDS     8

#define C2H_FLAG_EOB      0x8000u

#define CMP_BITS          128
#define CMP_WORDS         4
#define CMP_INDEX(d0)     ((d0) & 0x7f)

#define FPGA_PW_MAX       (ALGO->pw_max)

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

#define WAVE_CYCLES_PER_ITER (ALGO->wait_cycles_per_iter)

#define WAIT_SLACK      4

#define WAIT_MS_MIN     30000

#define WAIT_SLICE_MS   2

#define WORKITEM_MULTIPLE(cores)  ((cores) * ALGO->grain_per_core)

#define FPGA_CHUNKS_DEFAULT  2

#define CANARY_PW_DEFAULT  "hcfpga-ztex-canary"

static const char *canary_password (void)
{
  return (ALGO->canary_pw != NULL) ? ALGO->canary_pw : CANARY_PW_DEFAULT;
}

// The tmp struct is the module's, laid out as hcfpga_bridge.h describes; the algorithm gives its
// offsets with HCFPGA_TMP_LAYOUT.

static u8 *tmp_at (u8 *tmps, const u64 i)
{
  return tmps + (i * ALGO->tmp_size);
}

static u32 tmp_pw_len (const u8 *tmps, const u64 i)
{
  const u32 *p = (const u32 *) (const void *) (tmps + (i * ALGO->tmp_size) + ALGO->tmp_pw_len_off);

  return p[0];
}

static const u8 *tmp_pw_buf (const u8 *tmps, const u64 i)
{
  return tmps + (i * ALGO->tmp_size) + ALGO->tmp_pw_buf_off;
}

static u32 *tmp_digest (u8 *tmps, const u64 i)
{
  return (u32 *) (void *) (tmps + (i * ALGO->tmp_size) + ALGO->tmp_digest_off);
}

// What makes a configuration: everything of the salt the device or the canary can depend on.
// digests_cnt and digests_done move as hashes crack, so they are left out.

static bool salt_same (const salt_t *a, const salt_t *b)
{
  if (a->salt_len   != b->salt_len)   return false;
  if (a->salt_iter  != b->salt_iter)  return false;
  if (a->salt_iter2 != b->salt_iter2) return false;
  if (a->salt_iter3 != b->salt_iter3) return false;

  if (memcmp (a->salt_buf,  b->salt_buf,  sizeof (a->salt_buf))  != 0) return false;
  if (memcmp (a->salt_sign, b->salt_sign, sizeof (a->salt_sign)) != 0) return false;

  return true;
}

void hcfpga_digest_swap32 (const u32 *c2h, u32 *digest)
{
  for (u32 k = 0; k < ALGO->digest_words; k++) digest[k] = byte_swap_32 (c2h[k]);
}

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

  u32     cmp_sentinel;

  u32     cmp_bm[CMP_WORDS];

  bool    cmp_all;
  bool    returns_all;

  bool    configured;
  salt_t  cfg_salt;

  u32     cfg_digests_offset;
  u32     cfg_digests_cnt;

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

  bool    canary_valid;

  salt_t  canary_salt;

  u32     canary_gold[DIGEST_WORDS];

  u64     canary_waves;
  u32     canary_arm;
  u64     fails_seen;

  bool    dead_reported;

} unit_t;

typedef struct
{
  hashcat_ctx_t     *hashcat_ctx;

  struct hcfpga_bridge *ctx;

  unit_t            *unit_buf;

  int                unit_idx;

  u8                *tmps;

  const salt_t      *salt;
  hashes_t          *hashes;
  hashconfig_t      *hashconfig;

  u32                canary_gold[DIGEST_WORDS];

  bool               canary_on;

} launch_t;

typedef struct canary_entry
{
  salt_t salt;

  u32  gold[DIGEST_WORDS];

  bool valid;

} canary_entry_t;

typedef struct hcfpga_bridge
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
  canary_entry_t   *canary_cache;
  u32               canary_cache_cnt;

} hcfpga_bridge_t;

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

static void say_flush_locked (hashcat_ctx_t *hashcat_ctx, hcfpga_bridge_t *ctx)
{
  if (ctx->say_repeat == 0) return;

  char buf[256];

  snprintf (buf, sizeof (buf), "FPGA bridge: last message repeated %" PRIu64 " times.", ctx->say_repeat);

  say_emit (hashcat_ctx, ctx->say_level, buf);

  ctx->say_repeat  = 0;
  ctx->say_last[0] = 0;
}

static void fpga_say_flush (hashcat_ctx_t *hashcat_ctx, hcfpga_bridge_t *ctx)
{
  if (ctx == NULL) return;

  hc_thread_mutex_lock (ctx->say_mux);

  say_flush_locked (hashcat_ctx, ctx);

  hc_thread_mutex_unlock (ctx->say_mux);
}

static void fpga_say (hashcat_ctx_t *hashcat_ctx, hcfpga_bridge_t *ctx, const int level, const char *fmt, ...)
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

static u32 cmp_sentinel_pick (const salt_t *salt, const hashes_t *hashes, const hashconfig_t *hashconfig)
{
  const char *dbuf = (const char *) hashes->digests_buf;

  const u32 digests_cnt = (salt->digests_cnt > 0) ? salt->digests_cnt : 1;

  u32 sentinel = 0xa5a5a5a5u;

  for (;;)
  {
    bool clash = false;

    for (u32 i = 0; i < digests_cnt; i++)
    {
      const u32 *d = (const u32 *) (const void *) &dbuf[(salt->digests_offset + i) * hashconfig->dgst_size];

      if (d[0] == sentinel) clash = true;
    }

    if (clash == false) break;

    sentinel++;
  }

  return sentinel;
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

struct hcfpga_cfg
{
  fpga_dev_t *dev;

  const char *who;

};

bool hcfpga_cfg_write (hcfpga_cfg_t *cfg, const u32 addr, const u32 val, const char *name)
{
  return csr_write_verified (cfg->dev, addr, val, name, cfg->who);
}

static bool send_config (fpga_dev_t *dev, member_t *member_buf, const salt_t *salt, const hashes_t *hashes, const hashconfig_t *hashconfig, const u32 *canary_gold)
{
  u32 salt_regs[4] = { salt->salt_buf[0], salt->salt_buf[1], salt->salt_buf[2], salt->salt_buf[3] };

  u32 iter_count = salt->salt_iter;

  if (ALGO->config_regs != NULL) ALGO->config_regs (salt, salt_regs, &iter_count);

  if (csr_write_verified (dev, CSR_SALT0, salt_regs[0], "salt0", member_buf->name) == false) return false;
  if (csr_write_verified (dev, CSR_SALT1, salt_regs[1], "salt1", member_buf->name) == false) return false;
  if (csr_write_verified (dev, CSR_SALT2, salt_regs[2], "salt2", member_buf->name) == false) return false;
  if (csr_write_verified (dev, CSR_SALT3, salt_regs[3], "salt3", member_buf->name) == false) return false;

  if (csr_write_verified (dev, CSR_ITER_COUNT, iter_count, "iter_count", member_buf->name) == false) return false;

  if (ALGO->config_extra != NULL)
  {
    hcfpga_cfg_t cfg;

    cfg.dev = dev;
    cfg.who = member_buf->name;

    if (ALGO->config_extra (&cfg, salt) == false) return false;
  }

  const u32 pad_recs = (dev->transport->in_granule > 0) ? (dev->transport->in_granule / member_buf->c2h_rec_bytes) : 1;

  if (csr_write_verified (dev, CSR_PAD_RECS, pad_recs, "pad_recs", member_buf->name) == false) return false;

  u32 bm[CMP_WORDS];

  const bool cmp_off = (getenv ("HCFPGA_CMP_OFF") != NULL) || (dev->transport->batch_done == NULL);

  if (cmp_off == true)
  {
    for (u32 i = 0; i < CMP_WORDS; i++) bm[i] = 0xffffffffu;
  }
  else
  {
    for (u32 i = 0; i < CMP_WORDS; i++) bm[i] = 0;

    const char *dbuf = (const char *) hashes->digests_buf;

    const u32 digests_cnt = (salt->digests_cnt > 0) ? salt->digests_cnt : 1;

    for (u32 i = 0; i < digests_cnt; i++)
    {
      const u32 *d = (const u32 *) (const void *) &dbuf[(salt->digests_offset + i) * hashconfig->dgst_size];

      const u32 idx = CMP_INDEX (d[0]);

      bm[idx / 32] |= 1u << (idx % 32);
    }

    const u32 cidx = CMP_INDEX (canary_gold[0]);

    bm[cidx / 32] |= 1u << (cidx % 32);

    if (hashes->st_digests_buf != NULL)
    {
      const u32 *sd = (const u32 *) (const void *) hashes->st_digests_buf;

      const u32 sidx = CMP_INDEX (sd[0]);

      bm[sidx / 32] |= 1u << (sidx % 32);
    }
  }

  if (csr_write_verified (dev, CSR_CMP_BM0, bm[0], "cmp_bm0", member_buf->name) == false) return false;
  if (csr_write_verified (dev, CSR_CMP_BM1, bm[1], "cmp_bm1", member_buf->name) == false) return false;
  if (csr_write_verified (dev, CSR_CMP_BM2, bm[2], "cmp_bm2", member_buf->name) == false) return false;

  if (csr_write_verified (dev, CSR_CMP_BM3, bm[3], "cmp_bm3", member_buf->name) == false) return false;

  for (u32 i = 0; i < CMP_WORDS; i++) member_buf->cmp_bm[i] = bm[i];

  member_buf->cmp_all = cmp_off;

  member_buf->cmp_sentinel = cmp_sentinel_pick (salt, hashes, hashconfig);

  if (getenv ("HCFPGA_DEBUG") != NULL)
  {
    fprintf (stderr, "[hcfpga] cmp bitmap %08x%08x%08x%08x pad_recs=%u sentinel=%08x%s\n",
      bm[3], bm[2], bm[1], bm[0], pad_recs, member_buf->cmp_sentinel, cmp_off ? " (HCFPGA_CMP_OFF)" : "");
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

static void platform_term (hashcat_ctx_t *hashcat_ctx, void *platform_context);

static int member_label (const hcfpga_bridge_t *ctx, const int unit_idx, const int member_idx);

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

// The hooks are the algorithm's own file; refuse a set that cannot work rather than misbehave later.

static bool algo_valid (hashcat_ctx_t *hashcat_ctx)
{
  const char *why = NULL;

  if (ALGO == NULL)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: bridge_init () did not hand the shared bridge an algorithm.");

    return false;
  }

  if ((ALGO->name == NULL) || (ALGO->core_name == NULL))                    why = "name and core_name are required";
  else if ((ALGO->digest_words == 0) || (ALGO->digest_words > HCFPGA_DIGEST_WORDS_MAX)) why = "the tmp struct's digest must be 1 to 6 words";
  else if ((ALGO->pw_max == 0) || (ALGO->pw_max > (ALGO->tmp_pw_words * 4)) || (ALGO->pw_max > 255)) why = "pw_max must fit the tmp struct's pw_buf and the H2C length byte";
  else if (ALGO->grain_per_core == 0)                                       why = "grain_per_core must be at least 1";
  else if (ALGO->iter_min == 0)                                             why = "iter_min must be at least 1: candidates are spread over hashcat's loop calls by the iteration count";
  else if (ALGO->canary_digest == NULL)                                     why = "canary_digest is required";
  else if (strlen (canary_password ()) > ALGO->pw_max)                      why = "the canary password is longer than pw_max";

  if (why == NULL) return true;

  event_log_error (hashcat_ctx, "FPGA bridge: the %s bridge's hooks cannot work: %s.", (ALGO->name != NULL) ? ALGO->name : "?", why);

  return false;
}

static void *platform_init (hashcat_ctx_t *hashcat_ctx)
{
  MAYBE_UNUSED folder_config_t *folder_config = hashcat_ctx->folder_config;

  if (algo_valid (hashcat_ctx) == false) return NULL;

  hcfpga_bridge_t *ctx = (hcfpga_bridge_t *) hcmalloc (sizeof (hcfpga_bridge_t));

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
      event_log_error (hashcat_ctx, "FPGA bridge: %s speaks a framing this %s bridge does not, and is not used.", member_buf->name, ALGO_NAME);
      event_log_info (hashcat_ctx, NULL);

      dev->transport->session_close (dev);

      ctx->members_cnt--;

      continue;
    }

    member_buf->h2c_rec_bytes = H2C_REC_BYTES_MAX;
    member_buf->c2h_rec_bytes = C2H_REC_WORDS * 4;

    member_buf->out_capacity = dev->transport->out_capacity (dev);

    member_buf->cands_max = (u32) (member_buf->out_capacity / member_buf->h2c_rec_bytes);

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
      snprintf (class_buf, sizeof (class_buf), "mixed fpga %s (HCFPGA_ONE_CLASS)", ALGO_NAME);
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

static void report_failures (hashcat_ctx_t *hashcat_ctx, hcfpga_bridge_t *ctx)
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

static void platform_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  hcfpga_bridge_t *ctx = platform_context;

  if (ctx == NULL) return;

  fpga_say_flush (hashcat_ctx, ctx);

  report_failures (hashcat_ctx, ctx);

  hc_thread_mutex_delete (ctx->say_mux);
  hc_thread_mutex_delete (ctx->canary_mux);

  hcfree (ctx->canary_cache);

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

static int get_unit_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  hcfpga_bridge_t *ctx = platform_context;

  return ctx->units_cnt;
}

static int get_workitem_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

  return (int) ctx->units_buf[unit_idx].workitem_count;
}

static int get_workitem_multiple (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

  return (int) ctx->units_buf[unit_idx].workitem_multiple;
}

typedef hcfpga_wave_model_t wave_model_t;

#define TUNE_SPEED_SHARE      0.99

#define TUNE_LAUNCH_MSEC_MAX  3000

static const wave_model_t *wave_model_find (const fpga_dev_t *dev)
{
  if (ALGO->wave_models == NULL) return NULL;

  for (u32 i = 0; ALGO->wave_models[i].board != NULL; i++)
  {
    const wave_model_t *model = &ALGO->wave_models[i];

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

static bool get_unit_tuning (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx, MAYBE_UNUSED const hashconfig_t *hashconfig, const hashes_t *hashes, MAYBE_UNUSED const double target_msec, u32 *kernel_accel, u32 *kernel_loops)
{
  const hcfpga_bridge_t *ctx = platform_context;

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

static char *get_unit_info (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

  return ctx->units_buf[unit_idx].unit_info_buf;
}

static char *get_unit_class (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

  return ctx->units_buf[unit_idx].unit_class_buf;
}

static int member_temperature (const member_t *member_buf);

static int member_label (const hcfpga_bridge_t *ctx, const int unit_idx, const int member_idx)
{
  if (ctx->units_buf[unit_idx].members_cnt < 2) return unit_idx + 1;

  const int label = ((unit_idx + 1) * 100) + (member_idx + 1);

  return label;
}

static int class_alive_cnt (const hcfpga_bridge_t *ctx, const char *unit_class_buf)
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

static int get_unit_member_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

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

static char *get_unit_member_info (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx, const int member_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

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

static int get_unit_temperature_unwatched (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

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

static bool get_unit_temperature_str (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx, char *buf, const size_t len)
{
  hcfpga_bridge_t *ctx = platform_context;

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

static u32 get_unit_temperature_abort (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

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

static int get_unit_temperature (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

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

static int get_unit_corespeed (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  if (unit_buf->members_cnt == 0) return -1;

  const u32 clk_mhz = ctx->members_buf[unit_buf->member_idx[0]].dev->ident.clk_mhz;

  if (clk_mhz == 0) return -1;

  const int mhz = (int) clk_mhz;

  return mhz;
}

static bool get_unit_buslanes_str (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx, char *buf, const size_t len)
{
  hcfpga_bridge_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  if (unit_buf->members_cnt == 0) return false;

  fpga_dev_t *dev = ctx->members_buf[unit_buf->member_idx[0]].dev;

  if (dev == NULL) return false;

  if (dev->transport->link_str == NULL) return false;

  const bool result = dev->transport->link_str (dev, buf, len);

  return result;
}

static int get_unit_buslanes (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  hcfpga_bridge_t *ctx = platform_context;

  const unit_t *unit_buf = &ctx->units_buf[unit_idx];

  if (unit_buf->members_cnt == 0) return -1;

  fpga_dev_t *dev = ctx->members_buf[unit_buf->member_idx[0]].dev;

  if (dev->transport->link_str) return -1;

  if (dev->transport->csr_read == NULL) return -1;

  const u32 status = dev->transport->csr_read (dev, CSR_PCIE_LINK_STATUS);

  const int lanes = 1 << ((status >> 2) & 0x3);

  return lanes;
}

static u64 fill_batch (member_t *member_buf, const u8 *tmps, const u64 pws_cnt, const u32 canary_want, u64 *h2c_bytes)
{
  const u64 recs = pws_cnt + canary_want;

  u8 *h2c8 = (u8 *) member_buf->h2c;

  u64 acc  = 0;
  u64 ci   = 0;
  u64 used = 0;

  const u8 *canary_pw  = (const u8 *) canary_password ();
  const u32 canary_len = (u32) strlen (canary_password ());

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

      pw  = tmp_pw_buf (tmps, ci);
      len = MIN (tmp_pw_len (tmps, ci), (u32) FPGA_PW_MAX);

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

static u64 batch_wait_ms (const fpga_dev_t *dev, const u32 salt_iter, const u64 recs)
{
  const u32 cores = (dev->ident.cores   > 0) ? WORKITEM_MULTIPLE (dev->ident.cores) : 1;
  const u32 mhz   = (dev->ident.clk_mhz > 0) ? dev->ident.clk_mhz : 100;
  const u32 iters = (salt_iter          > 0) ? salt_iter          : 1;

  const u64 waves  = (recs + cores - 1) / cores;
  const u64 cycles = waves * (u64) iters * (u64) WAVE_CYCLES_PER_ITER;

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

static void pipe_report (const hcfpga_bridge_t *ctx, const int member_idx)
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

    if (ALGO->diag_hint != NULL)
    {
      event_log_info (hashcat_ctx, "%s", ALGO->diag_hint);
    }
    else
    {
      event_log_info (hashcat_ctx, "%s has no board diagnostic of its own yet. HCFPGA_DEBUG=1 prints every batch and register read.", ALGO_NAME);
    }
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

static fpga_pool_verdict_t run_range (launch_t *lc, const int member_idx, const u64 from, const u64 cnt)
{
  hashcat_ctx_t *hashcat_ctx = lc->hashcat_ctx;

  hcfpga_bridge_t *ctx = lc->ctx;

  const int global_idx = lc->unit_buf->member_idx[member_idx];

  member_t *member_buf = &ctx->members_buf[global_idx];

  fpga_dev_t *dev = member_buf->dev;

  const salt_t *salt = lc->salt;

  u8 *tmps = tmp_at (lc->tmps, from);

  const bool pipe_on = (getenv ("HCFPGA_PIPE") != NULL) ? true : false;

  const u64 pipe_t0 = fpga_now_ns ();

  const u32 *canary_gold = lc->canary_gold;

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

  bool config_changed = false;

  if (member_buf->configured == false) config_changed = true;
  if (salt_same (&member_buf->cfg_salt, salt) == false) config_changed = true;
  if (member_buf->cfg_digests_offset != salt->digests_offset) config_changed = true;
  if (member_buf->cfg_digests_cnt != salt->digests_cnt) config_changed = true;

  if (config_changed == true)
  {
    const bool cfg = send_config (dev, member_buf, salt, lc->hashes, lc->hashconfig, canary_gold);

    const bool cfg_injected = inject_due (inject_cfg (), member_idx, INJECT_FAULT_CONFIG, member_buf->batches);

    if ((cfg == false) || (cfg_injected == true))
    {
      event_log_error (hashcat_ctx, "FPGA bridge: board %s refused a salt and cost configuration.", member_buf->name);

      const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_CONFIG, 0);

      return verdict;
    }

    member_buf->cfg_salt           = *salt;
    member_buf->cfg_digests_offset = salt->digests_offset;
    member_buf->cfg_digests_cnt    = salt->digests_cnt;
    member_buf->configured         = true;
  }

  if (cnt > member_buf->cands_max)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: range of %" PRIu64 " candidates exceeds the limit of %u for board %s.", cnt, member_buf->cands_max, member_buf->name);

    const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_OVERSIZE, 0);

    return verdict;
  }

  const u32 canary_want = ((lc->canary_on == true) || (retrying == true)) ? member_buf->canary_want : 0;

  bool *got = (bool *) hccalloc (cnt, sizeof (bool));

  if (got == NULL)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: no memory to track %" PRIu64 " candidates for %s.", cnt, member_buf->name);

    return FPGA_POOL_DEAD;
  }

  u64 canary_seen = 0;
  u64 canary_bad  = 0;
  u16 canary_bad_core = 0;

  u32 canary_bad_sig = 0;

  u64 recv = 0;

  u64 unfiltered = 0;

  bool ok = true;

  member_fault_t fault = MEMBER_FAULT_NONE;

  u32 fault_sig = 0;

  const int dbg = (getenv ("HCFPGA_DEBUG") != NULL);

  fpga_timing_begin (&member_buf->timing);

  u64 fill_bytes = 0;

  const u64 t_fill = fpga_now_ns ();

  const u64 recs = fill_batch (member_buf, tmps, cnt, canary_want, &fill_bytes);

  if (pipe_on == true) g_pipe[global_idx].fill_ns += fpga_now_ns () - t_fill;

  if (recs == 0)
  {
    hcfree (got);

    return FPGA_POOL_DONE;
  }

  const bool device_compares = (dev->transport->batch_done != NULL) ? true : false;

  const u64 h2c_bytes = fill_bytes;

  u64 c2h_bytes = recs * member_buf->c2h_rec_bytes;

  if ((device_compares == true) && (dev->transport->in_granule > 0))
  {
    const u64 gran = dev->transport->in_granule;

    c2h_bytes = ((c2h_bytes + member_buf->c2h_rec_bytes + gran - 1) / gran) * gran;
  }
  else if (device_compares == true)
  {
    c2h_bytes += member_buf->c2h_rec_bytes;
  }

  if ((device_compares == true) && (dev->transport->csr_write != NULL))
  {
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

      hcfree (got);

      const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_CONFIG, 0);

      return verdict;
    }
  }

  const u64 wait_ms = batch_wait_ms (dev, member_buf->cfg_salt.salt_iter, recs);

  dev->batch_wait_ms = wait_ms;

  if (dev->transport->batch_begin (dev, h2c_bytes, c2h_bytes, member_buf->c2h_rec_bytes, (u32) recs) == false)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: board %s could not begin a batch of %" PRIu64 " records.", member_buf->name, recs);

    hcfree (got);

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

    hcfree (got);

    const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, MEMBER_FAULT_SEND, 0);

    return verdict;
  }

  if (dbg) fprintf (stderr, "[hcfpga] %s batch: recs=%" PRIu64 " h2c=%" PRIu64 " B c2h=%" PRIu64 " B canaries=%u\n", member_buf->name, recs, h2c_bytes, c2h_bytes, canary_want);

  u64 in_done = 0;

  if (device_compares == true)
  {
    for (u64 i = 0; i < cnt; i++)
    {
      tmp_digest (tmps, i)[0] = member_buf->cmp_sentinel;
    }
  }

  u64 quiet_since_ns = fpga_now_ns ();

  const u64 t_recv = fpga_now_ns ();

  while (in_done < c2h_bytes)
  {

    if (device_compares == true)
    {
      u32 processed = 0;

      if (dev->transport->batch_done (dev, &processed) == true)
      {
        if (processed != recs)
        {
          event_log_error (hashcat_ctx, "FPGA bridge: board %s reports %u candidates processed of %" PRIu64 " sent.", member_buf->name, processed, recs);

          ok = false;

          fault = MEMBER_FAULT_SHORT;
        }

        break;
      }
    }

    u64 bytes = 0;

    const u32 *rxbuf = (const u32 *) dev->transport->batch_recv (dev, &bytes, WAIT_SLICE_MS);

    if (rxbuf == NULL)
    {
      if ((dev->transport->batch_failed != NULL) && (dev->transport->batch_failed (dev) == true))
      {
        event_log_error (hashcat_ctx, "FPGA bridge: board %s failed the batch rather than timing out (%" PRIu64 " of %" PRIu64 " results).", member_buf->name, recv, cnt);

        ok = false;

        fault = MEMBER_FAULT_INCOMPLETE;

        break;
      }

      if ((fpga_now_ns () - quiet_since_ns) > (wait_ms * 1000000ull))
      {
        if ((dev->transport->csr_read != NULL) && (dev->transport->retired_reads_zero == false))
        {
          const u32 retired = dev->transport->csr_read (dev, CSR_RETIRED);

          event_log_error (hashcat_ctx, "FPGA bridge: board %s stopped responding after %" PRIu64 " ms (%" PRIu64 " of %" PRIu64 " results, %" PRIu64 " of %" PRIu64 " bytes, device retired %u of %" PRIu64 ").", member_buf->name, wait_ms, recv, cnt, in_done, c2h_bytes, retired, recs);

          if (dbg == true) hcfpga_debug_window (dev);
        }
        else
        {
          event_log_error (hashcat_ctx, "FPGA bridge: board %s stopped responding after %" PRIu64 " ms (%" PRIu64 " of %" PRIu64 " results, %" PRIu64 " of %" PRIu64 " bytes).", member_buf->name, wait_ms, recv, cnt, in_done, c2h_bytes);

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
      u32 idx = 0;

      u32 digest[DIGEST_WORDS];

      u16 core_id = 0;

      {
        const u32 *f = &rxbuf[boff / 4];

        if ((f[7] >> 16) == C2H_FLAG_EOB) continue;

        idx = f[0];

        // C2H words 1.. carry the digest; the algorithm says how they become digest_buf words.
        if (ALGO->digest_from_c2h != NULL)
        {
          ALGO->digest_from_c2h (&f[1], digest);
        }
        else
        {
          for (u32 k = 0; k < ALGO->digest_words; k++) digest[k] = f[1 + k];
        }

        // core_id names what the device can tell apart, ALGO->core_name in messages.
        core_id = (u16) (f[7] & 0xffff);
      }

      fpga_timing_first (&member_buf->timing);

      if (idx == CANARY_IDX)
      {
        if (inject_due (inject_cfg (), member_idx, INJECT_FAULT_LOSE, member_buf->batches) == true) continue;

        if (inject_due (inject_cfg (), member_idx, INJECT_FAULT_CANARY, member_buf->batches) == true)
        {
          digest[0] ^= (inject_cfg ()->sticky == true) ? 0xdeadbeef : (u32) (member_buf->batches | 1);
        }

        bool cbad = false;

        for (u32 k = 0; k < ALGO->digest_words; k++)
        {
          if (digest[k] != canary_gold[k]) cbad = true;
        }

        canary_seen++;

        if (cbad == true)
        {
          canary_bad++;
          canary_bad_core = core_id;

          if (canary_bad == 1) canary_bad_sig = digest[0];

          if (dbg)
          {
            fprintf (stderr, "[hcfpga] canary bad: got ");
            for (u32 k = 0; k < ALGO->digest_words; k++) fprintf (stderr, " %08x", digest[k]);
            fprintf (stderr, "\n[hcfpga] canary bad: want");
            for (u32 k = 0; k < ALGO->digest_words; k++) fprintf (stderr, " %08x", canary_gold[k]);
            fprintf (stderr, "\n");
          }
        }

        continue;
      }

      if (idx >= cnt) continue;

      if (got[idx] == true) continue;

      {
        const u32 bidx = CMP_INDEX (digest[0]);

        if (((member_buf->cmp_bm[bidx / 32] >> (bidx % 32)) & 1) == 0) unfiltered++;
      }

      u32 *out = tmp_digest (tmps, idx);

      for (u32 k = 0; k < ALGO->digest_words; k++) out[k] = digest[k];

      got[idx] = true;

      recv++;

      if (recv == cnt) fpga_timing_last (&member_buf->timing);
    }
  }

  if (pipe_on == true) g_pipe[global_idx].recv_ns += fpga_now_ns () - t_recv;

  dev->transport->batch_end (dev);

  if (unfiltered > member_buf->grain) member_buf->returns_all = true;

  const bool returns_all = ((member_buf->cmp_all == true) || (member_buf->returns_all == true)) ? true : false;

  const bool count_all = ((device_compares == false) || (returns_all == true)) ? true : false;

  if ((ok == true) && (count_all == true) && (recv != cnt))
  {
    event_log_error (hashcat_ctx, "FPGA bridge: board %s returned %" PRIu64 " of %" PRIu64 " candidates (%" PRIu64 " canaries of %u expected).", member_buf->name, recv, cnt, canary_seen, canary_want);

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

  hcfree (got);

  if (canary_bad > 0)
  {
    if (device_compares == true)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: board %s returned a wrong answer for a known-answer canary from %s %u (%" PRIu64 " of %" PRIu64 " bad).", member_buf->name, ALGO->core_name, canary_bad_core, canary_bad, canary_seen);
      event_log_info (hashcat_ctx, "The batch will be recomputed. The device had matched this digest before sending it, so a transfer");
      event_log_info (hashcat_ctx, "fault is as likely as a faulty core. Power-cycle and retest the board to tell the two apart.");
    }
    else
    {
      event_log_error (hashcat_ctx, "FPGA bridge: canary mismatch on board %s, %s %u produced wrong digests (%" PRIu64 " of %" PRIu64 " canaries bad).", member_buf->name, ALGO->core_name, canary_bad_core, canary_bad, canary_seen);
      event_log_info (hashcat_ctx, "A compute %s is faulty; results are untrustworthy. Reprogram the device or exclude that %s.", ALGO->core_name, ALGO->core_name);
    }

    ok = false;

    fault = MEMBER_FAULT_CANARY;

    fault_sig = canary_bad_sig;
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
    const fpga_pool_verdict_t verdict = member_fault (lc, member_idx, member_buf, fault, fault_sig);

    return verdict;
  }

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

static void canary_prepare (hcfpga_bridge_t *ctx, unit_t *unit_buf, const hashes_t *hashes, const u32 salt_pos, const salt_t *salt)
{
  bool changed = false;

  if (unit_buf->canary_valid == false) changed = true;
  if ((unit_buf->canary_valid == true) && (salt_same (&unit_buf->canary_salt, salt) == false)) changed = true;

  if (changed == false) return;

  bool hit = false;

  hc_thread_mutex_lock (ctx->canary_mux);

  if (ctx->canary_cache == NULL)
  {
    ctx->canary_cache     = (canary_entry_t *) hccalloc (hashes->salts_cnt, sizeof (canary_entry_t));
    ctx->canary_cache_cnt = hashes->salts_cnt;
  }

  canary_entry_t *entry = (salt_pos < ctx->canary_cache_cnt) ? &ctx->canary_cache[salt_pos] : NULL;

  if ((entry) && (entry->valid == true) && (salt_same (&entry->salt, salt) == true))
  {
    for (u32 i = 0; i < DIGEST_WORDS; i++) unit_buf->canary_gold[i] = entry->gold[i];

    hit = true;
  }

  hc_thread_mutex_unlock (ctx->canary_mux);

  if (hit == false)
  {
    for (u32 i = 0; i < DIGEST_WORDS; i++) unit_buf->canary_gold[i] = 0;

    ALGO->canary_digest ((const u8 *) canary_password (), (u32) strlen (canary_password ()), salt, unit_buf->canary_gold);

    if (entry)
    {
      hc_thread_mutex_lock (ctx->canary_mux);

      for (u32 i = 0; i < DIGEST_WORDS; i++) entry->gold[i] = unit_buf->canary_gold[i];

      entry->salt  = *salt;
      entry->valid = true;

      hc_thread_mutex_unlock (ctx->canary_mux);
    }
  }

  unit_buf->canary_salt  = *salt;
  unit_buf->canary_valid = true;
}

static void report_dropped (hashcat_ctx_t *hashcat_ctx, hcfpga_bridge_t *ctx, const int unit_idx, unit_t *unit_buf)
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

static bool launch_loop (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  hcfpga_bridge_t *ctx = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &ctx->units_buf[unit_idx];

  u8 *tmps = (u8 *) device_param->h_tmps;

  const salt_t *salt = &hashes->salts_buf[salt_pos];

  const u64 loop_end = MIN ((u64) device_param->kernel_param.loop_pos + device_param->kernel_param.loop_cnt, (u64) salt->salt_iter);
  const u64 loop_pos = MIN ((u64) device_param->kernel_param.loop_pos, loop_end);

  const u64 pw_from = (pws_cnt * loop_pos) / salt->salt_iter;
  const u64 pw_to   = (pws_cnt * loop_end) / salt->salt_iter;

  const u64 pw_cnt = pw_to - pw_from;

  if (pw_cnt == 0) return true;

  if (hashconfig->pw_max > FPGA_PW_MAX)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: this mode accepts passwords up to %u bytes, but the device supports up to %u.", hashconfig->pw_max, (u32) FPGA_PW_MAX);

    return false;
  }

  if (hashconfig->tmp_size != (u64) ALGO->tmp_size)
  {
    event_log_error (hashcat_ctx, "FPGA bridge: the module's tmp struct is %" PRIu64 " bytes, the %s bridge's %u. Module, kernel and bridge must share one struct.", hashconfig->tmp_size, ALGO_NAME, (u32) ALGO->tmp_size);

    return false;
  }

  const bool salt_short = (salt->salt_len < ALGO->salt_len_min);
  const bool salt_long  = (ALGO->salt_len_max > 0) && (salt->salt_len > ALGO->salt_len_max);
  const bool iter_low   = (salt->salt_iter < ALGO->iter_min);
  const bool iter_high  = (ALGO->iter_max > 0) && (salt->salt_iter > ALGO->iter_max);

  if ((salt_short == true) || (salt_long == true) || (iter_low == true) || (iter_high == true))
  {
    event_log_error (hashcat_ctx, "FPGA bridge: a salt of %u bytes with %u iterations is outside what the device computes (%u to %u bytes, %u to %u iterations).", salt->salt_len, salt->salt_iter, ALGO->salt_len_min, ALGO->salt_len_max, ALGO->iter_min, ALGO->iter_max);

    return false;
  }

  if (ALGO->salt_check != NULL)
  {
    char why[256];

    why[0] = 0;

    if (ALGO->salt_check (salt, why, sizeof (why)) == false)
    {
      event_log_error (hashcat_ctx, "FPGA bridge: the device cannot compute this salt: %s", why);

      return false;
    }
  }

  canary_prepare (ctx, unit_buf, hashes, salt_pos, salt);

  launch_t lc;

  lc.hashcat_ctx = hashcat_ctx;
  lc.ctx         = ctx;
  lc.unit_buf    = unit_buf;
  lc.unit_idx    = unit_idx;
  lc.tmps        = tmp_at (tmps, pw_from);
  lc.salt        = salt;
  lc.hashes      = hashes;
  lc.hashconfig  = hashconfig;

  for (u32 i = 0; i < DIGEST_WORDS; i++) lc.canary_gold[i] = unit_buf->canary_gold[i];

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

  const bool ok = fpga_pool_run (unit_buf->pool, pw_cnt, launch_work, &lc);

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

void hcfpga_bridge_init (bridge_ctx_t *bridge_ctx, const hcfpga_algo_t *algo)
{
  ALGO = algo;

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

  bridge_ctx->get_unit_temperature     = get_unit_temperature;
  bridge_ctx->get_unit_temperature_str = get_unit_temperature_str;
  bridge_ctx->get_unit_temperature_abort = get_unit_temperature_abort;
  bridge_ctx->get_unit_temperature_unwatched = get_unit_temperature_unwatched;
  bridge_ctx->get_unit_corespeed   = get_unit_corespeed;
  bridge_ctx->get_unit_buslanes    = get_unit_buslanes;
  bridge_ctx->get_unit_buslanes_str = get_unit_buslanes_str;
}
