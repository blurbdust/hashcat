/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// hcfpga_step: one batch, every step shown.
//
// Sends a handful of passwords to a bcrypt card as a single one-shot DMA batch, the way the bridge
// does, then prints every result record in words next to the digest the host computes for it. Use it
// when a card identifies but cracks nothing: it shows whether records come back at all, which core
// answered, what flags it set, and whether its digest is right, one record at a time.
//
//   hcfpga_step [options] [password ...]
//
//   --node PATH     device node, default /dev/litepcie0
//   --cost N        bcrypt cost, 2^N rounds, default 5
//   --salt HEX      16 salt bytes as 32 hex digits, default 000102...0f
//   --spread K      instead of named passwords, send K generated ones per core, so every core
//                   answers several times, then print a table of right and wrong digests per core
//   --hex           also dump each H2C record and each raw C2H record
//   --quiet         with --spread, print only the per-core table
//   --wave-model    time four batches and print this board's row for the bridge's WAVE_MODELS table
//
// With no passwords and no --spread it sends "hashcat".

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "liblitepcie.h"
#include "csr.h"
#include "hcfpga_iface.h"
#include "bcrypt_ek.h"

#define CSR(off) (CSR_BASE + (off))

#define H2C_ALIGN      32
#define MAX_RECS       131072
#define MAX_CORES      65536

static int  g_fd  = -1;
static bool g_hex = false;

static uint64_t now_us (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);

  return ((uint64_t) ts.tv_sec * 1000000) + ((uint64_t) ts.tv_nsec / 1000);
}

static uint64_t now_ms (void) { return now_us () / 1000; }

static uint32_t rd (const uint32_t off)                 { return litepcie_readl (g_fd, CSR (off)); }
static void     wr (const uint32_t off, const uint32_t v) { litepcie_writel (g_fd, CSR (off), v); }

static bool wr_verified (const uint32_t off, const uint32_t v, const char *name)
{
  for (int attempt = 0; attempt < 4; attempt++)
  {
    wr (off, v);

    if (rd (off) == v) return true;
  }

  printf ("  !! register %s (0x%02x) did not take 0x%08x, reads back 0x%08x\n", name, off, v, rd (off));

  return false;
}

static uint32_t be32 (const uint8_t *b)
{
  return ((uint32_t) b[0] << 24) | ((uint32_t) b[1] << 16) | ((uint32_t) b[2] << 8) | (uint32_t) b[3];
}

// The password as bcrypt cycles it into 72 bytes, NUL included, as big-endian words. This is what the
// card's feeder expands from the record, and what the reference below starts from.
static void expand_pw (const uint8_t *pw, const uint32_t len, uint32_t ek[18])
{
  const uint32_t period = len + 1;

  uint8_t km[72];

  for (uint32_t i = 0; i < 72; i++)
  {
    const uint32_t j = i % period;

    km[i] = (j == len) ? 0 : pw[j];
  }

  for (uint32_t w = 0; w < 18; w++) ek[w] = be32 (&km[4 * w]);
}

static void hexdump (const char *tag, const uint8_t *p, const size_t n)
{
  printf ("    %s", tag);

  for (size_t i = 0; i < n; i++) printf ("%s%02x", ((i % 4) == 0) ? " " : "", p[i]);

  printf ("\n");
}

static const char *flags_words (const uint16_t flags, char *buf, const size_t sz)
{
  buf[0] = 0;

  if (flags == HCFPGA_FLAG_OK) { snprintf (buf, sz, "ok"); return buf; }

  size_t off = 0;

  if (flags & HCFPGA_FLAG_EOB)      off += snprintf (buf + off, sz - off, "%send-of-batch", off ? "+" : "");
  if (flags & HCFPGA_FLAG_CORE_ERR) off += snprintf (buf + off, sz - off, "%score-error",   off ? "+" : "");

  const uint16_t rest = flags & (uint16_t) ~(HCFPGA_FLAG_EOB | HCFPGA_FLAG_CORE_ERR);

  if (rest) snprintf (buf + off, sz - off, "%sunknown 0x%04x", off ? "+" : "", rest);

  return buf;
}

typedef struct
{
  uint8_t  pw[HCFPGA_PW_MAX];
  uint32_t len;
  uint8_t  gold[24];
  uint32_t seen;
  uint32_t good;

} cand_t;

static cand_t g_cand[MAX_RECS];

static uint32_t g_core_ok [MAX_CORES];
static uint32_t g_core_bad[MAX_CORES];

static bool run_batch (const uint32_t cores, const uint32_t cost, const uint8_t *salt, const uint32_t spread, const bool quiet,
                       const char **pws, uint32_t npw, uint64_t *took_out)
{
  // Candidates.

  memset (g_cand,     0, sizeof (g_cand));
  memset (g_core_ok,  0, sizeof (g_core_ok));
  memset (g_core_bad, 0, sizeof (g_core_bad));

  uint32_t nrec = 0;

  if (spread)
  {
    const uint64_t want = (uint64_t) spread * cores;

    nrec = (want > MAX_RECS) ? MAX_RECS : (uint32_t) want;

    for (uint32_t c = 0; c < nrec; c++)
    {
      static const uint32_t LENS[4] = { 3, 8, 11, 71 };

      g_cand[c].len = LENS[c % 4];

      for (uint32_t k = 0; k < g_cand[c].len; k++) g_cand[c].pw[k] = (uint8_t) (0x21 + ((c + (k * 31u)) % 94u));
    }
  }
  else
  {
    if (npw == 0) pws[npw++] = "hashcat";

    for (uint32_t c = 0; c < npw; c++)
    {
      size_t len = strlen (pws[c]);

      if (len > HCFPGA_PW_MAX) { printf ("  password %u is %zu bytes, truncated to %u as bcrypt does\n", c, len, HCFPGA_PW_MAX); len = HCFPGA_PW_MAX; }

      memcpy (g_cand[c].pw, pws[c], len);

      g_cand[c].len = (uint32_t) len;
    }

    nrec = npw;
  }

  const uint32_t rounds = 1u << cost;

  for (uint32_t c = 0; c < nrec; c++)
  {
    uint32_t ek[18];

    expand_pw (g_cand[c].pw, g_cand[c].len, ek);

    bcrypt_raw_ek (ek, salt, (int) rounds, g_cand[c].gold);
  }

  printf ("[2] configure: framing reset, salt, %u rounds (cost %u), comparator off so every candidate returns\n", rounds, cost);

  wr (HCFPGA_CSR_CTRL, HCFPGA_CTRL_FRAMING_RESET);
  wr (HCFPGA_CSR_CTRL, 0);

  bool cfg_ok = true;

  cfg_ok &= wr_verified (HCFPGA_CSR_SALT0, be32 (salt +  0), "salt0");
  cfg_ok &= wr_verified (HCFPGA_CSR_SALT1, be32 (salt +  4), "salt1");
  cfg_ok &= wr_verified (HCFPGA_CSR_SALT2, be32 (salt +  8), "salt2");
  cfg_ok &= wr_verified (HCFPGA_CSR_SALT3, be32 (salt + 12), "salt3");

  cfg_ok &= wr_verified (HCFPGA_CSR_ITER_COUNT, rounds, "iter_count");

  cfg_ok &= wr_verified (HCFPGA_CSR_CMP_BM0, 0xffffffff, "cmp_bm0");
  cfg_ok &= wr_verified (HCFPGA_CSR_CMP_BM1, 0xffffffff, "cmp_bm1");
  cfg_ok &= wr_verified (HCFPGA_CSR_CMP_BM2, 0xffffffff, "cmp_bm2");
  cfg_ok &= wr_verified (HCFPGA_CSR_CMP_BM3, 0xffffffff, "cmp_bm3");

  const uint32_t pad_recs = DMA_BUFFER_SIZE / HCFPGA_C2H_REC_BYTES;

  cfg_ok &= wr_verified (HCFPGA_CSR_PAD_RECS, pad_recs, "pad_recs");

  cfg_ok &= wr_verified (HCFPGA_CSR_BATCH_TARGET, nrec, "batch_target");

  const uint32_t retired0 = rd (HCFPGA_CSR_RETIRED);

  printf ("  batch target %u records, C2H padded to %u-record buffers, retired counter %u (expect 0)\n", nrec, pad_recs, retired0);

  if (cfg_ok == false) printf ("  !! configuration did not stick, results below are not trustworthy\n");

  // H2C records.

  struct litepcie_ioctl_mmap_dma_info info;

  memset (&info, 0, sizeof (info));

  if (ioctl (g_fd, LITEPCIE_IOCTL_MMAP_DMA_INFO, &info) < 0) { printf ("  !! MMAP_DMA_INFO: %s\n", strerror (errno)); return false; }

  const size_t ring = (size_t) info.dma_tx_buf_size * info.dma_tx_buf_count;

  uint8_t *tx = mmap (NULL, ring, PROT_READ | PROT_WRITE, MAP_SHARED, g_fd, (off_t) info.dma_tx_buf_offset);
  uint8_t *rx = mmap (NULL, ring, PROT_READ | PROT_WRITE, MAP_SHARED, g_fd, (off_t) info.dma_rx_buf_offset);

  if ((tx == MAP_FAILED) || (rx == MAP_FAILED)) { printf ("  !! mmap of the DMA rings failed: %s\n", strerror (errno)); return false; }

  static uint8_t h2c[MAX_RECS * HCFPGA_H2C_REC_BYTES_MAX + H2C_ALIGN];

  size_t used = 0;

  for (uint32_t c = 0; c < nrec; c++)
  {
    const uint32_t b = hcfpga_h2c_put (h2c + used, c, g_cand[c].pw, g_cand[c].len);

    if (g_hex && (spread == 0)) { char tag[32]; snprintf (tag, sizeof (tag), "h2c[%u] ", c); hexdump (tag, h2c + used, b); }

    used += b;
  }

  const size_t tail = used % H2C_ALIGN;

  if (tail) { memset (h2c + used, 0, H2C_ALIGN - tail); used += H2C_ALIGN - tail; }

  uint64_t c2h_bytes = ((uint64_t) nrec + 1) * HCFPGA_C2H_REC_BYTES;

  c2h_bytes = ((c2h_bytes + DMA_BUFFER_SIZE - 1) / DMA_BUFFER_SIZE) * DMA_BUFFER_SIZE;

  if ((used > ring) || (c2h_bytes > ring)) { printf ("  !! batch of %u records does not fit the %zu byte ring\n", nrec, ring); return false; }

  printf ("[3] DMA: %zu bytes out (%u records, zero padded to %u bytes), %llu bytes armed in\n",
    used, nrec, H2C_ALIGN, (unsigned long long) c2h_bytes);

  struct litepcie_ioctl_lock lock;

  memset (&lock, 0, sizeof (lock));

  lock.dma_reader_request = 1;
  lock.dma_writer_request = 1;

  if ((ioctl (g_fd, LITEPCIE_IOCTL_LOCK, &lock) < 0) || (lock.dma_reader_status == 0) || (lock.dma_writer_status == 0))
  {
    printf ("  !! the DMA engines are in use by another process (hashcat?)\n");

    return false;
  }

  struct litepcie_ioctl_dma lb;             memset (&lb, 0, sizeof (lb));  ioctl (g_fd, LITEPCIE_IOCTL_DMA, &lb);
  struct litepcie_ioctl_dma_oneshot os;     memset (&os, 0, sizeof (os));  os.enable = 1;

  if (ioctl (g_fd, LITEPCIE_IOCTL_DMA_ONESHOT, &os) < 0) { printf ("  !! this driver has no one-shot DMA, build the one in src/fpga/driver\n"); return false; }

  struct litepcie_ioctl_dma_writer we; memset (&we, 0, sizeof (we)); we.enable = 1; ioctl (g_fd, LITEPCIE_IOCTL_DMA_WRITER, &we);
  struct litepcie_ioctl_dma_reader re; memset (&re, 0, sizeof (re)); re.enable = 1; ioctl (g_fd, LITEPCIE_IOCTL_DMA_READER, &re);

  memset (rx, 0xff, (size_t) c2h_bytes);

  struct litepcie_ioctl_dma_arm arm;

  memset (&arm, 0, sizeof (arm));

  arm.count       = (uint32_t) (c2h_bytes / DMA_BUFFER_SIZE);
  arm.last_length = 0;

  if (ioctl (g_fd, LITEPCIE_IOCTL_DMA_WRITER_ARM, &arm) < 0) { printf ("  !! arming the C2H engine failed\n"); return false; }

  memcpy (tx, h2c, used);

  memset (&arm, 0, sizeof (arm));

  arm.count       = (uint32_t) ((used + DMA_BUFFER_SIZE - 1) / DMA_BUFFER_SIZE);
  arm.last_length = (uint32_t) (used % DMA_BUFFER_SIZE);

  const uint64_t t0 = now_ms ();
  const uint64_t t0_us = now_us ();

  if (ioctl (g_fd, LITEPCIE_IOCTL_DMA_READER_ARM, &arm) < 0) { printf ("  !! arming the H2C engine failed\n"); return false; }

  // A wave is one candidate per core. Upstream's cycle model puts one at about 19k cycles per round
  // plus a fixed cost; allow ten times that at 50 MHz before calling the card stuck.
  const uint64_t waves      = (nrec + cores - 1) / cores;
  const uint64_t est_ms     = (waves * (19000ull * rounds + 100000ull)) / 50000ull;
  const uint64_t timeout_ms = 5000 + 10 * est_ms;

  printf ("[4] waiting for the end-of-batch record: %llu wave(s), giving up after %llu ms\n",
    (unsigned long long) waves, (unsigned long long) timeout_ms);

  int64_t  pos      = 0;
  bool     eob      = false;
  uint32_t got      = 0;
  uint32_t padding  = 0;
  uint32_t foreign  = 0;
  uint32_t ok_n     = 0;
  uint32_t bad_n    = 0;
  uint32_t err_n    = 0;
  uint32_t eob_proc = 0;

  while ((eob == false) && ((now_ms () - t0) < timeout_ms))
  {
    memset (&we, 0, sizeof (we));

    we.enable = 1;

    ioctl (g_fd, LITEPCIE_IOCTL_DMA_WRITER, &we);

    if (we.hw_count <= pos)
    {
      struct pollfd pfd = { .fd = g_fd, .events = POLLIN, .revents = 0 };

      poll (&pfd, 1, 100);

      continue;
    }

    const uint8_t *buf = rx + ((size_t) (pos % (int64_t) info.dma_rx_buf_count) * DMA_BUFFER_SIZE);

    for (uint32_t r = 0; r < DMA_BUFFER_SIZE / HCFPGA_C2H_REC_BYTES; r++)
    {
      const hcfpga_c2h_rec_t *f = (const hcfpga_c2h_rec_t *) (buf + (size_t) r * HCFPGA_C2H_REC_BYTES);

      const uint8_t *raw = (const uint8_t *) f;

      bool all_ff = true;

      for (int k = 0; k < HCFPGA_C2H_REC_BYTES; k++) if (raw[k] != 0xff) { all_ff = false; break; }

      if (all_ff) continue;

      if (f->flags & HCFPGA_FLAG_EOB)
      {
        eob      = true;
        eob_proc = f->ekid;

        printf ("  end-of-batch record from core %u: the card reports %u candidates processed\n", f->core_id, f->ekid);

        if (g_hex) hexdump ("raw ", raw, HCFPGA_C2H_REC_BYTES);

        break;
      }

      bool zero = true;

      for (int k = 0; k < HCFPGA_C2H_REC_BYTES; k++) if (raw[k] != 0) { zero = false; break; }

      if (zero) { padding++; continue; }

      got++;

      char fw[64];

      if (f->ekid >= nrec)
      {
        foreign++;

        printf ("  record %u: id %u is not one this batch sent (core %u, flags %s)\n", got, f->ekid, f->core_id, flags_words (f->flags, fw, sizeof (fw)));

        if (g_hex) hexdump ("raw ", raw, HCFPGA_C2H_REC_BYTES);

        continue;
      }

      cand_t *c = &g_cand[f->ekid];

      const bool good = (memcmp (f->digest, c->gold, 24) == 0);

      c->seen++;

      if (good) { c->good++; ok_n++; } else bad_n++;

      if (f->flags & HCFPGA_FLAG_CORE_ERR) err_n++;

      if (f->core_id < MAX_CORES) { if (good) g_core_ok[f->core_id]++; else g_core_bad[f->core_id]++; }

      if ((quiet == false) && ((spread == 0) || (good == false)))
      {
        printf ("  record %u: id %u \"%.*s\" from core %u, flags %s, digest %s\n", got, f->ekid, (int) c->len, (const char *) c->pw,
          f->core_id, flags_words (f->flags, fw, sizeof (fw)), good ? "RIGHT" : "WRONG");

        if ((good == false) || g_hex)
        {
          hexdump ("got  ", f->digest, 24);
          hexdump ("want ", c->gold,   24);
        }
      }
    }

    pos++;

    struct litepcie_ioctl_mmap_dma_update upd = { .sw_count = pos };

    ioctl (g_fd, LITEPCIE_IOCTL_MMAP_DMA_WRITER_UPDATE, &upd);
  }

  const uint64_t took_us = now_us () - t0_us;
  const uint64_t took    = took_us / 1000;

  const uint32_t retired = rd (HCFPGA_CSR_RETIRED);
  const uint32_t status2 = rd (HCFPGA_CSR_STATUS);

  memset (&we, 0, sizeof (we)); ioctl (g_fd, LITEPCIE_IOCTL_DMA_WRITER, &we);
  memset (&re, 0, sizeof (re)); ioctl (g_fd, LITEPCIE_IOCTL_DMA_READER, &re);

  memset (&lock, 0, sizeof (lock));

  lock.dma_reader_release = 1;
  lock.dma_writer_release = 1;

  ioctl (g_fd, LITEPCIE_IOCTL_LOCK, &lock);

  printf ("[5] result after %llu ms\n", (unsigned long long) took);

  if (eob == false) printf ("  !! no end-of-batch record arrived: the card took the batch but never finished it\n");

  printf ("  %u result records (%u right, %u wrong, %u with core-error), %u not from this batch, %u zero padding\n",
    got, ok_n, bad_n, err_n, foreign, padding);
  printf ("  card retired %u of %u, end-of-batch says %u processed\n", retired, nrec, eob_proc);
  printf ("  framing: slip %u, slip count %u (the zero padding after the last record counts here)\n", status2 & 1, (status2 >> 8) & 0xff);

  uint32_t missing = 0;

  for (uint32_t c = 0; c < nrec; c++) if (g_cand[c].seen == 0) missing++;

  if (missing) printf ("  !! %u of %u candidates never came back\n", missing, nrec);

  if (spread)
  {
    printf ("  per core (right/wrong):\n");

    uint32_t bad_cores = 0;

    for (uint32_t k = 0; k < cores; k++)
    {
      if (g_core_bad[k]) bad_cores++;

      if ((quiet == false) || g_core_bad[k]) printf ("    core %4u: %u/%u%s\n", k, g_core_ok[k], g_core_bad[k], g_core_bad[k] ? "   <- WRONG DIGESTS" : "");
    }

    printf ("  %u of %u cores returned a wrong digest\n", bad_cores, cores);
  }

  const bool pass = eob && (bad_n == 0) && (foreign == 0) && (missing == 0) && (err_n == 0);

  printf ("%s\n", pass ? "PASS" : "FAIL");

  if (took_out) *took_out = took_us;

  munmap (tx, ring);
  munmap (rx, ring);

  return pass;

}

int main (int argc, char **argv)
{
  const char *node   = "/dev/litepcie0";
  uint32_t    cost   = 5;
  uint32_t    spread = 0;
  bool        quiet  = false;
  bool        wave_model = false;

  uint8_t salt[16];

  for (int i = 0; i < 16; i++) salt[i] = (uint8_t) i;

  const char *pws[MAX_RECS];
  uint32_t    npw = 0;

  for (int i = 1; i < argc; i++)
  {
    if      ((strcmp (argv[i], "--node")   == 0) && (i + 1 < argc)) node   = argv[++i];
    else if ((strcmp (argv[i], "--cost")   == 0) && (i + 1 < argc)) cost   = (uint32_t) strtoul (argv[++i], NULL, 0);
    else if ((strcmp (argv[i], "--spread") == 0) && (i + 1 < argc)) spread = (uint32_t) strtoul (argv[++i], NULL, 0);
    else if  (strcmp (argv[i], "--hex")    == 0) g_hex = true;
    else if  (strcmp (argv[i], "--quiet")  == 0) quiet = true;
    else if  (strcmp (argv[i], "--wave-model") == 0) wave_model = true;
    else if ((strcmp (argv[i], "--salt")   == 0) && (i + 1 < argc))
    {
      const char *h = argv[++i];

      if (strlen (h) != 32) { fprintf (stderr, "--salt takes 32 hex digits\n"); return 1; }

      for (int k = 0; k < 16; k++) { unsigned v; sscanf (&h[2 * k], "%2x", &v); salt[k] = (uint8_t) v; }
    }
    else if ((strcmp (argv[i], "--help") == 0) || (strcmp (argv[i], "-h") == 0))
    {
      fprintf (stderr, "usage: %s [--node PATH] [--cost N] [--salt HEX32] [--spread K] [--hex] [--quiet] [--wave-model] [password ...]\n", argv[0]);
      return 0;
    }
    else if (npw < MAX_RECS) pws[npw++] = argv[i];
  }

  if ((cost < 4) || (cost > 31)) { fprintf (stderr, "cost %u is outside bcrypt's 4..31\n", cost); return 1; }

  printf ("[1] open %s\n", node);

  g_fd = open (node, O_RDWR | O_CLOEXEC);

  if (g_fd < 0) { printf ("  !! %s: %s\n", node, strerror (errno)); return 1; }

  char ident[257];

  int n = 0;

  for (; n < 256; n++)
  {
    ident[n] = (char) litepcie_readl (g_fd, CSR_IDENTIFIER_MEM_BASE + (uint32_t) (4 * n));

    if (ident[n] == 0) break;
  }

  ident[n] = 0;

  const uint32_t cores  = rd (HCFPGA_CSR_CORE_COUNT);
  const uint32_t status = rd (HCFPGA_CSR_STATUS);

  printf ("  identity: %s\n", ident);
  printf ("  cores %u, status 0x%08x (framing slip %u, buffer end seen %u, slip count %u)\n",
    cores, status, status & 1, (status >> 1) & 1, (status >> 8) & 0xff);

#ifdef CSR_XADC_TEMPERATURE_ADDR
  const uint32_t t = litepcie_readl (g_fd, CSR_XADC_TEMPERATURE_ADDR);

  printf ("  die temperature %.1f C\n", ((double) t * 503.975 / 4096.0) - 273.15);
#endif

  if ((cores == 0) || (cores > MAX_CORES)) { printf ("  !! a core count of %u is not believable, stopping\n", cores); return 1; }

  uint64_t took = 0;

  if (wave_model)
  {
    // Wave time is linear in the bcrypt round count: (cycles_per_iter * rounds + cycles_per_wave) / clock,
    // plus a fixed launch cost per batch. Two round counts and two batch sizes separate the three.
    const uint32_t K[2] = { 32, 256 };
    const uint32_t C[2] = { 5, 8 };

    double ms[2][2];

    for (int ci = 0; ci < 2; ci++) for (int ki = 0; ki < 2; ki++)
    {
      if (run_batch (cores, C[ci], salt, K[ki], true, NULL, 0, &took) == false) { printf ("  !! a timing batch failed, no model\n"); close (g_fd); return 2; }

      ms[ci][ki] = (double) took / 1000.0;
    }

    const char *cl = strstr (ident, ";clk=");

    const double mhz = (cl != NULL) ? atof (cl + 5) : 0;

    if (mhz <= 0) { printf ("  !! the identity carries no clock, no model\n"); close (g_fd); return 2; }

    const double kcyc = mhz * 1000.0;  // cycles per ms

    double wave_cyc[2], launch_ms[2];

    for (int ci = 0; ci < 2; ci++)
    {
      const double per_wave = (ms[ci][1] - ms[ci][0]) / (double) (K[1] - K[0]);

      wave_cyc[ci]  = per_wave * kcyc;
      launch_ms[ci] = ms[ci][0] - (per_wave * (double) K[0]);
    }

    const double r0 = (double) (1u << C[0]);
    const double r1 = (double) (1u << C[1]);

    const double cpi = (wave_cyc[1] - wave_cyc[0]) / (r1 - r0);
    const double cpw = wave_cyc[0] - (cpi * r0);

    char board[64] = "?";

    const char *b = strstr (ident, "board=");

    if (b != NULL) sscanf (&b[6], "%63[^;]", board);

    printf ("[wave model] batches of %u and %u waves at cost %u and %u: %.1f %.1f %.1f %.1f ms\n", K[0], K[1], C[0], C[1], ms[0][0], ms[0][1], ms[1][0], ms[1][1]);
    printf ("  cycles per round %.0f, cycles per wave %.0f, launch measured here %.2f ms\n", cpi, cpw, (launch_ms[0] + launch_ms[1]) / 2);
    printf ("  row for WAVE_MODELS in src/bridges/bridge_fpga_bcrypt.c; the launch column there is the\n");
    printf ("  bridge's whole per-batch overhead, which is larger than this tool's, so start from the\n");
    printf ("  value the other boards use:\n");
    printf ("  { \"%s\", %u, %.0f, %.0f, 2100 },\n", board, cores, cpi, cpw);

    close (g_fd);

    return 0;
  }

  const bool pass = run_batch (cores, cost, salt, spread, quiet, pws, npw, &took);

  close (g_fd);

  return pass ? 0 : 2;
}
