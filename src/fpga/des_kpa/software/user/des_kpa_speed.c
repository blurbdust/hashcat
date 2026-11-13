/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The DES known-plaintext design's own speed and answer check, outside hashcat.
//
//   des_kpa_speed [seconds] [amplifier positions] [/dev/node]
//
// Streams jobs over DMA without end, each a base word the device walks the whole amplifier over:
// the given number of positions (1 to 4) of all 128 DES key bytes (charsets/DES_full.hcchr), so a job
// is 128^positions keys. Every job is a different base word except one in every RING_PLANT, which is
// the planted key's base word and holds that key, the one that encrypts the plaintext to the target,
// at a known amplifier item. The device returns only hits; each is checked against the job and item
// it has to come from, and the key it names is encrypted again here.
//
// The rate is the device's own count of finished jobs (the retired register) times the keys in a
// job, over the scoring time after the first second. The die temperature and the thermal stop are
// read every second.

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>

#include "liblitepcie.h"
#include "csr.h"

#include "../../../../bridges/fpga/hcfpga_des_kpa_ref.h"

// The algorithm's bank is at 0 (the register map every LiteX PCIe board in this tree shares).

#define CSR_CTRL          0x00
#define CSR_SALT0         0x04
#define CSR_SALT1         0x08
#define CSR_STATUS        0x18
#define CSR_CORE_COUNT    0x1c
#define CSR_BATCH_TARGET  0x30
#define CSR_PAD_RECS      0x34
#define CSR_RETIRED       0x38
#define CSR_AMP_CNT       0x3c
#define CSR_AMP_LENS      0x40
#define CSR_AMP_TAB       0x44
#define CSR_TGT_MASK      0x48
#define CSR_TGT_LO(k)     (0x4c + (8 * (k)))
#define CSR_TGT_HI(k)     (0x50 + (8 * (k)))

#define STATUS_THERM_STOP (1u << 16)
#define STATUS_LOST_HIT   (1u << 17)

#define H2C_TAG           0xbcu
#define JOB_BYTES         16
#define C2H_REC_BYTES     32
#define C2H_FLAG_EOB      0x8000u

// One job in RING_PLANT holds a key that hits.
#define RING_PLANT        2

#ifndef HCFPGA_ABI
#define HCFPGA_ABI 4
#endif

static uint8_t des_full (const uint32_t v)
{
  const uint8_t hi = (uint8_t) (v << 1);

  return (uint8_t) (hi | ((__builtin_popcount (hi) & 1) ^ 1));
}

// The device's key of item `item` over a base word: position p takes digit p, position 0 fastest.

static void amp_key (const uint8_t *base, const uint32_t amp_cnt, uint64_t item, uint8_t key[8])
{
  memcpy (key, base, 8);

  for (uint32_t p = 0; p < amp_cnt; p++)
  {
    key[p] = des_full ((uint32_t) (item % 128));

    item /= 128;
  }
}

static uint64_t mix (uint64_t x)
{
  x ^= x >> 33; x *= 0xff51afd7ed558ccdull;
  x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ull;
  x ^= x >> 33;

  return x;
}

static void job_base (const uint32_t id, const uint32_t amp_cnt, uint8_t base[8])
{
  const uint64_t r = mix (0x5eed0000ull + id);

  for (uint32_t i = 0; i < 8; i++) base[i] = (i < amp_cnt) ? 0 : (uint8_t) (r >> (8 * i));
}

static uint64_t plant_item (const uint32_t id, const uint64_t amp_items)
{
  return mix (0xa11ce000ull + id) % amp_items;
}

static bool probe_identity (const int fd, char *buf, const size_t buf_size)
{
  if (litepcie_readl (fd, CSR_CTRL_SCRATCH_ADDR) != 0x12345678) return false;

  size_t n = 0;

  for (uint32_t i = 0; i < 256; i++)
  {
    const char c = (char) (litepcie_readl (fd, CSR_IDENTIFIER_MEM_BASE + 4 * i) & 0xff);

    if ((c == 0) || (n >= (buf_size - 1))) break;

    buf[n++] = c;
  }

  buf[n] = 0;

  return true;
}

static double temp_c (const uint32_t raw)
{
  return ((double) raw) * 503.975 / 4096.0 - 273.15;
}

typedef struct
{
  uint32_t       amp_cnt;
  uint32_t       ring_jobs;
  uint64_t       want_item;
  const uint8_t *pkey;
  const uint8_t *pt;
  const uint8_t *tct;

  uint64_t good, bad, eob;

} check_t;

// Every hit names a planted job, the planted item and target 0, and its key encrypts the plaintext
// to the target.

static void take_hits (struct litepcie_dma_ctrl *dma, const int fd, check_t *c)
{
  const ssize_t rlen = read (fd, dma->buf_rd, DMA_BUFFER_TOTAL_SIZE);

  for (ssize_t off = 0; off + C2H_REC_BYTES <= rlen; off += C2H_REC_BYTES)
  {
    const uint32_t *f = (const uint32_t *) (dma->buf_rd + off);

    if ((f[0] == 0) && (f[1] == 0) && (f[7] == 0)) continue;

    if ((f[7] >> 16) == C2H_FLAG_EOB)
    {
      c->eob++;

      continue;
    }

    const uint32_t id   = f[0];
    const uint32_t item = f[1];
    const uint32_t tgt  = f[2] & 0xff;

    uint8_t b[8], key[8], ct[8];

    memcpy (b, c->pkey, 8);

    if ((id < c->ring_jobs) && ((id % RING_PLANT) != 0)) job_base (id, c->amp_cnt, b);

    for (uint32_t p = 0; p < c->amp_cnt; p++) b[p] = 0;

    amp_key (b, c->amp_cnt, item, key);

    hcfpga_deskpa_encrypt (key, c->pt, ct);

    if ((id < c->ring_jobs) && ((id % RING_PLANT) == 0) && (item == c->want_item) && (tgt == 0) && (memcmp (ct, c->tct, 8) == 0))
    {
      c->good++;
    }
    else
    {
      c->bad++;

      if (c->bad <= 8) printf ("[> BAD hit: job %u item %u target %u core %u\n", id, item, tgt, f[7] & 0xffff);
    }
  }
}

int main (int argc, char **argv)
{
  const int      secs    = (argc > 1) ? atoi (argv[1]) : 30;
  const uint32_t amp_cnt = (argc > 2) ? (uint32_t) atoi (argv[2]) : 3;
  const char    *node    = (argc > 3) ? argv[3] : "/dev/litepcie0";

  if ((amp_cnt < 1) || (amp_cnt > 4) || (secs < 2))
  {
    fprintf (stderr, "usage: %s [seconds >= 2] [amplifier positions 1..4] [/dev/node]\n", argv[0]);

    return 1;
  }

  uint64_t amp_items = 1;

  for (uint32_t p = 0; p < amp_cnt; p++) amp_items *= 128;

  struct litepcie_dma_ctrl dma = {0};

  dma.use_reader = 1;
  dma.use_writer = 1;

  if (litepcie_dma_init (&dma, node, 0))
  {
    fprintf (stderr, "dma_init failed on %s\n", node);

    return 1;
  }

  const int fd = dma.fds.fd;

  char ident[512];

  if (probe_identity (fd, ident, sizeof (ident)) == false)
  {
    fprintf (stderr, "%s does not answer on its register path.\n", node);

    return 1;
  }

  printf ("[> identity: %s\n", ident);

  if (strstr (ident, "algo=des_kpa;") == NULL)
  {
    fprintf (stderr, "%s is not running the des_kpa design.\n", node);

    return 1;
  }

  const char *at = strstr (ident, ";abi=");

  if ((at == NULL) || (atoi (at + 5) != HCFPGA_ABI))
  {
    fprintf (stderr, "this card's ABI is not %d, the one this tool speaks.\n", HCFPGA_ABI);

    return 1;
  }

  const uint32_t cores = litepcie_readl (fd, CSR_CORE_COUNT);

  // The batch: a plaintext, one target, the amplifier over DES_full, no end-of-batch (the stream
  // never ends, so the retired count is read instead).

  const uint8_t pt[8] = { 0x14, 0x12, 0x78, 0x10, 0x58, 0x34, 0x31, 0x78 };

  uint8_t pkey[8];
  uint8_t base[8];

  job_base (RING_PLANT, amp_cnt, base);

  amp_key (base, amp_cnt, plant_item (RING_PLANT, amp_items), pkey);

  uint8_t tct[8];

  hcfpga_deskpa_encrypt (pkey, pt, tct);

  litepcie_writel (fd, CSR_CTRL, 1);
  litepcie_writel (fd, CSR_CTRL, 0);

  litepcie_writel (fd, CSR_SALT0, (uint32_t) pt[0] | ((uint32_t) pt[1] << 8) | ((uint32_t) pt[2] << 16) | ((uint32_t) pt[3] << 24));
  litepcie_writel (fd, CSR_SALT1, (uint32_t) pt[4] | ((uint32_t) pt[5] << 8) | ((uint32_t) pt[6] << 16) | ((uint32_t) pt[7] << 24));

  litepcie_writel (fd, CSR_TGT_LO (0), (uint32_t) tct[0] | ((uint32_t) tct[1] << 8) | ((uint32_t) tct[2] << 16) | ((uint32_t) tct[3] << 24));
  litepcie_writel (fd, CSR_TGT_HI (0), (uint32_t) tct[4] | ((uint32_t) tct[5] << 8) | ((uint32_t) tct[6] << 16) | ((uint32_t) tct[7] << 24));
  litepcie_writel (fd, CSR_TGT_MASK, 1);

  uint32_t lens = 0;

  for (uint32_t p = 0; p < amp_cnt; p++)
  {
    lens |= 127u << (8 * p);

    for (uint32_t i = 0; i < 128; i++) litepcie_writel (fd, CSR_AMP_TAB, (p << 16) | (i << 8) | des_full (i));
  }

  litepcie_writel (fd, CSR_AMP_LENS, lens);
  litepcie_writel (fd, CSR_AMP_CNT, amp_cnt);

  litepcie_writel (fd, CSR_PAD_RECS, 1);
  litepcie_writel (fd, CSR_BATCH_TARGET, 0);

  // The H2C ring: job ids count up through it, and the DMA reader replays it; a job's base word
  // comes from its id, so a replayed job is the same job. Planted jobs carry the planted key's base.

  const size_t ring_bytes = (DMA_BUFFER_TOTAL_SIZE / DMA_BUFFER_SIZE) * DMA_BUFFER_SIZE;
  const uint32_t ring_jobs = (uint32_t) (ring_bytes / JOB_BYTES);

  uint8_t *bw = (uint8_t *) dma.buf_wr;

  uint32_t planted = 0;

  for (uint32_t id = 0; id < ring_jobs; id++)
  {
    uint8_t b[8];

    if ((id % RING_PLANT) == 0)
    {
      memcpy (b, pkey, 8);

      for (uint32_t p = 0; p < amp_cnt; p++) b[p] = 0;

      planted++;
    }
    else
    {
      job_base (id, amp_cnt, b);
    }

    uint32_t *w = (uint32_t *) (bw + (size_t) id * JOB_BYTES);

    w[0] = (H2C_TAG << 24) | 8;
    w[1] = id;
    w[2] = ((uint32_t) b[0] << 24) | ((uint32_t) b[1] << 16) | ((uint32_t) b[2] << 8) | b[3];
    w[3] = ((uint32_t) b[4] << 24) | ((uint32_t) b[5] << 16) | ((uint32_t) b[6] << 8) | b[7];
  }

  printf ("[> %u cores, %u amplifier positions (%llu keys a job), %u jobs in the ring, %u planted\n",
    cores, amp_cnt, (unsigned long long) amp_items, ring_jobs, planted);

  const uint64_t want_item = plant_item (RING_PLANT, amp_items);

  dma.reader_enable = 1;
  dma.writer_enable = 1;

  check_t chk = { amp_cnt, ring_jobs, want_item, pkey, pt, tct, 0, 0, 0 };

  size_t wr_off = 0;

  const int64_t t0 = get_time_ms ();

  int64_t t_score = 0, t_tick = t0;

  uint32_t ret_score = 0, ret_last = 0;

  double temp_max = -300.0;

  uint64_t therm_ticks = 0;

  while (1)
  {
    const int64_t now = get_time_ms ();

    if (now - t0 >= (int64_t) secs * 1000) break;

    litepcie_dma_writer (fd, 1, &dma.writer_hw_count, &dma.writer_sw_count);
    litepcie_dma_reader (fd, 1, &dma.reader_hw_count, &dma.reader_sw_count);

    const int pr = poll (&dma.fds, 1, 100);

    if ((pr > 0) && (dma.fds.revents & POLLOUT))
    {
      const ssize_t wn = write (fd, bw + wr_off, DMA_BUFFER_SIZE);

      (void) wn;

      wr_off += DMA_BUFFER_SIZE;

      if (wr_off >= ring_bytes) wr_off = 0;
    }

    if ((pr > 0) && (dma.fds.revents & POLLIN)) take_hits (&dma, fd, &chk);

    if (now - t_tick >= 1000)
    {
      t_tick = now;

      const uint32_t retired = litepcie_readl (fd, CSR_RETIRED);
      const uint32_t status  = litepcie_readl (fd, CSR_STATUS);
      const uint32_t traw    = litepcie_readl (fd, CSR_XADC_TEMPERATURE_ADDR);

      const double t = temp_c (traw);

      if (t > temp_max) temp_max = t;

      if (status & STATUS_THERM_STOP) therm_ticks++;

      const double rate = (double) (retired - ret_last) * (double) amp_items;

      ret_last = retired;

      if ((t_score == 0) && (now - t0 >= 1000))
      {
        t_score   = now;
        ret_score = retired;
      }

      printf ("  t=%3llds  %10.3f Gkeys/s  jobs %u  hits %llu good %llu bad  %.1f C%s%s\n",
        (long long) ((now - t0) / 1000), rate / 1e9, retired, (unsigned long long) chk.good, (unsigned long long) chk.bad, t,
        (status & STATUS_THERM_STOP) ? "  THERMAL STOP" : "", (status & STATUS_LOST_HIT) ? "  LOST HIT" : "");

      fflush (stdout);
    }
  }

  const int64_t t_end = get_time_ms ();

  const uint32_t ret_end = litepcie_readl (fd, CSR_RETIRED);
  const uint32_t status  = litepcie_readl (fd, CSR_STATUS);

  // The host sees C2H data DMA_BUFFER_PER_IRQ buffers at a time, a megabyte, so the last hits are
  // still on their way. Arming a batch makes the device close it with end-of-batch records, padded
  // to a whole interrupt's worth, which pushes them out.

  litepcie_writel (fd, CSR_PAD_RECS, (DMA_BUFFER_PER_IRQ * DMA_BUFFER_SIZE) / C2H_REC_BYTES);
  litepcie_writel (fd, CSR_BATCH_TARGET, 1);

  const int64_t t_flush = get_time_ms ();

  while ((chk.eob == 0) && ((get_time_ms () - t_flush) < 5000))
  {
    litepcie_dma_writer (fd, 1, &dma.writer_hw_count, &dma.writer_sw_count);
    litepcie_dma_reader (fd, 1, &dma.reader_hw_count, &dma.reader_sw_count);

    const int pr = poll (&dma.fds, 1, 100);

    if ((pr > 0) && (dma.fds.revents & POLLOUT))
    {
      const ssize_t wn = write (fd, bw + wr_off, DMA_BUFFER_SIZE);

      (void) wn;

      wr_off += DMA_BUFFER_SIZE;

      if (wr_off >= ring_bytes) wr_off = 0;
    }

    if ((pr > 0) && (dma.fds.revents & POLLIN)) take_hits (&dma, fd, &chk);
  }

  dma.reader_enable = 0;
  dma.writer_enable = 0;

  litepcie_dma_writer (fd, 0, &dma.writer_hw_count, &dma.writer_sw_count);
  litepcie_dma_reader (fd, 0, &dma.reader_hw_count, &dma.reader_sw_count);

  litepcie_writel (fd, CSR_CTRL, 1);
  litepcie_writel (fd, CSR_CTRL, 0);

  litepcie_dma_cleanup (&dma);

  const double secs_scored = (double) (t_end - t_score) / 1000.0;
  const double jobs        = (double) (ret_end - ret_score);
  const double keys        = jobs * (double) amp_items;
  const double rate        = (secs_scored > 0) ? keys / secs_scored : 0.0;

  const double want_hits = jobs / RING_PLANT;

  printf ("[> %.0f jobs in %.1f s: %.3f Gkeys/s (%.1f Mkeys/s a core)\n", jobs, secs_scored, rate / 1e9, rate / 1e6 / (cores ? cores : 1));
  printf ("[> hits: %llu good, %llu bad (about %.0f planted jobs ran by the scored end), lost-hit flag %u\n",
    (unsigned long long) chk.good, (unsigned long long) chk.bad, want_hits, (status & STATUS_LOST_HIT) ? 1 : 0);
  printf ("[> die temperature: %.1f C at most, thermal stop held %llu of the 1 s readings\n", temp_max, (unsigned long long) therm_ticks);

  const bool pass = (chk.bad == 0) && (chk.good > 0) && ((status & STATUS_LOST_HIT) == 0);

  printf ("[> %s\n", pass ? "PASS" : "FAIL");

  return pass ? 0 : 1;
}
