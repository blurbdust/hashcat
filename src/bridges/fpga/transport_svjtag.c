/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"

#include "fpga/hcfpga.h"
#include "fpga/artyz7_ftdi.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

// A Stratix V card reached through an FT232H on its JTAG header, for a slot where the PCIe link does
// not come up. The gateware side, and the layout of the scans, is in
// src/fpga/bcrypt/hcfpga_jtaglink.py. Cards that also answer on PCIe are left to that transport.

#if defined (__linux__)

#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define SVJTAG_VID          0x0403
#define SVJTAG_PID          0x6014
#define SVJTAG_SYSFS        "/sys/bus/usb/devices"

#define SVJTAG_MAX_DEVS     16

#define SVJTAG_IR_BITS      10
#define SVJTAG_IR_USER0     0x00c
#define SVJTAG_IR_USER1     0x00e
#define SVJTAG_ALTERA_MFR   0x0dd

// Intel's JTAG hub: USER1 shifts the hub's virtual IR, whose top bits address a node, and USER0
// then reaches that node's data register. With the virtual IR at zero, successive 4-bit USER0
// scans return the hub's information word and then one word per node, low nibble first.
#define SVJTAG_SLD_MFR      0x06e
#define SVJTAG_SLD_NODES    16
#define SVJTAG_NODE_INST    0x48

#define SVJTAG_WORDS        16
#define SVJTAG_PAYLOAD      (4 * SVJTAG_WORDS)
#define SVJTAG_REG_BITS     (128 + (8 * SVJTAG_PAYLOAD))
#define SVJTAG_REG_BYTES    (SVJTAG_REG_BITS / 8)
#define SVJTAG_SLACK        2
#define SVJTAG_SCAN_BITS    (SVJTAG_REG_BITS + SVJTAG_SLACK)
#define SVJTAG_SCAN_BYTES   ((SVJTAG_SCAN_BITS + 7) / 8)

#define SVJTAG_REQ_MAGIC    0xa55a
#define SVJTAG_RSP_MAGIC    0x5aa5

#define SVJTAG_CSR_READ     1
#define SVJTAG_CSR_WRITE    2

// One USB write may only ask for as many TDO bytes as the FT232H's 1 KiB transmit buffer holds,
// or the MPSSE stalls while the host is still writing.
#define SVJTAG_CHUNK_SCANS  12

// Chunks in flight. A reader thread drains the chip while the next chunk is written, so the USB
// round trip overlaps the JTAG shifting.
#define SVJTAG_INFLIGHT     4
#define SVJTAG_RING         (64u << 10)

#define SVJTAG_CAPACITY     (4u << 20)
#define SVJTAG_RECV_MAX     (64u << 10)

#define SVJTAG_TCK_DEFAULT  30000000

typedef struct svjtag_scan
{
  u8 tdi[SVJTAG_SCAN_BYTES];
  u8 tdo[SVJTAG_SCAN_BYTES];

} svjtag_scan_t;

typedef struct svjtag_xfer
{
  svjtag_scan_t s[SVJTAG_CHUNK_SCANS];
  u32           n;

} svjtag_xfer_t;

typedef struct svjtag_priv
{
  char            port[64];
  ftdi_ctx_t      ftdi;
  bool            ftdi_open;
  pthread_mutex_t lock;

  u32  tck_hz;
  u32  idcode;
  u32  vir_bits;
  u32  vir_value;
  int  tdo_shift;
  u32  tdi_delay;
  u32  depth;
  u8   tag;
  u16  sent;
  u16  taken;
  bool overflow;
  bool broken;

  u8  *out;
  u64  out_bytes;
  u64  out_have;
  u64  out_pos;

  u8  *in;
  u64  in_bytes;
  u64  in_have;
  u64  in_given;
  u32  in_grain;
  u32  in_recs;
  bool eob_seen;
  u32  eob_processed;

  bool batch_active;

  svjtag_xfer_t q[SVJTAG_INFLIGHT];
  u32           q_head;
  u32           q_len;

  pthread_t       reader;
  bool            reader_on;
  volatile bool   reader_stop;
  volatile bool   reader_err;
  pthread_mutex_t ring_lock;
  pthread_cond_t  ring_cond;
  u8              ring[SVJTAG_RING];
  u32             ring_head;
  u32             ring_len;

} svjtag_priv_t;

static svjtag_priv_t SVJTAG_PRIV[SVJTAG_MAX_DEVS];

#define svjtag_dbg(p, ...) do { if (getenv ("HCFPGA_DEBUG") != NULL) { fprintf (stderr, "[svjtag %s] ", (p)->port); fprintf (stderr, __VA_ARGS__); fprintf (stderr, "\n"); } } while (0)

// Bits -------------------------------------------------------------------------------------------

static void bit_set (u8 *buf, const u32 pos, const u32 val)
{
  if (val) buf[pos / 8] |=  (u8) (1u << (pos % 8));
  else     buf[pos / 8] &= (u8) ~(1u << (pos % 8));
}

static u32 bit_get (const u8 *buf, const u32 pos)
{
  return (buf[pos / 8] >> (pos % 8)) & 1;
}

static void bits_put (u8 *buf, const u32 pos, const u32 n, const u32 val)
{
  for (u32 i = 0; i < n; i++) bit_set (buf, pos + i, (val >> i) & 1);
}

static u32 bits_get (const u8 *buf, const u32 pos, const u32 n)
{
  u32 v = 0;

  for (u32 i = 0; i < n; i++) v |= bit_get (buf, pos + i) << i;

  return v;
}

// MPSSE ------------------------------------------------------------------------------------------

static bool mp_tap_reset (svjtag_priv_t *p)
{
  // Test-Logic-Reset, then Run-Test/Idle.
  const u8 cmd[] = { 0x4B, 0x05, 0x1F };

  return ftdi_write (&p->ftdi, cmd, sizeof (cmd));
}

static bool mp_ir (svjtag_priv_t *p, const u32 ir)
{
  // Run-Test/Idle to Shift-IR, the instruction, and back through Update-IR to Run-Test/Idle.
  const u8 cmd[] =
  {
    0x4B, 0x03, 0x03,
    0x1B, 0x07, (u8) (ir & 0xff),
    0x1B, 0x00, (u8) ((ir >> 8) & 1),
    0x4B, 0x00, (u8) ((((ir >> 9) & 1) << 7) | 0x01),
    0x4B, 0x01, 0x01,
  };

  return ftdi_write (&p->ftdi, cmd, sizeof (cmd));
}

static u32 mp_rx_per (const u32 bits)
{
  const u32 body = bits - 1;

  return (body / 8) + (((body % 8) > 0) ? 1 : 0) + 1;
}

static bool rx_get (svjtag_priv_t *p, u8 *buf, const u32 len)
{
  if (p->reader_on == false) return ftdi_read (&p->ftdi, buf, len);

  pthread_mutex_lock (&p->ring_lock);

  const u64 t0 = fpga_now_ns ();

  while ((p->ring_len < len) && (p->reader_err == false))
  {
    if ((fpga_now_ns () - t0) > 2000000000ull) break;

    struct timespec ts;

    clock_gettime (CLOCK_REALTIME, &ts);

    ts.tv_nsec += 10000000;

    if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }

    pthread_cond_timedwait (&p->ring_cond, &p->ring_lock, &ts);
  }

  const bool ok = (p->ring_len >= len);

  if (ok == true)
  {
    for (u32 i = 0; i < len; i++) buf[i] = p->ring[(p->ring_head + i) % SVJTAG_RING];

    p->ring_head = (p->ring_head + len) % SVJTAG_RING;
    p->ring_len -= len;
  }

  pthread_mutex_unlock (&p->ring_lock);

  return ok;
}

static void *svjtag_reader (void *arg)
{
  svjtag_priv_t *p = (svjtag_priv_t *) arg;

  u8 buf[16384];

  while (p->reader_stop == false)
  {
    const int got = ftdi_read_some (&p->ftdi, buf, sizeof (buf), 50);

    pthread_mutex_lock (&p->ring_lock);

    if ((got < 0) || ((p->ring_len + (u32) MAX (got, 0)) > SVJTAG_RING))
    {
      p->reader_err = true;
    }
    else
    {
      for (int i = 0; i < got; i++) p->ring[(p->ring_head + p->ring_len + (u32) i) % SVJTAG_RING] = buf[i];

      p->ring_len += (u32) got;
    }

    pthread_cond_signal (&p->ring_cond);

    pthread_mutex_unlock (&p->ring_lock);

    if (p->reader_err == true) break;
  }

  return NULL;
}

static bool reader_start (svjtag_priv_t *p)
{
  p->reader_stop = false;
  p->reader_err  = false;
  p->ring_head   = 0;
  p->ring_len    = 0;

  pthread_mutex_init (&p->ring_lock, NULL);
  pthread_cond_init  (&p->ring_cond, NULL);

  if (pthread_create (&p->reader, NULL, svjtag_reader, p) != 0) return false;

  p->reader_on = true;

  return true;
}

static void reader_stop (svjtag_priv_t *p)
{
  if (p->reader_on == false) return;

  p->reader_stop = true;

  pthread_join (p->reader, NULL);

  pthread_cond_destroy  (&p->ring_cond);
  pthread_mutex_destroy (&p->ring_lock);

  p->reader_on = false;
}

static bool mp_dr_send (svjtag_priv_t *p, const u8 *tdi, const u32 bits, const u32 stride, const u32 n)
{
  // n back-to-back DR scans of `bits` bits from Run-Test/Idle, through Update-DR and straight on
  // to the next Capture-DR, ending in Run-Test/Idle.
  const u32 body  = bits - 1;
  const u32 bytes = body / 8;
  const u32 rem   = body % 8;

  u8 cmd[SVJTAG_CHUNK_SCANS * (SVJTAG_SCAN_BYTES + 16) + 16];

  if (n > SVJTAG_CHUNK_SCANS) return false;
  if ((mp_rx_per (bits) * n) > 1000) return false;

  size_t c = 0;

  cmd[c++] = 0x4B; cmd[c++] = 0x02; cmd[c++] = 0x01;

  for (u32 s = 0; s < n; s++)
  {
    const u8 *in = &tdi[s * stride];

    if (bytes > 0)
    {
      cmd[c++] = 0x39;
      cmd[c++] = (u8) ((bytes - 1) & 0xff);
      cmd[c++] = (u8) ((bytes - 1) >> 8);

      memcpy (&cmd[c], in, bytes);

      c += bytes;
    }

    if (rem > 0)
    {
      cmd[c++] = 0x3B;
      cmd[c++] = (u8) (rem - 1);
      cmd[c++] = in[bytes];
    }

    cmd[c++] = 0x6B;
    cmd[c++] = 0x00;
    cmd[c++] = (u8) ((bit_get (in, body) << 7) | 0x01);

    if (s + 1 < n)
    {
      cmd[c++] = 0x4B; cmd[c++] = 0x03; cmd[c++] = 0x03;
    }
    else
    {
      cmd[c++] = 0x4B; cmd[c++] = 0x01; cmd[c++] = 0x01;
    }
  }

  cmd[c++] = 0x87;

  return ftdi_write (&p->ftdi, cmd, c);
}

static bool mp_dr_collect (svjtag_priv_t *p, u8 *tdo, const u32 bits, const u32 stride, const u32 n)
{
  // TDO of each scan sent by mp_dr_send lands in tdo at the same stride.
  const u32 body   = bits - 1;
  const u32 bytes  = body / 8;
  const u32 rem    = body % 8;
  const u32 rx_per = mp_rx_per (bits);

  u8 rx[SVJTAG_CHUNK_SCANS * (SVJTAG_SCAN_BYTES + 4)];

  if ((rx_per * n) > sizeof (rx)) return false;

  if (rx_get (p, rx, rx_per * n) == false) return false;

  for (u32 s = 0; s < n; s++)
  {
    const u8 *r   = &rx[s * rx_per];
    u8       *out = &tdo[s * stride];

    memset (out, 0, (bits + 7) / 8);

    memcpy (out, r, bytes);

    if (rem > 0)
    {
      const u8 v = (u8) (r[bytes] >> (8 - rem));

      for (u32 i = 0; i < rem; i++) bit_set (out, (bytes * 8) + i, (v >> i) & 1);
    }

    bit_set (out, body, (r[rx_per - 1] >> 7) & 1);
  }

  return true;
}

static bool mp_dr (svjtag_priv_t *p, const u8 *tdi, u8 *tdo, const u32 bits, const u32 stride, const u32 n)
{
  if (mp_dr_send (p, tdi, bits, stride, n) == false) return false;

  return mp_dr_collect (p, tdo, bits, stride, n);
}

// Link -------------------------------------------------------------------------------------------

typedef struct svjtag_rsp
{
  u32 magic;
  u32 count;
  u32 overflow;
  u32 csr_tag;
  u32 taken;
  u32 depth_log2;
  u32 active;
  u32 tail;
  u32 rdata;
  u32 echo;
  u8  payload[SVJTAG_PAYLOAD];

} svjtag_rsp_t;

static void req_build (const svjtag_priv_t *p, svjtag_scan_t *s, const u32 words, const u8 *payload, const bool claim, const bool release, const u32 op, const u8 tag, const u32 addr, const u32 wdata)
{
  u8 reg[SVJTAG_REG_BYTES];

  memset (reg, 0, sizeof (reg));

  bits_put (reg,  0, 16, SVJTAG_REQ_MAGIC);
  bits_put (reg, 16,  5, words);
  bits_put (reg, 21,  1, claim   ? 1 : 0);
  bits_put (reg, 22,  1, release ? 1 : 0);
  bits_put (reg, 24,  2, op);
  bits_put (reg, 32,  8, tag);
  bits_put (reg, 64, 32, addr);
  bits_put (reg, 96, 32, wdata);

  if (words > 0) memcpy (&reg[16], payload, words * 4);

  // The card's register holds the last REG_BITS bits it shifted in, which are TDI_DELAY bits
  // behind what the host sent.
  const u32 start = SVJTAG_SLACK - p->tdi_delay;

  memset (s->tdi, 0, sizeof (s->tdi));

  for (u32 i = 0; i < SVJTAG_REG_BITS; i++) bit_set (s->tdi, start + i, bit_get (reg, i));
}

static void rsp_parse (const svjtag_priv_t *p, const svjtag_scan_t *s, svjtag_rsp_t *r)
{
  u8 reg[SVJTAG_REG_BYTES];

  memset (reg, 0, sizeof (reg));

  for (u32 i = 0; i < SVJTAG_REG_BITS; i++)
  {
    const int at = (int) i + p->tdo_shift;

    // Bits before the host's first sample can only be the start of the magic.
    if (at < 0)
    {
      if (i < 16) bit_set (reg, i, (SVJTAG_RSP_MAGIC >> i) & 1);

      continue;
    }

    if (at >= SVJTAG_SCAN_BITS) continue;

    bit_set (reg, i, bit_get (s->tdo, (u32) at));
  }

  r->magic      = bits_get (reg,  0, 16);
  r->count      = bits_get (reg, 16,  7);
  r->overflow   = bits_get (reg, 23,  1);
  r->csr_tag    = bits_get (reg, 24,  8);
  r->taken      = bits_get (reg, 32, 16);
  r->depth_log2 = bits_get (reg, 48,  4);
  r->active     = bits_get (reg, 52,  1);
  r->tail       = bits_get (reg, 53, 11);
  r->rdata      = bits_get (reg, 64, 32);
  r->echo       = bits_get (reg, 96, 32);

  memcpy (r->payload, &reg[16], SVJTAG_PAYLOAD);
}

static bool rsp_sane (const svjtag_rsp_t *r)
{
  if (r->magic != SVJTAG_RSP_MAGIC) return false;
  if (r->tail  != 0)                return false;
  if (r->count >  SVJTAG_PAYLOAD)   return false;

  if ((r->depth_log2 < 4) || (r->depth_log2 > 15)) return false;

  return true;
}

static bool rsp_take (svjtag_priv_t *p, const svjtag_rsp_t *r)
{
  // Every response may carry engine output. Outside a batch there should be none, and what comes
  // is dropped.
  if (rsp_sane (r) == false) return false;

  p->taken = (u16) r->taken;

  if (r->overflow) p->overflow = true;

  if (r->count == 0) return true;

  if (p->batch_active == false) return true;

  const u8 *src = &r->payload[SVJTAG_PAYLOAD - r->count];

  const u64 room = p->in_bytes - p->in_have;

  const u64 len = MIN ((u64) r->count, room);

  memcpy (&p->in[p->in_have], src, len);

  p->in_have += len;

  return true;
}

static bool xfer_submit (svjtag_priv_t *p, svjtag_xfer_t *x)
{
  if (p->broken == true) return false;

  if (mp_dr_send (p, x->s[0].tdi, SVJTAG_SCAN_BITS, sizeof (svjtag_scan_t), x->n) == false)
  {
    p->broken = true;

    return false;
  }

  return true;
}

static bool xfer_retire (svjtag_priv_t *p)
{
  // Collect and process the oldest chunk in flight.
  if (p->q_len == 0) return true;

  svjtag_xfer_t *x = &p->q[p->q_head];

  p->q_head = (p->q_head + 1) % SVJTAG_INFLIGHT;
  p->q_len--;

  if (p->broken == true) return false;

  if (mp_dr_collect (p, x->s[0].tdo, SVJTAG_SCAN_BITS, sizeof (svjtag_scan_t), x->n) == false)
  {
    p->broken = true;

    return false;
  }

  for (u32 i = 0; i < x->n; i++)
  {
    svjtag_rsp_t r;

    rsp_parse (p, &x->s[i], &r);

    if (rsp_take (p, &r) == false)
    {
      p->broken = true;

      return false;
    }
  }

  return true;
}

static bool xfer_flush (svjtag_priv_t *p)
{
  bool ok = true;

  while (p->q_len > 0)
  {
    if (xfer_retire (p) == false) ok = false;
  }

  return ok;
}

static svjtag_xfer_t *xfer_slot (svjtag_priv_t *p)
{
  svjtag_xfer_t *x = &p->q[(p->q_head + p->q_len) % SVJTAG_INFLIGHT];

  p->q_len++;

  return x;
}

static bool svjtag_scans (svjtag_priv_t *p, svjtag_scan_t *scans, const u32 n)
{
  // A synchronous exchange: everything in flight first, then these scans, answered in place.
  if (xfer_flush (p) == false) return false;

  svjtag_xfer_t *x = xfer_slot (p);

  memcpy (x->s, scans, n * sizeof (svjtag_scan_t));

  x->n = n;

  if (xfer_submit (p, x) == false) { p->q_len = 0; return false; }

  if (xfer_retire (p) == false) return false;

  memcpy (scans, x->s, n * sizeof (svjtag_scan_t));

  return true;
}

static bool svjtag_calibrate (svjtag_priv_t *p)
{
  // Find where the response starts on TDO from the magic, then which TDI alignment the card
  // reads the request magic back from. Requests with a broken magic are ignored by the card.
  for (u32 delay = 0; delay <= SVJTAG_SLACK; delay++)
  {
    p->tdi_delay = delay;

    svjtag_scan_t s[2];

    req_build (p, &s[0], 0, NULL, false, false, 0, 0, 0, 0);
    req_build (p, &s[1], 0, NULL, false, false, 0, 0, 0, 0);

    if (mp_dr (p, s[0].tdi, s[0].tdo, SVJTAG_SCAN_BITS, sizeof (svjtag_scan_t), 2) == false) return false;

    bool found = false;

    for (int shift = -SVJTAG_SLACK; shift <= SVJTAG_SLACK; shift++)
    {
      p->tdo_shift = shift;

      svjtag_rsp_t r;

      rsp_parse (p, &s[1], &r);

      if (rsp_sane (&r) == false) continue;

      found = true;

      if (r.echo == SVJTAG_REQ_MAGIC)
      {
        p->depth = 1u << r.depth_log2;
        p->taken = (u16) r.taken;
        p->sent  = p->taken;

        return true;
      }

      break;
    }

    if (found == false) return false;
  }

  return false;
}

static bool svjtag_csr (svjtag_priv_t *p, const u32 op, const u32 addr, const u32 wdata, u32 *rdata)
{
  for (int attempt = 0; attempt < 3; attempt++)
  {
    p->tag++;

    if (p->tag == 0) p->tag = 1;

    svjtag_scan_t s[3];

    req_build (p, &s[0], 0, NULL, false, false, op, p->tag, addr, wdata);
    req_build (p, &s[1], 0, NULL, false, false, 0, 0, 0, 0);
    req_build (p, &s[2], 0, NULL, false, false, 0, 0, 0, 0);

    if (svjtag_scans (p, s, 3) == false) return false;

    for (u32 i = 1; i < 3; i++)
    {
      svjtag_rsp_t r;

      rsp_parse (p, &s[i], &r);

      if (r.csr_tag != p->tag) continue;

      if (rdata != NULL) *rdata = r.rdata;

      return true;
    }
  }

  return false;
}

static bool svjtag_route (svjtag_priv_t *p, const bool claim)
{
  svjtag_scan_t s[2];

  req_build (p, &s[0], 0, NULL, claim, !claim, 0, 0, 0, 0);
  req_build (p, &s[1], 0, NULL, false, false, 0, 0, 0, 0);

  if (svjtag_scans (p, s, 2) == false) return false;

  svjtag_rsp_t r;

  rsp_parse (p, &s[1], &r);

  if (claim == true) p->overflow = false;

  return (r.active == (claim ? 1u : 0u));
}

static bool svjtag_pump (svjtag_priv_t *p)
{
  // One more chunk in flight, after collecting the oldest when the pipeline is full: as much host
  // data as the card's FIFO has room for, and whatever the card has for the host.
  if (p->q_len == SVJTAG_INFLIGHT)
  {
    if (xfer_retire (p) == false) return false;
  }

  if (p->overflow == true)
  {
    p->broken = true;

    return false;
  }

  svjtag_xfer_t *x = xfer_slot (p);

  svjtag_scan_t *s = x->s;

  x->n = SVJTAG_CHUNK_SCANS;

  const u16 inflight = (u16) (p->sent - p->taken);

  u32 room = (p->depth > ((u32) inflight + 2)) ? (p->depth - inflight - 2) : 0;

  for (u32 i = 0; i < SVJTAG_CHUNK_SCANS; i++)
  {
    const u64 pending = p->out_have - p->out_pos;

    u32 words = 0;

    if ((room > 0) && (pending >= 4))
    {
      words = (u32) MIN ((u64) SVJTAG_WORDS, pending / 4);
    }

    req_build (p, &s[i], words, (words > 0) ? &p->out[p->out_pos] : NULL, false, false, 0, 0, 0, 0);

    if (words > 0)
    {
      p->out_pos += words * 4;

      p->sent++;

      room--;
    }
  }

  if (xfer_submit (p, x) == false) { p->q_len = 0; return false; }

  return true;
}

static bool sld_info (svjtag_priv_t *p, u32 *words, const u32 count)
{
  u8 zeros[8] = { 0 };
  u8 dummy[8];

  if (mp_ir (p, SVJTAG_IR_USER1) == false) return false;

  if (mp_dr (p, zeros, dummy, 64, 8, 1) == false) return false;

  if (mp_ir (p, SVJTAG_IR_USER0) == false) return false;

  for (u32 w = 0; w < count; w++)
  {
    words[w] = 0;

    for (u32 k = 0; k < 8; k++)
    {
      u8 t = 0;
      u8 r = 0;

      if (mp_dr (p, &t, &r, 4, 1, 1) == false) return false;

      words[w] |= (u32) (r & 0x0f) << (4 * k);
    }
  }

  return true;
}

static bool sld_address (svjtag_priv_t *p, const u32 bits, const u32 value)
{
  u8 v[4];

  v[0] = (u8) (value >>  0);
  v[1] = (u8) (value >>  8);
  v[2] = (u8) (value >> 16);
  v[3] = (u8) (value >> 24);

  u8 dummy[4];

  if (mp_ir (p, SVJTAG_IR_USER1) == false) return false;

  if (mp_dr (p, v, dummy, bits, 4, 1) == false) return false;

  return mp_ir (p, SVJTAG_IR_USER0);
}

static bool sld_select (svjtag_priv_t *p)
{
  // Find this link's node on the hub by its instance number, address it, and calibrate the scan
  // alignment. Other nodes, such as the transceiver controller's Nios debug node, are never
  // scanned.
  u32 hub = 0;

  if (sld_info (p, &hub, 1) == false) return false;

  svjtag_dbg (p, "hub info %08x", hub);

  if (((hub >> 8) & 0x7ff) != SVJTAG_SLD_MFR) return false;

  const u32 nodes = (hub >> 19) & 0xff;
  const u32 m     = hub & 0xff;

  if ((nodes == 0) || (nodes > SVJTAG_SLD_NODES) || (m == 0) || (m > 16)) return false;

  u32 words[1 + SVJTAG_SLD_NODES];

  if (sld_info (p, words, 1 + nodes) == false) return false;

  u32 n = 0;

  while ((1u << n) < (nodes + 1)) n++;

  for (u32 node = 1; node <= nodes; node++) svjtag_dbg (p, "node %u info %08x", node, words[node]);

  for (u32 node = 1; node <= nodes; node++)
  {
    if (((words[node] >> 8) & 0x7ff) != SVJTAG_SLD_MFR) continue;

    if ((words[node] & 0xff) != SVJTAG_NODE_INST) continue;

    p->vir_bits  = m + n;
    p->vir_value = node << m;

    if (sld_address (p, p->vir_bits, p->vir_value) == false) return false;

    const bool ok = svjtag_calibrate (p);

    svjtag_dbg (p, "node %u selected, vir %u bits %x, calibration %s (tdi delay %u, tdo shift %d, depth %u)", node, p->vir_bits, p->vir_value, ok ? "ok" : "failed", p->tdi_delay, p->tdo_shift, p->depth);

    return ok;
  }

  return false;
}

static void svjtag_shutdown (svjtag_priv_t *p)
{
  if (p->ftdi_open == true)
  {
    if ((p->broken == false) && (p->depth != 0)) svjtag_route (p, false);

    reader_stop (p);

    ftdi_close (&p->ftdi);

    p->ftdi_open = false;
  }

  hcfree (p->out);
  hcfree (p->in);

  p->out = NULL;
  p->in  = NULL;
}

static bool svjtag_bringup (svjtag_priv_t *p, const u32 tck_hz)
{
  if (ftdi_open_port (&p->ftdi, SVJTAG_VID, SVJTAG_PID, p->port) == false) return false;

  p->ftdi_open = true;
  p->broken    = false;
  p->tck_hz    = tck_hz;
  p->depth     = 0;
  p->q_head    = 0;
  p->q_len     = 0;

  if (ftdi_mpsse_enable_jtag (&p->ftdi, tck_hz) == false) return false;
  if (ftdi_mpsse_sync (&p->ftdi) == false) return false;

  if (mp_tap_reset (p) == false) return false;

  // After Test-Logic-Reset the instruction is IDCODE.
  u8 tdi[4] = { 0xff, 0xff, 0xff, 0xff };
  u8 tdo[4] = { 0 };

  if (mp_dr (p, tdi, tdo, 32, 4, 1) == false) return false;

  p->idcode = (u32) tdo[0] | ((u32) tdo[1] << 8) | ((u32) tdo[2] << 16) | ((u32) tdo[3] << 24);

  svjtag_dbg (p, "idcode %08x at %u Hz", p->idcode, tck_hz);

  if ((p->idcode & 0xfff) != SVJTAG_ALTERA_MFR) return false;

  if (sld_select (p) == false) return false;

  // The scratch register reads the same every time on a clean link.
  u32 first = 0;

  for (int i = 0; i < 8; i++)
  {
    u32 v = 0;

    if (svjtag_csr (p, SVJTAG_CSR_READ, fpga_csr_map_no_cpu.base + fpga_csr_map_no_cpu.scratch, 0, &v) == false) return false;

    if (i == 0) first = v;

    if ((v != first) || (v == 0) || (v == 0xffffffff)) return false;
  }

  if (reader_start (p) == false) return false;

  if (getenv ("HCFPGA_SVJTAG_BENCH") != NULL)
  {
    const u32 rounds = 200;

    const u64 t0 = fpga_now_ns ();

    for (u32 i = 0; i < rounds; i++)
    {
      if (svjtag_pump (p) == false) return false;
    }

    if (xfer_flush (p) == false) return false;

    const u64 dt = fpga_now_ns () - t0;

    const double us = (double) dt / 1000.0 / rounds;

    svjtag_dbg (p, "%.1f us per %u scans, %.2f MB/s each way at most", us, SVJTAG_CHUNK_SCANS, (SVJTAG_CHUNK_SCANS * SVJTAG_PAYLOAD) / us);
  }

  return true;
}

static bool svjtag_dna (svjtag_priv_t *p, char *serial, const size_t len)
{
  const u32 base = fpga_csr_map_no_cpu.base + fpga_csr_map_no_cpu.dna;

  u32 hi = 0;
  u32 lo = 0;

  if (svjtag_csr (p, SVJTAG_CSR_READ, base + 0, 0, &hi) == false) return false;
  if (svjtag_csr (p, SVJTAG_CSR_READ, base + 4, 0, &lo) == false) return false;

  const u64 dna = (((u64) hi << 32) | lo) & 0x01ffffffffffffffULL;

  if ((dna == 0) || (dna == 0x01ffffffffffffffULL)) return false;

  snprintf (serial, len, "%014" PRIx64, dna);

  return true;
}

// Transport --------------------------------------------------------------------------------------

static u32 svjtag_tck_hz (void)
{
  const char *env = getenv ("HCFPGA_SVJTAG_TCK");

  if (env == NULL) return SVJTAG_TCK_DEFAULT;

  const unsigned long v = strtoul (env, NULL, 10);

  return (v >= 100000 && v <= 30000000) ? (u32) v : SVJTAG_TCK_DEFAULT;
}

static int svjtag_enumerate (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, fpga_status_t *status)
{
  (void) hashcat_ctx;

  *status = FPGA_STATUS_NO_PCI_DEVICE;

  if (getenv ("HCFPGA_SVJTAG_OFF") != NULL) return 0;

  DIR *d = opendir (SVJTAG_SYSFS);

  if (d == NULL) return 0;

  int cnt = 0;

  bool saw_permission = false;

  struct dirent *e = NULL;

  while ((e = readdir (d)) != NULL)
  {
    if ((cnt >= max) || (cnt >= SVJTAG_MAX_DEVS)) break;

    if (e->d_name[0] == '.') continue;

    if (strchr (e->d_name, ':') != NULL) continue;

    char path[512];

    snprintf (path, sizeof (path), "%s/%s/idVendor", SVJTAG_SYSFS, e->d_name);

    FILE *fp = fopen (path, "r");

    if (fp == NULL) continue;

    unsigned int vid = 0;
    unsigned int pid = 0;

    const int got_vid = fscanf (fp, "%x", &vid);

    fclose (fp);

    snprintf (path, sizeof (path), "%s/%s/idProduct", SVJTAG_SYSFS, e->d_name);

    fp = fopen (path, "r");

    if (fp == NULL) continue;

    const int got_pid = fscanf (fp, "%x", &pid);

    fclose (fp);

    if ((got_vid != 1) || (got_pid != 1)) continue;

    if ((vid != SVJTAG_VID) || (pid != SVJTAG_PID)) continue;

    svjtag_priv_t *p = &SVJTAG_PRIV[cnt];

    memset (p, 0, sizeof (svjtag_priv_t));

    snprintf (p->port, sizeof (p->port), "%.63s", e->d_name);

    if (svjtag_bringup (p, svjtag_tck_hz ()) == false)
    {
      if ((p->ftdi_open == false) && (access ("/dev/bus/usb", R_OK) == 0)) saw_permission = true;

      svjtag_shutdown (p);

      continue;
    }

    char serial[32];

    if (svjtag_dna (p, serial, sizeof (serial)) == false)
    {
      svjtag_shutdown (p);

      continue;
    }

    if (fpga_litepcie_serial_present (serial) == true)
    {
      svjtag_shutdown (p);

      continue;
    }

    pthread_mutex_init (&p->lock, NULL);

    fpga_dev_t *dev = &devs[cnt];

    memset (dev, 0, sizeof (fpga_dev_t));

    snprintf (dev->path, sizeof (dev->path), "jtag:%s", p->port);

    dev->fd        = -1;
    dev->priv      = p;
    dev->transport = &fpga_transport_svjtag;

    cnt++;
  }

  closedir (d);

  if (cnt > 0)              *status = FPGA_STATUS_OK;
  else if (saw_permission)  *status = FPGA_STATUS_NO_PERMISSION;

  return cnt;
}

static void svjtag_close (fpga_dev_t *dev)
{
  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  if (p == NULL) return;

  svjtag_shutdown (p);

  pthread_mutex_destroy (&p->lock);

  dev->priv = NULL;
}

static u32 svjtag_csr_read (fpga_dev_t *dev, const u32 addr)
{
  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  u32 v = 0;

  pthread_mutex_lock (&p->lock);

  if (svjtag_csr (p, SVJTAG_CSR_READ, dev->csr_base + addr, 0, &v) == false) v = 0;

  pthread_mutex_unlock (&p->lock);

  return v;
}

static bool svjtag_csr_write (fpga_dev_t *dev, const u32 addr, const u32 val)
{
  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  pthread_mutex_lock (&p->lock);

  const bool ok = svjtag_csr (p, SVJTAG_CSR_WRITE, dev->csr_base + addr, val, NULL);

  pthread_mutex_unlock (&p->lock);

  return ok;
}

static fpga_status_t svjtag_identify (fpga_dev_t *dev)
{
  const u32 scratch = svjtag_csr_read (dev, dev->map->scratch);

  if (scratch != 0x12345678) return FPGA_STATUS_BAD_IDENT;

  char raw[FPGA_IDENT_MAX];

  u32 i = 0;

  for (i = 0; i < (FPGA_IDENT_MAX - 1); i++)
  {
    const u32 c = svjtag_csr_read (dev, dev->map->identifier_mem + (4 * i)) & 0xff;

    if (c == 0) break;

    raw[i] = (char) c;
  }

  raw[i] = 0;

  if (fpga_ident_parse (raw, &dev->ident) == false) return FPGA_STATUS_BAD_IDENT;

  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  pthread_mutex_lock (&p->lock);

  svjtag_dna (p, dev->ident.serial, sizeof (dev->ident.serial));

  pthread_mutex_unlock (&p->lock);

  return FPGA_STATUS_OK;
}

static bool svjtag_session_open (fpga_dev_t *dev)
{
  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  pthread_mutex_lock (&p->lock);

  const bool ok = svjtag_route (p, true);

  pthread_mutex_unlock (&p->lock);

  return ok;
}

static void svjtag_session_close (fpga_dev_t *dev)
{
  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  pthread_mutex_lock (&p->lock);

  if (p->broken == false) svjtag_route (p, false);

  pthread_mutex_unlock (&p->lock);
}

static bool svjtag_session_refresh (fpga_dev_t *dev)
{
  // A failed batch may have left words in the card's FIFO and the link marked broken. Bring the
  // link up again from scratch and claim the engine.
  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  pthread_mutex_lock (&p->lock);

  reader_stop (p);

  if (p->ftdi_open == true) ftdi_close (&p->ftdi);

  p->ftdi_open = false;

  bool ok = svjtag_bringup (p, p->tck_hz);

  if (ok == true) ok = svjtag_route (p, true);

  pthread_mutex_unlock (&p->lock);

  return ok;
}

static u64 svjtag_out_capacity (MAYBE_UNUSED fpga_dev_t *dev)
{
  return SVJTAG_CAPACITY;
}

static bool svjtag_batch_begin (fpga_dev_t *dev, const u64 out_bytes, const u64 in_bytes, const u32 in_grain, const u32 in_recs)
{
  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  if (in_grain == 0) return false;

  if (out_bytes > SVJTAG_CAPACITY) return false;
  if (in_bytes  > SVJTAG_CAPACITY) return false;

  if ((out_bytes % 4) != 0) return false;

  pthread_mutex_lock (&p->lock);

  if (p->out == NULL) p->out = (u8 *) hcmalloc (SVJTAG_CAPACITY);
  if (p->in  == NULL) p->in  = (u8 *) hcmalloc (SVJTAG_CAPACITY);

  p->out_bytes = out_bytes;
  p->out_have  = 0;
  p->out_pos   = 0;

  p->in_bytes  = in_bytes;
  p->in_have   = 0;
  p->in_given  = 0;
  p->in_grain  = in_grain;
  p->in_recs   = in_recs;

  p->eob_seen      = false;
  p->eob_processed = 0;

  p->batch_active = true;

  pthread_mutex_unlock (&p->lock);

  return true;
}

static bool svjtag_batch_send (fpga_dev_t *dev, const void *src, const u64 bytes)
{
  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  pthread_mutex_lock (&p->lock);

  const bool fits = ((p->out_have + bytes) <= p->out_bytes);

  if (fits == true)
  {
    memcpy (&p->out[p->out_have], src, bytes);

    p->out_have += bytes;
  }

  pthread_mutex_unlock (&p->lock);

  return fits;
}

static const void *svjtag_batch_recv (fpga_dev_t *dev, u64 *bytes, const u32 timeout_ms)
{
  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  *bytes = 0;

  const u64 t0 = fpga_now_ns ();

  const void *ret = NULL;

  pthread_mutex_lock (&p->lock);

  while (p->in_given < p->in_bytes)
  {
    const u64 ready = ((p->in_have - p->in_given) / p->in_grain) * p->in_grain;

    const bool tail = ((p->in_have == p->in_bytes) && (p->in_have > p->in_given));

    if ((ready > 0) || (tail == true))
    {
      const u64 len = (tail == true && ready == 0) ? (p->in_have - p->in_given) : MIN (ready, (u64) SVJTAG_RECV_MAX);

      const u8 *buf = &p->in[p->in_given];

      if (p->eob_seen == false)
      {
        u32 processed = 0;

        if (hcfpga_c2h_scan_eob (buf, len, p->in_grain, p->in_recs, &processed) == true)
        {
          p->eob_seen      = true;
          p->eob_processed = processed;
        }
      }

      p->in_given += len;

      *bytes = len;

      ret = buf;

      break;
    }

    if (svjtag_pump (p) == false) break;

    if ((fpga_now_ns () - t0) > ((u64) timeout_ms * 1000000ull)) break;
  }

  pthread_mutex_unlock (&p->lock);

  return ret;
}

static bool svjtag_batch_done (fpga_dev_t *dev, u32 *processed)
{
  const svjtag_priv_t *p = (const svjtag_priv_t *) dev->priv;

  if (p->eob_seen == false) return false;

  if (processed != NULL) *processed = p->eob_processed;

  return true;
}

static bool svjtag_batch_failed (fpga_dev_t *dev)
{
  const svjtag_priv_t *p = (const svjtag_priv_t *) dev->priv;

  return p->broken;
}

static void svjtag_batch_end (fpga_dev_t *dev)
{
  svjtag_priv_t *p = (svjtag_priv_t *) dev->priv;

  pthread_mutex_lock (&p->lock);

  xfer_flush (p);

  p->batch_active = false;

  pthread_mutex_unlock (&p->lock);
}

static bool svjtag_link_str (fpga_dev_t *dev, char *buf, const size_t len)
{
  const svjtag_priv_t *p = (const svjtag_priv_t *) dev->priv;

  snprintf (buf, len, "JTAG %u MHz", p->tck_hz / 1000000);

  return true;
}

#else

static int svjtag_enumerate (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED fpga_dev_t *devs, MAYBE_UNUSED const int max, fpga_status_t *status)
{
  *status = FPGA_STATUS_UNSUPPORTED_OS;

  return 0;
}

static void          svjtag_close           (MAYBE_UNUSED fpga_dev_t *dev) { }
static u32           svjtag_csr_read        (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const u32 addr) { return 0; }
static bool          svjtag_csr_write       (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const u32 addr, MAYBE_UNUSED const u32 val) { return false; }
static fpga_status_t svjtag_identify        (MAYBE_UNUSED fpga_dev_t *dev) { return FPGA_STATUS_UNSUPPORTED_OS; }
static bool          svjtag_session_open    (MAYBE_UNUSED fpga_dev_t *dev) { return false; }
static void          svjtag_session_close   (MAYBE_UNUSED fpga_dev_t *dev) { }
static bool          svjtag_session_refresh (MAYBE_UNUSED fpga_dev_t *dev) { return false; }
static u64           svjtag_out_capacity    (MAYBE_UNUSED fpga_dev_t *dev) { return 0; }
static bool          svjtag_batch_begin     (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const u64 out_bytes, MAYBE_UNUSED const u64 in_bytes, MAYBE_UNUSED const u32 in_grain, MAYBE_UNUSED const u32 in_recs) { return false; }
static bool          svjtag_batch_send      (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const void *src, MAYBE_UNUSED const u64 bytes) { return false; }
static const void   *svjtag_batch_recv      (MAYBE_UNUSED fpga_dev_t *dev, u64 *bytes, MAYBE_UNUSED const u32 timeout_ms) { *bytes = 0; return NULL; }
static bool          svjtag_batch_done      (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED u32 *processed) { return false; }
static bool          svjtag_batch_failed    (MAYBE_UNUSED fpga_dev_t *dev) { return true; }
static void          svjtag_batch_end       (MAYBE_UNUSED fpga_dev_t *dev) { }
static bool          svjtag_link_str        (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED char *buf, MAYBE_UNUSED const size_t len) { return false; }

#endif

const fpga_transport_t fpga_transport_svjtag =
{
  .name            = "svjtag",
  .bus             = "USB",
  .data_link       = "JTAG",
  .udev            = "99-ft232h.rules",
  .dialect         = FPGA_DIALECT_HCFPGA,

  .enumerate       = svjtag_enumerate,
  .identify        = svjtag_identify,
  .close           = svjtag_close,

  .csr_read        = svjtag_csr_read,
  .csr_write       = svjtag_csr_write,

  .session_open    = svjtag_session_open,
  .session_close   = svjtag_session_close,
  .session_refresh = svjtag_session_refresh,
  .out_capacity    = svjtag_out_capacity,

  .batch_begin     = svjtag_batch_begin,
  .batch_send      = svjtag_batch_send,
  .batch_recv      = svjtag_batch_recv,
  .batch_end       = svjtag_batch_end,
  .batch_done      = svjtag_batch_done,
  .batch_failed    = svjtag_batch_failed,

  .in_granule      = 0,

  .program         = NULL,

  .temperature     = NULL,

  .link_str        = svjtag_link_str,
};
