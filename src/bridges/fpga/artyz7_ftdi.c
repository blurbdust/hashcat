/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "artyz7_ftdi.h"

bool ARTYZ7_VERBOSE = false;

#if defined (__linux__)

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/usbdevice_fs.h>
#include <sys/ioctl.h>

#define SYSFS_USB_DEVICES "/sys/bus/usb/devices"

#define CTRL_TIMEOUT_MS   1000
#define BULK_TIMEOUT_MS   5000

static bool read_attr (const char *dir, const char *name, char *out, const size_t out_len)
{
  char path[512];

  snprintf (path, sizeof (path), "%s/%s/%s", SYSFS_USB_DEVICES, dir, name);

  const int fd = open (path, O_RDONLY);

  if (fd < 0) return false;

  const ssize_t n = read (fd, out, out_len - 1);

  close (fd);

  if (n <= 0) return false;

  out[n] = 0;

  for (ssize_t i = n - 1; i >= 0; i--)
  {
    if ((out[i] == '\n') || (out[i] == '\r')) out[i] = 0;
  }

  return true;
}

static bool find_device (const u16 vid, const u16 pid, const char *serial, u32 *busnum, u32 *devnum)
{
  DIR *d = opendir (SYSFS_USB_DEVICES);

  if (d == NULL) return false;

  bool found = false;

  struct dirent *e = NULL;

  while ((e = readdir (d)) != NULL)
  {
    if (e->d_name[0] == '.') continue;

    char v[32];
    char p[32];

    if (read_attr (e->d_name, "idVendor",  v, sizeof (v)) == false) continue;
    if (read_attr (e->d_name, "idProduct", p, sizeof (p)) == false) continue;

    if ((u16) strtoul (v, NULL, 16) != vid) continue;
    if ((u16) strtoul (p, NULL, 16) != pid) continue;

    if (serial != NULL)
    {
      char s[64];

      if (read_attr (e->d_name, "serial", s, sizeof (s)) == false) continue;
      if (strcmp (s, serial) != 0) continue;
    }

    char b[32];
    char n[32];

    if (read_attr (e->d_name, "busnum",  b, sizeof (b)) == false) continue;
    if (read_attr (e->d_name, "devnum",  n, sizeof (n)) == false) continue;

    *busnum = (u32) strtoul (b, NULL, 10);
    *devnum = (u32) strtoul (n, NULL, 10);

    found = true;

    break;
  }

  closedir (d);

  return found;
}

static bool ctrl_out (ftdi_ctx_t *ctx, const u8 request, const u16 value, const u16 index)
{
  struct usbdevfs_ctrltransfer ct;

  memset (&ct, 0, sizeof (ct));

  ct.bRequestType = 0x40;
  ct.bRequest     = request;
  ct.wValue       = value;
  ct.wIndex       = index;
  ct.wLength      = 0;
  ct.timeout      = CTRL_TIMEOUT_MS;
  ct.data         = NULL;

  const int rc = ioctl (ctx->fd, USBDEVFS_CONTROL, &ct);

  if (rc < 0)
  {
    fprintf (stderr, "ftdi: control request 0x%02x failed: %s\n", request, strerror (errno));

    return false;
  }

  return true;
}

bool ftdi_write (ftdi_ctx_t *ctx, const u8 *buf, const size_t len)
{
  struct usbdevfs_bulktransfer bt;

  memset (&bt, 0, sizeof (bt));

  bt.ep      = FTDI_EP_OUT;
  bt.len     = (unsigned int) len;
  bt.timeout = BULK_TIMEOUT_MS;
  bt.data    = (void *) buf;

  const int rc = ioctl (ctx->fd, USBDEVFS_BULK, &bt);

  if (rc < 0)
  {
    fprintf (stderr, "ftdi: bulk out failed: %s\n", strerror (errno));

    return false;
  }

  if ((size_t) rc != len)
  {
    fprintf (stderr, "ftdi: bulk out short, wanted %zu got %d\n", len, rc);

    return false;
  }

  return true;
}

static bool ftdi_fill (ftdi_ctx_t *ctx)
{
  u8 raw[4096];

  struct usbdevfs_bulktransfer bt;

  memset (&bt, 0, sizeof (bt));

  bt.ep      = FTDI_EP_IN;
  bt.len     = (unsigned int) (sizeof (raw) - (sizeof (raw) % ctx->in_packet_size));
  bt.timeout = BULK_TIMEOUT_MS;
  bt.data    = raw;

  const int rc = ioctl (ctx->fd, USBDEVFS_BULK, &bt);

  if (rc < 0)
  {
    fprintf (stderr, "ftdi: bulk in failed: %s\n", strerror (errno));

    return false;
  }

  ctx->rx_len = 0;
  ctx->rx_pos = 0;

  for (int off = 0; off < rc; off += (int) ctx->in_packet_size)
  {
    int chunk = rc - off;

    if (chunk > (int) ctx->in_packet_size) chunk = (int) ctx->in_packet_size;
    if (chunk <= FTDI_STATUS_BYTES) continue;

    const u32 payload = (u32) (chunk - FTDI_STATUS_BYTES);

    if ((ctx->rx_len + payload) > sizeof (ctx->rx)) break;

    memcpy (&ctx->rx[ctx->rx_len], &raw[off + FTDI_STATUS_BYTES], payload);

    ctx->rx_len += payload;
  }

  return true;
}

bool ftdi_read (ftdi_ctx_t *ctx, u8 *buf, const size_t len)
{
  size_t got = 0;

  u32 empty = 0;

  while (got < len)
  {
    while ((got < len) && (ctx->rx_pos < ctx->rx_len))
    {
      buf[got] = ctx->rx[ctx->rx_pos];

      got++;
      ctx->rx_pos++;
    }

    if (got == len) break;

    if (empty > 1000)
    {
      fprintf (stderr, "ftdi: bulk in gave only status bytes, wanted %zu got %zu\n", len, got);

      return false;
    }

    if (ftdi_fill (ctx) == false) return false;

    if (ctx->rx_len == 0)
    {
      empty++;
    }
    else
    {
      empty = 0;
    }
  }

  return true;
}

bool ftdi_open (ftdi_ctx_t *ctx, const u16 vid, const u16 pid, const char *serial)
{
  u32 busnum = 0;
  u32 devnum = 0;

  if (find_device (vid, pid, serial, &busnum, &devnum) == false)
  {
    fprintf (stderr, "ftdi: no device %04x:%04x serial %s\n", vid, pid, (serial != NULL) ? serial : "any");

    return false;
  }

  if (ftdi_open_busdev (ctx, vid, pid, busnum, devnum) == false) return false;

  if (serial != NULL) snprintf (ctx->serial, sizeof (ctx->serial), "%s", serial);

  return true;
}

bool ftdi_open_busdev (ftdi_ctx_t *ctx, const u16 vid, const u16 pid, const u32 busnum, const u32 devnum)
{
  memset (ctx, 0, sizeof (ftdi_ctx_t));

  ctx->fd  = -1;
  ctx->vid = vid;
  ctx->pid = pid;

  char path[128];

  snprintf (path, sizeof (path), "/dev/bus/usb/%03u/%03u", busnum, devnum);

  ctx->fd = open (path, O_RDWR);

  if (ctx->fd < 0)
  {
    fprintf (stderr, "ftdi: open %s: %s\n", path, strerror (errno));

    return false;
  }

  ctx->in_packet_size = 512;

  struct usbdevfs_ioctl cmd;

  memset (&cmd, 0, sizeof (cmd));

  cmd.ifno       = FTDI_INTERFACE_A_NUMBER;
  cmd.ioctl_code = USBDEVFS_DISCONNECT;
  cmd.data       = NULL;

  if (ioctl (ctx->fd, USBDEVFS_IOCTL, &cmd) == 0)
  {
    ctx->detached = true;
  }
  else
  {
    if ((errno != ENODATA) && (errno != EINVAL))
    {
      fprintf (stderr, "ftdi: detach kernel driver: %s\n", strerror (errno));
    }
  }

  int ifno = FTDI_INTERFACE_A_NUMBER;

  if (ioctl (ctx->fd, USBDEVFS_CLAIMINTERFACE, &ifno) < 0)
  {
    fprintf (stderr, "ftdi: claim interface: %s\n", strerror (errno));

    close (ctx->fd);

    ctx->fd = -1;

    return false;
  }

  ctx->claimed = true;

  return true;
}

int ftdi_read_some (ftdi_ctx_t *ctx, u8 *buf, const size_t max, const u32 timeout_ms)
{
  // One bulk read of whatever the chip has, status bytes stripped. 0 on timeout, -1 on error.
  u8 raw[16384];

  struct usbdevfs_bulktransfer bt;

  memset (&bt, 0, sizeof (bt));

  bt.ep      = FTDI_EP_IN;
  bt.len     = (unsigned int) (sizeof (raw) - (sizeof (raw) % ctx->in_packet_size));
  bt.timeout = timeout_ms;
  bt.data    = raw;

  const int rc = ioctl (ctx->fd, USBDEVFS_BULK, &bt);

  if (rc < 0) return (errno == ETIMEDOUT) ? 0 : -1;

  size_t got = 0;

  for (int off = 0; off < rc; off += (int) ctx->in_packet_size)
  {
    int chunk = rc - off;

    if (chunk > (int) ctx->in_packet_size) chunk = (int) ctx->in_packet_size;
    if (chunk <= FTDI_STATUS_BYTES) continue;

    const size_t payload = (size_t) (chunk - FTDI_STATUS_BYTES);

    if ((got + payload) > max) return -1;

    memcpy (&buf[got], &raw[off + FTDI_STATUS_BYTES], payload);

    got += payload;
  }

  return (int) got;
}

bool ftdi_open_port (ftdi_ctx_t *ctx, const u16 vid, const u16 pid, const char *port)
{
  // Adapters without a serial number are told apart by the USB port they sit on, as in
  // /sys/bus/usb/devices (for example "2-2.3").
  char v[32];
  char p[32];
  char b[32];
  char n[32];

  if (read_attr (port, "idVendor",  v, sizeof (v)) == false) return false;
  if (read_attr (port, "idProduct", p, sizeof (p)) == false) return false;

  if ((u16) strtoul (v, NULL, 16) != vid) return false;
  if ((u16) strtoul (p, NULL, 16) != pid) return false;

  if (read_attr (port, "busnum", b, sizeof (b)) == false) return false;
  if (read_attr (port, "devnum", n, sizeof (n)) == false) return false;

  return ftdi_open_busdev (ctx, vid, pid, (u32) strtoul (b, NULL, 10), (u32) strtoul (n, NULL, 10));
}

bool ftdi_mpsse_enable_jtag (ftdi_ctx_t *ctx, const u32 tck_hz)
{
  // A bare FT232H wired as a JTAG cable: ADBUS0 TCK, ADBUS1 TDI, ADBUS2 TDO, ADBUS3 TMS, nothing
  // else driven.
  if (ctrl_out (ctx, FTDI_SIO_RESET, FTDI_RESET_SIO,      FTDI_INTERFACE_A_INDEX) == false) return false;
  if (ctrl_out (ctx, FTDI_SIO_RESET, FTDI_RESET_PURGE_RX, FTDI_INTERFACE_A_INDEX) == false) return false;
  if (ctrl_out (ctx, FTDI_SIO_RESET, FTDI_RESET_PURGE_TX, FTDI_INTERFACE_A_INDEX) == false) return false;

  if (ctrl_out (ctx, FTDI_SIO_SET_LATENCY_TIMER, 1, FTDI_INTERFACE_A_INDEX) == false) return false;

  if (ctrl_out (ctx, FTDI_SIO_SET_BITMODE, (FTDI_BITMODE_RESET << 8) | 0x00, FTDI_INTERFACE_A_INDEX) == false) return false;
  if (ctrl_out (ctx, FTDI_SIO_SET_BITMODE, (FTDI_BITMODE_MPSSE << 8) | 0x0B, FTDI_INTERFACE_A_INDEX) == false) return false;

  usleep (50000);

  // A command a previous user left waiting for its data would take the setup below for that data.
  if (ftdi_mpsse_sync (ctx) == false) return false;

  u32 divisor = 0;

  if (tck_hz > 0)
  {
    divisor = (60000000 + (2 * tck_hz) - 1) / (2 * tck_hz);

    if (divisor > 0) divisor = divisor - 1;
    if (divisor > 0xFFFF) divisor = 0xFFFF;
  }

  const u8 setup[] =
  {
    0x8A, 0x97, 0x8D, 0x85,

    0x86, (u8) (divisor & 0xFF), (u8) (divisor >> 8),

    0x80, 0x08, 0x0B,
  };

  if (ftdi_write (ctx, setup, sizeof (setup)) == false) return false;

  return true;
}

void ftdi_close (ftdi_ctx_t *ctx)
{
  if (ctx->fd < 0) return;

  ctrl_out (ctx, FTDI_SIO_SET_BITMODE, (FTDI_BITMODE_RESET << 8) | 0x00, FTDI_INTERFACE_A_INDEX);

  if (ctx->claimed == true)
  {
    int ifno = FTDI_INTERFACE_A_NUMBER;

    ioctl (ctx->fd, USBDEVFS_RELEASEINTERFACE, &ifno);
  }

  close (ctx->fd);

  ctx->fd = -1;
}

bool ftdi_mpsse_enable (ftdi_ctx_t *ctx, const u32 tck_hz)
{
  if (ctrl_out (ctx, FTDI_SIO_RESET, FTDI_RESET_SIO,      FTDI_INTERFACE_A_INDEX) == false) return false;
  if (ctrl_out (ctx, FTDI_SIO_RESET, FTDI_RESET_PURGE_RX, FTDI_INTERFACE_A_INDEX) == false) return false;
  if (ctrl_out (ctx, FTDI_SIO_RESET, FTDI_RESET_PURGE_TX, FTDI_INTERFACE_A_INDEX) == false) return false;

  if (ctrl_out (ctx, FTDI_SIO_SET_LATENCY_TIMER, 5, FTDI_INTERFACE_A_INDEX) == false) return false;

  if (ctrl_out (ctx, FTDI_SIO_SET_BAUDRATE, 0x04E2, 0x0201) == false) return false;

  if (ctrl_out (ctx, FTDI_SIO_SET_BITMODE, (FTDI_BITMODE_RESET << 8) | 0x00, FTDI_INTERFACE_A_INDEX) == false) return false;
  if (ctrl_out (ctx, FTDI_SIO_SET_BITMODE, (FTDI_BITMODE_MPSSE << 8) | 0xFB, FTDI_INTERFACE_A_INDEX) == false) return false;

  usleep (50000);

  u32 divisor = 0;

  if (tck_hz > 0)
  {
    divisor = (60000000 / (2 * tck_hz));

    if (divisor > 0) divisor = divisor - 1;
    if (divisor > 0xFFFF) divisor = 0xFFFF;
  }

  const u8 setup[] =
  {
    0x8A,

    0x86, (u8) (divisor & 0xFF), (u8) (divisor >> 8),

    0x80, 0xE8, 0xEB,

    0x82, 0x00, 0x60,
  };

  if (ftdi_write (ctx, setup, sizeof (setup)) == false) return false;

  return true;
}

static bool ftdi_drain (ftdi_ctx_t *ctx)
{
  // Read until the chip has had nothing to send twice in a row.
  for (int i = 0, quiet = 0; (i < 64) && (quiet < 2); i++)
  {
    if (ftdi_fill (ctx) == false) return false;

    quiet = (ctx->rx_len == 0) ? quiet + 1 : 0;
  }

  ctx->rx_len = 0;
  ctx->rx_pos = 0;

  return true;
}

bool ftdi_mpsse_sync (ftdi_ctx_t *ctx)
{
  // The MPSSE answers a bad command with 0xFA and the command. A user that stopped in the middle
  // of a transfer can leave bytes on their way to the host, and a command still waiting for its
  // data that takes the bad command for that data. So the bytes are drained, the question is asked
  // once and then as a run long enough to finish such a command, and the answers after the first
  // are drained too.
  u8 ask[257];

  for (int attempt = 0; attempt < 3; attempt++)
  {
    if (ftdi_drain (ctx) == false) return false;

    const size_t n = (attempt == 0) ? 1 : (sizeof (ask) - 1);

    memset (ask, 0xAB, n);

    ask[n] = MPSSE_SEND_IMMEDIATE_BYTE;

    if (ftdi_write (ctx, ask, n + 1) == false) return false;

    u8 prev = 0;

    for (int i = 0; i < 100; i++)
    {
      if (ftdi_fill (ctx) == false) return false;

      for (u32 j = 0; j < ctx->rx_len; j++)
      {
        if ((prev == 0xFA) && (ctx->rx[j] == 0xAB)) return ftdi_drain (ctx);

        prev = ctx->rx[j];
      }
    }
  }

  fprintf (stderr, "ftdi: MPSSE did not answer a bad command\n");

  return false;
}

#else

bool ftdi_open (ftdi_ctx_t *ctx, const u16 vid, const u16 pid, const char *serial)
{
  (void) ctx;
  (void) vid;
  (void) pid;
  (void) serial;

  return false;
}

bool ftdi_open_busdev (ftdi_ctx_t *ctx, const u16 vid, const u16 pid, const u32 busnum, const u32 devnum)
{
  (void) ctx;
  (void) vid;
  (void) pid;
  (void) busnum;
  (void) devnum;

  return false;
}

int ftdi_read_some (ftdi_ctx_t *ctx, u8 *buf, const size_t max, const u32 timeout_ms)
{
  (void) ctx;
  (void) buf;
  (void) max;
  (void) timeout_ms;

  return -1;
}

bool ftdi_open_port (ftdi_ctx_t *ctx, const u16 vid, const u16 pid, const char *port)
{
  (void) ctx;
  (void) vid;
  (void) pid;
  (void) port;

  return false;
}

bool ftdi_mpsse_enable_jtag (ftdi_ctx_t *ctx, const u32 tck_hz)
{
  (void) ctx;
  (void) tck_hz;

  return false;
}

void ftdi_close (ftdi_ctx_t *ctx)
{
  (void) ctx;
}

bool ftdi_mpsse_enable (ftdi_ctx_t *ctx, const u32 tck_hz)
{
  (void) ctx;
  (void) tck_hz;

  return false;
}

bool ftdi_mpsse_sync (ftdi_ctx_t *ctx)
{
  (void) ctx;

  return false;
}

bool ftdi_write (ftdi_ctx_t *ctx, const u8 *buf, const size_t len)
{
  (void) ctx;
  (void) buf;
  (void) len;

  return false;
}

bool ftdi_read (ftdi_ctx_t *ctx, u8 *buf, const size_t len)
{
  (void) ctx;
  (void) buf;
  (void) len;

  return false;
}

#endif
