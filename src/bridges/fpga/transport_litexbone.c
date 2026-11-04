/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"
#include "thread.h"

#include "fpga/hcfpga.h"

#include <stdio.h>
#include <string.h>

static bool LXB_TRIED = false;

bool fpga_transport_litexbone_tried (void)
{
  return LXB_TRIED;
}

#if defined (__linux__)

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

// A LiteX board without PCIe: hashcat's bcrypt wrapper sits behind HcfpgaMemStream, two rings in CSR
// space, and every access goes over a LiteX bus bridge. Etherbone over UDP, or UARTBone over a
// serial port or a TCP connection to one. Boards are listed in --bridge-parameter1, as
// udp:HOST[:PORT], uart:DEVICE[:BAUD] or tcp:HOST:PORT[:BAUD], separated by commas or spaces.

#define LXB_SEPARATORS      ", \t\r\n"

#define LXB_UDP_PORT        1234
#define LXB_UART_BAUD       115200

// ser2net does not say what rate it runs the port at, so bursts are sized for the slowest one in use

#define LXB_TCP_BAUD        9600

#define LXB_BAUD_MIN        1200
#define LXB_BAUD_MAX        12000000

#define LXB_SCRATCH_VALUE   0x12345678

// memstream is pinned at CSR locations 24, 25 and 26 with 0x800 paging, above everything the
// PCIe boards use

#define LXB_MS_CTRL         0xc000
#define LXB_MS_INFO         0xc004
#define LXB_MS_H2C_WR       0xc008
#define LXB_MS_C2H_RD       0xc00c
#define LXB_MS_H2C_RD       0xc010
#define LXB_MS_C2H_WR       0xc014
#define LXB_MS_H2C_MEM      0xc800
#define LXB_MS_C2H_MEM      0xd000

#define LXB_MS_DEPTH_MIN    16
#define LXB_MS_DEPTH_MAX    512
#define LXB_PTR_MASK        0xffff

#define LXB_EB_HDR_BYTES    8
#define LXB_EB_REC_BYTES    4

// An Etherbone record holds its base address and up to 15 words, which is what a buffer_depth of 16,
// LiteX's default, carries in every LiteEth release. LiteEth up to 2026.08 waits for a longer record
// forever, later versions drop it. Writes and reads never share a record: up to 2026.08 a read after
// writes in one record takes the return address for its first read address.

#define LXB_EB_WORDS        15
#define LXB_EB_PROBE_TRIES  2

#define LXB_UB_CMD_WRITE    0x01
#define LXB_UB_CMD_READ     0x02
#define LXB_UB_HDR_BYTES    6
#define LXB_UB_BURST_MAX    255

// UARTBone abandons a command 100 ms after its first byte. A burst gets half of that on the wire,
// and resynchronising waits it out twice.

#define LXB_UB_BURST_MS     50
#define LXB_UB_RESYNC_MS    200
#define LXB_UB_QUIET_MS     20
#define LXB_UB_TRIES        3

#define LXB_REPLY_MS        500
#define LXB_TRIES           6
#define LXB_CONNECT_MS      2000

#define LXB_IDLE_MS         1
#define LXB_WAIT_MS_DEFAULT 30000

#define LXB_OUT_BYTES       (256 * 1024)

#define LXB_HOST_MAX        1024
#define LXB_PATH_MAX        (LXB_HOST_MAX + 64)
#define LXB_IDENT_CHUNK     16

typedef enum lxb_link
{
  LXB_LINK_UDP  = 0,
  LXB_LINK_UART = 1,
  LXB_LINK_TCP  = 2,

} lxb_link_t;

// What a write is checked against once the words read back: ACK only waits for the read, RETRY
// rewrites a register that reads back different and accepts it in the end, STRICT fails.

typedef enum lxb_check
{
  LXB_CHECK_ACK    = 0,
  LXB_CHECK_RETRY  = 1,
  LXB_CHECK_STRICT = 2,

} lxb_check_t;

typedef struct lxb_priv
{
  lxb_link_t link;

  char  host[LXB_HOST_MAX];
  u32   port;
  u32   baud;
  bool  baud_given;

  int   fd;
  bool  busy;

  char  why[160];

  hc_thread_mutex_t mux;

  u32   tag;

  u32   burst;

  bool  in_session;

  u32   h2c_depth;
  u32   c2h_depth;

  u32   h2c_wr;
  u32   c2h_rd;

  u32   grain;
  u32   want;
  bool  done;
  u32   processed;
  bool  lost;

  u8   *pend;
  u64   pend_size;
  u64   pend_head;
  u64   pend_tail;

} lxb_priv_t;

static void lxb_sleep_ms (const u32 ms)
{
  struct timespec ts;

  ts.tv_sec  = ms / 1000;
  ts.tv_nsec = (long) (ms % 1000) * 1000000;

  nanosleep (&ts, NULL);
}

static u64 lxb_now_ms (void)
{
  const u64 ms = fpga_now_ns () / 1000000;

  return ms;
}

static void lxb_put32 (u8 *p, const u32 v)
{
  p[0] = (u8) (v >> 24);
  p[1] = (u8) (v >> 16);
  p[2] = (u8) (v >>  8);
  p[3] = (u8) (v >>  0);
}

static u32 lxb_get32 (const u8 *p)
{
  const u32 v = ((u32) p[0] << 24) | ((u32) p[1] << 16) | ((u32) p[2] << 8) | ((u32) p[3] << 0);

  return v;
}

static bool lxb_wait_in (const int fd, const u32 ms)
{
  struct pollfd pfd;

  pfd.fd      = fd;
  pfd.events  = POLLIN;
  pfd.revents = 0;

  const int rc = poll (&pfd, 1, (int) ms);

  if (rc <= 0) return false;

  if ((pfd.revents & POLLIN) == 0) return false;

  return true;
}

// hashcat does not ignore SIGPIPE, so a peer that hung up must not raise it

static bool lxb_send_all (const lxb_priv_t *priv, const u8 *buf, const size_t len)
{
  size_t done = 0;

  while (done < len)
  {
    const ssize_t n = (priv->link == LXB_LINK_UART) ? write (priv->fd, &buf[done], len - done) : send (priv->fd, &buf[done], len - done, MSG_NOSIGNAL);

    if ((n < 0) && (errno == EINTR)) continue;

    if (n <= 0) return false;

    done += (size_t) n;
  }

  return true;
}

static bool lxb_recv_exact (const int fd, u8 *buf, const size_t len, const u32 ms)
{
  const u64 deadline = lxb_now_ms () + ms;

  size_t done = 0;

  while (done < len)
  {
    const u64 now = lxb_now_ms ();

    if (now >= deadline) return false;

    if (lxb_wait_in (fd, (u32) (deadline - now)) == false) return false;

    const ssize_t n = read (fd, &buf[done], len - done);

    if ((n < 0) && (errno == EINTR)) continue;

    if (n <= 0) return false;

    done += (size_t) n;
  }

  return true;
}

static void lxb_drain (lxb_priv_t *priv)
{
  if (priv->fd < 0) return;

  if (priv->link == LXB_LINK_UART)
  {
    tcflush (priv->fd, TCIFLUSH);

    return;
  }

  u8 buf[2048];

  while (lxb_wait_in (priv->fd, 0) == true)
  {
    if (read (priv->fd, buf, sizeof (buf)) <= 0) break;
  }
}

// Etherbone

static void eb_header (u8 *req, const u32 wcount, const u32 rcount)
{
  memset (req, 0, LXB_EB_HDR_BYTES);

  req[0] = 0x4e;
  req[1] = 0x6f;
  req[2] = 0x10;
  req[3] = 0x44;

  req[ 8] = 0x00;
  req[ 9] = 0x0f;
  req[10] = (u8) wcount;
  req[11] = (u8) rcount;
}

static bool eb_send (lxb_priv_t *priv, const u8 *req, const u32 len)
{
  for (u32 attempt = 0; attempt < LXB_TRIES; attempt++)
  {
    if (send (priv->fd, req, len, MSG_NOSIGNAL) == (ssize_t) len) return true;

    // a connected UDP socket reports an earlier ICMP port unreachable on the next send

    if ((errno != ECONNREFUSED) && (errno != EINTR)) return false;

    lxb_sleep_ms (LXB_REPLY_MS / 10);
  }

  return false;
}

static bool eb_write (lxb_priv_t *priv, const u32 addr, const u32 *wr, const u32 n)
{
  u8 req[LXB_EB_HDR_BYTES + LXB_EB_REC_BYTES + 4 + (LXB_EB_WORDS * 4)];

  eb_header (req, n, 0);

  u32 off = LXB_EB_HDR_BYTES + LXB_EB_REC_BYTES;

  lxb_put32 (&req[off], addr);

  off += 4;

  for (u32 i = 0; i < n; i++)
  {
    lxb_put32 (&req[off], wr[i]);

    off += 4;
  }

  const bool ok = eb_send (priv, req, off);

  return ok;
}

static bool eb_read (lxb_priv_t *priv, const u32 addr, u32 *rd, const u32 n, const u32 tries)
{
  u8 req[LXB_EB_HDR_BYTES + LXB_EB_REC_BYTES + 4 + (LXB_EB_WORDS * 4)];

  eb_header (req, 0, n);

  priv->tag++;

  const u32 tag = priv->tag;

  u32 off = LXB_EB_HDR_BYTES + LXB_EB_REC_BYTES;

  lxb_put32 (&req[off], tag);

  off += 4;

  for (u32 i = 0; i < n; i++)
  {
    lxb_put32 (&req[off], addr + (i * 4));

    off += 4;
  }

  const u32 want = LXB_EB_HDR_BYTES + LXB_EB_REC_BYTES + 4 + (n * 4);

  for (u32 attempt = 0; attempt < tries; attempt++)
  {
    if (eb_send (priv, req, off) == false) return false;

    const u64 deadline = lxb_now_ms () + LXB_REPLY_MS;

    for (;;)
    {
      const u64 now = lxb_now_ms ();

      if (now >= deadline) break;

      if (lxb_wait_in (priv->fd, (u32) (deadline - now)) == false) break;

      u8 rep[2048];

      const ssize_t got = recv (priv->fd, rep, sizeof (rep), 0);

      if (got < (ssize_t) want) continue;

      if ((rep[0] != 0x4e) || (rep[1] != 0x6f)) continue;

      if (rep[10] != n) continue;

      // a late answer to an earlier request carries an older tag

      if (lxb_get32 (&rep[LXB_EB_HDR_BYTES + LXB_EB_REC_BYTES]) != tag) continue;

      for (u32 i = 0; i < n; i++) rd[i] = lxb_get32 (&rep[LXB_EB_HDR_BYTES + LXB_EB_REC_BYTES + 4 + (i * 4)]);

      return true;
    }
  }

  return false;
}

// The largest read the board answers, 0 once it answers nothing. Records that are too long are dropped
// by current LiteEth, and stall LiteEth up to 2026.08 until the board is reset.

static u32 eb_probe_words (lxb_priv_t *priv)
{
  for (u32 n = LXB_EB_WORDS; n >= 1; n /= 2)
  {
    u32 words[LXB_EB_WORDS];

    if (eb_read (priv, fpga_csr_map_no_cpu.base + fpga_csr_map_no_cpu.identifier_mem, words, n, LXB_EB_PROBE_TRIES) == true) return n;
  }

  return 0;
}

// UARTBone

static bool ub_read_once (lxb_priv_t *priv, const u32 addr, u32 *rd, const u32 n)
{
  u8 cmd[LXB_UB_HDR_BYTES];

  cmd[0] = LXB_UB_CMD_READ;
  cmd[1] = (u8) n;

  lxb_put32 (&cmd[2], addr >> 2);

  if (lxb_send_all (priv, cmd, sizeof (cmd)) == false) return false;

  u8 buf[LXB_UB_BURST_MAX * 4];

  const u32 ms = LXB_REPLY_MS + (u32) (((u64) n * 4 * 10 * 1000) / priv->baud);

  if (lxb_recv_exact (priv->fd, buf, n * 4, ms) == false) return false;

  for (u32 i = 0; i < n; i++) rd[i] = lxb_get32 (&buf[i * 4]);

  return true;
}

static bool ub_write_once (lxb_priv_t *priv, const u32 addr, const u32 *wr, const u32 n)
{
  u8 buf[LXB_UB_HDR_BYTES + (LXB_UB_BURST_MAX * 4)];

  buf[0] = LXB_UB_CMD_WRITE;
  buf[1] = (u8) n;

  lxb_put32 (&buf[2], addr >> 2);

  for (u32 i = 0; i < n; i++) lxb_put32 (&buf[LXB_UB_HDR_BYTES + (i * 4)], wr[i]);

  const bool ok = lxb_send_all (priv, buf, LXB_UB_HDR_BYTES + (n * 4));

  return ok;
}

// Wait out UARTBone's command timeout, then read the scratch register until it answers with its
// value and nothing follows: a late answer to an earlier read would otherwise shift every later one.

static bool ub_sync (lxb_priv_t *priv)
{
  if (priv->fd < 0) return false;

  for (u32 attempt = 0; attempt < LXB_UB_TRIES; attempt++)
  {
    lxb_sleep_ms (LXB_UB_RESYNC_MS);

    lxb_drain (priv);

    u32 scratch = 0;

    if (ub_read_once (priv, fpga_csr_map_no_cpu.base + fpga_csr_map_no_cpu.scratch, &scratch, 1) == false) continue;

    if (lxb_wait_in (priv->fd, LXB_UB_QUIET_MS) == true) continue;

    if (scratch == LXB_SCRATCH_VALUE) return true;
  }

  return false;
}

// UARTBone has no tags and does not answer writes, so after a lost or late byte nothing already sent
// can be trusted. During a session the batch fails instead, and the bridge restarts the board and
// writes its configuration again.

static bool ub_recover (lxb_priv_t *priv)
{
  const bool synced = ub_sync (priv);

  if (priv->in_session == true)
  {
    priv->lost = true;

    return false;
  }

  return synced;
}

// Either bridge

static bool lxb_read_chunk (lxb_priv_t *priv, const u32 addr, u32 *rd, const u32 n)
{
  if (priv->link == LXB_LINK_UDP)
  {
    const bool ok = eb_read (priv, addr, rd, n, LXB_TRIES);

    return ok;
  }

  const bool ok = ub_read_once (priv, addr, rd, n);

  return ok;
}

static bool lxb_read (lxb_priv_t *priv, const u32 addr, u32 *rd, const u32 n)
{
  if (priv->fd < 0) return false;

  bool ok = true;

  hc_thread_mutex_lock (priv->mux);

  for (u32 done = 0; done < n; )
  {
    const u32 len = MIN (n - done, priv->burst);

    for (u32 attempt = 0; attempt < LXB_UB_TRIES; attempt++)
    {
      ok = lxb_read_chunk (priv, addr + (done * 4), &rd[done], len);

      if (ok == true) break;

      if (priv->link == LXB_LINK_UDP) break;

      if (ub_recover (priv) == false) break;
    }

    if (ok == false) break;

    done += len;
  }

  hc_thread_mutex_unlock (priv->mux);

  return ok;
}

// One write burst, then a read of what it wrote. Neither bridge answers a write, and the read
// is what tells that it arrived: a lost datagram reads back the old words, a lost byte shifts the
// UARTBone stream so that the read does not come back.

static bool lxb_write_chunk (lxb_priv_t *priv, const u32 addr, const u32 *wr, const u32 n, const lxb_check_t check)
{
  const bool udp = (priv->link == LXB_LINK_UDP);

  const u32 back_cnt  = (check == LXB_CHECK_ACK) ? 1 : n;
  const u32 back_addr = (check == LXB_CHECK_ACK) ? addr + ((n - 1) * 4) : addr;

  bool answered = false;

  for (u32 attempt = 0; attempt < LXB_TRIES; attempt++)
  {
    const bool sent = (udp == true) ? eb_write (priv, addr, wr, n) : ub_write_once (priv, addr, wr, n);

    u32 back[LXB_UB_BURST_MAX];

    const bool got = (sent == true) ? lxb_read_chunk (priv, back_addr, back, back_cnt) : false;

    if (got == false)
    {
      if (udp == true) return false;

      if (ub_recover (priv) == false) return false;

      continue;
    }

    answered = true;

    if (check == LXB_CHECK_ACK) return true;

    if (memcmp (back, wr, n * 4) == 0) return true;

    if ((udp == false) && (check == LXB_CHECK_STRICT))
    {
      if (ub_recover (priv) == false) return false;
    }
  }

  const bool ok = ((check == LXB_CHECK_RETRY) && (answered == true));

  return ok;
}

static bool lxb_write (lxb_priv_t *priv, const u32 addr, const u32 *wr, const u32 n, const lxb_check_t check)
{
  if (priv->fd < 0) return false;

  bool ok = true;

  hc_thread_mutex_lock (priv->mux);

  for (u32 done = 0; done < n; )
  {
    const u32 len = MIN (n - done, priv->burst);

    ok = lxb_write_chunk (priv, addr + (done * 4), &wr[done], len, check);

    if (ok == false) break;

    done += len;
  }

  hc_thread_mutex_unlock (priv->mux);

  return ok;
}

static bool lxb_read1 (lxb_priv_t *priv, const u32 addr, u32 *val)
{
  const bool ok = lxb_read (priv, addr, val, 1);

  return ok;
}

static bool lxb_write1 (lxb_priv_t *priv, const u32 addr, const u32 val, const lxb_check_t check)
{
  const bool ok = lxb_write (priv, addr, &val, 1, check);

  return ok;
}

// Links

typedef struct lxb_speed
{
  u32     baud;
  speed_t speed;

} lxb_speed_t;

static const lxb_speed_t LXB_SPEEDS[] =
{
  {    9600, B9600    },
  {   19200, B19200   },
  {   38400, B38400   },
  {   57600, B57600   },
  {  115200, B115200  },
  {  230400, B230400  },
  {  460800, B460800  },
  {  500000, B500000  },
  {  921600, B921600  },
  { 1000000, B1000000 },
  { 1500000, B1500000 },
  { 2000000, B2000000 },
  { 3000000, B3000000 },
};

static bool lxb_speed_find (const u32 baud, speed_t *speed)
{
  const size_t cnt = sizeof (LXB_SPEEDS) / sizeof (LXB_SPEEDS[0]);

  for (size_t i = 0; i < cnt; i++)
  {
    if (LXB_SPEEDS[i].baud != baud) continue;

    *speed = LXB_SPEEDS[i].speed;

    return true;
  }

  return false;
}

static int lxb_open_uart (lxb_priv_t *priv)
{
  speed_t speed = B115200;

  lxb_speed_find (priv->baud, &speed);

  const int fd = open (priv->host, O_RDWR | O_NOCTTY | O_NONBLOCK);

  if (fd < 0)
  {
    // another process holds the port with TIOCEXCL

    if (errno == EBUSY) priv->busy = true;

    snprintf (priv->why, sizeof (priv->why), "%s", strerror (errno));

    return -1;
  }

  // a second hashcat, or a terminal program, would interleave its bytes with ours

  if (flock (fd, LOCK_EX | LOCK_NB) != 0)
  {
    priv->busy = true;

    snprintf (priv->why, sizeof (priv->why), "%s", strerror (errno));

    close (fd);

    return -1;
  }

  ioctl (fd, TIOCEXCL);

  struct termios tio;

  if (tcgetattr (fd, &tio) < 0)
  {
    snprintf (priv->why, sizeof (priv->why), "%s", strerror (errno));

    close (fd);

    return -1;
  }

  cfmakeraw (&tio);

  tio.c_cflag |= CLOCAL | CREAD;
  tio.c_cflag &= ~CRTSCTS;

  tio.c_cc[VMIN]  = 0;
  tio.c_cc[VTIME] = 0;

  cfsetispeed (&tio, speed);
  cfsetospeed (&tio, speed);

  if (tcsetattr (fd, TCSANOW, &tio) < 0)
  {
    snprintf (priv->why, sizeof (priv->why), "%s", strerror (errno));

    close (fd);

    return -1;
  }

  const int flags = fcntl (fd, F_GETFL);

  fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);

  tcflush (fd, TCIOFLUSH);

  return fd;
}

static int lxb_open_inet (lxb_priv_t *priv, const int socktype)
{
  struct addrinfo hints;

  memset (&hints, 0, sizeof (hints));

  hints.ai_family   = AF_INET;
  hints.ai_socktype = socktype;

  char port[16];

  snprintf (port, sizeof (port), "%u", priv->port);

  struct addrinfo *res = NULL;

  const int gai = getaddrinfo (priv->host, port, &hints, &res);

  if (gai != 0)
  {
    snprintf (priv->why, sizeof (priv->why), "%s", gai_strerror (gai));

    return -1;
  }

  const int fd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);

  if (fd < 0)
  {
    snprintf (priv->why, sizeof (priv->why), "%s", strerror (errno));

    freeaddrinfo (res);

    return -1;
  }

  const int flags = fcntl (fd, F_GETFL);

  fcntl (fd, F_SETFL, flags | O_NONBLOCK);

  int rc = connect (fd, res->ai_addr, res->ai_addrlen);

  int err = (rc < 0) ? errno : 0;

  freeaddrinfo (res);

  if (err == EINPROGRESS)
  {
    struct pollfd pfd;

    pfd.fd      = fd;
    pfd.events  = POLLOUT;
    pfd.revents = 0;

    err = ETIMEDOUT;

    if (poll (&pfd, 1, LXB_CONNECT_MS) > 0)
    {
      socklen_t len = sizeof (err);

      getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &len);
    }
  }

  if (err != 0)
  {
    snprintf (priv->why, sizeof (priv->why), "%s", strerror (err));

    close (fd);

    return -1;
  }

  fcntl (fd, F_SETFL, flags);

  if (socktype == SOCK_STREAM)
  {
    const int one = 1;

    setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
  }

  return fd;
}

static u32 lxb_ub_burst (const u32 baud)
{
  const u32 bytes = (u32) (((u64) baud * LXB_UB_BURST_MS) / (10 * 1000));

  if (bytes < (LXB_UB_HDR_BYTES + 4)) return 1;

  const u32 words = (bytes - LXB_UB_HDR_BYTES) / 4;

  const u32 burst = MIN (words, (u32) LXB_UB_BURST_MAX);

  return burst;
}

static bool lxb_link_open (lxb_priv_t *priv)
{
  switch (priv->link)
  {
    case LXB_LINK_UDP:
      priv->fd    = lxb_open_inet (priv, SOCK_DGRAM);
      priv->burst = LXB_EB_WORDS;
      break;

    case LXB_LINK_UART:
      priv->fd    = lxb_open_uart (priv);
      priv->burst = lxb_ub_burst (priv->baud);
      break;

    case LXB_LINK_TCP:
      priv->fd    = lxb_open_inet (priv, SOCK_STREAM);
      priv->burst = lxb_ub_burst (priv->baud);
      break;
  }

  if (priv->fd < 0) return false;

  return true;
}

// udp:HOST[:PORT], uart:DEVICE[:BAUD], tcp:HOST:PORT[:BAUD]. A device path may hold colons of its own,
// so only trailing all-digit fields are taken for numbers.

static bool lxb_parse (const char *spec, lxb_priv_t *priv)
{
  const char *colon = strchr (spec, ':');

  if (colon == NULL) return false;

  const size_t kind_len = (size_t) (colon - spec);

  if      ((kind_len == 3) && (strncmp (spec, "udp",  3) == 0)) priv->link = LXB_LINK_UDP;
  else if ((kind_len == 4) && (strncmp (spec, "uart", 4) == 0)) priv->link = LXB_LINK_UART;
  else if ((kind_len == 3) && (strncmp (spec, "tcp",  3) == 0)) priv->link = LXB_LINK_TCP;
  else return false;

  const char *rest = &colon[1];

  size_t host_len = strlen (rest);

  const u32 nums_max = (priv->link == LXB_LINK_TCP) ? 2 : 1;

  u32 nums[2] = { 0, 0 };

  u32 nums_cnt = 0;

  while (nums_cnt < nums_max)
  {
    const char *last = NULL;

    for (size_t i = 0; i < host_len; i++)
    {
      if (rest[i] == ':') last = &rest[i];
    }

    if (last == NULL) break;

    const size_t digits = host_len - (size_t) (last - rest) - 1;

    if ((digits == 0) || (digits > 9)) break;

    if (strspn (&last[1], "0123456789") < digits) break;

    nums[nums_cnt] = (u32) strtoul (&last[1], NULL, 10);

    nums_cnt++;

    host_len = (size_t) (last - rest);
  }

  if (host_len == 0) return false;

  if (host_len >= sizeof (priv->host)) return false;

  memcpy (priv->host, rest, host_len);

  priv->host[host_len] = 0;

  priv->port       = 0;
  priv->baud       = LXB_UART_BAUD;
  priv->baud_given = false;

  if (priv->link == LXB_LINK_UDP)
  {
    priv->port = (nums_cnt == 1) ? nums[0] : LXB_UDP_PORT;
  }
  else if (priv->link == LXB_LINK_UART)
  {
    if (nums_cnt == 1) priv->baud = nums[0];

    speed_t speed = B115200;

    if (lxb_speed_find (priv->baud, &speed) == false) return false;
  }
  else
  {
    if (nums_cnt == 0) return false;

    priv->port = (nums_cnt == 2) ? nums[1] : nums[0];
    priv->baud = (nums_cnt == 2) ? nums[0] : LXB_TCP_BAUD;

    priv->baud_given = (nums_cnt == 2);

    if ((priv->baud < LXB_BAUD_MIN) || (priv->baud > LXB_BAUD_MAX)) return false;
  }

  if ((priv->link != LXB_LINK_UART) && ((priv->port == 0) || (priv->port > 65535))) return false;

  return true;
}

static void lxb_describe (const lxb_priv_t *priv, char *buf, const size_t len)
{
  switch (priv->link)
  {
    case LXB_LINK_UDP:  snprintf (buf, len, "udp:%s:%u",  priv->host, priv->port); break;
    case LXB_LINK_UART: snprintf (buf, len, "uart:%s:%u", priv->host, priv->baud); break;

    case LXB_LINK_TCP:

      if (priv->baud_given == true)
      {
        snprintf (buf, len, "tcp:%s:%u:%u", priv->host, priv->port, priv->baud);
        break;
      }

      snprintf (buf, len, "tcp:%s:%u", priv->host, priv->port);
      break;
  }
}

static void lxb_free (lxb_priv_t *priv)
{
  if (priv == NULL) return;

  if (priv->fd >= 0) close (priv->fd);

  hcfree (priv->pend);

  hc_thread_mutex_delete (priv->mux);

  hcfree (priv);
}

// Transport

static int lxb_enumerate (hashcat_ctx_t *hashcat_ctx, fpga_dev_t *devs, const int max, fpga_status_t *status)
{
  *status = FPGA_STATUS_NO_PCI_DEVICE;

  const user_options_t *user_options = hashcat_ctx->user_options;

  // the bench tools enumerate with a context that has no user options

  if (user_options == NULL) return 0;

  if (user_options->bridge_parameter1 == NULL) return 0;

  char *list = hcstrdup (user_options->bridge_parameter1);

  if (list == NULL) return 0;

  char *seen = (char *) hccalloc (FPGA_MAX_DEVICES, LXB_PATH_MAX);

  if (seen == NULL)
  {
    hcfree (list);

    return 0;
  }

  int seen_cnt = 0;

  int cnt = 0;

  char *saveptr = NULL;

  for (char *spec = strtok_r (list, LXB_SEPARATORS, &saveptr); spec != NULL; spec = strtok_r (NULL, LXB_SEPARATORS, &saveptr))
  {
    if (cnt >= max) break;

    if (seen_cnt >= FPGA_MAX_DEVICES) break;

    lxb_priv_t *priv = (lxb_priv_t *) hccalloc (1, sizeof (lxb_priv_t));

    if (priv == NULL) break;

    priv->fd = -1;

    hc_thread_mutex_init (priv->mux);

    if (lxb_parse (spec, priv) == false)
    {
      event_log_warning (hashcat_ctx, "FPGA bridge: --bridge-parameter1 entry '%s' is not udp:HOST[:PORT], uart:DEVICE[:BAUD] or tcp:HOST:PORT[:BAUD] with a supported baud rate, and is ignored.", spec);

      lxb_free (priv);

      continue;
    }

    char *path = &seen[seen_cnt * LXB_PATH_MAX];

    lxb_describe (priv, path, LXB_PATH_MAX);

    bool dup = false;

    for (int i = 0; i < seen_cnt; i++)
    {
      if (strcmp (&seen[i * LXB_PATH_MAX], path) == 0) dup = true;
    }

    if (dup == true)
    {
      event_log_warning (hashcat_ctx, "FPGA bridge: --bridge-parameter1 lists %s twice. The second entry is ignored.", path);

      lxb_free (priv);

      continue;
    }

    seen_cnt++;

    LXB_TRIED = true;

    const bool opened = lxb_link_open (priv);

    if ((opened == false) && (priv->busy == false))
    {
      event_log_error (hashcat_ctx, "FPGA bridge: cannot open %s: %s.", path, priv->why);

      if ((priv->link == LXB_LINK_UART) && (access (priv->host, R_OK | W_OK) != 0) && (errno == EACCES))
      {
        event_log_info (hashcat_ctx, "Add this account to the group that owns %s, usually dialout, then log in again.", priv->host);
        event_log_info (hashcat_ctx, NULL);
      }

      lxb_free (priv);

      continue;
    }

    // a port held by another process is not probed: its bytes would land in that process's stream

    if (opened == true)
    {
      u32 scratch = 0;

      if (lxb_read1 (priv, fpga_csr_map_no_cpu.base + fpga_csr_map_no_cpu.scratch, &scratch) == false)
      {
        event_log_error (hashcat_ctx, "FPGA bridge: nothing answered at %s.", path);

        if (priv->link == LXB_LINK_UDP)
        {
          event_log_info (hashcat_ctx, "Check the address and port, that this host routes to it, and that the board is programmed.");
        }
        else
        {
          event_log_info (hashcat_ctx, "Check that the board is programmed and that the baud rate matches the one it was built with.");
        }

        event_log_info (hashcat_ctx, NULL);

        lxb_free (priv);

        continue;
      }

      if (priv->link == LXB_LINK_UDP)
      {
        const u32 words = eb_probe_words (priv);

        if (words == 0)
        {
          event_log_error (hashcat_ctx, "FPGA bridge: %s stopped answering after a %u word Etherbone read.", path, (u32) LXB_EB_WORDS);
          event_log_info (hashcat_ctx, "Its etherbone buffer_depth is below 16, and LiteEth up to 2026.08 stalls on a longer record until reset.");
          event_log_info (hashcat_ctx, "Rebuild the SoC with a buffer_depth of 16 or more, LiteX's default, and reset the board.");
          event_log_info (hashcat_ctx, NULL);

          lxb_free (priv);

          continue;
        }

        if (words < LXB_EB_WORDS)
        {
          event_log_warning (hashcat_ctx, "FPGA bridge: %s answers Etherbone records of up to %u words only. Its buffer_depth is below 16, which slows it down.", path, words);
        }

        priv->burst = words;
      }
    }

    fpga_dev_t *dev = &devs[cnt];

    memset (dev, 0, sizeof (fpga_dev_t));

    snprintf (dev->path, sizeof (dev->path), "%s", path);

    dev->fd   = -1;
    dev->priv = priv;

    cnt++;
  }

  hcfree (seen);
  hcfree (list);

  if (cnt > 0) *status = FPGA_STATUS_OK;

  return cnt;
}

static void lxb_close (fpga_dev_t *dev)
{
  lxb_free ((lxb_priv_t *) dev->priv);

  dev->priv = NULL;
}

// a board that -d leaves out gives its port back, so another hashcat can use it

static void lxb_release (fpga_dev_t *dev)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (priv == NULL) return;

  priv->in_session = false;

  if (priv->fd >= 0) close (priv->fd);

  priv->fd = -1;

  hcfree (priv->pend);

  priv->pend      = NULL;
  priv->pend_size = 0;
}

static fpga_status_t lxb_identify (fpga_dev_t *dev)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (priv == NULL) return FPGA_STATUS_NO_PCI_DEVICE;

  if (priv->busy == true) return FPGA_STATUS_IN_USE;

  u32 scratch = 0;

  if (lxb_read1 (priv, dev->csr_base + dev->map->scratch, &scratch) == false) return FPGA_STATUS_NO_PCI_DEVICE;

  if (scratch != LXB_SCRATCH_VALUE) return FPGA_STATUS_BAD_IDENT;

  char raw[FPGA_IDENT_MAX];

  u32 len = 0;

  while (len < (FPGA_IDENT_MAX - 1))
  {
    u32 words[LXB_IDENT_CHUNK];

    const u32 n = MIN ((u32) LXB_IDENT_CHUNK, (u32) (FPGA_IDENT_MAX - 1) - len);

    if (lxb_read (priv, dev->csr_base + dev->map->identifier_mem + (len * 4), words, n) == false) return FPGA_STATUS_NO_PCI_DEVICE;

    u32 i = 0;

    for (i = 0; i < n; i++)
    {
      const u32 c = words[i] & 0xff;

      if (c == 0) break;

      raw[len + i] = (char) c;
    }

    len += i;

    if (i < n) break;
  }

  raw[len] = 0;

  if (fpga_ident_parse (raw, &dev->ident) == false) return FPGA_STATUS_BAD_IDENT;

  u32 info = 0;

  if (lxb_read1 (priv, dev->csr_base + LXB_MS_INFO, &info) == false) return FPGA_STATUS_NO_PCI_DEVICE;

  const u32 h2c_depth = (info >>  0) & 0xffff;
  const u32 c2h_depth = (info >> 16) & 0xffff;

  const bool h2c_ok = ((h2c_depth >= LXB_MS_DEPTH_MIN) && (h2c_depth <= LXB_MS_DEPTH_MAX) && ((h2c_depth & (h2c_depth - 1)) == 0));
  const bool c2h_ok = ((c2h_depth >= LXB_MS_DEPTH_MIN) && (c2h_depth <= LXB_MS_DEPTH_MAX) && ((c2h_depth & (c2h_depth - 1)) == 0));

  if (getenv ("HCFPGA_DEBUG") != NULL)
  {
    fprintf (stderr, "[hcfpga] %s memstream h2c %u words, c2h %u words, bursts of %u words\n", dev->path, h2c_depth, c2h_depth, priv->burst);
  }

  // a design without memstream at its pinned location cannot take candidates over this transport

  if ((h2c_ok == false) || (c2h_ok == false)) return FPGA_STATUS_BAD_IDENT;

  priv->h2c_depth = h2c_depth;
  priv->c2h_depth = c2h_depth;

  return FPGA_STATUS_OK;
}

static u32 lxb_csr_read (fpga_dev_t *dev, const u32 addr)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (priv == NULL) return 0;

  u32 val = 0;

  if (lxb_read1 (priv, dev->csr_base + addr, &val) == false) return 0;

  return val;
}

static bool lxb_csr_write (fpga_dev_t *dev, const u32 addr, const u32 val)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (priv == NULL) return false;

  const bool ok = lxb_write1 (priv, dev->csr_base + addr, val, LXB_CHECK_RETRY);

  return ok;
}

static bool lxb_ms_reset (fpga_dev_t *dev)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (lxb_write1 (priv, dev->csr_base + LXB_MS_CTRL, 1, LXB_CHECK_ACK) == false) return false;

  u32 ptr[4];

  if (lxb_read (priv, dev->csr_base + LXB_MS_H2C_WR, ptr, 4) == false) return false;

  for (u32 i = 0; i < 4; i++)
  {
    if ((ptr[i] & LXB_PTR_MASK) != 0) return false;
  }

  priv->h2c_wr = 0;
  priv->c2h_rd = 0;

  return true;
}

static bool lxb_session_open (fpga_dev_t *dev)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (priv == NULL) return false;

  priv->lost       = false;
  priv->in_session = true;

  const bool ok = lxb_ms_reset (dev);

  if (ok == false) priv->in_session = false;

  return ok;
}

static void lxb_session_close (fpga_dev_t *dev)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (priv == NULL) return;

  priv->in_session = false;

  hcfree (priv->pend);

  priv->pend      = NULL;
  priv->pend_size = 0;
}

static bool lxb_session_refresh (fpga_dev_t *dev)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (priv == NULL) return false;

  priv->in_session = false;

  hc_thread_mutex_lock (priv->mux);

  bool synced = true;

  if (priv->link == LXB_LINK_UDP)
  {
    lxb_drain (priv);
  }
  else
  {
    synced = ub_sync (priv);
  }

  hc_thread_mutex_unlock (priv->mux);

  if (synced == false) return false;

  priv->lost       = false;
  priv->in_session = true;

  const bool ok = lxb_ms_reset (dev);

  return ok;
}

static u64 lxb_out_capacity (MAYBE_UNUSED fpga_dev_t *dev)
{
  return LXB_OUT_BYTES;
}

// Move what the C2H ring holds into the staging buffer and hand the ring space back. The device
// stalls on a full ring, so this runs while H2C is still going out as well.

static bool lxb_c2h_pull (fpga_dev_t *dev, const u32 c2h_wr, bool *moved)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  const u32 avail = (c2h_wr - priv->c2h_rd) & LXB_PTR_MASK;

  if (avail == 0) return true;

  if (avail > priv->c2h_depth) return false;

  if (priv->pend_head == priv->pend_tail)
  {
    priv->pend_head = 0;
    priv->pend_tail = 0;
  }

  if ((priv->pend_head > 0) && ((priv->pend_size - priv->pend_tail) < ((u64) avail * 4)))
  {
    memmove (priv->pend, &priv->pend[priv->pend_head], (size_t) (priv->pend_tail - priv->pend_head));

    priv->pend_tail -= priv->pend_head;
    priv->pend_head  = 0;
  }

  const u32 take = (u32) MIN ((priv->pend_size - priv->pend_tail) / 4, (u64) avail);

  if (take == 0) return true;

  u32 words[LXB_MS_DEPTH_MAX];

  for (u32 done = 0; done < take; )
  {
    const u32 idx = (priv->c2h_rd + done) % priv->c2h_depth;
    const u32 len = MIN (take - done, priv->c2h_depth - idx);

    if (lxb_read (priv, dev->csr_base + LXB_MS_C2H_MEM + (idx * 4), &words[done], len) == false) return false;

    done += len;
  }

  // the module packs the byte stream four to a word, first byte in bits 7..0

  for (u32 i = 0; i < take; i++)
  {
    u8 *p = &priv->pend[priv->pend_tail + (i * 4)];

    p[0] = (u8) (words[i] >>  0);
    p[1] = (u8) (words[i] >>  8);
    p[2] = (u8) (words[i] >> 16);
    p[3] = (u8) (words[i] >> 24);
  }

  priv->pend_tail += (u64) take * 4;

  priv->c2h_rd = (priv->c2h_rd + take) & LXB_PTR_MASK;

  if (lxb_write1 (priv, dev->csr_base + LXB_MS_C2H_RD, priv->c2h_rd, LXB_CHECK_STRICT) == false) return false;

  if (moved != NULL) *moved = true;

  return true;
}

static bool lxb_batch_begin (fpga_dev_t *dev, MAYBE_UNUSED const u64 out_bytes, const u64 in_bytes, const u32 in_grain, const u32 in_recs)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (priv == NULL) return false;

  if (in_grain == 0) return false;

  const u64 need = in_bytes + (LXB_MS_DEPTH_MAX * 4);

  if (priv->pend_size < need)
  {
    hcfree (priv->pend);

    priv->pend      = (u8 *) hcmalloc (need);
    priv->pend_size = (priv->pend == NULL) ? 0 : need;
  }

  if (priv->pend == NULL) return false;

  priv->pend_head = 0;
  priv->pend_tail = 0;

  priv->grain     = in_grain;
  priv->want      = in_recs;
  priv->done      = false;
  priv->processed = 0;
  priv->lost      = false;

  u32 ptr[4];

  if (lxb_read (priv, dev->csr_base + LXB_MS_H2C_WR, ptr, 4) == false) return false;

  priv->h2c_wr = ptr[0] & LXB_PTR_MASK;
  priv->c2h_rd = ptr[1] & LXB_PTR_MASK;

  const u32 c2h_wr = ptr[3] & LXB_PTR_MASK;

  // nothing of this batch has been sent yet, so whatever the ring holds is left from an earlier one

  if (c2h_wr == priv->c2h_rd) return true;

  priv->c2h_rd = c2h_wr;

  const bool ok = lxb_write1 (priv, dev->csr_base + LXB_MS_C2H_RD, priv->c2h_rd, LXB_CHECK_STRICT);

  return ok;
}

static bool lxb_h2c_put (fpga_dev_t *dev, const u8 *src, const u32 n)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  u32 words[LXB_MS_DEPTH_MAX];

  // the bytes in the order DMA would read them from host memory, the first one in bits 7..0

  for (u32 i = 0; i < n; i++)
  {
    const u8 *p = &src[i * 4];

    words[i] = ((u32) p[0] << 0) | ((u32) p[1] << 8) | ((u32) p[2] << 16) | ((u32) p[3] << 24);
  }

  for (u32 done = 0; done < n; )
  {
    const u32 idx = (priv->h2c_wr + done) % priv->h2c_depth;
    const u32 len = MIN (n - done, priv->h2c_depth - idx);

    if (lxb_write (priv, dev->csr_base + LXB_MS_H2C_MEM + (idx * 4), &words[done], len, LXB_CHECK_STRICT) == false) return false;

    done += len;
  }

  priv->h2c_wr = (priv->h2c_wr + n) & LXB_PTR_MASK;

  const bool ok = lxb_write1 (priv, dev->csr_base + LXB_MS_H2C_WR, priv->h2c_wr, LXB_CHECK_STRICT);

  return ok;
}

static bool lxb_batch_send (fpga_dev_t *dev, const void *src, const u64 bytes)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (priv == NULL) return false;

  if ((bytes % 4) != 0) return false;

  const u8 *in = (const u8 *) src;

  const u64 total = bytes / 4;

  const u64 wait_ms = (dev->batch_wait_ms > 0) ? dev->batch_wait_ms : LXB_WAIT_MS_DEFAULT;

  u64 sent = 0;

  u64 busy_ms = lxb_now_ms ();

  while (sent < total)
  {
    u32 ptr[2];

    if (lxb_read (priv, dev->csr_base + LXB_MS_H2C_RD, ptr, 2) == false) return false;

    const u32 h2c_rd = ptr[0] & LXB_PTR_MASK;
    const u32 c2h_wr = ptr[1] & LXB_PTR_MASK;

    bool moved = false;

    if (lxb_c2h_pull (dev, c2h_wr, &moved) == false) return false;

    const u32 used = (priv->h2c_wr - h2c_rd) & LXB_PTR_MASK;

    if (used > priv->h2c_depth) return false;

    const u32 n = (u32) MIN ((u64) (priv->h2c_depth - used), total - sent);

    if (n > 0)
    {
      if (lxb_h2c_put (dev, &in[sent * 4], n) == false) return false;

      sent += n;

      moved = true;
    }

    if (moved == true)
    {
      busy_ms = lxb_now_ms ();

      continue;
    }

    if ((lxb_now_ms () - busy_ms) > wait_ms) return false;

    lxb_sleep_ms (LXB_IDLE_MS);
  }

  return true;
}

static const void *lxb_batch_recv (fpga_dev_t *dev, u64 *bytes, const u32 timeout_ms)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  *bytes = 0;

  if (priv == NULL) return NULL;

  if (priv->lost == true) return NULL;

  if ((priv->pend_tail - priv->pend_head) < priv->grain)
  {
    u32 c2h_wr = 0;

    if ((lxb_read1 (priv, dev->csr_base + LXB_MS_C2H_WR, &c2h_wr) == false) || (lxb_c2h_pull (dev, c2h_wr & LXB_PTR_MASK, NULL) == false))
    {
      priv->lost = true;

      return NULL;
    }
  }

  const u64 have = priv->pend_tail - priv->pend_head;

  const u64 len = (have / priv->grain) * priv->grain;

  if (len == 0)
  {
    lxb_sleep_ms (timeout_ms);

    return NULL;
  }

  const u8 *buf = &priv->pend[priv->pend_head];

  priv->pend_head += len;

  u32 processed = 0;

  if ((priv->done == false) && (hcfpga_c2h_scan_eob (buf, len, priv->grain, priv->want, &processed) == true))
  {
    priv->done      = true;
    priv->processed = processed;
  }

  *bytes = len;

  return buf;
}

static void lxb_batch_end (fpga_dev_t *dev)
{
  lxb_priv_t *priv = (lxb_priv_t *) dev->priv;

  if (priv == NULL) return;

  priv->done      = false;
  priv->processed = 0;
}

static bool lxb_batch_done (fpga_dev_t *dev, u32 *processed)
{
  const lxb_priv_t *priv = (const lxb_priv_t *) dev->priv;

  if (priv == NULL) return false;

  if (priv->done == false) return false;

  if (processed != NULL) *processed = priv->processed;

  return true;
}

static bool lxb_batch_failed (fpga_dev_t *dev)
{
  const lxb_priv_t *priv = (const lxb_priv_t *) dev->priv;

  if (priv == NULL) return false;

  return priv->lost;
}

// The shared map puts a temperature sensor and the PCIe link status where this board may have
// nothing, and both would be read from the status thread while a batch holds the link.

static int lxb_temperature (MAYBE_UNUSED fpga_dev_t *dev)
{
  return -1;
}

static bool lxb_link_str (fpga_dev_t *dev, char *buf, const size_t len)
{
  const lxb_priv_t *priv = (const lxb_priv_t *) dev->priv;

  if (priv == NULL) return false;

  if (priv->link == LXB_LINK_UDP)
  {
    snprintf (buf, len, "Etherbone");

    return true;
  }

  snprintf (buf, len, "UARTBone");

  return true;
}

#else

static int lxb_enumerate (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED fpga_dev_t *devs, MAYBE_UNUSED const int max, fpga_status_t *status) { *status = FPGA_STATUS_UNSUPPORTED_OS; return 0; }
static fpga_status_t lxb_identify (MAYBE_UNUSED fpga_dev_t *dev) { return FPGA_STATUS_UNSUPPORTED_OS; }
static void lxb_close   (MAYBE_UNUSED fpga_dev_t *dev) { }
static void lxb_release (MAYBE_UNUSED fpga_dev_t *dev) { }

static u32  lxb_csr_read  (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const u32 addr) { return 0; }
static bool lxb_csr_write (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const u32 addr, MAYBE_UNUSED const u32 val) { return false; }

static bool lxb_session_open    (MAYBE_UNUSED fpga_dev_t *dev) { return false; }
static void lxb_session_close   (MAYBE_UNUSED fpga_dev_t *dev) { }
static bool lxb_session_refresh (MAYBE_UNUSED fpga_dev_t *dev) { return false; }
static u64  lxb_out_capacity    (MAYBE_UNUSED fpga_dev_t *dev) { return 0; }

static bool lxb_batch_begin (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const u64 out_bytes, MAYBE_UNUSED const u64 in_bytes, MAYBE_UNUSED const u32 in_grain, MAYBE_UNUSED const u32 in_recs) { return false; }
static bool lxb_batch_send  (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED const void *src, MAYBE_UNUSED const u64 bytes) { return false; }
static void lxb_batch_end   (MAYBE_UNUSED fpga_dev_t *dev) { }

static const void *lxb_batch_recv (MAYBE_UNUSED fpga_dev_t *dev, u64 *bytes, MAYBE_UNUSED const u32 timeout_ms) { *bytes = 0; return NULL; }

static bool lxb_batch_done   (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED u32 *processed) { return false; }
static bool lxb_batch_failed (MAYBE_UNUSED fpga_dev_t *dev) { return false; }

static int  lxb_temperature (MAYBE_UNUSED fpga_dev_t *dev) { return -1; }
static bool lxb_link_str    (MAYBE_UNUSED fpga_dev_t *dev, MAYBE_UNUSED char *buf, MAYBE_UNUSED const size_t len) { return false; }

#endif

const fpga_transport_t fpga_transport_litexbone =
{
  .name            = "litexbone",
  .bus             = "Etherbone/UARTBone",
  .data_link       = NULL,
  .udev            = NULL,

  .dialect         = FPGA_DIALECT_HCFPGA,

  .enumerate       = lxb_enumerate,
  .close           = lxb_close,
  .release         = lxb_release,
  .identify        = lxb_identify,
  .confirm         = NULL,

  .csr_read        = lxb_csr_read,
  .csr_write       = lxb_csr_write,

  .session_open    = lxb_session_open,
  .session_close   = lxb_session_close,
  .session_refresh = lxb_session_refresh,
  .out_capacity    = lxb_out_capacity,

  .batch_begin     = lxb_batch_begin,
  .batch_send      = lxb_batch_send,
  .control         = NULL,
  .batch_recv      = lxb_batch_recv,
  .batch_end       = lxb_batch_end,
  .batch_done      = lxb_batch_done,
  .batch_failed    = lxb_batch_failed,

  .in_granule      = 0,

  .program         = NULL,

  .temperature     = lxb_temperature,
  .temperature_all = NULL,

  .temperature_is_die = false,

  .clock_step_down = NULL,

  .link_str        = lxb_link_str,
};
