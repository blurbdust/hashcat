/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 */

#ifndef HCFPGA_MD5CRYPT_REF_H
#define HCFPGA_MD5CRYPT_REF_H

// md5crypt on the host, for the bridge's known-answer canary: the 16 bytes the device returns, as
// hashcat's digest_buf (four little-endian words). Self-contained, it runs once per salt.

#include <stdint.h>
#include <string.h>

typedef struct
{
  uint32_t h[4];
  uint8_t  buf[64];
  uint32_t len;
  uint64_t total;

} hcfpga_md5_t;

static const uint32_t HCFPGA_MD5_K[64] =
{
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const uint8_t HCFPGA_MD5_S[64] =
{
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static void hcfpga_md5_block (hcfpga_md5_t *ctx, const uint8_t *p)
{
  uint32_t w[16];

  for (int i = 0; i < 16; i++)
  {
    w[i] = (uint32_t) p[4 * i] | ((uint32_t) p[4 * i + 1] << 8) | ((uint32_t) p[4 * i + 2] << 16) | ((uint32_t) p[4 * i + 3] << 24);
  }

  uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];

  for (int i = 0; i < 64; i++)
  {
    uint32_t f;
    int      g;

    if      (i < 16) { f = (b & c) | (~b & d); g = i;                }
    else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
    else if (i < 48) { f = b ^ c ^ d;          g = (3 * i + 5) % 16; }
    else             { f = c ^ (b | ~d);       g = (7 * i) % 16;     }

    const uint32_t t = d;

    d = c;
    c = b;

    const uint32_t x = a + f + HCFPGA_MD5_K[i] + w[g];

    b = b + ((x << HCFPGA_MD5_S[i]) | (x >> (32 - HCFPGA_MD5_S[i])));
    a = t;
  }

  ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
}

static void hcfpga_md5_init (hcfpga_md5_t *ctx)
{
  ctx->h[0] = 0x67452301; ctx->h[1] = 0xefcdab89; ctx->h[2] = 0x98badcfe; ctx->h[3] = 0x10325476;

  ctx->len   = 0;
  ctx->total = 0;
}

static void hcfpga_md5_update (hcfpga_md5_t *ctx, const uint8_t *p, uint32_t n)
{
  ctx->total += n;

  while (n > 0)
  {
    const uint32_t take = ((64 - ctx->len) < n) ? (64 - ctx->len) : n;

    memcpy (ctx->buf + ctx->len, p, take);

    ctx->len += take;
    p        += take;
    n        -= take;

    if (ctx->len == 64)
    {
      hcfpga_md5_block (ctx, ctx->buf);

      ctx->len = 0;
    }
  }
}

static void hcfpga_md5_final (hcfpga_md5_t *ctx, uint8_t out[16])
{
  const uint64_t bits = ctx->total * 8;

  const uint8_t one = 0x80, zero = 0;

  hcfpga_md5_update (ctx, &one, 1);

  while (ctx->len != 56) hcfpga_md5_update (ctx, &zero, 1);

  uint8_t lenb[8];

  for (int i = 0; i < 8; i++) lenb[i] = (uint8_t) (bits >> (8 * i));

  hcfpga_md5_update (ctx, lenb, 8);

  for (int i = 0; i < 4; i++)
  {
    out[4 * i + 0] = (uint8_t) (ctx->h[i] >>  0);
    out[4 * i + 1] = (uint8_t) (ctx->h[i] >>  8);
    out[4 * i + 2] = (uint8_t) (ctx->h[i] >> 16);
    out[4 * i + 3] = (uint8_t) (ctx->h[i] >> 24);
  }
}

// FreeBSD's crypt-md5.c, the "$1$" magic, rounds as the salt_iter of mode 500 and 75100.
static void hcfpga_md5crypt (const uint8_t *pw, uint32_t pw_len, const uint8_t *salt, uint32_t salt_len, uint32_t rounds, uint32_t out[4])
{
  hcfpga_md5_t ctx;

  uint8_t fin[16];

  hcfpga_md5_init   (&ctx);
  hcfpga_md5_update (&ctx, pw, pw_len);
  hcfpga_md5_update (&ctx, salt, salt_len);
  hcfpga_md5_update (&ctx, pw, pw_len);
  hcfpga_md5_final  (&ctx, fin);

  hcfpga_md5_init   (&ctx);
  hcfpga_md5_update (&ctx, pw, pw_len);
  hcfpga_md5_update (&ctx, (const uint8_t *) "$1$", 3);
  hcfpga_md5_update (&ctx, salt, salt_len);

  for (int32_t n = (int32_t) pw_len; n > 0; n -= 16) hcfpga_md5_update (&ctx, fin, (n > 16) ? 16 : (uint32_t) n);

  for (uint32_t i = pw_len; i != 0; i >>= 1)
  {
    const uint8_t z = 0;

    if (i & 1) hcfpga_md5_update (&ctx, &z, 1);
    else       hcfpga_md5_update (&ctx, pw, 1);
  }

  hcfpga_md5_final (&ctx, fin);

  for (uint32_t i = 0; i < rounds; i++)
  {
    hcfpga_md5_init (&ctx);

    if (i & 1) hcfpga_md5_update (&ctx, pw, pw_len);
    else       hcfpga_md5_update (&ctx, fin, 16);

    if (i % 3) hcfpga_md5_update (&ctx, salt, salt_len);
    if (i % 7) hcfpga_md5_update (&ctx, pw, pw_len);

    if (i & 1) hcfpga_md5_update (&ctx, fin, 16);
    else       hcfpga_md5_update (&ctx, pw, pw_len);

    hcfpga_md5_final (&ctx, fin);
  }

  for (int i = 0; i < 4; i++)
  {
    out[i] = (uint32_t) fin[4 * i] | ((uint32_t) fin[4 * i + 1] << 8) | ((uint32_t) fin[4 * i + 2] << 16) | ((uint32_t) fin[4 * i + 3] << 24);
  }
}

#endif // HCFPGA_MD5CRYPT_REF_H
