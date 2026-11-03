/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 */

#ifndef HCFPGA_SCRYPT_REF_H
#define HCFPGA_SCRYPT_REF_H

// scrypt on the host, for the bridge's known-answer canary: the 16 bytes the device returns (the
// first 16 bytes of the 32-byte derived key), as hashcat's digest_buf words 0..3, four little-endian
// words. Self-contained, it runs once per salt. It agrees with the bench's reference
// (src/fpga/scrypt/gateware/scrypt/scrypt_ref.py), which is Python's hashlib.scrypt.
//
// What the device computes: scrypt with p = 1, r from 1 to HCFPGA_SCRYPT_R_MAX, N a power of two, a
// key of at most 64 bytes (HMAC-SHA256 takes such a key as it is, zero filled to the block) and a salt
// of at most 32 bytes:
//
//   B  = PBKDF2-HMAC-SHA256 (pw, salt, 1, 128 r)
//   B' = ROMix (B, N), BlockMix over Salsa20/8 with r
//   DK = PBKDF2-HMAC-SHA256 (pw, B', 1, 32)

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// The widest r the reference computes (the gateware's R_MAX in the simulated board's build).

#define HCFPGA_SCRYPT_R_MAX 8

typedef struct
{
  uint32_t h[8];
  uint8_t  buf[64];
  uint32_t len;
  uint64_t total;

} hcfpga_scrypt_sha256_t;

static const uint32_t HCFPGA_SCRYPT_SHA256_K[64] =
{
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define HCFPGA_SCRYPT_SHA256_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void hcfpga_scrypt_sha256_block (hcfpga_scrypt_sha256_t *ctx, const uint8_t *p)
{
  uint32_t w[64];

  for (int i = 0; i < 16; i++)
  {
    w[i] = ((uint32_t) p[4 * i] << 24) | ((uint32_t) p[4 * i + 1] << 16) | ((uint32_t) p[4 * i + 2] << 8) | (uint32_t) p[4 * i + 3];
  }

  for (int i = 16; i < 64; i++)
  {
    const uint32_t s0 = HCFPGA_SCRYPT_SHA256_ROTR (w[i - 15],  7) ^ HCFPGA_SCRYPT_SHA256_ROTR (w[i - 15], 18) ^ (w[i - 15] >>  3);
    const uint32_t s1 = HCFPGA_SCRYPT_SHA256_ROTR (w[i -  2], 17) ^ HCFPGA_SCRYPT_SHA256_ROTR (w[i -  2], 19) ^ (w[i -  2] >> 10);

    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
  uint32_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h = ctx->h[7];

  for (int i = 0; i < 64; i++)
  {
    const uint32_t S1 = HCFPGA_SCRYPT_SHA256_ROTR (e, 6) ^ HCFPGA_SCRYPT_SHA256_ROTR (e, 11) ^ HCFPGA_SCRYPT_SHA256_ROTR (e, 25);
    const uint32_t ch = (e & f) ^ (~e & g);
    const uint32_t t1 = h + S1 + ch + HCFPGA_SCRYPT_SHA256_K[i] + w[i];
    const uint32_t S0 = HCFPGA_SCRYPT_SHA256_ROTR (a, 2) ^ HCFPGA_SCRYPT_SHA256_ROTR (a, 13) ^ HCFPGA_SCRYPT_SHA256_ROTR (a, 22);
    const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
    const uint32_t t2 = S0 + mj;

    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }

  ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
  ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

#undef HCFPGA_SCRYPT_SHA256_ROTR

static void hcfpga_scrypt_sha256_init (hcfpga_scrypt_sha256_t *ctx)
{
  static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

  memcpy (ctx->h, iv, sizeof (iv));

  ctx->len   = 0;
  ctx->total = 0;
}

static void hcfpga_scrypt_sha256_update (hcfpga_scrypt_sha256_t *ctx, const uint8_t *p, uint32_t n)
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
      hcfpga_scrypt_sha256_block (ctx, ctx->buf);

      ctx->len = 0;
    }
  }
}

static void hcfpga_scrypt_sha256_final (hcfpga_scrypt_sha256_t *ctx, uint8_t out[32])
{
  const uint64_t bits = ctx->total * 8;

  const uint8_t pad = 0x80;
  const uint8_t zero = 0;

  hcfpga_scrypt_sha256_update (ctx, &pad, 1);

  while (ctx->len != 56) hcfpga_scrypt_sha256_update (ctx, &zero, 1);

  uint8_t lenbuf[8];

  for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t) (bits >> (56 - 8 * i));

  hcfpga_scrypt_sha256_update (ctx, lenbuf, 8);

  for (int i = 0; i < 8; i++)
  {
    out[4 * i + 0] = (uint8_t) (ctx->h[i] >> 24);
    out[4 * i + 1] = (uint8_t) (ctx->h[i] >> 16);
    out[4 * i + 2] = (uint8_t) (ctx->h[i] >>  8);
    out[4 * i + 3] = (uint8_t) (ctx->h[i] >>  0);
  }
}

// HMAC-SHA256 with a key of at most 64 bytes, of msg || INT32BE (idx).

static void hcfpga_scrypt_hmac (const uint8_t *key, uint32_t key_len, const uint8_t *msg, uint32_t msg_len, uint32_t idx, uint8_t out[32])
{
  uint8_t pad[64];
  uint8_t inner[32];
  uint8_t ctr[4] = { (uint8_t) (idx >> 24), (uint8_t) (idx >> 16), (uint8_t) (idx >> 8), (uint8_t) idx };

  hcfpga_scrypt_sha256_t ctx;

  memset (pad, 0, sizeof (pad));
  memcpy (pad, key, key_len);

  for (int i = 0; i < 64; i++) pad[i] ^= 0x36;

  hcfpga_scrypt_sha256_init (&ctx);
  hcfpga_scrypt_sha256_update (&ctx, pad, 64);
  hcfpga_scrypt_sha256_update (&ctx, msg, msg_len);
  hcfpga_scrypt_sha256_update (&ctx, ctr, 4);
  hcfpga_scrypt_sha256_final (&ctx, inner);

  for (int i = 0; i < 64; i++) pad[i] ^= 0x36 ^ 0x5c;

  hcfpga_scrypt_sha256_init (&ctx);
  hcfpga_scrypt_sha256_update (&ctx, pad, 64);
  hcfpga_scrypt_sha256_update (&ctx, inner, 32);
  hcfpga_scrypt_sha256_final (&ctx, out);
}

// Salsa20/8 on 16 little-endian words, in place.

static void hcfpga_scrypt_salsa8 (uint32_t b[16])
{
  uint32_t x[16];

  memcpy (x, b, sizeof (x));

  #define HCFPGA_SCRYPT_R(a,n) (((a) << (n)) | ((a) >> (32 - (n))))

  for (int i = 0; i < 8; i += 2)
  {
    x[ 4] ^= HCFPGA_SCRYPT_R (x[ 0] + x[12],  7); x[ 8] ^= HCFPGA_SCRYPT_R (x[ 4] + x[ 0],  9);
    x[12] ^= HCFPGA_SCRYPT_R (x[ 8] + x[ 4], 13); x[ 0] ^= HCFPGA_SCRYPT_R (x[12] + x[ 8], 18);
    x[ 9] ^= HCFPGA_SCRYPT_R (x[ 5] + x[ 1],  7); x[13] ^= HCFPGA_SCRYPT_R (x[ 9] + x[ 5],  9);
    x[ 1] ^= HCFPGA_SCRYPT_R (x[13] + x[ 9], 13); x[ 5] ^= HCFPGA_SCRYPT_R (x[ 1] + x[13], 18);
    x[14] ^= HCFPGA_SCRYPT_R (x[10] + x[ 6],  7); x[ 2] ^= HCFPGA_SCRYPT_R (x[14] + x[10],  9);
    x[ 6] ^= HCFPGA_SCRYPT_R (x[ 2] + x[14], 13); x[10] ^= HCFPGA_SCRYPT_R (x[ 6] + x[ 2], 18);
    x[ 3] ^= HCFPGA_SCRYPT_R (x[15] + x[11],  7); x[ 7] ^= HCFPGA_SCRYPT_R (x[ 3] + x[15],  9);
    x[11] ^= HCFPGA_SCRYPT_R (x[ 7] + x[ 3], 13); x[15] ^= HCFPGA_SCRYPT_R (x[11] + x[ 7], 18);

    x[ 1] ^= HCFPGA_SCRYPT_R (x[ 0] + x[ 3],  7); x[ 2] ^= HCFPGA_SCRYPT_R (x[ 1] + x[ 0],  9);
    x[ 3] ^= HCFPGA_SCRYPT_R (x[ 2] + x[ 1], 13); x[ 0] ^= HCFPGA_SCRYPT_R (x[ 3] + x[ 2], 18);
    x[ 6] ^= HCFPGA_SCRYPT_R (x[ 5] + x[ 4],  7); x[ 7] ^= HCFPGA_SCRYPT_R (x[ 6] + x[ 5],  9);
    x[ 4] ^= HCFPGA_SCRYPT_R (x[ 7] + x[ 6], 13); x[ 5] ^= HCFPGA_SCRYPT_R (x[ 4] + x[ 7], 18);
    x[11] ^= HCFPGA_SCRYPT_R (x[10] + x[ 9],  7); x[ 8] ^= HCFPGA_SCRYPT_R (x[11] + x[10],  9);
    x[ 9] ^= HCFPGA_SCRYPT_R (x[ 8] + x[11], 13); x[10] ^= HCFPGA_SCRYPT_R (x[ 9] + x[ 8], 18);
    x[12] ^= HCFPGA_SCRYPT_R (x[15] + x[14],  7); x[13] ^= HCFPGA_SCRYPT_R (x[12] + x[15],  9);
    x[14] ^= HCFPGA_SCRYPT_R (x[13] + x[12], 13); x[15] ^= HCFPGA_SCRYPT_R (x[14] + x[13], 18);
  }

  #undef HCFPGA_SCRYPT_R

  for (int i = 0; i < 16; i++) b[i] += x[i];
}

// BlockMix with r on 32 r little-endian words (2 r blocks of 16), in place: Y[i] = Salsa20/8 (Y[i - 1]
// ^ B[i]) from Y[-1] = B[2r - 1], then the even Y first and the odd ones after them.

static void hcfpga_scrypt_blockmix (uint32_t *b, const uint32_t r)
{
  uint32_t x[16];
  uint32_t y[32 * HCFPGA_SCRYPT_R_MAX];

  memcpy (x, b + 16 * (2 * r - 1), sizeof (x));

  for (uint32_t i = 0; i < 2 * r; i++)
  {
    for (int k = 0; k < 16; k++) x[k] ^= b[16 * i + k];

    hcfpga_scrypt_salsa8 (x);

    memcpy (y + 16 * ((i / 2) + ((i & 1) ? r : 0)), x, sizeof (x));
  }

  memcpy (b, y, 32 * r * sizeof (uint32_t));
}

// The device's 16 bytes for pw under salt with cost n (a power of two, at least 2) and r (1 to
// HCFPGA_SCRYPT_R_MAX). A key longer than 64 bytes, a salt longer than 32 or another r is outside
// what the device takes; the bridge never asks.

static void hcfpga_scrypt (const uint8_t *pw, uint32_t pw_len, const uint8_t *salt, uint32_t salt_len, uint32_t n, uint32_t r, uint32_t out[4])
{
  uint8_t  b[128 * HCFPGA_SCRYPT_R_MAX];
  uint32_t x[32 * HCFPGA_SCRYPT_R_MAX];
  uint8_t  dk[32];

  memset (out, 0, 4 * sizeof (uint32_t));

  if ((r < 1) || (r > HCFPGA_SCRYPT_R_MAX)) return;

  if (pw_len > 64) pw_len = 64;

  const uint32_t words = 32 * r;

  for (uint32_t i = 0; i < 4 * r; i++) hcfpga_scrypt_hmac (pw, pw_len, salt, salt_len, i + 1, b + 32 * i);

  for (uint32_t i = 0; i < words; i++)
  {
    x[i] = (uint32_t) b[4 * i] | ((uint32_t) b[4 * i + 1] << 8) | ((uint32_t) b[4 * i + 2] << 16) | ((uint32_t) b[4 * i + 3] << 24);
  }

  uint32_t *v = (uint32_t *) malloc ((size_t) n * words * sizeof (uint32_t));

  if (v == NULL) return;

  for (uint32_t i = 0; i < n; i++)
  {
    memcpy (v + words * (size_t) i, x, words * sizeof (uint32_t));

    hcfpga_scrypt_blockmix (x, r);
  }

  for (uint32_t i = 0; i < n; i++)
  {
    const uint32_t j = x[16 * (2 * r - 1)] & (n - 1);

    for (uint32_t k = 0; k < words; k++) x[k] ^= v[words * (size_t) j + k];

    hcfpga_scrypt_blockmix (x, r);
  }

  free (v);

  for (uint32_t i = 0; i < words; i++)
  {
    b[4 * i + 0] = (uint8_t) (x[i] >>  0);
    b[4 * i + 1] = (uint8_t) (x[i] >>  8);
    b[4 * i + 2] = (uint8_t) (x[i] >> 16);
    b[4 * i + 3] = (uint8_t) (x[i] >> 24);
  }

  hcfpga_scrypt_hmac (pw, pw_len, b, 128 * r, 1, dk);

  for (uint32_t i = 0; i < 4; i++)
  {
    out[i] = (uint32_t) dk[4 * i] | ((uint32_t) dk[4 * i + 1] << 8) | ((uint32_t) dk[4 * i + 2] << 16) | ((uint32_t) dk[4 * i + 3] << 24);
  }
}

#endif // HCFPGA_SCRYPT_REF_H
