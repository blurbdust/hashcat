/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 */

#ifndef HCFPGA_SHA256CRYPT_REF_H
#define HCFPGA_SHA256CRYPT_REF_H

// sha256crypt on the host, for the bridge's known-answer canary: the 16 bytes the device returns
// (the first half of the result, in SHA-256 output order), as hashcat's digest_buf words 0..3, four
// little-endian words. Self-contained, it runs once per salt. It agrees with the bench's reference
// (src/fpga/sha256crypt/gateware/sha256crypt/sha256crypt_ref.py), which is hashcat's own oracle.
//
// Drepper's sha256crypt as mode 7400 computes it: the rounds are taken as given (libc clamps them
// to 1000..999999999, hashcat and the device do not), and the salt is whatever the caller passes
// (the device takes 1 to 16 bytes).

#include <stdint.h>
#include <string.h>

typedef struct
{
  uint32_t h[8];
  uint8_t  buf[64];
  uint32_t len;
  uint64_t total;

} hcfpga_sha256_t;

static const uint32_t HCFPGA_SHA256_K[64] =
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

#define HCFPGA_SHA256_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void hcfpga_sha256_block (hcfpga_sha256_t *ctx, const uint8_t *p)
{
  uint32_t w[64];

  for (int i = 0; i < 16; i++)
  {
    w[i] = ((uint32_t) p[4 * i] << 24) | ((uint32_t) p[4 * i + 1] << 16) | ((uint32_t) p[4 * i + 2] << 8) | (uint32_t) p[4 * i + 3];
  }

  for (int i = 16; i < 64; i++)
  {
    const uint32_t s0 = HCFPGA_SHA256_ROTR (w[i - 15],  7) ^ HCFPGA_SHA256_ROTR (w[i - 15], 18) ^ (w[i - 15] >>  3);
    const uint32_t s1 = HCFPGA_SHA256_ROTR (w[i -  2], 17) ^ HCFPGA_SHA256_ROTR (w[i -  2], 19) ^ (w[i -  2] >> 10);

    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
  uint32_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h = ctx->h[7];

  for (int i = 0; i < 64; i++)
  {
    const uint32_t S1 = HCFPGA_SHA256_ROTR (e, 6) ^ HCFPGA_SHA256_ROTR (e, 11) ^ HCFPGA_SHA256_ROTR (e, 25);
    const uint32_t ch = (e & f) ^ (~e & g);
    const uint32_t t1 = h + S1 + ch + HCFPGA_SHA256_K[i] + w[i];
    const uint32_t S0 = HCFPGA_SHA256_ROTR (a, 2) ^ HCFPGA_SHA256_ROTR (a, 13) ^ HCFPGA_SHA256_ROTR (a, 22);
    const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
    const uint32_t t2 = S0 + mj;

    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }

  ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
  ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

#undef HCFPGA_SHA256_ROTR

static void hcfpga_sha256_init (hcfpga_sha256_t *ctx)
{
  static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

  memcpy (ctx->h, iv, sizeof (iv));

  ctx->len   = 0;
  ctx->total = 0;
}

static void hcfpga_sha256_update (hcfpga_sha256_t *ctx, const uint8_t *p, uint32_t n)
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
      hcfpga_sha256_block (ctx, ctx->buf);

      ctx->len = 0;
    }
  }
}

static void hcfpga_sha256_final (hcfpga_sha256_t *ctx, uint8_t out[32])
{
  const uint64_t bits = ctx->total * 8;

  const uint8_t pad = 0x80;
  const uint8_t zero = 0;

  hcfpga_sha256_update (ctx, &pad, 1);

  while (ctx->len != 56) hcfpga_sha256_update (ctx, &zero, 1);

  uint8_t lenbuf[8];

  for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t) (bits >> (56 - 8 * i));

  hcfpga_sha256_update (ctx, lenbuf, 8);

  for (int i = 0; i < 8; i++)
  {
    out[4 * i + 0] = (uint8_t) (ctx->h[i] >> 24);
    out[4 * i + 1] = (uint8_t) (ctx->h[i] >> 16);
    out[4 * i + 2] = (uint8_t) (ctx->h[i] >>  8);
    out[4 * i + 3] = (uint8_t) (ctx->h[i] >>  0);
  }
}

// sha256crypt's 32-byte result in SHA-256 output order (mode 7400's digest_buf as bytes).

static void hcfpga_sha256crypt_raw (const uint8_t *pw, uint32_t pw_len, const uint8_t *salt, uint32_t salt_len, uint32_t rounds, uint8_t result[32])
{
  hcfpga_sha256_t ctx;

  uint8_t alt[32];
  uint8_t dp[32];
  uint8_t ds[32];

  // The alternate sum: key, salt, key.

  hcfpga_sha256_init (&ctx);
  hcfpga_sha256_update (&ctx, pw, pw_len);
  hcfpga_sha256_update (&ctx, salt, salt_len);
  hcfpga_sha256_update (&ctx, pw, pw_len);
  hcfpga_sha256_final (&ctx, alt);

  // A: key, salt, key_len bytes of the alternate sum, then per bit of key_len the sum or the key.

  hcfpga_sha256_init (&ctx);
  hcfpga_sha256_update (&ctx, pw, pw_len);
  hcfpga_sha256_update (&ctx, salt, salt_len);

  uint32_t n;

  for (n = pw_len; n > 32; n -= 32) hcfpga_sha256_update (&ctx, alt, 32);

  hcfpga_sha256_update (&ctx, alt, n);

  for (n = pw_len; n > 0; n >>= 1)
  {
    if (n & 1) hcfpga_sha256_update (&ctx, alt, 32);
    else       hcfpga_sha256_update (&ctx, pw, pw_len);
  }

  hcfpga_sha256_final (&ctx, result);

  // DP: the key key_len times. DS: the salt 16 + A[0] times.

  hcfpga_sha256_init (&ctx);

  for (n = 0; n < pw_len; n++) hcfpga_sha256_update (&ctx, pw, pw_len);

  hcfpga_sha256_final (&ctx, dp);

  hcfpga_sha256_init (&ctx);

  for (n = 0; n < 16u + result[0]; n++) hcfpga_sha256_update (&ctx, salt, salt_len);

  hcfpga_sha256_final (&ctx, ds);

  // P and S: the first key_len and salt_len bytes of DP and DS repeated (both at most 32 here,
  // hence one copy cut short).

  uint8_t p[32];
  uint8_t s[32];

  for (n = 0; n < pw_len;   n++) p[n] = dp[n % 32];
  for (n = 0; n < salt_len; n++) s[n] = ds[n % 32];

  for (uint32_t i = 0; i < rounds; i++)
  {
    hcfpga_sha256_init (&ctx);

    if (i & 1) hcfpga_sha256_update (&ctx, p, pw_len);
    else       hcfpga_sha256_update (&ctx, result, 32);

    if (i % 3) hcfpga_sha256_update (&ctx, s, salt_len);
    if (i % 7) hcfpga_sha256_update (&ctx, p, pw_len);

    if (i & 1) hcfpga_sha256_update (&ctx, result, 32);
    else       hcfpga_sha256_update (&ctx, p, pw_len);

    hcfpga_sha256_final (&ctx, result);
  }
}

// The canary's reference: the 16 bytes the device returns, as four little-endian digest_buf words.
// pw_len and salt_len above 32 are cut to 32 (the device takes 32 and 16).

static void hcfpga_sha256crypt (const uint8_t *pw, uint32_t pw_len, const uint8_t *salt, uint32_t salt_len, uint32_t rounds, uint32_t out[4])
{
  uint8_t d[32];

  if (pw_len   > 32) pw_len   = 32;
  if (salt_len > 32) salt_len = 32;

  hcfpga_sha256crypt_raw (pw, pw_len, salt, salt_len, rounds, d);

  for (uint32_t i = 0; i < 4; i++)
  {
    out[i] = (uint32_t) d[4 * i] | ((uint32_t) d[4 * i + 1] << 8) | ((uint32_t) d[4 * i + 2] << 16) | ((uint32_t) d[4 * i + 3] << 24);
  }
}

#endif // HCFPGA_SHA256CRYPT_REF_H
