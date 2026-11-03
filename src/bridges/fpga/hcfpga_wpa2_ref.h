/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 */

#ifndef HCFPGA_WPA2_REF_H
#define HCFPGA_WPA2_REF_H

// wpa2 on the host, for the bridge's known-answer canary: the 32 bytes the device returns, the WPA
// PMK, PBKDF2-HMAC-SHA1 (passphrase, ESSID, 4096 iterations, 32 bytes), as hashcat's digest_buf
// words: word k is PMK bytes 4k..4k+3 big-endian (mode 22000's tmps out[k]). Self-contained, it
// runs once per salt. Checked against the bench's reference (src/fpga/wpa2/gateware/wpa2/wpa2_ref.py).
//
// The iteration count is the format's, not salt_iter (4095, the count after U1): the device does
// not read it either.

#include <stdint.h>
#include <string.h>

static uint32_t hcfpga_wpa2_rol (const uint32_t x, const int n)
{
  return (x << n) | (x >> (32 - n));
}

static void hcfpga_wpa2_sha1 (uint32_t state[5], const uint32_t block[16])
{
  uint32_t w[80];

  for (int t = 0; t < 16; t++) w[t] = block[t];

  for (int t = 16; t < 80; t++) w[t] = hcfpga_wpa2_rol (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);

  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

  for (int t = 0; t < 80; t++)
  {
    uint32_t f, k;

    if      (t < 20) { f = (b & c) | (~b & d);          k = 0x5a827999; }
    else if (t < 40) { f = b ^ c ^ d;                   k = 0x6ed9eba1; }
    else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
    else             { f = b ^ c ^ d;                   k = 0xca62c1d6; }

    const uint32_t tmp = hcfpga_wpa2_rol (a, 5) + f + e + k + w[t];

    e = d;
    d = c;
    c = hcfpga_wpa2_rol (b, 30);
    b = a;
    a = tmp;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

// The 64-byte block of bytes buf[0..len-1], zero filled, as big-endian words.

static void hcfpga_wpa2_words (uint32_t block[16], const uint8_t *buf, const uint32_t len)
{
  uint8_t b[64];

  memset (b, 0, sizeof (b));
  memcpy (b, buf, (len < 64) ? len : 64);

  for (int i = 0; i < 16; i++)
  {
    block[i] = ((uint32_t) b[4 * i] << 24) | ((uint32_t) b[4 * i + 1] << 16) | ((uint32_t) b[4 * i + 2] << 8) | (uint32_t) b[4 * i + 3];
  }
}

// One HMAC-SHA1 of a 20-byte message from the precomputed pad states.

static void hcfpga_wpa2_hmac20 (const uint32_t ipad[5], const uint32_t opad[5], const uint32_t msg[5], uint32_t out[5])
{
  uint32_t block[16];

  for (int i = 0; i < 5; i++) block[i] = msg[i];

  block[5] = 0x80000000;

  for (int i = 6; i < 15; i++) block[i] = 0;

  block[15] = (64 + 20) * 8;

  uint32_t inner[5];

  memcpy (inner, ipad, sizeof (inner));

  hcfpga_wpa2_sha1 (inner, block);

  for (int i = 0; i < 5; i++) block[i] = inner[i];

  memcpy (out, opad, 5 * sizeof (uint32_t));

  hcfpga_wpa2_sha1 (out, block);
}

// rounds is hashcat's salt_iter, taken for the scaffold's signature and not used (above).

static void hcfpga_wpa2 (const uint8_t *pw, uint32_t pw_len, const uint8_t *essid, uint32_t essid_len, const uint32_t rounds, uint32_t out[8])
{
  (void) rounds;

  static const uint32_t iv[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

  if (pw_len > 64) pw_len = 64;   // the device takes at most 63; HMAC would hash a longer key first

  if (essid_len > 32) essid_len = 32;

  uint32_t key[16];

  hcfpga_wpa2_words (key, pw, pw_len);

  uint32_t block[16];

  uint32_t ipad[5], opad[5];

  for (int i = 0; i < 16; i++) block[i] = key[i] ^ 0x36363636;

  memcpy (ipad, iv, sizeof (ipad));

  hcfpga_wpa2_sha1 (ipad, block);

  for (int i = 0; i < 16; i++) block[i] = key[i] ^ 0x5c5c5c5c;

  memcpy (opad, iv, sizeof (opad));

  hcfpga_wpa2_sha1 (opad, block);

  uint32_t t[10];

  for (uint32_t blk = 1; blk <= 2; blk++)
  {
    // U1 = HMAC (K, ESSID || INT (blk)): the inner message fits one block after the key's.
    uint8_t m[64];

    memset (m, 0, sizeof (m));
    memcpy (m, essid, essid_len);

    m[essid_len + 3] = (uint8_t) blk;
    m[essid_len + 4] = 0x80;

    hcfpga_wpa2_words (block, m, 64);

    block[15] = (64 + essid_len + 4) * 8;

    uint32_t inner[5];

    memcpy (inner, ipad, sizeof (inner));

    hcfpga_wpa2_sha1 (inner, block);

    for (int i = 0; i < 5; i++) block[i] = inner[i];

    block[5] = 0x80000000;

    for (int i = 6; i < 15; i++) block[i] = 0;

    block[15] = (64 + 20) * 8;

    uint32_t u[5];

    memcpy (u, opad, sizeof (u));

    hcfpga_wpa2_sha1 (u, block);

    uint32_t *acc = &t[5 * (blk - 1)];

    memcpy (acc, u, sizeof (u));

    for (int iter = 1; iter < 4096; iter++)
    {
      hcfpga_wpa2_hmac20 (ipad, opad, u, u);

      for (int i = 0; i < 5; i++) acc[i] ^= u[i];
    }
  }

  for (int i = 0; i < 8; i++) out[i] = t[i];
}

#endif // HCFPGA_WPA2_REF_H
