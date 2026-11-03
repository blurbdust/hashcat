/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 */

#ifndef HCFPGA_DESCRYPT_REF_H
#define HCFPGA_DESCRYPT_REF_H

// descrypt on the host, for the bridge's known-answer canary: the 8 bytes the device returns, as
// hashcat's digest_buf words. Self-contained, it runs once per salt. Check it against the bench's
// reference (src/fpga/descrypt/gateware/descrypt/descrypt_ref.py).
//
// crypt(3)'s traditional DES, one bit per byte from the DES tables (FIPS 46 numbering): the key is
// the low 7 bits of up to 8 password bytes, the 12-bit salt (salt bytes 0..1, as hashcat's
// salt_buf[0] holds it) swaps E-box output bits i and i + 24, the zero block is encrypted 25 times.
// The output block then becomes digest_buf[0..1] as module_01500.c's parser makes it from the hash:
// two little-endian words of the block's bytes, through DES_IP. Words 2 and 3 are zero.

#include <stdint.h>
#include <string.h>

static const uint8_t hcfpga_des_pc1[56] =
{
  57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35, 27, 19, 11,  3,
  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37,
  29, 21, 13,  5, 28, 20, 12,  4
};

static const uint8_t hcfpga_des_pc2[48] =
{
  14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10, 23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const uint8_t hcfpga_des_shifts[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

static const uint8_t hcfpga_des_e[48] =
{
  32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

static const uint8_t hcfpga_des_p[32] =
{
  16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
   2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

static const uint8_t hcfpga_des_fp[64] =
{
  40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30,
  37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
  34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
};

static const uint8_t hcfpga_des_sbox[8][64] =
{
  { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
  { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
  { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
  { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
  { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
  { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
  { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
  { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
};

// hashcat's PERM_OP and DES_IP (OpenCL/inc_cipher_des.h), on plain words.

static void hcfpga_des_perm_op (uint32_t *a, uint32_t *b, const uint32_t n, const uint32_t m)
{
  const uint32_t t = ((*a >> n) ^ *b) & m;

  *b ^= t;
  *a ^= t << n;
}

static void hcfpga_descrypt (const uint8_t *pw, uint32_t pw_len, const uint8_t *salt, uint32_t salt_len, uint32_t rounds, uint32_t out[4])
{
  (void) rounds; // crypt(3)'s 25, fixed in the core

  const uint32_t salt12 = (salt_len >= 2) ? (((uint32_t) salt[0] | ((uint32_t) salt[1] << 8)) & 0xfff) : 0;

  // The key: byte i is (pw[i] & 0x7f) << 1, bit 1 of the key the top bit of byte 0.

  uint8_t kb[64];

  memset (kb, 0, sizeof (kb));

  for (uint32_t i = 0; (i < pw_len) && (i < 8); i++)
  {
    const uint8_t k = (uint8_t) ((pw[i] & 0x7f) << 1);

    for (uint32_t j = 0; j < 8; j++) kb[8 * i + j] = (k >> (7 - j)) & 1;
  }

  uint8_t cd[56];

  for (uint32_t i = 0; i < 56; i++) cd[i] = kb[hcfpga_des_pc1[i] - 1];

  uint8_t ks[16][48];

  for (uint32_t r = 0; r < 16; r++)
  {
    for (uint32_t s = 0; s < hcfpga_des_shifts[r]; s++)
    {
      const uint8_t c0 = cd[0];
      const uint8_t d0 = cd[28];

      memmove (&cd[0],  &cd[1],  27); cd[27] = c0;
      memmove (&cd[28], &cd[29], 27); cd[55] = d0;
    }

    for (uint32_t i = 0; i < 48; i++) ks[r][i] = cd[hcfpga_des_pc2[i] - 1];
  }

  uint8_t e[48];

  memcpy (e, hcfpga_des_e, sizeof (e));

  for (uint32_t i = 0; i < 12; i++)
  {
    if ((salt12 >> i) & 1)
    {
      const uint8_t t = e[i];

      e[i] = e[i + 24];

      e[i + 24] = t;
    }
  }

  uint8_t l[32], r[32];

  memset (l, 0, sizeof (l));
  memset (r, 0, sizeof (r));

  for (uint32_t n = 0; n < 25; n++)
  {
    for (uint32_t k = 0; k < 16; k++)
    {
      uint8_t x[48];

      for (uint32_t i = 0; i < 48; i++) x[i] = r[e[i] - 1] ^ ks[k][i];

      uint8_t f[32];

      for (uint32_t s = 0; s < 8; s++)
      {
        const uint8_t *six = &x[6 * s];

        const uint32_t row = ((uint32_t) six[0] << 1) | six[5];
        const uint32_t col = ((uint32_t) six[1] << 3) | ((uint32_t) six[2] << 2) | ((uint32_t) six[3] << 1) | six[4];

        const uint8_t v = hcfpga_des_sbox[s][16 * row + col];

        for (uint32_t j = 0; j < 4; j++) f[4 * s + j] = (v >> (3 - j)) & 1;
      }

      uint8_t nr[32];

      for (uint32_t i = 0; i < 32; i++) nr[i] = l[i] ^ f[hcfpga_des_p[i] - 1];

      memcpy (l, r, 32);
      memcpy (r, nr, 32);
    }

    uint8_t t[32];

    memcpy (t, l, 32);
    memcpy (l, r, 32);
    memcpy (r, t, 32);
  }

  // Preoutput is L R after the last swap; the output block is its final permutation.

  uint8_t pre[64];

  memcpy (&pre[0],  l, 32);
  memcpy (&pre[32], r, 32);

  uint8_t blk[8];

  memset (blk, 0, sizeof (blk));

  for (uint32_t i = 0; i < 64; i++) blk[i / 8] |= (uint8_t) (pre[hcfpga_des_fp[i] - 1] << (7 - (i % 8)));

  uint32_t d0 = (uint32_t) blk[0] | ((uint32_t) blk[1] << 8) | ((uint32_t) blk[2] << 16) | ((uint32_t) blk[3] << 24);
  uint32_t d1 = (uint32_t) blk[4] | ((uint32_t) blk[5] << 8) | ((uint32_t) blk[6] << 16) | ((uint32_t) blk[7] << 24);

  hcfpga_des_perm_op (&d1, &d0,  4, 0x0f0f0f0f);
  hcfpga_des_perm_op (&d0, &d1, 16, 0x0000ffff);
  hcfpga_des_perm_op (&d1, &d0,  2, 0x33333333);
  hcfpga_des_perm_op (&d0, &d1,  8, 0x00ff00ff);
  hcfpga_des_perm_op (&d1, &d0,  1, 0x55555555);

  out[0] = d0;
  out[1] = d1;
  out[2] = 0;
  out[3] = 0;
}

#endif // HCFPGA_DESCRYPT_REF_H
