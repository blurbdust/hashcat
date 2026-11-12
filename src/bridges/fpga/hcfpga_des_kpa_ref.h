/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 */

#ifndef HCFPGA_DES_KPA_REF_H
#define HCFPGA_DES_KPA_REF_H

// DES on the host, for the DES known-plaintext bridge: every key the device reports is encrypted here
// before hashcat sees it, and the known-answer canary comes from here too. Self-contained, one block at
// a time, one bit per byte from the DES tables (FIPS 46 numbering). Check it against the bench's
// reference (src/fpga/des_kpa/gateware/des_kpa/des_kpa_ref.py).

#include <stdint.h>
#include <string.h>

static const uint8_t hcfpga_deskpa_pc1[56] =
{
  57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35, 27, 19, 11,  3,
  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37,
  29, 21, 13,  5, 28, 20, 12,  4
};

static const uint8_t hcfpga_deskpa_pc2[48] =
{
  14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10, 23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const uint8_t hcfpga_deskpa_shifts[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

static const uint8_t hcfpga_deskpa_e[48] =
{
  32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

static const uint8_t hcfpga_deskpa_p[32] =
{
  16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
   2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

static const uint8_t hcfpga_deskpa_fp[64] =
{
  40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31, 38,  6, 46, 14, 54, 22, 62, 30,
  37,  5, 45, 13, 53, 21, 61, 29, 36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
  34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
};

static const uint8_t hcfpga_deskpa_sbox[8][64] =
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

static const uint8_t hcfpga_deskpa_ip[64] =
{
  58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4, 62, 54, 46, 38, 30, 22, 14,  6,
  64, 56, 48, 40, 32, 24, 16,  8, 57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
  61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7
};

// DES-ECB of one block: the 8-byte key (the low bit of every byte, its parity bit, unused), the
// 8-byte plaintext, the 8-byte ciphertext.

static inline void hcfpga_deskpa_encrypt (const uint8_t key[8], const uint8_t pt[8], uint8_t ct[8])
{
  uint8_t kb[64];

  for (uint32_t i = 0; i < 64; i++) kb[i] = (key[i / 8] >> (7 - (i % 8))) & 1;

  uint8_t cd[56];

  for (uint32_t i = 0; i < 56; i++) cd[i] = kb[hcfpga_deskpa_pc1[i] - 1];

  uint8_t ks[16][48];

  for (uint32_t r = 0; r < 16; r++)
  {
    for (uint32_t s = 0; s < hcfpga_deskpa_shifts[r]; s++)
    {
      const uint8_t c0 = cd[0];
      const uint8_t d0 = cd[28];

      memmove (&cd[0],  &cd[1],  27); cd[27] = c0;
      memmove (&cd[28], &cd[29], 27); cd[55] = d0;
    }

    for (uint32_t i = 0; i < 48; i++) ks[r][i] = cd[hcfpga_deskpa_pc2[i] - 1];
  }

  uint8_t pb[64];

  for (uint32_t i = 0; i < 64; i++) pb[i] = (pt[i / 8] >> (7 - (i % 8))) & 1;

  uint8_t lr[64];

  for (uint32_t i = 0; i < 64; i++) lr[i] = pb[hcfpga_deskpa_ip[i] - 1];

  uint8_t *l = &lr[0];
  uint8_t *r = &lr[32];

  for (uint32_t round = 0; round < 16; round++)
  {
    uint8_t x[48];

    for (uint32_t i = 0; i < 48; i++) x[i] = r[hcfpga_deskpa_e[i] - 1] ^ ks[round][i];

    uint8_t s[32];

    for (uint32_t b = 0; b < 8; b++)
    {
      const uint8_t *six = &x[6 * b];

      const uint32_t row = (six[0] << 1) | six[5];
      const uint32_t col = (six[1] << 3) | (six[2] << 2) | (six[3] << 1) | six[4];

      const uint8_t v = hcfpga_deskpa_sbox[b][(row * 16) + col];

      for (uint32_t j = 0; j < 4; j++) s[4 * b + j] = (v >> (3 - j)) & 1;
    }

    uint8_t f[32];

    for (uint32_t i = 0; i < 32; i++) f[i] = s[hcfpga_deskpa_p[i] - 1];

    uint8_t nr[32];

    for (uint32_t i = 0; i < 32; i++) nr[i] = l[i] ^ f[i];

    memcpy (l, r, 32);
    memcpy (r, nr, 32);
  }

  // The preoutput block is R16 L16.

  uint8_t pre[64];

  memcpy (&pre[0],  r, 32);
  memcpy (&pre[32], l, 32);

  memset (ct, 0, 8);

  for (uint32_t i = 0; i < 64; i++)
  {
    const uint8_t bit = pre[hcfpga_deskpa_fp[i] - 1];

    ct[i / 8] |= (uint8_t) (bit << (7 - (i % 8)));
  }
}

// hashcat's PERM_OP and DES_FP (OpenCL/inc_cipher_des.h), on plain words: mode 14000's digest words
// 0..1 (the ciphertext's bytes as two little-endian words, through DES_IP) back to the ciphertext, as
// module_14000.c's encoder does it.

static inline void hcfpga_deskpa_perm_op (uint32_t *a, uint32_t *b, const uint32_t n, const uint32_t m)
{
  const uint32_t t = ((*a >> n) ^ *b) & m;

  *b ^= t;
  *a ^= t << n;
}

static inline void hcfpga_deskpa_digest_ct (const uint32_t digest[2], uint8_t ct[8])
{
  uint32_t r = digest[0];
  uint32_t l = digest[1];

  hcfpga_deskpa_perm_op (&l, &r,  1, 0x55555555);
  hcfpga_deskpa_perm_op (&r, &l,  8, 0x00ff00ff);
  hcfpga_deskpa_perm_op (&l, &r,  2, 0x33333333);
  hcfpga_deskpa_perm_op (&r, &l, 16, 0x0000ffff);
  hcfpga_deskpa_perm_op (&l, &r,  4, 0x0f0f0f0f);

  for (uint32_t i = 0; i < 4; i++)
  {
    ct[i]     = (uint8_t) (r >> (8 * i));
    ct[i + 4] = (uint8_t) (l >> (8 * i));
  }
}

#endif // HCFPGA_DES_KPA_REF_H
