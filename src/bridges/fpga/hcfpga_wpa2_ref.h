/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 */

#ifndef HCFPGA_WPA2_REF_H
#define HCFPGA_WPA2_REF_H

// wpa2 on the host, for the bridge's known-answer canary: the 32 bytes the device
// returns, as hashcat's digest_buf words. Self-contained, it runs once per salt. Check it against
// the bench's reference (src/fpga/wpa2/gateware/wpa2/wpa2_ref.py).

#include <stdint.h>
#include <string.h>

// HCFPGA-TODO: the real algorithm (src/bridges/fpga/hcfpga_md5crypt_ref.h is an example). Until
// the core is in, this is the stub's toy hash, byte j = pw[j % len] ^ salt[j % 16] ^ (rounds + j).

static void hcfpga_wpa2 (const uint8_t *pw, uint32_t pw_len, const uint8_t *salt, uint32_t salt_len, uint32_t rounds, uint32_t out[8])
{
  uint8_t s[16];
  uint8_t d[4 * 8];

  memset (s, 0, sizeof (s));
  memcpy (s, salt, (salt_len < 16) ? salt_len : 16);

  memset (d, 0, sizeof (d));

  for (uint32_t j = 0; j < 32; j++)
  {
    const uint8_t k = (pw_len > 0) ? pw[j % pw_len] : 0;

    d[j] = (uint8_t) (k ^ s[j % 16] ^ ((rounds + j) & 0xff));
  }

  for (uint32_t i = 0; i < 8; i++)
  {
    out[i] = (uint32_t) d[4 * i] | ((uint32_t) d[4 * i + 1] << 8) | ((uint32_t) d[4 * i + 2] << 16) | ((uint32_t) d[4 * i + 3] << 24);
  }
}

#endif // HCFPGA_WPA2_REF_H
