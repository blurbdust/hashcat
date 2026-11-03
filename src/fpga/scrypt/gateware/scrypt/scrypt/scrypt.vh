/*
 * This file is part of LiteX-Scrypt.
 *
 * Scrypt-specific parameters and constants.
 */

`ifndef _SCRYPT_VH_
`define _SCRYPT_VH_

// Unit I/O widths (same as wpa2/sha256crypt for arbiter compatibility)
`define UNIT_INPUT_WIDTH   8
`define UNIT_OUTPUT_WIDTH  2

// Scrypt parameters (defaults, can be overridden via CMP_CONFIG at runtime)
`define SCRYPT_N_DEFAULT     1024    // Cost parameter (must be power of 2)
`define SCRYPT_N_LOG2_DEFAULT 10     // log2(1024)

// Derived sizes based on compile-time R
`define SCRYPT_CHUNK_BYTES   (128 * `SCRYPT_R)    // = 128 * r
`define SCRYPT_BLOCK_BYTES   64                    // Salsa20/8 block size
`define SCRYPT_BLOCK_WORDS   16                    // 64 / 4
`define SCRYPT_CHUNK_WORDS   (32 * `SCRYPT_R)     // chunk_bytes / 4
`define SCRYPT_NUM_BLOCKS    (2 * `SCRYPT_R)      // Number of 64-byte blocks
`define SCRYPT_DATA_WIDTH    (1024 * `SCRYPT_R)   // Total data width in bits

// CMP_CONFIG layout (matches scrypt_cmp_config.v):
// Byte 0:     unused (0x00)
// Byte 1:     salt_len (1-32)
// Byte 2-33:  salt (padded to 32 bytes)
// Byte 34-37: N_log2 (LE32) -- log2 of scrypt N parameter
// Byte 38-41: r_actual (LE32) -- runtime scrypt r parameter
// Byte 42-43: num_hashes (LE16)
// Byte 44+:   hash data (4 bytes each)
// Final:      magic (0xCC)
//
// Distributed RAM layout (read by arbiter_tx):
//   [0-3]:  N_log2 (LE32)
//   [4-7]:  salt_len (byte 4, bytes 5-7 = 0)
//   [8-39]: salt (32 bytes)
//   [40-43]: r_actual (LE32)

`define SCRYPT_SALT_MAX_LEN  32

`endif
