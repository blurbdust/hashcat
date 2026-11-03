/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`ifndef HCFPGA_IFACE_VH
`define HCFPGA_IFACE_VH

// The frame contract between hashcat's md5crypt bridge (src/bridges/bridge_fpga_md5crypt.c) and
// this design. Everything but the two md5crypt lines below is the same as
// src/fpga/bcrypt/hcfpga_iface.vh, see src/fpga/md5crypt/README.md.

`define HCFPGA_H2C_TAG         8'hbc

`define HCFPGA_C2H_REC_BYTES   32

`define HCFPGA_FLAG_OK         16'h0000
`define HCFPGA_FLAG_CORE_ERR   16'h0001

`define HCFPGA_FLAG_EOB        16'h8000

`define HCFPGA_CMP_BITS        128

// md5crypt: the unit keeps a candidate in 16 words of its thread memory (words 10 to 25)
`define HCFPGA_PW_MAX          64

// md5crypt: 16 digest bytes at C2H bytes 4..19, bytes 20..27 are zero
`define HCFPGA_DIGEST_BYTES    16

`endif
