/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`ifndef HCFPGA_COMMON_IFACE_VH
`define HCFPGA_COMMON_IFACE_VH

// The frame contract between hashcat's shared FPGA bridge (src/bridges/fpga/hcfpga_bridge.c) and
// every algorithm built on src/fpga/common. bcrypt keeps its own copy (src/fpga/bcrypt/
// hcfpga_iface.vh); the values below are the same.
//
// H2C record: word 0 is (HCFPGA_H2C_TAG << 24) | len, word 1 the candidate id, then the password
// big-endian four bytes per word. C2H record: HCFPGA_C2H_REC_BYTES bytes, id at 0..3, digest from 4
// (at most HCFPGA_DIGEST_FIELD bytes), core_id at 28..29, flags at 30..31.
//
// What differs per algorithm is a parameter of its top, not a define here: PW_MAX (the longest
// password the core takes), the digest bytes it returns, and its extra registers from 0x3c. The
// bridge hook file (src/bridges/bridge_fpga_<algo>.c) states the same values.

`define HCFPGA_H2C_TAG         8'hbc

`define HCFPGA_C2H_REC_BYTES   32

`define HCFPGA_DIGEST_FIELD    24

`define HCFPGA_FLAG_OK         16'h0000
`define HCFPGA_FLAG_CORE_ERR   16'h0001

`define HCFPGA_FLAG_EOB        16'h8000

`define HCFPGA_CANARY_ID       32'hfffffffe

`define HCFPGA_CMP_BITS        128

`endif
