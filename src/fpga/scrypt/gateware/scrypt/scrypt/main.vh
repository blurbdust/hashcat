/*
 * This file is part of LiteX-Scrypt.
 *
 * Global parameters for scrypt FPGA cracker.
 *
 * SCRYPT_R and N_LOG2_MAX can be overridden by a generated defines file
 * (scrypt_params.v) compiled before this header.
 */

`include "log2.vh"

// Scrypt algorithm parameters (compile-time, overridable via scrypt_params.v)
`ifndef SCRYPT_R
`define	SCRYPT_R		1
`endif

`ifndef N_LOG2_MAX
`define	N_LOG2_MAX		15   // Max supported N = 2^15 = 32768
`endif

`ifndef V_TABLE_EXTERNAL
`define	V_TABLE_EXTERNAL	0    // 0=internal BRAM, 1=external DDR3
`endif

// Parameters for pkt_comm
`define	PKT_COMM_VERSION	2
`define	RANGES_MAX		4
`define	CHAR_BITS		8
`define	PLAINTEXT_LEN		(128 * `SCRYPT_R)   // SMix input: 128*r bytes
`define	PKT_MAX_TYPE		7

// must be power of 2; actual size for output fifo is 2 bytes less
`define	OUTPUT_FIFO_SIZE	8192

// outpkt
`define	OUTPKT_TYPE_MSB	2
`define	OUTPKT_TYPE_CMP_EQUAL	'b01
`define	OUTPKT_TYPE_PACKET_DONE	'b10
`define	OUTPKT_TYPE_RESULT	'b11
`define	OUTPKT_TYPE_CMP_RESULT	'b100

// scrypt result: 128*r bytes = ROMix output
`define	RESULT_LEN		(128 * `SCRYPT_R)

// comparator
`define	NUM_HASHES		512
`define	HASH_NUM_MSB	`MSB(`NUM_HASHES-1)
`define	HASH_COUNT_MSB	`MSB(`NUM_HASHES)
