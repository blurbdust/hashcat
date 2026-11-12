/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// descrypt datapath top: H2C records in, C2H records out, NUM_CORES of John the Ripper's DES
// pipelines in between (hcfpga_descrypt_engine.v).
//
// The shared parts (the hcfpga_* files beside this one) are the H2C intake, which delivers one whole record at a
// time, and the end-of-batch tail, which counts retired candidates and closes the batch. The engine
// takes records from the intake, computes, and hands the tail whole 32-byte result records plus a
// retire pulse per candidate. It also sees the arm (batch_target, batch_arm): a batch's last
// candidates go into a ring that is not full as soon as no record of the batch is left.
//
// descrypt's geometry: passwords of up to 8 bytes (DES keys), 8 digest bytes (hashcat's
// digest_buf[0..1]), the 12-bit salt in salt0[11:0]. salt1..3 and iter_count are unused: the salt
// is the 2 characters of the hash and the count is crypt(3)'s 25, fixed in the ring. A core holds
// 16 candidates, the identity's cores= counts cores.

`timescale 1ns / 1ps
module hcfpga_descrypt_top #(
  // The identity's cores= (the wrapper's core_count): DES rings of 16 candidates each.
  parameter integer NUM_CORES = 1,

  parameter WITH_CMP = 1,

  // A partly filled ring starts after this many cycles without a record.
  parameter IDLE_FLUSH = 4096
)(
  input  wire CLK,
  input  wire rst,

  input  wire [31:0] s_data,
  input  wire        s_valid,
  output wire        s_ready,
  input  wire        s_last,

  output wire [31:0] frame_status,

  /* verilator lint_off UNUSEDSIGNAL */
  input  wire [31:0] salt0,
  input  wire [31:0] salt1,
  input  wire [31:0] salt2,
  input  wire [31:0] salt3,
  input  wire [31:0] iter_count,
  /* verilator lint_on UNUSEDSIGNAL */

  input  wire [127:0] cmp_bitmap,
  input  wire         cmp_load,

  input  wire [31:0]  batch_target,
  input  wire         batch_arm,

  input  wire [15:0]  pad_recs,

  output wire [31:0]  retired_cnt,

  output wire [7:0]  m_data,
  output wire        m_valid,
  input  wire        m_ready,
  output wire        m_last
);

  localparam PW_MAX = 8;

  wire [31:0] intake_status;

  wire        rec_valid;
  wire [7:0]  rec_len;
  wire [31:0] rec_id;
  wire        pw_rd_addr;
  wire [31:0] pw_rd_data;
  wire        rec_taken;

  hcfpga_h2c_intake #(.PW_MAX(PW_MAX)) intake (
    .CLK(CLK), .rst(rst),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last),
    .frame_status(intake_status),
    .rec_valid(rec_valid), .rec_len(rec_len), .rec_id(rec_id),
    .pw_rd_addr(pw_rd_addr), .pw_rd_data(pw_rd_data),
    .rec_taken(rec_taken), .hold(1'b0)
  );

  wire       retire;

  wire [7:0] r_data;
  wire       r_valid;
  wire       r_ready;
  wire       r_last;

  hcfpga_descrypt_engine #(.NUM_CORES(NUM_CORES), .WITH_CMP(WITH_CMP), .IDLE_FLUSH(IDLE_FLUSH)) engine (
    .CLK(CLK), .rst(rst),
    .rec_valid(rec_valid), .rec_len(rec_len), .rec_id(rec_id),
    .pw_rd_addr(pw_rd_addr), .pw_rd_data(pw_rd_data), .rec_taken(rec_taken),
    .salt(salt0[11:0]),
    .cmp_bitmap(cmp_bitmap), .cmp_load(cmp_load),
    .batch_target(batch_target), .batch_arm(batch_arm),
    .retire(retire),
    .r_data(r_data), .r_valid(r_valid), .r_ready(r_ready), .r_last(r_last)
  );

  hcfpga_c2h_eob eob (
    .CLK(CLK), .rst(rst),
    .retire(retire),
    .batch_target(batch_target), .batch_arm(batch_arm), .pad_recs(pad_recs),
    .retired_cnt(retired_cnt),
    .r_data(r_data), .r_valid(r_valid), .r_ready(r_ready), .r_last(r_last),
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last)
  );

  // The shared frame status; bits 31:16 are unused.
  assign frame_status = {16'd0, intake_status[15:0]};

endmodule
