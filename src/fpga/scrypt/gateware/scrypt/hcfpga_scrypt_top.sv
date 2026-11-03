/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// scrypt datapath top: H2C records in, C2H records out, this algorithm's engine in between.
//
// The shared parts (src/fpga/common/rtl/) are the H2C intake, which delivers one whole record at a
// time, and the end-of-batch tail, which counts retired candidates and closes the batch. The engine
// takes records from the intake, computes, and hands the tail whole 32-byte result records plus a
// retire pulse per candidate.
//
// The engine (hcfpga_scrypt_engine.v) holds NUM_CORES LiteX-Scrypt units, the transmitter that
// hands a record to an idle unit as one unit packet, the generation (the units cannot be reset) and
// the shared JtR result collector. A packet once started is always finished, so the engine holds the
// intake's record across a framing reset while it sends (hold).
//
// scrypt's own registers, from 0x3c: salt_len, then salt4..7 (salt bytes 16..31; salt0..3 carry
// bytes 0..15). iter_count is N.

`timescale 1ns / 1ps
module hcfpga_scrypt_top #(
  // The identity's cores= (the wrapper's core_count): scrypt units, one candidate in flight each.
  parameter NUM_CORES = 1,

  parameter WITH_CMP = 1
)(
  input  wire CLK,
  input  wire rst,

  input  wire [31:0] s_data,
  input  wire        s_valid,
  output wire        s_ready,
  input  wire        s_last,

  output wire [31:0] frame_status,

  input  wire [31:0] salt0,
  input  wire [31:0] salt1,
  input  wire [31:0] salt2,
  input  wire [31:0] salt3,
  input  wire [31:0] iter_count,

  input  wire [31:0] salt_len,
  input  wire [31:0] salt4,
  input  wire [31:0] salt5,
  input  wire [31:0] salt6,
  input  wire [31:0] salt7,

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

  localparam PW_MAX       = 64;
  localparam DIGEST_BYTES = 16;

  localparam PW_WORDS = (PW_MAX + 3) / 4;
  localparam PW_AW    = (PW_WORDS <= 2) ? 1 : $clog2(PW_WORDS);

  wire [31:0] intake_status;

  wire             rec_valid;
  wire [7:0]       rec_len;
  wire [31:0]      rec_id;
  wire [PW_AW-1:0] pw_rd_addr;
  wire [31:0]      pw_rd_data;
  wire             rec_taken;
  wire             send_busy;

  hcfpga_h2c_intake #(.PW_MAX(PW_MAX)) intake (
    .CLK(CLK), .rst(rst),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last),
    .frame_status(intake_status),
    .rec_valid(rec_valid), .rec_len(rec_len), .rec_id(rec_id),
    .pw_rd_addr(pw_rd_addr), .pw_rd_data(pw_rd_data),
    .rec_taken(rec_taken), .hold(send_busy)
  );

  wire       retire;
  wire [7:0] unit_errors;

  wire [7:0] r_data;
  wire       r_valid;
  wire       r_ready;
  wire       r_last;

  hcfpga_scrypt_engine #(.NUM_CORES(NUM_CORES), .PW_MAX(PW_MAX), .DIGEST_BYTES(DIGEST_BYTES), .WITH_CMP(WITH_CMP)) engine (
    .CLK(CLK), .rst(rst),
    .rec_valid(rec_valid), .rec_len(rec_len), .rec_id(rec_id),
    .pw_rd_addr(pw_rd_addr), .pw_rd_data(pw_rd_data), .rec_taken(rec_taken), .hold(send_busy),
    .salt0(salt0), .salt1(salt1), .salt2(salt2), .salt3(salt3), .iter_count(iter_count),
    .salt_len(salt_len), .salt4(salt4), .salt5(salt5), .salt6(salt6), .salt7(salt7),
    .cmp_bitmap(cmp_bitmap), .cmp_load(cmp_load),
    .batch_target(batch_target), .batch_arm(batch_arm),
    .retire(retire),
    .err_count(unit_errors),
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

  // The shared frame status; bits 23:16 count unit results whose framing was off, as md5crypt's do.
  assign frame_status = {8'd0, unit_errors, intake_status[15:0]};

endmodule
