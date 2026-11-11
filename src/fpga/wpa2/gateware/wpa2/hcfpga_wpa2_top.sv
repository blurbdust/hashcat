/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// wpa2 datapath top: H2C records in, C2H records out, this algorithm's engine in between.
//
// The shared parts (the hcfpga_* files beside this one) are the H2C intake, which delivers one whole record at a
// time, and the end-of-batch tail, which counts retired candidates and closes the batch. The engine
// takes records from the intake, computes, and hands the tail whole 32-byte result records (PARTS
// per returned candidate) plus a retire pulse per candidate.
//
// The engine (hcfpga_wpa2_engine.v) holds a setup unit that computes each candidate's HMAC setup,
// PIPES PBKDF2 pipes (unrolled SHA-1 rings, RPS rounds a stage, of SLOTS candidates each, both PMK
// blocks of every candidate), the generation and a collector that sends each PMK as two C2H records (PARTS = 2).
// The setup unit holds the intake's record while it reads the password (hold).
//
// wpa2's own registers, from 0x3c: salt_len, then salt4..7 (ESSID bytes 16..31; salt0..3 carry
// bytes 0..15). iter_count is hashcat's salt_iter, 4095, and not used: the count is fixed.

`timescale 1ns / 1ps
module hcfpga_wpa2_top #(
  // PBKDF2 pipes, and SHA-1 rounds per pipe stage (1 or 2). The identity's cores= (the wrapper's
  // core_count) is the candidates in flight, PIPES * (80 / RPS + 4) / 2 (the engine's SLOTS a pipe).
  parameter PIPES = 1,
  parameter RPS   = 2,

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

  localparam PW_MAX       = 63;
  localparam DIGEST_BYTES = 32;

  // C2H records per candidate, 24 digest bytes each (the identity's parts= when above 1).
  localparam PARTS        = 2;

  localparam PW_WORDS = (PW_MAX + 3) / 4;
  localparam PW_AW    = (PW_WORDS <= 2) ? 1 : $clog2(PW_WORDS);

  wire [31:0] intake_status;

  wire             rec_valid;
  wire [7:0]       rec_len;
  wire [31:0]      rec_id;
  wire [PW_AW-1:0] pw_rd_addr;
  wire [31:0]      pw_rd_data;
  wire             rec_taken;
  wire             rec_hold;

  hcfpga_h2c_intake #(.PW_MAX(PW_MAX)) intake (
    .CLK(CLK), .rst(rst),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last),
    .frame_status(intake_status),
    .rec_valid(rec_valid), .rec_len(rec_len), .rec_id(rec_id),
    .pw_rd_addr(pw_rd_addr), .pw_rd_data(pw_rd_data),
    .rec_taken(rec_taken), .hold(rec_hold)
  );

  wire       retire;

  wire [7:0] r_data;
  wire       r_valid;
  wire       r_ready;
  wire       r_last;

  hcfpga_wpa2_engine #(.PIPES(PIPES), .RPS(RPS), .PW_MAX(PW_MAX), .DIGEST_BYTES(DIGEST_BYTES), .PARTS(PARTS), .WITH_CMP(WITH_CMP)) engine (
    .CLK(CLK), .rst(rst),
    .rec_valid(rec_valid), .rec_len(rec_len), .rec_id(rec_id),
    .pw_rd_addr(pw_rd_addr), .pw_rd_data(pw_rd_data), .rec_taken(rec_taken), .hold(rec_hold),
    .salt0(salt0), .salt1(salt1), .salt2(salt2), .salt3(salt3), .iter_count(iter_count),
    .salt_len(salt_len), .salt4(salt4), .salt5(salt5), .salt6(salt6), .salt7(salt7),
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

  // The shared frame status; bits 31:16 are not used.
  assign frame_status = {16'd0, intake_status[15:0]};

endmodule
