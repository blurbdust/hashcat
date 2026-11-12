/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// wpa2 datapath top: H2C records in, C2H records out, this algorithm's engine in between.
//
// The shared parts (the hcfpga_* files beside this one) are the H2C intake, which delivers one whole record at a
// time, and the end-of-batch tail, which counts retired candidates and closes the batch. The engine
// takes records from the intake, computes, and hands the tail whole result records (PARTS per
// returned candidate, below) plus a retire pulse per candidate.
//
// The engine (hcfpga_wpa2_engine.v) holds a setup unit that computes each candidate's HMAC setup,
// PIPES PBKDF2 pipes (unrolled SHA-1 rings, RPS rounds a stage, of SLOTS candidates each, both PMK
// blocks of every candidate), the generation and a collector that sends each PMK in PARTS C2H records.
// The setup unit holds the intake's record while it reads the password (hold).
//
// wpa2's own registers, from 0x3c: salt_len, then salt4..7 (ESSID bytes 16..31; salt0..3 carry
// bytes 0..15). iter_count is hashcat's salt_iter, 4095, and not used: the count is fixed.
//
// die_temp is the die temperature in XADC encoding (0 where the board has none) for the engine's
// thermal stop; frame_status bit 16 is set while that stop holds new candidates back.
//
// PARTS = 2 sends each PMK as two 32-byte C2H records. PARTS = 1 sends it as one 40-byte record (the
// engine's contract), and the end-of-batch records of the shared tail get 8 zero bytes more here, so
// that every C2H record is 40 bytes long: the flags stay at bytes 30..31 of each. The identity's
// parts= says which one a board was built with.

`timescale 1ns / 1ps
module hcfpga_wpa2_top #(
  // PBKDF2 pipes, and SHA-1 rounds per pipe stage (1 or 2). The identity's cores= (the wrapper's
  // core_count) is the candidates in flight, PIPES * (80 / RPS + 4) / 2 (the engine's SLOTS a pipe).
  parameter PIPES = 1,
  parameter RPS   = 2,

  parameter WITH_CMP = 1,

  // The engine's thermal stop: no new candidate from THERM_HOT_C until below THERM_COOL_C.
  parameter THERM_HOT_C  = 85,
  parameter THERM_COOL_C = 75,

  // C2H records per candidate: 2 of 32 bytes, or 1 of 40 (above).
  parameter PARTS = 2
)(
  input  wire CLK,
  input  wire rst,

  input  wire [11:0] die_temp,

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

  wire therm_stop;

  hcfpga_wpa2_engine #(.PIPES(PIPES), .RPS(RPS), .PW_MAX(PW_MAX), .DIGEST_BYTES(DIGEST_BYTES), .PARTS(PARTS), .WITH_CMP(WITH_CMP),
                       .THERM_HOT_C(THERM_HOT_C), .THERM_COOL_C(THERM_COOL_C)) engine (
    .CLK(CLK), .rst(rst),
    .die_temp(die_temp), .therm_stop(therm_stop),
    .rec_valid(rec_valid), .rec_len(rec_len), .rec_id(rec_id),
    .pw_rd_addr(pw_rd_addr), .pw_rd_data(pw_rd_data), .rec_taken(rec_taken), .hold(rec_hold),
    .salt0(salt0), .salt1(salt1), .salt2(salt2), .salt3(salt3), .iter_count(iter_count),
    .salt_len(salt_len), .salt4(salt4), .salt5(salt5), .salt6(salt6), .salt7(salt7),
    .cmp_bitmap(cmp_bitmap), .cmp_load(cmp_load),
    .batch_target(batch_target), .batch_arm(batch_arm),
    .retire(retire),
    .r_data(r_data), .r_valid(r_valid), .r_ready(r_ready), .r_last(r_last)
  );

  wire [7:0] e_data;
  wire       e_valid;
  wire       e_ready;
  wire       e_last;

  hcfpga_c2h_eob eob (
    .CLK(CLK), .rst(rst),
    .retire(retire),
    .batch_target(batch_target), .batch_arm(batch_arm), .pad_recs(pad_recs),
    .retired_cnt(retired_cnt),
    .r_data(r_data), .r_valid(r_valid), .r_ready(r_ready), .r_last(r_last),
    .m_data(e_data), .m_valid(e_valid), .m_ready(e_ready), .m_last(e_last)
  );

  generate
    if (PARTS == 1)
    begin : rec40
      // The engine's records are 40 bytes, the tail's end-of-batch records 32: a record that ends
      // at byte 31 gets 8 zero bytes, and its end moves to the last of them.
      reg [5:0] bcnt = 0;
      reg       ext  = 0;
      reg [2:0] ecnt = 0;

      assign m_data  = (ext == 1'b1) ? 8'h00 : e_data;
      assign m_valid = ext | e_valid;
      assign e_ready = ~ext & m_ready;
      assign m_last  = (ext == 1'b1) ? (ecnt == 3'd7) : (e_last & (bcnt != 6'd31));

      always @(posedge CLK)
      begin
        if (rst == 1'b1)
        begin
          bcnt <= 0;
          ext  <= 0;
          ecnt <= 0;
        end
        else if (ext == 1'b1)
        begin
          if (m_ready == 1'b1)
          begin
            ecnt <= ecnt + 1'b1;

            if (ecnt == 3'd7)
            begin
              ext  <= 0;
              bcnt <= 0;
            end
          end
        end
        else if ((e_valid == 1'b1) && (m_ready == 1'b1))
        begin
          if (e_last == 1'b1)
          begin
            if (bcnt == 6'd31)
            begin
              ext  <= 1'b1;
              ecnt <= 0;
            end
            else
              bcnt <= 0;
          end
          else
            bcnt <= bcnt + 1'b1;
        end
      end
    end
    else
    begin : rec32
      assign m_data  = e_data;
      assign m_valid = e_valid;
      assign e_ready = m_ready;
      assign m_last  = e_last;
    end
  endgenerate

  // The shared frame status, and bit 16 the thermal stop.
  assign frame_status = {15'd0, therm_stop, intake_status[15:0]};

endmodule
