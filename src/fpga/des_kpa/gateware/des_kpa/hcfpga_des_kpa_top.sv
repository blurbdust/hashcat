/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// DES known-plaintext datapath top: H2C records in, C2H records out, NUM_CORES pipelined DES cores
// with the amplifier generator and the comparator in between (hcfpga_des_kpa_engine.v).
//
// The shared parts (the hcfpga_* files beside this one) are the H2C intake, which delivers one whole
// record at a time, and the end-of-batch tail, which counts retired records and closes the batch. A
// record is a job, an 8-byte base word; the engine runs the amplifier over it and returns a C2H record
// per hit only, then retires the job.
//
// des_kpa's geometry: keys of 8 bytes, the plaintext in salt0..1 (hashcat's salt_buf[0..1], mode
// 14000's salt). salt2..3, iter_count and the comparator bitmap are not used: the engine compares
// against the targets in full.
//
// des_kpa's own registers, from 0x3c: amp_cnt, amp_lens (len - 1 of each position, position p in
// bits 8p+7..8p), amp_tab (a table write: position, index, character; amp_tab_we strobes it),
// tgt_mask, then tgt0_lo, tgt0_hi .. tgt3_lo, tgt3_hi (each target's ciphertext, salt word order).
//
// die_temp is the die temperature in XADC encoding (0 where the board has none) for the engine's
// thermal stop. frame_status bit 16 is set while that stop holds the generator, bit 17 once a core
// had a hit its FIFO could not take (until the framing reset).

`timescale 1ns / 1ps
module hcfpga_des_kpa_top #(
  parameter integer NUM_CORES = 1,

  // Accepted for the shared wrapper; this engine always compares in full.
  parameter WITH_CMP = 1,

  // Cores per group and groups per region of the engine's bus and collector tree.
  parameter integer GROUP  = 8,
  parameter integer REGION = 8,

  parameter integer IDLE_FLUSH = 4096,

  // The engine's thermal stop: the generator holds from THERM_HOT_C until below THERM_COOL_C.
  parameter integer THERM_HOT_C  = 85,
  parameter integer THERM_COOL_C = 75
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
  /* verilator lint_off UNUSEDSIGNAL */
  input  wire [31:0] salt2,
  input  wire [31:0] salt3,
  input  wire [31:0] iter_count,

  input  wire [127:0] cmp_bitmap,
  input  wire         cmp_load,
  /* verilator lint_on UNUSEDSIGNAL */

  input  wire [31:0]  batch_target,
  input  wire         batch_arm,

  input  wire [15:0]  pad_recs,

  output wire [31:0]  retired_cnt,

  output wire [7:0]  m_data,
  output wire        m_valid,
  input  wire        m_ready,
  output wire        m_last,

  input  wire [31:0] amp_cnt,
  input  wire [31:0] amp_lens,
  input  wire [31:0] amp_tab,
  input  wire        amp_tab_we,
  input  wire [31:0] tgt_mask,
  input  wire [31:0] tgt0_lo,
  input  wire [31:0] tgt0_hi,
  input  wire [31:0] tgt1_lo,
  input  wire [31:0] tgt1_hi,
  input  wire [31:0] tgt2_lo,
  input  wire [31:0] tgt2_hi,
  input  wire [31:0] tgt3_lo,
  input  wire [31:0] tgt3_hi
);

  localparam PW_MAX = 8;

  localparam NUM_TARGETS = 4;

  // The reset, the registers and the status belong to the SoC around the PCIe core, which can sit
  // across the chip from the engine: each crosses through a register here, the reset through two so
  // the fitter can place it in steps. Nothing the host does follows a register write that closely.
  reg rst_q1 = 1;
  reg rst_q2 = 1;

  reg [11:0]  die_temp_q;
  reg [63:0]  pt_q;
  reg [64*NUM_TARGETS-1:0] tgt_q;
  reg [NUM_TARGETS-1:0]    tgt_mask_q;
  reg [2:0]   amp_cnt_q;
  reg [31:0]  amp_lens_q;
  reg [31:0]  amp_tab_q;
  reg         amp_tab_we_q = 0;
  reg [31:0]  batch_target_q;
  reg         batch_arm_q = 0;
  reg [15:0]  pad_recs_q;

  always @(posedge CLK)
  begin
    rst_q1         <= rst;
    rst_q2         <= rst_q1;

    die_temp_q     <= die_temp;
    pt_q           <= {salt1, salt0};
    tgt_q          <= {tgt3_hi, tgt3_lo, tgt2_hi, tgt2_lo, tgt1_hi, tgt1_lo, tgt0_hi, tgt0_lo};
    tgt_mask_q     <= tgt_mask[NUM_TARGETS-1:0];
    amp_cnt_q      <= (amp_cnt > 32'd4) ? 3'd4 : amp_cnt[2:0];
    amp_lens_q     <= amp_lens;
    amp_tab_q      <= amp_tab;
    amp_tab_we_q   <= amp_tab_we;
    batch_target_q <= batch_target;
    batch_arm_q    <= batch_arm;
    pad_recs_q     <= pad_recs;
  end

  wire [31:0] intake_status;

  wire        rec_valid;
  wire [7:0]  rec_len;
  wire [31:0] rec_id;
  wire        pw_rd_addr;
  wire [31:0] pw_rd_data;
  wire        rec_taken;

  hcfpga_h2c_intake #(.PW_MAX(PW_MAX)) intake (
    .CLK(CLK), .rst(rst_q2),
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

  wire       therm_stop;
  wire       lost;

  hcfpga_des_kpa_engine #(.NUM_CORES(NUM_CORES), .NUM_TARGETS(NUM_TARGETS), .GROUP(GROUP), .REGION(REGION), .IDLE_FLUSH(IDLE_FLUSH),
                          .THERM_HOT_C(THERM_HOT_C), .THERM_COOL_C(THERM_COOL_C)) engine (
    .CLK(CLK), .rst(rst_q2),
    .die_temp(die_temp_q), .therm_stop(therm_stop), .lost(lost),
    .rec_valid(rec_valid), .rec_len(rec_len), .rec_id(rec_id),
    .pw_rd_addr(pw_rd_addr), .pw_rd_data(pw_rd_data), .rec_taken(rec_taken),
    .pt(pt_q),
    .tgt_ct(tgt_q),
    .tgt_mask(tgt_mask_q),
    .amp_cnt(amp_cnt_q), .amp_lens(amp_lens_q),
    .amp_tab(amp_tab_q), .amp_tab_we(amp_tab_we_q),
    .batch_target(batch_target_q), .batch_arm(batch_arm_q),
    .retire(retire),
    .r_data(r_data), .r_valid(r_valid), .r_ready(r_ready), .r_last(r_last)
  );

  wire [31:0] retired;

  hcfpga_c2h_eob eob (
    .CLK(CLK), .rst(rst_q2),
    .retire(retire),
    .batch_target(batch_target_q), .batch_arm(batch_arm_q), .pad_recs(pad_recs_q),
    .retired_cnt(retired),
    .r_data(r_data), .r_valid(r_valid), .r_ready(r_ready), .r_last(r_last),
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last)
  );

  // The shared frame status, bit 16 the thermal stop, bit 17 a lost hit.
  reg [31:0] frame_status_q = 0;
  reg [31:0] retired_q      = 0;

  always @(posedge CLK)
  begin
    frame_status_q <= {14'd0, lost, therm_stop, intake_status[15:0]};
    retired_q      <= retired;
  end

  assign frame_status = frame_status_q;
  assign retired_cnt  = retired_q;

endmodule
