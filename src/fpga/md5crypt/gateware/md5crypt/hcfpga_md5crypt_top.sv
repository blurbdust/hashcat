/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// md5crypt datapath top: H2C records in, C2H records out, John the Ripper's computing units in
// between. The ports are bcrypt's hcfpga_top.sv ports, with salt_len added and mode_dump dropped.
//
//   s_*      H2C, 32-bit words, first byte of the host buffer in bits 7:0
//   m_*      C2H, bytes, m_last on byte 31 of every 32-byte record
//   CLK      the stream, CSR and unit I/O clock (JtR's PKT_COMM_CLK)
//   CLK_CORE the clock of the units' cores, CPU and engine (JtR's CORE_CLK); may be CLK
//
// NUM_UNITS computing units of CORES_PER_UNIT MD5 cores each. A unit runs 4 threads per core, so
// NUM_UNITS * CORES_PER_UNIT * 4 candidates are in flight at once. CORES_PER_UNIT is 3, as
// upstream: core_ctrl.v spaces the cores' start slots for 12 threads.

`timescale 1ns / 1ps
module hcfpga_md5crypt_top #(
  parameter NUM_UNITS = 1,

  parameter CORES_PER_UNIT = 3,

  parameter WITH_CMP = 1
)(
  input  wire CLK,
  input  wire CLK_CORE,
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

  // Generation: bumped by every framing reset and every arm. Units cannot be reset, so their
  // results carry the generation they were fed under, and the collector drops the stale ones.
  reg [15:0] gen   = 0;
  reg        rst_q = 0;

  always @(posedge CLK)
  begin
    rst_q <= rst;

    if (((rst == 1'b1) && (rst_q == 1'b0)) || (batch_arm == 1'b1))
      gen <= gen + 1'b1;
  end

  wire [31:0] feed_status;

  wire [7:0]           unit_in;
  wire                 unit_in_ctrl;
  wire [NUM_UNITS-1:0] unit_in_wr_en;
  wire [NUM_UNITS-1:0] unit_in_afull;
  wire [NUM_UNITS-1:0] unit_in_ready;

  wire [NUM_UNITS-1:0]   unit_empty;
  wire [2*NUM_UNITS-1:0] unit_dout;
  wire [NUM_UNITS-1:0]   unit_rd_en;

  hcfpga_md5crypt_feed #(.NUM_UNITS(NUM_UNITS)) feed (
    .CLK(CLK), .rst(rst),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last),
    .frame_status(feed_status),
    .salt0(salt0), .salt1(salt1), .salt2(salt2), .salt3(salt3),
    .iter_count(iter_count), .salt_len(salt_len),
    .gen(gen),
    .unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl), .unit_in_wr_en(unit_in_wr_en),
    .unit_in_afull(unit_in_afull), .unit_in_ready(unit_in_ready)
  );

  genvar u;

  generate
  for (u = 0; u < NUM_UNITS; u = u + 1)
  begin : units
    md5unit #(.N_CORES(CORES_PER_UNIT), .UNIT_CONF(64'd0)) unit (
      .CLK(CLK_CORE),
      .unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl), .unit_in_wr_en(unit_in_wr_en[u]),
      .unit_in_afull(unit_in_afull[u]), .unit_in_ready(unit_in_ready[u]),
      .PKT_COMM_CLK(CLK),
      .dout(unit_dout[2*u +: 2]), .rd_en(unit_rd_en[u]), .empty(unit_empty[u])
    );
  end
  endgenerate

  wire       retire;
  wire [7:0] err_count;

  wire [7:0] r_data;
  wire       r_valid;
  wire       r_ready;
  wire       r_last;

  hcfpga_md5crypt_collect #(.NUM_UNITS(NUM_UNITS), .WITH_CMP(WITH_CMP)) collect (
    .CLK(CLK), .rst(rst),
    .gen(gen),
    .cmp_bitmap(cmp_bitmap), .cmp_load(cmp_load),
    .unit_empty(unit_empty), .unit_dout(unit_dout), .unit_rd_en(unit_rd_en),
    .retire(retire), .err_count(err_count),
    .m_data(r_data), .m_valid(r_valid), .m_ready(r_ready), .m_last(r_last)
  );

  hcfpga_c2h_eob eob (
    .CLK(CLK), .rst(rst),
    .retire(retire),
    .batch_target(batch_target), .batch_arm(batch_arm), .pad_recs(pad_recs),
    .retired_cnt(retired_cnt),
    .r_data(r_data), .r_valid(r_valid), .r_ready(r_ready), .r_last(r_last),
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last)
  );

  // bcrypt's frame status (slip, last_seen, slip count), plus the count of unit results whose
  // framing was off in bits 23:16.
  assign frame_status = {8'd0, err_count, feed_status[15:0]};

endmodule
