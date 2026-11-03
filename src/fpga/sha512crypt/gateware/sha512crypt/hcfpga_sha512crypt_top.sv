/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// sha512crypt datapath top: H2C records in, C2H records out, John the Ripper's computing units in
// between, on the shared JtR unit feeder and collector (src/fpga/common/rtl/).
//
// HCFPGA-TODO: until the real unit is imported, the units are hcfpga_jtr_unit_stub.v (a toy hash
// with the JtR unit protocol), so this top builds, lints and benches from the start. Replace the
// stub instance with the unit (sha256crypt: sha256unit, sha512crypt: sha512unit, ...), and check
// the geometry against the unit's arbiter_tx.v and arbiter_rx.v:
//
//   PW_MAX       the longest key the unit's thread memory holds (JtR's PLAINTEXT_LEN)
//   KEY_ALIGN    4 for 32-bit thread memory, 8 for 64-bit (sha512crypt)
//   RESULT_LEN   JtR's RESULT_LEN: the result bytes after the four ID words
//   DIGEST_OFF   the first result byte forwarded to hashcat; DIGEST_BYTES of them, from there
//
// The units run on CLK. A unit with its own core clock (md5crypt's) gets a CLK_CORE port and
// HAS_CORE_CLK in the wrapper, as src/fpga/md5crypt does.

`timescale 1ns / 1ps
module hcfpga_sha512crypt_top #(
  parameter NUM_UNITS      = 1,
  parameter CORES_PER_UNIT = 4,    // the unit's N_CORES; the identity's cores= is NUM_UNITS * this

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
  localparam KEY_ALIGN    = 8;
  localparam RESULT_LEN   = 64;
  localparam DIGEST_OFF   = 0;
  localparam DIGEST_BYTES = 16;

  // Generation: units cannot be reset, so their results carry the generation they were fed under,
  // and the collector drops the stale ones.
  wire [15:0] gen;

  hcfpga_gen generation (.CLK(CLK), .rst(rst), .batch_arm(batch_arm), .gen(gen));

  wire [31:0] feed_status;

  wire [7:0]           unit_in;
  wire                 unit_in_ctrl;
  wire [NUM_UNITS-1:0] unit_in_wr_en;
  wire [NUM_UNITS-1:0] unit_in_afull;
  wire [NUM_UNITS-1:0] unit_in_ready;

  wire [NUM_UNITS-1:0]   unit_empty;
  wire [2*NUM_UNITS-1:0] unit_dout;
  wire [NUM_UNITS-1:0]   unit_rd_en;

  hcfpga_jtr_unit_feed #(.NUM_UNITS(NUM_UNITS), .PW_MAX(PW_MAX), .KEY_ALIGN(KEY_ALIGN)) feed (
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
    // HCFPGA-TODO: the real unit instead of the stub, with .N_CORES(CORES_PER_UNIT).
    hcfpga_jtr_unit_stub #(.RESULT_LEN(RESULT_LEN)) unit (
      .CLK(CLK),
      .unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl), .unit_in_wr_en(unit_in_wr_en[u]),
      .unit_in_afull(unit_in_afull[u]), .unit_in_ready(unit_in_ready[u]),
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

  hcfpga_jtr_unit_collect #(.NUM_UNITS(NUM_UNITS), .RESULT_LEN(RESULT_LEN), .DIGEST_OFF(DIGEST_OFF),
                            .DIGEST_BYTES(DIGEST_BYTES), .WITH_CMP(WITH_CMP)) collect (
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

  // The shared frame status (slip, last_seen, slip count), plus the count of unit results whose
  // framing was off in bits 23:16.
  assign frame_status = {8'd0, err_count, feed_status[15:0]};

endmodule
