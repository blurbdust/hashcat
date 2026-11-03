/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// sha512crypt datapath top: H2C records in, C2H records out, John the Ripper's sha512crypt computing
// units (unit/sha512unit.v) in between, on the shared JtR unit feeder and collector
// (src/fpga/common/rtl/). The ports are sha256crypt's top's.
//
// Everything around the units is shared: the feeder, the collector, the generation counter and the
// end-of-batch tail. What is sha512crypt's is the unit and its geometry, from JtR's arbiter_tx.v,
// arbiter_rx.v, main.vh, sha512.vh and cpu/program.vh:
//
//   PW_MAX       64   PLAINTEXT_LEN; the program keeps the key in thread memory words 5..12 (64-bit
//                     words) and writes the P byte sequence over it ("max.key_len=64" in sha512.vh)
//   KEY_ALIGN    8    64-bit thread memory ("Data size must be divisible by MEM_WIDTH bits";
//                     arbiter_tx sends the key "rounded up to 64 bits")
//   RESULT_LEN   64   the unit writes 4 ID words, then alt_result (words 24..31), 36 16-bit words
//   DIGEST_OFF   0    hashcat compares digest words 0..3 (DGST_POS0..3 of mode 1800): the first
//   DIGEST_BYTES 16   16 result bytes, in SHA-512 output order; the other 48 are read and dropped
//
// The whole unit, its input, output and cores, runs on CLK: like sha256crypt's, JtR's sha512crypt
// unit has one clock (upstream clocks it with CORE_CLK and crosses over in its arbiters).
//
// NUM_UNITS computing units of CORES_PER_UNIT SHA-512 cores each. A core interleaves 4 computations,
// so a unit runs 16 threads and NUM_UNITS * 16 candidates are in flight at once. CORES_PER_UNIT
// stays 4, as upstream: core_ctrl.v spaces the cores' start slots for 16 threads
// (COMP_INTERVAL = 352 / N_THREADS, "must be 22"), and sha512unit.v does not pass N_CORES on to
// unit_ctrl.v, which takes the 4 of sha512.vh.
//
// The unit's program has two entry points, sha512crypt (0, the one a unit starts in) and Drupal7
// (1, chosen by an initialization packet, type 1). The feeder only sends type 0 packets, so the
// units stay on sha512crypt.

`timescale 1ns / 1ps
module hcfpga_sha512crypt_top #(
  parameter NUM_UNITS      = 1,
  parameter CORES_PER_UNIT = 4,    // the unit's N_CORES, upstream's 4; the identity's cores= is NUM_UNITS * this

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
    sha512unit #(.N_CORES(CORES_PER_UNIT), .UNIT_CONF(64'd0)) unit (
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
