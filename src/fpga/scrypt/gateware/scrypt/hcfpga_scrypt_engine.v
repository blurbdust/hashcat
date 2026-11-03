/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// scrypt's engine: NUM_CORES LiteX-Scrypt units (scrypt/scrypt_unit.v, full mode, r from 1 to
// R_MAX at run time, N up to 2^N_LOG2_MAX), a transmitter that hands each H2C record to an idle unit as one unit packet, and the shared JtR
// result collector (src/fpga/common/rtl/hcfpga_jtr_unit_collect.v), whose read the unit's output
// matches.
//
// Contract with the top (src/fpga/common/template, the custom engine):
//
// - A record is ready while rec_valid is high: rec_len, rec_id, and the password through
//   pw_rd_addr/pw_rd_data (word k = bytes 4k..4k+3, big-endian). rec_taken pulses when its packet
//   is out; hold is high while the packet is being sent, so the intake keeps the record across a
//   framing reset (a unit given half a packet would take the next one's bytes as the rest of it).
// - Each candidate's result comes back through the collector: one 32-byte C2H record and a retire
//   after its last byte, or a retire alone when the comparator filters it.
// - The units cannot be reset. A candidate carries the generation (hcfpga_gen.v) in its ID bytes,
//   and the collector drops a result of another generation without retiring it.
//
// The unit packet, one byte per write, the type byte and the end marker with ctrl (scrypt_unit.v's
// header comment):
//
//   type      0x00, ctrl
//   0..3      log2 (N), little-endian       (iter_count is N, a power of two)
//   4..7      salt length, little-endian    (salt_len)
//   8..39     salt, 32 bytes                (salt0..3, then salt4..7, byte 0 in bits 7:0 of salt0)
//   40..43    r, little-endian              (the r register, 1 to R_MAX)
//   44..107   key, 64 bytes, zero filled    (the unit takes every payload byte before the IDs as key)
//   108..111  candidate id, little-endian
//   112..113  generation, little-endian
//   114..115  zero
//   end       0x00, ctrl
//
// The unit's input FIFO reports full with no margin, so the transmitter writes at most every other
// cycle and checks the unit's full flag as it is, not registered. A unit takes one packet while it
// is idle and is busy until its result has been read.

`timescale 1ns / 1ps
module hcfpga_scrypt_engine #(
  parameter NUM_CORES    = 1,
  parameter PW_MAX       = 64,
  parameter DIGEST_BYTES = 16,
  parameter WITH_CMP     = 1,
  parameter N_LOG2_MAX   = 15,     // the V table holds 2^N_LOG2_MAX blocks: N up to that
  parameter R_MAX        = 8,      // the widest r the units compute; r comes at run time
  parameter GAP_LOG2     = 0,      // ROMix lookup gap G = 2^GAP_LOG2: the V table holds every G-th block

  parameter PW_WORDS = (PW_MAX + 3) / 4,
  parameter PW_AW    = (PW_WORDS <= 2) ? 1 : $clog2(PW_WORDS)
)(
  input  wire CLK,
  input  wire rst,

  input  wire              rec_valid,
  input  wire [7:0]        rec_len,
  input  wire [31:0]       rec_id,
  output wire [PW_AW-1:0]  pw_rd_addr,
  input  wire [31:0]       pw_rd_data,
  output wire              rec_taken,
  output wire              hold,

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
  input  wire [31:0] scrypt_r,

  input  wire [127:0] cmp_bitmap,
  input  wire         cmp_load,

  /* verilator lint_off UNUSEDSIGNAL */
  input  wire [31:0]  batch_target,
  /* verilator lint_on UNUSEDSIGNAL */
  input  wire         batch_arm,

  output wire retire,

  output wire [7:0] err_count,

  output wire [7:0] r_data,
  output wire       r_valid,
  input  wire       r_ready,
  output wire       r_last
);

  localparam UW = (NUM_CORES <= 1) ? 1 : $clog2(NUM_CORES);

  localparam [UW-1:0] LAST_UNIT = NUM_CORES[UW-1:0] - 1'b1;

  localparam CFG_BYTES = 44;
  localparam KEY_BYTES = 64;
  localparam ID_BYTES  = 8;
  localparam END_IDX   = CFG_BYTES + KEY_BYTES + ID_BYTES;   // 116, the end marker

  // Generation ------------------------------------------------------------------------------------

  wire [15:0] gen;

  hcfpga_gen gen_i (.CLK(CLK), .rst(rst), .batch_arm(batch_arm), .gen(gen));

  // log2 (N) --------------------------------------------------------------------------------------

  reg [4:0] n_log2_c;
  reg [4:0] n_log2 = 0;

  integer b;

  always @(*)
  begin
    n_log2_c = 5'd0;
    for (b = 1; b <= N_LOG2_MAX; b = b + 1)
      if (iter_count[b] == 1'b1) n_log2_c = b[4:0];
  end

  always @(posedge CLK) n_log2 <= n_log2_c;

  // Units -----------------------------------------------------------------------------------------

  reg  [7:0]           unit_in       = 0;
  reg                  unit_in_ctrl  = 0;
  reg  [NUM_CORES-1:0] unit_in_wr_en = 0;
  wire [NUM_CORES-1:0] unit_in_afull;
  wire [NUM_CORES-1:0] unit_in_ready;

  wire [NUM_CORES-1:0]   unit_empty;
  wire [2*NUM_CORES-1:0] unit_dout;
  wire [NUM_CORES-1:0]   unit_rd_en;

  genvar u;

  generate
    for (u = 0; u < NUM_CORES; u = u + 1)
    begin : units
      // The external V table ports are unused with V_TABLE_EXTERNAL 0.
      /* verilator lint_off PINCONNECTEMPTY */
      scrypt_unit #(.R(R_MAX), .N_LOG2_MAX(N_LOG2_MAX), .FULL_MODE(1), .V_TABLE_EXTERNAL(0), .GAP_LOG2(GAP_LOG2)) unit (
        .CLK(CLK),
        .unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl), .unit_in_wr_en(unit_in_wr_en[u]),
        .unit_in_afull(unit_in_afull[u]), .unit_in_ready(unit_in_ready[u]),
        .dout(unit_dout[2*u +: 2]), .rd_en(unit_rd_en[u]), .empty(unit_empty[u]),
        .vt_we(), .vt_waddr(), .vt_wdata(), .vt_raddr(), .vt_rdata({1024*R_MAX{1'b0}}), .vt_rd_req(),
        .vt_rd_valid(1'b0), .vt_wr_req(), .vt_wr_done(1'b0)
      );
      /* verilator lint_on PINCONNECTEMPTY */
    end
  endgenerate

  // Transmitter -----------------------------------------------------------------------------------

  localparam T_IDLE = 3'd0, T_SEARCH = 3'd1, T_SEARCH2 = 3'd2, T_TYPE = 3'd3, T_DATA = 3'd4, T_DONE = 3'd5;

  reg [2:0]    t_state  = T_IDLE;
  reg [UW-1:0] unit_num = 0;

  reg ready_r = 0;
  reg afull_r = 1;

  always @(posedge CLK)
  begin
    ready_r <= unit_in_ready[unit_num];
    afull_r <= unit_in_afull[unit_num];
  end

  wire afull_now = unit_in_afull[unit_num];

  reg [7:0]  byte_idx = 0;
  reg        gap      = 0;
  reg [15:0] gen_r    = 0;

  assign hold      = (t_state == T_TYPE) | (t_state == T_DATA) | (t_state == T_DONE);
  assign rec_taken = (t_state == T_DONE);

  wire [8*CFG_BYTES-1:0] cfg = { scrypt_r, salt7, salt6, salt5, salt4, salt3, salt2, salt1, salt0, salt_len, 27'd0, n_log2 };
  wire [8*ID_BYTES-1:0]  ids = { 16'd0, gen_r, rec_id };

  wire [7:0] key_idx = byte_idx - CFG_BYTES;
  wire [2:0] id_idx  = byte_idx[2:0] - 3'd4;   // (byte_idx - 108) mod 8

  assign pw_rd_addr = key_idx[PW_AW+1:2];

  reg [7:0] key_byte;

  always @(*)
  begin
    case (key_idx[1:0])
      2'd0:    key_byte = pw_rd_data[31:24];
      2'd1:    key_byte = pw_rd_data[23:16];
      2'd2:    key_byte = pw_rd_data[15: 8];
      default: key_byte = pw_rd_data[ 7: 0];
    endcase
  end

  wire [7:0] tx_byte = (byte_idx < CFG_BYTES)              ? cfg[8*byte_idx[5:0] +: 8]
                     : (byte_idx < CFG_BYTES + KEY_BYTES)  ? ((key_idx < rec_len) ? key_byte : 8'h00)
                     : (byte_idx < END_IDX)                ? ids[8*id_idx +: 8]
                     : 8'h00;

  wire [UW-1:0] unit_next = (unit_num == LAST_UNIT) ? {UW{1'b0}} : unit_num + 1'b1;

  always @(posedge CLK)
  begin
    unit_in_wr_en <= 0;
    unit_in_ctrl  <= 0;

    case (t_state)
    T_IDLE:
      if ((rec_valid == 1'b1) && (rst == 1'b0))
        t_state <= T_SEARCH;

    T_SEARCH:
      if ((rec_valid == 1'b0) || (rst == 1'b1))
        t_state <= T_IDLE;
      else if ((ready_r == 1'b1) && (afull_r == 1'b0))
        t_state <= T_TYPE;
      else
      begin
        unit_num <= unit_next;
        t_state  <= T_SEARCH2;
      end

    T_SEARCH2:
      t_state <= T_SEARCH;

    // From here to T_DONE the packet goes out whatever happens: hold keeps the record in the intake.
    T_TYPE:
      if (afull_now == 1'b0)
      begin
        unit_in                 <= 8'h00;
        unit_in_ctrl            <= 1'b1;
        unit_in_wr_en[unit_num] <= 1'b1;

        gen_r    <= gen;
        byte_idx <= 0;
        gap      <= 1'b1;

        t_state  <= T_DATA;
      end

    T_DATA:
      if (gap == 1'b1)
        gap <= 1'b0;
      else if (afull_now == 1'b0)
      begin
        unit_in                 <= tx_byte;
        unit_in_ctrl            <= (byte_idx == END_IDX);
        unit_in_wr_en[unit_num] <= 1'b1;

        byte_idx <= byte_idx + 1'b1;
        gap      <= 1'b1;

        if (byte_idx == END_IDX) t_state <= T_DONE;
      end

    T_DONE:
    begin
      unit_num <= unit_next;
      t_state  <= T_IDLE;
    end

    default:
      t_state <= T_IDLE;
    endcase
  end

  // Collector -------------------------------------------------------------------------------------

  hcfpga_jtr_unit_collect #(
    .NUM_UNITS(NUM_CORES), .RESULT_LEN(32), .DIGEST_OFF(0), .DIGEST_BYTES(DIGEST_BYTES), .CMP_BYTE(0), .WITH_CMP(WITH_CMP)
  ) collect (
    .CLK(CLK), .rst(rst),
    .gen(gen),
    .cmp_bitmap(cmp_bitmap), .cmp_load(cmp_load),
    .unit_empty(unit_empty), .unit_dout(unit_dout), .unit_rd_en(unit_rd_en),
    .retire(retire),
    .err_count(err_count),
    .m_data(r_data), .m_valid(r_valid), .m_ready(r_ready), .m_last(r_last)
  );

endmodule
