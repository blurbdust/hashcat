/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Feeder for John the Ripper's crypt-family computing units (md5crypt, sha256crypt, sha512crypt
// and phpass in src/ztex/fpga-*crypt/), in place of JtR's arbiter_tx.v.
//
// Takes hashcat's H2C records through hcfpga_h2c_intake.v and hands each candidate to a unit that
// is ready, as one unit input packet: a type byte 0 with ctrl, then the 40 header bytes arbiter_tx
// sends, then the key rounded up to KEY_ALIGN bytes, the last byte with ctrl. The unit stores the
// 40 + key bytes at the start of a free thread's memory, little-endian:
//
//   bytes  0..3   iteration count     (iter_count)
//   bytes  4..7   salt length         (salt_len)
//   bytes  8..23  salt, 16 bytes      (salt0..3, byte 0 in bits 7:0 of salt0)
//   bytes 24..27  candidate id        (JtR: word_id, pkt_id)
//   bytes 28..29  generation          (JtR: low half of gen_id)
//   bytes 30..31  zero
//   byte  32      key length
//   bytes 33..39  zero
//   bytes 40..    key, KEY_ALIGN-byte aligned, zero filled
//
// KEY_ALIGN is 4 for md5crypt and sha256crypt (32-bit thread memory), 8 for sha512crypt (64-bit;
// its arbiter_tx rounds the key "up to 64 bits"). The unit echoes bytes 24..31 back ahead of the
// result, which is how hcfpga_jtr_unit_collect.v learns the id and the generation (hcfpga_gen.v).
//
// A packet once started is always finished, even across rst: a unit given half a packet would take
// the next one's bytes as the rest of it. Only the intake and a send not yet started are reset.
//
// The unit side runs on CLK. JtR's sha256crypt and sha512crypt units have one clock for their
// input, output and cores; md5crypt's unit has its own core clock and crosses over inside.

`timescale 1ns / 1ps
module hcfpga_jtr_unit_feed #(
  parameter NUM_UNITS = 1,
  parameter PW_MAX    = 64,
  parameter KEY_ALIGN = 4
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

  input  wire [15:0] gen,

  output reg  [7:0]           unit_in       = 0,
  output reg                  unit_in_ctrl  = 0,
  output reg  [NUM_UNITS-1:0] unit_in_wr_en = 0,
  input  wire [NUM_UNITS-1:0] unit_in_afull,
  input  wire [NUM_UNITS-1:0] unit_in_ready
);

  localparam UW = (NUM_UNITS <= 1) ? 1 : $clog2(NUM_UNITS);

  localparam PW_WORDS = (PW_MAX + 3) / 4;
  localparam PW_AW    = (PW_WORDS <= 2) ? 1 : $clog2(PW_WORDS);

  localparam HDR_BYTES = 40;

  // Intake ----------------------------------------------------------------------------------------

  wire        rec_full;
  wire [7:0]  rec_len;
  wire [31:0] rec_id;
  wire [31:0] key_word;
  wire        rec_taken;
  wire        send_busy;

  wire [7:0]  key_idx;

  hcfpga_h2c_intake #(.PW_MAX(PW_MAX)) intake (
    .CLK(CLK), .rst(rst),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last),
    .frame_status(frame_status),
    .rec_valid(rec_full), .rec_len(rec_len), .rec_id(rec_id),
    .pw_rd_addr(key_idx[PW_AW+1:2]), .pw_rd_data(key_word),
    .rec_taken(rec_taken), .hold(send_busy)
  );

  // Unit transmitter ------------------------------------------------------------------------------

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

  reg [7:0]  byte_idx = 0;
  reg [7:0]  last_idx = 0;
  reg [15:0] gen_r    = 0;

  assign send_busy = (t_state == T_TYPE) | (t_state == T_DATA) | (t_state == T_DONE);
  assign rec_taken = (t_state == T_DONE);

  wire [8*HDR_BYTES-1:0] hdr = { 56'd0, rec_len, 16'd0, gen_r, rec_id, salt3, salt2, salt1, salt0, salt_len, iter_count };

  assign key_idx = byte_idx - HDR_BYTES;

  reg [7:0] key_byte;

  always @(*)
  begin
    case (key_idx[1:0])
      2'd0:    key_byte = key_word[31:24];
      2'd1:    key_byte = key_word[23:16];
      2'd2:    key_byte = key_word[15: 8];
      default: key_byte = key_word[ 7: 0];
    endcase
  end

  wire [7:0] tx_byte = (byte_idx < HDR_BYTES) ? hdr[8*byte_idx[5:0] +: 8]
                     : (key_idx < rec_len)    ? key_byte : 8'h00;

  // Key bytes on the wire: the length rounded up to KEY_ALIGN.
  wire [8:0] key_span = ({1'b0, rec_len} + (KEY_ALIGN - 1)) & ~(KEY_ALIGN - 1);

  wire [UW-1:0] unit_next = (unit_num == NUM_UNITS-1) ? {UW{1'b0}} : unit_num + 1'b1;

  always @(posedge CLK)
  begin
    unit_in_wr_en <= 0;
    unit_in_ctrl  <= 0;

    case (t_state)
    T_IDLE:
      if ((rec_full == 1'b1) && (rst == 1'b0))
        t_state <= T_SEARCH;

    T_SEARCH:
      if ((rec_full == 1'b0) || (rst == 1'b1))
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

    T_TYPE:
    begin
      unit_in                 <= 8'h00;
      unit_in_ctrl            <= 1'b1;
      unit_in_wr_en[unit_num] <= 1'b1;

      gen_r    <= gen;
      byte_idx <= 0;
      last_idx <= HDR_BYTES - 1 + key_span[7:0];

      t_state  <= T_DATA;
    end

    T_DATA:
      if (afull_r == 1'b0)
      begin
        unit_in                 <= tx_byte;
        unit_in_ctrl            <= (byte_idx == last_idx);
        unit_in_wr_en[unit_num] <= 1'b1;

        byte_idx <= byte_idx + 1'b1;

        if (byte_idx == last_idx) t_state <= T_DONE;
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

endmodule
