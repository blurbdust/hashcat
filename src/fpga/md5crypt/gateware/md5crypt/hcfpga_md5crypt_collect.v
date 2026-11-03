/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Result collector.
//
// Polls the computing units round robin and reads one result at a time over a unit's 2 bit
// output, the way John the Ripper's arbiter_rx does: one rd_en cycle, a start marker 2'b11, then
// 12 16-bit words, least significant dibit first, then 2'b00. The CPU program writes the words:
//
//   word  0..1   candidate id         (input bytes 24..27)
//   word  2      generation           (input bytes 28..29)
//   word  3      zero                 (input bytes 30..31)
//   word  4..11  the 16 digest bytes, MD5 output order, byte 0 in bits 7:0 of word 4
//
// A result of another generation is dropped and not retired: it belongs to a batch that a framing
// reset or a new arm abandoned. Otherwise the comparator looks the low 7 bits of digest byte 0
// up in the bitmap (hashcat's digest[0] & 0x7f, as on bcrypt). A miss retires the result without
// sending it, a hit sends one 32-byte C2H record:
//
//   bytes  0..3   candidate id, little-endian
//   bytes  4..19  digest, the 16 bytes in MD5 output order (hashcat's digest[k] is the
//                 little-endian word at 4+4k, no byte swap, unlike bcrypt)
//   bytes 20..27  zero
//   bytes 28..29  core_id, little-endian: the computing unit (3 MD5 cores, 12 threads each)
//   bytes 30..31  flags, little-endian: 0x0001 CORE_ERR when the unit's output framing was off
//
// retire pulses once per result retired, sent or filtered, after a sent record's last byte.

`timescale 1ns / 1ps
module hcfpga_md5crypt_collect #(
  parameter NUM_UNITS = 1,

  parameter WITH_CMP = 1
)(
  input  wire CLK,
  input  wire rst,

  input  wire [15:0]  gen,

  input  wire [127:0] cmp_bitmap,
  input  wire         cmp_load,

  input  wire [NUM_UNITS-1:0]   unit_empty,
  input  wire [2*NUM_UNITS-1:0] unit_dout,
  output reg  [NUM_UNITS-1:0]   unit_rd_en = 0,

  output reg  retire = 0,

  output reg  [7:0] err_count = 0,

  output wire [7:0] m_data,
  output wire       m_valid,
  input  wire       m_ready,
  output wire       m_last
);

  localparam UW = (NUM_UNITS <= 1) ? 1 : $clog2(NUM_UNITS);

  localparam C_WAIT = 3'd0, C_WAIT2 = 3'd1, C_RDEN = 3'd2, C_HDR = 3'd3, C_DATA = 3'd4, C_END = 3'd5, C_EMIT = 3'd6;

  reg [2:0]    state    = C_WAIT;
  reg [UW-1:0] unit_num = 0;

  reg [1:0] din     = 0;
  reg       empty_r = 1;

  always @(posedge CLK)
  begin
    din     <= unit_dout[2*unit_num +: 2];
    empty_r <= unit_empty[unit_num];
  end

  reg [127:0] bitmap = {128{1'b1}};

  always @(posedge CLK)
    if (cmp_load == 1'b1) bitmap <= cmp_bitmap;

  reg [191:0] cap    = 0;
  reg [6:0]   cnt    = 0;
  reg [7:0]   wait_t = 0;
  reg         bad    = 0;

  reg [255:0] frame   = 0;
  reg [4:0]   bytecnt = 0;

  assign m_data  = frame[7:0];
  assign m_valid = (state == C_EMIT);
  assign m_last  = (state == C_EMIT) & (bytecnt == 5'd31);

  wire [31:0]  r_id     = cap[31:0];
  wire [15:0]  r_gen    = cap[47:32];
  wire [127:0] r_digest = cap[191:64];

  wire [6:0] cmp_idx = r_digest[6:0];
  wire       cmp_hit = (WITH_CMP == 0) | bitmap[cmp_idx];

  wire [15:0] core_id = {{(16-UW){1'b0}}, unit_num};

  wire [UW-1:0] unit_next = (unit_num == NUM_UNITS-1) ? {UW{1'b0}} : unit_num + 1'b1;

  always @(posedge CLK)
  begin
    unit_rd_en <= 0;
    retire     <= 0;

    case (state)
    C_WAIT:
      if (empty_r == 1'b0)
        state <= C_RDEN;
      else
      begin
        unit_num <= unit_next;
        state    <= C_WAIT2;
      end

    C_WAIT2:
      state <= C_WAIT;

    // From here to C_END the unit streams its result no matter what, so rst does not cut in: the
    // result carries the old generation and is dropped at C_END.
    C_RDEN:
    begin
      unit_rd_en[unit_num] <= 1'b1;
      wait_t <= 0;
      bad    <= 0;
      state  <= C_HDR;
    end

    C_HDR:
      if (din != 2'b00)
      begin
        if (din != 2'b11) bad <= 1'b1;
        cnt   <= 0;
        state <= C_DATA;
      end
      else if (wait_t == 8'hff)
      begin
        if (err_count != 8'hff) err_count <= err_count + 1'b1;
        unit_num <= unit_next;
        state    <= C_WAIT2;
      end
      else
        wait_t <= wait_t + 1'b1;

    C_DATA:
    begin
      cap <= {din, cap[191:2]};
      cnt <= cnt + 1'b1;
      if (cnt == 7'd95) state <= C_END;
    end

    C_END:
    begin
      if ((din != 2'b00) || (bad == 1'b1))
      begin
        bad <= 1'b1;
        if (err_count != 8'hff) err_count <= err_count + 1'b1;
      end

      if ((r_gen != gen) || (rst == 1'b1))
      begin
        unit_num <= unit_next;
        state    <= C_WAIT2;
      end
      else if (cmp_hit == 1'b0)
      begin
        retire   <= 1'b1;
        unit_num <= unit_next;
        state    <= C_WAIT2;
      end
      else
      begin
        frame   <= { (((din != 2'b00) || bad) ? 16'h0001 : 16'h0000), core_id, 64'd0, r_digest, r_id };
        bytecnt <= 0;
        state   <= C_EMIT;
      end
    end

    C_EMIT:
      if (rst == 1'b1)
      begin
        unit_num <= unit_next;
        state    <= C_WAIT2;
      end
      else if (m_ready == 1'b1)
      begin
        if (bytecnt == 5'd31)
        begin
          retire   <= 1'b1;
          unit_num <= unit_next;
          state    <= C_WAIT2;
        end
        else
        begin
          frame   <= frame >> 8;
          bytecnt <= bytecnt + 1'b1;
        end
      end

    default:
      state <= C_WAIT;
    endcase
  end

endmodule
