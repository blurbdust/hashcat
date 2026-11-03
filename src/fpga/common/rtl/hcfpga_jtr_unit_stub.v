/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// A stand-in for one of John the Ripper's crypt-family computing units, with the same ports and
// the same packet and result protocol as md5unit, sha256unit and sha512unit, and a toy hash.
//
// For benches and scaffolds only: it lets hcfpga_jtr_unit_feed.v and hcfpga_jtr_unit_collect.v,
// and an algorithm top made by new_fpga_algo.py, be built, linted and run before the real unit is
// imported. It holds one packet at a time (a real unit holds one per thread).
//
// Input: a type byte with unit_in_ctrl, then the packet (40 header bytes, the key rounded up),
// the last byte with unit_in_ctrl. ready is high while it can take a packet; afull stays low.
// Output: once LATENCY cycles have passed, empty drops. One rd_en cycle later dout gives the 2'b11
// marker, then 4 + RESULT_LEN/2 16-bit words least significant dibit first (packet bytes 24..31,
// then the result), then 2'b00.
//
// The toy result, byte j of RESULT_LEN, with key = packet bytes 40.., len = packet byte 32,
// salt = packet bytes 8..23, iter = packet byte 0:
//
//   result[j] = key[j % len] ^ salt[j % 16] ^ ((iter + j) & 0xff)      (key[...] = 0 when len = 0)
//
// hcfpga_bench.py's toy_result() and the scaffold's C and Python references compute the same.

`timescale 1ns / 1ps
module hcfpga_jtr_unit_stub #(
  parameter RESULT_LEN = 16,
  parameter LATENCY    = 200
)(
  input  wire       CLK,

  input  wire [7:0] unit_in,
  input  wire       unit_in_ctrl,
  input  wire       unit_in_wr_en,
  output wire       unit_in_afull,
  output wire       unit_in_ready,

  output reg  [1:0] dout = 0,
  input  wire       rd_en,
  output wire       empty
);

  localparam OUT_BYTES = 8 + RESULT_LEN;

  localparam S_IDLE = 3'd0, S_RECV = 3'd1, S_CALC = 3'd2, S_WAIT = 3'd3, S_FULL = 3'd4, S_MARK = 3'd5, S_OUT = 3'd6;

  reg [2:0] state = S_IDLE;

  reg [7:0] pkt [0:255];
  reg [7:0] wptr = 0;

  reg [7:0] res [0:OUT_BYTES-1];

  reg [7:0]  j     = 0;
  reg [7:0]  kj    = 0;
  reg [15:0] timer = 0;
  reg [9:0]  oidx  = 0;

  assign unit_in_afull = 1'b0;
  assign unit_in_ready = (state == S_IDLE);
  assign empty         = (state != S_FULL);

  wire [7:0] klen = pkt[32];
  wire [7:0] kbyte = (klen == 0) ? 8'h00 : pkt[40 + kj];
  wire [7:0] obyte = res[oidx[9:2]];

  always @(posedge CLK)
  begin
    case (state)
    S_IDLE:
    begin
      dout <= 2'b00;
      if ((unit_in_wr_en == 1'b1) && (unit_in_ctrl == 1'b1))
      begin
        wptr  <= 0;
        state <= S_RECV;
      end
    end

    S_RECV:
      if (unit_in_wr_en == 1'b1)
      begin
        pkt[wptr] <= unit_in;
        wptr      <= wptr + 1'b1;
        if (unit_in_ctrl == 1'b1)
        begin
          j     <= 0;
          kj    <= 0;
          state <= S_CALC;
        end
      end

    // The 8 echoed bytes, then the toy result, one byte a cycle.
    S_CALC:
    begin
      if (j < 8)
        res[j] <= pkt[24 + j];
      else
      begin
        res[j] <= kbyte ^ pkt[8 + ((j - 8) & 15)] ^ (pkt[0] + (j - 8));
        kj     <= ((klen == 0) || (kj + 1 == klen)) ? 8'd0 : kj + 1'b1;
      end

      j <= j + 1'b1;

      if (j == OUT_BYTES - 1)
      begin
        timer <= 0;
        state <= S_WAIT;
      end
    end

    S_WAIT:
    begin
      timer <= timer + 1'b1;
      if (timer >= LATENCY) state <= S_FULL;
    end

    S_FULL:
      if (rd_en == 1'b1) state <= S_MARK;

    S_MARK:
    begin
      dout  <= 2'b11;
      oidx  <= 0;
      state <= S_OUT;
    end

    S_OUT:
    begin
      dout <= obyte[2*oidx[1:0] +: 2];
      oidx <= oidx + 1'b1;
      if (oidx == (4 * OUT_BYTES) - 1) state <= S_IDLE;
    end

    default:
      state <= S_IDLE;
    endcase
  end

endmodule
