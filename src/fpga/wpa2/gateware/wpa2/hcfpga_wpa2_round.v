/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// One SHA-1 round of the PBKDF2 pipeline (hcfpga_wpa2_pipe.v): round T of 0..79, one register
// stage. The pipeline compresses only the blocks the PBKDF2 loop hashes, a 20-byte message (a SHA-1
// digest) padded as the tail of an 84-byte HMAC message, so message words 5..15 are constants:
//
//   W0..W4 the digest, W5 0x80000000, W6..W14 0, W15 0x2a0 ((64 + 20) * 8 bits).
//
// In:  the state of round T as a, b, c, d and h = e + K (T) + W (T), and the schedule window
//      W (T+1) .. W (T+16), W (T+1) in bits 31:0 of w_i.
// Out: the same for round T+1, a cycle later. Round 79 gives the state after the last round, its e
//      in h_o.
//
// e + K + W is added a round early, so a round's critical path is f and one three-input add. A
// window word that is a constant (W5..W15), or past W79, is a constant here too and not a register.

`timescale 1ns / 1ps
module hcfpga_wpa2_round #(
  parameter T  = 0,
  parameter TW = 2
)(
  input  wire          CLK,

  input  wire [TW-1:0] tag_i,
  input  wire [31:0]   a_i,
  input  wire [31:0]   b_i,
  input  wire [31:0]   c_i,
  input  wire [31:0]   d_i,
  input  wire [31:0]   h_i,
  // A round reads the window words its own schedule and h use; the others pass through.
  /* verilator lint_off UNUSEDSIGNAL */
  input  wire [511:0]  w_i,
  /* verilator lint_on UNUSEDSIGNAL */

  output reg  [TW-1:0] tag_o = 0,
  output reg  [31:0]   a_o,
  output reg  [31:0]   b_o,
  output reg  [31:0]   c_o,
  output reg  [31:0]   d_o,
  output reg  [31:0]   h_o,
  output wire [511:0]  w_o
);

  function [31:0] rol (input [31:0] x, input integer s);
    rol = (x << s) | (x >> (32 - s));
  endfunction

  function [31:0] k_of (input integer r);
    k_of = (r < 20) ? 32'h5a827999 : (r < 40) ? 32'h6ed9eba1 : (r < 60) ? 32'h8f1bbcdc : 32'hca62c1d6;
  endfunction

  function [31:0] w_const (input integer g);
    w_const = (g == 5) ? 32'h80000000 : (g == 15) ? 32'h000002a0 : 32'h00000000;
  endfunction

  // The round function of round T.
  wire [31:0] f = (T < 20) ? ((b_i & c_i) | (~b_i & d_i))
                : (T < 40) ? (b_i ^ c_i ^ d_i)
                : (T < 60) ? ((b_i & c_i) | (b_i & d_i) | (c_i & d_i))
                :            (b_i ^ c_i ^ d_i);

  wire [31:0] w1 = w_i[31:0];

  always @(posedge CLK)
  begin
    tag_o <= tag_i;
    a_o   <= rol (a_i, 5) + f + h_i;
    b_o   <= a_i;
    c_o   <= rol (b_i, 30);
    d_o   <= c_i;
    h_o   <= (T == 79) ? d_i : (d_i + k_of (T + 1) + w1);
  end

  // The window a cycle on: W (T+2) .. W (T+17), the new word
  // W (T+17) = rol1 (W (T+14) ^ W (T+9) ^ W (T+3) ^ W (T+1)).

  // Not used by the last rounds, whose new word would be past W79.
  /* verilator lint_off UNUSEDSIGNAL */
  wire [31:0] w_new = rol (w_i[32*13 +: 32] ^ w_i[32*8 +: 32] ^ w_i[32*2 +: 32] ^ w_i[31:0], 1);
  /* verilator lint_on UNUSEDSIGNAL */

  genvar j;

  generate
    for (j = 0; j < 16; j = j + 1)
    begin : win
      localparam G = T + 2 + j;

      if ((G >= 5) && (G <= 15))
      begin : k
        assign w_o[32*j +: 32] = w_const (G);
      end
      else if (G > 79)
      begin : z
        assign w_o[32*j +: 32] = 32'd0;
      end
      else if (j == 15)
      begin : n
        reg [31:0] w;
        always @(posedge CLK) w <= w_new;
        assign w_o[32*j +: 32] = w;
      end
      else
      begin : r
        reg [31:0] w;
        always @(posedge CLK) w <= w_i[32*(j+1) +: 32];
        assign w_o[32*j +: 32] = w;
      end
    end
  endgenerate

endmodule
