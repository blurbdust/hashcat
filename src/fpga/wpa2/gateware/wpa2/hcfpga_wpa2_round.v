/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// One stage of the PBKDF2 pipeline (hcfpga_wpa2_pipe.v): N SHA-1 rounds (1 or 2), T to T+N-1 of
// 0..79, one register stage. The pipeline compresses only the blocks the PBKDF2 loop hashes, a
// 20-byte message (a SHA-1 digest) padded as the tail of an 84-byte HMAC message, so message words
// 5..15 are constants:
//
//   W0..W4 the digest, W5 0x80000000, W6..W14 0, W15 0x2a0 ((64 + 20) * 8 bits).
//
// In:  the state of round T as a, b, c, d and h = e + K (T) + W (T), and the schedule window
//      W (T+1) .. W (T+16), W (T+1) in bits 31:0 of w_i.
// Out: the same for round T+N, a cycle later. The last stage gives the state after round 79, its e
//      in h_o.
//
// e + K + W is added a round early, so a round's critical path is f and one three-input add; with
// N = 2 the second round's f and its e + K + W come from the stage's inputs, and its add follows the
// first's. A window word that is a constant (W5..W15), or past W79, is a constant here too and not
// a register.

`timescale 1ns / 1ps
module hcfpga_wpa2_round #(
  parameter T  = 0,
  parameter N  = 1,
  parameter TW = 2
)(
  input  wire          CLK,

  input  wire [TW-1:0] tag_i,
  input  wire [31:0]   a_i,
  input  wire [31:0]   b_i,
  input  wire [31:0]   c_i,
  input  wire [31:0]   d_i,
  input  wire [31:0]   h_i,
  // A stage reads the window words its own schedule and h use; the others pass through.
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

  localparam LAST = (T + N - 1 == 79);

  function [31:0] rol (input [31:0] x, input integer s);
    rol = (x << s) | (x >> (32 - s));
  endfunction

  function [31:0] k_of (input integer r);
    k_of = (r < 20) ? 32'h5a827999 : (r < 40) ? 32'h6ed9eba1 : (r < 60) ? 32'h8f1bbcdc : 32'hca62c1d6;
  endfunction

  // The round function of round r.
  function [31:0] f_of (input integer r, input [31:0] x, input [31:0] y, input [31:0] z);
    f_of = (r < 20) ? ((x & y) | (~x & z))
         : (r < 40) ? (x ^ y ^ z)
         : (r < 60) ? ((x & y) | (x & z) | (y & z))
         :            (x ^ y ^ z);
  endfunction

  function [31:0] w_const (input integer g);
    w_const = (g == 5) ? 32'h80000000 : (g == 15) ? 32'h000002a0 : 32'h00000000;
  endfunction

  // Round T.
  wire [31:0] a1 = rol (a_i, 5) + f_of (T, b_i, c_i, d_i) + h_i;

  generate
    if (N == 1)
    begin : one
      always @(posedge CLK)
      begin
        tag_o <= tag_i;
        a_o   <= a1;
        b_o   <= a_i;
        c_o   <= rol (b_i, 30);
        d_o   <= c_i;
        h_o   <= LAST ? d_i : (d_i + k_of (T + 1) + w_i[31:0]);
      end
    end
    else
    begin : two
      // Round T+1 on round T's output: b = a, c = rol30 (b), d = c, e = d.
      wire [31:0] h1 = d_i + k_of (T + 1) + w_i[31:0];
      wire [31:0] g1 = f_of (T + 1, a_i, rol (b_i, 30), c_i) + h1;

      always @(posedge CLK)
      begin
        tag_o <= tag_i;
        a_o   <= rol (a1, 5) + g1;
        b_o   <= a1;
        c_o   <= rol (a_i, 30);
        d_o   <= rol (b_i, 30);
        h_o   <= LAST ? c_i : (c_i + k_of (T + 2) + w_i[63:32]);
      end
    end
  endgenerate

  // The window a cycle on: W (T+N+1) .. W (T+N+16). The N new words are
  // W (T+17+m) = rol1 (W (T+14+m) ^ W (T+9+m) ^ W (T+3+m) ^ W (T+1+m)), all from the input window.

  genvar j;

  generate
    for (j = 0; j < 16; j = j + 1)
    begin : win
      localparam G = T + N + 1 + j;
      localparam M = j - (16 - N);

      if ((G >= 5) && (G <= 15))
      begin : k
        assign w_o[32*j +: 32] = w_const (G);
      end
      else if (G > 79)
      begin : z
        assign w_o[32*j +: 32] = 32'd0;
      end
      else if (j >= 16 - N)
      begin : n
        reg [31:0] w;
        always @(posedge CLK) w <= rol (w_i[32*(13+M) +: 32] ^ w_i[32*(8+M) +: 32] ^ w_i[32*(2+M) +: 32] ^ w_i[32*M +: 32], 1);
        assign w_o[32*j +: 32] = w;
      end
      else
      begin : r
        reg [31:0] w;
        always @(posedge CLK) w <= w_i[32*(j+N) +: 32];
        assign w_o[32*j +: 32] = w;
      end
    end
  endgenerate

endmodule
