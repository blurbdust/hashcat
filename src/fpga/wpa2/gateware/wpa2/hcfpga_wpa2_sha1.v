/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// SHA-1 compression of one 512-bit block, a round a cycle: the core of wpa2's setup unit
// (hcfpga_wpa2_engine.v), which hashes the blocks the PBKDF2 pipeline does not take (the key
// blocks and the salt block).
//
// start takes iv and blk; done pulses 82 cycles later with dig = iv + the state after round 79,
// which stays until the next start. iv and dig hold a in bits 159:128, blk word 0 in bits 511:480.
// As in the pipeline, e + K + W is added a round early.

`timescale 1ns / 1ps
module hcfpga_wpa2_sha1 (
  input  wire         CLK,

  input  wire         start,
  input  wire [159:0] iv,
  input  wire [511:0] blk,

  output reg          done = 0,
  output reg  [159:0] dig
);

  function [31:0] rol (input [31:0] x, input integer s);
    rol = (x << s) | (x >> (32 - s));
  endfunction

  function [31:0] k_of (input [6:0] t);
    k_of = (t < 20) ? 32'h5a827999 : (t < 40) ? 32'h6ed9eba1 : (t < 60) ? 32'h8f1bbcdc : 32'hca62c1d6;
  endfunction

  reg         run = 0;
  reg [6:0]   t   = 0;

  reg [159:0] iv_r;
  reg [31:0]  a, b, c, d, e, h;

  // W (t) .. W (t+15), W (t) in bits 511:480.
  reg [511:0] w;

  // Which round function the current round uses: 0 choose, 1 parity, 2 majority.
  reg [1:0]   fsel = 0;

  wire [31:0] f = (fsel == 2'd0) ? ((b & c) | (~b & d))
                : (fsel == 2'd2) ? ((b & c) | (b & d) | (c & d))
                :                  (b ^ c ^ d);

  wire [31:0] w_new = rol (w[511-32*13 -: 32] ^ w[511-32*8 -: 32] ^ w[511-32*2 -: 32] ^ w[511:480], 1);

  wire [6:0]  t1 = t + 1'b1;

  always @(posedge CLK)
  begin
    done <= 0;

    if (start == 1'b1)
    begin
      iv_r <= iv;
      { a, b, c, d, e } <= iv;
      h    <= iv[31:0] + 32'h5a827999 + blk[511:480];
      w    <= blk;
      fsel <= 2'd0;
      t    <= 0;
      run  <= 1'b1;
    end
    else if (run == 1'b1)
    begin
      if (t == 7'd80)
      begin
        dig  <= { iv_r[159:128] + a, iv_r[127:96] + b, iv_r[95:64] + c, iv_r[63:32] + d, iv_r[31:0] + e };
        done <= 1'b1;
        run  <= 1'b0;
      end
      else
      begin
        a <= rol (a, 5) + f + h;
        b <= a;
        c <= rol (b, 30);
        d <= c;
        e <= d;
        h <= d + k_of (t1) + w[479:448];
        w <= { w[479:0], w_new };

        fsel <= (t1 < 20) ? 2'd0 : (t1 < 40) ? 2'd1 : (t1 < 60) ? 2'd2 : 2'd1;
        t    <= t1;
      end
    end
  end

endmodule
