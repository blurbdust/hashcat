`timescale 1ns / 1ps
/*
 * This file is part of LiteX-Scrypt.
 *
 * sha256_core.v: simple iterative SHA-256 compression function
 *
 * Processes one 512-bit (64-byte) message block at a time.
 * 64 rounds, 1 round per cycle + load + finalize = 66 cycles per block.
 *
 * Interface:
 *   start + block + state_in -> wait 66 cycles -> done + state_out
 *
 * For initial hash, state_in = SHA-256 IV.
 * For continuation, state_in = previous state_out.
 *
 * This is intentionally simple: no pipelining, no multi-context.
 * Scrypt only needs PBKDF2-SHA256 with c=1, so throughput is not critical.
 */

// Modified for hashcat from LiteX-Scrypt's original.
// src/fpga/scrypt/PROVENANCE.md lists every change.

module sha256_core (
   input CLK,
   input start,
   input [511:0] block,        // 64-byte message block (big-endian words)
   input [255:0] state_in,     // 8 x 32-bit hash state (a,b,c,d,e,f,g,h)
   output reg [255:0] state_out,
   output reg done = 0
);

   // SHA-256 round constants K[0..63]
   (* ROM_STYLE="DISTRIBUTED" *)
   reg [31:0] K [0:63];
   initial begin
      K[ 0] = 32'h428a2f98; K[ 1] = 32'h71374491;
      K[ 2] = 32'hb5c0fbcf; K[ 3] = 32'he9b5dba5;
      K[ 4] = 32'h3956c25b; K[ 5] = 32'h59f111f1;
      K[ 6] = 32'h923f82a4; K[ 7] = 32'hab1c5ed5;
      K[ 8] = 32'hd807aa98; K[ 9] = 32'h12835b01;
      K[10] = 32'h243185be; K[11] = 32'h550c7dc3;
      K[12] = 32'h72be5d74; K[13] = 32'h80deb1fe;
      K[14] = 32'h9bdc06a7; K[15] = 32'hc19bf174;
      K[16] = 32'he49b69c1; K[17] = 32'hefbe4786;
      K[18] = 32'h0fc19dc6; K[19] = 32'h240ca1cc;
      K[20] = 32'h2de92c6f; K[21] = 32'h4a7484aa;
      K[22] = 32'h5cb0a9dc; K[23] = 32'h76f988da;
      K[24] = 32'h983e5152; K[25] = 32'ha831c66d;
      K[26] = 32'hb00327c8; K[27] = 32'hbf597fc7;
      K[28] = 32'hc6e00bf3; K[29] = 32'hd5a79147;
      K[30] = 32'h06ca6351; K[31] = 32'h14292967;
      K[32] = 32'h27b70a85; K[33] = 32'h2e1b2138;
      K[34] = 32'h4d2c6dfc; K[35] = 32'h53380d13;
      K[36] = 32'h650a7354; K[37] = 32'h766a0abb;
      K[38] = 32'h81c2c92e; K[39] = 32'h92722c85;
      K[40] = 32'ha2bfe8a1; K[41] = 32'ha81a664b;
      K[42] = 32'hc24b8b70; K[43] = 32'hc76c51a3;
      K[44] = 32'hd192e819; K[45] = 32'hd6990624;
      K[46] = 32'hf40e3585; K[47] = 32'h106aa070;
      K[48] = 32'h19a4c116; K[49] = 32'h1e376c08;
      K[50] = 32'h2748774c; K[51] = 32'h34b0bcb5;
      K[52] = 32'h391c0cb3; K[53] = 32'h4ed8aa4a;
      K[54] = 32'h5b9cca4f; K[55] = 32'h682e6ff3;
      K[56] = 32'h748f82ee; K[57] = 32'h78a5636f;
      K[58] = 32'h84c87814; K[59] = 32'h8cc70208;
      K[60] = 32'h90befffa; K[61] = 32'ha4506ceb;
      K[62] = 32'hbef9a3f7; K[63] = 32'hc67178f2;
   end

   // Message schedule W[0..15] (circular buffer, expanded on the fly)
   reg [31:0] W [0:15];

   // Working variables
   reg [31:0] a, b, c, d, e, f, g, h;
   // Initial hash values (saved for final addition)
   reg [31:0] H0, H1, H2, H3, H4, H5, H6, H7;

   reg [6:0] round;  // 0..63

   localparam ST_IDLE  = 2'd0;
   localparam ST_ROUND = 2'd1;
   localparam ST_FINAL = 2'd2;

   reg [1:0] state = ST_IDLE;

   // SHA-256 helper functions (combinational)
   function [31:0] rotr;
      input [31:0] val;
      input [4:0] amt;
      rotr = (val >> amt) | (val << (32 - amt));
   endfunction

   function [31:0] ch;
      input [31:0] x, y, z;
      ch = (x & y) ^ (~x & z);
   endfunction

   function [31:0] maj;
      input [31:0] x, y, z;
      maj = (x & y) ^ (x & z) ^ (y & z);
   endfunction

   function [31:0] sigma0;
      input [31:0] x;
      sigma0 = rotr(x, 5'd2) ^ rotr(x, 5'd13) ^ rotr(x, 5'd22);
   endfunction

   function [31:0] sigma1;
      input [31:0] x;
      sigma1 = rotr(x, 5'd6) ^ rotr(x, 5'd11) ^ rotr(x, 5'd25);
   endfunction

   function [31:0] gamma0;
      input [31:0] x;
      gamma0 = rotr(x, 5'd7) ^ rotr(x, 5'd18) ^ (x >> 3);
   endfunction

   function [31:0] gamma1;
      input [31:0] x;
      gamma1 = rotr(x, 5'd17) ^ rotr(x, 5'd19) ^ (x >> 10);
   endfunction

   // Current W value and next expanded W
   wire [31:0] Wt;
   wire [31:0] W_new;

   // For rounds 0-15: W[round] from loaded block
   // For rounds 16-63: expanded value
   // Rounds 16..63 use the word expanded for this round, not the one it replaces.
   assign Wt = (round < 16) ? W[round[3:0]] : W_new;

   // W expansion: W[i] = gamma1(W[i-2]) + W[i-7] + gamma0(W[i-15]) + W[i-16]
   assign W_new = gamma1(W[(round-2) & 4'hF]) + W[(round-7) & 4'hF]
                + gamma0(W[(round-15) & 4'hF]) + W[round[3:0]];

   // Round computation (combinational)
   wire [31:0] T1 = h + sigma1(e) + ch(e, f, g) + K[round] + Wt;
   wire [31:0] T2 = sigma0(a) + maj(a, b, c);

   integer k;

   always @(posedge CLK) begin
      done <= 0;

      case (state)
      ST_IDLE: begin
         if (start) begin
            // Load message block into W[0..15] (big-endian word order)
            for (k = 0; k < 16; k = k + 1)
               W[k] <= block[(15-k)*32 +: 32];

            // Load initial hash state
            a <= state_in[255:224]; H0 <= state_in[255:224];
            b <= state_in[223:192]; H1 <= state_in[223:192];
            c <= state_in[191:160]; H2 <= state_in[191:160];
            d <= state_in[159:128]; H3 <= state_in[159:128];
            e <= state_in[127: 96]; H4 <= state_in[127: 96];
            f <= state_in[ 95: 64]; H5 <= state_in[ 95: 64];
            g <= state_in[ 63: 32]; H6 <= state_in[ 63: 32];
            h <= state_in[ 31:  0]; H7 <= state_in[ 31:  0];

            round <= 0;
            state <= ST_ROUND;
         end
      end

      ST_ROUND: begin
         // Update working variables
         h <= g;
         g <= f;
         f <= e;
         e <= d + T1;
         d <= c;
         c <= b;
         b <= a;
         a <= T1 + T2;

         // W expansion: overwrite W[round % 16] for future use
         if (round >= 16)
            W[round[3:0]] <= W_new;

         round <= round + 1'b1;
         if (round == 63)
            state <= ST_FINAL;
      end

      ST_FINAL: begin
         // Add initial hash values
         state_out <= {
            a + H0, b + H1, c + H2, d + H3,
            e + H4, f + H5, g + H6, h + H7
         };
         done <= 1;
         state <= ST_IDLE;
      end
      endcase
   end

endmodule
