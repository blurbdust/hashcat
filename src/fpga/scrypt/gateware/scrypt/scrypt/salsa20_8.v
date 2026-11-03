`timescale 1ns / 1ps
/*
 * This file is part of LiteX-Scrypt.
 *
 * salsa20_8.v — Salsa20/8 core (2-stage pipeline, 8 cycles per call)
 *
 * Takes 512 bits (16 x 32-bit LE words), applies 8 rounds
 * (4 double-rounds, two cycles each), adds original input.
 *
 * Pipeline: Each double-round is split into two stages:
 *   Stage 1 (COL): Column round computed combinationally, registered into cx_reg[]
 *   Stage 2 (ROW): Row round computed from cx_reg[], registered into x[]
 *
 * This halves the combinational depth from ~11ns to ~5.5ns, enabling
 * 150+ MHz operation on Kintex-7.
 *
 * Interface:
 *   start + data_in -> wait 9 cycles -> done + data_out
 *
 * Cycle budget:
 *   Cycle 0: Load (start)
 *   Cycles 1-8: 4 double-rounds × 2 stages each (COL, ROW)
 *   Cycle 9: Add original, assert done
 */

module salsa20_8 (
   input CLK,
   input start,
   input [511:0] data_in,
   output reg [511:0] data_out,
   output reg done = 0
);

   // Working state: 16 x 32-bit words
   reg [31:0] x [0:15];
   // Pipeline register: column round output
   reg [31:0] cx_reg [0:15];
   // Original input for final addition
   reg [31:0] orig [0:15];

   reg [2:0] round_cnt;  // 0..3 for 4 double-rounds

   localparam ST_IDLE   = 3'd0;
   localparam ST_COL    = 3'd1;  // Column round: compute cx[], register into cx_reg[]
   localparam ST_ROW    = 3'd2;  // Row round: compute rx[] from cx_reg[], register into x[]
   localparam ST_ADD    = 3'd3;
   localparam ST_DONE   = 3'd4;

   reg [2:0] state = ST_IDLE;

   // Rotate-left helper
   function [31:0] rotl;
      input [31:0] val;
      input [4:0] amt;
      rotl = (val << amt) | (val >> (32 - amt));
   endfunction

   // Intermediate wires for column round (from x[])
   wire [31:0] cx [0:15];
   // Intermediate wires for row round (from cx_reg[])
   wire [31:0] rx [0:15];

   // Column round (combinational, reads x[])
   assign cx[ 4] = x[ 4] ^ rotl(x[ 0] + x[12],  5'd7);
   assign cx[ 8] = x[ 8] ^ rotl(cx[4]  + x[ 0],  5'd9);
   assign cx[12] = x[12] ^ rotl(cx[8]  + cx[4],  5'd13);
   assign cx[ 0] = x[ 0] ^ rotl(cx[12] + cx[8],  5'd18);

   assign cx[ 9] = x[ 9] ^ rotl(x[ 5] + x[ 1],  5'd7);
   assign cx[13] = x[13] ^ rotl(cx[9]  + x[ 5],  5'd9);
   assign cx[ 1] = x[ 1] ^ rotl(cx[13] + cx[9],  5'd13);
   assign cx[ 5] = x[ 5] ^ rotl(cx[1]  + cx[13], 5'd18);

   assign cx[14] = x[14] ^ rotl(x[10] + x[ 6],  5'd7);
   assign cx[ 2] = x[ 2] ^ rotl(cx[14] + x[10],  5'd9);
   assign cx[ 6] = x[ 6] ^ rotl(cx[2]  + cx[14], 5'd13);
   assign cx[10] = x[10] ^ rotl(cx[6]  + cx[2],  5'd18);

   assign cx[ 3] = x[ 3] ^ rotl(x[15] + x[11],  5'd7);
   assign cx[ 7] = x[ 7] ^ rotl(cx[3]  + x[15],  5'd9);
   assign cx[11] = x[11] ^ rotl(cx[7]  + cx[3],  5'd13);
   assign cx[15] = x[15] ^ rotl(cx[11] + cx[7],  5'd18);

   // Row round (combinational, reads cx_reg[] — the REGISTERED column output)
   assign rx[ 1] = cx_reg[ 1] ^ rotl(cx_reg[ 0] + cx_reg[ 3],  5'd7);
   assign rx[ 2] = cx_reg[ 2] ^ rotl(rx[ 1]     + cx_reg[ 0],  5'd9);
   assign rx[ 3] = cx_reg[ 3] ^ rotl(rx[ 2]     + rx[ 1],      5'd13);
   assign rx[ 0] = cx_reg[ 0] ^ rotl(rx[ 3]     + rx[ 2],      5'd18);

   assign rx[ 6] = cx_reg[ 6] ^ rotl(cx_reg[ 5] + cx_reg[ 4],  5'd7);
   assign rx[ 7] = cx_reg[ 7] ^ rotl(rx[ 6]     + cx_reg[ 5],  5'd9);
   assign rx[ 4] = cx_reg[ 4] ^ rotl(rx[ 7]     + rx[ 6],      5'd13);
   assign rx[ 5] = cx_reg[ 5] ^ rotl(rx[ 4]     + rx[ 7],      5'd18);

   assign rx[11] = cx_reg[11] ^ rotl(cx_reg[10] + cx_reg[ 9],  5'd7);
   assign rx[ 8] = cx_reg[ 8] ^ rotl(rx[11]     + cx_reg[10],  5'd9);
   assign rx[ 9] = cx_reg[ 9] ^ rotl(rx[ 8]     + rx[11],      5'd13);
   assign rx[10] = cx_reg[10] ^ rotl(rx[ 9]     + rx[ 8],      5'd18);

   assign rx[12] = cx_reg[12] ^ rotl(cx_reg[15] + cx_reg[14],  5'd7);
   assign rx[13] = cx_reg[13] ^ rotl(rx[12]     + cx_reg[15],  5'd9);
   assign rx[14] = cx_reg[14] ^ rotl(rx[13]     + rx[12],      5'd13);
   assign rx[15] = cx_reg[15] ^ rotl(rx[14]     + rx[13],      5'd18);

   integer k;

   always @(posedge CLK) begin
      done <= 0;

      case (state)
      ST_IDLE: begin
         if (start) begin
            // Load input
            for (k = 0; k < 16; k = k + 1) begin
               x[k]    <= data_in[k*32 +: 32];
               orig[k] <= data_in[k*32 +: 32];
            end
            round_cnt <= 0;
            state <= ST_COL;
         end
      end

      ST_COL: begin
         // Column round: register the combinational cx[] output
         for (k = 0; k < 16; k = k + 1)
            cx_reg[k] <= cx[k];
         state <= ST_ROW;
      end

      ST_ROW: begin
         // Row round: register the combinational rx[] output (uses cx_reg[])
         for (k = 0; k < 16; k = k + 1)
            x[k] <= rx[k];

         round_cnt <= round_cnt + 1'b1;
         if (round_cnt == 3)
            state <= ST_ADD;
         else
            state <= ST_COL;
      end

      ST_ADD: begin
         // Add original input
         for (k = 0; k < 16; k = k + 1)
            data_out[k*32 +: 32] <= x[k] + orig[k];
         state <= ST_DONE;
      end

      ST_DONE: begin
         done <= 1;
         state <= ST_IDLE;
      end
      endcase
   end

endmodule
