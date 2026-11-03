`timescale 1ns / 1ps
/*
 * This file is part of LiteX-Scrypt.
 *
 * blockmix.v -- scryptBlockMix with runtime r support
 *
 * R parameter sets the MAXIMUM r (determines array sizes).
 * r_actual input selects the actual r at runtime (1..R).
 *
 * Algorithm (general r):
 *   X = B[2r-1]                           (last 64-byte input block)
 *   for i = 0 to 2r-1:
 *     X = Salsa20/8(X ^ B[i])
 *     Y[i] = X
 *   Output: Y[0], Y[2], ..., Y[2r-2], Y[1], Y[3], ..., Y[2r-1]
 *           (evens first, then odds)
 */

module blockmix #(
   parameter R = 1    // Max scrypt block size (compile-time)
)(
   input CLK,
   input start,
   input [$clog2(R+1)-1:0] r_actual,   // Runtime r (1..R)
   input [1024*R-1:0] block_in,
   output [1024*R-1:0] block_out,
   output reg done = 0
);

   localparam NUM_BLOCKS_MAX = 2 * R;     // Maximum number of 64-byte blocks
   localparam BLOCK_BITS = 512;           // 64 bytes = 512 bits
   localparam IDX_BITS = (NUM_BLOCKS_MAX <= 2) ? 1 : $clog2(NUM_BLOCKS_MAX);

   // Latched runtime parameters
   reg [IDX_BITS:0] num_blocks_r;        // 2 * r_actual (latched at start)
   reg [$clog2(R+1)-1:0] r_latched;      // r_actual latched at start

   // Input block array (loaded from block_in on start)
   reg [BLOCK_BITS-1:0] B [0:NUM_BLOCKS_MAX-1];

   // Output Y array (stored at reordered positions)
   reg [BLOCK_BITS-1:0] Y [0:NUM_BLOCKS_MAX-1];

   // Salsa20/8 instance
   reg         salsa_start = 0;
   reg [511:0] salsa_in;
   wire [511:0] salsa_out;
   wire         salsa_done;

   salsa20_8 u_salsa (
      .CLK(CLK),
      .start(salsa_start),
      .data_in(salsa_in),
      .data_out(salsa_out),
      .done(salsa_done)
   );

   // State machine
   localparam ST_IDLE  = 2'd0;
   localparam ST_XOR   = 2'd1;   // XOR X with B[i], start Salsa
   localparam ST_WAIT  = 2'd2;   // Wait for Salsa20/8, store result
   localparam ST_DONE  = 2'd3;

   reg [1:0] state = ST_IDLE;
   reg [IDX_BITS-1:0] round_cnt;
   reg [511:0] X;   // Working register

   // Output index: reorder evens then odds
   // i even -> position i/2
   // i odd  -> position r_actual + (i-1)/2
   // = round_cnt[0] ? (r_latched + round_cnt[MSB:1]) : round_cnt[MSB:1]
   wire [IDX_BITS-1:0] out_idx = round_cnt[0]
      ? (r_latched[IDX_BITS-1:0] + round_cnt[IDX_BITS-1:1])
      : round_cnt[IDX_BITS-1:1];

   // Flatten Y array to output
   genvar gi;
   generate
      for (gi = 0; gi < NUM_BLOCKS_MAX; gi = gi + 1) begin : gen_out
         assign block_out[gi*BLOCK_BITS +: BLOCK_BITS] = Y[gi];
      end
   endgenerate

   integer j;

   always @(posedge CLK) begin
      done <= 0;
      salsa_start <= 0;

      case (state)
      ST_IDLE: begin
         if (start) begin
            // Latch runtime r
            r_latched <= r_actual;
            num_blocks_r <= {r_actual, 1'b0};  // 2 * r_actual

            // Load input blocks into array
            for (j = 0; j < NUM_BLOCKS_MAX; j = j + 1)
               B[j] <= block_in[j*BLOCK_BITS +: BLOCK_BITS];

            // X = B[2*r_actual - 1] (last block for this r)
            // Variable index into block_in
            X <= block_in[({r_actual, 1'b0} - 1) * BLOCK_BITS +: BLOCK_BITS];

            // Zero out Y for blocks beyond 2*r_actual
            for (j = 0; j < NUM_BLOCKS_MAX; j = j + 1)
               Y[j] <= 0;

            round_cnt <= 0;
            state <= ST_XOR;
         end
      end

      ST_XOR: begin
         // salsa_in = X ^ B[round_cnt]
         salsa_in <= X ^ B[round_cnt];
         salsa_start <= 1;
         state <= ST_WAIT;
      end

      ST_WAIT: begin
         if (salsa_done) begin
            X <= salsa_out;
            Y[out_idx] <= salsa_out;
            if (round_cnt == num_blocks_r[IDX_BITS-1:0] - 1'b1) begin
               state <= ST_DONE;
            end else begin
               round_cnt <= round_cnt + 1'b1;
               state <= ST_XOR;
            end
         end
      end

      ST_DONE: begin
         done <= 1;
         state <= ST_IDLE;
      end
      endcase
   end

endmodule
