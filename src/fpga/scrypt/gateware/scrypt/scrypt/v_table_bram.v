`timescale 1ns / 1ps
/*
 * This file is part of LiteX-Scrypt.
 *
 * v_table_bram.v -- V[] table BRAM storage for scrypt ROMix
 *
 * Stores up to (1 << N_LOG2_MAX) entries, each WIDTH bits wide.
 * For r=1, N_max=32768: WIDTH=1024, DEPTH=32768 (32 x 36Kb BRAMs x 32).
 * For r=8, N_max=16384: WIDTH=8192, DEPTH=16384 (256 x 36Kb BRAMs x 16).
 *
 * Simple dual-port: one write port, one read port.
 * Read latency: 2 cycles (registered output).
 */

module v_table_bram #(
   parameter N_LOG2_MAX = 15, // Max log2(N), determines BRAM depth
   parameter WIDTH  = 1024    // Data width (128*r bytes in bits)
)(
   input CLK,

   // Write port
   input we,
   input [N_LOG2_MAX-1:0] waddr,
   input [WIDTH-1:0] wdata,

   // Read port
   input [N_LOG2_MAX-1:0] raddr,
   output reg [WIDTH-1:0] rdata
);

   localparam DEPTH = 1 << N_LOG2_MAX;
   localparam NUM_BRAMS = WIDTH / 32;  // 32 BRAMs per 1024-bit width

   // Generate N_BRAMS, each 32-bit wide x DEPTH deep
   genvar g;
   generate
      for (g = 0; g < NUM_BRAMS; g = g + 1) begin : gen_bram
         (* RAM_STYLE = "BLOCK" *)
         reg [31:0] mem [0:DEPTH-1];

         // Write
         always @(posedge CLK) begin
            if (we)
               mem[waddr] <= wdata[g*32 +: 32];
         end

         // Read (registered output for timing)
         always @(posedge CLK) begin
            rdata[g*32 +: 32] <= mem[raddr];
         end
      end
   endgenerate

endmodule
