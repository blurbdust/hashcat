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

// Modified for hashcat from LiteX-Scrypt's original.
// src/fpga/scrypt/PROVENANCE.md lists every change.

module v_table_bram #(
   parameter N_LOG2_MAX = 15, // Max log2(N), determines BRAM depth
   parameter WIDTH  = 1024    // Data width (128*r bytes in bits)
)(
   input CLK,

   // Write port
   input we,
   input [N_LOG2_MAX-1:0] waddr,
   input [WIDTH-1:0] wdata,

   // Read port: rdata takes mem[raddr] in a cycle with re high, and holds otherwise
   input re,
   input [N_LOG2_MAX-1:0] raddr,
   output reg [WIDTH-1:0] rdata
);

   localparam DEPTH = 1 << N_LOG2_MAX;

   // One memory WIDTH bits wide (vendor tools slice it into block RAMs of their own width; Quartus
   // merged upstream's 32-bit slices into one such memory anyway). The read enable keeps Verilator
   // from copying WIDTH bits every cycle, which made up most of a unit's simulation time at R = 8.
   // max_depth (Quartus): Stratix V M20K blocks hold 20 Kbit as 4K x 5 and shallower, 16 Kbit as
   // 8K x 2 and 16K x 1, and Quartus picks the shape as deep as the table; capped at 4K a deeper
   // table takes cascaded 4K x 5 blocks (16384 x 1024 bits: 820 blocks instead of 1024).
   (* RAM_STYLE = "BLOCK", max_depth = 4096 *)
   reg [WIDTH-1:0] mem [0:DEPTH-1];

   always @(posedge CLK) begin
      if (we)
         mem[waddr] <= wdata;
      if (re)
         rdata <= mem[raddr];
   end

endmodule
