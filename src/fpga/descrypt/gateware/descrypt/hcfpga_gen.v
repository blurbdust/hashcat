/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Batch generation, for cores that cannot be reset in the middle of a job.
//
// hashcat resets framing after every failed batch, and a core that cannot be reset still holds
// candidates from that batch. Their results come back during the next one and would be counted
// there, ending it early. So every candidate carries the generation it was sent under, the core
// echoes it with the result, and the collector drops a result whose generation is not the current
// one without retiring it.
//
// The generation moves on at every framing reset (rising edge of rst) and every arm (a write of
// batch_target). 16 bits: a stale result would need 65536 resets or arms in flight to alias.
//
// A core that can be reset, or that is drained before a batch ends, does not need this.

`timescale 1ns / 1ps
module hcfpga_gen (
  input  wire        CLK,
  input  wire        rst,
  input  wire        batch_arm,

  output reg  [15:0] gen = 0
);

  reg rst_q = 0;

  always @(posedge CLK)
  begin
    rst_q <= rst;

    if (((rst == 1'b1) && (rst_q == 1'b0)) || (batch_arm == 1'b1))
      gen <= gen + 1'b1;
  end

endmodule
