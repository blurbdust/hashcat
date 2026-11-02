/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The Stratix V temperature sensing diode. Written out by hand because Quartus validates the
// primitive's parameters as an integer and a lowercase string, and a generated sized literal such as
// 7'd80 is rejected as the bit string 1010000.

module hcfpga_sv_tsd #(
  parameter integer CLOCK_DIVIDER_VALUE = 80
)(
  input  wire       clk,
  input  wire       clr,
  output wire [7:0] tsdcalo,
  output wire       tsdcaldone
);

  stratixv_tsdblock #(
    .clock_divider_enable ("true"),
    .clock_divider_value  (CLOCK_DIVIDER_VALUE)
  ) tsd (
    .clk        (clk),
    .ce         (1'b1),
    .clr        (clr),
    .tsdcalo    (tsdcalo),
    .tsdcaldone (tsdcaldone)
  );

endmodule
