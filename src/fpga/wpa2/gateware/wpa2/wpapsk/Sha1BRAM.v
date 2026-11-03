`timescale 1ns / 1ps

module Sha1BRAM(
   Clk,
   WAddr0, WAddr1, WAddr2, WAddr3, WAddr4,
   WDout0, WDout1, WDout2, WDout3, WDin4, WWE4
);

input Clk;
input [3:0] WAddr0, WAddr1, WAddr2, WAddr3, WAddr4;
output [31:0] WDout0, WDout1, WDout2, WDout3;
input [31:0] WDin4;
input WWE4;

reg [31:0] WDout0, WDout1, WDout2, WDout3;

reg [31:0] BRAM0 [15:0];
reg [31:0] BRAM1 [15:0];
reg [31:0] BRAM2 [15:0];
reg [31:0] BRAM3 [15:0];

always @(posedge Clk) begin
   if(WWE4) begin
      BRAM0[WAddr4] <= WDin4;
      BRAM1[WAddr4] <= WDin4;
      BRAM2[WAddr4] <= WDin4;
      BRAM3[WAddr4] <= WDin4;
   end
   WDout0 <= BRAM0[WAddr0];
   WDout1 <= BRAM1[WAddr1];
   WDout2 <= BRAM2[WAddr2];
   WDout3 <= BRAM3[WAddr3];
end

endmodule
