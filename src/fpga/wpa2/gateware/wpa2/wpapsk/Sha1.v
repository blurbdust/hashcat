`timescale 1ns / 1ps

module Sha1(
   Clk, Go, Wait, Done, Busy,
   Ai, Bi, Ci, Di, Ei,
   Ao, Bo, Co, Do, Eo,
   Fi, Gi, Hi, Ii, Ji
);

input  Clk;
input  Go, Wait;
output Done, Busy;
input  [31:0] Ai, Bi, Ci, Di, Ei;
output [31:0] Ao, Bo, Co, Do, Eo;
input  [31:0] Fi, Gi, Hi, Ii, Ji;

reg [6:0] T, T_0;
reg [31:0] A, B, C, D, E;
reg [31:0] Ao, Bo, Co, Do, Eo;
reg GoLatch;
reg [3:0] R_0;
//synthesis attribute init T 0;
//synthesis attribute init A 0;
//synthesis attribute init B 0;
//synthesis attribute init C 0;
//synthesis attribute init D 0;
//synthesis attribute init E 0;
//synthesis attribute init Ao 0;
//synthesis attribute init Bo 0;
//synthesis attribute init Co 0;
//synthesis attribute init Do 0;
//synthesis attribute init Eo 0;
//synthesis attribute init T_0 0;
//synthesis attribute init GoLatch 0;
//synthesis attribute init R_0 0;
initial begin
   T   = 0;
   A   = 0;
   B   = 0;
   C   = 0;
   D   = 0;
   E   = 0;
   Ao  = 0;
   Bo  = 0;
   Co  = 0;
   Do  = 0;
   Eo  = 0;
   T_0 = 0;
   GoLatch = 0;
   R_0 = 0;
end

wire [3:0] WAddr0, WAddr1, WAddr2, WAddr3, WAddr4;
wire [31:0] WDin0, WDin1, WDin2, WDin3;
wire [31:0] WDout4;
wire WWE4;
Sha1BRAM Sha1BRAM(
   .Clk(Clk),
   .WAddr0(WAddr0),
   .WAddr1(WAddr1),
   .WAddr2(WAddr2),
   .WAddr3(WAddr3),
   .WAddr4(WAddr4),
   .WDout0(WDin0),
   .WDout1(WDin1),
   .WDout2(WDin2),
   .WDout3(WDin3),
   .WDin4(WDout4),
   .WWE4(WWE4)
);

wire [3:0] R =
   (T < 7'h10) ? 4'h0 :
   (T < 7'h14) ? 4'h1 :
   (T < 7'h28) ? 4'h2 :
   (T < 7'h3C) ? 4'h3 :
   (T < 7'h50) ? 4'h4 : 4'h8;

wire [31:0] WDin = WDin0 ^ WDin1 ^ WDin2 ^ WDin3;
wire [31:0] Ws   = (|R_0[2:0]) ? {WDin[30:0], WDin[31]} :
   (T_0[3:0] == 4'h0) ? Fi :
   (T_0[3:0] == 4'h1) ? Gi :
   (T_0[3:0] == 4'h2) ? Hi :
   (T_0[3:0] == 4'h3) ? Ii :
   (T_0[3:0] == 4'h4) ? Ji :
   (T_0[3:0] == 4'h5) ? 32'h80000000 :
   (T_0[3:0] == 4'hF) ? 32'h000002a0 : 32'h0;

assign WAddr0 = T + 13;
assign WAddr1 = T + 8;
assign WAddr2 = T + 2;
assign WAddr3 = T;
assign WAddr4 = T_0;
assign WWE4   = ~Done;
assign WDout4 = Ws;

wire [31:0] AddA, AddB, AddC, AddD, AddE, Zo;
wire [31:0] P0, P1, P2, P3;
R R_(
   .R(R_0),
   .V(A),
   .W(B),
   .X(C),
   .Y(D),
   .L(Ws),
   .Zi(E),
   .Zo(Zo),
   .A(AddA),
   .B(AddB),
   .C(AddC),
   .D(AddD),
   .E(AddE),
   .P(Done ? 32'h0 : P3)
);

Add32 Add320(.A(R_0[3] ? Ai : AddA), .B(R_0[3] ? A : AddB), .P(P0));
Add32 Add321(.A(R_0[3] ? Bi : AddC), .B(R_0[3] ? B : AddD), .P(P1));
Add32 Add322(.A(R_0[3] ? Ci : P0),   .B(R_0[3] ? C : AddE), .P(P2));
Add32 Add323(.A(R_0[3] ? Di : P1),   .B(R_0[3] ? D : P2),   .P(P3));

always @(posedge Clk) begin
   if(~Wait) begin
      if(Go & ~GoLatch) begin
         T   <= 7'h0;
         A   <= Ai;
         B   <= Bi;
         C   <= Ci;
         D   <= Di;
         E   <= Ei;
         GoLatch <= 1'b1;
      end else if((~R[3] | ~R_0[3]) & GoLatch) begin
         T <= T + 7'h1;
         if(|T) begin
            E <= D;
            D <= C;
            C <= {B[1:0], B[31:2]};
            B <= A;
            A <= Zo;
         end
      end else if(R[3]) begin
         Ao <= P0;
         Bo <= P1;
         Co <= P2;
         Do <= P3;
         Eo <= Ei + E;
         T <= 7'h7F;
         GoLatch <= 1'b0;
      end

      T_0  <= T;
      R_0  <= R;
   end
end

assign Done = ~GoLatch;
assign Busy = GoLatch;

endmodule