`timescale 1ns / 1ps

module Sha1(
   Clk, Go, Wait, Done, Busy,
   Ai, Bi, Ci, Di, Ei,
   Ao, Bo, Co, Do, Eo,
   WAddr0, WDin0,
   WAddr1, WDin1,
   WAddr2, WDin2,
   WAddr3, WDin3,
   WAddr4, WDout4, WWE4
);

input  Clk;
input  Go, Wait;
output Done, Busy;
input  [31:0] Ai, Bi, Ci, Di, Ei;
output [31:0] Ao, Bo, Co, Do, Eo;
output [3:0]  WAddr0, WAddr1, WAddr2, WAddr3, WAddr4;
input  [31:0] WDin0,  WDin1,  WDin2,  WDin3;
output [31:0] WDout4;
output WWE4;

reg [6:0] T, T_0;
reg [31:0] A, B, C, D, E;
reg GoLatch;
reg [3:0] R_0;
reg Go_0;
//synthesis attribute init T 0;
//synthesis attribute init A 0;
//synthesis attribute init B 0;
//synthesis attribute init C 0;
//synthesis attribute init D 0;
//synthesis attribute init E 0;
//synthesis attribute init T_0 0;
//synthesis attribute init GoLatch 0;
//synthesis attribute init R_0 0;
//synthesis attribute init Go_0 0;
initial begin
   T = 0;
   A = 0;
   B = 0;
   C = 0;
   D = 0;
   E = 0;
   T_0 = 0;
   GoLatch = 0;
   R_0 = 0;
   Go_0 = 0;
end

wire [3:0] R =
   (T < 7'h10) ? 4'h0 :
   (T < 7'h14) ? 4'h1 :
   (T < 7'h28) ? 4'h2 :
   (T < 7'h3C) ? 4'h3 :
   (T < 7'h50) ? 4'h4 : 4'h8;

wire [31:0] WDin = WDin0 ^ WDin1 ^ WDin2 ^ WDin3;
wire [31:0] Ws =
   (|R_0[2:0]) ? {WDin[30:0], WDin[31]}
               : WDin3;

assign WAddr0 = T + 13;
assign WAddr1 = T + 8;
assign WAddr2 = T + 2;
assign WAddr3 = T;
assign WAddr4 = T_0;
assign WWE4   = |R_0[2:0];
assign WDout4 = Ws;

wire GoNow = Go & ~Go_0;

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

Add32 Add320(.A(Done ? Ai : AddA), .B(Done ? A : AddB), .P(P0));
Add32 Add321(.A(Done ? Bi : AddC), .B(Done ? B : AddD), .P(P1));
Add32 Add322(.A(Done ? Ci : P0),   .B(Done ? C : AddE), .P(P2));
Add32 Add323(.A(Done ? Di : P1),   .B(Done ? D : P2),   .P(P3));

always @(posedge Clk) begin
   if(~Wait) begin
      if(GoNow & ~GoLatch) begin
         T <= 7'h0;
         A <= Ai;
         B <= Bi;
         C <= Ci;
         D <= Di;
         E <= Ei;
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
      end else begin
         T <= 7'h7F;
         GoLatch <= 1'b0;
      end

      T_0  <= T;
      R_0  <= R;
      Go_0 <= Go;
   end
end

assign Done = R_0[3];
assign Busy = ~Done;
assign Ao = P0;
assign Bo = P1;
assign Co = P2;
assign Do = P3;
assign Eo = Ei + E;

endmodule