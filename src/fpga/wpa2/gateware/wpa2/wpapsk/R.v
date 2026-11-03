`timescale 1ns / 1ps

module R(R, V, W, X, Y, L, Zi, Zo, A, B, C, D, E, P);

input [3:0] R;
input [31:0] V;
input [31:0] W;
input [31:0] X;
input [31:0] Y;
input [31:0] L;
input [31:0] Zi;
output [31:0] Zo;
output [31:0] A;
output [31:0] B;
output [31:0] C;
output [31:0] D;
output [31:0] E;
input [31:0] P;

assign A  =
   ((R == 4'h0) || (R == 4'h1)) ? ((W & (X ^ Y)) ^ Y) :
   ((R == 4'h2) || (R == 4'h4)) ? (W ^ X ^ Y) :
   (R == 4'h3)                  ? (((W | X) & Y) | (W & X)) :
   32'h0;

assign B  =
   ((R == 4'h0) || (R == 4'h1)) ? 32'h5A827999 :
   (R == 4'h2)                  ? 32'h6ED9EBA1 :
   (R == 4'h3)                  ? 32'h8F1BBCDC :
   (R == 4'h4)                  ? 32'hCA62C1D6 :
   32'h0;

assign C  = {V[26:0], V[31:27]};

assign D  = L;
assign E  = Zi;
assign Zo = P;

endmodule
