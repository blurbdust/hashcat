`timescale 1ns / 1ps

module Add32(A, B, P);

input [31:0] A;
input [31:0] B;
output [31:0] P;

assign P = A + B;

endmodule
