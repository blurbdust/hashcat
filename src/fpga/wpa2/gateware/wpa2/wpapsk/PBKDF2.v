`timescale 1ns / 1ps

/* This specifies the number of bits of iterations (4096 in this case) */
`define ITERATIONS 12

module PBKDF2(
   Clk, Go, Rst, Done,
   ipad_A, ipad_B, ipad_C, ipad_D, ipad_E,
   opad_A, opad_B, opad_C, opad_D, opad_E,
   mac_F,  mac_G,  mac_H,  mac_I,  mac_J,
   mac_Fo, mac_Go, mac_Ho, mac_Io, mac_Jo
);

input  Clk, Go, Rst;
output Done;
input  [31:0] ipad_A, ipad_B, ipad_C, ipad_D, ipad_E;
input  [31:0] opad_A, opad_B, opad_C, opad_D, opad_E;
input  [31:0] mac_F,  mac_G,  mac_H,  mac_I,  mac_J;
output [31:0] mac_Fo, mac_Go, mac_Ho, mac_Io, mac_Jo;

reg [`ITERATIONS+1:0] Counter;
reg [31:0] ipad_A_, ipad_B_, ipad_C_, ipad_D_, ipad_E_;
reg [31:0] opad_A_, opad_B_, opad_C_, opad_D_, opad_E_;
reg [31:0] mac_F_,  mac_G_,  mac_H_,  mac_I_,  mac_J_;
reg [31:0] mac_Fo,  mac_Go,  mac_Ho,  mac_Io,  mac_Jo;
reg Go_0, GoLatch;
//synthesis attribute init Counter 0;
//synthesis attribute init ipad_A_ 0;
//synthesis attribute init ipad_B_ 0;
//synthesis attribute init ipad_C_ 0;
//synthesis attribute init ipad_D_ 0;
//synthesis attribute init ipad_E_ 0;
//synthesis attribute init opad_A_ 0;
//synthesis attribute init opad_B_ 0;
//synthesis attribute init opad_C_ 0;
//synthesis attribute init opad_D_ 0;
//synthesis attribute init opad_E_ 0;
//synthesis attribute init mac_F_ 0;
//synthesis attribute init mac_G_ 0;
//synthesis attribute init mac_H_ 0;
//synthesis attribute init mac_I_ 0;
//synthesis attribute init mac_J_ 0;
//synthesis attribute init mac_Fo 0;
//synthesis attribute init mac_Go 0;
//synthesis attribute init mac_Ho 0;
//synthesis attribute init mac_Io 0;
//synthesis attribute init mac_Jo 0;
//synthesis attribute init Go_0 0;
//synthesis attribute init GoLatch 0;
initial begin
   Counter <= 0;
   ipad_A_ <= 0;
   ipad_B_ <= 0;
   ipad_C_ <= 0;
   ipad_D_ <= 0;
   ipad_E_ <= 0;
   opad_A_ <= 0;
   opad_B_ <= 0;
   opad_C_ <= 0;
   opad_D_ <= 0;
   opad_E_ <= 0;
   mac_F_ <= 0;
   mac_G_ <= 0;
   mac_H_ <= 0;
   mac_I_ <= 0;
   mac_J_ <= 0;
   mac_Fo <= 0;
   mac_Go <= 0;
   mac_Ho <= 0;
   mac_Io <= 0;
   mac_Jo <= 0;
   Go_0 <= 0;
   GoLatch <= 0;
end

wire Sha1Done, Sha1Busy;
wire Start = ~(|Counter[`ITERATIONS+1:2]) & ~(&Counter[1:0]);
wire GoNow = Go & ~Go_0;
wire Odd   = Counter[0] ^ Sha1Done;

wire [31:0] mac_Fi, mac_Gi, mac_Hi, mac_Ii, mac_Ji;
wire [31:0] Fi = Start ? mac_F_ : mac_Fi;
wire [31:0] Gi = Start ? mac_G_ : mac_Gi;
wire [31:0] Hi = Start ? mac_H_ : mac_Hi;
wire [31:0] Ii = Start ? mac_I_ : mac_Ii;
wire [31:0] Ji = Start ? mac_J_ : mac_Ji;

Sha1 Sha1(
   .Clk(Clk),
   .Go((Sha1Done & GoLatch) | GoNow),
   .Wait(1'b0),
   .Done(Sha1Done),
   .Busy(Sha1Busy),
   .Ai(Odd ? opad_A_ : ipad_A_),
   .Bi(Odd ? opad_B_ : ipad_B_),
   .Ci(Odd ? opad_C_ : ipad_C_),
   .Di(Odd ? opad_D_ : ipad_D_),
   .Ei(Odd ? opad_E_ : ipad_E_),
   .Ao(mac_Fi),
   .Bo(mac_Gi),
   .Co(mac_Hi),
   .Do(mac_Ii),
   .Eo(mac_Ji),
   .Fi(Fi),
   .Gi(Gi),
   .Hi(Hi),
   .Ii(Ii),
   .Ji(Ji)
);

assign Done = Counter[`ITERATIONS+1];

always @(posedge Clk) begin
   if(Rst) begin
      ipad_A_ <= ipad_A;
      ipad_B_ <= ipad_B;
      ipad_C_ <= ipad_C;
      ipad_D_ <= ipad_D;
      ipad_E_ <= ipad_E;
      opad_A_ <= opad_A;
      opad_B_ <= opad_B;
      opad_C_ <= opad_C;
      opad_D_ <= opad_D;
      opad_E_ <= opad_E;
      mac_F_  <= mac_F;
      mac_G_  <= mac_G;
      mac_H_  <= mac_H;
      mac_I_  <= mac_I;
      mac_J_  <= mac_J;
      Counter <= 14'h1;
      GoLatch <= 0;
   end

   if((Go | GoLatch) & Sha1Done & ~Done) begin
      GoLatch <= 1;
      Counter <= Counter + 1;
      if(~Odd) begin
         mac_Fo  <= mac_Fo ^ Fi;
         mac_Go  <= mac_Go ^ Gi;
         mac_Ho  <= mac_Ho ^ Hi;
         mac_Io  <= mac_Io ^ Ii;
         mac_Jo  <= mac_Jo ^ Ji;
      end
   end else if(Done)
      GoLatch <= 0;
   Go_0 <= Go;
end 

endmodule
