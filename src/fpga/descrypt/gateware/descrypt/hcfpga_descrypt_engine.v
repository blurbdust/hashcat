/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// HCFPGA-TODO: a stub. Replace it with descrypt's cores and keep the contract below.
//
// Contract with the top:
//
// - A record is ready while rec_valid is high: rec_len, rec_id, and the password through
//   pw_rd_addr/pw_rd_data (word k = bytes 4k..4k+3, big-endian). Pulse rec_taken for one cycle
//   when done with it; the intake then takes the next one.
// - For each candidate, either send one 32-byte C2H record on r_* (byte 0 first, r_last on byte
//   31) and pulse retire after its last byte, or, when the comparator filters it, pulse retire
//   without a record. Exactly one retire per candidate, canaries (id 0xfffffffe) included.
// - C2H record: bytes 0..3 rec_id little-endian, bytes 4.. the DIGEST_BYTES digest bytes as the
//   bridge's digest_from_c2h expects them, zero up to byte 27, bytes 28..29 core_id, bytes 30..31
//   flags (0x0001 when the core reports an error).
// - Comparator: the low 7 bits of the byte that becomes the low byte of hashcat's digest[0] index
//   cmp_bitmap, loaded on cmp_load; a clear bit filters the result. WITH_CMP = 0 returns all.
// - rst is a framing reset: drop what is in flight, or (cores that cannot be reset) keep going
//   and drop the stale results by generation, see hcfpga_gen.v.
//
// The stub computes one candidate at a time, DIGEST_BYTES bytes of a toy hash:
//
//   digest[j] = pw[j % len] ^ salt[j % 16] ^ ((iter_count + j) & 0xff)     (pw[...] = 0 if len = 0)

`timescale 1ns / 1ps
module hcfpga_descrypt_engine #(
  parameter PW_MAX       = 64,
  parameter DIGEST_BYTES = 16,
  parameter WITH_CMP     = 1,

  parameter PW_WORDS = (PW_MAX + 3) / 4,
  parameter PW_AW    = (PW_WORDS <= 2) ? 1 : $clog2(PW_WORDS)
)(
  input  wire CLK,
  input  wire rst,

  input  wire              rec_valid,
  input  wire [7:0]        rec_len,
  input  wire [31:0]       rec_id,
  output wire [PW_AW-1:0]  pw_rd_addr,
  input  wire [31:0]       pw_rd_data,
  output wire              rec_taken,

  input  wire [31:0] salt0,
  input  wire [31:0] salt1,
  input  wire [31:0] salt2,
  input  wire [31:0] salt3,
  input  wire [31:0] iter_count,

  input  wire [127:0] cmp_bitmap,
  input  wire         cmp_load,

  output reg  retire = 0,

  output wire [7:0] r_data,
  output wire       r_valid,
  input  wire       r_ready,
  output wire       r_last
);

  localparam E_IDLE = 2'd0, E_CALC = 2'd1, E_DONE = 2'd2, E_EMIT = 2'd3;

  reg [1:0] state = E_IDLE;

  reg [127:0] bitmap = {128{1'b1}};

  always @(posedge CLK)
    if (cmp_load == 1'b1) bitmap <= cmp_bitmap;

  reg [7:0]   j   = 0;
  reg [7:0]   kj  = 0;
  reg [191:0] dig = 0;

  reg [255:0] frame   = 0;
  reg [4:0]   bytecnt = 0;

  wire [127:0] salt = {salt3, salt2, salt1, salt0};

  assign pw_rd_addr = kj[PW_AW+1:2];

  wire [7:0] kbyte = (rec_len == 0) ? 8'h00 : pw_rd_data[8*(3 - kj[1:0]) +: 8];

  wire [7:0] dbyte = kbyte ^ salt[8*j[3:0] +: 8] ^ (iter_count[7:0] + j);

  wire cmp_hit = (WITH_CMP == 0) | bitmap[dig[6:0]];

  assign rec_taken = (state == E_DONE);

  assign r_data  = frame[7:0];
  assign r_valid = (state == E_EMIT);
  assign r_last  = (state == E_EMIT) & (bytecnt == 5'd31);

  always @(posedge CLK)
  begin
    retire <= 0;

    if (rst == 1'b1)
      state <= E_IDLE;
    else
    case (state)
    E_IDLE:
      if (rec_valid == 1'b1)
      begin
        j     <= 0;
        kj    <= 0;
        dig   <= 0;
        state <= E_CALC;
      end

    E_CALC:
    begin
      dig[8*j +: 8] <= dbyte;
      kj <= ((rec_len == 0) || (kj + 1 == rec_len)) ? 8'd0 : kj + 1'b1;
      j  <= j + 1'b1;
      if (j == DIGEST_BYTES - 1) state <= E_DONE;
    end

    E_DONE:
      if (cmp_hit == 1'b0)
      begin
        retire <= 1'b1;
        state  <= E_IDLE;
      end
      else
      begin
        frame   <= { 16'h0000, 16'h0000, dig, rec_id };
        bytecnt <= 0;
        state   <= E_EMIT;
      end

    E_EMIT:
      if (r_ready == 1'b1)
      begin
        if (bytecnt == 5'd31)
        begin
          retire <= 1'b1;
          state  <= E_IDLE;
        end
        else
        begin
          frame   <= frame >> 8;
          bytecnt <= bytecnt + 1'b1;
        end
      end
    endcase
  end

endmodule
