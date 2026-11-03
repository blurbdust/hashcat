/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// HCFPGA-TODO: a stub. Replace it with wpa2's cores and keep the contract below.
//
// Contract with the top:
//
// - A record is ready while rec_valid is high: rec_len, rec_id, and the password through
//   pw_rd_addr/pw_rd_data (word k = bytes 4k..4k+3, big-endian). Pulse rec_taken for one cycle
//   when done with it; the intake then takes the next one. Drive hold high while a record is being
//   sent into a core that cannot take half of one: the intake then keeps it across a framing reset
//   so the send finishes (scrypt's engine does, as hcfpga_jtr_unit_feed.v does). An engine that
//   can drop a half-read record, like this stub, ties hold low.
// - For each candidate, either send its PARTS 32-byte C2H records on r_*, one after the other with
//   nothing in between (byte 0 first, r_last on byte 31 of each), and pulse retire after the last
//   byte of the last one, or, when the comparator filters it, pulse retire without a record.
//   Exactly one retire per candidate, canaries (id 0xfffffffe) included.
// - C2H record k of a candidate (k = 0 .. PARTS-1): bytes 0..3 rec_id little-endian, bytes 4..27
//   digest bytes 24k..24k+23 as the bridge's digest_from_c2h expects them (zero past
//   DIGEST_BYTES), bytes 28..29 core_id, bytes 30..31 flags: k in bits 11..8, 0x0001 when the core
//   reports an error. PARTS = ceil (DIGEST_BYTES / 24); with PARTS = 1 that is the one record of
//   bcrypt's contract, flags 0x0000.
// - Comparator: the low 7 bits of the byte that becomes the low byte of hashcat's digest[0] (in
//   the first part) index cmp_bitmap, loaded on cmp_load; a clear bit filters the whole candidate.
//   WITH_CMP = 0 returns all.
// - rst is a framing reset: drop what is in flight, or (cores that cannot be reset) keep going
//   and drop the stale results by generation, see hcfpga_gen.v.
// - batch_arm pulses when the host arms a batch, with batch_target its record count (0: the
//   transport sends no count). An engine that groups candidates (descrypt fills a ring of 16)
//   starts the last, short group when it has taken batch_target records since the arm; with no
//   count it needs another rule, such as a flush after some idle cycles. A one-at-a-time engine
//   like this stub ignores both.
//
// The stub computes one candidate at a time, DIGEST_BYTES bytes of a toy hash, and sends it in
// PARTS records:
//
//   digest[j] = pw[j % len] ^ salt[j % 16] ^ ((iter_count + j) & 0xff)     (pw[...] = 0 if len = 0)

`timescale 1ns / 1ps
module hcfpga_wpa2_engine #(
  parameter PW_MAX       = 64,
  parameter DIGEST_BYTES = 16,
  parameter PARTS        = 1,
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
  output wire              hold,

  input  wire [31:0] salt0,
  input  wire [31:0] salt1,
  input  wire [31:0] salt2,
  input  wire [31:0] salt3,
  input  wire [31:0] iter_count,

  input  wire [127:0] cmp_bitmap,
  input  wire         cmp_load,

  input  wire [31:0]  batch_target,
  input  wire         batch_arm,

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

  localparam DIG_BITS = 192 * PARTS;

  reg [7:0]          j   = 0;
  reg [7:0]          kj  = 0;
  reg [DIG_BITS-1:0] dig = 0;

  reg [255:0]        frame   = 0;
  reg [4:0]          bytecnt = 0;
  reg [3:0]          part    = 0;
  reg [DIG_BITS-1:0] rest    = 0;
  reg [31:0]         id_r    = 0;

  wire [127:0] salt = {salt3, salt2, salt1, salt0};

  assign pw_rd_addr = kj[PW_AW+1:2];

  wire [7:0] kbyte = (rec_len == 0) ? 8'h00 : pw_rd_data[8*(3 - kj[1:0]) +: 8];

  wire [7:0] dbyte = kbyte ^ salt[8*j[3:0] +: 8] ^ (iter_count[7:0] + j);

  wire cmp_hit = (WITH_CMP == 0) | bitmap[dig[6:0]];

  assign rec_taken = (state == E_DONE);
  assign hold      = 1'b0;

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
        frame   <= { 16'h0000, 16'h0000, dig[191:0], rec_id };
        rest    <= dig >> 192;
        id_r    <= rec_id;
        part    <= 0;
        bytecnt <= 0;
        state   <= E_EMIT;
      end

    // The parts back to back; the candidate retires after the last byte of the last one.
    E_EMIT:
      if (r_ready == 1'b1)
      begin
        if ((bytecnt == 5'd31) && (part == PARTS - 1))
        begin
          retire <= 1'b1;
          state  <= E_IDLE;
        end
        else if (bytecnt == 5'd31)
        begin
          frame   <= { 4'h0, part + 4'h1, 8'h00, 16'h0000, rest[191:0], id_r };
          rest    <= rest >> 192;
          part    <= part + 1'b1;
          bytecnt <= 0;
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
