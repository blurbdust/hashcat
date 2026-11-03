/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// H2C intake: hashcat's candidate records in, one whole record out at a time.
//
// The H2C record is the same for every algorithm (bcrypt's hcfpga_feed.v reads it the same way):
//
//   word 0   (0xbc << 24) | len      a word without the tag, or with len > PW_MAX, is a slip
//   word 1   candidate id            echoed back in the C2H record; 0xfffffffe is a canary
//   word 2.. password, big-endian, four bytes per word, zero filled
//
// Words are the host buffer's bytes four at a time, first byte in bits 7:0. hashcat pads a batch to
// 32 bytes with zero words, which land in a header position and count as slips: on a healthy batch
// the slip count equals the pad words.
//
// frame_status is the status register's low half: bit 0 a slip was seen, bit 1 the stream's last
// word was seen, bits 15:8 the slip count (saturating). The algorithm may use bits 31:16.
//
// When a record is complete, rec_valid rises and the intake stops taking words until the consumer
// pulses rec_taken. rec_len and rec_id hold the header, the password is read through
// pw_rd_addr/pw_rd_data (combinational, word k = password bytes 4k..4k+3, big-endian, as sent).
//
// rst clears the intake. A record the consumer is still sending (hold high) survives rst until
// rec_taken: a core given half a packet would take the next one's bytes as the rest of it, so a
// started send is always finished. A consumer that can abandon a send ties hold low.

`timescale 1ns / 1ps

`include "hcfpga_iface.vh"

module hcfpga_h2c_intake #(
  parameter PW_MAX = 64,

  parameter PW_WORDS = (PW_MAX + 3) / 4,
  parameter PW_AW    = (PW_WORDS <= 2) ? 1 : $clog2(PW_WORDS)
)(
  input  wire CLK,
  input  wire rst,

  input  wire [31:0] s_data,
  input  wire        s_valid,
  output wire        s_ready,
  input  wire        s_last,

  output wire [31:0] frame_status,

  output reg               rec_valid = 0,
  output reg  [7:0]        rec_len   = 0,
  output reg  [31:0]       rec_id    = 0,
  input  wire [PW_AW-1:0]  pw_rd_addr,
  output wire [31:0]       pw_rd_data,
  input  wire              rec_taken,
  input  wire              hold
);

  localparam [7:0] H2C_TAG = `HCFPGA_H2C_TAG;

  localparam WW = $clog2(PW_WORDS + 3);

  reg [31:0] pw_buf [0:PW_WORDS-1];

  assign pw_rd_data = pw_buf[pw_rd_addr];

  reg [WW-1:0] in_wcnt   = 0;
  reg [WW-1:0] rec_words = 2;

  reg       frame_slip = 0;
  reg       last_seen  = 0;
  reg [7:0] slip_count = 0;

  assign frame_status = {16'd0, slip_count, 6'd0, last_seen, frame_slip};

  assign s_ready = (rst == 1'b0) & (rec_valid == 1'b0);

  wire       hdr_word = (in_wcnt == 0);
  wire       hdr_bad  = (s_data[31:24] != H2C_TAG) | (s_data[7:0] > PW_MAX);
  wire [7:0] hdr_len  = s_data[7:0];

  wire [WW-1:0] hdr_words = 2 + hdr_len[7:2] + ((hdr_len[1:0] != 2'd0) ? 1 : 0);

  wire take = s_valid & s_ready;

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      in_wcnt    <= 0;
      rec_words  <= 2;
      frame_slip <= 0;
      last_seen  <= 0;
      slip_count <= 0;

      // A record already being sent stays until its packet is out, see the header.
      if (hold == 1'b0) rec_valid <= 0;
      else if (rec_taken == 1'b1) rec_valid <= 0;
    end
    else
    begin
      if (rec_taken == 1'b1) rec_valid <= 0;

      if (take == 1'b1)
      begin
        if (s_last == 1'b1) last_seen <= 1'b1;

        if (hdr_word == 1'b1)
        begin
          if (hdr_bad == 1'b1)
          begin
            frame_slip <= 1'b1;

            if (slip_count != 8'hff) slip_count <= slip_count + 1'b1;
          end
          else
          begin
            rec_len   <= hdr_len;
            rec_words <= hdr_words;
            in_wcnt   <= 1;
          end
        end
        else
        begin
          if (in_wcnt == 1)
            rec_id <= s_data;
          else
            pw_buf[in_wcnt - 2] <= s_data;

          if (in_wcnt == (rec_words - 1'b1))
          begin
            in_wcnt   <= 0;
            rec_valid <= 1'b1;
          end
          else
            in_wcnt <= in_wcnt + 1'b1;
        end
      end
    end
  end

endmodule
