/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// H2C intake and unit transmitter.
//
// Takes hashcat's H2C records, the same framing as bcrypt's hcfpga_feed.v:
//
//   word 0   (0xbc << 24) | len      a word without the tag, or with len > 64, is a slip
//   word 1   candidate id            echoed back in the C2H record
//   word 2.. password, big-endian, four bytes per word, zero filled
//
// and hands each candidate to a computing unit that is ready, as one unit input packet: a type
// byte 0 with ctrl, then the 40 header bytes John the Ripper's arbiter_tx sends, then the key
// rounded up to whole words, the last byte with ctrl. The unit stores the 40 + key bytes at the
// start of a free thread's memory, little-endian:
//
//   bytes  0..3   iteration count     (the CPU reads the low 16 bits)
//   bytes  4..7   salt length         (1..16, md5crypt uses 1..8)
//   bytes  8..23  salt, 16 bytes      (salt0..3, byte 0 in bits 7:0 of salt0)
//   bytes 24..27  candidate id        (JtR: word_id, pkt_id)
//   bytes 28..29  generation          (JtR: low half of gen_id)
//   bytes 30..31  zero
//   byte  32      key length
//   bytes 33..39  zero
//   bytes 40..    key
//
// The unit echoes bytes 24..31 back with the digest, so the collector learns the id and the
// generation. The generation is the top's counter of framing resets and batch arms. A unit has
// no reset, so a candidate in flight at a reset still finishes later; the collector drops a
// result whose generation is not the current one rather than count it in the next batch.
//
// A packet once started is always finished, even across rst: a unit given half a packet would
// take the next one's bytes as the rest of it. Only the intake and a send not yet started are
// reset.

`timescale 1ns / 1ps
module hcfpga_md5crypt_feed #(
  parameter NUM_UNITS = 1
)(
  input  wire CLK,
  input  wire rst,

  input  wire [31:0] s_data,
  input  wire        s_valid,
  output wire        s_ready,
  input  wire        s_last,

  output wire [31:0] frame_status,

  input  wire [31:0] salt0,
  input  wire [31:0] salt1,
  input  wire [31:0] salt2,
  input  wire [31:0] salt3,
  input  wire [31:0] iter_count,
  input  wire [31:0] salt_len,

  input  wire [15:0] gen,

  output reg  [7:0]           unit_in       = 0,
  output reg                  unit_in_ctrl  = 0,
  output reg  [NUM_UNITS-1:0] unit_in_wr_en = 0,
  input  wire [NUM_UNITS-1:0] unit_in_afull,
  input  wire [NUM_UNITS-1:0] unit_in_ready
);

  localparam [7:0] H2C_TAG = 8'hbc;
  localparam [7:0] PW_MAX  = 8'd64;

  localparam UW = (NUM_UNITS <= 1) ? 1 : $clog2(NUM_UNITS);

  // Intake ----------------------------------------------------------------------------------------

  reg [31:0] pw_buf [0:15];
  reg [7:0]  rec_len = 0;
  reg [31:0] rec_id  = 0;

  reg [4:0]  in_wcnt   = 0;
  reg [4:0]  rec_words = 5'd2;
  reg        rec_full  = 0;

  wire       rec_taken;
  wire       send_busy;

  reg       frame_slip = 0;
  reg       last_seen  = 0;
  reg [7:0] slip_count = 0;

  assign frame_status = {16'd0, slip_count, 6'd0, last_seen, frame_slip};

  assign s_ready = (rst == 1'b0) & (rec_full == 1'b0);

  wire       hdr_word = (in_wcnt == 5'd0);
  wire       hdr_bad  = (s_data[31:24] != H2C_TAG) | (s_data[7:0] > PW_MAX);
  wire [7:0] hdr_len  = s_data[7:0];

  wire [4:0] hdr_words = 5'd2 + hdr_len[6:2] + ((hdr_len[1:0] != 2'd0) ? 5'd1 : 5'd0);

  wire take = s_valid & s_ready;

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      in_wcnt    <= 0;
      rec_words  <= 5'd2;
      frame_slip <= 0;
      last_seen  <= 0;
      slip_count <= 0;

      // A record already being sent stays until its packet is out, see the header.
      if (send_busy == 1'b0) rec_full <= 0;
      else if (rec_taken == 1'b1) rec_full <= 0;
    end
    else
    begin
      if (rec_taken == 1'b1) rec_full <= 0;

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
            in_wcnt   <= 5'd1;
          end
        end
        else
        begin
          if (in_wcnt == 5'd1)
            rec_id <= s_data;
          else
            pw_buf[in_wcnt - 5'd2] <= s_data;

          if (in_wcnt == (rec_words - 1'b1))
          begin
            in_wcnt  <= 0;
            rec_full <= 1'b1;
          end
          else
            in_wcnt <= in_wcnt + 1'b1;
        end
      end
    end
  end

  // Unit transmitter ------------------------------------------------------------------------------

  localparam T_IDLE = 3'd0, T_SEARCH = 3'd1, T_SEARCH2 = 3'd2, T_TYPE = 3'd3, T_DATA = 3'd4, T_DONE = 3'd5;

  reg [2:0]    t_state  = T_IDLE;
  reg [UW-1:0] unit_num = 0;

  reg ready_r = 0;
  reg afull_r = 1;

  always @(posedge CLK)
  begin
    ready_r <= unit_in_ready[unit_num];
    afull_r <= unit_in_afull[unit_num];
  end

  reg [6:0]  byte_idx = 0;
  reg [6:0]  last_idx = 0;
  reg [15:0] gen_r    = 0;

  assign send_busy = (t_state == T_TYPE) | (t_state == T_DATA) | (t_state == T_DONE);
  assign rec_taken = (t_state == T_DONE);

  wire [319:0] hdr = { 56'd0, rec_len, 16'd0, gen_r, rec_id, salt3, salt2, salt1, salt0, salt_len, iter_count };

  wire [5:0]  key_idx  = byte_idx[5:0] - 6'd40;
  wire [31:0] key_word = pw_buf[key_idx[5:2]];

  reg [7:0] key_byte;

  always @(*)
  begin
    case (key_idx[1:0])
      2'd0:    key_byte = key_word[31:24];
      2'd1:    key_byte = key_word[23:16];
      2'd2:    key_byte = key_word[15: 8];
      default: key_byte = key_word[ 7: 0];
    endcase
  end

  wire [7:0] key_pos  = {1'b0, byte_idx} - 8'd40;
  wire [7:0] tx_byte  = (byte_idx < 7'd40)  ? hdr[8*byte_idx[5:0] +: 8]
                      : (key_pos < rec_len) ? key_byte : 8'h00;

  wire [UW-1:0] unit_next = (unit_num == NUM_UNITS-1) ? {UW{1'b0}} : unit_num + 1'b1;

  always @(posedge CLK)
  begin
    unit_in_wr_en <= 0;
    unit_in_ctrl  <= 0;

    case (t_state)
    T_IDLE:
      if ((rec_full == 1'b1) && (rst == 1'b0))
        t_state <= T_SEARCH;

    T_SEARCH:
      if ((rec_full == 1'b0) || (rst == 1'b1))
        t_state <= T_IDLE;
      else if ((ready_r == 1'b1) && (afull_r == 1'b0))
        t_state <= T_TYPE;
      else
      begin
        unit_num <= unit_next;
        t_state  <= T_SEARCH2;
      end

    T_SEARCH2:
      t_state <= T_SEARCH;

    T_TYPE:
    begin
      unit_in                 <= 8'h00;
      unit_in_ctrl            <= 1'b1;
      unit_in_wr_en[unit_num] <= 1'b1;

      gen_r    <= gen;
      byte_idx <= 0;
      last_idx <= 7'd39 + {1'b0, ((rec_len[6:0] + 7'd3) & 7'h7c)};

      t_state  <= T_DATA;
    end

    T_DATA:
      if (afull_r == 1'b0)
      begin
        unit_in                 <= tx_byte;
        unit_in_ctrl            <= (byte_idx == last_idx);
        unit_in_wr_en[unit_num] <= 1'b1;

        byte_idx <= byte_idx + 1'b1;

        if (byte_idx == last_idx) t_state <= T_DONE;
      end

    T_DONE:
    begin
      unit_num <= unit_next;
      t_state  <= T_IDLE;
    end

    default:
      t_state <= T_IDLE;
    endcase
  end

endmodule
