/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// C2H tail: retired count, end-of-batch record and granule padding.
//
// Nothing here is md5crypt's. It is the batch accounting of bcrypt's hcfpga_collect_group.v,
// taken out on its own so that any algorithm's collector can sit in front of it:
//
// - retired counts the retire pulses since the last arm or reset, and is the retired register.
// - Writing batch_target arms: target = batch_target, retired = 0. A target of 0 disarms.
// - Once armed and retired >= target, and between two records, one EOB record goes out:
//   bytes 0..3 the retired count little-endian, bytes 4..29 zero, flags 0x8000 at bytes 30..31.
//   EOB records repeat until the number of records sent since the arm, results included, is a
//   multiple of pad_recs (0 or 1: no padding). That fills a DMA granule of pad_recs records.
// - Result records pass through unchanged, one whole record at a time, last on byte 31.

`timescale 1ns / 1ps
module hcfpga_c2h_eob (
  input  wire CLK,
  input  wire rst,

  input  wire        retire,

  input  wire [31:0] batch_target,
  input  wire        batch_arm,

  input  wire [15:0] pad_recs,

  output wire [31:0] retired_cnt,

  input  wire [7:0]  r_data,
  input  wire        r_valid,
  output wire        r_ready,
  input  wire        r_last,

  output wire [7:0]  m_data,
  output wire        m_valid,
  input  wire        m_ready,
  output wire        m_last
);

  localparam [15:0] FLAG_EOB = 16'h8000;

  reg [31:0] retired = 0;

  always @(posedge CLK)
  begin
    if ((rst == 1'b1) || (batch_arm == 1'b1))
      retired <= 0;
    else if (retire == 1'b1)
      retired <= retired + 1'b1;
  end

  assign retired_cnt = retired;

  localparam O_IDLE = 2'd0, O_REC = 2'd1, O_EOB = 2'd2;

  reg [1:0]   o_state = O_IDLE;

  reg         armed   = 0;
  reg [31:0]  target  = 0;
  reg [15:0]  pad_pos = 0;

  reg [255:0] eob_frame = 0;
  reg [4:0]   eob_byte  = 0;

  wire [15:0] pad_mod  = (pad_recs >= 16'd2) ? pad_recs : 16'd1;
  wire        pad_wrap = ((pad_pos + 16'd1) == pad_mod);

  assign r_ready = (o_state == O_REC) & m_ready;

  assign m_data  = (o_state == O_EOB) ? eob_frame[7:0] : r_data;
  assign m_valid = (o_state == O_EOB) | ((o_state == O_REC) & r_valid);
  assign m_last  = (o_state == O_EOB) ? (eob_byte == 5'd31) : ((o_state == O_REC) & r_valid & r_last);

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      o_state  <= O_IDLE;
      armed    <= 0;
      target   <= 0;
      pad_pos  <= 0;
      eob_byte <= 0;
    end
    else
    begin
      if (batch_arm == 1'b1)
      begin
        armed   <= (batch_target != 32'd0);
        target  <= batch_target;
        pad_pos <= 0;
      end

      case (o_state)
      O_IDLE:
        if ((armed == 1'b1) && (batch_arm == 1'b0) && (retired >= target))
        begin
          eob_frame <= { FLAG_EOB, 16'h0000, 192'd0, retired };
          eob_byte  <= 0;
          o_state   <= O_EOB;
        end
        else if (r_valid == 1'b1)
          o_state <= O_REC;

      O_REC:
        if ((m_ready == 1'b1) && (r_valid == 1'b1) && (r_last == 1'b1))
        begin
          if (batch_arm == 1'b0) pad_pos <= pad_wrap ? 16'd0 : (pad_pos + 16'd1);
          o_state <= O_IDLE;
        end

      O_EOB:
        if (m_ready == 1'b1)
        begin
          if (eob_byte == 5'd31)
          begin
            if (batch_arm == 1'b0)
            begin
              pad_pos <= pad_wrap ? 16'd0 : (pad_pos + 16'd1);
              if (pad_wrap == 1'b1) armed <= 0;
            end
            o_state <= O_IDLE;
          end
          else
          begin
            eob_frame <= eob_frame >> 8;
            eob_byte  <= eob_byte + 1'b1;
          end
        end

      default:
        o_state <= O_IDLE;
      endcase
    end
  end

endmodule
