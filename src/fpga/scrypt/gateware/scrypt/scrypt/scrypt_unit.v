`timescale 1ns / 1ps
/*
 * This file is part of LiteX-Scrypt.
 *
 * scrypt_unit.v -- Per-unit top level (SMix-only + full mode)
 *
 * Arbiter-compatible wrapper around ROMix (+ optional PBKDF2-SHA256).
 *
 * Two modes controlled by FULL_MODE parameter:
 *
 * FULL_MODE=0 (SMix-only):
 *   Receives 128*R-byte precomputed PBKDF2 output, runs ROMix,
 *   outputs 128*R-byte result + IDs via 2-bit streaming output.
 *
 * FULL_MODE=1 (Full scrypt):
 *   Receives password (variable length), salt+N_log2 from cmp_config,
 *   runs PBKDF2-SHA256 expand -> ROMix -> PBKDF2-SHA256 derive,
 *   outputs 32-byte derived key + IDs via 2-bit streaming output.
 *
 * V_TABLE_EXTERNAL=0 (default): V table stored in internal BRAM.
 * V_TABLE_EXTERNAL=1:           V table accessed via external ports (DDR3).
 *
 * Input packet format (from arbiter_tx, between ctrl=1 markers):
 *   Byte 0:       ctrl=1 header (consumed by FIFO)
 *   Byte 1-4:     N_log2 (LE32)
 *   Byte 5-8:     salt_len (LE32, byte 5 has len, 6-8 = 0)
 *   Byte 9-40:    salt (32 bytes)
 *   Byte 41-44:   r_actual (LE32) — runtime scrypt r parameter
 *   Byte 45+:     Payload (SMix: 128*r bytes of B data; Full: password)
 *   Last 8 bytes: IDs (word_id[16], pkt_id[16], gen_id[32])
 *   Final:        ctrl=1 end marker
 *
 * Output data order (2-bit serial):
 *   Words 0-3:  IDs = {word_id, pkt_id, gen_id} (64 bits = 32 shifts)
 *   Words 4+:   Result:
 *     SMix-only: 128*R bytes = 1024*R bits = 512*R shifts, total 32 + 512*R
 *     Full mode: 32 bytes = 256 bits = 128 shifts, total 160 shifts
 */

`include "scrypt.vh"

module scrypt_unit #(
   parameter R                = `SCRYPT_R,
   parameter N_LOG2_MAX       = `N_LOG2_MAX,
   parameter FULL_MODE        = 0,   // 0=SMix-only, 1=Full scrypt with PBKDF2
   parameter V_TABLE_EXTERNAL = `V_TABLE_EXTERNAL
)(
   input CLK,

   // Unit input (from arbiter_tx broadcast + per-unit wr_en)
   input [`UNIT_INPUT_WIDTH-1:0] unit_in,
   input unit_in_ctrl,
   input unit_in_wr_en,
   output unit_in_afull,
   output unit_in_ready,

   // Unit output (2-bit streaming to arbiter_rx)
   output reg [`UNIT_OUTPUT_WIDTH-1:0] dout = 0,
   input rd_en,
   output reg empty = 1,

   // External V table ports (active when V_TABLE_EXTERNAL=1)
   output                              vt_we,
   output [N_LOG2_MAX-1:0]             vt_waddr,
   output [1024*R-1:0]                 vt_wdata,
   output [N_LOG2_MAX-1:0]             vt_raddr,
   input  [1024*R-1:0]                 vt_rdata,
   output                              vt_rd_req,
   input                               vt_rd_valid,
   output                              vt_wr_req,
   input                               vt_wr_done
);

   localparam DATA_WIDTH  = 1024 * R;       // Total data width in bits
   localparam CHUNK_BYTES = 128 * R;        // Input/output byte count
   localparam CHUNK_BITS  = CHUNK_BYTES * 8; // = DATA_WIDTH

   // =========================================================
   // Input FIFO (9-bit: ctrl + data)
   // =========================================================
   wire [8:0] ififo_din = {unit_in_ctrl, unit_in};
   wire ififo_wr_en = unit_in_wr_en;
   wire ififo_full;
   wire [8:0] ififo_dout;
   wire ififo_rd_en;
   wire ififo_empty;

   fifo_sync_fast #(.D_WIDTH(9), .A_WIDTH(4)) input_fifo(
      .CLK(CLK),
      .din(ififo_din), .wr_en(ififo_wr_en & ~ififo_full), .full(ififo_full),
      .dout(ififo_dout), .rd_en(ififo_rd_en), .empty(ififo_empty)
   );

   wire [7:0] ififo_data = ififo_dout[7:0];
   wire ififo_ctrl = ififo_dout[8];

   assign unit_in_afull = ififo_full;

   // =========================================================
   // Input deserialization registers
   // =========================================================
   // CMP_CONFIG header: 44 bytes (N_log2[4] + salt_len[4] + salt[32] + r[4])
   localparam CMP_HDR_BYTES = 44;

   reg [31:0] n_log2_reg;
   reg [31:0] r_reg_raw;            // Runtime r (parsed from CMP_CONFIG preamble)
   wire [11:0] chunk_bytes_r = {r_reg_raw[4:0], 7'b0}; // r * 128
   reg [7:0]  salt_len_reg;
   reg [255:0] salt_reg;       // 32 bytes of salt (big-endian for SHA-256)

   // Payload data
   reg [DATA_WIDTH-1:0] B_reg;   // 128*R bytes for SMix-only mode
   reg [511:0] pw_reg;           // 64 bytes for full mode password
   reg [7:0] pw_len_reg;         // Password length

   reg [63:0] ids;
   reg [11:0] in_byte_cnt;       // Wide enough for 40 + 1024 + 8 = 1072 bytes
   reg [11:0] payload_cnt;       // Counts payload bytes

   // =========================================================
   // ROMix instance
   // =========================================================
   wire romix_done;
   reg romix_start;
   wire [DATA_WIDTH-1:0] romix_out;
   reg [DATA_WIDTH-1:0] romix_in;

   romix #(
      .R(R),
      .N_LOG2_MAX(N_LOG2_MAX),
      .V_TABLE_EXTERNAL(V_TABLE_EXTERNAL)
   ) u_romix (
      .CLK(CLK),
      .start(romix_start),
      .n_log2(n_log2_reg[4:0]),   // Runtime N from CMP_CONFIG
      .r_actual(r_reg_raw[$clog2(R+1)-1:0]),  // Runtime r from CMP_CONFIG
      .x_in(romix_in),
      .x_out(romix_out),
      .done(romix_done),
      // External V table ports (active when V_TABLE_EXTERNAL=1)
      .vt_we(vt_we),
      .vt_waddr(vt_waddr),
      .vt_wdata(vt_wdata),
      .vt_raddr(vt_raddr),
      .vt_rdata(vt_rdata),
      .vt_rd_req(vt_rd_req),
      .vt_rd_valid(vt_rd_valid),
      .vt_wr_req(vt_wr_req),
      .vt_wr_done(vt_wr_done)
   );

   // =========================================================
   // PBKDF2-SHA256 instance (only for full mode)
   // =========================================================
   // Signals declared at module level to avoid generate scope issues
   reg pbkdf2_start_r;
   reg pbkdf2_mode_r;           // 0=expand, 1=derive
   wire pbkdf2_done_w;
   wire [DATA_WIDTH-1:0] pbkdf2_dk_out_w;

   generate if (FULL_MODE) begin : gen_pbkdf2
      pbkdf2_sha256 u_pbkdf2 (
         .CLK(CLK),
         .start(pbkdf2_start_r),
         .password(pw_reg),
         .password_len(pw_len_reg),
         .salt(salt_reg),
         .salt_len(salt_len_reg),
         .b_mixed(romix_out),
         .mode(pbkdf2_mode_r),
         .dk_out(pbkdf2_dk_out_w),
         .done(pbkdf2_done_w)
      );
   end else begin : gen_no_pbkdf2
      assign pbkdf2_done_w = 1'b0;
      assign pbkdf2_dk_out_w = {DATA_WIDTH{1'b0}};
   end endgenerate

   // =========================================================
   // Output streaming registers
   // =========================================================
   // SMix-only: IDs(64b) + result(DATA_WIDTH) = 64 + 1024*R bits
   // Full mode: IDs(64b) + result(256b)        = 320 bits
   localparam OUT_BITS_SMIX = 64 + DATA_WIDTH;
   localparam OUT_BITS_FULL = 320;
   localparam OUT_BITS_MAX  = OUT_BITS_SMIX;  // Use max for shift register width
   localparam OUT_N_WORDS_SMIX = OUT_BITS_SMIX / 2;
   localparam OUT_N_WORDS_FULL = 160;
   localparam OUT_N_WORDS = FULL_MODE ? OUT_N_WORDS_FULL : OUT_N_WORDS_SMIX;

   reg [OUT_BITS_MAX-1:0] out_sr;
   reg [12:0] out_count;          // Wide enough for OUT_N_WORDS_SMIX

   // =========================================================
   // Main state machine
   // =========================================================
   localparam ST_IDLE        = 4'd0;
   localparam ST_RECEIVE     = 4'd1;
   localparam ST_LOAD        = 4'd2;
   localparam ST_RST_SETTLE  = 4'd3;
   localparam ST_RUN         = 4'd4;   // ROMix (SMix-only) or PBKDF2 expand (full)
   localparam ST_OUT_READY   = 4'd5;
   localparam ST_OUT_STREAM  = 4'd6;
   localparam ST_OUT_END     = 4'd7;
   // Full mode additional states
   localparam ST_PBKDF2_EXPAND = 4'd8;
   localparam ST_ROMIX_START   = 4'd9;
   localparam ST_ROMIX_WAIT    = 4'd10;
   localparam ST_PBKDF2_DERIVE = 4'd11;

   reg [3:0] state;

   initial begin
      state = ST_IDLE;
      in_byte_cnt = 0;
      payload_cnt = 0;
      out_count = 0;
      romix_start = 0;
      B_reg = 0;
      pw_reg = 0;
      pw_len_reg = 0;
      n_log2_reg = 0;
      r_reg_raw = 1;
      salt_len_reg = 0;
      salt_reg = 0;
      ids = 0;
      out_sr = 0;
      romix_in = 0;
      pbkdf2_start_r = 0;
      pbkdf2_mode_r = 0;
   end

   assign unit_in_ready = (state == ST_IDLE);

   assign ififo_rd_en = (state == ST_RECEIVE) & ~ififo_empty;

   always @(posedge CLK) begin
      romix_start <= 0;
      if (FULL_MODE) begin
         pbkdf2_start_r <= 0;
      end

      case(state)

      // -------------------------------------------------------
      ST_IDLE: begin
         in_byte_cnt <= 0;
         payload_cnt <= 0;
         if(~ififo_empty & ififo_ctrl) begin
            state <= ST_RECEIVE;
         end
      end

      // -------------------------------------------------------
      ST_RECEIVE: begin
         if(~ififo_empty) begin
            if(ififo_ctrl & in_byte_cnt > 0) begin
               // End of packet: save payload length for full mode
               if (FULL_MODE) begin
                  pw_len_reg <= in_byte_cnt - 12'd53;  // = (in_byte_cnt - 1) - 44 - 8
               end
               state <= ST_LOAD;
            end else begin
               in_byte_cnt <= in_byte_cnt + 1;

               // Byte layout (in_byte_cnt starts at 0 for ctrl header):
               // Byte 0: ctrl=1 header (already consumed as state transition)
               // Bytes 1-4: N_log2 (LE32)
               // Bytes 5-8: salt_len (LE32)
               // Bytes 9-40: salt (32 bytes, stored big-endian for SHA-256)
               // Bytes 41-44: r_actual (LE32)
               // Bytes 45+: payload (B data or password)
               // Last 8 bytes before ctrl=1 end: IDs

               if (in_byte_cnt >= 1 && in_byte_cnt <= 4) begin
                  // N_log2 (LE32)
                  n_log2_reg[(in_byte_cnt-1)*8 +: 8] <= ififo_data;
               end
               else if (in_byte_cnt >= 5 && in_byte_cnt <= 8) begin
                  // salt_len (LE32, only byte 0 matters)
                  if (in_byte_cnt == 5)
                     salt_len_reg <= ififo_data;
               end
               else if (in_byte_cnt >= 9 && in_byte_cnt <= 40) begin
                  // Salt (32 bytes)
                  salt_reg[(40 - in_byte_cnt)*8 +: 8] <= ififo_data;
               end
               else if (in_byte_cnt >= 41 && in_byte_cnt <= 44) begin
                  // r_actual (LE32)
                  r_reg_raw[(in_byte_cnt-41)*8 +: 8] <= ififo_data;
               end
               else if (in_byte_cnt >= 45) begin
                  // Payload: data bytes followed by 8 ID bytes

                  // Shift into B_reg for SMix mode (runtime chunk_bytes_r bytes)
                  if (!FULL_MODE) begin
                     if (payload_cnt < chunk_bytes_r) begin
                        B_reg[payload_cnt*8 +: 8] <= ififo_data;
                     end
                     else if (payload_cnt >= chunk_bytes_r && payload_cnt < chunk_bytes_r + 12'd8) begin
                        ids[(payload_cnt - chunk_bytes_r)*8 +: 8] <= ififo_data;
                     end
                  end

                  // Shift into pw_reg for full mode (64 bytes max password)
                  if (FULL_MODE) begin
                     if (payload_cnt < 64) begin
                        pw_reg[payload_cnt*8 +: 8] <= ififo_data;
                     end
                     // Always keep last 8 bytes as potential IDs
                     ids <= {ififo_data, ids[63:8]};
                  end

                  payload_cnt <= payload_cnt + 1;
               end
            end
         end
      end

      // -------------------------------------------------------
      ST_LOAD: begin
         state <= ST_RST_SETTLE;
         /* verilator lint_off STMTDLY */
         if (FULL_MODE)
            $display("[SCRYPT_UNIT] ST_LOAD (FULL): pw_len=%0d salt_len=%0d n_log2=%0d",
                     pw_len_reg, salt_len_reg, n_log2_reg);
         else
            $display("[SCRYPT_UNIT] ST_LOAD (SMIX): B[0:3]=%08x n_log2=%0d r=%0d R_MAX=%0d",
                     B_reg[31:0], n_log2_reg, r_reg_raw, R);
         /* verilator lint_on STMTDLY */
      end

      // -------------------------------------------------------
      ST_RST_SETTLE: begin
         if (FULL_MODE)
            state <= ST_PBKDF2_EXPAND;
         else begin
            romix_in <= B_reg;
            state <= ST_RUN;
         end
      end

      // =========================================================
      // SMix-only mode: just run ROMix
      // =========================================================
      ST_RUN: begin
         romix_start <= 1;
         if(romix_done) begin
            romix_start <= 0;
            out_sr <= {romix_out, ids};
            out_count <= 0;
            empty <= 0;
            state <= ST_OUT_READY;
            /* verilator lint_off STMTDLY */
            $display("[SCRYPT_UNIT] DONE (SMIX): result[0:3]=%08x",
                     romix_out[31:0]);
            /* verilator lint_on STMTDLY */
         end
      end

      // =========================================================
      // Full mode: PBKDF2 expand -> ROMix -> PBKDF2 derive
      // =========================================================
      ST_PBKDF2_EXPAND: begin
         if (FULL_MODE) begin
            pbkdf2_mode_r <= 0;  // EXPAND mode
            pbkdf2_start_r <= 1;
            if (pbkdf2_done_w) begin
               pbkdf2_start_r <= 0;
               romix_in <= pbkdf2_dk_out_w;
               state <= ST_ROMIX_START;
            end
         end
      end

      ST_ROMIX_START: begin
         romix_start <= 1;
         state <= ST_ROMIX_WAIT;
      end

      ST_ROMIX_WAIT: begin
         if (romix_done) begin
            if (FULL_MODE) begin
               state <= ST_PBKDF2_DERIVE;
            end else begin
               state <= ST_IDLE;
            end
         end
      end

      ST_PBKDF2_DERIVE: begin
         if (FULL_MODE) begin
            pbkdf2_mode_r <= 1;  // DERIVE mode
            pbkdf2_start_r <= 1;
            if (pbkdf2_done_w) begin
               pbkdf2_start_r <= 0;
               out_sr <= {{(OUT_BITS_MAX-320){1'b0}},
                          pbkdf2_dk_out_w[255:0], ids};
               out_count <= 0;
               empty <= 0;
               state <= ST_OUT_READY;
               /* verilator lint_off STMTDLY */
               $display("[SCRYPT_UNIT] DONE (FULL): dk[0:3]=%08x",
                        pbkdf2_dk_out_w[31:0]);
               /* verilator lint_on STMTDLY */
            end
         end
      end

      // =========================================================
      // Output streaming (shared by both modes)
      // =========================================================
      ST_OUT_READY: begin
         if(rd_en) begin
            dout <= {`UNIT_OUTPUT_WIDTH{1'b1}};  // Header: all 1s
            empty <= 1;
            state <= ST_OUT_STREAM;
         end
      end

      ST_OUT_STREAM: begin
         // Auto-advance: output 2 bits per clock from shift register
         dout <= out_sr[`UNIT_OUTPUT_WIDTH-1:0];
         out_sr <= {{`UNIT_OUTPUT_WIDTH{1'b0}}, out_sr[OUT_BITS_MAX-1:`UNIT_OUTPUT_WIDTH]};
         out_count <= out_count + 1'b1;
         if(out_count == OUT_N_WORDS[12:0] - 13'd1)
            state <= ST_OUT_END;
      end

      ST_OUT_END: begin
         dout <= {`UNIT_OUTPUT_WIDTH{1'b0}};  // Trailer: all 0s
         state <= ST_IDLE;
      end

      default: state <= ST_IDLE;
      endcase
   end

endmodule
