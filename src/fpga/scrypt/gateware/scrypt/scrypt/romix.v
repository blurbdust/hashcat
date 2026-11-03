`timescale 1ns / 1ps
/*
 * This file is part of LiteX-Scrypt.
 *
 * romix.v -- scryptROMix state machine with runtime r and N
 *
 * R parameter sets the MAXIMUM r (BRAM width). r_actual selects runtime r.
 * N_LOG2_MAX sets max BRAM depth. n_log2 selects runtime N = 2^n_log2.
 *
 * V_TABLE_EXTERNAL=0 (default): V table stored in internal BRAM (v_table_bram).
 * V_TABLE_EXTERNAL=1:           V table accessed via external handshake ports
 *                                (for DDR3 or other off-chip memory).
 *
 * Phase A (Fill): V[0]=X; for i=1..N-1: V[i]=BlockMix(V[i-1])
 * Phase B (Mix):  for i=0..N-1: j=Integerify(X) mod N; X=BlockMix(X xor V[j])
 */

module romix #(
   parameter R                = 1,   // Max scrypt block size (compile-time)
   parameter N_LOG2_MAX       = 15,  // Max supported log2(N)
   parameter V_TABLE_EXTERNAL = 0    // 0=internal BRAM, 1=external port
)(
   input CLK,
   input start,
   input [4:0] n_log2,                          // Runtime: log2(N), 1..N_LOG2_MAX
   input [$clog2(R+1)-1:0] r_actual,            // Runtime: r, 1..R
   input [1024*R-1:0] x_in,                     // 128*R bytes initial state (max width)
   output reg [1024*R-1:0] x_out,               // 128*R bytes result (max width)
   output reg done = 0,

   // External V table ports (active when V_TABLE_EXTERNAL=1)
   output reg                   vt_we,          // Write enable pulse
   output reg [N_LOG2_MAX-1:0]  vt_waddr,       // Write address
   output     [1024*R-1:0]      vt_wdata,       // Write data (= X register)
   output reg [N_LOG2_MAX-1:0]  vt_raddr,       // Read address
   input      [1024*R-1:0]      vt_rdata,       // Read data
   output reg                   vt_rd_req,      // Read request pulse
   input                        vt_rd_valid,    // Read data valid
   output reg                   vt_wr_req,      // Write request pulse
   input                        vt_wr_done      // Write accepted
);

   localparam DATA_WIDTH = 1024 * R;
   localparam NUM_BLOCKS_MAX = 2 * R;

   // Latched parameters (captured at start, stable during computation)
   reg [4:0] n_log2_r;
   reg [N_LOG2_MAX-1:0] n_mask;
   reg [N_LOG2_MAX:0]   n_val;
   reg [$clog2(R+1)-1:0] r_actual_r;

   // Working register
   reg [DATA_WIDTH-1:0] X;

   // Expose X as write data for external V table
   assign vt_wdata = X;

   // =========================================================================
   // V table: internal BRAM (V_TABLE_EXTERNAL=0) or external (V_TABLE_EXTERNAL=1)
   // =========================================================================

   // Internal BRAM signals (active when V_TABLE_EXTERNAL=0)
   reg v_we_int;
   reg [N_LOG2_MAX-1:0] v_waddr_int;
   reg [N_LOG2_MAX-1:0] v_raddr_int;
   wire [DATA_WIDTH-1:0] v_rdata_int;

   generate if (V_TABLE_EXTERNAL == 0) begin : gen_vtable_bram
      v_table_bram #(
         .N_LOG2_MAX(N_LOG2_MAX),
         .WIDTH(DATA_WIDTH)
      ) u_vtable (
         .CLK(CLK),
         .we(v_we_int),
         .waddr(v_waddr_int),
         .wdata(X),
         .raddr(v_raddr_int),
         .rdata(v_rdata_int)
      );
   end else begin : gen_vtable_external
      assign v_rdata_int = {DATA_WIDTH{1'b0}};  // unused
   end endgenerate

   // =========================================================================
   // BlockMix instance
   // =========================================================================
   reg bm_start;
   reg [DATA_WIDTH-1:0] bm_in;
   wire [DATA_WIDTH-1:0] bm_out;
   wire bm_done;

   blockmix #(.R(R)) u_blockmix (
      .CLK(CLK),
      .start(bm_start),
      .r_actual(r_actual_r),
      .block_in(bm_in),
      .block_out(bm_out),
      .done(bm_done)
   );

   // Integerify: first 32-bit word of the last 64-byte block for runtime r
   // Last block index = (2*r_actual - 1), at bit offset (2*r_actual - 1) * 512
   // Use MUX over possible r values
   reg [31:0] integerify_word;
   always @(*) begin
      integerify_word = X[512 +: 32]; // default: r=1 -> block 1
      case (r_actual_r)
      1: integerify_word = X[  1*512 +: 32];
      2: integerify_word = X[  3*512 +: 32];
      3: integerify_word = X[  5*512 +: 32];
      4: integerify_word = X[  7*512 +: 32];
      5: integerify_word = X[  9*512 +: 32];
      6: integerify_word = X[ 11*512 +: 32];
      7: integerify_word = X[ 13*512 +: 32];
      8: integerify_word = X[ 15*512 +: 32];
      default: integerify_word = X[1*512 +: 32];
      endcase
   end
   wire [N_LOG2_MAX-1:0] integerify_j = integerify_word[N_LOG2_MAX-1:0] & n_mask;

   // =========================================================================
   // State machine, BRAM path (V_TABLE_EXTERNAL=0)
   // =========================================================================

   generate if (V_TABLE_EXTERNAL == 0) begin : gen_fsm_bram

      localparam ST_IDLE       = 4'd0;
      localparam ST_FILL_STORE = 4'd1;
      localparam ST_FILL_WAIT  = 4'd2;
      localparam ST_MIX_ADDR   = 4'd3;
      localparam ST_MIX_READ   = 4'd4;
      localparam ST_MIX_READ2  = 4'd5;
      localparam ST_MIX_XOR    = 4'd6;
      localparam ST_MIX_WAIT   = 4'd7;
      localparam ST_DONE       = 4'd8;

      reg [3:0] state = ST_IDLE;
      reg [N_LOG2_MAX-1:0] counter;

      always @(posedge CLK) begin
         done <= 0;
         v_we_int <= 0;
         bm_start <= 0;

         // Tie off external port signals in BRAM mode
         vt_we <= 0;
         vt_waddr <= 0;
         vt_raddr <= 0;
         vt_rd_req <= 0;
         vt_wr_req <= 0;

         case (state)
         ST_IDLE: begin
            if (start) begin
               X <= x_in;
               counter <= 0;
               // Latch parameters
               n_log2_r <= n_log2;
               n_mask <= (1 << n_log2) - 1;
               n_val <= 1 << n_log2;
               r_actual_r <= r_actual;
               state <= ST_FILL_STORE;
            end
         end

         // ============ FILL PHASE ============

         ST_FILL_STORE: begin
            v_we_int <= 1;
            v_waddr_int <= counter;
            bm_in <= X;
            bm_start <= 1;
            state <= ST_FILL_WAIT;
         end

         ST_FILL_WAIT: begin
            if (bm_done) begin
               X <= bm_out;
               counter <= counter + 1'b1;
               if (counter == n_val[N_LOG2_MAX-1:0] - 1'b1) begin
                  counter <= 0;
                  state <= ST_MIX_ADDR;
               end else begin
                  state <= ST_FILL_STORE;
               end
            end
         end

         // ============ MIX PHASE ============

         ST_MIX_ADDR: begin
            v_raddr_int <= integerify_j;
            state <= ST_MIX_READ;
         end

         ST_MIX_READ: begin
            state <= ST_MIX_READ2;
         end

         ST_MIX_READ2: begin
            state <= ST_MIX_XOR;
         end

         ST_MIX_XOR: begin
            bm_in <= X ^ v_rdata_int;
            bm_start <= 1;
            state <= ST_MIX_WAIT;
         end

         ST_MIX_WAIT: begin
            if (bm_done) begin
               X <= bm_out;
               counter <= counter + 1'b1;
               if (counter == n_val[N_LOG2_MAX-1:0] - 1'b1) begin
                  x_out <= bm_out;
                  state <= ST_DONE;
               end else begin
                  state <= ST_MIX_ADDR;
               end
            end
         end

         ST_DONE: begin
            done <= 1;
            state <= ST_IDLE;
         end
         endcase
      end

   end endgenerate

   // =========================================================================
   // State machine, external path (V_TABLE_EXTERNAL=1)
   // =========================================================================

   generate if (V_TABLE_EXTERNAL == 1) begin : gen_fsm_ext

      localparam ST_IDLE           = 4'd0;
      localparam ST_FILL_WRITE     = 4'd1;   // Assert vt_wr_req, wait vt_wr_done
      localparam ST_FILL_BM_START  = 4'd2;   // Start BlockMix
      localparam ST_FILL_BM_WAIT   = 4'd3;   // Wait for BlockMix done
      localparam ST_MIX_ADDR       = 4'd4;   // Assert vt_rd_req with address
      localparam ST_MIX_WAIT_RDATA = 4'd5;   // Wait for vt_rd_valid
      localparam ST_MIX_XOR        = 4'd6;   // XOR and start BlockMix
      localparam ST_MIX_BM_WAIT    = 4'd7;   // Wait for BlockMix done
      localparam ST_DONE           = 4'd8;

      reg [3:0] state = ST_IDLE;
      reg [N_LOG2_MAX-1:0] counter;

      always @(posedge CLK) begin
         done <= 0;
         bm_start <= 0;

         // Tie off internal BRAM signals in external mode
         v_we_int <= 0;
         v_waddr_int <= 0;
         v_raddr_int <= 0;

         case (state)
         ST_IDLE: begin
            vt_we <= 0;
            vt_wr_req <= 0;
            vt_rd_req <= 0;
            if (start) begin
               X <= x_in;
               counter <= 0;
               // Latch parameters
               n_log2_r <= n_log2;
               n_mask <= (1 << n_log2) - 1;
               n_val <= 1 << n_log2;
               r_actual_r <= r_actual;
               state <= ST_FILL_WRITE;
            end
         end

         // ============ FILL PHASE (external) ============

         ST_FILL_WRITE: begin
            // Request write: address and data (X via vt_wdata) are valid
            vt_we <= 1;
            vt_waddr <= counter;
            vt_wr_req <= 1;
            if (vt_wr_done) begin
               vt_we <= 0;
               vt_wr_req <= 0;
               state <= ST_FILL_BM_START;
            end
         end

         ST_FILL_BM_START: begin
            bm_in <= X;
            bm_start <= 1;
            state <= ST_FILL_BM_WAIT;
         end

         ST_FILL_BM_WAIT: begin
            if (bm_done) begin
               X <= bm_out;
               counter <= counter + 1'b1;
               if (counter == n_val[N_LOG2_MAX-1:0] - 1'b1) begin
                  counter <= 0;
                  state <= ST_MIX_ADDR;
               end else begin
                  state <= ST_FILL_WRITE;
               end
            end
         end

         // ============ MIX PHASE (external) ============

         ST_MIX_ADDR: begin
            vt_raddr <= integerify_j;
            vt_rd_req <= 1;
            state <= ST_MIX_WAIT_RDATA;
         end

         ST_MIX_WAIT_RDATA: begin
            vt_rd_req <= 0;
            if (vt_rd_valid) begin
               state <= ST_MIX_XOR;
            end
         end

         ST_MIX_XOR: begin
            bm_in <= X ^ vt_rdata;
            bm_start <= 1;
            state <= ST_MIX_BM_WAIT;
         end

         ST_MIX_BM_WAIT: begin
            if (bm_done) begin
               X <= bm_out;
               counter <= counter + 1'b1;
               if (counter == n_val[N_LOG2_MAX-1:0] - 1'b1) begin
                  x_out <= bm_out;
                  state <= ST_DONE;
               end else begin
                  state <= ST_MIX_ADDR;
               end
            end
         end

         ST_DONE: begin
            done <= 1;
            state <= ST_IDLE;
         end
         endcase
      end

   end endgenerate

endmodule
