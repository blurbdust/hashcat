`timescale 1ns / 1ps
/*
 * This file is part of LiteX-Scrypt.
 *
 * hmac_sha256.v: HMAC-SHA256 for PBKDF2
 *
 * Computes HMAC-SHA256(key, msg) where:
 *   - key is up to 64 bytes (pre-padded to 64 bytes by caller)
 *   - msg is up to 128 bytes (2 SHA-256 blocks with padding)
 *
 * HMAC(K, m) = SHA256( (K ^ opad) || SHA256( (K ^ ipad) || m ) )
 *
 * For PBKDF2-SHA256 with c=1 in scrypt:
 *   key = password (padded to 64 bytes, or SHA256(password) if >64 bytes)
 *   msg = salt || INT32BE(block_index) [for expand step]
 *   msg = B_mixed (128 bytes) [for derive step]
 *
 * The caller pre-computes ipad_block = key ^ 0x36 (padded to 64 bytes)
 * and opad_block = key ^ 0x5C (padded to 64 bytes) to save area.
 *
 * State machine:
 *   1. Hash inner: SHA256(ipad_block || msg_block0 [|| msg_block1])
 *   2. Hash outer: SHA256(opad_block || inner_hash_padded)
 *
 * Interface:
 *   start + ipad_block + opad_block + msg + msg_blocks -> done + hmac_out
 *
 * msg_blocks: 1 = single 64-byte msg block, 2 = two 64-byte msg blocks
 * msg: msg_block0 (512 bits) and msg_block1 (512 bits)
 *      Caller must add SHA-256 padding to the last block.
 */

module hmac_sha256 (
   input CLK,
   input start,

   // Key pads (each 64 bytes = 512 bits, pre-XORed by caller)
   input [511:0] ipad_block,   // key ^ 0x36363636...
   input [511:0] opad_block,   // key ^ 0x5C5C5C5C...

   // Message (up to 2 x 512-bit blocks, caller adds SHA-256 padding)
   input [511:0] msg_block0,
   input [511:0] msg_block1,
   input [1:0] msg_blocks,     // 1 or 2 message blocks

   output reg [255:0] hmac_out,
   output reg done = 0
);

   // SHA-256 IV
   localparam [255:0] SHA256_IV = {
      32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a,
      32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19
   };

   // SHA-256 core instance
   reg sha_start;
   reg [511:0] sha_block;
   reg [255:0] sha_state_in;
   wire [255:0] sha_state_out;
   wire sha_done;

   sha256_core u_sha256 (
      .CLK(CLK),
      .start(sha_start),
      .block(sha_block),
      .state_in(sha_state_in),
      .state_out(sha_state_out),
      .done(sha_done)
   );

   // State machine
   localparam ST_IDLE        = 4'd0;
   localparam ST_INNER_IPAD  = 4'd1;  // Hash ipad_block (block 0 of inner)
   localparam ST_INNER_WAIT1 = 4'd2;
   localparam ST_INNER_MSG0  = 4'd3;  // Hash msg_block0 (block 1 of inner)
   localparam ST_INNER_WAIT2 = 4'd4;
   localparam ST_INNER_MSG1  = 4'd5;  // Hash msg_block1 (block 2 of inner, if msg_blocks==2)
   localparam ST_INNER_WAIT3 = 4'd6;
   localparam ST_OUTER_OPAD  = 4'd7;  // Hash opad_block (block 0 of outer)
   localparam ST_OUTER_WAIT1 = 4'd8;
   localparam ST_OUTER_HASH  = 4'd9;  // Hash inner_hash with padding (block 1 of outer)
   localparam ST_OUTER_WAIT2 = 4'd10;
   localparam ST_DONE        = 4'd11;

   reg [3:0] state = ST_IDLE;
   reg [255:0] inner_state;     // Intermediate hash state
   reg [1:0] n_msg_blocks;

   // Build padded block for outer hash:
   // inner_hash (32 bytes) || 0x80 || zeros || length(64+32=96 bytes = 768 bits)
   // 768 = 0x300
   wire [511:0] outer_hash_block = {
      inner_state,              // 256 bits: inner hash result
      8'h80,                    // padding start
      183'b0,                   // zero padding (183 bits to fill)
      1'b0,                     // (184 zeros total before length)
      64'h0000_0000_0000_0300   // length in bits: 768 = 0x300
   };

   always @(posedge CLK) begin
      done <= 0;
      sha_start <= 0;

      case (state)
      ST_IDLE: begin
         if (start) begin
            n_msg_blocks <= msg_blocks;
            // Start hashing ipad block
            sha_block <= ipad_block;
            sha_state_in <= SHA256_IV;
            sha_start <= 1;
            state <= ST_INNER_WAIT1;
         end
      end

      // --- Inner hash: SHA256(ipad || msg) ---

      ST_INNER_WAIT1: begin
         if (sha_done) begin
            inner_state <= sha_state_out;
            // Hash msg_block0
            sha_block <= msg_block0;
            sha_state_in <= sha_state_out;
            sha_start <= 1;
            state <= ST_INNER_WAIT2;
         end
      end

      ST_INNER_WAIT2: begin
         if (sha_done) begin
            inner_state <= sha_state_out;
            if (n_msg_blocks == 2) begin
               // Hash msg_block1
               sha_block <= msg_block1;
               sha_state_in <= sha_state_out;
               sha_start <= 1;
               state <= ST_INNER_WAIT3;
            end else begin
               // Inner hash complete, start outer
               state <= ST_OUTER_OPAD;
            end
         end
      end

      ST_INNER_WAIT3: begin
         if (sha_done) begin
            inner_state <= sha_state_out;
            state <= ST_OUTER_OPAD;
         end
      end

      // --- Outer hash: SHA256(opad || inner_hash) ---

      ST_OUTER_OPAD: begin
         sha_block <= opad_block;
         sha_state_in <= SHA256_IV;
         sha_start <= 1;
         state <= ST_OUTER_WAIT1;
      end

      ST_OUTER_WAIT1: begin
         if (sha_done) begin
            // Hash inner_hash with padding
            sha_block <= outer_hash_block;
            sha_state_in <= sha_state_out;
            sha_start <= 1;
            state <= ST_OUTER_WAIT2;
         end
      end

      ST_OUTER_WAIT2: begin
         if (sha_done) begin
            hmac_out <= sha_state_out;
            state <= ST_DONE;
         end
      end

      ST_DONE: begin
         done <= 1;
         state <= ST_IDLE;
      end
      endcase
   end

endmodule
