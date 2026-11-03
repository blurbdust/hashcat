`timescale 1ns / 1ps
/*
 * This file is part of LiteX-Scrypt.
 *
 * pbkdf2_sha256.v: PBKDF2-SHA256 with c=1, specialized for scrypt
 *
 * scrypt calls PBKDF2-SHA256 twice, always with iteration count c=1:
 *
 * 1. EXPAND: B = PBKDF2-SHA256(password, salt, 1, 128)
 *    Produces 128 bytes = 4 HMAC-SHA256 blocks (each 32 bytes).
 *    HMAC-SHA256(password, salt || INT32BE(i)) for i = 1..4
 *
 * 2. DERIVE: DK = PBKDF2-SHA256(password, B_mixed, 1, 32)
 *    Produces 32 bytes = 1 HMAC-SHA256 block.
 *    HMAC-SHA256(password, B_mixed || INT32BE(1))
 *    B_mixed is 128 bytes, so the HMAC message is 132 bytes (3 SHA-256 blocks
 *    with ipad: ipad(64) + msg0(64) + msg1(64+padding)).
 *
 * This module supports both operations via the `mode` input:
 *   mode=0 (EXPAND): salt up to 32 bytes, dkLen=128, produces 4 HMAC blocks
 *   mode=1 (DERIVE): B_mixed = 128 bytes, dkLen=32, produces 1 HMAC block
 *
 * Interface:
 *   start + password + salt/B_mixed + mode -> done + dk_out
 *
 * Password handling:
 *   - Password up to 64 bytes (zero-padded). If >64 bytes, caller must
 *     pre-hash with SHA-256 and pass the 32-byte hash as password.
 *   - ipad_block and opad_block are computed internally from password.
 *
 * As hashcat uses it: r, 1..R, is taken at start. EXPAND produces 128*r bytes
 * (4*r HMAC blocks), and DERIVE hashes the 128*r bytes of B_mixed (2*r SHA-256
 * blocks). b_mixed and dk_out keep byte 0 in bits 7:0, as romix does; the module
 * turns each 64-byte block it hashes and each 32-byte result around for SHA-256.
 * b_mixed is not copied: it has to hold still until done.
 */

// Modified for hashcat from LiteX-Scrypt's original.
// src/fpga/scrypt/PROVENANCE.md lists every change.

module pbkdf2_sha256 #(
   parameter R = 1             // Max scrypt r (compile-time)
)(
   input CLK,
   input start,

   // Runtime r, 1..R, taken at start
   input [$clog2(R+1)-1:0] r,

   // Password (up to 64 bytes, zero-padded, big-endian)
   input [511:0] password,     // 64 bytes
   input [7:0] password_len,   // Actual length (0-64)

   // Salt (for EXPAND mode) or B_mixed (for DERIVE mode)
   // For EXPAND: salt up to 32 bytes at salt[255:0] portion, rest zero
   input [255:0] salt,         // Up to 32 bytes (big-endian)
   input [7:0] salt_len,       // Actual salt length (1-32)

   // B_mixed for DERIVE mode (128*r bytes, byte 0 in bits 7:0)
   input [1024*R-1:0] b_mixed,

   // Mode: 0 = EXPAND (dkLen=128), 1 = DERIVE (dkLen=32)
   input mode,

   // Output: 128*r bytes for EXPAND, 32 bytes for DERIVE, byte 0 in bits 7:0
   // For EXPAND: dk_out[1024*r-1:0] = T(4r)(32B) || ... || T2(32B) || T1(32B)
   // For DERIVE: dk_out[255:0] = T1(32B)
   output reg [1024*R-1:0] dk_out,
   output reg done = 0
);

   localparam DATA_WIDTH = 1024 * R;
   localparam BLK_BITS   = (R <= 1) ? 1 : $clog2(2 * R);   // index of a 64-byte block of B_mixed

   // Byte 0 in bits 7:0 (romix's order) to byte 0 in the top bits (SHA-256's) and back.
   function [511:0] rev_bytes64;
      input [511:0] v;
      integer b;
      for (b = 0; b < 64; b = b + 1)
         rev_bytes64[8*b +: 8] = v[504 - 8*b +: 8];
   endfunction

   function [255:0] rev_bytes32;
      input [255:0] v;
      integer b;
      for (b = 0; b < 32; b = b + 1)
         rev_bytes32[8*b +: 8] = v[248 - 8*b +: 8];
   endfunction

   // HMAC instance
   reg hmac_start;
   reg [511:0] hmac_ipad;
   reg [511:0] hmac_opad;
   reg [511:0] hmac_msg0;
   reg [511:0] hmac_msg1;
   reg [1:0] hmac_msg_blocks;
   wire [255:0] hmac_out;
   wire hmac_done;

   hmac_sha256 u_hmac (
      .CLK(CLK),
      .start(hmac_start),
      .ipad_block(hmac_ipad),
      .opad_block(hmac_opad),
      .msg_block0(hmac_msg0),
      .msg_block1(hmac_msg1),
      .msg_blocks(hmac_msg_blocks),
      .hmac_out(hmac_out),
      .done(hmac_done)
   );

   // Pre-computed ipad/opad blocks from password
   reg [511:0] ipad_block;
   reg [511:0] opad_block;

   // State machine
   localparam ST_IDLE      = 4'd0;
   localparam ST_PREP_KEYS = 4'd1;  // Compute ipad/opad from password
   localparam ST_HMAC_START = 4'd2; // Start HMAC for current block index
   localparam ST_HMAC_WAIT = 4'd3;  // Wait for HMAC completion
   localparam ST_NEXT      = 4'd4;  // Store result, advance to next block
   localparam ST_DONE      = 4'd5;

   reg [3:0] state = ST_IDLE;
   reg [5:0] block_idx;        // 1..4*r for EXPAND, 1 for DERIVE
   wire [31:0] t_slot = {26'd0, block_idx} - 32'd1;   // T[block_idx] goes to slot block_idx - 1
   reg [5:0] num_blocks;       // 4*r for EXPAND, 1 for DERIVE
   reg mode_reg;
   reg [$clog2(R+1)-1:0] r_reg;

   // Saved inputs
   reg [255:0] salt_reg;
   reg [7:0] salt_len_reg;

   integer i;

   // Build HMAC message blocks for EXPAND mode:
   // Message = salt || INT32BE(block_idx)
   // Salt up to 32 bytes + 4 bytes index + SHA-256 padding
   // Total message: salt_len + 4 bytes
   // After ipad(64B), this fits in 1 SHA-256 block if salt_len + 4 <= 64
   // For salt_len <= 32: salt(32) + idx(4) = 36 bytes -> fits in 1 block
   //
   // Block layout (64 bytes):
   //   [0..salt_len-1]: salt bytes
   //   [salt_len..salt_len+3]: INT32BE(block_idx)
   //   [salt_len+4]: 0x80
   //   [...]: zeros
   //   [last 8 bytes]: bit length = (64 + salt_len + 4) * 8

   // For DERIVE mode:
   // Message = B_mixed(128B) || INT32BE(1)
   // After ipad(64B): 132 bytes of message = 2 SHA-256 blocks + padding
   // Block 0: B_mixed[0..63] (64 bytes)
   // Block 1: B_mixed[64..127](64B) || INT32BE(1)(4B) || 0x80 || zeros || length
   // But 64+4+1 = 69 > 64, so we need 3 message blocks:
   // Block 0: B_mixed[0..63]
   // Block 1: B_mixed[64..127]
   // Block 2: INT32BE(1) || 0x80 || zeros || length
   // Total with ipad: 4 SHA-256 blocks = ipad + msg0 + msg1 + msg2
   // But HMAC only supports 2 msg blocks... need to handle this differently.
   //
   // Actually, HMAC internally does SHA256(ipad || msg), so the total is:
   //   ipad(64B) + B_mixed(128B) + INT32BE(1)(4B) + padding
   //   = 196 bytes before padding -> needs ceil(196/64) = 4 SHA-256 blocks
   //   Block 0: ipad (64B), handled by HMAC
   //   Block 1: B_mixed[0:63], msg_block0
   //   Block 2: B_mixed[64:127], msg_block1
   //   Block 3: INT32BE(1) + 0x80 + zeros + length, msg_block2
   //
   // We need to extend HMAC to support 3 message blocks for DERIVE mode,
   // OR we can pre-compute SHA256(ipad || B_mixed[0:63] || B_mixed[64:127])
   // and then feed one more block to the sha256 core directly.
   //
   // Simpler approach: for DERIVE mode, call SHA-256 core directly to handle
   // the 4-block inner hash, then compute the 2-block outer hash.
   // Let's handle this with a more detailed state machine.

   // SHA-256 core for direct access in DERIVE mode
   reg sha_direct_start;
   reg [511:0] sha_direct_block;
   reg [255:0] sha_direct_state_in;
   wire [255:0] sha_direct_state_out;
   wire sha_direct_done;

   // SHA-256 IV
   localparam [255:0] SHA256_IV = {
      32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a,
      32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19
   };

   sha256_core u_sha256_direct (
      .CLK(CLK),
      .start(sha_direct_start),
      .block(sha_direct_block),
      .state_in(sha_direct_state_in),
      .state_out(sha_direct_state_out),
      .done(sha_direct_done)
   );

   // Additional states for DERIVE mode (direct SHA-256 chaining)
   localparam ST_DERIVE_INNER0  = 4'd6;  // Inner: ipad block
   localparam ST_DERIVE_INNER1  = 4'd7;  // Inner: B_mixed blocks 0..2r-1, one per call
   localparam ST_DERIVE_INNER3  = 4'd9;  // Inner: INT32BE(1) + padding
   localparam ST_DERIVE_OUTER0  = 4'd10; // Outer: opad block
   localparam ST_DERIVE_OUTER1  = 4'd11; // Outer: inner_hash + padding

   reg [255:0] derive_inner_state;
   reg [BLK_BITS-1:0] derive_blk;        // the B_mixed block being hashed, 0..2r-1
                                         // (block k: bytes 64k..64k+63, b_mixed[512k +: 512])
   wire [31:0] derive_next = {{(32-BLK_BITS){1'b0}}, derive_blk} + 32'd1;

   // Build the last message block for DERIVE inner hash:
   // INT32BE(1) (4 bytes) || 0x80 || zeros || length
   // Length = (64 + 128*r + 4) * 8 bits (r = 1: 196 * 8 = 1568 bits = 0x620)
   wire [63:0] derive_bitlen = 64'd544 + 64'd1024 * r_reg;
   wire [511:0] derive_inner_last_block = {
      32'h0000_0001,            // INT32BE(1)
      8'h80,                    // padding start
      407'b0,                   // zero padding
      1'b0,                     // total 408 zero bits
      derive_bitlen
   };

   // Build outer hash block for DERIVE:
   // inner_hash(32B) || 0x80 || zeros || length
   // Length = (64 + 32) * 8 = 768 bits = 0x300
   wire [511:0] derive_outer_hash_block = {
      derive_inner_state,       // 256 bits
      8'h80,
      183'b0,
      1'b0,
      64'h0000_0000_0000_0300
   };

   // For EXPAND mode: build message block
   // Message = salt || INT32BE(block_idx) || 0x80 || zeros || length
   // Length = (64 + salt_len + 4) * 8 bits
   // This all fits in one 64-byte block since salt_len <= 32
   reg [511:0] expand_msg_block;
   wire [63:0] expand_msg_bitlen = {32'b0, {24'b0, salt_len_reg} + 32'd68} << 3;

   // Build expand message block dynamically
   // Layout: salt bytes (big-endian) | INT32BE(idx) | 0x80 | zeros | length
   always @(*) begin
      expand_msg_block = 512'b0;
      // Place salt at the beginning (big-endian byte order)
      // salt[255:0] contains up to 32 bytes, MSB-first
      // We need salt bytes at positions [511:256] of the message block
      for (i = 0; i < 32; i = i + 1) begin
         if (i < salt_len_reg)
            expand_msg_block[511 - i*8 -: 8] = salt_reg[255 - i*8 -: 8];
      end
      // INT32BE(block_idx) at offset salt_len
      expand_msg_block[511 - salt_len_reg*8 -: 32] = {26'b0, block_idx};
      // 0x80 padding byte
      expand_msg_block[511 - (salt_len_reg + 4)*8 -: 8] = 8'h80;
      // Length at end (last 64 bits)
      expand_msg_block[63:0] = expand_msg_bitlen;
   end

   always @(posedge CLK) begin
      done <= 0;
      hmac_start <= 0;
      sha_direct_start <= 0;

      case (state)
      ST_IDLE: begin
         if (start) begin
            // Compute ipad/opad from password
            for (i = 0; i < 16; i = i + 1) begin
               ipad_block[i*32 +: 32] <= password[i*32 +: 32] ^ 32'h36363636;
               opad_block[i*32 +: 32] <= password[i*32 +: 32] ^ 32'h5C5C5C5C;
            end
            salt_reg <= salt;
            salt_len_reg <= salt_len;
            mode_reg <= mode;
            r_reg <= r;
            block_idx <= 1;
            num_blocks <= mode ? 6'd1 : 6'd4 * r;     // DERIVE 1, EXPAND 4*r
            state <= ST_PREP_KEYS;
         end
      end

      ST_PREP_KEYS: begin
         if (mode_reg) begin
            // DERIVE mode: use direct SHA-256 chaining
            // Start inner hash: SHA256(ipad || B_mixed || INT32BE(1) || padding)
            sha_direct_block <= ipad_block;
            sha_direct_state_in <= SHA256_IV;
            sha_direct_start <= 1;
            state <= ST_DERIVE_INNER0;
         end else begin
            // EXPAND mode: use HMAC for each block
            state <= ST_HMAC_START;
         end
      end

      // ===== EXPAND mode: HMAC-SHA256(password, salt || INT32BE(i)) =====

      ST_HMAC_START: begin
         hmac_ipad <= ipad_block;
         hmac_opad <= opad_block;
         hmac_msg0 <= expand_msg_block;
         hmac_msg1 <= 512'b0;
         hmac_msg_blocks <= 2'd1;
         hmac_start <= 1;
         state <= ST_HMAC_WAIT;
      end

      ST_HMAC_WAIT: begin
         if (hmac_done) begin
            // Store T[block_idx] into dk_out, bytes 32*(block_idx-1).., byte 0 in bits 7:0
            dk_out[256*t_slot +: 256] <= rev_bytes32(hmac_out);
            state <= ST_NEXT;
         end
      end

      ST_NEXT: begin
         block_idx <= block_idx + 1'b1;
         if (block_idx == num_blocks) begin
            state <= ST_DONE;
         end else begin
            state <= ST_HMAC_START;
         end
      end

      // ===== DERIVE mode: direct SHA-256 chaining =====

      ST_DERIVE_INNER0: begin
         // Wait for ipad block hash
         if (sha_direct_done) begin
            derive_inner_state <= sha_direct_state_out;
            // Hash B_mixed block 0 (first 64 bytes, big-endian)
            derive_blk <= 0;
            sha_direct_block <= rev_bytes64(b_mixed[511:0]);
            sha_direct_state_in <= sha_direct_state_out;
            sha_direct_start <= 1;
            state <= ST_DERIVE_INNER1;
         end
      end

      ST_DERIVE_INNER1: begin
         if (sha_direct_done) begin
            derive_inner_state <= sha_direct_state_out;
            sha_direct_state_in <= sha_direct_state_out;
            sha_direct_start <= 1;
            if ({1'b0, derive_blk} == {r_reg, 1'b0} - 1'b1) begin
               // Hash last block: INT32BE(1) + padding
               sha_direct_block <= derive_inner_last_block;
               state <= ST_DERIVE_INNER3;
            end else begin
               // Hash the next 64 bytes of B_mixed
               derive_blk <= derive_blk + 1'b1;
               sha_direct_block <= rev_bytes64(b_mixed[512*derive_next +: 512]);
            end
         end
      end

      ST_DERIVE_INNER3: begin
         if (sha_direct_done) begin
            // Inner hash complete
            derive_inner_state <= sha_direct_state_out;
            // Start outer hash: SHA256(opad || inner_hash || padding)
            sha_direct_block <= opad_block;
            sha_direct_state_in <= SHA256_IV;
            sha_direct_start <= 1;
            state <= ST_DERIVE_OUTER0;
         end
      end

      ST_DERIVE_OUTER0: begin
         if (sha_direct_done) begin
            // Hash inner_hash + padding
            sha_direct_block <= derive_outer_hash_block;
            sha_direct_state_in <= sha_direct_state_out;
            sha_direct_start <= 1;
            state <= ST_DERIVE_OUTER1;
         end
      end

      ST_DERIVE_OUTER1: begin
         if (sha_direct_done) begin
            dk_out[255:0] <= rev_bytes32(sha_direct_state_out);
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
