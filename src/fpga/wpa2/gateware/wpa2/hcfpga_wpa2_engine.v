/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// wpa2's engine: the WPA PMK, PBKDF2-HMAC-SHA1 (passphrase, ESSID, 4096 iterations, 32 bytes),
// from the password of an H2C record and the ESSID in the registers.
//
//   setup unit   two SHA-1 cores (hcfpga_wpa2_sha1.v) that compute a candidate's HMAC setup in two
//                rounds of two compressions: ipad = SHA1-compress (IV, K ^ 0x36..) and opad =
//                SHA1-compress (IV, K ^ 0x5c..), then inner (i) = SHA1-compress (ipad, ESSID ||
//                INT (i) || padding) for blocks i = 1, 2. K is the password, zero filled to 64 bytes
//                (WPA passphrases are 8 to 63 bytes, so never hashed first).
//   PIPES        pipes (hcfpga_wpa2_pipe.v): an unrolled SHA-1 closed into a ring that holds SLOTS
//                candidates, both PBKDF2 blocks of each, and does one compression a cycle. A pipe
//                starts a candidate from its setup in a free slot and returns T1 and T2, from which
//                the PMK is T1's 20 bytes and the first 12 of T2's.
//   collector    takes the pipes' results in turn and sends each PMK as two C2H records.
//
// A candidate takes 8191 compressions in each block, 8191 * 84 cycles in its slot; a pipe finishes
// one every 16382 cycles, and the setup unit sets one up in about 190.
//
// Contract with the top, PARTS = 2:
//
// - A record is ready while rec_valid is high: rec_len, rec_id, and the password through
//   pw_rd_addr/pw_rd_data (word k = bytes 4k..4k+3, big-endian, as SHA-1 reads them). The setup unit
//   reads the 16 words, holding the record (hold) while it does, and pulses rec_taken with the
//   last. Bytes at and past rec_len are taken as zero, whatever the intake's buffer holds there.
// - Each candidate whose generation is current retires exactly once. A returned one sends two
//   32-byte C2H records one after the other, same id, and retires after the last byte of the
//   second: record 0 carries PMK bytes 0..23 at C2H bytes 4..27, record 1 PMK bytes 24..31 at
//   bytes 4..11 and zeros at 12..27, flags 0x0000 and 0x0100 (the part index in bits 11..8),
//   core_id the slot that computed it (pipe * SLOTS + slot, below the identity's cores=). A
//   filtered one retires without a record.
// - Comparator: the low 7 bits of PMK byte 3 (C2H byte 7 of record 0; the low byte of the bridge's
//   digest[0] after hcfpga_digest_swap32) index cmp_bitmap. WITH_CMP = 0 returns every candidate,
//   which is how hashcat builds it: hashcat's digest is a MIC or a PMKID that its comp kernels
//   compute from the PMK, so no bit of the PMK can be looked up in a bitmap of digests.
// - A candidate carries the generation (hcfpga_gen.v) of the moment the setup unit took it. A
//   framing reset empties the pipes (flush, below), so their candidates never return; the setup
//   unit drops a candidate it finished after the generation moved on, and the collector a result
//   whose generation is not current (a batch armed again without a reset), neither retiring. A
//   framing reset in the middle of a result's records abandons them.
// - batch_target and iter_count are not used: candidates stream through the slots, and the
//   iteration count is fixed by the format (hashcat's salt_iter is 4095, the count after U1).

`timescale 1ns / 1ps
module hcfpga_wpa2_engine #(
  parameter PIPES        = 1,
  parameter PW_MAX       = 63,
  parameter DIGEST_BYTES = 32,
  parameter PARTS        = 2,
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
  /* verilator lint_off UNUSEDSIGNAL */
  input  wire [31:0] iter_count,
  /* verilator lint_on UNUSEDSIGNAL */
  input  wire [31:0] salt_len,
  input  wire [31:0] salt4,
  input  wire [31:0] salt5,
  input  wire [31:0] salt6,
  input  wire [31:0] salt7,

  input  wire [127:0] cmp_bitmap,
  input  wire         cmp_load,

  /* verilator lint_off UNUSEDSIGNAL */
  input  wire [31:0]  batch_target,
  /* verilator lint_on UNUSEDSIGNAL */
  input  wire         batch_arm,

  output reg  retire = 0,

  output wire [7:0] r_data,
  output wire       r_valid,
  input  wire       r_ready,
  output wire       r_last
);

  // Candidates in flight in a pipe: its ring is 2 * SLOTS stages long (hcfpga_wpa2_pipe.v).
  localparam SLOTS = 42;

  localparam QW = (PIPES <= 1) ? 1 : $clog2(PIPES);

  localparam [QW-1:0] LAST_PIPE = PIPES[QW-1:0] - 1'b1;

  localparam CMP_BYTE = 3;

  localparam [159:0] SHA1_IV = 160'h67452301_efcdab89_98badcfe_10325476_c3d2e1f0;

  // A framing reset keeps the pipes flushing until every token has been round once.
  localparam [7:0] FLUSH_CYCLES = 2 * SLOTS + 8;

  function [QW-1:0] next_pipe (input [QW-1:0] q);
    next_pipe = (q == LAST_PIPE) ? {QW{1'b0}} : q + 1'b1;
  endfunction

  function [31:0] bswap (input [31:0] w);
    bswap = { w[7:0], w[15:8], w[23:16], w[31:24] };
  endfunction

  // Generation and flush ---------------------------------------------------------------------

  wire [15:0] gen;

  hcfpga_gen gen_i (.CLK(CLK), .rst(rst), .batch_arm(batch_arm), .gen(gen));

  reg [7:0] flush_cnt = FLUSH_CYCLES;
  reg       flush     = 1;

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
      flush_cnt <= FLUSH_CYCLES;
    else if (flush_cnt != 0)
      flush_cnt <= flush_cnt - 1'b1;

    flush <= (rst == 1'b1) | (flush_cnt != 0);
  end

  // The salt blocks -------------------------------------------------------------------------
  //
  // ESSID || INT (i) || 0x80 || zeros || the bit length of the inner message, (64 + slen + 4) * 8,
  // after the 64-byte key block. Byte j of a block is in bits 511-8j..504-8j; the ESSID's byte 0 is
  // in bits 7:0 of salt0. They change only with the registers, so they are registered.

  wire [255:0] essid  = { salt7, salt6, salt5, salt4, salt3, salt2, salt1, salt0 };
  wire [5:0]   slen   = (salt_len > 32'd32) ? 6'd32 : salt_len[5:0];
  wire [31:0]  slen32 = {26'd0, slen};
  wire [15:0]  bitlen = ({10'd0, slen} + 16'd68) << 3;

  reg  [511:0] salt_blk1, salt_blk2;

  integer j;

  always @(posedge CLK)
    for (j = 0; j < 64; j = j + 1)
    begin
      if (j < slen32)
      begin
        salt_blk1[511 - 8*j -: 8] <= essid[8*(j % 32) +: 8];
        salt_blk2[511 - 8*j -: 8] <= essid[8*(j % 32) +: 8];
      end
      else if (j == slen32 + 3)
      begin
        salt_blk1[511 - 8*j -: 8] <= 8'h01;
        salt_blk2[511 - 8*j -: 8] <= 8'h02;
      end
      else if (j == slen32 + 4)
      begin
        salt_blk1[511 - 8*j -: 8] <= 8'h80;
        salt_blk2[511 - 8*j -: 8] <= 8'h80;
      end
      else if (j == 62)
      begin
        salt_blk1[511 - 8*j -: 8] <= bitlen[15:8];
        salt_blk2[511 - 8*j -: 8] <= bitlen[15:8];
      end
      else if (j == 63)
      begin
        salt_blk1[511 - 8*j -: 8] <= bitlen[7:0];
        salt_blk2[511 - 8*j -: 8] <= bitlen[7:0];
      end
      else
      begin
        salt_blk1[511 - 8*j -: 8] <= 8'h00;
        salt_blk2[511 - 8*j -: 8] <= 8'h00;
      end
    end

  // Setup unit ------------------------------------------------------------------------------
  //
  // Reads the password (16 cycles), then two compressions on each core: the key blocks, then the
  // salt blocks from ipad. The two cores start together and finish together. The result waits in
  // so_* for a pipe while the next candidate is set up.

  localparam S_IDLE = 3'd0, S_READ = 3'd1, S_KEY = 3'd2, S_KEYW = 3'd3, S_SALTW = 3'd4, S_OUT = 3'd5;

  reg [2:0]   s_state = S_IDLE;
  reg [3:0]   rd      = 0;

  reg [31:0]  c_id  = 0;
  reg [7:0]   c_len = 0;
  reg [15:0]  c_gen = 0;

  reg [511:0] key;

  reg         sha_start = 0;
  reg [159:0] sha_iv;
  reg [511:0] sha_blk_a, sha_blk_b;

  /* verilator lint_off UNUSEDSIGNAL */
  wire        done_b;
  /* verilator lint_on UNUSEDSIGNAL */
  wire        done_a;
  wire [159:0] dig_a, dig_b;

  reg [159:0] ipad_s, opad_s, in1_s, in2_s;

  hcfpga_wpa2_sha1 sha_a (.CLK(CLK), .start(sha_start), .iv(sha_iv), .blk(sha_blk_a), .done(done_a), .dig(dig_a));
  hcfpga_wpa2_sha1 sha_b (.CLK(CLK), .start(sha_start), .iv(sha_iv), .blk(sha_blk_b), .done(done_b), .dig(dig_b));

  assign pw_rd_addr = rd[PW_AW-1:0];
  assign hold       = (s_state == S_READ);
  assign rec_taken  = (s_state == S_READ) & (rd == 4'd15);

  // Password word rd, its bytes at and past c_len zeroed.
  reg [31:0] pw_word;
  reg [7:0]  pw_at;

  integer k;

  always @(*)
  begin
    pw_word = 32'd0;
    pw_at   = 8'd0;

    for (k = 0; k < 4; k = k + 1)
    begin
      pw_at = {2'd0, rd, k[1:0]};
      pw_word[31 - 8*k -: 8] = (pw_at < c_len) ? pw_rd_data[31 - 8*k -: 8] : 8'h00;
    end
  end

  // The setup's result, until a pipe takes it.
  reg         so_v = 0;
  reg [159:0] so_ipad, so_opad, so_in1, so_in2;
  reg [31:0]  so_id;
  reg [15:0]  so_gen;

  wire [PIPES-1:0] p_ready;
  reg  [PIPES-1:0] p_load = 0;
  reg  [QW-1:0]    hq     = 0;

  always @(posedge CLK)
  begin
    sha_start <= 0;

    case (s_state)
    S_IDLE:
      if ((rec_valid == 1'b1) && (rst == 1'b0))
      begin
        c_gen   <= gen;
        c_id    <= rec_id;
        c_len   <= rec_len;
        rd      <= 0;
        s_state <= S_READ;
      end

    S_READ:
    begin
      key <= { key[479:0], pw_word };
      rd  <= rd + 1'b1;

      if (rd == 4'd15) s_state <= S_KEY;
    end

    S_KEY:
    begin
      sha_iv    <= SHA1_IV;
      sha_blk_a <= key ^ {64{8'h36}};
      sha_blk_b <= key ^ {64{8'h5c}};
      sha_start <= 1'b1;
      s_state   <= S_KEYW;
    end

    S_KEYW:
      if (done_a == 1'b1)
      begin
        ipad_s    <= dig_a;
        opad_s    <= dig_b;
        sha_iv    <= dig_a;
        sha_blk_a <= salt_blk1;
        sha_blk_b <= salt_blk2;
        sha_start <= 1'b1;
        s_state   <= S_SALTW;
      end

    S_SALTW:
      if (done_a == 1'b1)
      begin
        in1_s   <= dig_a;
        in2_s   <= dig_b;
        s_state <= S_OUT;
      end

    default:   // S_OUT
      if (so_v == 1'b0)
        s_state <= S_IDLE;
    endcase

    // Hand the setup to the next pipe that can take it, round robin. A candidate whose batch was
    // abandoned while it was set up is dropped here.
    p_load <= 0;

    if ((s_state == S_OUT) && (so_v == 1'b0))
    begin
      so_v    <= 1'b1;
      so_ipad <= ipad_s;
      so_opad <= opad_s;
      so_in1  <= in1_s;
      so_in2  <= in2_s;
      so_id   <= c_id;
      so_gen  <= c_gen;
    end
    else if ((so_v == 1'b1) && (flush == 1'b0))
    begin
      if (so_gen != gen)
        so_v <= 1'b0;
      else if (p_ready[hq] == 1'b1)
      begin
        p_load[hq] <= 1'b1;
        so_v       <= 1'b0;
        hq         <= next_pipe (hq);
      end
      else
        hq <= next_pipe (hq);
    end
  end

  // Pipes -----------------------------------------------------------------------------------

  wire [PIPES-1:0] p_avail;
  reg  [PIPES-1:0] p_rd = 0;
  wire [309:0]     p_res [0:PIPES-1];

  genvar q;

  generate
    for (q = 0; q < PIPES; q = q + 1)
    begin : pipes
      wire res_avail;
      reg  avail_r = 0;

      hcfpga_wpa2_pipe #(.SLOTS(SLOTS)) pipe (
        .CLK(CLK), .flush(flush),
        .cand_load(p_load[q]), .cand_ready(p_ready[q]),
        .cand_ipad(so_ipad), .cand_opad(so_opad), .cand_in1(so_in1), .cand_in2(so_in2),
        .cand_id(so_id), .cand_gen(so_gen),
        .res_avail(res_avail), .res_rd(p_rd[q]), .res_data(p_res[q])
      );

      always @(posedge CLK) avail_r <= res_avail;

      assign p_avail[q] = avail_r;
    end
  endgenerate

  // Collector -------------------------------------------------------------------------------

  reg [127:0] bitmap = {128{1'b1}};

  always @(posedge CLK)
    if (cmp_load == 1'b1) bitmap <= cmp_bitmap;

  localparam C_SCAN = 3'd0, C_WAIT = 3'd1, C_DECIDE = 3'd2, C_EMIT = 3'd3, C_NEXT = 3'd4;

  localparam REST_BITS = 192 * PARTS;

  reg [2:0]    c_state = C_SCAN;
  reg [QW-1:0] cq      = 0;
  reg [1:0]    wcnt    = 0;

  // A pipe's result: { gen, id, slot, T1, T2[159:64] }.
  reg [309:0]  ent;

  wire [15:0]  e_gen  = ent[309:294];
  wire [31:0]  e_id   = ent[293:262];
  wire [5:0]   e_slot = ent[261:256];

  wire [15:0]  slot_id = cq * SLOTS[15:0] + {10'd0, e_slot};

  // PMK byte m in bits 8m+7..8m: T1's five words then T2's first three, big-endian words.
  wire [255:0] pmk = { bswap(ent[31:0]),    bswap(ent[63:32]),   bswap(ent[95:64]),
                       bswap(ent[127:96]),  bswap(ent[159:128]), bswap(ent[191:160]),
                       bswap(ent[223:192]), bswap(ent[255:224]) };

  wire [6:0]   cmp_idx = pmk[8*CMP_BYTE +: 7];
  wire         cmp_hit = (WITH_CMP == 0) | bitmap[cmp_idx];

  wire [REST_BITS-1:0] pmk_field = { {(REST_BITS - 8*DIGEST_BYTES){1'b0}}, pmk[8*DIGEST_BYTES-1:0] };

  reg [15:0]          core_id = 0;
  reg [255:0]         frame   = 0;
  reg [4:0]           bytecnt = 0;
  reg [3:0]           part    = 0;
  reg [REST_BITS-1:0] rest    = 0;
  reg [31:0]          id_r    = 0;

  assign r_data  = frame[7:0];
  assign r_valid = (c_state == C_EMIT);
  assign r_last  = (c_state == C_EMIT) & (bytecnt == 5'd31);

  always @(posedge CLK)
  begin
    retire <= 0;
    p_rd   <= 0;

    case (c_state)
    C_SCAN:
      if ((flush == 1'b0) && (p_avail[cq] == 1'b1))
      begin
        p_rd[cq] <= 1'b1;
        wcnt     <= 0;
        c_state  <= C_WAIT;
      end
      else
        cq <= next_pipe (cq);

    // The pipe pops in the next cycle and shows the entry two cycles after that.
    C_WAIT:
    begin
      wcnt <= wcnt + 1'b1;
      if (wcnt == 2'd2)
      begin
        ent     <= p_res[cq];
        c_state <= C_DECIDE;
      end
    end

    C_DECIDE:
      if ((e_gen != gen) || (flush == 1'b1))
        c_state <= C_NEXT;
      else if (cmp_hit == 1'b0)
      begin
        retire  <= 1'b1;
        c_state <= C_NEXT;
      end
      else
      begin
        core_id <= slot_id;
        frame   <= { 16'h0000, slot_id, pmk_field[191:0], e_id };
        rest    <= pmk_field >> 192;
        part    <= 0;
        id_r    <= e_id;
        bytecnt <= 0;
        c_state <= C_EMIT;
      end

    // The parts back to back; the candidate retires after the last byte of the last one.
    C_EMIT:
      if (rst == 1'b1)
        c_state <= C_NEXT;
      else if (r_ready == 1'b1)
      begin
        if ((bytecnt == 5'd31) && (part == PARTS - 1))
        begin
          retire  <= 1'b1;
          c_state <= C_NEXT;
        end
        else if (bytecnt == 5'd31)
        begin
          frame   <= { 4'h0, part + 4'h1, 8'h00, core_id, rest[191:0], id_r };
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

    // One cycle for the pipe's avail to follow the pop before the scan looks at it again.
    default:
    begin
      cq      <= next_pipe (cq);
      c_state <= C_SCAN;
    end
    endcase
  end

endmodule
