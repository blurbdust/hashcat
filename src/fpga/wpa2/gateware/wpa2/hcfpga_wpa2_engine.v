/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// wpa2's engine: the WPA PMK, PBKDF2-HMAC-SHA1 (passphrase, ESSID, 4096 iterations, 32 bytes), from
// the password of an H2C record and the ESSID in the registers.
//
//   setup unit   one OpenCiphers SHA-1 core (sha1/Sha1.v, Sha1Full) with its message memory
//                (wpapsk/Sha1BRAM.v), shared by every pair: the HMAC setup of a candidate in six
//                compressions, ipad = SHA1-compress (IV, K ^ 0x36..), opad = SHA1-compress (IV,
//                K ^ 0x5c..), and for block i = 1, 2: inner = SHA1-compress (ipad, ESSID || INT (i) ||
//                padding), U1 (i) = SHA1-compress (opad, inner || padding). K is the password, zero
//                filled to 64 bytes (WPA passphrases are 8 to 63 bytes, so never hashed first).
//   NUM_CORES    pairs of OpenCiphers PBKDF2 cores (wpapsk/PBKDF2.v), one candidate each: the first
//                runs block 1 from U1 (1), the second block 2 from U1 (2), side by side, 4096
//                iterations each. The PMK is block 1's 20 bytes and the first 12 of block 2's.
//   collector    reads a finished pair and sends its PMK as two C2H records.
//
// Contract with the top (src/fpga/common/template, the custom engine), PARTS = 2:
//
// - A record is ready while rec_valid is high: rec_len, rec_id, and the password through
//   pw_rd_addr/pw_rd_data (word k = bytes 4k..4k+3, big-endian, as SHA-1 reads them). The setup unit
//   takes it, holds it (hold) while it computes the setup, and pulses rec_taken when it hands the
//   candidate to a pair. Bytes at and past rec_len are taken as zero, whatever the intake's buffer
//   holds there.
// - Each candidate whose generation is current retires exactly once. A returned one sends two
//   32-byte C2H records one after the other, same id, and retires after the last byte of the
//   second: record 0 carries PMK bytes 0..23 at C2H bytes 4..27, record 1 PMK bytes 24..31 at
//   bytes 4..11 and zeros at 12..27, flags 0x0000 and 0x0100 (the part index in bits 11..8),
//   core_id the pair. A filtered one retires without a record.
// - Comparator: the low 7 bits of PMK byte 3 (C2H byte 7 of record 0; the low byte of the bridge's
//   digest[0] after hcfpga_digest_swap32) index cmp_bitmap. WITH_CMP = 0 returns every candidate,
//   which is how hashcat builds it: hashcat's digest is a MIC or a PMKID that its comp kernels
//   compute from the PMK, so no bit of the PMK can be looked up in a bitmap of digests.
// - A PBKDF2 core cannot be stopped in the middle of a run, so nothing is: a candidate carries the
//   generation (hcfpga_gen.v) of the moment the setup unit took it, a pair always runs to the end,
//   and the collector drops (without a retire) a result whose generation is no longer current. The
//   setup unit drops a candidate it finished after the generation moved on instead of starting a
//   pair. A framing reset in the middle of a result's records abandons them.
// - batch_target and iter_count are not used: candidates go one at a time, and the iteration count
//   is fixed by the format (hashcat's salt_iter is 4095, the count after U1).
//
// PBKDF2.v starts one more SHA-1 compression as it finishes, and a run started before that
// compression ends is corrupted (benched: a restart 80 cycles after Done or later is right, one at
// 78 is not). A pair rests COOL cycles after Done before it takes the next candidate.
//
// A candidate takes about 680,000 cycles on a pair (8191 compressions of 83 cycles); the setup
// unit about 600, so one setup unit can feed about a thousand pairs.

`timescale 1ns / 1ps
module hcfpga_wpa2_engine #(
  parameter NUM_CORES    = 1,
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

  localparam UW = (NUM_CORES <= 1) ? 1 : $clog2(NUM_CORES);

  localparam [UW-1:0] LAST_CORE = NUM_CORES[UW-1:0] - 1'b1;

  localparam [7:0] COOL = 8'd128;

  localparam CMP_BYTE = 3;

  localparam [159:0] SHA1_IV = 160'h67452301_efcdab89_98badcfe_10325476_c3d2e1f0;

  // Generation ------------------------------------------------------------------------------------

  wire [15:0] gen;

  hcfpga_gen gen_i (.CLK(CLK), .rst(rst), .batch_arm(batch_arm), .gen(gen));

  // Setup unit ------------------------------------------------------------------------------------

  localparam S_IDLE = 3'd0, S_LOAD = 3'd1, S_GO = 3'd2, S_WAIT = 3'd3, S_RUN = 3'd4, S_DISPATCH = 3'd5;

  localparam PH_IPAD = 3'd0, PH_OPAD = 3'd1, PH_IN1 = 3'd2, PH_OUT1 = 3'd3, PH_IN2 = 3'd4, PH_OUT2 = 3'd5;

  reg [2:0]  s_state = S_IDLE;
  reg [2:0]  phase   = PH_IPAD;
  reg [3:0]  ld_t    = 0;
  reg [1:0]  wcnt    = 0;

  reg [15:0] c_gen = 0;
  reg [31:0] c_id  = 0;
  reg [7:0]  c_len = 0;

  // Five-word SHA-1 states, word A in bits 159:128.
  reg [159:0] ipad_s = 0;
  reg [159:0] opad_s = 0;
  reg [159:0] inner  = 0;
  reg [159:0] u1a    = 0;
  reg [159:0] u1b    = 0;

  reg         sha_go = 0;
  reg [159:0] sha_in = 0;

  wire        sha_done;
  wire [31:0] sha_ao, sha_bo, sha_co, sha_do, sha_eo;

  wire [3:0]  sw_a0, sw_a1, sw_a2, sw_a3, sw_a4;
  wire [31:0] sw_d0, sw_d1, sw_d2, sw_d3, sw_d4;
  wire        sw_we4;

  // The message memory: the loader writes the 16 words while the core is idle, as OpenCiphers'
  // Sha1Top does over its bus; the core writes the expanded schedule while it runs.
  wire        ld_we = (s_state == S_LOAD);
  reg  [31:0] ld_word;

  Sha1BRAM setup_w (
    .Clk(CLK),
    .WAddr0(sw_a0), .WAddr1(sw_a1), .WAddr2(sw_a2), .WAddr3(sw_a3),
    .WAddr4(sha_go ? sw_a4 : ld_t),
    .WDout0(sw_d0), .WDout1(sw_d1), .WDout2(sw_d2), .WDout3(sw_d3),
    .WDin4(sha_go ? sw_d4 : ld_word),
    .WWE4(sha_go ? sw_we4 : ld_we)
  );

  /* verilator lint_off PINCONNECTEMPTY */
  Sha1Full setup_sha (
    .Clk(CLK), .Go(sha_go), .Wait(1'b0), .Done(sha_done), .Busy(),
    .Ai(sha_in[159:128]), .Bi(sha_in[127:96]), .Ci(sha_in[95:64]), .Di(sha_in[63:32]), .Ei(sha_in[31:0]),
    .Ao(sha_ao), .Bo(sha_bo), .Co(sha_co), .Do(sha_do), .Eo(sha_eo),
    .WAddr0(sw_a0), .WDin0(sw_d0), .WAddr1(sw_a1), .WDin1(sw_d1),
    .WAddr2(sw_a2), .WDin2(sw_d2), .WAddr3(sw_a3), .WDin3(sw_d3),
    .WAddr4(sw_a4), .WDout4(sw_d4), .WWE4(sw_we4)
  );
  /* verilator lint_on PINCONNECTEMPTY */

  // The words of the block being loaded. The key bytes come from the intake (word ld_t), the ESSID
  // bytes from the salt registers, byte 0 in bits 7:0 of salt0.

  assign pw_rd_addr = ld_t[PW_AW-1:0];

  wire [255:0] essid = { salt7, salt6, salt5, salt4, salt3, salt2, salt1, salt0 };
  wire [5:0]   slen  = (salt_len > 32'd32) ? 6'd32 : salt_len[5:0];

  // The inner message is ESSID || INT (i) after the 64-byte key block: (68 + slen) * 8 bits.
  wire [8:0]   msg_bytes = {3'd0, slen} + 9'd68;
  wire [15:0]  bitlen    = {4'd0, msg_bytes, 3'd0};

  wire [7:0]   blk_no = (phase == PH_IN1) ? 8'd1 : 8'd2;

  reg [7:0] mb;
  reg [5:0] j;

  integer k;

  always @(*)
  begin
    ld_word = 32'd0;
    mb      = 8'd0;
    j       = 6'd0;

    case (phase)
    PH_IPAD, PH_OPAD:
      for (k = 0; k < 4; k = k + 1)
      begin
        j  = {ld_t, k[1:0]};
        mb = ({2'd0, j} < c_len) ? pw_rd_data[31 - 8*k -: 8] : 8'h00;
        ld_word[31 - 8*k -: 8] = mb ^ ((phase == PH_IPAD) ? 8'h36 : 8'h5c);
      end

    PH_IN1, PH_IN2:
      if (ld_t == 4'd15)
        ld_word = {16'd0, bitlen};
      else
        for (k = 0; k < 4; k = k + 1)
        begin
          j = {ld_t, k[1:0]};
          if (j < slen)                                mb = essid[8*j[4:0] +: 8];
          else if ({1'b0, j} <  ({1'b0, slen} + 7'd3)) mb = 8'h00;
          else if ({1'b0, j} == ({1'b0, slen} + 7'd3)) mb = blk_no;
          else if ({1'b0, j} == ({1'b0, slen} + 7'd4)) mb = 8'h80;
          else                                         mb = 8'h00;
          ld_word[31 - 8*k -: 8] = mb;
        end

    default:   // PH_OUT1, PH_OUT2: the inner hash, its padding, (64 + 20) * 8 bits
      case (ld_t)
        4'd0:    ld_word = inner[159:128];
        4'd1:    ld_word = inner[127:96];
        4'd2:    ld_word = inner[95:64];
        4'd3:    ld_word = inner[63:32];
        4'd4:    ld_word = inner[31:0];
        4'd5:    ld_word = 32'h80000000;
        4'd15:   ld_word = 32'h000002a0;
        default: ld_word = 32'd0;
      endcase
    endcase
  end

  // Pairs ------------------------------------------------------------------------------------------

  wire [NUM_CORES-1:0] p_free;
  wire [NUM_CORES-1:0] p_ready;
  reg  [NUM_CORES-1:0] p_start     = 0;
  reg  [NUM_CORES-1:0] p_collected = 0;

  reg  [15:0] p_gen [0:NUM_CORES-1];
  reg  [31:0] p_id  [0:NUM_CORES-1];

  wire [255:0] p_pmk [0:NUM_CORES-1];

  function [31:0] bswap (input [31:0] w);
    bswap = { w[7:0], w[15:8], w[23:16], w[31:24] };
  endfunction

  localparam P_FREE = 3'd0, P_RST = 3'd1, P_SET = 3'd2, P_RUN = 3'd3, P_READY = 3'd4, P_COOL = 3'd5;

  genvar c;

  generate
    for (c = 0; c < NUM_CORES; c = c + 1)
    begin : pairs
      reg [2:0] st   = P_FREE;
      reg       prst = 0;
      reg       pgo  = 0;
      reg [7:0] cool = 0;

      wire        done_a, done_b;
      wire [31:0] a_f, a_g, a_h, a_i, a_j;
      wire [31:0] b_f, b_g, b_h;

      // Block 2's last two words are not part of the PMK.
      /* verilator lint_off UNUSEDSIGNAL */
      wire [31:0] b_i, b_j;
      /* verilator lint_on UNUSEDSIGNAL */

      // Both take ipad, opad and their U1 from the setup unit's registers on Rst; those hold the
      // candidate until the setup unit's next compression ends, long after.
      PBKDF2 blk1 (
        .Clk(CLK), .Go(pgo), .Rst(prst), .Done(done_a),
        .ipad_A(ipad_s[159:128]), .ipad_B(ipad_s[127:96]), .ipad_C(ipad_s[95:64]), .ipad_D(ipad_s[63:32]), .ipad_E(ipad_s[31:0]),
        .opad_A(opad_s[159:128]), .opad_B(opad_s[127:96]), .opad_C(opad_s[95:64]), .opad_D(opad_s[63:32]), .opad_E(opad_s[31:0]),
        .mac_F(u1a[159:128]), .mac_G(u1a[127:96]), .mac_H(u1a[95:64]), .mac_I(u1a[63:32]), .mac_J(u1a[31:0]),
        .mac_Fo(a_f), .mac_Go(a_g), .mac_Ho(a_h), .mac_Io(a_i), .mac_Jo(a_j)
      );

      PBKDF2 blk2 (
        .Clk(CLK), .Go(pgo), .Rst(prst), .Done(done_b),
        .ipad_A(ipad_s[159:128]), .ipad_B(ipad_s[127:96]), .ipad_C(ipad_s[95:64]), .ipad_D(ipad_s[63:32]), .ipad_E(ipad_s[31:0]),
        .opad_A(opad_s[159:128]), .opad_B(opad_s[127:96]), .opad_C(opad_s[95:64]), .opad_D(opad_s[63:32]), .opad_E(opad_s[31:0]),
        .mac_F(u1b[159:128]), .mac_G(u1b[127:96]), .mac_H(u1b[95:64]), .mac_I(u1b[63:32]), .mac_J(u1b[31:0]),
        .mac_Fo(b_f), .mac_Go(b_g), .mac_Ho(b_h), .mac_Io(b_i), .mac_Jo(b_j)
      );

      // PMK byte m in bits 8m+7..8m: the PBKDF2 words are big-endian.
      assign p_pmk[c] = { bswap(b_h), bswap(b_g), bswap(b_f), bswap(a_j), bswap(a_i), bswap(a_h), bswap(a_g), bswap(a_f) };

      assign p_free[c]  = (st == P_FREE);
      assign p_ready[c] = (st == P_READY);

      // Rst for a cycle with Go low, a cycle for PBKDF2's Counter to leave Done, then Go until both
      // are done. The results stay until the next Rst.
      always @(posedge CLK)
      begin
        case (st)
        P_FREE:
          if (p_start[c] == 1'b1)
          begin
            prst <= 1'b1;
            st   <= P_RST;
          end

        P_RST:
        begin
          prst <= 1'b0;
          st   <= P_SET;
        end

        P_SET:
        begin
          pgo <= 1'b1;
          st  <= P_RUN;
        end

        P_RUN:
          if ((done_a == 1'b1) && (done_b == 1'b1))
          begin
            pgo  <= 1'b0;
            cool <= 0;
            st   <= P_READY;
          end

        P_READY:
        begin
          if (cool != COOL) cool <= cool + 1'b1;
          if (p_collected[c] == 1'b1) st <= P_COOL;
        end

        P_COOL:
          if (cool != COOL)
            cool <= cool + 1'b1;
          else
            st <= P_FREE;

        default:
          st <= P_FREE;
        endcase
      end
    end
  endgenerate

  // The lowest free pair.

  reg [UW-1:0] free_idx;
  reg          free_any;

  integer f;

  always @(*)
  begin
    free_idx = {UW{1'b0}};
    free_any = 1'b0;
    for (f = NUM_CORES - 1; f >= 0; f = f - 1)
      if (p_free[f] == 1'b1)
      begin
        free_idx = f[UW-1:0];
        free_any = 1'b1;
      end
  end

  wire stale_c = (c_gen != gen);

  assign hold      = (s_state != S_IDLE);
  assign rec_taken = (s_state == S_DISPATCH) & (stale_c | free_any);

  // Setup FSM ------------------------------------------------------------------------------------

  always @(posedge CLK)
  begin
    p_start <= 0;

    case (s_state)
    S_IDLE:
      if ((rec_valid == 1'b1) && (rst == 1'b0))
      begin
        c_gen   <= gen;
        c_id    <= rec_id;
        c_len   <= rec_len;
        phase   <= PH_IPAD;
        ld_t    <= 0;
        s_state <= S_LOAD;
      end

    S_LOAD:
    begin
      ld_t <= ld_t + 1'b1;
      if (ld_t == 4'd15) s_state <= S_GO;
    end

    // Sha1Full starts on a rising Go and shows its last Done for two more cycles: wait them out.
    S_GO:
    begin
      sha_in  <= ((phase == PH_IPAD) || (phase == PH_OPAD)) ? SHA1_IV
               : ((phase == PH_IN1)  || (phase == PH_IN2))  ? ipad_s
               :                                              opad_s;
      sha_go  <= 1'b1;
      wcnt    <= 0;
      s_state <= S_WAIT;
    end

    S_WAIT:
    begin
      wcnt <= wcnt + 1'b1;
      if (wcnt == 2'd2) s_state <= S_RUN;
    end

    S_RUN:
      if (sha_done == 1'b1)
      begin
        case (phase)
          PH_IPAD:          ipad_s <= { sha_ao, sha_bo, sha_co, sha_do, sha_eo };
          PH_OPAD:          opad_s <= { sha_ao, sha_bo, sha_co, sha_do, sha_eo };
          PH_IN1, PH_IN2:   inner  <= { sha_ao, sha_bo, sha_co, sha_do, sha_eo };
          PH_OUT1:          u1a    <= { sha_ao, sha_bo, sha_co, sha_do, sha_eo };
          default:          u1b    <= { sha_ao, sha_bo, sha_co, sha_do, sha_eo };
        endcase

        sha_go <= 1'b0;
        ld_t   <= 0;

        if (phase == PH_OUT2)
          s_state <= S_DISPATCH;
        else
        begin
          phase   <= phase + 1'b1;
          s_state <= S_LOAD;
        end
      end

    // A candidate whose batch was abandoned while it was set up is dropped here.
    S_DISPATCH:
      if (stale_c == 1'b1)
        s_state <= S_IDLE;
      else if (free_any == 1'b1)
      begin
        p_start[free_idx] <= 1'b1;
        p_gen[free_idx]   <= c_gen;
        p_id[free_idx]    <= c_id;
        s_state           <= S_IDLE;
      end

    default:
      s_state <= S_IDLE;
    endcase
  end

  // Collector ------------------------------------------------------------------------------------

  reg [127:0] bitmap = {128{1'b1}};

  always @(posedge CLK)
    if (cmp_load == 1'b1) bitmap <= cmp_bitmap;

  localparam C_SCAN = 2'd0, C_DECIDE = 2'd1, C_EMIT = 2'd2, C_NEXT = 2'd3;

  localparam REST_BITS = 192 * PARTS;

  reg [1:0]    c_state = C_SCAN;
  reg [UW-1:0] cidx    = 0;

  reg [255:0]         frame   = 0;
  reg [4:0]           bytecnt = 0;
  reg [3:0]           part    = 0;
  reg [REST_BITS-1:0] rest    = 0;
  reg [31:0]          id_r    = 0;

  wire [255:0] pmk_sel = p_pmk[cidx];
  wire [6:0]   cmp_idx = pmk_sel[8*CMP_BYTE +: 7];
  wire         cmp_hit = (WITH_CMP == 0) | bitmap[cmp_idx];

  wire [REST_BITS-1:0] pmk_field = { {(REST_BITS - 8*DIGEST_BYTES){1'b0}}, pmk_sel[8*DIGEST_BYTES-1:0] };

  wire [15:0] core_id = {{(16-UW){1'b0}}, cidx};

  wire [UW-1:0] cidx_next = (cidx == LAST_CORE) ? {UW{1'b0}} : cidx + 1'b1;

  assign r_data  = frame[7:0];
  assign r_valid = (c_state == C_EMIT);
  assign r_last  = (c_state == C_EMIT) & (bytecnt == 5'd31);

  always @(posedge CLK)
  begin
    retire      <= 0;
    p_collected <= 0;

    case (c_state)
    C_SCAN:
      if (p_ready[cidx] == 1'b1)
        c_state <= C_DECIDE;
      else
        cidx <= cidx_next;

    C_DECIDE:
      if ((p_gen[cidx] != gen) || (rst == 1'b1))
      begin
        p_collected[cidx] <= 1'b1;
        c_state           <= C_NEXT;
      end
      else if (cmp_hit == 1'b0)
      begin
        retire            <= 1'b1;
        p_collected[cidx] <= 1'b1;
        c_state           <= C_NEXT;
      end
      else
      begin
        frame   <= { 16'h0000, core_id, pmk_field[191:0], p_id[cidx] };
        rest    <= pmk_field >> 192;
        part    <= 0;
        id_r    <= p_id[cidx];
        bytecnt <= 0;
        c_state <= C_EMIT;
      end

    // The parts back to back; the candidate retires after the last byte of the last one.
    C_EMIT:
      if (rst == 1'b1)
      begin
        p_collected[cidx] <= 1'b1;
        c_state           <= C_NEXT;
      end
      else if (r_ready == 1'b1)
      begin
        if ((bytecnt == 5'd31) && (part == PARTS - 1))
        begin
          retire            <= 1'b1;
          p_collected[cidx] <= 1'b1;
          c_state           <= C_NEXT;
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

    // One cycle for the pair to leave P_READY before the scan looks at it again.
    default:
    begin
      cidx    <= cidx_next;
      c_state <= C_SCAN;
    end
    endcase
  end

endmodule
