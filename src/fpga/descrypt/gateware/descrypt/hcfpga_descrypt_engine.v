/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// descrypt engine: H2C records from the shared intake in, 32-byte C2H records and retire pulses
// out, NUM_CORES of John the Ripper's DES pipelines (descrypt_core/descrypt16.v) in between.
//
// A core is descrypt16: a ring of 16 registered DES rounds. 16 keys enter it on 16 consecutive
// cycles (START_CRYPT), circle 25 times (400 cycles) and leave it on 16 consecutive cycles, slot i
// at cycle 400 + i after the first key went in. Upstream's descrypt_core.v wraps the same ring in
// this control plus a 35-bit comparator that reports only matches; hashcat compares on the host,
// so the control is here and every result leaves the core.
//
//   loader     takes one record every 2 cycles (the password is 2 words), packs its 8 bytes into
//              upstream's 56-bit word (7 low bits per byte, byte 0 in bits 6:0, zero past len) and
//              writes it with the id into the input buffer of core ld_core. A buffer is handed to
//              its core when it holds 16, when the armed batch has no record left (records taken
//              since the arm = batch_target), or when no record came for IDLE_FLUSH cycles.
//   core c     starts when its buffer is handed over and one of its two result banks is free:
//              16 cycles loading keys (crypt3_ascii2bin, pc1, as upstream's arbiter does) and ids,
//              400 cycles of DES, then 16 cycles writing the results into the bank. A new batch
//              can start in the cycle the previous one's results begin to come out.
//   collector  drains banks whose results are in, slot by slot: the comparator looks up the low
//              7 bits of hashcat's digest[0] in cmp_bitmap; a hit leaves as a C2H record and then
//              retires, a miss retires at once. Empty slots of a short batch are not candidates.
//
// rst (framing reset) clears every buffer, bank and counter. The DES ring needs no reset: START
// loads all 16 slots and Ti starts from zero, so nothing of an abandoned batch reaches the next
// one, and no generation (hcfpga_gen.v) is needed.
//
// C2H record: bytes 0..3 id, 4..11 hashcat's digest_buf[0..1] little-endian (module_01500's
// digest: the DES output block with the initial permutation applied, DES_IP), 12..27 zero,
// 28..29 the core, 30..31 flags 0.

`timescale 1ns / 1ps

`include "descrypt.vh"

module hcfpga_descrypt_engine #(
  parameter integer NUM_CORES  = 1,
  parameter WITH_CMP   = 1,
  parameter IDLE_FLUSH = 4096
)(
  input  wire CLK,
  input  wire rst,

  input  wire        rec_valid,
  input  wire [7:0]  rec_len,
  input  wire [31:0] rec_id,
  output wire        pw_rd_addr,
  input  wire [31:0] pw_rd_data,
  output wire        rec_taken,

  input  wire [11:0] salt,

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

  // 16 slots per core: the ring is 16 rounds deep (upstream: "unchangeable in this version").
  localparam SLOTS = 16;

  // 25 DES encryptions of 16 rounds each.
  localparam [8:0] CRYPT_CYCLES = 9'd400;

  localparam CW = (NUM_CORES <= 1) ? 1 : $clog2(NUM_CORES);

  // Core indexes are CW bits wide; the collector's per-core arrays have 2**CW rows, those past
  // NUM_CORES - 1 tied to nothing ready.
  localparam NC2 = 1 << CW;

  localparam integer LAST = NUM_CORES - 1;

  localparam [CW-1:0] LAST_CORE = LAST[CW-1:0];

  localparam IW = $clog2(IDLE_FLUSH + 1);

  localparam [IW-1:0] IDLE_MAX = IDLE_FLUSH;

  genvar c, k, a, b;

  integer i;

  // ----------------------------------------------------------------------------------------------
  // Loader
  // ----------------------------------------------------------------------------------------------

  reg [CW-1:0] ld_core  = 0;
  reg [3:0]    ld_cnt   = 0;
  reg          ld_word1 = 0;
  reg [31:0]   pw_w0    = 0;

  reg          armed  = 0;
  reg [31:0]   target = 0;
  reg [31:0]   taken  = 0;

  reg [IW-1:0] idle_cnt = 0;

  // Per core: its input buffer was handed over, with in_n entries; the core releases it once loaded.
  reg  [NUM_CORES-1:0] in_ready = 0;
  reg  [4:0]           in_n [0:NUM_CORES-1];
  wire [NUM_CORES-1:0] in_release;

  // The password is word 0 then word 1; the record is taken with word 1.
  assign pw_rd_addr = ld_word1;
  assign rec_taken  = ld_word1;

  // The 8 bytes, big-endian in the two words, packed as upstream's word list packs a candidate
  // (CHAR_BITS 7): byte k in bits 7k+6..7k, its top bit dropped as crypt(3) drops it, zero past len.
  /* verilator lint_off UNUSEDSIGNAL */
  wire [63:0] pw_bytes = { pw_w0, pw_rd_data };
  /* verilator lint_on UNUSEDSIGNAL */

  wire [55:0] ld_word;

  generate
  for (k = 0; k < 8; k = k + 1)
  begin : pack
    assign ld_word[7*k +: 7] = (k < rec_len) ? pw_bytes[56 - 8*k +: 7] : 7'd0;
  end
  endgenerate

  wire ld_write = ld_word1;

  wire batch_drained = armed & (taken == target);

  wire ld_flush = (ld_word1 == 1'b0) & (ld_cnt != 4'd0) & (batch_drained | (idle_cnt == IDLE_MAX));

  wire [CW-1:0] ld_core_next = (ld_core == LAST_CORE) ? {CW{1'b0}} : ld_core + 1'b1;

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      ld_core  <= 0;
      ld_cnt   <= 0;
      ld_word1 <= 0;
      armed    <= 0;
      target   <= 0;
      taken    <= 0;
      idle_cnt <= 0;
      in_ready <= 0;
    end
    else
    begin
      if (batch_arm == 1'b1)
      begin
        armed  <= (batch_target != 32'd0);
        target <= batch_target;
        taken  <= 0;
      end
      else if (ld_write == 1'b1)
        taken <= taken + 1'b1;

      for (i = 0; i < NUM_CORES; i = i + 1)
        if (in_release[i] == 1'b1) in_ready[i] <= 1'b0;

      if (ld_word1 == 1'b1)
      begin
        ld_word1 <= 0;
        idle_cnt <= 0;

        if (ld_cnt == 4'd15)
        begin
          in_ready[ld_core] <= 1'b1;
          in_n[ld_core]     <= 5'd16;
          ld_cnt            <= 0;
          ld_core           <= ld_core_next;
        end
        else
          ld_cnt <= ld_cnt + 1'b1;
      end
      else if (ld_flush == 1'b1)
      begin
        in_ready[ld_core] <= 1'b1;
        in_n[ld_core]     <= {1'b0, ld_cnt};
        ld_cnt            <= 0;
        idle_cnt          <= 0;
        ld_core           <= ld_core_next;
      end
      else
      begin
        if ((rec_valid == 1'b1) && (in_ready[ld_core] == 1'b0))
        begin
          pw_w0    <= pw_rd_data;
          ld_word1 <= 1'b1;
        end

        if ((ld_cnt != 4'd0) && (idle_cnt != IDLE_MAX)) idle_cnt <= idle_cnt + 1'b1;
      end
    end
  end

  // ----------------------------------------------------------------------------------------------
  // Cores
  // ----------------------------------------------------------------------------------------------

  // What the collector sees of each core: per bank, results in and slots holding a candidate; the
  // id and digest of the slot it points at.
  wire [2*NC2-1:0] bank_ready;
  wire [15:0]      bank_vmask [0:2*NC2-1];
  wire [31:0]      col_id_c   [0:NC2-1];
  wire [63:0]      col_dig_c  [0:NC2-1];

  reg  [CW-1:0] col_core = 0;
  reg           col_bank = 0;
  reg  [3:0]    col_slot = 0;
  wire          col_done;          // the collector is done with bank col_bank of core col_core

  generate
  for (c = 0; c < NUM_CORES; c = c + 1)
  begin : cores

    // Input buffer: the loader writes it, the core reads it while loading.
    reg [55:0] in_word [0:SLOTS-1];
    reg [31:0] in_id   [0:SLOTS-1];

    always @(posedge CLK)
      if ((ld_write == 1'b1) && (ld_core == c))
      begin
        in_word[ld_cnt] <= ld_word;
        in_id[ld_cnt]   <= rec_id;
      end

    // run counts from the start (0) to CRYPT_CYCLES, which is also idle.
    reg [8:0]  run      = CRYPT_CYCLES;
    reg        wr_bank  = 0;
    reg        run_bank = 0;
    reg [4:0]  run_n    = 0;
    reg [11:0] run_salt = 0;

    reg [1:0]  busy  = 0;
    reg [1:0]  ready = 0;
    reg [15:0] vmask0 = 0;
    reg [15:0] vmask1 = 0;

    wire start   = (run == CRYPT_CYCLES) & in_ready[c] & ~busy[wr_bank];
    wire loading = start | ((run >= 9'd1) & (run <= 9'd15));

    wire [3:0] slot    = start ? 4'd0 : run[3:0];
    wire       ld_bank = start ? wr_bank : run_bank;
    wire [4:0] n_now   = start ? in_n[c] : run_n;
    wire       slot_ok = ({1'b0, slot} < n_now);

    assign in_release[c] = (run == 9'd15);

    wire [63:0] key64;
    wire [55:0] key56;

    crypt3_ascii2bin ascii2bin (.din(in_word[slot]), .dout(key64));

    pc1 pc1 (.din(key64), .dout(key56));

    wire [`HASH_MSB:0] hash_out;

    /* verilator lint_off PINCONNECTEMPTY */
    descrypt16 ring (
      .CLK(CLK),
      .salt_in(start ? salt : run_salt),
      .key56_in(key56), .valid_in(1'b1),
      .ENABLE_CRYPT(start | (run < CRYPT_CYCLES)),
      .START_CRYPT(loading),
      .hash_out(hash_out), .valid_out()
    );
    /* verilator lint_on PINCONNECTEMPTY */

    // hashcat's digest_buf[0..1] from the DES output block: hash_out is the block after the final
    // permutation (JtR's binary); module_01500 applies the initial permutation and keeps the halves
    // little-endian. Bit 8a + b of the digest is block bit 8 (7 - b) + {0,2,4,6,1,3,5,7}[a].
    wire [63:0] dig;

    for (a = 0; a < 8; a = a + 1)
    begin : dig_byte
      for (b = 0; b < 8; b = b + 1)
      begin : dig_bit
        assign dig[8*a + b] = hash_out[8*(7 - b) + ((a < 4) ? (2*a) : (2*(a - 4) + 1))];
      end
    end

    // Results: two banks of 16, ids written while loading, digests while the ring empties.
    reg [31:0] id_mem  [0:2*SLOTS-1];
    reg [63:0] dig_mem [0:2*SLOTS-1];

    reg       cap      = 0;
    reg [3:0] cap_slot = 0;
    reg       cap_bank = 0;

    always @(posedge CLK)
    begin
      if (loading == 1'b1)
        id_mem[{ld_bank, slot}] <= in_id[slot];

      if (cap == 1'b1)
        dig_mem[{cap_bank, cap_slot}] <= dig;
    end

    wire done_here = col_done & (col_core == c);

    always @(posedge CLK)
    begin
      if (rst == 1'b1)
      begin
        run      <= CRYPT_CYCLES;
        wr_bank  <= 0;
        run_bank <= 0;
        busy     <= 0;
        ready    <= 0;
        cap      <= 0;
      end
      else
      begin
        if (start == 1'b1)
        begin
          run           <= 9'd1;
          run_bank      <= wr_bank;
          wr_bank       <= ~wr_bank;
          run_n         <= in_n[c];
          run_salt      <= salt;
          busy[wr_bank] <= 1'b1;
        end
        else if (run != CRYPT_CYCLES)
          run <= run + 1'b1;

        if (run == CRYPT_CYCLES - 1'b1)
        begin
          cap      <= 1'b1;
          cap_slot <= 0;
          cap_bank <= run_bank;
        end
        else if (cap == 1'b1)
        begin
          cap_slot <= cap_slot + 1'b1;

          if (cap_slot == 4'd15)
          begin
            cap             <= 0;
            ready[cap_bank] <= 1'b1;
          end
        end

        if (done_here == 1'b1)
        begin
          busy[col_bank]  <= 1'b0;
          ready[col_bank] <= 1'b0;
        end
      end

      if (loading == 1'b1)
      begin
        if (ld_bank == 1'b0) vmask0[slot] <= slot_ok;
        else                 vmask1[slot] <= slot_ok;
      end
    end

    assign bank_ready[2*c]     = ready[0];
    assign bank_ready[2*c + 1] = ready[1];

    assign bank_vmask[2*c]     = vmask0;
    assign bank_vmask[2*c + 1] = vmask1;

    assign col_id_c[c]  = id_mem[{col_bank, col_slot}];
    assign col_dig_c[c] = dig_mem[{col_bank, col_slot}];

  end

  for (c = NUM_CORES; c < NC2; c = c + 1)
  begin : no_cores
    assign bank_ready[2*c +: 2] = 2'b00;
    assign bank_vmask[2*c]      = 16'd0;
    assign bank_vmask[2*c + 1]  = 16'd0;
    assign col_id_c[c]          = 32'd0;
    assign col_dig_c[c]         = 64'd0;
  end
  endgenerate

  // ----------------------------------------------------------------------------------------------
  // Collector
  // ----------------------------------------------------------------------------------------------

  reg [127:0] bitmap = {128{1'b1}};

  always @(posedge CLK)
    if (cmp_load == 1'b1) bitmap <= cmp_bitmap;

  localparam [1:0] C_SCAN = 2'd0, C_SLOT = 2'd1, C_EMIT = 2'd2;

  reg [1:0] col_state = C_SCAN;

  reg [255:0] frame   = 0;
  reg [4:0]   bytecnt = 0;

  wire [CW:0] col_bi = {col_core, col_bank};

  wire        cur_ready = bank_ready[col_bi];
  wire [15:0] cur_vmask = bank_vmask[col_bi];

  wire [31:0] cur_id  = col_id_c[col_core];
  wire [63:0] cur_dig = col_dig_c[col_core];

  wire cur_valid = cur_vmask[col_slot];

  wire cmp_hit = (WITH_CMP == 0) | bitmap[cur_dig[6:0]];

  wire last_slot = (col_slot == 4'd15);

  wire emit_end = (col_state == C_EMIT) & r_ready & (bytecnt == 5'd31);

  assign col_done = (col_state == C_SLOT) & last_slot & ~(cur_valid & cmp_hit)
                  | emit_end & last_slot;

  assign r_data  = frame[7:0];
  assign r_valid = (col_state == C_EMIT);
  assign r_last  = (col_state == C_EMIT) & (bytecnt == 5'd31);

  wire [CW-1:0] col_core_next = (col_core == LAST_CORE) ? {CW{1'b0}} : col_core + 1'b1;

  wire [15:0] core_id = {{(16 - CW){1'b0}}, col_core};

  always @(posedge CLK)
  begin
    retire <= 0;

    if (rst == 1'b1)
    begin
      col_state <= C_SCAN;
      col_core  <= 0;
      col_bank  <= 0;
      col_slot  <= 0;
    end
    else
    case (col_state)
    // One (core, bank) per cycle until one has its results in.
    C_SCAN:
      if (cur_ready == 1'b1)
      begin
        col_slot  <= 0;
        col_state <= C_SLOT;
      end
      else
      begin
        col_bank <= ~col_bank;
        if (col_bank == 1'b1) col_core <= col_core_next;
      end

    // One slot per cycle: empty, filtered (retired here) or a record to send.
    C_SLOT:
      if ((cur_valid == 1'b1) && (cmp_hit == 1'b1))
      begin
        frame     <= { 16'h0000, core_id, 128'd0, cur_dig, cur_id };
        bytecnt   <= 0;
        col_state <= C_EMIT;
      end
      else
      begin
        if (cur_valid == 1'b1) retire <= 1'b1;

        if (last_slot == 1'b1)
        begin
          col_bank <= ~col_bank;
          if (col_bank == 1'b1) col_core <= col_core_next;
          col_state <= C_SCAN;
        end
        else
          col_slot <= col_slot + 1'b1;
      end

    C_EMIT:
      if (r_ready == 1'b1)
      begin
        if (bytecnt == 5'd31)
        begin
          retire <= 1'b1;

          if (last_slot == 1'b1)
          begin
            col_bank <= ~col_bank;
            if (col_bank == 1'b1) col_core <= col_core_next;
            col_state <= C_SCAN;
          end
          else
          begin
            col_slot  <= col_slot + 1'b1;
            col_state <= C_SLOT;
          end
        end
        else
        begin
          frame   <= frame >> 8;
          bytecnt <= bytecnt + 1'b1;
        end
      end

    default:
      col_state <= C_SCAN;
    endcase
  end

endmodule
