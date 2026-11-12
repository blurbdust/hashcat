/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// One DES known-plaintext core: a fully pipelined DES encryption, 16 rounds unrolled, that takes one
// key per clock, and a comparator against the batch's target ciphertexts behind it.
//
// Keys are 56-bit words (K56): key byte b's seven high bits in K56[55-7b -: 7], byte 0 highest; the
// low bit of every key byte is DES's parity bit and does not reach the cipher. A key is the core's
// job (its base word, constant for a whole wave) with the amplifier's bytes on top: the engine
// broadcasts the amplifier positions' bits (K56[55:28], bytes 0..3) to every core each clock, zero
// where the amplifier does not reach, and the base word holds zero where it does.
//
//   S0      hi <= amp_hi | base[55:28]          only while an item is valid for this core, so an idle
//                                               core's pipeline settles and stops toggling
//   R1..R16 one DES round each, the subkey wired from {hi of the stage before, base[27:0]}
//   C1, C2  64-bit compare of the preoutput block (R16 L16) against each enabled target, which the
//           engine hands over as IP(ct); C2 holds the match bits
//
// An item that leaves C2 valid and matching target k is a hit, pushed with the engine's tracking of
// that item (its amplifier item number and the wave's parity, trk_*, aligned to C2) into a small FIFO
// the collector drains. Each target is reported once per wave: seen[k] holds it back after the first.
// A hit that finds the FIFO full sets lost, which stays set until rst.
//
// Latency: an item on amp_hi in cycle t is in C2 during cycle t + LAT.

`timescale 1ns / 1ps

module hcfpga_des_kpa_core #(
  parameter integer NUM_TARGETS = 4,
  parameter integer HIT_DEPTH   = 4,

  parameter integer TW = (NUM_TARGETS <= 2) ? 1 : $clog2(NUM_TARGETS)
)(
  input  wire CLK,
  input  wire rst,

  // Job: ld_we writes the next base word; wave_start makes it the current one, with job_valid
  // saying whether this core has one in the new wave.
  input  wire        ld_we,
  input  wire [55:0] ld_base,
  input  wire        wave_start,
  input  wire        job_valid,

  // The batch: IP(pt), and IP(ct) of each target with its enable.
  input  wire [63:0]                   pt_ip,
  input  wire [64*NUM_TARGETS-1:0]     tgt_ip,
  input  wire [NUM_TARGETS-1:0]        tgt_en,

  // The amplifier bus.
  input  wire [27:0] amp_hi,
  input  wire        amp_valid,

  // The engine's tracking of the item in C2.
  input  wire [31:0] trk_item,
  input  wire        trk_parity,

  output wire          hit_valid,
  output wire [31:0]   hit_item,
  output wire          hit_parity,
  output wire [TW-1:0] hit_tgt,
  input  wire          hit_pop,

  output reg  lost = 0
);

  localparam integer LAT = 19;

  `include "des_kpa_tables.vh"

  genvar r, j, k, i;

  // Subkey bit j (1..48) of round r (1..16) as a K56 bit: PC2 picks a bit of C_r D_r, which is C0 D0
  // rotated left by the shifts so far, PC1 names the key bit that C0 D0 took there.
  function integer ks_idx (input integer rr, input integer jj);
    integer s, n, p, q;
    begin
      s = 0;
      for (n = 1; n <= rr; n = n + 1) s = s + T_SHIFT[(16 - n)*2 +: 2];
      p = T_PC2[(48 - jj)*6 +: 6];
      if (p <= 28) q = ((p - 1 + s) % 28) + 1;
      else         q = 28 + ((p - 29 + s) % 28) + 1;
      n = T_PC1[(56 - q)*7 +: 7];
      ks_idx = 55 - (7 * ((n - 1) / 8) + ((n - 1) % 8));
    end
  endfunction

  function [3:0] sbox (input integer kk, input [5:0] x);
    sbox = T_SBOX[(511 - (kk*64 + {x[5], x[0]}*16 + x[4:1]))*4 +: 4];
  endfunction

  // ----------------------------------------------------------------------------------------------
  // Job
  // ----------------------------------------------------------------------------------------------

  reg [55:0] next_base = 0;
  reg [55:0] base      = 0;
  reg        has_job   = 0;

  always @(posedge CLK)
  begin
    if (ld_we == 1'b1) next_base <= ld_base;

    if (rst == 1'b1)
      has_job <= 0;
    else if (wave_start == 1'b1)
    begin
      base    <= next_base;
      has_job <= job_valid;
    end
  end

  // ----------------------------------------------------------------------------------------------
  // S0 and the rounds
  // ----------------------------------------------------------------------------------------------

  reg [27:0] hi [0:15];
  reg [31:0] L  [1:16];
  reg [31:0] R  [1:16];
  reg        v  [0:16];

  wire item = amp_valid & has_job;

  always @(posedge CLK)
  begin
    if (item == 1'b1) hi[0] <= amp_hi | base[55:28];

    v[0] <= (rst == 1'b0) & item;
  end

  generate
  for (r = 1; r <= 16; r = r + 1)
  begin : rnd
    wire [31:0] lin = (r == 1) ? pt_ip[63:32] : L[(r == 1) ? 1 : r - 1];
    wire [31:0] rin = (r == 1) ? pt_ip[31:0]  : R[(r == 1) ? 1 : r - 1];
    wire [55:0] key = {hi[r - 1], base[27:0]};

    wire [47:0] er;
    wire [47:0] sk;

    for (j = 1; j <= 48; j = j + 1)
    begin : ebit
      assign er[48 - j] = rin[32 - T_E[(48 - j)*6 +: 6]];
      assign sk[48 - j] = key[ks_idx(r, j)];
    end

    wire [47:0] x = er ^ sk;

    wire [31:0] so;

    for (k = 0; k < 8; k = k + 1)
    begin : sb
      assign so[31 - 4*k -: 4] = sbox(k, x[47 - 6*k -: 6]);
    end

    wire [31:0] fo;

    for (i = 1; i <= 32; i = i + 1)
    begin : pbit
      assign fo[32 - i] = so[32 - T_P[(32 - i)*6 +: 6]];
    end

    always @(posedge CLK)
    begin
      L[r] <= rin;
      R[r] <= lin ^ fo;
      v[r] <= (rst == 1'b0) & v[r - 1];
      if (r < 16) hi[(r < 16) ? r : 15] <= hi[r - 1];
    end
  end
  endgenerate

  // ----------------------------------------------------------------------------------------------
  // Compare
  // ----------------------------------------------------------------------------------------------

  wire [63:0] preout = {R[16], L[16]};

  // C1: per target, 16 nibble compares; C2: all 16 equal.
  reg [16*NUM_TARGETS-1:0] eq_nib = 0;
  reg [NUM_TARGETS-1:0]    match  = 0;
  reg                      v1 = 0;
  reg                      v2 = 0;

  integer t, n;

  always @(posedge CLK)
  begin
    for (t = 0; t < NUM_TARGETS; t = t + 1)
      for (n = 0; n < 16; n = n + 1)
        eq_nib[16*t + n] <= (preout[4*n +: 4] == tgt_ip[64*t + 4*n +: 4]) & tgt_en[t];

    for (t = 0; t < NUM_TARGETS; t = t + 1)
      match[t] <= &eq_nib[16*t +: 16];

    v1 <= (rst == 1'b0) & v[16];
    v2 <= (rst == 1'b0) & v1;
  end

  // ----------------------------------------------------------------------------------------------
  // Hits
  // ----------------------------------------------------------------------------------------------

  reg [NUM_TARGETS-1:0] seen = 0;

  wire [NUM_TARGETS-1:0] fresh = match & ~seen & {NUM_TARGETS{v2}};

  reg [TW-1:0] fresh_k;

  always @(*)
  begin
    fresh_k = 0;
    for (t = NUM_TARGETS - 1; t >= 0; t = t - 1)
      if (fresh[t] == 1'b1) fresh_k = t[TW-1:0];
  end

  localparam integer DW = (HIT_DEPTH <= 2) ? 1 : $clog2(HIT_DEPTH);

  reg [32+TW:0] fifo [0:HIT_DEPTH-1];
  reg [DW-1:0]  wr_ptr = 0;
  reg [DW-1:0]  rd_ptr = 0;
  reg [DW:0]    count  = 0;

  wire push = (fresh != 0) & (count != HIT_DEPTH);
  wire pop  = hit_pop & (count != 0);

  always @(posedge CLK)
  begin
    if (push == 1'b1) fifo[wr_ptr] <= {trk_parity, fresh_k, trk_item};

    if (rst == 1'b1)
    begin
      wr_ptr <= 0;
      rd_ptr <= 0;
      count  <= 0;
      seen   <= 0;
      lost   <= 0;
    end
    else
    begin
      if (push == 1'b1) wr_ptr <= (wr_ptr == HIT_DEPTH - 1) ? 0 : wr_ptr + 1'b1;
      if (pop  == 1'b1) rd_ptr <= (rd_ptr == HIT_DEPTH - 1) ? 0 : rd_ptr + 1'b1;

      count <= count + push - pop;

      if (wave_start == 1'b1)
        seen <= 0;
      else if (fresh != 0)
        seen <= seen | (fresh & ~(fresh - 1'b1));

      if ((fresh != 0) && (count == HIT_DEPTH)) lost <= 1'b1;
    end
  end

  wire [32+TW:0] head = fifo[rd_ptr];

  assign hit_valid  = (count != 0);
  assign hit_item   = head[31:0];
  assign hit_tgt    = head[32 +: TW];
  assign hit_parity = head[32 + TW];

endmodule
