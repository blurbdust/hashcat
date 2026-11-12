/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// DES known-plaintext engine: H2C records (jobs) from the shared intake in, 32-byte C2H hit records
// and one retire pulse per job out, NUM_CORES pipelined DES cores (hcfpga_des_kpa_core.v) between.
//
// A job is an 8-byte base word. The device puts every item of the amplifier on top of it: amp_cnt
// (0..4) positions at the front of the key, position p walking the amp_len[p] characters of table p.
// Item i takes digit (i / (len_0 * .. * len_{p-1})) % len_p at position p, position 0 fastest; with
// amp_cnt 0 a job is its one key. Every core runs the same item in the same clock, so one generator
// feeds them all:
//
//   loader     takes one record every 2 cycles and writes it to core ld_cnt as its next job (bytes
//              under the amplifier and past the record's length are zeroed), the id to id_tab.
//   waves      a wave starts when every core holds a next job, or some do and the armed batch has
//              no record left or none came for IDLE_FLUSH cycles: the next jobs become current, the
//              generator walks all amplifier items once, one per clock, and the wave drains through
//              the cores. Waves alternate between two parities, each with its half of id_tab; the
//              loader fills a parity only once the collector has retired its previous wave.
//   generator  digit counters and the four 256-entry tables (written through amp_tab: pos in bits
//              17:16, index in 15:8, the character in 7:0); the amplifier bytes go out on a bus that
//              is registered at the root and once per group of GROUP cores.
//   collector  sweeps the cores without end, sending every hit their FIFOs hold. Once a wave has
//              drained, the sweep after that retires its jobs.
//
// C2H hit record: bytes 0..3 the job's id, 4..7 the amplifier item, 8 the target, 28..29 the core,
// 30..31 flags 0. The host turns item and job into the key: the base word with tab_p[digit p] at
// position p.
//
// Targets: tgt_ct is each target's ciphertext and pt the plaintext, 8 bytes each in hashcat's salt
// word order (byte 0 in bits 7:0 of the low word); tgt_mask enables them. Each target is reported
// once per job.
//
// Thermal stop: die_temp is the die temperature in XADC encoding (code * 503.975 / 4096 - 273.15 C;
// 0 where the board has none). From THERM_HOT_C up the generator stops (therm_stop) until the die
// reads below THERM_COOL_C; the cores then hold their last key and stop toggling, and the wave goes on
// where it stopped once the die has cooled. Nothing is dropped. A reading has to hold for
// THERM_FILTER cycles to count.
//
// rst (framing reset) clears every job, wave, FIFO and counter.

`timescale 1ns / 1ps

module hcfpga_des_kpa_engine #(
  parameter integer NUM_CORES   = 1,
  parameter integer NUM_TARGETS = 4,
  parameter integer GROUP       = 8,
  parameter integer IDLE_FLUSH  = 4096,

  parameter integer THERM_HOT_C  = 85,
  parameter integer THERM_COOL_C = 75
)(
  input  wire CLK,
  input  wire rst,

  input  wire [11:0] die_temp,
  output reg         therm_stop = 0,
  output wire        lost,

  input  wire        rec_valid,
  input  wire [7:0]  rec_len,
  input  wire [31:0] rec_id,
  output wire        pw_rd_addr,
  input  wire [31:0] pw_rd_data,
  output wire        rec_taken,

  input  wire [63:0]                pt,
  input  wire [64*NUM_TARGETS-1:0]  tgt_ct,
  input  wire [NUM_TARGETS-1:0]     tgt_mask,

  input  wire [2:0]  amp_cnt,
  input  wire [31:0] amp_lens,
  input  wire [31:0] amp_tab,
  input  wire        amp_tab_we,

  input  wire [31:0] batch_target,
  input  wire        batch_arm,

  output reg  retire = 0,

  output wire [7:0] r_data,
  output wire       r_valid,
  input  wire       r_ready,
  output wire       r_last
);

  localparam integer CW  = (NUM_CORES <= 1) ? 1 : $clog2(NUM_CORES);
  localparam integer NG  = (NUM_CORES + GROUP - 1) / GROUP;
  localparam integer GW  = (NG <= 1) ? 1 : $clog2(NG);
  localparam integer SW  = (GROUP <= 1) ? 1 : $clog2(GROUP);
  localparam integer TW  = (NUM_TARGETS <= 2) ? 1 : $clog2(NUM_TARGETS);

  localparam integer HIT_DEPTH = NUM_TARGETS;

  // The core's latency, amplifier bus to compare (hcfpga_des_kpa_core.v), and what lies before it:
  // the table read, the root register and the group register.
  localparam integer CORE_LAT = 19;
  localparam integer BUS_LAT  = 3;
  localparam integer DRAIN    = BUS_LAT + CORE_LAT + 4;

  localparam IW = $clog2(IDLE_FLUSH + 1);
  localparam [IW-1:0] IDLE_MAX = IDLE_FLUSH;

  localparam [CW:0] CORES = NUM_CORES;

  `include "des_kpa_tables.vh"

  integer i, p;
  genvar  c, g, b;

  // ----------------------------------------------------------------------------------------------
  // Thermal stop
  // ----------------------------------------------------------------------------------------------

  // The register value the host would read as C + 0.5, as hcfpga_stratixv.py's
  // xadc_temperature_code computes it.
  localparam integer THERM_HOT  = ((THERM_HOT_C  * 1000 + 500 + 273150) * 4096 + 251987) / 503975;
  localparam integer THERM_COOL = ((THERM_COOL_C * 1000 + 500 + 273150) * 4096 + 251987) / 503975;

  localparam [11:0] HOT_CODE  = THERM_HOT[11:0];
  localparam [11:0] COOL_CODE = THERM_COOL[11:0];

  localparam THERM_FILTER = 64;

  reg [11:0] temp_q    = 0;
  reg        temp_hot  = 0;
  reg        temp_cool = 1;
  reg [6:0]  therm_cnt = 0;

  always @(posedge CLK)
  begin
    temp_q    <= die_temp;
    temp_hot  <= (temp_q >= HOT_CODE);
    temp_cool <= (temp_q < COOL_CODE);

    if ((therm_stop == 1'b0) ? (temp_hot == 1'b1) : (temp_cool == 1'b1))
    begin
      if (therm_cnt == THERM_FILTER - 1)
      begin
        therm_stop <= ~therm_stop;
        therm_cnt  <= 0;
      end
      else
        therm_cnt <= therm_cnt + 1'b1;
    end
    else
      therm_cnt <= 0;
  end

  // ----------------------------------------------------------------------------------------------
  // The batch: IP of the plaintext and of every target, registered once here and once per group
  // ----------------------------------------------------------------------------------------------

  function [63:0] ip64 (input [63:0] x);
    integer n;
    begin
      for (n = 1; n <= 64; n = n + 1)
        ip64[64 - n] = x[64 - T_IP[(64 - n)*7 +: 7]];
    end
  endfunction

  // The salt word order to a block, byte 0 most significant.
  function [63:0] block (input [63:0] w);
    integer n;
    begin
      for (n = 0; n < 8; n = n + 1)
        block[63 - 8*n -: 8] = w[8*n +: 8];
    end
  endfunction

  reg [63:0]               pt_ip_q  = 0;
  reg [64*NUM_TARGETS-1:0] tgt_ip_q = 0;
  reg [NUM_TARGETS-1:0]    tgt_en_q = 0;

  always @(posedge CLK)
  begin
    pt_ip_q <= ip64(block(pt));
    for (i = 0; i < NUM_TARGETS; i = i + 1)
      tgt_ip_q[64*i +: 64] <= ip64(block(tgt_ct[64*i +: 64]));
    tgt_en_q <= tgt_mask;
  end

  // ----------------------------------------------------------------------------------------------
  // Loader
  // ----------------------------------------------------------------------------------------------

  reg [CW:0]   ld_cnt   = 0;
  reg          ld_word1 = 0;
  reg [31:0]   pw_w0    = 0;
  reg          p_next   = 0;

  reg          armed  = 0;
  reg [31:0]   target = 0;
  reg [31:0]   taken  = 0;
  reg [IW-1:0] idle_cnt = 0;

  // busy[q]: a wave of parity q started and the collector has not retired it yet.
  reg [1:0]    busy = 0;

  // The retire of a drained wave (collector): armed at the start of a sweep that began after it
  // drained, done at that sweep's end.
  reg         ret_p     = 0;
  reg         ret_armed = 0;
  reg [CW:0]  ret_left  = 0;
  reg         ret_done  = 0;
  reg         ret_done_p = 0;

  reg          wave_start = 0;

  wire start_ok;

  // Not in the cycle a wave starts: p_next moves then, and busy[] has to be read for the new one.
  wire can_load = (ld_cnt != CORES) & (busy[p_next] == 1'b0) & (wave_start == 1'b0) & (start_ok == 1'b0);

  assign pw_rd_addr = ld_word1;
  assign rec_taken  = ld_word1;

  wire [63:0] pw_bytes = { pw_w0, pw_rd_data };

  reg [55:0] ld_word;

  always @(*)
  begin
    for (i = 0; i < 8; i = i + 1)
      ld_word[55 - 7*i -: 7] = ((i < rec_len) && (i >= amp_cnt)) ? pw_bytes[63 - 8*i -: 7] : 7'd0;
  end

  // The record goes to the cores through two registers, root and group.
  reg [55:0]   ld_base_q = 0;
  reg          ld_we_q   = 0;
  reg [CW-1:0] ld_core_q = 0;

  reg [31:0]   id_tab [0:2*(1 << CW)-1];

  always @(posedge CLK)
  begin
    ld_we_q <= 1'b0;

    if (ld_word1 == 1'b1)
    begin
      ld_base_q <= ld_word;
      ld_core_q <= ld_cnt[CW-1:0];
      ld_we_q   <= 1'b1;
      id_tab[{p_next, ld_cnt[CW-1:0]}] <= rec_id;
    end
  end

  wire batch_drained = armed & (taken == target);

  // ----------------------------------------------------------------------------------------------
  // Waves and the generator
  // ----------------------------------------------------------------------------------------------

  localparam [1:0] W_IDLE = 2'd0, W_RUN = 2'd1, W_DRAIN = 2'd2;

  reg [1:0]  w_state  = W_IDLE;
  reg        w_parity = 0;
  reg [CW:0] w_jobs   = 0;
  reg [5:0]  drain    = 0;

  reg [1:0]  drained  = 0;
  reg [CW:0] jobs [0:1];

  reg [7:0]  dig    [0:3];
  reg [3:0]  at_max = 0;
  reg [31:0] item   = 0;

  wire [7:0] len_m1 [0:3];

  generate
  for (b = 0; b < 4; b = b + 1)
  begin : lens
    assign len_m1[b] = (b < amp_cnt) ? amp_lens[8*b +: 8] : 8'd0;
  end
  endgenerate

  wire advance = (w_state == W_RUN) & (therm_stop == 1'b0);
  wire last    = &at_max;

  assign start_ok = (w_state == W_IDLE) & (ld_cnt != 0) & (ld_word1 == 1'b0) & (wave_start == 1'b0)
                & ((ld_cnt == CORES) | batch_drained | (idle_cnt == IDLE_MAX));

  reg [3:0] carry;
  reg [7:0] dig_n [0:3];

  always @(*)
  begin
    carry[0] = 1'b1;
    for (p = 0; p < 4; p = p + 1)
    begin
      dig_n[p] = (carry[p] == 1'b0) ? dig[p] : (at_max[p] == 1'b1) ? 8'd0 : dig[p] + 1'b1;
      if (p < 3) carry[p + 1] = carry[p] & at_max[p];
    end
  end

  always @(posedge CLK)
  begin
    wave_start <= 1'b0;

    if (rst == 1'b1)
    begin
      ld_cnt   <= 0;
      ld_word1 <= 0;
      p_next   <= 0;
      armed    <= 0;
      target   <= 0;
      taken    <= 0;
      idle_cnt <= 0;
      busy     <= 0;
      drained  <= 0;
      w_state  <= W_IDLE;
      w_parity <= 0;
    end
    else
    begin
      if (batch_arm == 1'b1)
      begin
        armed  <= (batch_target != 32'd0);
        target <= batch_target;
        taken  <= 0;
      end
      else if (ld_word1 == 1'b1)
        taken <= taken + 1'b1;

      // Loader
      if (ld_word1 == 1'b1)
      begin
        ld_word1 <= 1'b0;
        ld_cnt   <= ld_cnt + 1'b1;
        idle_cnt <= 0;
      end
      else if ((rec_valid == 1'b1) && (can_load == 1'b1))
      begin
        pw_w0    <= pw_rd_data;
        ld_word1 <= 1'b1;
      end
      else if ((ld_cnt != 0) && (idle_cnt != IDLE_MAX))
        idle_cnt <= idle_cnt + 1'b1;

      // Waves
      case (w_state)
      W_IDLE:
        if (start_ok == 1'b1)
        begin
          wave_start     <= 1'b1;
          w_parity       <= p_next;
          w_jobs         <= ld_cnt;
          jobs[p_next]   <= ld_cnt;
          busy[p_next]   <= 1'b1;
          p_next         <= ~p_next;
          ld_cnt         <= 0;
          idle_cnt       <= 0;
          item           <= 0;
          for (p = 0; p < 4; p = p + 1)
          begin
            dig[p]    <= 0;
            at_max[p] <= (len_m1[p] == 8'd0);
          end
          w_state        <= W_RUN;
        end

      W_RUN:
        if (advance == 1'b1)
        begin
          item <= item + 1'b1;
          for (p = 0; p < 4; p = p + 1)
          begin
            dig[p]    <= dig_n[p];
            at_max[p] <= (dig_n[p] == len_m1[p]);
          end
          if (last == 1'b1)
          begin
            drain   <= DRAIN[5:0];
            w_state <= W_DRAIN;
          end
        end

      W_DRAIN:
        if (drain == 0)
        begin
          drained[w_parity] <= 1'b1;
          w_state           <= W_IDLE;
        end
        else
          drain <= drain - 1'b1;

      default:
        w_state <= W_IDLE;
      endcase

      if (ret_done == 1'b1)
      begin
        busy[ret_done_p]    <= 1'b0;
        drained[ret_done_p] <= 1'b0;
      end
    end
  end

  // The tables, and the item the generator emits this cycle read through them (G1).
  reg [6:0] tab0 [0:255];
  reg [6:0] tab1 [0:255];
  reg [6:0] tab2 [0:255];
  reg [6:0] tab3 [0:255];

  always @(posedge CLK)
    if (amp_tab_we == 1'b1)
      case (amp_tab[17:16])
      2'd0: tab0[amp_tab[15:8]] <= amp_tab[7:1];
      2'd1: tab1[amp_tab[15:8]] <= amp_tab[7:1];
      2'd2: tab2[amp_tab[15:8]] <= amp_tab[7:1];
      2'd3: tab3[amp_tab[15:8]] <= amp_tab[7:1];
      endcase

  reg [6:0]  g1_ch [0:3];
  reg [31:0] g1_item   = 0;
  reg        g1_valid  = 0;
  reg        g1_parity = 0;

  always @(posedge CLK)
  begin
    g1_ch[0]  <= tab0[dig[0]];
    g1_ch[1]  <= tab1[dig[1]];
    g1_ch[2]  <= tab2[dig[2]];
    g1_ch[3]  <= tab3[dig[3]];
    g1_item   <= item;
    g1_valid  <= (rst == 1'b0) & advance;
    g1_parity <= w_parity;
  end

  // The root of the bus (G2): the amplifier's bytes at the front of the key, zero past amp_cnt.
  reg [27:0] g2_hi     = 0;
  reg [31:0] g2_item   = 0;
  reg        g2_valid  = 0;
  reg        g2_parity = 0;

  reg        g2_ws     = 0;
  reg [CW:0] g2_jobs   = 0;
  reg        g2_rst    = 1;

  always @(posedge CLK)
  begin
    if (g1_valid == 1'b1)
      for (p = 0; p < 4; p = p + 1)
        g2_hi[27 - 7*p -: 7] <= (p < amp_cnt) ? g1_ch[p] : 7'd0;
    g2_item   <= g1_item;
    g2_valid  <= (rst == 1'b0) & g1_valid;
    g2_parity <= g1_parity;

    g2_ws     <= (rst == 1'b0) & wave_start;
    g2_jobs   <= w_jobs;
    g2_rst    <= rst;
  end

  // ----------------------------------------------------------------------------------------------
  // Groups and cores
  // ----------------------------------------------------------------------------------------------

  wire [NUM_CORES-1:0] c_hit_valid;
  wire [31:0]          c_hit_item   [0:NUM_CORES-1];
  wire [NUM_CORES-1:0] c_hit_parity;
  wire [TW-1:0]        c_hit_tgt    [0:NUM_CORES-1];
  wire [NUM_CORES-1:0] c_lost;

  reg  [NUM_CORES-1:0] c_pop = 0;

  // The collector's selection, through a register per group and one across groups.
  reg  [CW-1:0] sel = 0;

  reg  [NG-1:0] l1_valid  = 0;
  reg  [31:0]   l1_item   [0:NG-1];
  reg  [NG-1:0] l1_parity = 0;
  reg  [TW-1:0] l1_tgt    [0:NG-1];

  generate
  for (g = 0; g < NG; g = g + 1)
  begin : grp
    localparam integer C0 = g * GROUP;
    localparam integer CN = ((C0 + GROUP) <= NUM_CORES) ? GROUP : (NUM_CORES - C0);

    // The group's copy of everything the cores share.
    reg [63:0]               pt_ip  = 0;
    reg [64*NUM_TARGETS-1:0] tgt_ip = 0;
    reg [NUM_TARGETS-1:0]    tgt_en = 0;

    reg [27:0] amp_hi    = 0;
    reg        amp_valid = 0;
    reg [31:0] bus_item  = 0;
    reg        bus_parity = 0;

    reg        ws    = 0;
    reg [CW:0] wjobs = 0;
    reg        grst  = 1;

    reg [55:0] ld_base = 0;
    reg        ld_we   = 0;
    reg [CW-1:0] ld_core = 0;

    always @(posedge CLK)
    begin
      pt_ip      <= pt_ip_q;
      tgt_ip     <= tgt_ip_q;
      tgt_en     <= tgt_en_q;

      amp_hi     <= g2_hi;
      amp_valid  <= g2_valid;
      bus_item   <= g2_item;
      bus_parity <= g2_parity;

      ws         <= g2_ws;
      wjobs      <= g2_jobs;
      grst       <= g2_rst;

      ld_base    <= ld_base_q;
      ld_we      <= ld_we_q;
      ld_core    <= ld_core_q;
    end

    // The item each core holds in C2: the bus, CORE_LAT cycles later.
    reg [32:0] trk [0:CORE_LAT-1];

    always @(posedge CLK)
    begin
      trk[0] <= {bus_parity, bus_item};
      for (i = 1; i < CORE_LAT; i = i + 1)
        trk[i] <= trk[i - 1];
    end

    wire [32:0] trk_c2 = trk[CORE_LAT - 1];

    for (c = C0; c < C0 + CN; c = c + 1)
    begin : core
      localparam [CW:0] CI = c;

      hcfpga_des_kpa_core #(.NUM_TARGETS(NUM_TARGETS), .HIT_DEPTH(HIT_DEPTH)) u (
        .CLK(CLK), .rst(grst),
        .ld_we(ld_we & (ld_core == CI[CW-1:0])), .ld_base(ld_base),
        .wave_start(ws), .job_valid(CI < wjobs),
        .pt_ip(pt_ip), .tgt_ip(tgt_ip), .tgt_en(tgt_en),
        .amp_hi(amp_hi), .amp_valid(amp_valid),
        .trk_item(trk_c2[31:0]), .trk_parity(trk_c2[32]),
        .hit_valid(c_hit_valid[c]), .hit_item(c_hit_item[c]), .hit_parity(c_hit_parity[c]),
        .hit_tgt(c_hit_tgt[c]), .hit_pop(c_pop[c]),
        .lost(c_lost[c])
      );
    end

    // First level of the collector's mux.
    wire [SW-1:0] s = sel[SW-1:0];
    wire [CW:0]   cs = C0 + s;

    always @(posedge CLK)
    begin
      if (cs < C0 + CN)
      begin
        l1_valid[g]  <= c_hit_valid[cs[CW-1:0]];
        l1_item[g]   <= c_hit_item[cs[CW-1:0]];
        l1_parity[g] <= c_hit_parity[cs[CW-1:0]];
        l1_tgt[g]    <= c_hit_tgt[cs[CW-1:0]];
      end
      else
        l1_valid[g]  <= 1'b0;
    end
  end
  endgenerate

  assign lost = |c_lost;

  // ----------------------------------------------------------------------------------------------
  // Collector
  // ----------------------------------------------------------------------------------------------

  wire [GW-1:0] sel_g = (NG <= 1) ? {GW{1'b0}} : sel[CW-1:SW];

  reg          l2_valid  = 0;
  reg [31:0]   l2_item   = 0;
  reg          l2_parity = 0;
  reg [TW-1:0] l2_tgt    = 0;

  always @(posedge CLK)
  begin
    l2_valid  <= l1_valid[sel_g];
    l2_item   <= l1_item[sel_g];
    l2_parity <= l1_parity[sel_g];
    l2_tgt    <= l1_tgt[sel_g];
  end

  reg [31:0] id_q = 0;

  localparam [2:0] K_SEL = 3'd0, K_WAIT = 3'd1, K_CHK = 3'd2, K_ID = 3'd3, K_FRM = 3'd4, K_EMIT = 3'd5, K_RET = 3'd6;

  reg [2:0]   k_state = K_SEL;
  reg [1:0]   k_wait  = 0;
  reg [255:0] frame   = 0;
  reg [4:0]   bytecnt = 0;

  localparam [CW-1:0] LAST_CORE = NUM_CORES - 1;

  wire [15:0] core_id = {{(16 - CW){1'b0}}, sel};

  assign r_data  = frame[7:0];
  assign r_valid = (k_state == K_EMIT);
  assign r_last  = (k_state == K_EMIT) & (bytecnt == 5'd31);

  always @(posedge CLK)
  begin
    c_pop    <= 0;
    retire   <= 1'b0;
    ret_done <= 1'b0;

    if (rst == 1'b1)
    begin
      k_state   <= K_SEL;
      sel       <= 0;
      ret_p     <= 0;
      ret_armed <= 0;
    end
    else
    case (k_state)
    K_SEL:
    begin
      if ((sel == 0) && (drained[ret_p] == 1'b1) && (ret_armed == 1'b0) && (ret_done == 1'b0))
        ret_armed <= 1'b1;
      k_wait  <= 2'd1;
      k_state <= K_WAIT;
    end

    // A new selection reaches l2 two cycles after sel moves: one cycle of waiting covers it. After a
    // pop, c_pop, the core's count and the two mux levels take three.
    K_WAIT:
      if (k_wait == 0) k_state <= K_CHK;
      else             k_wait  <= k_wait - 1'b1;

    K_CHK:
      if (l2_valid == 1'b1)
        k_state <= K_ID;
      else if (sel == LAST_CORE)
      begin
        sel <= 0;
        if (ret_armed == 1'b1)
        begin
          ret_left <= jobs[ret_p];
          k_state  <= K_RET;
        end
        else
          k_state <= K_SEL;
      end
      else
      begin
        sel     <= sel + 1'b1;
        k_state <= K_SEL;
      end

    K_ID:
    begin
      id_q    <= id_tab[{l2_parity, sel}];
      k_state <= K_FRM;
    end

    K_FRM:
    begin
      frame   <= { 16'h0000, core_id, 152'd0, {(8 - TW){1'b0}}, l2_tgt, l2_item, id_q };
      bytecnt <= 0;
      k_state <= K_EMIT;
    end

    K_EMIT:
    begin
      if (r_ready == 1'b1)
      begin
        if (bytecnt == 5'd31)
        begin
          c_pop[sel] <= 1'b1;
          k_wait     <= 2'd3;
          k_state    <= K_WAIT;
        end
        else
        begin
          frame   <= frame >> 8;
          bytecnt <= bytecnt + 1'b1;
        end
      end
    end

    K_RET:
      if (ret_left == 0)
      begin
        ret_done   <= 1'b1;
        ret_done_p <= ret_p;
        ret_armed  <= 1'b0;
        ret_p      <= ~ret_p;
        k_state   <= K_SEL;
      end
      else
      begin
        retire   <= 1'b1;
        ret_left <= ret_left - 1'b1;
      end

    default:
      k_state <= K_SEL;
    endcase
  end

endmodule
