/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// wpa2's restart bench, driven by tb_datapath.py (case restart): a batch abandoned with candidates
// in flight, then a batch that has to come back whole and alone. The shared bench (tb_hcfpga.v)
// runs one batch; this one is the same around wpa2's top (tb_dut.vh), with a batch A before it.
//
// Reads cfg.hex as tb_hcfpga.v does, plus:
//
//   cfg[24]  batch A's records (its batch_target)    cfg[26]  cycle (from A's first word) of the abort
//   cfg[25]  batch A's H2C word count (h2c_a.hex)    cfg[27]  1: framing reset; 2: arm B without one
//
// Streams A, stops at the abort and drops whatever came back of A, then arms batch B (h2c.hex,
// cfg[10..12]) and prints its records as tb_hcfpga.v does: REC lines, then DONE.

`timescale 1ns / 1ps

`define HCFPGA_TB_PORTS \
    .CLK(CLK), .rst(rst), \
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last), \
    .frame_status(frame_status), \
    .salt0(cfg[0]), .salt1(cfg[1]), .salt2(cfg[2]), .salt3(cfg[3]), \
    .iter_count(cfg[4]), \
    .cmp_bitmap(bitmap), .cmp_load(cmp_load), \
    .batch_target(batch_target), .batch_arm(batch_arm), \
    .pad_recs(cfg[11][15:0]), \
    .retired_cnt(retired_cnt), \
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last)

module tb_restart;

  parameter NUM_UNITS = 1;
  parameter WITH_CMP  = 1;

  reg CLK = 0;
  always #5 CLK = ~CLK;

  reg rst = 1;

  reg  [31:0] s_data  = 0;
  reg         s_valid = 0;
  wire        s_ready;
  reg         s_last  = 0;

  wire [31:0] frame_status;
  wire [31:0] retired_cnt;

  wire [7:0] m_data;
  wire       m_valid;
  reg        m_ready = 1;
  wire       m_last;

  reg [31:0] cfg   [0:31];
  reg [31:0] h2c   [0:16383];
  reg [31:0] h2c_a [0:16383];

  reg [127:0] bitmap   = 0;
  reg         cmp_load = 0;

  reg [31:0] batch_target = 0;
  reg        batch_arm    = 0;

  `include "tb_dut.vh"

  integer i, n_words;
  integer cycles = 0;
  integer a_start = 0;
  integer dropped = 0;
  reg [255:0] rec = 0;
  integer     bcnt = 0;
  reg         done = 0;
  reg         in_b = 0;

  always @(posedge CLK) cycles <= cycles + 1;

  // H2C: one word per cycle from A's or B's words.
  reg     streaming = 0;
  reg     from_a    = 0;
  integer widx      = 0;

  always @(posedge CLK)
  begin
    if (streaming && ((s_valid == 0) || (s_ready == 1)))
    begin
      if (widx < n_words)
      begin
        s_data  <= from_a ? h2c_a[widx] : h2c[widx];
        s_valid <= 1;
        s_last  <= (widx == n_words - 1);
        widx    <= widx + 1;
      end
      else
      begin
        s_valid <= 0;
        s_last  <= 0;
      end
    end
  end

  // C2H: whole records; before B is armed they are A's and dropped.
  always @(posedge CLK)
  begin
    if (m_valid & m_ready)
    begin
      rec = {m_data, rec[255:8]};
      bcnt = bcnt + 1;

      if (m_last)
      begin
        if (in_b == 0)
          dropped = dropped + 1;
        else
        begin
          if (bcnt != 32) $display("ERR record of %0d bytes", bcnt);
          $write("REC ");
          for (i = 0; i < 32; i = i + 1) $write("%02x", rec[8*i +: 8]);
          $write("\n");
          if (rec[255:240] == 16'h8000) done = 1;
        end
        bcnt = 0;
      end
    end
  end

  initial
  begin
    for (i = 0; i < 32; i = i + 1) cfg[i] = 0;

    $readmemh("cfg.hex", cfg);
    $readmemh("h2c.hex", h2c);
    $readmemh("h2c_a.hex", h2c_a);

    repeat (8) @(posedge CLK);
    rst <= 0;
    repeat (4) @(posedge CLK);

    bitmap   <= {cfg[9], cfg[8], cfg[7], cfg[6]};
    cmp_load <= 1;
    @(posedge CLK);
    cmp_load <= 0;

    // Batch A, abandoned at cycle cfg[26] of its stream.
    batch_target <= cfg[24];
    batch_arm    <= 1;
    @(posedge CLK);
    batch_arm    <= 0;
    @(posedge CLK);

    n_words   = cfg[25];
    widx      = 0;
    from_a    = 1;
    streaming = 1;
    a_start   = cycles;

    while (cycles - a_start < cfg[26]) @(posedge CLK);

    streaming = 0;
    @(posedge CLK);
    s_valid <= 0;
    s_last  <= 0;

    if (cfg[27] == 1)
    begin
      rst <= 1;
      repeat (16) @(posedge CLK);
      rst <= 0;
      repeat (4) @(posedge CLK);
    end

    $display("ABORT at %0d, %0d words of A sent, %0d records of A dropped, retired %0d", cycles, widx, dropped, retired_cnt);

    bcnt = 0;
    in_b = 1;

    // Batch B, as tb_hcfpga.v runs its batch.
    batch_target <= cfg[10];
    batch_arm    <= 1;
    @(posedge CLK);
    batch_arm    <= 0;
    @(posedge CLK);

    if (retired_cnt != 0) $display("ERR retired %0d after arm", retired_cnt);

    n_words   = cfg[12];
    widx      = 0;
    from_a    = 0;
    streaming = 1;

    while (done == 0)
    begin
      @(posedge CLK);
      if (cycles > 200000000) begin $display("ERR timeout"); $finish; end
    end

    repeat (64) @(posedge CLK);

    $display("DONE %0d %08x %0d", retired_cnt, frame_status, cycles);
    $finish;
  end

endmodule
