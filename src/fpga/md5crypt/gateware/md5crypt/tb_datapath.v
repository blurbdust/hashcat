/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Datapath bench for hcfpga_md5crypt_top, driven by tb_datapath.py.
//
// Reads the batch from files the script writes: cfg.hex (salt0..3, iter_count, salt_len,
// bitmap0..3, records, pad_recs, h2c word count, gaps), h2c.hex (the H2C words). Streams the
// words in with s_valid gaps, collects the C2H bytes, and prints one line per 32-byte record:
//
//   REC <32 bytes hex, byte 0 first>
//
// until the end-of-batch record, then DONE <retired> <frame_status> <cycles>. The script checks
// the lines against its md5crypt reference.

`timescale 1ns / 1ps
module tb_datapath;

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

  reg [31:0] cfg [0:15];
  reg [31:0] h2c [0:16383];

  reg [127:0] bitmap   = 0;
  reg         cmp_load = 0;

  reg [31:0] batch_target = 0;
  reg        batch_arm    = 0;

  hcfpga_md5crypt_top #(.NUM_UNITS(NUM_UNITS), .CORES_PER_UNIT(3), .WITH_CMP(WITH_CMP)) dut (
    .CLK(CLK), .CLK_CORE(CLK), .rst(rst),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last),
    .frame_status(frame_status),
    .salt0(cfg[0]), .salt1(cfg[1]), .salt2(cfg[2]), .salt3(cfg[3]),
    .iter_count(cfg[4]), .salt_len(cfg[5]),
    .cmp_bitmap(bitmap), .cmp_load(cmp_load),
    .batch_target(batch_target), .batch_arm(batch_arm),
    .pad_recs(cfg[11][15:0]),
    .retired_cnt(retired_cnt),
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last)
  );

  integer i, n_words, gaps, seed;
  integer cycles = 0;
  reg [255:0] rec = 0;
  integer     bcnt = 0;
  reg         done = 0;

  always @(posedge CLK) cycles <= cycles + 1;

  // H2C: one word per cycle, with random idle cycles when gaps is set.
  reg     streaming = 0;
  integer widx      = 0;

  always @(posedge CLK)
  begin
    if (streaming && ((s_valid == 0) || (s_ready == 1)))
    begin
      if ((widx < n_words) && !((gaps != 0) && ($random(seed) & 1)))
      begin
        s_data  <= h2c[widx];
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

  // C2H: assemble records, stop at the end-of-batch record.
  always @(posedge CLK)
  begin
    if (m_valid & m_ready)
    begin
      rec = {m_data, rec[255:8]};
      bcnt = bcnt + 1;

      if (m_last)
      begin
        if (bcnt != 32) $display("ERR record of %0d bytes", bcnt);
        $write("REC ");
        for (i = 0; i < 32; i = i + 1) $write("%02x", rec[8*i +: 8]);
        $write("\n");
        if (rec[255:240] == 16'h8000) done = 1;
        bcnt = 0;
      end
    end
  end

  initial
  begin
    $readmemh("cfg.hex", cfg);
    $readmemh("h2c.hex", h2c);

    n_words = cfg[12];
    gaps    = cfg[13];
    seed    = 1;

    repeat (8) @(posedge CLK);
    rst <= 0;
    repeat (4) @(posedge CLK);

    bitmap   <= {cfg[9], cfg[8], cfg[7], cfg[6]};
    cmp_load <= 1;
    @(posedge CLK);
    cmp_load <= 0;

    batch_target <= cfg[10];
    batch_arm    <= 1;
    @(posedge CLK);
    batch_arm    <= 0;
    @(posedge CLK);

    if (retired_cnt != 0) $display("ERR retired %0d after arm", retired_cnt);

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
