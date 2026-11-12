// des_kpa's top in the shared bench (tb_hcfpga.v): NUM_UNITS cores, and the extra registers
// cfg[16..27] in EXTRA_CSRS order: amp_cnt, amp_lens, amp_tab (written from amp.hex instead, see
// below), tgt_mask, tgt0_lo, tgt0_hi .. tgt3_lo, tgt3_hi.
//
// The amplifier tables are written before the first H2C word goes in: amp.hex holds the number of
// writes, then the amp_tab words. The bench holds s_ready low until they are done.
//
// The die temperature the thermal stop reads (XADC encoding): 0 until cycle cfg[28], cfg[29] from
// then, cfg[31] from cycle cfg[30]. With cfg[28] 0 the die stays cold.

  reg [31:0] dut_cycles = 0;

  always @(posedge CLK) dut_cycles <= dut_cycles + 1;

  wire [11:0] dut_die_temp = ((cfg[28] == 0) || (dut_cycles < cfg[28])) ? 12'd0
                           : ((cfg[30] == 0) || (dut_cycles < cfg[30])) ? cfg[29][11:0]
                           :                                              cfg[31][11:0];

  reg [31:0] tab_words [0:1024];
  reg [31:0] tab_word = 0;
  reg        tab_we   = 0;
  reg        tab_done = 0;
  integer    tab_i;

  initial
  begin
    for (tab_i = 0; tab_i <= 1024; tab_i = tab_i + 1) tab_words[tab_i] = 0;
    $readmemh("amp.hex", tab_words);
    @(posedge CLK);
    for (tab_i = 1; tab_i <= tab_words[0]; tab_i = tab_i + 1)
    begin
      tab_word <= tab_words[tab_i];
      tab_we   <= 1;
      @(posedge CLK);
    end
    tab_we   <= 0;
    tab_done <= 1;
  end

  wire dut_s_ready;

  assign s_ready = dut_s_ready & tab_done;

  hcfpga_des_kpa_top #(.NUM_CORES(NUM_UNITS), .WITH_CMP(WITH_CMP)) dut (
    .CLK(CLK), .rst(rst),
    .die_temp(dut_die_temp),
    .s_data(s_data), .s_valid(s_valid & tab_done), .s_ready(dut_s_ready), .s_last(s_last),
    .frame_status(frame_status),
    .salt0(cfg[0]), .salt1(cfg[1]), .salt2(cfg[2]), .salt3(cfg[3]),
    .iter_count(cfg[4]),
    .cmp_bitmap(bitmap), .cmp_load(cmp_load),
    .batch_target(batch_target), .batch_arm(batch_arm),
    .pad_recs(cfg[11][15:0]),
    .retired_cnt(retired_cnt),
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last),
    .amp_cnt(cfg[16]), .amp_lens(cfg[17]), .amp_tab(tab_word), .amp_tab_we(tab_we),
    .tgt_mask(cfg[19]),
    .tgt0_lo(cfg[20]), .tgt0_hi(cfg[21]), .tgt1_lo(cfg[22]), .tgt1_hi(cfg[23]),
    .tgt2_lo(cfg[24]), .tgt2_hi(cfg[25]), .tgt3_lo(cfg[26]), .tgt3_hi(cfg[27])
  );
