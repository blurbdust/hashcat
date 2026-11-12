// wpa2's top in the shared bench (tb_hcfpga.v): NUM_UNITS PBKDF2 pipes of RPS rounds a stage, and
// the extra registers cfg[16..20] in EXTRA_CSRS order: salt_len, salt4..7.
//
// The die temperature the thermal stop reads (XADC encoding): cfg[28] from cycle cfg[21], cfg[29]
// from cycle cfg[22], 0 again from cycle cfg[23]. With those words 0 the die stays cold.

  parameter RPS = 2;

  reg [31:0] dut_cycles = 0;

  always @(posedge CLK) dut_cycles <= dut_cycles + 1;

  wire [11:0] dut_die_temp = (dut_cycles < cfg[21]) ? 12'd0
                           : (dut_cycles < cfg[22]) ? cfg[28][11:0]
                           : (dut_cycles < cfg[23]) ? cfg[29][11:0]
                           :                          12'd0;

  hcfpga_wpa2_top #(.PIPES(NUM_UNITS), .RPS(RPS), .WITH_CMP(WITH_CMP)) dut (
    `HCFPGA_TB_PORTS,
    .die_temp(dut_die_temp),
    .salt_len(cfg[16]), .salt4(cfg[17]), .salt5(cfg[18]), .salt6(cfg[19]), .salt7(cfg[20])
  );
