// wpa2's top in the shared bench (tb_hcfpga.v): NUM_UNITS PBKDF2 pipes of RPS rounds a stage, and
// the extra registers cfg[16..20] in EXTRA_CSRS order: salt_len, salt4..7.

  parameter RPS = 2;

  hcfpga_wpa2_top #(.PIPES(NUM_UNITS), .RPS(RPS), .WITH_CMP(WITH_CMP)) dut (
    `HCFPGA_TB_PORTS,
    .salt_len(cfg[16]), .salt4(cfg[17]), .salt5(cfg[18]), .salt6(cfg[19]), .salt7(cfg[20])
  );
