// scrypt's top in the shared bench (src/fpga/common/rtl/tb_hcfpga.v): NUM_UNITS scrypt units, and
// the extra registers cfg[16..20] in EXTRA_CSRS order: salt_len, salt4..7.

  hcfpga_scrypt_top #(.NUM_CORES(NUM_UNITS), .WITH_CMP(WITH_CMP)) dut (
    `HCFPGA_TB_PORTS,
    .salt_len(cfg[16]), .salt4(cfg[17]), .salt5(cfg[18]), .salt6(cfg[19]), .salt7(cfg[20])
  );
