// md5crypt's top in the shared bench (src/fpga/common/rtl/tb_hcfpga.v): the units run on the
// stream clock, and salt_len is the first extra register (cfg[16]).

  hcfpga_md5crypt_top #(.NUM_UNITS(NUM_UNITS), .CORES_PER_UNIT(3), .WITH_CMP(WITH_CMP)) dut (
    `HCFPGA_TB_PORTS,
    .CLK_CORE(CLK),
    .salt_len(cfg[16])
  );
