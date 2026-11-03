// sha256crypt's top in the shared bench (tb_hcfpga.v): the units run on the
// stream clock, and salt_len is the first extra register (cfg[16]).

  hcfpga_sha256crypt_top #(.NUM_UNITS(NUM_UNITS), .CORES_PER_UNIT(3), .WITH_CMP(WITH_CMP)) dut (
    `HCFPGA_TB_PORTS,
    .salt_len(cfg[16])
  );
