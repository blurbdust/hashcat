// sha512crypt's top in the shared bench (src/fpga/common/rtl/tb_hcfpga.v). Extra registers are
// cfg[16..] in EXTRA_CSRS order: salt_len first.

  hcfpga_sha512crypt_top #(.NUM_UNITS(NUM_UNITS), .CORES_PER_UNIT(4), .WITH_CMP(WITH_CMP)) dut (
    `HCFPGA_TB_PORTS,
    .salt_len(cfg[16])
  );
