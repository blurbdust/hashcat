// descrypt's top in the shared bench (src/fpga/common/rtl/tb_hcfpga.v): NUM_UNITS DES rings, no
// register beyond the shared block.

  hcfpga_descrypt_top #(.NUM_CORES(NUM_UNITS), .WITH_CMP(WITH_CMP)) dut (
    `HCFPGA_TB_PORTS
  );
