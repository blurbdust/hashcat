// wpa2's top in the shared bench (src/fpga/common/rtl/tb_hcfpga.v). Extra registers are
// cfg[16..] in EXTRA_CSRS order. HCFPGA-TODO: connect each extra port, .<name>(cfg[16 + n]).

  hcfpga_wpa2_top #(.NUM_CORES(NUM_UNITS), .WITH_CMP(WITH_CMP)) dut (
    `HCFPGA_TB_PORTS
  );
