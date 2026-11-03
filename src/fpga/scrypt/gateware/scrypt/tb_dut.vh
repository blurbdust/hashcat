// scrypt's top in the shared bench (src/fpga/common/rtl/tb_hcfpga.v): NUM_UNITS scrypt units, and
// the extra registers cfg[16..21] in EXTRA_CSRS order: salt_len, salt4..7, r. The build
// parameters (N_LOG2_MAX, R_MAX, GAP_LOG2) come from tb_scrypt_build.vh, which tb_datapath.py
// writes into the build directory.

`include "tb_scrypt_build.vh"

  hcfpga_scrypt_top #(
    .NUM_CORES(NUM_UNITS), .WITH_CMP(WITH_CMP),
    .N_LOG2_MAX(`TB_SCRYPT_N_LOG2_MAX), .R_MAX(`TB_SCRYPT_R_MAX), .GAP_LOG2(`TB_SCRYPT_GAP_LOG2)
  ) dut (
    `HCFPGA_TB_PORTS,
    .salt_len(cfg[16]), .salt4(cfg[17]), .salt5(cfg[18]), .salt6(cfg[19]), .salt7(cfg[20]),
    .r(cfg[21])
  );
