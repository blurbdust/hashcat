#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# LiteX wrapper of the md5crypt datapath, on the shared HcfpgaDmaWrapper (src/fpga/common): the
# shared register block at bcrypt's offsets, plus
#
#   0x3c salt_len      salt length in bytes, 1..8 (bcrypt's salt is always 16)
#
# md5crypt's use of the shared registers: salt0..3 carry hashcat's salt_buf[0..3] unchanged,
# iter_count is the rounds (1..65535, the CPU reads 16 bits), status bits 23:16 count unit results
# whose 2-bit framing was off, core_count is MD5 cores (num_units * cores_per_unit).

import os
import sys

HERE   = os.path.dirname(os.path.abspath(__file__))
COMMON = os.path.normpath(os.path.join(HERE, "..", "..", "common"))
MD5    = os.path.join(HERE, "md5crypt")

if COMMON not in sys.path:
    sys.path.insert(0, COMMON)

from hcfpga_dma_wrapper import HcfpgaDmaWrapper

class Md5cryptDmaWrapper(HcfpgaDmaWrapper):
    ALGO = "md5crypt"
    TOP  = "hcfpga_md5crypt_top"

    EXTRA_CSRS = (
        ("salt_len", 32, "Salt length in bytes, 1 to 8."),
    )

    COMMON_RTL = HcfpgaDmaWrapper.COMMON_RTL + ("hcfpga_jtr_unit_feed.v", "hcfpga_jtr_unit_collect.v")

    HAS_CORE_CLK = True

    def __init__(self, platform, num_units=1, cores_per_unit=3, with_cmp=1, core_clk=False):
        self.num_units      = num_units
        self.cores_per_unit = cores_per_unit

        HcfpgaDmaWrapper.__init__(self, platform,
            num_cores = num_units * cores_per_unit,
            params    = dict(NUM_UNITS=num_units, CORES_PER_UNIT=cores_per_unit, WITH_CMP=with_cmp),
            core_clk  = core_clk,
        )

    def hdl_sources(self):
        includes = [MD5, os.path.join(MD5, "util"), os.path.join(MD5, "cpu")]

        files = [os.path.join(MD5, f) for f in
                 ["hcfpga_md5crypt_top.sv", "md5unit.v", "unit_ctrl.v", "core_ctrl.v", "unit_input_async.v", "uob16pq.v"]]

        for d in ["cpu", "md5core", "md5engine"]:
            for f in sorted(os.listdir(os.path.join(MD5, d))):
                if f.endswith(".v"):
                    files.append(os.path.join(MD5, d, f))

        files += [os.path.join(MD5, "util", f) for f in ["sync.v", "delay.v", "asymm_bram.v"]]

        return includes, files

    SIM_UNITS_HELP = "computing units, 3 MD5 cores and 12 candidates in flight each"

    @classmethod
    def for_sim(cls, platform, units, with_cmp):
        return cls(platform, num_units=units, cores_per_unit=3, with_cmp=with_cmp)
