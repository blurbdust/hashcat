#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# LiteX wrapper of the sha256crypt datapath, on the shared HcfpgaDmaWrapper (src/fpga/common): the
# shared register block at bcrypt's offsets, plus
#
#   0x3c salt_len      salt length in bytes, 1..16
#
# sha256crypt's use of the shared registers: salt0..3 carry hashcat's salt_buf[0..3] unchanged (the
# raw salt), iter_count is the rounds (1..999999999, the unit's CPU counts in 32 bits), status bits
# 23:16 count unit results whose 2-bit framing was off, core_count is SHA-256 cores
# (num_units * 3). The units run on the stream clock: JtR's sha256crypt unit has one clock.

import os
import sys

HERE   = os.path.dirname(os.path.abspath(__file__))
COMMON = os.path.normpath(os.path.join(HERE, "..", "..", "common"))
ALGO   = os.path.join(HERE, "sha256crypt")

if COMMON not in sys.path:
    sys.path.insert(0, COMMON)

from hcfpga_dma_wrapper import HcfpgaDmaWrapper

# SHA-256 cores per computing unit, as the identity's cores= counts them. Each interleaves 4
# computations, so the bridge's grain_per_core is 4. Upstream's core_ctrl.v needs exactly 3.
CORES_PER_UNIT = 3

class Sha256cryptDmaWrapper(HcfpgaDmaWrapper):
    ALGO = "sha256crypt"
    TOP  = "hcfpga_sha256crypt_top"

    # The JtR unit packet carries the salt length; the unit needs nothing else.
    EXTRA_CSRS = (
        ("salt_len", 32, "Salt length in bytes, 1 to 16."),
    )

    COMMON_RTL = HcfpgaDmaWrapper.COMMON_RTL + ("hcfpga_jtr_unit_feed.v", "hcfpga_jtr_unit_collect.v")

    def __init__(self, platform, num_units=1, with_cmp=1):
        self.num_units = num_units

        HcfpgaDmaWrapper.__init__(self, platform,
            num_cores = num_units * CORES_PER_UNIT,
            params    = dict(NUM_UNITS=num_units, CORES_PER_UNIT=CORES_PER_UNIT, WITH_CMP=with_cmp),
        )

    def hdl_sources(self):
        # sha256.vh and log2.vh, and cpu/program.vh, which cpu/instruction.v includes.
        includes = [ALGO, os.path.join(ALGO, "util"), os.path.join(ALGO, "cpu")]

        files = [os.path.join(ALGO, "hcfpga_sha256crypt_top.sv")]
        files += [os.path.join(ALGO, "unit", f) for f in
                  ["sha256unit.v", "unit_ctrl.v", "core_ctrl.v", "unit_input.v", "uob.v"]]

        for d in ["cpu", "sha256core", "sha256engine"]:
            for f in sorted(os.listdir(os.path.join(ALGO, d))):
                if f.endswith(".v"):
                    files.append(os.path.join(ALGO, d, f))

        files += [os.path.join(ALGO, "util", f) for f in ["sync.v", "delay.v", "asymm_bram.v"]]

        return includes, files

    SIM_UNITS_HELP = "computing units, 3 SHA-256 cores and 12 candidates in flight each"

    @classmethod
    def for_sim(cls, platform, units, with_cmp):
        return cls(platform, num_units=units, with_cmp=with_cmp)
