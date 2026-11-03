#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# LiteX wrapper of the sha256crypt datapath, on the shared HcfpgaDmaWrapper (src/fpga/common): the
# shared register block at bcrypt's offsets, plus EXTRA_CSRS from 0x3c.

import os
import sys

HERE   = os.path.dirname(os.path.abspath(__file__))
COMMON = os.path.normpath(os.path.join(HERE, "..", "..", "common"))
ALGO   = os.path.join(HERE, "sha256crypt")

if COMMON not in sys.path:
    sys.path.insert(0, COMMON)

from hcfpga_dma_wrapper import HcfpgaDmaWrapper

# HCFPGA-TODO: cores per computing unit, as the identity's cores= counts them (the bridge's
# grain_per_core multiplies this). The stub unit holds one candidate, so 1 until the real unit is in.
CORES_PER_UNIT = 1

class Sha256cryptDmaWrapper(HcfpgaDmaWrapper):
    ALGO = "sha256crypt"
    TOP  = "hcfpga_sha256crypt_top"

    # The JtR unit packet carries the salt length, so the crypt family needs it. HCFPGA-TODO: any
    # other register the core needs, appended here and in the bridge's config_extra in the same order.
    EXTRA_CSRS = (
        ("salt_len", 32, "Salt length in bytes."),
    )

    # HCFPGA-TODO: drop hcfpga_jtr_unit_stub.v once the real unit is in hdl_sources().
    COMMON_RTL = HcfpgaDmaWrapper.COMMON_RTL + ("hcfpga_jtr_unit_feed.v", "hcfpga_jtr_unit_collect.v", "hcfpga_jtr_unit_stub.v")

    def __init__(self, platform, num_units=1, with_cmp=1):
        self.num_units = num_units

        HcfpgaDmaWrapper.__init__(self, platform,
            num_cores = num_units * CORES_PER_UNIT,
            params    = dict(NUM_UNITS=num_units, WITH_CMP=with_cmp),
        )

    def hdl_sources(self):
        # HCFPGA-TODO: the imported unit's include directories and files.
        includes = [ALGO]
        files    = [os.path.join(ALGO, "hcfpga_sha256crypt_top.sv")]
        return includes, files

    SIM_UNITS_HELP = "computing units"

    @classmethod
    def for_sim(cls, platform, units, with_cmp):
        return cls(platform, num_units=units, with_cmp=with_cmp)
