#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# LiteX wrapper of the descrypt datapath, on the shared HcfpgaDmaWrapper (src/fpga/common): the
# shared register block at bcrypt's offsets, plus EXTRA_CSRS from 0x3c.

import os
import sys

HERE   = os.path.dirname(os.path.abspath(__file__))
COMMON = os.path.normpath(os.path.join(HERE, "..", "..", "common"))
ALGO   = os.path.join(HERE, "descrypt")

if COMMON not in sys.path:
    sys.path.insert(0, COMMON)

from hcfpga_dma_wrapper import HcfpgaDmaWrapper

class DescryptDmaWrapper(HcfpgaDmaWrapper):
    ALGO = "descrypt"
    TOP  = "hcfpga_descrypt_top"

    # HCFPGA-TODO: the registers the core needs beyond the shared block, appended from 0x3c, in the
    # same order as the bridge's config_extra writes them. Each is wired to the top's port of that name.
    EXTRA_CSRS = ()

    def __init__(self, platform, num_cores=1, with_cmp=1):
        HcfpgaDmaWrapper.__init__(self, platform,
            num_cores = num_cores,
            params    = dict(NUM_CORES=num_cores, WITH_CMP=with_cmp),
        )

    def hdl_sources(self):
        # HCFPGA-TODO: the core's include directories and files.
        includes = [ALGO]
        files    = [os.path.join(ALGO, f) for f in ["hcfpga_descrypt_top.sv", "hcfpga_descrypt_engine.v"]]
        return includes, files

    SIM_UNITS_HELP = "cores"

    @classmethod
    def for_sim(cls, platform, units, with_cmp):
        return cls(platform, num_cores=units, with_cmp=with_cmp)
