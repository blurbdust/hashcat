#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# LiteX wrapper of the descrypt datapath, on HcfpgaDmaWrapper (../hcfpga_dma_wrapper.py): the
# shared register block at bcrypt's offsets, and nothing beyond it.
#
# descrypt's use of the shared registers: salt0 carries hashcat's salt_buf[0], of which the core
# takes the 12-bit salt (bits 11:0; bits 31:16 are the salt characters, which hashcat keeps only to
# print the hash); salt1..3 and iter_count are written but unused (crypt(3) runs 25 encryptions,
# fixed in the core); core_count is the number of DES rings, 16 candidates in flight each.

import os
import sys

HERE   = os.path.dirname(os.path.abspath(__file__))
BASE   = os.path.normpath(os.path.join(HERE, ".."))
ALGO   = os.path.join(HERE, "descrypt")

if BASE not in sys.path:
    sys.path.insert(0, BASE)

from hcfpga_dma_wrapper import HcfpgaDmaWrapper

# John the Ripper's DES pipeline and the key preparation its arbiter applies (see PROVENANCE.md).
CORE_FILES = ["descrypt16.v", "descrypt_round.v", "rotate_1or2_pc2.v", "des_loop.v", "Eblock.v", "SP_v2.v",
              "IP1.v", "crypt3_ascii2bin.v", "pc1.v"]

class DescryptDmaWrapper(HcfpgaDmaWrapper):
    ALGO = "descrypt"
    TOP  = "hcfpga_descrypt_top"

    # The 12-bit salt fits salt0, and the count is fixed: no register beyond the shared block.
    EXTRA_CSRS = ()

    def __init__(self, platform, num_cores=1, with_cmp=1):
        HcfpgaDmaWrapper.__init__(self, platform,
            num_cores = num_cores,
            params    = dict(NUM_CORES=num_cores, WITH_CMP=with_cmp),
        )

    def hdl_sources(self):
        # descrypt.vh is included by name from descrypt_core/.
        includes = [ALGO, os.path.join(ALGO, "descrypt_core")]
        files    = [os.path.join(ALGO, f) for f in ["hcfpga_descrypt_top.sv", "hcfpga_descrypt_engine.v"]]
        files   += [os.path.join(ALGO, "descrypt_core", f) for f in CORE_FILES]
        return includes, files

    SIM_UNITS_HELP = "DES rings, 16 candidates in flight each"

    @classmethod
    def for_sim(cls, platform, units, with_cmp):
        return cls(platform, num_cores=units, with_cmp=with_cmp)
