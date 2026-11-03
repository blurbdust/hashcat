#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# LiteX wrapper of the scrypt datapath, on the shared HcfpgaDmaWrapper (src/fpga/common): the
# shared register block at bcrypt's offsets, plus EXTRA_CSRS from 0x3c.
#
# scrypt's use of the shared registers: salt0..3 carry salt bytes 0..15 (hashcat's salt_buf[0..3]),
# iter_count is N, core_count the number of scrypt units, one candidate in flight each.
#
# Build parameters: n_log2_max (N up to 2^n_log2_max), r_max (the widest r a unit computes; r
# comes at run time) and gap (ROMix's lookup gap G, 1, 2, 4 or 8: the V table holds every G-th
# block, and a read recomputes up to G - 1 BlockMix steps). A unit's V table takes
# 2^n_log2_max / gap * 128 * r_max bytes of block RAM. The simulated board uses the defaults, whose
# limits are the ones module_98900.c and bridge_fpga_scrypt.c state; a board build with smaller ones
# needs the module's limits changed to match (the known-answer canary fails a salt the build cannot
# compute).

import os
import sys

HERE   = os.path.dirname(os.path.abspath(__file__))
COMMON = os.path.normpath(os.path.join(HERE, "..", "..", "common"))
ALGO   = os.path.join(HERE, "scrypt")

if COMMON not in sys.path:
    sys.path.insert(0, COMMON)

from hcfpga_dma_wrapper import HcfpgaDmaWrapper

# LiteX-Scrypt's unit and what it instantiates (see PROVENANCE.md), in upstream's directories.
CORE_FILES = ["scrypt_unit.v", "romix.v", "v_table_bram.v", "blockmix.v", "salsa20_8.v", "pbkdf2_sha256.v",
              "hmac_sha256.v", "sha256_core.v"]
UTIL_FILES = ["fifo_sync.v"]

class ScryptDmaWrapper(HcfpgaDmaWrapper):
    ALGO = "scrypt"
    TOP  = "hcfpga_scrypt_top"

    # The salt length and salt bytes 16..31, in the order the bridge's config_extra writes them.
    EXTRA_CSRS = (
        ("salt_len", 32, "Salt length in bytes, 0 to 32."),
        ("salt4",    32, "Salt bytes 16..19 (hashcat's salt_buf[4])."),
        ("salt5",    32, "Salt bytes 20..23 (hashcat's salt_buf[5])."),
        ("salt6",    32, "Salt bytes 24..27 (hashcat's salt_buf[6])."),
        ("salt7",    32, "Salt bytes 28..31 (hashcat's salt_buf[7])."),
        # Named r, not scrypt_r: register names that start with the bank's name lose that prefix
        # in the offset check (and in csr.csv this one is scrypt_r).
        ("r",        32, "scrypt's r, 1 to the build's r_max."),
    )

    N_LOG2_MAX = 15
    R_MAX      = 8
    GAP        = 1

    # The engine reads the units with the shared JtR collector.
    COMMON_RTL = HcfpgaDmaWrapper.COMMON_RTL + ("hcfpga_jtr_unit_collect.v",)

    def __init__(self, platform, num_cores=1, with_cmp=1, n_log2_max=N_LOG2_MAX, r_max=R_MAX, gap=GAP):
        if gap not in (1, 2, 4, 8) or (1 << n_log2_max) <= gap:
            raise ValueError("gap must be 1, 2, 4 or 8 and below 2^n_log2_max")
        self.n_log2_max = n_log2_max
        self.r_max      = r_max
        self.gap        = gap
        HcfpgaDmaWrapper.__init__(self, platform,
            num_cores = num_cores,
            params    = dict(NUM_CORES=num_cores, WITH_CMP=with_cmp, N_LOG2_MAX=n_log2_max, R_MAX=r_max,
                             GAP_LOG2=gap.bit_length() - 1),
        )

    def hdl_sources(self):
        # scrypt_unit.v includes main.vh (scrypt/), which includes log2.vh (util/).
        core     = os.path.join(ALGO, "scrypt")
        util     = os.path.join(ALGO, "util")
        includes = [ALGO, core, util]
        files    = [os.path.join(ALGO, f) for f in ["hcfpga_scrypt_top.sv", "hcfpga_scrypt_engine.v"]]
        files   += [os.path.join(core, f) for f in CORE_FILES]
        files   += [os.path.join(util, f) for f in UTIL_FILES]
        return includes, files

    SIM_UNITS_HELP = "scrypt units, one candidate in flight each"

    @classmethod
    def for_sim(cls, platform, units, with_cmp):
        return cls(platform, num_cores=units, with_cmp=with_cmp)
