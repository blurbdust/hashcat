#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# LiteX wrapper of the wpa2 datapath, on the shared HcfpgaDmaWrapper (src/fpga/common): the
# shared register block at bcrypt's offsets, plus EXTRA_CSRS from 0x3c.
#
# wpa2's use of the shared registers: salt0..3 carry ESSID bytes 0..15 (hashcat's salt_buf[0..3]),
# iter_count is hashcat's salt_iter (4095, not used: the count is fixed), core_count the number of
# PBKDF2 pairs, one candidate in flight each. The comparator bitmap is not used (WITH_CMP = 0, see
# the engine): hashcat's digest is a MIC or PMKID its kernels compute from the PMK.

import os
import sys

HERE   = os.path.dirname(os.path.abspath(__file__))
COMMON = os.path.normpath(os.path.join(HERE, "..", "..", "common"))
ALGO   = os.path.join(HERE, "wpa2")

if COMMON not in sys.path:
    sys.path.insert(0, COMMON)

from hcfpga_dma_wrapper import HcfpgaDmaWrapper

# OpenCiphers' cores (see PROVENANCE.md), in upstream's directories.
WPAPSK_FILES = ["PBKDF2.v", "Sha1.v", "Sha1BRAM.v", "R.v", "Add32.v"]
SHA1_FILES   = ["Sha1.v"]

class Wpa2DmaWrapper(HcfpgaDmaWrapper):
    ALGO = "wpa2"
    TOP  = "hcfpga_wpa2_top"

    # The ESSID length and ESSID bytes 16..31, in the order the bridge's config_extra writes them.
    EXTRA_CSRS = (
        ("salt_len", 32, "ESSID length in bytes, 0 to 32."),
        ("salt4",    32, "ESSID bytes 16..19 (hashcat's salt_buf[4])."),
        ("salt5",    32, "ESSID bytes 20..23 (hashcat's salt_buf[5])."),
        ("salt6",    32, "ESSID bytes 24..27 (hashcat's salt_buf[6])."),
        ("salt7",    32, "ESSID bytes 28..31 (hashcat's salt_buf[7])."),
    )

    # C2H records per candidate (the top's PARTS, the bridge's c2h_parts, the identity's parts=):
    # the 32-byte PMK in two.
    PARTS = 2

    # with_cmp is taken for the shared signature and not used: the device cannot compare (above).
    def __init__(self, platform, num_cores=1, with_cmp=0):
        HcfpgaDmaWrapper.__init__(self, platform,
            num_cores = num_cores,
            params    = dict(NUM_CORES=num_cores, WITH_CMP=0),
        )

    def hdl_sources(self):
        wpapsk   = os.path.join(ALGO, "wpapsk")
        sha1     = os.path.join(ALGO, "sha1")
        includes = [ALGO]
        files    = [os.path.join(ALGO, f) for f in ["hcfpga_wpa2_top.sv", "hcfpga_wpa2_engine.v"]]
        files   += [os.path.join(wpapsk, f) for f in WPAPSK_FILES]
        files   += [os.path.join(sha1, f) for f in SHA1_FILES]
        return includes, files

    SIM_UNITS_HELP = "PBKDF2 pairs, one candidate in flight each"

    @classmethod
    def for_sim(cls, platform, units, with_cmp):
        return cls(platform, num_cores=units, with_cmp=with_cmp)
