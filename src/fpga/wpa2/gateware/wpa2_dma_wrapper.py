#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# LiteX wrapper of the wpa2 datapath, on HcfpgaDmaWrapper (../hcfpga_dma_wrapper.py): the
# shared register block at bcrypt's offsets, plus EXTRA_CSRS from 0x3c.
#
# wpa2's use of the shared registers: salt0..3 carry ESSID bytes 0..15 (hashcat's salt_buf[0..3]),
# iter_count is hashcat's salt_iter (4095, not used: the count is fixed), core_count the candidates
# in flight, SLOTS_PER_PIPE in each PBKDF2 pipe. The comparator bitmap is not used (WITH_CMP = 0,
# see the engine): hashcat's digest is a MIC or PMKID its kernels compute from the PMK.

import os
import sys

HERE   = os.path.dirname(os.path.abspath(__file__))
BASE   = os.path.normpath(os.path.join(HERE, ".."))
ALGO   = os.path.join(HERE, "wpa2")

if BASE not in sys.path:
    sys.path.insert(0, BASE)

from migen import Signal, Instance

from hcfpga_dma_wrapper import HcfpgaDmaWrapper

# The engine and what it instantiates.
ENGINE_FILES = ["hcfpga_wpa2_top.sv", "hcfpga_wpa2_engine.v", "hcfpga_wpa2_pipe.v", "hcfpga_wpa2_round.v",
                "hcfpga_wpa2_sha1.v"]

# SHA-1 rounds a pipe stage (the top's RPS), and the candidates in flight in one pipe that gives
# (the engine's SLOTS): half the ring of 80 / RPS round stages and four more.
ROUNDS_PER_STAGE = 2
SLOTS_PER_PIPE   = (80 // ROUNDS_PER_STAGE + 4) // 2

# The engine's thermal stop (C): no new candidate from THERM_HOT_C until the die reads below
# THERM_COOL_C. A board wires its die temperature, in XADC encoding, to the wrapper's die_temp;
# where nothing drives it, it reads 0 and the stop never acts.
THERM_HOT_C  = 85
THERM_COOL_C = 75

class Wpa2DmaWrapper(HcfpgaDmaWrapper):
    ALGO = "wpa2"
    TOP  = "hcfpga_wpa2_top"

    # The ESSID length and ESSID bytes 16..31, in the order the bridge's send_config writes them.
    EXTRA_CSRS = (
        ("salt_len", 32, "ESSID length in bytes, 0 to 32."),
        ("salt4",    32, "ESSID bytes 16..19 (hashcat's salt_buf[4])."),
        ("salt5",    32, "ESSID bytes 20..23 (hashcat's salt_buf[5])."),
        ("salt6",    32, "ESSID bytes 24..27 (hashcat's salt_buf[6])."),
        ("salt7",    32, "ESSID bytes 28..31 (hashcat's salt_buf[7])."),
    )

    # C2H records per candidate (the top's PARTS, the identity's parts=): the 32-byte PMK in two
    # records of 32 bytes. parts=1 sends it in one record of 40 bytes instead (hcfpga_wpa2_top.sv):
    # 40 bytes a candidate instead of 64, for a board whose link is short of C2H bytes (UARTBone).
    # The bridge reads the format from the identity. A DMA board keeps 2: its granule is a multiple
    # of 32 bytes.
    PARTS = 2

    # with_cmp is taken for the shared signature and not used: the device cannot compare (above).
    def __init__(self, platform, pipes=1, with_cmp=0, parts=PARTS):
        assert parts in (1, 2), "wpa2 returns its PMK in 1 or 2 C2H records"
        self.PARTS = parts
        HcfpgaDmaWrapper.__init__(self, platform,
            num_cores = pipes * SLOTS_PER_PIPE,
            params    = dict(PIPES=pipes, RPS=ROUNDS_PER_STAGE, WITH_CMP=0,
                             THERM_HOT_C=THERM_HOT_C, THERM_COOL_C=THERM_COOL_C, PARTS=parts),
        )

        # The die temperature, a port of wpa2's top beyond the shared ones.
        self.die_temp = Signal(12)

        top = [s for s in self._fragment.specials if isinstance(s, Instance) and s.of == self.TOP]
        assert len(top) == 1
        top[0].items.append(Instance.Input("die_temp", self.die_temp))

    def hdl_sources(self):
        includes = [ALGO]
        files    = [os.path.join(ALGO, f) for f in ENGINE_FILES]
        return includes, files

    SIM_UNITS_HELP = f"PBKDF2 pipes, {SLOTS_PER_PIPE} candidates in flight each"

    @classmethod
    def for_sim(cls, platform, units, with_cmp):
        return cls(platform, pipes=units, with_cmp=with_cmp)
