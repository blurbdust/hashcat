#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# LiteX wrapper of the DES known-plaintext datapath, on HcfpgaDmaWrapper (../hcfpga_dma_wrapper.py):
# the shared register block at bcrypt's offsets, and des_kpa's own registers after it.
#
# des_kpa's use of the shared registers: salt0..1 carry hashcat's salt_buf[0..1], the plaintext;
# salt2..3, iter_count and the comparator bitmap are written but unused (the engine compares every
# key against the targets in full); core_count is the number of DES cores, one key per clock each.
#
# Its own, from 0x3c: amp_cnt and amp_lens (the amplifier's positions and their lengths), amp_tab (a
# write puts one character into a position's table), tgt_mask and the four targets' ciphertexts.

import os
import sys

HERE   = os.path.dirname(os.path.abspath(__file__))
BASE   = os.path.normpath(os.path.join(HERE, ".."))
ALGO   = os.path.join(HERE, "des_kpa")

if BASE not in sys.path:
    sys.path.insert(0, BASE)

from migen import Signal, Instance

from hcfpga_dma_wrapper import HcfpgaDmaWrapper

ENGINE_FILES = ["hcfpga_des_kpa_top.sv", "hcfpga_des_kpa_engine.v", "hcfpga_des_kpa_core.v"]

# The engine's thermal stop (C): the generator holds from THERM_HOT_C until the die reads below
# THERM_COOL_C. A board wires its die temperature, in XADC encoding, to the wrapper's die_temp; where
# nothing drives it, it reads 0 and the stop never acts.
THERM_HOT_C  = 85
THERM_COOL_C = 75

class DesKpaDmaWrapper(HcfpgaDmaWrapper):
    ALGO = "des_kpa"
    TOP  = "hcfpga_des_kpa_top"

    EXTRA_CSRS = (
        ("amp_cnt",  32, "Amplifier positions the device walks, 0 to 4 (0: one key per record)."),
        ("amp_lens", 32, "Characters in each amplifier position minus one, position p in bits 8p+7..8p."),
        ("amp_tab",  32, "Table write: bits 17:16 the position, 15:8 the index, 7:0 the character."),
        ("tgt_mask", 32, "Targets the comparator uses, bit k for target k."),
        ("tgt0_lo",  32, "Target 0 ciphertext bytes 0..3 (byte 0 in bits 7:0)."),
        ("tgt0_hi",  32, "Target 0 ciphertext bytes 4..7."),
        ("tgt1_lo",  32, "Target 1 ciphertext bytes 0..3."),
        ("tgt1_hi",  32, "Target 1 ciphertext bytes 4..7."),
        ("tgt2_lo",  32, "Target 2 ciphertext bytes 0..3."),
        ("tgt2_hi",  32, "Target 2 ciphertext bytes 4..7."),
        ("tgt3_lo",  32, "Target 3 ciphertext bytes 0..3."),
        ("tgt3_hi",  32, "Target 3 ciphertext bytes 4..7."),
    )

    def __init__(self, platform, num_cores=1, with_cmp=1):
        HcfpgaDmaWrapper.__init__(self, platform,
            num_cores = num_cores,
            params    = dict(NUM_CORES=num_cores, WITH_CMP=1,
                             THERM_HOT_C=THERM_HOT_C, THERM_COOL_C=THERM_COOL_C),
        )

        # Ports of des_kpa's top beyond the shared ones: the table write strobe and the die
        # temperature.
        self.die_temp = Signal(12)

        top = [s for s in self._fragment.specials if isinstance(s, Instance) and s.of == self.TOP]
        assert len(top) == 1
        top[0].items.append(Instance.Input("amp_tab_we", self.extra_csrs["amp_tab"].re))
        top[0].items.append(Instance.Input("die_temp", self.die_temp))

    def hdl_sources(self):
        includes = [ALGO]
        files    = [os.path.join(ALGO, f) for f in ENGINE_FILES]
        return includes, files

    SIM_UNITS_HELP = "pipelined DES cores, one key per clock each"

    @classmethod
    def for_sim(cls, platform, units, with_cmp):
        return cls(platform, num_cores=units, with_cmp=with_cmp)
