#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# HcfpgaDmaWrapper: the LiteX side every hcfpga algorithm shares.
#
# A wrapper puts an algorithm's HDL top behind the register block and the two streams hashcat's
# bridge drives. The block is bcrypt's (src/fpga/bcrypt/gateware/bcrypt_dma_wrapper.py), at the same
# offsets, because the transports and the shared CSR map hardcode them:
#
#   0x00 ctrl          bit 0: framing reset (bit 1 is bcrypt's mode_dump; unused here)
#   0x04 salt0 .. 0x10 salt3   the four salt words the bridge writes
#   0x14 iter_count    the cost the bridge writes
#   0x18 status        frame status: bit 0 slip, bit 1 last_seen, 15:8 slip count, 31:16 the algorithm's
#   0x1c core_count    num_cores
#   0x20 cmp_bm0 .. 0x2c cmp_bm3   comparator bitmap, loaded on the write of cmp_bm3
#   0x30 batch_target  arm: EOB once this many records have retired
#   0x34 pad_recs      C2H records per DMA granule
#   0x38 retired       records retired since the arm
#   0x3c ...           the algorithm's EXTRA_CSRS, in order, never in front of the above
#
# A subclass names its top (TOP), its extra registers (EXTRA_CSRS), its sources (hdl_sources) and
# how the simulated board builds it (for_sim). Each extra register is a CSRStorage wired to the
# top's input port of the same name. The top has these ports, the same as bcrypt's hcfpga_top.sv
# apart from mode_dump:
#
#   CLK, [CLK_CORE], rst, s_data/s_valid/s_ready/s_last (32-bit H2C words), frame_status,
#   salt0..salt3, iter_count, cmp_bitmap, cmp_load, batch_target, batch_arm, pad_recs, retired_cnt,
#   m_data/m_valid/m_ready/m_last (C2H bytes), one input per extra register.
#
# check_offsets() asserts the layout after the SoC is finalized.

import os

from migen import *
from litex.gen import *
from litex.soc.interconnect.csr import *
from litex.soc.interconnect import stream

COMMON = os.path.dirname(os.path.abspath(__file__))
RTL    = os.path.join(COMMON, "rtl")

SHARED_CSRS = ["ctrl", "salt0", "salt1", "salt2", "salt3", "iter_count", "status", "core_count",
               "cmp_bm0", "cmp_bm1", "cmp_bm2", "cmp_bm3", "batch_target", "pad_recs", "retired"]

EXTRA_OFFSET = 4 * len(SHARED_CSRS)

class HcfpgaDmaWrapper(LiteXModule):
    ALGO = None

    TOP = None

    # ((name, bits, description), ...), appended from 0x3c in this order.
    EXTRA_CSRS = ()

    # Shared RTL the top instantiates, from src/fpga/common/rtl/.
    COMMON_RTL = ("hcfpga_c2h_eob.v", "hcfpga_gen.v", "hcfpga_h2c_intake.v")

    # The top has a CLK_CORE port (cores on their own clock, as JtR's md5crypt unit allows).
    HAS_CORE_CLK = False

    # C2H records per candidate: 1, or up to 4 for a device that returns more than 24 digest bytes
    # (record k carries digest bytes 24k..24k+23, its part index in flag bits 8..11). The identity
    # says parts= when above 1, and the bridge's hcfpga_algo_t.c2h_parts has to agree.
    PARTS = 1

    def __init__(self, platform, num_cores, params=None, core_clk=False):
        assert self.ALGO and self.TOP, "a wrapper names its ALGO and its TOP"

        self.sink   = stream.Endpoint([("data", 32)])
        self.source = stream.Endpoint([("data", 8)])

        self.num_cores = num_cores

        # The shared block, in this order: offsets are 4 * position.
        self._ctrl       = CSRStorage(32)
        self._salt0      = CSRStorage(32)
        self._salt1      = CSRStorage(32)
        self._salt2      = CSRStorage(32)
        self._salt3      = CSRStorage(32)
        self._iter_count = CSRStorage(32)
        self._status     = CSRStatus(32)
        self._core_count = CSRStatus(32, reset=num_cores)

        self._cmp_bm0    = CSRStorage(32)
        self._cmp_bm1    = CSRStorage(32)
        self._cmp_bm2    = CSRStorage(32)
        self._cmp_bm3    = CSRStorage(32)

        self._batch_target = CSRStorage(32)

        self._pad_recs   = CSRStorage(16)

        self._retired    = CSRStatus(32)

        # The algorithm's own, from 0x3c.
        self.extra_csrs = {}
        for name, bits, description in self.EXTRA_CSRS:
            csr = CSRStorage(bits, name=name, description=description)
            object.__setattr__(self, "_" + name, csr)
            self.extra_csrs[name] = csr

        # # #

        rst = Signal()

        self.comb += rst.eq(ResetSignal("sys") | self._ctrl.storage[0])

        m_last       = Signal()
        frame_status = Signal(32)
        retired_cnt  = Signal(32)

        ports = dict(
            i_CLK = ClockSignal(),
            i_rst = rst,

            i_s_data  = self.sink.data,
            i_s_valid = self.sink.valid,
            o_s_ready = self.sink.ready,
            i_s_last  = self.sink.last,

            o_frame_status = frame_status,

            i_salt0      = self._salt0.storage,
            i_salt1      = self._salt1.storage,
            i_salt2      = self._salt2.storage,
            i_salt3      = self._salt3.storage,
            i_iter_count = self._iter_count.storage,

            i_cmp_bitmap = Cat(self._cmp_bm0.storage, self._cmp_bm1.storage,
                               self._cmp_bm2.storage, self._cmp_bm3.storage),
            i_cmp_load   = self._cmp_bm3.re,

            i_batch_target = self._batch_target.storage,
            i_batch_arm    = self._batch_target.re,

            i_pad_recs     = self._pad_recs.storage,
            o_retired_cnt  = retired_cnt,

            o_m_data  = self.source.data,
            o_m_valid = self.source.valid,
            i_m_ready = self.source.ready,
            o_m_last  = m_last,
        )

        if self.HAS_CORE_CLK:
            ports["i_CLK_CORE"] = ClockSignal("core") if core_clk else ClockSignal("sys")

        for name, csr in self.extra_csrs.items():
            ports["i_" + name] = csr.storage

        for k, v in (params or {}).items():
            ports["p_" + k] = v

        self.specials += Instance(self.TOP, **ports)

        self.comb += self.source.last.eq(m_last)

        self.comb += self._status.status.eq(frame_status)

        self.comb += self._retired.status.eq(retired_cnt)

    # Sources ------------------------------------------------------------------------------------

    def hdl_sources(self):
        """(include_dirs, files) of the algorithm's own HDL, absolute paths."""
        raise NotImplementedError

    def add_hdl_sources(self):
        from litex.gen import LiteXContext
        platform = LiteXContext.platform

        includes, files = self.hdl_sources()

        platform.add_verilog_include_path(RTL)
        for d in includes:
            platform.add_verilog_include_path(d)

        for f in self.COMMON_RTL:
            platform.add_source(os.path.join(RTL, f))
        for f in files:
            platform.add_source(f)

    # Simulated board ----------------------------------------------------------------------------

    @classmethod
    def for_sim(cls, platform, units, with_cmp):
        """The wrapper the simulated board (hcfpga_sim.py) builds, with units computing units."""
        raise NotImplementedError

    SIM_UNITS_HELP = "computing units"

# Checks -----------------------------------------------------------------------------------------

def check_offsets(soc, name, wrapper):
    """After soc.finalize(): every shared register at its fixed offset, the extras from 0x3c."""
    want = SHARED_CSRS + [n for n, _, _ in wrapper.EXTRA_CSRS]
    banks = {bank_name: rmap for bank_name, csrs, mapaddr, rmap in soc.csr_bankarray.banks}
    if name not in banks:
        raise SystemExit(f"No CSR bank named {name}: the wrapper must be the SoC attribute {name}.")
    # Register names inside a bank, without the bank prefix csr.csv adds (LiteX versions differ).
    have = [c.name[len(name) + 1:] if c.name.startswith(name + "_") else c.name for c in banks[name].simple_csrs]
    bad  = []
    for i, n in enumerate(want):
        if (i >= len(have)) or (have[i] != n):
            bad.append(f"0x{4 * i:02x} holds {have[i] if i < len(have) else 'nothing'}, wants {n}")
    if len(have) != len(want):
        bad.append(f"{len(have)} registers in the bank, wants {len(want)}: {', '.join(have[len(want):])}")
    if bad:
        raise SystemExit("The algorithm bank does not match the offsets the bridge uses:\n  " + "\n  ".join(bad))
