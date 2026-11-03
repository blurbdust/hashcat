#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# LiteX wrapper of the md5crypt datapath, the counterpart of bcrypt_dma_wrapper.py.
#
# The CSRs keep bcrypt's order, so every shared register sits at the offset the bridges use:
#
#   0x00 ctrl          bit 0: framing reset (bit 1, bcrypt's mode_dump, is unused)
#   0x04 salt0 .. 0x10 salt3   salt bytes 0..15, hashcat's salt_buf[0..3] unchanged
#   0x14 iter_count    md5crypt rounds, 1..65535 (the CPU reads 16 bits)
#   0x18 status        frame status: bit 0 slip, bit 1 last_seen, 15:8 slip count,
#                      23:16 unit results whose 2-bit framing was off
#   0x1c core_count    MD5 cores, num_units * cores_per_unit
#   0x20 cmp_bm0 .. 0x2c cmp_bm3   comparator bitmap, loaded on the write of cmp_bm3
#   0x30 batch_target  arm: EOB once this many records have retired
#   0x34 pad_recs      C2H records per DMA granule
#   0x38 retired       records retired since the arm
#   0x3c salt_len      md5crypt only: salt length in bytes, 1..8 (bcrypt's salt is always 16)

import os

from migen import *
from litex.gen import *
from litex.soc.interconnect.csr import *
from litex.soc.interconnect import stream

class Md5cryptDmaWrapper(LiteXModule):
    def __init__(self, platform, num_units=1, cores_per_unit=3, with_cmp=1, core_clk=False):
        self.sink   = stream.Endpoint([("data", 32)])
        self.source = stream.Endpoint([("data", 8)])

        self.num_units      = num_units
        self.cores_per_unit = cores_per_unit
        self.num_cores      = num_units * cores_per_unit

        self._ctrl       = CSRStorage(32)
        self._salt0      = CSRStorage(32)
        self._salt1      = CSRStorage(32)
        self._salt2      = CSRStorage(32)
        self._salt3      = CSRStorage(32)
        self._iter_count = CSRStorage(32)
        self._status     = CSRStatus(32)
        self._core_count = CSRStatus(32, reset=self.num_cores)

        self._cmp_bm0    = CSRStorage(32)
        self._cmp_bm1    = CSRStorage(32)
        self._cmp_bm2    = CSRStorage(32)
        self._cmp_bm3    = CSRStorage(32)

        self._batch_target = CSRStorage(32)

        self._pad_recs   = CSRStorage(16)

        self._retired    = CSRStatus(32)

        self._salt_len   = CSRStorage(32)

        rst = Signal()

        self.comb += rst.eq(ResetSignal("sys") | self._ctrl.storage[0])

        m_last       = Signal()
        frame_status = Signal(32)
        retired_cnt  = Signal(32)

        self.specials += Instance("hcfpga_md5crypt_top",
            p_NUM_UNITS      = num_units,
            p_CORES_PER_UNIT = cores_per_unit,
            p_WITH_CMP       = with_cmp,

            i_CLK      = ClockSignal(),
            i_CLK_CORE = ClockSignal("core") if core_clk else ClockSignal("sys"),
            i_rst      = rst,

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
            i_salt_len   = self._salt_len.storage,

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

        self.comb += self.source.last.eq(m_last)

        self.comb += self._status.status.eq(frame_status)

        self.comb += self._retired.status.eq(retired_cnt)

    def add_hdl_sources(self):
        from litex.gen import LiteXContext
        here = os.path.dirname(__file__)
        md5  = os.path.join(here, "md5crypt")

        for d in ["", "util", "cpu"]:
            LiteXContext.platform.add_verilog_include_path(os.path.join(md5, d))

        for f in ["hcfpga_md5crypt_top.sv", "hcfpga_md5crypt_feed.v", "hcfpga_md5crypt_collect.v", "hcfpga_c2h_eob.v",
                  "md5unit.v", "unit_ctrl.v", "core_ctrl.v", "unit_input_async.v", "uob16pq.v"]:
            LiteXContext.platform.add_source(os.path.join(md5, f))

        for d in ["cpu", "md5core", "md5engine"]:
            for f in sorted(os.listdir(os.path.join(md5, d))):
                if f.endswith(".v"):
                    LiteXContext.platform.add_source(os.path.join(md5, d, f))

        for f in ["sync.v", "delay.v", "asymm_bram.v"]:
            LiteXContext.platform.add_source(os.path.join(md5, "util", f))
