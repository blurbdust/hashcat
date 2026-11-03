#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# HcfpgaMemStream: hcfpga's two streams carried over plain register accesses.
#
# From the LiteX hashcat Guide (gateware/hcfpga_memstream.py, MIT), which keeps a copy for its bcrypt
# debug sim. Every algorithm's directory has this copy, for its simulated board.
#
# Every hcfpga wrapper takes H2C 32-bit words on a sink and gives C2H bytes on a source. On PCIe
# boards LitePCIe's DMA feeds them. This module feeds them from two rings that the host reaches
# with ordinary reads and writes instead, so any LiteX bus bridge can drive the datapath:
# Etherbone, UARTBone, JTAGBone or the CSR window behind a PCIe BAR.
#
# Both rings and all their registers live in CSR space, not on the main bus. That is what makes the
# module work behind a PCIe BAR, which LiteX maps onto the CSR region only, and it needs no bus
# region from the SoC: instantiate it, connect the two streams, done.
#
# Each ring has one producer and one consumer, and each pointer is written by exactly one side:
#
#   H2C: the host writes words into h2c_mem, then advances h2c_wr. The module streams words out
#        until h2c_rd catches up. source.last marks the word that empties the ring, which is the
#        end of what the host had published, the closest thing to a DMA buffer end.
#   C2H: the module packs bytes four to a word (first byte in bits 7:0) into c2h_mem and advances
#        c2h_wr. The host reads words, then advances c2h_rd. A full ring backpressures the source
#        rather than dropping anything.
#
# Pointers count words modulo 2^16, so the host computes fill as (wr - rd) & 0xffff and indexes
# the memory with ptr % depth. Reads have no side effects, so a host can re-read or retry anything.

from migen import *

from litex.gen import *

from litex.soc.interconnect.csr import *
from litex.soc.interconnect     import stream

# Helpers ------------------------------------------------------------------------------------------

PTR_BITS = 16

def _check_depth(name, depth):
    if (depth < 2) or (depth & (depth - 1)) or (depth > 2**(PTR_BITS - 1)):
        raise ValueError(f"{name} must be a power of two between 2 and {2**(PTR_BITS - 1)}, not {depth}.")

# HcfpgaMemStream ----------------------------------------------------------------------------------

class HcfpgaMemStream(LiteXModule):
    """H2C/C2H rings in CSR space.

    Depths are in 32-bit words. Keep each at or below csr_paging/4 (512 with LiteX's default 0x800
    paging), otherwise LiteX adds a page register in front of the memory.
    """
    def __init__(self, h2c_depth=512, c2h_depth=512):
        _check_depth("h2c_depth", h2c_depth)
        _check_depth("c2h_depth", c2h_depth)

        self.source = source = stream.Endpoint([("data", 32)]) # H2C words, to the wrapper's sink.
        self.sink   = sink   = stream.Endpoint([("data",  8)]) # C2H bytes, from the wrapper's source.

        self.h2c_mem = Memory(32, h2c_depth, name="h2c_mem")
        self.c2h_mem = Memory(32, c2h_depth, name="c2h_mem")

        # Host-owned registers first, then the three the host polls, so one 3-word burst reads them.
        self._ctrl = CSRStorage(fields=[
            CSRField("reset", size=1, pulse=True, description="Empty both rings: all four pointers to 0, partial C2H word dropped."),
        ])
        self._info = CSRStatus(fields=[
            CSRField("h2c_depth", size=16, description="H2C ring size in 32-bit words."),
            CSRField("c2h_depth", size=16, description="C2H ring size in 32-bit words."),
        ])
        self._h2c_wr = CSRStorage(PTR_BITS, write_from_dev=True, description="H2C write pointer. Host advances it after filling h2c_mem.")
        self._c2h_rd = CSRStorage(PTR_BITS, write_from_dev=True, description="C2H read pointer. Host advances it after reading c2h_mem.")
        self._h2c_rd = CSRStatus(PTR_BITS, description="H2C read pointer: words the sink has accepted.")
        self._c2h_wr = CSRStatus(PTR_BITS, description="C2H write pointer: words captured from the source.")
        self._status = CSRStatus(fields=[
            CSRField("h2c_valid", size=1, description="H2C words are waiting to go out."),
            CSRField("h2c_ready", size=1, description="The sink is accepting a word right now."),
            CSRField("c2h_valid", size=1, description="The source is offering a byte right now."),
            CSRField("c2h_ready", size=1, description="The C2H ring has room."),
        ])

        # # #

        reset = self._ctrl.fields.reset

        self.comb += [
            self._info.fields.h2c_depth.eq(h2c_depth),
            self._info.fields.c2h_depth.eq(c2h_depth),
            self._h2c_wr.we.eq(reset),
            self._h2c_wr.dat_w.eq(0),
            self._c2h_rd.we.eq(reset),
            self._c2h_rd.dat_w.eq(0),
        ]

        # H2C: h2c_mem -> source.
        # The read port is synchronous, so it is addressed with the pointer's next value: dat_r then
        # always holds the word at h2c_rd and a stall needs no extra holding register.
        h2c_wr   = self._h2c_wr.storage
        h2c_rd   = Signal(PTR_BITS)
        h2c_next = Signal(PTR_BITS)

        h2c_port = self.h2c_mem.get_port()
        self.specials += h2c_port

        self.comb += [
            source.valid.eq(h2c_rd != h2c_wr),
            source.data.eq(h2c_port.dat_r),
            source.last.eq((h2c_rd + 1)[:PTR_BITS] == h2c_wr),
            If(reset,
                h2c_next.eq(0)
            ).Else(
                h2c_next.eq(h2c_rd + (source.valid & source.ready))
            ),
            h2c_port.adr.eq(h2c_next),
            self._h2c_rd.status.eq(h2c_rd),
        ]
        self.sync += h2c_rd.eq(h2c_next)

        # C2H: sink -> 8:32 packer -> c2h_mem.
        self.packer = packer = ResetInserter()(stream.Converter(8, 32, reverse=False))
        self.comb += [
            packer.reset.eq(reset),
            sink.connect(packer.sink),
        ]

        c2h_rd   = self._c2h_rd.storage
        c2h_wr   = Signal(PTR_BITS)
        c2h_fill = Signal(PTR_BITS)

        c2h_port = self.c2h_mem.get_port(write_capable=True)
        self.specials += c2h_port

        self.comb += [
            c2h_fill.eq(c2h_wr - c2h_rd),
            packer.source.ready.eq(c2h_fill != c2h_depth),
            c2h_port.adr.eq(c2h_wr),
            c2h_port.dat_w.eq(packer.source.data),
            c2h_port.we.eq(packer.source.valid & packer.source.ready),
            self._c2h_wr.status.eq(c2h_wr),
        ]
        self.sync += [
            If(reset,
                c2h_wr.eq(0)
            ).Elif(c2h_port.we,
                c2h_wr.eq(c2h_wr + 1)
            )
        ]

        self.comb += [
            self._status.fields.h2c_valid.eq(source.valid),
            self._status.fields.h2c_ready.eq(source.ready),
            self._status.fields.c2h_valid.eq(sink.valid),
            self._status.fields.c2h_ready.eq(packer.source.ready),
        ]

    def get_memories(self):
        # Read-only on the bus keeps c2h_mem a simple dual-port RAM (one write, one read), which is
        # all an iCE40 block RAM offers. Same convention as LiteX's Identifier.
        return [(False, self.h2c_mem), (True, self.c2h_mem)]
