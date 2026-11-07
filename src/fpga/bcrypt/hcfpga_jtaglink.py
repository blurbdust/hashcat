#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from migen import *
from migen.genlib.cdc import MultiReg
from migen.genlib.resetsync import AsyncResetSynchronizer

from litex.gen import *

from litex.soc.interconnect import stream, wishbone

# The engine over the card's own JTAG, for a slot whose PCIe link does not come up. The link is a
# Virtual JTAG node on Intel's JTAG hub, which the transceiver reconfiguration controller's Nios
# debug node already brings in, so the raw JTAG atom cannot be used. The host finds the node through
# the hub, selects it, and shifts fixed size scans through its data register. Each scan carries a
# request in and a response out, laid out below, LSB first. A scan whose request does not start
# with the magic is ignored, so the host can probe the bit alignment without side effects.
#
# Request, host to card, acted on in Update-DR:
#   [  0: 16] magic 0xa55a
#   [ 16: 21] payload words, 0 to 16
#   [ 21]     claim: route the engine streams to JTAG
#   [ 22]     release: route them back to PCIe
#   [ 24: 26] register access: 1 read, 2 write
#   [ 32: 40] register access tag, returned with the result
#   [ 64: 96] register byte address, as on PCIe BAR0
#   [ 96:128] register write data
#   [128:640] payload words for the engine, first word in the lowest bits
#
# Response, card to host, loaded in Capture-DR:
#   [  0: 16] magic 0x5aa5
#   [ 16: 23] payload bytes, 0 to 64
#   [ 23]     a request found the input FIFO full (sticky until the next claim)
#   [ 24: 32] tag of the last finished register access
#   [ 32: 48] input FIFO entries taken by the engine side, wrapping
#   [ 48: 52] log2 of the input FIFO depth in entries
#   [ 52]     the engine streams are routed to JTAG
#   [ 64: 96] read data of the last finished register access
#   [ 96:128] first 32 bits of the previous scan as the card saw them
#   [128:640] payload bytes from the engine. With fewer than 64, they are the top ones.
#
# The host keeps at most the FIFO depth of requests with payload in flight, counted against the
# entries taken, so a request never finds the FIFO full in normal use.

JTAGLINK_INSTANCE  = 0x48
JTAGLINK_WORDS     = 16
JTAGLINK_HDR_BITS  = 128
JTAGLINK_SCAN_BITS = JTAGLINK_HDR_BITS + 32 * JTAGLINK_WORDS

JTAGLINK_REQ_MAGIC = 0xa55a
JTAGLINK_RSP_MAGIC = 0x5aa5

JTAGLINK_CSR_READ  = 1
JTAGLINK_CSR_WRITE = 2

JTAGLINK_TCK_HZ    = 30e6

class JTAGLink (LiteXModule):
  def __init__ (self, platform, csr_base=0, fifo_depth=256, flush_cycles=512):
    assert fifo_depth in [2 ** n for n in range (4, 16)]

    payload_bits = 32 * JTAGLINK_WORDS

    self.source = stream.Endpoint ([("data", 32)])
    self.sink   = stream.Endpoint ([("data",  8)])
    self.bus    = wishbone.Interface (data_width=32, address_width=32, addressing="word")
    self.active = Signal ()

    # # #

    # Virtual JTAG node ----------------------------------------------------------------------------

    tck     = Signal ()
    tdi     = Signal ()
    tdo     = Signal ()
    capture = Signal ()
    shift   = Signal ()
    update  = Signal ()

    self.specials += Instance ("sld_virtual_jtag",
      p_sld_auto_instance_index = "NO",
      p_sld_instance_index      = JTAGLINK_INSTANCE,
      p_sld_ir_width            = 1,
      o_tck                     = tck,
      o_tdi                     = tdi,
      i_tdo                     = tdo,
      i_ir_out                  = 0,
      o_virtual_state_cdr       = capture,
      o_virtual_state_sdr       = shift,
      o_virtual_state_udr       = update,
    )

    self.cd_jtag = ClockDomain ()
    self.comb += ClockSignal ("jtag").eq (tck)
    self.specials += AsyncResetSynchronizer (self.cd_jtag, ResetSignal ("sys"))

    # FIFOs ----------------------------------------------------------------------------------------

    self.h2c = h2c = ClockDomainsRenamer ({"write": "jtag", "read": "sys"}) (
      stream.AsyncFIFO ([("data", payload_bits), ("count", 5)], fifo_depth))
    self.c2h = c2h = ClockDomainsRenamer ({"write": "sys", "read": "jtag"}) (
      stream.AsyncFIFO ([("data", payload_bits), ("count", 7)], fifo_depth))

    # Scan register (jtag) -------------------------------------------------------------------------

    sr = Signal (JTAGLINK_SCAN_BITS)

    self.comb += tdo.eq (sr[0])

    req_magic = sr[  0: 16]
    req_words = sr[ 16: 21]
    req_claim = sr[ 21]
    req_rel   = sr[ 22]
    req_op    = sr[ 24: 26]
    req_tag   = sr[ 32: 40]
    req_addr  = sr[ 64: 96]
    req_wdata = sr[ 96:128]
    req_data  = sr[128:   ]

    req_ok = Signal ()
    push   = Signal ()

    self.comb += [
      req_ok.eq ((req_magic == JTAGLINK_REQ_MAGIC) & (req_words <= JTAGLINK_WORDS)),
      push  .eq (update & req_ok & (req_words != 0)),

      h2c.sink.valid.eq (push),
      h2c.sink.data .eq (req_data),
      h2c.sink.count.eq (req_words),

      c2h.source.ready.eq (capture),
    ]

    active_j   = Signal ()
    overflow   = Signal ()
    echo       = Signal (32)
    csr_tag_j  = Signal (8)
    csr_dat_j  = Signal (32)
    consumed_j = Signal (16)

    # Register access request, held for the sys side until the next one.
    req_toggle = Signal ()
    req_we_r   = Signal ()
    req_adr_r  = Signal (32)
    req_dat_r  = Signal (32)
    req_tag_r  = Signal (8)

    rsp_count = Signal (7)
    rsp_data  = Signal (payload_bits)

    self.comb += If (c2h.source.valid,
      rsp_count.eq (c2h.source.count),
      rsp_data .eq (c2h.source.data),
    )

    rsp = Cat (
      Constant (JTAGLINK_RSP_MAGIC, 16),
      rsp_count,
      overflow,
      csr_tag_j,
      consumed_j,
      Constant (log2_int (fifo_depth), 4),
      active_j,
      Constant (0, 11),
      csr_dat_j,
      echo,
      rsp_data,
    )

    assert len (rsp) == JTAGLINK_SCAN_BITS

    self.sync.jtag += [
      If (capture,
        sr.eq (rsp),
      ).Elif (shift,
        sr.eq (Cat (sr[1:], tdi)),
      ),
      If (update,
        echo.eq (sr[0:32]),
        If (req_ok,
          If (req_claim, active_j.eq (1), overflow.eq (0)),
          If (req_rel,   active_j.eq (0)),
          If (push & ~h2c.sink.ready, overflow.eq (1)),
          If (req_op != 0,
            req_we_r .eq (req_op == JTAGLINK_CSR_WRITE),
            req_adr_r.eq (req_addr),
            req_dat_r.eq (req_wdata),
            req_tag_r.eq (req_tag),
            req_toggle.eq (~req_toggle),
          ),
        ),
      ),
    ]

    self.specials += MultiReg (active_j, self.active, "sys")

    # Entries taken, Gray coded across -------------------------------------------------------------

    consumed   = Signal (16)
    consumed_g = Signal (16)
    consumed_s = Signal (16)

    self.sync += consumed_g.eq (consumed ^ (consumed >> 1))

    self.specials += MultiReg (consumed_g, consumed_s, "jtag")

    bits = [None] * 16

    bits[15] = consumed_s[15]

    for i in reversed (range (15)):
      bits[i] = bits[i + 1] ^ consumed_s[i]

    self.sync.jtag += consumed_j.eq (Cat (*bits))

    # Host to engine (sys) -------------------------------------------------------------------------

    buf  = Signal (payload_bits)
    left = Signal (5)
    load = Signal ()

    self.comb += [
      self.source.valid.eq (left != 0),
      self.source.data .eq (buf[:32]),

      load.eq ((left == 0) | ((left == 1) & self.source.ready)),

      h2c.source.ready.eq (load),
    ]

    self.sync += [
      If (load,
        If (h2c.source.valid,
          buf     .eq (h2c.source.data),
          left    .eq (h2c.source.count),
          consumed.eq (consumed + 1),
        ).Else (
          left.eq (0),
        ),
      ).Elif (self.source.ready & (left != 0),
        buf .eq (buf[32:]),
        left.eq (left - 1),
      ),
    ]

    # Engine to host (sys) -------------------------------------------------------------------------

    pbuf = Signal (payload_bits)
    pcnt = Signal (7)
    idle = Signal (max=flush_cycles + 1)
    emit = Signal ()

    self.comb += [
      emit.eq ((pcnt == 4 * JTAGLINK_WORDS) | ((pcnt != 0) & (idle == flush_cycles))),

      c2h.sink.valid.eq (emit),
      c2h.sink.data .eq (pbuf),
      c2h.sink.count.eq (pcnt),

      self.sink.ready.eq (~emit),
    ]

    self.sync += [
      If (emit,
        If (c2h.sink.ready,
          pcnt.eq (0),
          idle.eq (0),
        ),
      ).Elif (self.sink.valid,
        pbuf.eq (Cat (pbuf[8:], self.sink.data)),
        pcnt.eq (pcnt + 1),
        idle.eq (0),
      ).Elif ((pcnt != 0) & (idle != flush_cycles),
        idle.eq (idle + 1),
      ),
    ]

    # Register access (sys) ------------------------------------------------------------------------

    req_toggle_s = Signal ()
    req_seen     = Signal ()
    busy         = Signal ()

    rsp_toggle = Signal ()
    rsp_tag_s  = Signal (8)
    rsp_dat_s  = Signal (32)

    self.specials += MultiReg (req_toggle, req_toggle_s, "sys")

    self.comb += [
      self.bus.adr  .eq ((csr_base + req_adr_r) >> 2),
      self.bus.dat_w.eq (req_dat_r),
      self.bus.we   .eq (req_we_r),
      self.bus.sel  .eq (0xf),
      self.bus.cyc  .eq (busy),
      self.bus.stb  .eq (busy),
    ]

    self.sync += [
      If (~busy & (req_toggle_s != req_seen),
        req_seen.eq (req_toggle_s),
        busy    .eq (1),
      ).Elif (busy & (self.bus.ack | self.bus.err),
        busy      .eq (0),
        rsp_dat_s .eq (self.bus.dat_r),
        rsp_tag_s .eq (req_tag_r),
        rsp_toggle.eq (~rsp_toggle),
      ),
    ]

    rsp_toggle_j = Signal ()
    rsp_seen_j   = Signal ()

    self.specials += MultiReg (rsp_toggle, rsp_toggle_j, "jtag")

    self.sync.jtag += If (rsp_toggle_j != rsp_seen_j,
      rsp_seen_j.eq (rsp_toggle_j),
      csr_tag_j .eq (rsp_tag_s),
      csr_dat_j .eq (rsp_dat_s),
    )

  def add_timing_constraints (self, platform, sys_clk_name="sys_clk", tck_hz=JTAGLINK_TCK_HZ):
    # The hub's clock is the JTAG pin, which Quartus' own hub constraints may already have named.
    # Every crossing to and from it goes through a FIFO, a MultiReg or a register that the protocol
    # holds still until the other side has seen a toggle, so the paths between the clocks are false.
    period = 1e9 / tck_hz

    platform.toolchain.additional_sdc_commands += [
      "if {[get_collection_size [get_clocks -nowarn altera_reserved_tck]] == 0} {",
      f"    create_clock -name altera_reserved_tck -period {period:.3f} [get_ports {{altera_reserved_tck}}]",
      "}",
      f"set_false_path -from [get_clocks altera_reserved_tck] -to [get_clocks {sys_clk_name}]",
      f"set_false_path -from [get_clocks {sys_clk_name}] -to [get_clocks altera_reserved_tck]",
    ]

def connect_engine (soc, link, down, up, engine):
  # The engine's input and output go to JTAG while the host has claimed them, otherwise to PCIe.
  # The buffers keep the mux out of the paths the engine was placed against.
  sink_buf   = stream.Buffer ([("data", 32)], pipe_valid=True, pipe_ready=True)
  source_buf = stream.Buffer ([("data",  8)], pipe_valid=True, pipe_ready=True)

  soc.submodules += sink_buf, source_buf

  soc.comb += [
    sink_buf.source.connect (engine.sink),
    engine.source.connect (source_buf.sink),

    If (link.active,
      link.source.connect (sink_buf.sink),
      source_buf.source.connect (link.sink),
    ).Else (
      down.connect (sink_buf.sink),
      source_buf.source.connect (up),
    ),
  ]
