#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

import os
import math
import argparse
import datetime

from migen import *

from litex.gen import *

from litex_boards.platforms import microsoft_a2020
from litex_boards.targets.microsoft_a2020 import request_pcie_lanes

from litex.soc.interconnect     import stream
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *

from litex.soc.cores.clock.intel_stratix10 import Stratix10PLL
from litex.soc.cores.led import LedChaser

from litepcie.phy.s10pciephy import S10PCIEPHY
from litepcie.software       import generate_litepcie_software_headers

from gateware.bcrypt_dma_wrapper import BcryptDmaWrapper

from hcfpga_abi import fpga_abi_current
from hcfpga_litepcie import PCIE_CLASS_CODE, clock_mhz
from hcfpga_stratix10 import Stratix10SDM, Stratix10Temperature, Stratix10ChipID

BOARD = "a2020"

BOARD_SHAPE = {
    "din_bits":       32,

    "init_batch":     0,

    "num_cores_dist": 0,

    "feed_group":     32,

    "feed_shard":     128,

    "collect_group":  50,

    "no_dump":        1,

    "no_cmp":         1,

    "cslow":          1,
}

# Extra setup uncertainty, in ns, that the fitter places sys_clk against.
PLACEMENT_MARGIN = 0.0

# The A-2020 is a Microsoft card with a Stratix 10 GX 2800, 1SG280LN2F43E2VG, L-Tile, on an x16
# edge connector. Quartus Prime Pro builds it, with a license that covers Stratix 10.

# The SDM clients and their counters run on their own slow clock, away from sys_clk. It is an
# integer fraction of sys_clk at or below 100 MHz, so the PLL needs no VCO that sys_clk could only
# approximate.
MGMT_FREQ_MAX = 100e6

def mgmt_freq(sys_clk_freq):
    return sys_clk_freq / math.ceil(sys_clk_freq / MGMT_FREQ_MAX)

class _CRG(LiteXModule):
    def __init__(self, platform, sys_clk_freq, ninit_done, cslow=1):
        self.rst     = Signal()
        self.cd_sys  = ClockDomain()
        self.cd_mgmt = ClockDomain()

        # 100 MHz from the onboard clock. The card has no reset input, so the PLL lock is the
        # reset. ninit_done holds the PLL, and so every domain it feeds, until the device has
        # finished initialising.
        clk100 = platform.request("clk100")

        self.pll = pll = Stratix10PLL(platform, speedgrade="-2")
        self.comb += pll.reset.eq(self.rst | ninit_done)
        pll.register_clkin(clk100, 100e6)
        pll.create_clkout(self.cd_sys,  sys_clk_freq)
        pll.create_clkout(self.cd_mgmt, mgmt_freq(sys_clk_freq))

        if cslow == 2:
            self.cd_core = ClockDomain()
            pll.create_clkout(self.cd_core, 2 * sys_clk_freq)

        # The SoC reset reaching the PLL reset is the only path from sys to clk100, and the PLL
        # lock reaching each domain's reset synchroniser the only path back. Both are asynchronous
        # by construction. Each domain is cut from clk100 on its own, because sys and core must stay
        # timed against each other.
        for cd in [self.cd_sys, self.cd_mgmt] + ([self.cd_core] if cslow == 2 else []):
            platform.add_false_path_constraints(cd.clk, clk100)

        # The temperature and chip ID cross from mgmt to sys through synchronisers.
        platform.toolchain.additional_sdc_commands += [
            "set_false_path -from [get_clocks {sys_clk}] -to [get_clocks {mgmt_clk}]",
            "set_false_path -from [get_clocks {mgmt_clk}] -to [get_clocks {sys_clk}]",
        ]

class BcryptSoC(SoCMini):
    def __init__(self, sys_clk_freq=200e6, num_cores=1, with_led=True, feed_group=0, feed_shard=0, collect_group=0, init_batch=0, num_cores_dist=0, with_dump=1, with_cmp=1, din_bits=32, abi=1, cslow=1, pcie_speed="gen2", pcie_lanes=8, placement_margin=0.0):
        platform = microsoft_a2020.Platform()

        # The SDM clients come first: the CRG needs the Reset Release IP's ninit_done.
        self.sdm = Stratix10SDM(platform, cd="mgmt")

        self.crg = _CRG(platform, sys_clk_freq, self.sdm.ninit_done, cslow)

        stamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = f"hcfpga/1;board={BOARD};algo=bcrypt;cores={num_cores};clk={int(sys_clk_freq/1e6)};abi={abi};build={stamp}",
            ident_version = False,
        )

        # The shared register map. LiteX places CSR blocks in order, and this PHY has no status
        # block where the Xilinx ones have two, so the later blocks are pinned to the addresses the
        # driver and the bridge use on every other LiteX board.
        self.csr.add("pcie_endpoint", n=5)
        self.csr.add("pcie_msi",      n=6)
        self.csr.add("pcie_phy",      n=7)
        self.csr.add("xadc",          n=8)
        self.csr.add("dna",           n=9)

        # Lanes beyond the ones in use are left unrequested: a transceiver pin that is constrained
        # and not driven is a fitter error.
        self.pcie_phy = S10PCIEPHY(platform, request_pcie_lanes(platform, pcie_lanes),
            ninit_done = self.sdm.ninit_done,
            speed      = pcie_speed,
            nlanes     = pcie_lanes,
            bar0_size  = 0x10_0000,
            class_code = PCIE_CLASS_CODE << 8,
        )

        self.add_pcie(phy=self.pcie_phy, ndmas=1, address_width=64)

        # Power optimisation puts logic on the critical path into a slower mode. Speed is the right
        # trade here.
        platform.toolchain.additional_qsf_commands += [
            "set_global_assignment -name OPTIMIZE_POWER_DURING_SYNTHESIS OFF",
            "set_global_assignment -name OPTIMIZE_POWER_DURING_FITTING OFF",
            "set_global_assignment -name OPTIMIZATION_MODE \"SUPERIOR PERFORMANCE\"",
        ]

        # Extra setup uncertainty squeezes placement. Only the fitter sees it, so the Timing Analyzer
        # reports the design's real slack. With two hash cores the round loop runs on core_clk.
        if placement_margin:
            platform.toolchain.additional_sdc_commands += [
                "if {$::TimeQuestInfo(nameofexecutable) eq \"quartus_fit\"} {",
            ] + [
                f"    set_clock_uncertainty -add -setup -from [get_clocks {c}] -to [get_clocks {c}] {placement_margin:.3f}"
                for c in ["sys_clk"] + (["core_clk"] if cslow == 2 else [])
            ] + [
                "}",
            ]

        if with_led:
            self.leds = LedChaser(pads=platform.request_all("user_led"), sys_clk_freq=sys_clk_freq)

        self.xadc = Stratix10Temperature(self.sdm, cd="mgmt", clk_freq=mgmt_freq(sys_clk_freq))
        self.dna  = Stratix10ChipID(self.sdm, cd="mgmt", clk_freq=mgmt_freq(sys_clk_freq))

        self.bcrypt = BcryptDmaWrapper(platform, num_cores=num_cores,
            num_cores_dist=num_cores_dist, din_bits=din_bits, feed_group=feed_group,
            feed_shard=feed_shard,
            collect_group=collect_group, init_batch=init_batch, with_dump=with_dump, with_cmp=with_cmp,
            cslow=cslow)
        self.bcrypt.add_hdl_sources()

        dw = self.pcie_dma0.data_width

        self.dma_down = stream.Converter(dw, 32, reverse=False)
        self.comb += [
            self.pcie_dma0.source.connect(self.dma_down.sink),
            self.dma_down.source.connect(self.bcrypt.sink),
        ]

        self.dma_up = stream.Converter(8, dw, reverse=False)
        self.comb += [
            self.bcrypt.source.connect(self.dma_up.sink),
            self.dma_up.source.connect(self.pcie_dma0.sink),
        ]

def main():
    parser = argparse.ArgumentParser(description="hcfpga bcrypt on a Microsoft A-2020 (Stratix 10).")
    parser.add_argument("--build", action="store_true", help="Build the bitstream.")
    parser.add_argument("--load",  action="store_true", help="Load the bitstream over JTAG with the Quartus Programmer.")
    parser.add_argument("--cores",        type=int,   default=1,     help="Number of bcrypt cores.")
    parser.add_argument("--no-dump",      action="store_true",       help="Omit the unfinished S state dump logic, whose muxes affect the Feistel critical path.")
    parser.add_argument("--no-cmp",       action="store_true",       help="Omit the per-core comparator. Every candidate then returns to the host.")
    parser.add_argument("--din-bits",     type=int,   default=BOARD_SHAPE["din_bits"],     help="Feeder-to-core bus width, 8 or 32 bits.")
    parser.add_argument("--feed-group",   type=int,   default=BOARD_SHAPE["feed_group"],   help="Cores per feeder fanout group. Zero means no fanout pipeline.")
    parser.add_argument("--feed-shard",   type=int,   default=BOARD_SHAPE["feed_shard"],   help="Cores per feeder engine. Must be a multiple of --feed-group. Zero uses one engine.")
    parser.add_argument("--collect-group", type=int,  default=BOARD_SHAPE["collect_group"], help="Cores per collector engine. Zero uses one engine over the whole array.")
    parser.add_argument("--num-cores-dist", type=int, default=BOARD_SHAPE["num_cores_dist"], help="Cores whose S-boxes use distributed RAM. Zero uses block RAM for every core.")
    parser.add_argument("--init-batch",   type=int,   default=BOARD_SHAPE["init_batch"],   help="Ready cores required to start an initialization broadcast. Zero starts immediately.")
    parser.add_argument("--sys-clk-freq", type=float, default=200e6, help="System clock (Hz).")
    parser.add_argument("--abi",          type=int,   default=fpga_abi_current(), help="Wire ABI version, stamped into the bitstream identity and refused by the bridge when it does not match.")
    parser.add_argument("--cslow",        type=int,   default=BOARD_SHAPE["cslow"], choices=[1, 2], help="2 builds the array from two hash cores on a second clock at twice --sys-clk-freq. --cores then counts virtual cores.")
    parser.add_argument("--pcie-speed",   type=str,   default="gen2", choices=["gen1", "gen2", "gen3"], help="PCIe link rate.")
    parser.add_argument("--pcie-lanes",   type=int,   default=8, choices=[1, 2, 4, 8], help="PCIe link width. The edge is x16, and a narrower endpoint negotiates down in an x16 slot.")
    parser.add_argument("--placement-margin", type=float, default=PLACEMENT_MARGIN, help="Extra ns of setup clock uncertainty on sys_clk to over-constrain placement.")
    parser.add_argument("--fitter-seed",  type=int, default=None, help="Quartus fitter seed. Different seeds give different placements and a spread of Fmax.")
    parser.add_argument("--threads",      type=int,   default=None, help="Same as --num-processors, the name src/fpga/Makefile passes.")
    parser.add_argument("--num-processors", type=int, default=None, help="Cap Quartus parallel processors, so several builds can share a machine.")
    args = parser.parse_args()

    mhz  = clock_mhz(args.sys_clk_freq)

    fg_suffix = "" if args.feed_group == 0 else f"_fg{args.feed_group}"

    nd_suffix = "_nodump" if args.no_dump == True else ""
    nc_suffix = "_nocmp"  if args.no_cmp  == True else ""

    db_suffix = "" if args.din_bits == 8 else f"_din{args.din_bits}"

    fs_suffix = "" if args.feed_shard    == 0 else f"_fs{args.feed_shard}"
    cg_suffix = "" if args.collect_group  == 0 else f"_cg{args.collect_group}"
    ds_suffix = "" if args.num_cores_dist == 0 else f"_d{args.num_cores_dist}"
    ib_suffix = "" if args.init_batch     == 0 else f"_ib{args.init_batch}"

    cs_suffix = "_cs2" if args.cslow == 2 else ""

    link_suffix = "" if (args.pcie_speed, args.pcie_lanes) == ("gen2", 8) else f"_{args.pcie_speed}x{args.pcie_lanes}"

    name = f"bcrypt_{BOARD}_dma_c{args.cores}_{mhz}mhz{fg_suffix}{nd_suffix}{nc_suffix}{db_suffix}{ds_suffix}{fs_suffix}{cg_suffix}{ib_suffix}{cs_suffix}{link_suffix}"

    soc = BcryptSoC(
        sys_clk_freq     = args.sys_clk_freq,
        num_cores        = args.cores,
        feed_group       = args.feed_group,
        feed_shard       = args.feed_shard,
        with_dump        = 0 if args.no_dump else 1,
        with_cmp         = 0 if args.no_cmp  else 1,
        din_bits         = args.din_bits,
        collect_group    = args.collect_group,
        num_cores_dist   = args.num_cores_dist,
        init_batch       = args.init_batch,
        abi              = args.abi,
        cslow            = args.cslow,
        pcie_speed       = args.pcie_speed,
        pcie_lanes       = args.pcie_lanes,
        placement_margin = args.placement_margin,
    )

    # In picoseconds: Quartus takes everything after a dot in a revision name for an extension.
    if args.placement_margin != PLACEMENT_MARGIN:
        name += f"_m{round(args.placement_margin * 1000)}"

    if args.fitter_seed is not None:
        soc.platform.toolchain.additional_qsf_commands += [f"set_global_assignment -name SEED {args.fitter_seed}"]
        name += f"_s{args.fitter_seed}"

    if args.num_processors is None:
        args.num_processors = args.threads

    if args.num_processors is not None:
        soc.platform.toolchain.additional_qsf_commands += [f"set_global_assignment -name NUM_PARALLEL_PROCESSORS {args.num_processors}"]

    output_dir = os.path.join("build", name)

    builder = Builder(soc, output_dir=output_dir)

    # Stratix 10 is Quartus Prime Pro only, whose synthesis and conversion tools have other names.
    builder.build(build_name=name, run=args.build, synth_tool="quartus_syn", conv_tool="quartus_pfg")

    hdr_dir = os.path.join("software", "kernel", BOARD)

    os.makedirs(hdr_dir, exist_ok=True)
    generate_litepcie_software_headers(soc, hdr_dir)

    if args.load:
        prog = soc.platform.create_programmer()

        # The card's own JTAG adapter goes through a Quartus JTAG server driver of its own, under a
        # cable name jtagconfig lists.
        cable = os.environ.get("HCFPGA_CABLE")

        if cable:
            prog.cable_name = cable
            print(f"  using JTAG cable {cable} from HCFPGA_CABLE")

        prog.load_bitstream(builder.get_bitstream_filename(mode="sram"))

if __name__ == "__main__":
    main()
