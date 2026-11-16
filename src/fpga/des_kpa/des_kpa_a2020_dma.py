#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# This algorithm on a Microsoft A-2020 (Stratix 10 GX 2800, 1SG280LN2F43E2VG), over PCIe with
# LitePCIe's DMA, the way bcrypt's bcrypt_a2020_dma.py builds it. The algorithm is the directory this
# file is in, src/fpga/<algo>/, and its wrapper is gateware/<algo>_dma_wrapper.py.
#
#   python3 <algo>_a2020_dma.py --units <n> --sys-clk-freq <hz> --build
#
# Quartus Prime Pro builds it, with a license that covers Stratix 10. Its Platform Designer tools
# (qsys/bin) generate the PCIe hard IP and the Secure Device Manager clients at elaboration.

import os
import sys
import math
import inspect
import argparse
import datetime
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO = os.path.basename(HERE)

if HERE not in sys.path:
    sys.path.insert(0, HERE)

from migen import *

from litex.gen import *

from litex_boards.platforms import microsoft_a2020
from litex_boards.targets.microsoft_a2020 import request_pcie_lanes

from litex.soc.interconnect         import stream
from litex.soc.integration.soc_core import SoCMini
from litex.soc.integration.builder  import Builder

from litex.soc.cores.clock.intel_stratix10 import Stratix10PLL
from litex.soc.cores.led import LedChaser

from litepcie.phy.s10pciephy import S10PCIEPHY
from litepcie.software       import generate_litepcie_software_headers

from hcfpga_abi         import fpga_abi_current
from hcfpga_dma_wrapper import HcfpgaDmaWrapper
from hcfpga_litepcie    import PCIE_CLASS_CODE, clock_mhz
from hcfpga_stratix10   import Stratix10SDM, Stratix10Temperature, Stratix10ChipID

BOARD = "a2020"

# The register map every LiteX PCIe board in this tree shares, so one driver and one bridge serve
# them all: the algorithm's bank at 0, then the banks the driver reads.
CSR_MAP = {
    ALGO            : 0,
    "ctrl"          : 1,
    "identifier_mem": 2,
    "leds"          : 3,
    "pcie_dma0"     : 4,
    "pcie_endpoint" : 5,
    "pcie_msi"      : 6,
    "pcie_phy"      : 7,
    "xadc"          : 8,
    "dna"           : 9,
}

# The SDM clients and their counters run on their own slow clock, away from sys_clk. It is an
# integer fraction of sys_clk at or below 100 MHz, so the PLL needs no VCO that sys_clk could only
# approximate.
MGMT_FREQ_MAX = 100e6

def mgmt_freq(sys_clk_freq):
    return sys_clk_freq / math.ceil(sys_clk_freq / MGMT_FREQ_MAX)

def load_wrapper():
    """The wrapper class of this algorithm, gateware/<algo>_dma_wrapper.py, loaded by path."""
    path = os.path.join(HERE, "gateware", f"{ALGO}_dma_wrapper.py")
    spec = importlib.util.spec_from_file_location(f"{ALGO}_dma_wrapper", path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for _, cls in inspect.getmembers(mod, inspect.isclass):
        if issubclass(cls, HcfpgaDmaWrapper) and (cls is not HcfpgaDmaWrapper) and (cls.ALGO == ALGO):
            return cls
    raise SystemExit(f"{path} has no HcfpgaDmaWrapper subclass with ALGO = \"{ALGO}\".")

class _CRG(LiteXModule):
    def __init__(self, platform, sys_clk_freq, ninit_done):
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

        # The SoC reset reaching the PLL reset is the only path from sys to clk100, and the PLL
        # lock reaching each domain's reset synchroniser the only path back. Both are asynchronous
        # by construction.
        for cd in [self.cd_sys, self.cd_mgmt]:
            platform.add_false_path_constraints(cd.clk, clk100)

        # The temperature and chip ID cross from mgmt to sys through synchronisers.
        platform.toolchain.additional_sdc_commands += [
            "set_false_path -from [get_clocks {sys_clk}] -to [get_clocks {mgmt_clk}]",
            "set_false_path -from [get_clocks {mgmt_clk}] -to [get_clocks {sys_clk}]",
        ]

class A2020SoC(SoCMini):
    def __init__(self, Wrapper, sys_clk_freq=100e6, units=1, with_cmp=1, placement_margin=0.0,
        pcie_speed="gen2", pcie_lanes=8):
        platform = microsoft_a2020.Platform()

        # The SDM clients come first: the CRG needs the Reset Release IP's ninit_done.
        self.sdm = Stratix10SDM(platform, cd="mgmt")

        self.crg = _CRG(platform, sys_clk_freq, self.sdm.ninit_done)

        wrapper = Wrapper.for_sim(platform, units, with_cmp)

        stamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        parts = getattr(wrapper, "PARTS", 1)
        parts = f";parts={parts}" if parts > 1 else ""

        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = f"hcfpga/1;board={BOARD};algo={ALGO};cores={wrapper.num_cores}{parts};clk={clock_mhz(sys_clk_freq)};abi={fpga_abi_current()};build={stamp}",
            ident_version = False,
        )

        for name, n in CSR_MAP.items():
            self.csr.add(name, n=n)

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
        # reports the design's real slack.
        if placement_margin:
            platform.toolchain.additional_sdc_commands += [
                "if {$::TimeQuestInfo(nameofexecutable) eq \"quartus_fit\"} {",
                f"    set_clock_uncertainty -add -setup -from [get_clocks sys_clk] -to [get_clocks sys_clk] {placement_margin:.3f}",
                "}",
            ]

        self.leds = LedChaser(pads=platform.request_all("user_led"), sys_clk_freq=sys_clk_freq)

        self.xadc = Stratix10Temperature(self.sdm, cd="mgmt", clk_freq=mgmt_freq(sys_clk_freq))
        self.dna  = Stratix10ChipID(self.sdm, cd="mgmt", clk_freq=mgmt_freq(sys_clk_freq))

        setattr(self, ALGO, wrapper)
        wrapper.add_hdl_sources()

        # An algorithm with a thermal stop reads the die temperature.
        if hasattr(wrapper, "die_temp"):
            self.comb += wrapper.die_temp.eq(self.xadc.temperature.status)

        dw = self.pcie_dma0.data_width

        # On a full chip the datapath sits across the die from the PCIe core: a register each way
        # on valid, data and ready lets each stream cross in two steps.
        self.dma_down     = stream.Converter(dw, 32, reverse=False)
        self.dma_down_buf = stream.Buffer([("data", 32)], pipe_valid=True, pipe_ready=True)
        self.comb += [
            self.pcie_dma0.source.connect(self.dma_down.sink),
            self.dma_down.source.connect(self.dma_down_buf.sink),
            self.dma_down_buf.source.connect(wrapper.sink),
        ]

        self.dma_up     = stream.Converter(8, dw, reverse=False)
        self.dma_up_buf = stream.Buffer([("data", 8)], pipe_valid=True, pipe_ready=True)
        self.comb += [
            wrapper.source.connect(self.dma_up_buf.sink),
            self.dma_up_buf.source.connect(self.dma_up.sink),
            self.dma_up.source.connect(self.pcie_dma0.sink),
        ]

# The build that closes timing at every corner: 512 cores at 250 MHz, one key per core and clock,
# 128 G keys/s, at 76% of the ALMs. 576 cores (89%) congest the routing and fail at 240 and 280 MHz;
# past about 289 MHz LitePCIe's DMA fails first even on an empty die. Not yet run on a card.
UNITS            = 512
SYS_CLK_FREQ     = 250e6
PLACEMENT_MARGIN = 0.2

def main():
    Wrapper = load_wrapper()

    parser = argparse.ArgumentParser(description=f"hcfpga {ALGO} on a Microsoft A-2020 (Stratix 10).")
    parser.add_argument("--build",            action="store_true", help="Build the bitstream.")
    parser.add_argument("--load",             action="store_true", help="Load the bitstream over JTAG with the Quartus Programmer.")
    parser.add_argument("--units",            type=int,   default=UNITS, help=f"Computing units: {getattr(Wrapper, 'SIM_UNITS_HELP', 'see the wrapper')}.")
    parser.add_argument("--no-cmp",           action="store_true",       help="Omit the on-device comparator. Every candidate then returns to the host.")
    parser.add_argument("--sys-clk-freq",     type=float, default=SYS_CLK_FREQ, help="System clock (Hz).")
    parser.add_argument("--placement-margin", type=float, default=PLACEMENT_MARGIN, help="Extra ns of setup clock uncertainty on sys_clk to over-constrain placement.")
    parser.add_argument("--pcie-speed",       type=str,   default="gen2", choices=["gen1", "gen2", "gen3"], help="PCIe link rate.")
    parser.add_argument("--pcie-lanes",       type=int,   default=8, choices=[1, 2, 4, 8], help="PCIe link width. The edge is x16, and a narrower endpoint negotiates down in an x16 slot.")
    parser.add_argument("--fitter-seed",      type=int,   default=None,  help="Quartus fitter seed.")
    parser.add_argument("--threads",          type=int,   default=None,  help="Cap Quartus parallel processors.")
    args = parser.parse_args()

    soc = A2020SoC(Wrapper,
        sys_clk_freq     = args.sys_clk_freq,
        units            = args.units,
        with_cmp         = 0 if args.no_cmp else 1,
        placement_margin = args.placement_margin,
        pcie_speed       = args.pcie_speed,
        pcie_lanes       = args.pcie_lanes,
    )

    name = f"{ALGO}_{BOARD}_dma_u{args.units}_{clock_mhz(args.sys_clk_freq)}mhz" + ("_nocmp" if args.no_cmp else "")

    if (args.pcie_speed, args.pcie_lanes) != ("gen2", 8):
        name += f"_{args.pcie_speed}x{args.pcie_lanes}"

    # In picoseconds: Quartus takes everything after a dot in a revision name for an extension.
    if args.placement_margin != PLACEMENT_MARGIN:
        name += f"_m{round(args.placement_margin * 1000)}"

    if args.fitter_seed is not None:
        soc.platform.toolchain.additional_qsf_commands += [f"set_global_assignment -name SEED {args.fitter_seed}"]
        name += f"_s{args.fitter_seed}"

    if args.threads is not None:
        soc.platform.toolchain.additional_qsf_commands += [f"set_global_assignment -name NUM_PARALLEL_PROCESSORS {args.threads}"]

    output_dir = os.path.join("build", name)

    builder = Builder(soc, output_dir=output_dir)

    # Stratix 10 is Quartus Prime Pro only, whose synthesis and conversion tools have other names.
    builder.build(build_name=name, run=args.build, synth_tool="quartus_syn", conv_tool="quartus_pfg")

    hdr_dir = os.path.join(output_dir, "driver")
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
