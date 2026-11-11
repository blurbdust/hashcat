#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# This algorithm on a Microsoft Storey Peak (Stratix V 5SGSMD5), over PCIe with LitePCIe's DMA, the
# way bcrypt's bcrypt_storeypeak_dma.py builds it. The algorithm is the directory this file is in,
# src/fpga/<algo>/, and its wrapper is gateware/<algo>_dma_wrapper.py.
#
#   python3 <algo>_storeypeak_dma.py --units <n> --sys-clk-freq <hz> --build
#
# Edge lanes 0-7 reach pcie_x8 connector 0, whose hard IP block Quartus reports as disabled for this
# part. The LiteX-Boards platform makes Quartus place it when a design uses that connector.

import os
import sys
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

from litex_boards.platforms import microsoft_storey_peak

from litex.soc.interconnect         import stream
from litex.soc.integration.soc_core import SoCMini
from litex.soc.integration.builder  import Builder

from litex.soc.cores.clock.intel_stratix5 import StratixVPLL
from litex.soc.cores.led import LedChaser

from litepcie.phy.svpciephy import SVPCIEPHY
from litepcie.software      import generate_litepcie_software_headers

from hcfpga_abi         import fpga_abi_current
from hcfpga_dma_wrapper import HcfpgaDmaWrapper
from hcfpga_jtaglink    import JTAGLink, connect_engine
from hcfpga_litepcie    import PCIE_CLASS_CODE, clock_mhz
from hcfpga_stratixv    import StratixVTemperature, StratixVChipID, sv_pcie_endpoint_params

BOARD = "storeypeak"

PCIE_MGMT_FREQ = 50e6

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
    def __init__(self, platform, sys_clk_freq):
        self.rst          = Signal()
        self.cd_sys       = ClockDomain()
        self.cd_pcie_mgmt = ClockDomain()

        # 125 MHz from the onboard clock generator. The card has no reset input, so the PLL lock is
        # the reset.
        clk125 = platform.request("clk125")

        # The transceiver reconfiguration controller needs a free running management clock.
        self.pll = pll = StratixVPLL(speedgrade="-C1")
        self.comb += pll.reset.eq(self.rst)
        pll.register_clkin(clk125, 125e6)
        pll.create_clkout(self.cd_sys,       sys_clk_freq)
        pll.create_clkout(self.cd_pcie_mgmt, PCIE_MGMT_FREQ)

        platform.toolchain.additional_sdc_commands += [
            "set_false_path -from [get_clocks sys_clk] -to [get_clocks clk125]",
            "set_false_path -from [get_clocks clk125] -to [get_clocks sys_clk]",
            "set_false_path -from [get_clocks sys_clk] -to [get_clocks {*|clk[1]}]",
            "set_false_path -from [get_clocks {*|clk[1]}] -to [get_clocks sys_clk]",
        ]

class StoreyPeakSoC(SoCMini):
    def __init__(self, Wrapper, sys_clk_freq=100e6, units=1, with_cmp=1, placement_margin=0.0, with_jtaglink=False):
        platform = microsoft_storey_peak.Platform()

        self.crg = _CRG(platform, sys_clk_freq)

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

        self.pcie_phy = SVPCIEPHY(platform, platform.request("pcie_x8", 0),
            data_width    = 128,
            speed         = "gen2",
            nlanes        = 8,
            bar0_size     = 0x10_0000,
            class_code    = PCIE_CLASS_CODE << 8,
            mgmt_clk      = self.crg.cd_pcie_mgmt.clk,
            mgmt_rst      = self.crg.cd_pcie_mgmt.rst,
            mgmt_clk_name = "pcie_mgmt_clk",
        )
        self.pcie_phy.hip_params.update(sv_pcie_endpoint_params("gen2", 8, 128))

        self.add_pcie(phy=self.pcie_phy, ndmas=1, address_width=64)

        platform.toolchain.additional_qsf_commands += [
            "set_global_assignment -name OPTIMIZE_POWER_DURING_SYNTHESIS OFF",
            "set_global_assignment -name OPTIMIZE_POWER_DURING_FITTING OFF",
            "set_global_assignment -name OPTIMIZATION_TECHNIQUE SPEED",
            "set_global_assignment -name OPTIMIZATION_MODE \"AGGRESSIVE PERFORMANCE\"",
            "set_global_assignment -name STRATIXV_CONFIGURATION_SCHEME \"ACTIVE SERIAL X4\"",
            "set_global_assignment -name USE_CONFIGURATION_DEVICE ON",
            "set_global_assignment -name STRATIX_CONFIGURATION_DEVICE EPCQ256",
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

        self.xadc = StratixVTemperature(platform, cd="pcie_mgmt", clk_freq=PCIE_MGMT_FREQ)
        self.dna  = StratixVChipID(platform, cd="pcie_mgmt")

        setattr(self, ALGO, wrapper)
        wrapper.add_hdl_sources()

        dw = self.pcie_dma0.data_width

        self.dma_down = stream.Converter(dw, 32, reverse=False)
        self.comb += self.pcie_dma0.source.connect(self.dma_down.sink)

        self.dma_up = stream.Converter(8, dw, reverse=False)
        self.comb += self.dma_up.source.connect(self.pcie_dma0.sink)

        if with_jtaglink:
            # The same engine over the card's JTAG, for slots where the PCIe link does not come up.
            self.jtaglink = JTAGLink(platform, csr_base=self.mem_map.get("csr", 0))
            self.jtaglink.add_timing_constraints(platform)
            self.bus.add_master(name="jtaglink", master=self.jtaglink.bus)
            connect_engine(self, self.jtaglink, self.dma_down.source, self.dma_up.sink, wrapper)
        else:
            self.comb += [
                self.dma_down.source.connect(wrapper.sink),
                wrapper.source.connect(self.dma_up.sink),
            ]

UNITS            = 1
SYS_CLK_FREQ     = 100e6
PLACEMENT_MARGIN = 0.0

def main():
    Wrapper = load_wrapper()

    parser = argparse.ArgumentParser(description=f"hcfpga {ALGO} on a Microsoft Storey Peak (Stratix V).")
    parser.add_argument("--build",            action="store_true", help="Build the bitstream.")
    parser.add_argument("--load",             action="store_true", help="Load the bitstream over the card's own JTAG.")
    parser.add_argument("--units",            type=int,   default=UNITS, help=f"Computing units: {getattr(Wrapper, 'SIM_UNITS_HELP', 'see the wrapper')}.")
    parser.add_argument("--no-cmp",           action="store_true",       help="Omit the on-device comparator. Every candidate then returns to the host.")
    parser.add_argument("--sys-clk-freq",     type=float, default=SYS_CLK_FREQ, help="System clock (Hz).")
    parser.add_argument("--placement-margin", type=float, default=PLACEMENT_MARGIN, help="Extra ns of setup clock uncertainty on sys_clk to over-constrain placement.")
    parser.add_argument("--fitter-seed",      type=int,   default=None,  help="Quartus fitter seed.")
    parser.add_argument("--threads",          type=int,   default=None,  help="Cap Quartus parallel processors.")
    parser.add_argument("--jtaglink",         action="store_true", help="Also reach the engine over the card's JTAG, for slots where PCIe does not come up.")
    args = parser.parse_args()

    soc = StoreyPeakSoC(Wrapper,
        sys_clk_freq     = args.sys_clk_freq,
        units            = args.units,
        with_cmp         = 0 if args.no_cmp else 1,
        placement_margin = args.placement_margin,
        with_jtaglink    = args.jtaglink,
    )

    name = f"{ALGO}_{BOARD}_dma_u{args.units}_{clock_mhz(args.sys_clk_freq)}mhz" + ("_nocmp" if args.no_cmp else "") + ("_jtag" if args.jtaglink else "")

    if args.fitter_seed is not None:
        soc.platform.toolchain.additional_qsf_commands += [f"set_global_assignment -name SEED {args.fitter_seed}"]
        name += f"_s{args.fitter_seed}"

    if args.threads is not None:
        soc.platform.toolchain.additional_qsf_commands += [f"set_global_assignment -name NUM_PARALLEL_PROCESSORS {args.threads}"]

    output_dir = os.path.join("build", name)

    builder = Builder(soc, output_dir=output_dir)

    builder.build(build_name=name, run=args.build)

    hdr_dir = os.path.join(output_dir, "driver")
    os.makedirs(hdr_dir, exist_ok=True)
    generate_litepcie_software_headers(soc, hdr_dir)

    if args.load:
        prog = soc.platform.create_programmer()
        prog.load_bitstream(builder.get_bitstream_filename(mode="sram"))

if __name__ == "__main__":
    main()
