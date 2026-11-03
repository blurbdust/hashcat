#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

import os
import shutil
import argparse
import datetime
import subprocess

from migen import *

from litex.gen import *

from litex_boards.platforms import microsoft_storey_peak

from litex.soc.interconnect     import stream
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *

from litex.soc.cores.clock.intel_stratix5 import StratixVPLL
from litex.soc.cores.led import LedChaser

from litepcie.phy.svpciephy import SVPCIEPHY
from litepcie.software      import generate_litepcie_software_headers

from gateware.bcrypt_dma_wrapper import BcryptDmaWrapper

from hcfpga_abi import fpga_abi_current
from hcfpga_litepcie import PCIE_CLASS_CODE, clock_mhz
from hcfpga_stratixv import StratixVTemperature, StratixVChipID, sv_pcie_endpoint_params, sv_flash_image, sv_flash_command

BOARD = "storeypeak"

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

# The Storey Peak is a Microsoft Catapult v2 card, X930613-001, Stratix V GS 5SGSMD5. Edge lanes 0-7
# reach pcie_x8 connector 0, whose hard IP block Quartus reports as disabled for this part and
# refuses to place, so the build preloads sv_pcie_hip_enable.c to answer "enabled" for that block.

PCIE_MGMT_FREQ = 50e6

AS_CLOCKS = {12.5: "FREQ_12_5MHZ", 25: "FREQ_25MHZ", 50: "FREQ_50MHZ", 100: "FREQ_100MHZ"}

class _CRG(LiteXModule):
    def __init__(self, platform, sys_clk_freq, cslow=1):
        self.rst          = Signal()
        self.cd_sys       = ClockDomain()
        self.cd_pcie_mgmt = ClockDomain()

        # 125 MHz from the onboard clock generator. The card has no reset input, so the PLL lock is
        # the reset.
        clk125 = platform.request("clk125")

        # The transceiver reconfiguration controller needs a free running management clock. At
        # 50 MHz it shares the VCO with sys_clk on exact ratios, where 100 MHz forces awkward ones.
        self.pll = pll = StratixVPLL(speedgrade="-C1")
        self.comb += pll.reset.eq(self.rst)
        pll.register_clkin(clk125, 125e6)
        pll.create_clkout(self.cd_sys,       sys_clk_freq)
        pll.create_clkout(self.cd_pcie_mgmt, PCIE_MGMT_FREQ)

        if cslow == 2:
            self.cd_core = ClockDomain()
            pll.create_clkout(self.cd_core, 2 * sys_clk_freq)

        # Only the SoC reset reaching the PLL reset crosses from sys to clk125, asynchronous by
        # construction.
        platform.toolchain.additional_sdc_commands += [
            "set_false_path -from [get_clocks sys_clk] -to [get_clocks clk125]",
            "set_false_path -from [get_clocks clk125] -to [get_clocks sys_clk]",
        ]

class BcryptSoC(SoCMini):
    def __init__(self, sys_clk_freq=150e6, num_cores=1, with_led=True, feed_group=0, feed_shard=0, collect_group=0, init_batch=0, num_cores_dist=0, with_dump=1, with_cmp=1, din_bits=32, abi=1, cslow=1, pcie_connector=0, placement_margin=0.0, as_clock_mhz=100):
        platform = microsoft_storey_peak.Platform()

        self.crg = _CRG(platform, sys_clk_freq, cslow)

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

        self.pcie_phy = SVPCIEPHY(platform, platform.request("pcie_x8", pcie_connector),
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

        # Quartus enables power optimisation by default and puts ALMs on the critical path into
        # Low Power mode, which is slower. Speed is the right trade here.
        platform.toolchain.additional_qsf_commands += [
            "set_global_assignment -name OPTIMIZE_POWER_DURING_SYNTHESIS OFF",
            "set_global_assignment -name OPTIMIZE_POWER_DURING_FITTING OFF",
            "set_global_assignment -name OPTIMIZATION_TECHNIQUE SPEED",
            "set_global_assignment -name OPTIMIZATION_MODE \"AGGRESSIVE PERFORMANCE\"",
        ]

        # The card boots from its N25Q256A in Active Serial x4. Declaring that, rather than Quartus'
        # passive-serial default, puts the right scheme in the flash image header. The AS clock sets how
        # long configuration takes after power-on, which is time the PCIe endpoint does not exist: the
        # factory image reads at 25 MHz, 100 MHz loads a full image in about a quarter of a second.
        platform.toolchain.additional_qsf_commands += [
            "set_global_assignment -name STRATIXV_CONFIGURATION_SCHEME \"ACTIVE SERIAL X4\"",
            "set_global_assignment -name USE_CONFIGURATION_DEVICE ON",
            "set_global_assignment -name STRATIX_CONFIGURATION_DEVICE EPCQ256",
            f"set_global_assignment -name ACTIVE_SERIAL_CLOCK {AS_CLOCKS[as_clock_mhz]}",
        ]

        # Extra setup uncertainty squeezes placement. Quartus places and routes in one run and the PLL
        # output is the real clock, so this cannot be removed before routing as on Vivado.
        if placement_margin:
            platform.toolchain.additional_sdc_commands += [
                f"set_clock_uncertainty -add -setup -from [get_clocks sys_clk] -to [get_clocks sys_clk] {placement_margin:.3f}",
            ]

        if with_led:
            self.leds = LedChaser(pads=platform.request_all("user_led"), sys_clk_freq=sys_clk_freq)

        self.xadc = StratixVTemperature(platform, cd="pcie_mgmt", clk_freq=PCIE_MGMT_FREQ)
        self.dna  = StratixVChipID(platform, cd="pcie_mgmt")

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

def build_pcie_hip_shim(output_dir):
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quartus", "sv_pcie_hip_enable.c")

    # Absolute, because LiteX's build script changes into the gateware directory before it starts
    # Quartus, and ld.so resolves LD_PRELOAD against the working directory.
    so = os.path.abspath(os.path.join(output_dir, "sv_pcie_hip_enable.so"))

    os.makedirs(output_dir, exist_ok=True)

    if os.path.exists(so) and os.path.getmtime(so) >= os.path.getmtime(src):
        return so

    cc = os.environ.get("CC", "gcc")

    if shutil.which(cc) is None:
        raise SystemExit(f"Connector 0 needs the PCIe hard IP interposer, which needs {cc} to build.")

    cmd = [cc, "-shared", "-fPIC", "-O2", "-o", so, src, "-ldl"]

    if subprocess.call(cmd) != 0:
        raise SystemExit("Failed to build the PCIe hard IP interposer: " + " ".join(cmd))

    return so

def preload_pcie_hip_shim(so):
    # LiteX's Quartus backend starts the tools without its own env=, so they inherit this one.
    quartus_lib = os.path.join(os.path.dirname(os.path.dirname(shutil.which("quartus_sh") or "")), "linux64")

    os.environ["LD_PRELOAD"]      = so
    os.environ["LD_LIBRARY_PATH"] = os.pathsep.join([p for p in [quartus_lib, os.environ.get("LD_LIBRARY_PATH", "")] if p])

def main():
    parser = argparse.ArgumentParser(description="hcfpga bcrypt on a Microsoft Storey Peak (Stratix V).")
    parser.add_argument("--build", action="store_true", help="Build the bitstream.")
    parser.add_argument("--load",  action="store_true", help="Load the bitstream over the card's own JTAG.")
    parser.add_argument("--rpd",   action="store_true", help="Convert the built .sof into a compressed AS x4 flash image (.rpd). Needs quartus_cpf, no license.")
    parser.add_argument("--flash", action="store_true", help="Write the flash image over the card's own JTAG. Implies --rpd. Needs an openFPGALoader that honours OFL_SPI_4BYTE.")
    parser.add_argument("--cores",        type=int,   default=1,     help="Number of bcrypt cores.")
    parser.add_argument("--no-dump",      action="store_true",       help="Omit the unfinished S state dump logic, whose muxes affect the Feistel critical path.")
    parser.add_argument("--no-cmp",       action="store_true",       help="Omit the per-core comparator. Every candidate then returns to the host.")
    parser.add_argument("--din-bits",     type=int,   default=BOARD_SHAPE["din_bits"],     help="Feeder-to-core bus width, 8 or 32 bits.")
    parser.add_argument("--feed-group",   type=int,   default=BOARD_SHAPE["feed_group"],   help="Cores per feeder fanout group. Zero means no fanout pipeline.")
    parser.add_argument("--feed-shard",   type=int,   default=BOARD_SHAPE["feed_shard"],   help="Cores per feeder engine. Must be a multiple of --feed-group. Zero uses one engine.")
    parser.add_argument("--collect-group", type=int,  default=BOARD_SHAPE["collect_group"], help="Cores per collector engine. Zero uses one engine over the whole array.")
    parser.add_argument("--num-cores-dist", type=int, default=BOARD_SHAPE["num_cores_dist"], help="Cores whose S-boxes use distributed RAM. Zero uses block RAM for every core.")
    parser.add_argument("--init-batch",   type=int,   default=BOARD_SHAPE["init_batch"],   help="Ready cores required to start an initialization broadcast. Zero starts immediately.")
    parser.add_argument("--sys-clk-freq", type=float, default=150e6, help="System clock (Hz).")
    parser.add_argument("--abi",          type=int,   default=fpga_abi_current(), help="Wire ABI version, stamped into the bitstream identity and refused by the bridge when it does not match.")
    parser.add_argument("--cslow",        type=int,   default=BOARD_SHAPE["cslow"], choices=[1, 2], help="2 builds the array from two hash cores on a second clock at twice --sys-clk-freq. --cores then counts virtual cores.")
    parser.add_argument("--pcie-connector", type=int, default=0, choices=[0, 1], help="Which x8 half of the edge connector. 0 carries edge lanes 0-7.")
    parser.add_argument("--placement-margin", type=float, default=0.0, help="Extra ns of setup clock uncertainty on sys_clk to over-constrain placement.")
    parser.add_argument("--pcie-shim",    default=None, help="Prebuilt sv_pcie_hip_enable.so, otherwise built from source.")
    parser.add_argument("--fitter-seed",  type=int, default=None, help="Quartus fitter seed. Different seeds give different placements and a spread of Fmax.")
    parser.add_argument("--as-clock",     type=float, default=100, choices=[12.5, 25, 50, 100], help="Active Serial clock in MHz for booting from flash. The factory image uses 25.")
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

    name = f"bcrypt_{BOARD}_dma_c{args.cores}_{mhz}mhz{fg_suffix}{nd_suffix}{nc_suffix}{db_suffix}{ds_suffix}{fs_suffix}{cg_suffix}{ib_suffix}{cs_suffix}"

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
        pcie_connector   = args.pcie_connector,
        placement_margin = args.placement_margin,
        as_clock_mhz     = args.as_clock,
    )

    if args.fitter_seed is not None:
        soc.platform.toolchain.additional_qsf_commands += [f"set_global_assignment -name SEED {args.fitter_seed}"]
        name += f"_s{args.fitter_seed}"

    if args.num_processors is None:
        args.num_processors = args.threads

    if args.num_processors is not None:
        soc.platform.toolchain.additional_qsf_commands += [f"set_global_assignment -name NUM_PARALLEL_PROCESSORS {args.num_processors}"]

    output_dir = os.path.join("build", name)

    if args.build and args.pcie_connector == 0:
        preload_pcie_hip_shim(args.pcie_shim or build_pcie_hip_shim(output_dir))

    builder = Builder(soc, output_dir=output_dir)

    builder.build(build_name=name, run=args.build)

    hdr_dir = os.path.join("software", "kernel", BOARD)

    os.makedirs(hdr_dir, exist_ok=True)
    generate_litepcie_software_headers(soc, hdr_dir)

    if args.load:
        prog = soc.platform.create_programmer()
        prog.load_bitstream(builder.get_bitstream_filename(mode="sram"))

    if args.rpd or args.flash:
        sof = os.path.join(builder.gateware_dir, name + ".sof")
        rpd = sv_flash_image(sof)
        print(f"  flash image: {rpd}")
        cmd = sv_flash_command(rpd)
        print(f"  write it with: OFL_SPI_4BYTE=1 {' '.join(cmd)}")
        if args.flash:
            subprocess.check_call(cmd, env=dict(os.environ, OFL_SPI_4BYTE="1"))

if __name__ == "__main__":
    main()
