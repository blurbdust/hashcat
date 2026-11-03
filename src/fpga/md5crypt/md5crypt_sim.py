#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

# md5crypt on a simulated LiteX board: Verilator, reached by hashcat's litexbone transport.
#
# The md5crypt wrapper sits behind HcfpgaMemStream, two rings in CSR space that stand in for
# LitePCIe's DMA, and the host reaches everything over Etherbone (UDP on a tap interface) or
# UARTBone (TCP to LiteX's serial2tcp sim module). The identity names board "sim", so hashcat
# drives it like any LiteX board listed in HCFPGA_LITEXBONE.
#
# HcfpgaMemStream and the CSR locations hashcat expects come from the LiteX hashcat Guide
# (gateware/hcfpga_memstream.py, gateware/hcfpga_csr.py), found with --guide.
#
#   ./md5crypt_sim.py --bridge uartbone --build-only
#   ./md5crypt_sim.py --bridge uartbone --no-build &
#   HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 90500 hash.txt words.txt

import os
import sys
import argparse
import datetime
import importlib.util
import subprocess

sys.dont_write_bytecode = True

from migen import *

from litex.gen import *

from litex.build.io               import CRG
from litex.build.generic_platform import *
from litex.build.sim              import SimPlatform
from litex.build.sim.config       import SimConfig
from litex.build.sim.verilator    import verilator_build_args, verilator_build_argdict

from litex.soc.integration.soc_core import SoCMini
from litex.soc.integration.builder  import Builder

HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)

from gateware.md5crypt_dma_wrapper import Md5cryptDmaWrapper

from hcfpga_abi import fpga_abi_current

ALGO  = "md5crypt"
BOARD = "sim"

SIM_IP    = "192.168.9.50"
HOST_IP   = "192.168.9.100"
UART_PORT = 2430

DEFAULT_GUIDE = os.environ.get("HCFPGA_GUIDE",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(HERE)))), "litex_hashcat_guide"))

# IOs ----------------------------------------------------------------------------------------------

_io = [
    ("sys_clk", 0, Pins(1)),
    ("sys_rst", 0, Pins(1)),

    # Etherbone, through LiteX's ethernet sim module (tap interface).
    ("eth_clocks", 0,
        Subsignal("tx", Pins(1)),
        Subsignal("rx", Pins(1)),
    ),
    ("eth", 0,
        Subsignal("source_valid", Pins(1)),
        Subsignal("source_ready", Pins(1)),
        Subsignal("source_data",  Pins(8)),
        Subsignal("sink_valid",   Pins(1)),
        Subsignal("sink_ready",   Pins(1)),
        Subsignal("sink_data",    Pins(8)),
    ),

    # UARTBone, through LiteX's serial2tcp sim module.
    ("serial", 0,
        Subsignal("source_valid", Pins(1)),
        Subsignal("source_ready", Pins(1)),
        Subsignal("source_data",  Pins(8)),
        Subsignal("sink_valid",   Pins(1)),
        Subsignal("sink_ready",   Pins(1)),
        Subsignal("sink_data",    Pins(8)),
    ),
]

class Platform(SimPlatform):
    def __init__(self):
        SimPlatform.__init__(self, "SIM", _io)

# Guide --------------------------------------------------------------------------------------------

def load_guide(guide_dir):
    """HcfpgaMemStream and the CSR locations, from the LiteX hashcat Guide checkout."""
    if not os.path.isfile(os.path.join(guide_dir, "gateware", "hcfpga_memstream.py")):
        raise SystemExit(f"No LiteX hashcat Guide at {guide_dir}. Pass --guide <path> or set HCFPGA_GUIDE.")
    # By path: both trees have a gateware/ directory, so a package import would pick the wrong one.
    def load(name):
        spec = importlib.util.spec_from_file_location(name, os.path.join(guide_dir, "gateware", name + ".py"))
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    memstream = load("hcfpga_memstream")
    csr       = load("hcfpga_csr")
    return memstream.HcfpgaMemStream, csr.HCFPGA_CSR_LOCATIONS, csr.EXTRA_FIRST

def csr_locations(guide_locations):
    """The guide's map names the algorithm bank 'bcrypt'. The bank at 0 is the algorithm's, whatever it is called."""
    locs = {}
    for name, n in guide_locations.items():
        locs[ALGO if n == 0 else name] = n
    return locs

# Simulation SoC -----------------------------------------------------------------------------------

class SimSoC(SoCMini):
    def __init__(self, HcfpgaMemStream, locations, extra_first, bridge="uartbone", num_units=1,
        with_cmp=1, h2c_depth=512, c2h_depth=512):
        sys_clk_freq = int(1e6)

        platform = Platform()
        self.comb += platform.trace.eq(1)

        cores = num_units * 3

        # The identity every hcfpga board reports. clk is the declared 1 MHz, which is about what
        # Verilator manages for one unit; hashcat only uses it for its timeouts.
        stamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = f"hcfpga/1;board={BOARD};algo={ALGO};cores={cores};clk=1;abi={fpga_abi_current()};build={stamp}",
            ident_version = False,
        )

        # hashcat hardcodes the algorithm bank at 0x0000, ctrl at 0x0800, identifier_mem at 0x1000
        # and memstream at 0xc000. Pin those, and what this sim adds above them.
        for name, n in locations.items():
            self.csr.add(name, n=n)
        self.csr.add("ethphy", n=extra_first)
        self.csr_locations = locations
        self.csr_extra_first = extra_first

        self.crg = CRG(platform.request("sys_clk"))

        if bridge == "etherbone":
            from liteeth.phy.model import LiteEthPHYModel
            self.ethphy = LiteEthPHYModel(platform.request("eth"))
            self.add_etherbone(phy=self.ethphy,
                ip_address  = SIM_IP,
                mac_address = 0x10e2d5000001,
            )
        else:
            from litex.soc.cores.uart import RS232PHYModel, UARTBone
            self.uartbone_phy = RS232PHYModel(platform.request("serial"))
            self.uartbone     = UARTBone(
                phy           = self.uartbone_phy,
                clk_freq      = sys_clk_freq,
                address_width = self.bus.address_width,
            )
            self.bus.add_master(name="uartbone", master=self.uartbone.wishbone)

        # md5crypt datapath --------------------------------------------------------------------
        self.md5crypt = Md5cryptDmaWrapper(platform,
            num_units      = num_units,
            cores_per_unit = 3,
            with_cmp       = with_cmp,
        )
        self.md5crypt.add_hdl_sources()

        # Memstream: the rings stand in for LitePCIe's DMA ---------------------------------------
        self.memstream = HcfpgaMemStream(h2c_depth=h2c_depth, c2h_depth=c2h_depth)
        self.comb += [
            self.memstream.source.connect(self.md5crypt.sink),
            self.md5crypt.source.connect(self.memstream.sink),
        ]

def check_csrs(soc):
    locs = soc.csr.locs
    bad  = []
    for name, n in soc.csr_locations.items():
        if locs.get(name) != n:
            bad.append(f"{name} at {locs.get(name)}, wants {n}")
    for name, n in locs.items():
        if (name not in soc.csr_locations) and (n < soc.csr_extra_first):
            bad.append(f"{name} at {n}, below {soc.csr_extra_first}")
    if bad:
        raise SystemExit("CSR map does not match what hashcat's bridge expects:\n  " + "\n  ".join(bad))

# Build / Run --------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="hashcat FPGA md5crypt on a simulated LiteX board.")
    parser.add_argument("--bridge",     default="uartbone", choices=["etherbone", "uartbone"],
        help=f"Host bridge. uartbone: HCFPGA_LITEXBONE=tcp:127.0.0.1:{UART_PORT} (no privileges). "
             f"etherbone: HCFPGA_LITEXBONE=udp:{SIM_IP} (needs a tap, run under the guide's debug/simns.sh).")
    parser.add_argument("--units",      type=int, default=1,   help="Computing units, 3 MD5 cores and 12 candidates in flight each.")
    parser.add_argument("--no-cmp",     action="store_true",   help="Build without the comparator: every result returns.")
    parser.add_argument("--h2c-depth",  type=int, default=512, help="H2C ring size in 32-bit words.")
    parser.add_argument("--c2h-depth",  type=int, default=512, help="C2H ring size in 32-bit words.")
    parser.add_argument("--guide",      default=DEFAULT_GUIDE, help="LiteX hashcat Guide checkout providing HcfpgaMemStream.")
    parser.add_argument("--output-dir", default=None,          help="Build directory (default: build/sim_<bridge> here).")
    parser.add_argument("--no-build",   action="store_true",   help="Rerun the existing simulator without regenerating it.")
    parser.add_argument("--build-only", action="store_true",   help="Build the simulator, do not run it.")
    parser.add_argument("--debug",      action="store_true",   help="Print every H2C word and C2H byte from the simulator.")
    verilator_build_args(parser)
    args = parser.parse_args()

    output_dir = os.path.abspath(args.output_dir or os.path.join(HERE, "build", f"sim_{args.bridge}"))
    gateware   = os.path.join(output_dir, "gateware")

    if not args.no_build:
        HcfpgaMemStream, guide_locations, extra_first = load_guide(os.path.abspath(args.guide))

        soc = SimSoC(HcfpgaMemStream, csr_locations(guide_locations), extra_first,
            bridge    = args.bridge,
            num_units = args.units,
            with_cmp  = 0 if args.no_cmp else 1,
            h2c_depth = args.h2c_depth,
            c2h_depth = args.c2h_depth,
        )
        if args.debug:
            cycle = Signal(64)
            soc.sync += [
                cycle.eq(cycle + 1),
                If(soc.md5crypt.sink.valid & soc.md5crypt.sink.ready,
                    Display("[%0d] H2C %08x last=%d", cycle, soc.md5crypt.sink.data, soc.md5crypt.sink.last)),
                If(soc.md5crypt.source.valid & soc.md5crypt.source.ready,
                    Display("[%0d] C2H %02x last=%d", cycle, soc.md5crypt.source.data, soc.md5crypt.source.last)),
            ]

        soc.finalize()
        check_csrs(soc)

        sim_config = SimConfig()
        sim_config.add_clocker("sys_clk", freq_hz=int(1e6))
        if args.bridge == "etherbone":
            sim_config.add_module("ethernet", "eth", args={"interface": "tap0", "ip": HOST_IP})
        else:
            sim_config.add_module("serial2tcp", "serial", args={"port": UART_PORT})

        # run=False: LiteX would wrap the run in sudo whenever the ethernet module is present.
        builder = Builder(soc, output_dir=output_dir, csr_csv=os.path.join(output_dir, "csr.csv"))
        builder.build(sim_config=sim_config, run=False, **verilator_build_argdict(args))

        log = os.path.join(gateware, "verilator.log")
        print(f"[> Compiling the simulator (log: {log})")
        with open(log, "w") as f:
            r = subprocess.run(["bash", "build_sim.sh"], cwd=gateware, stdout=f, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            os.system(f"tail -30 {log}")
            raise SystemExit("Verilator build failed.")

    vsim = os.path.join(gateware, "obj_dir", "Vsim")
    if not os.path.isfile(vsim):
        raise SystemExit(f"No simulator at {vsim}. Build it first (drop --no-build).")
    if args.build_only:
        print(f"[> Built {vsim}")
        return

    if args.bridge == "etherbone":
        print(f"[> Simulator up next. hashcat: HCFPGA_LITEXBONE=udp:{SIM_IP}")
    else:
        print(f"[> Simulator up next. hashcat: HCFPGA_LITEXBONE=tcp:127.0.0.1:{UART_PORT}")
    print(f"[> CSR map: {os.path.join(output_dir, 'csr.csv')}")
    sys.stdout.flush()

    os.chdir(gateware)
    os.execvp("obj_dir/Vsim", ["obj_dir/Vsim"])

if __name__ == "__main__":
    main()
