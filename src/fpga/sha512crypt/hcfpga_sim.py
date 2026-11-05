#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# This algorithm on a simulated LiteX board: Verilator, reached by hashcat's litexbone transport.
# The algorithm is the directory this file is in, src/fpga/<algo>/.
#
# The algorithm's wrapper sits behind HcfpgaMemStream, two rings in CSR space that stand in for
# LitePCIe's DMA, and the host reaches everything over Etherbone (UDP on a tap interface) or
# UARTBone (TCP to LiteX's serial2tcp sim module). The identity names board "sim", so hashcat
# drives it like any LiteX board listed in --bridge-parameter1.
#
# The wrapper is gateware/<algo>_dma_wrapper.py, an HcfpgaDmaWrapper subclass whose for_sim()
# builds it.
#
#   src/fpga/md5crypt/hcfpga_sim.py --bridge uartbone --build-only
#   src/fpga/md5crypt/hcfpga_sim.py --bridge uartbone --no-build &
#   ./hashcat -m 75300 --bridge-parameter1 tcp:127.0.0.1:2430 hash.txt words.txt
#
# Etherbone needs a tap interface the user may open (--tap) and hashcat able to reach the board
# at its address: --bridge-parameter1 udp:192.168.9.50.
#
# The simulator is built with run=False and exec'd here: LiteX would wrap the run in sudo whenever
# the ethernet module is present, which a user namespace neither needs nor allows. Two UARTBone sims
# on one host need different --uart-port values (or separate namespaces).

import os
import sys
import argparse
import datetime
import importlib.util
import inspect
import json
import subprocess

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO = os.path.basename(HERE)

sys.path.insert(0, HERE)

from migen import *

from litex.gen import *

from litex.build.io               import CRG
from litex.build.generic_platform import *
from litex.build.sim              import SimPlatform
from litex.build.sim.config       import SimConfig
from litex.build.sim.verilator    import verilator_build_args, verilator_build_argdict

from litex.soc.integration.soc_core import SoCMini
from litex.soc.integration.builder  import Builder

from hcfpga_abi         import fpga_abi_current
from hcfpga_csr         import pin_csrs, check_csrs
from hcfpga_memstream   import HcfpgaMemStream
from hcfpga_dma_wrapper import HcfpgaDmaWrapper, check_offsets

BOARD = "sim"

SIM_IP    = "192.168.9.50"
HOST_IP   = "192.168.9.100"
UART_PORT = 2430

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

# Algorithms ---------------------------------------------------------------------------------------

def load_algo(algo):
    """The wrapper class of this algorithm, gateware/<algo>_dma_wrapper.py, loaded by path."""
    path = os.path.join(HERE, "gateware", f"{algo}_dma_wrapper.py")
    if not os.path.isfile(path):
        raise SystemExit(f"No wrapper for {algo}: {path} does not exist.")
    spec = importlib.util.spec_from_file_location(f"{algo}_dma_wrapper", path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for _, cls in inspect.getmembers(mod, inspect.isclass):
        if issubclass(cls, HcfpgaDmaWrapper) and (cls is not HcfpgaDmaWrapper) and (cls.ALGO == algo):
            return cls
    raise SystemExit(f"{path} has no HcfpgaDmaWrapper subclass with ALGO = \"{algo}\".")

# Simulation SoC -----------------------------------------------------------------------------------

class SimSoC(SoCMini):
    def __init__(self, algo, Wrapper, bridge="uartbone", units=1, with_cmp=1, h2c_depth=512, c2h_depth=512,
        ip=SIM_IP):
        sys_clk_freq = int(1e6)

        platform = Platform()
        self.comb += platform.trace.eq(1)

        wrapper = Wrapper.for_sim(platform, units, with_cmp)

        # The identity every hcfpga board reports. clk is the declared 1 MHz, about what Verilator
        # manages for a small array; hashcat only uses it for its timeouts. parts= only when a
        # candidate's result takes more than one C2H record.
        stamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        parts = getattr(wrapper, "PARTS", 1)
        parts = f";parts={parts}" if parts > 1 else ""
        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = f"hcfpga/1;board={BOARD};algo={algo};cores={wrapper.num_cores}{parts};clk=1;abi={fpga_abi_current()};build={stamp}",
            ident_version = False,
        )

        # hashcat hardcodes the algorithm bank at 0x0000, ctrl at 0x0800, identifier_mem at 0x1000
        # and memstream at 0xc000. Pin those, and what this sim adds above them.
        pin_csrs(self, algo, extra=["ethphy"])

        self.crg = CRG(platform.request("sys_clk"))

        if bridge == "etherbone":
            from liteeth.phy.model import LiteEthPHYModel
            self.ethphy = LiteEthPHYModel(platform.request("eth"))
            self.add_etherbone(phy=self.ethphy,
                ip_address  = ip,
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

        # The algorithm's datapath, as the bank named after it -----------------------------------
        setattr(self, algo, wrapper)
        wrapper.add_hdl_sources()

        # Memstream: the rings stand in for LitePCIe's DMA ---------------------------------------
        self.memstream = HcfpgaMemStream(h2c_depth=h2c_depth, c2h_depth=c2h_depth)
        self.comb += [
            self.memstream.source.connect(wrapper.sink),
            wrapper.source.connect(self.memstream.sink),
        ]

# Build / Run --------------------------------------------------------------------------------------

def patch_sim_config(gateware, args):
    """The simulator reads sim_config.js when it starts: apply --uart-port, --tap, --host-ip to it."""
    path = os.path.join(gateware, "sim_config.js")
    cfg  = json.load(open(path))
    port = None
    for m in cfg:
        if m.get("module") == "serial2tcp":
            if args.uart_port is not None:
                m["args"]["port"] = args.uart_port
            port = m["args"]["port"]
        if m.get("module") == "ethernet":
            if args.tap is not None:
                m["args"]["interface"] = args.tap
            if args.host_ip is not None:
                m["args"]["ip"] = args.host_ip
    with open(path, "w") as f:
        json.dump(cfg, f, indent=4)
    return port

def main():
    parser = argparse.ArgumentParser(description=f"{ALGO} on a simulated LiteX board, for hashcat's litexbone transport.")
    parser.add_argument("--bridge",     default="uartbone", choices=["etherbone", "uartbone"],
        help="Host bridge. uartbone: --bridge-parameter1 tcp:127.0.0.1:<uart-port> (no privileges). "
             f"etherbone: --bridge-parameter1 udp:<ip> (needs a tap interface).")
    parser.add_argument("--units",      type=int, default=1,   help="Computing units (see the algorithm's SIM_UNITS_HELP).")
    parser.add_argument("--no-cmp",     action="store_true",   help="Build without the comparator: every result returns.")
    parser.add_argument("--h2c-depth",  type=int, default=512, help="H2C ring size in 32-bit words.")
    parser.add_argument("--c2h-depth",  type=int, default=512, help="C2H ring size in 32-bit words.")
    parser.add_argument("--uart-port",  type=int, default=None, help=f"TCP port of the UARTBone sim, default {UART_PORT} (serial2tcp listens on all interfaces). Also applies with --no-build.")
    parser.add_argument("--ip",         default=SIM_IP,        help="Etherbone address of the simulated board (built in, so not changed by --no-build).")
    parser.add_argument("--host-ip",    default=None,          help=f"Address of the tap interface on the host side, default {HOST_IP}. Also applies with --no-build.")
    parser.add_argument("--tap",        default=None,          help="Tap interface the Etherbone sim creates, default tap0. Also applies with --no-build.")
    parser.add_argument("--output-dir", default=None,          help=f"Build directory (default: src/fpga/{ALGO}/build/sim_<bridge>).")
    parser.add_argument("--no-build",   action="store_true",   help="Rerun the existing simulator without regenerating it.")
    parser.add_argument("--build-only", action="store_true",   help="Build the simulator, do not run it.")
    parser.add_argument("--debug",      action="store_true",   help="Print every H2C word and C2H byte from the simulator.")
    verilator_build_args(parser)
    args = parser.parse_args()

    output_dir = os.path.abspath(args.output_dir or os.path.join(HERE, "build", f"sim_{args.bridge}"))
    gateware   = os.path.join(output_dir, "gateware")

    if not args.no_build:
        Wrapper = load_algo(ALGO)

        soc = SimSoC(ALGO, Wrapper,
            bridge    = args.bridge,
            units     = args.units,
            with_cmp  = 0 if args.no_cmp else 1,
            h2c_depth = args.h2c_depth,
            c2h_depth = args.c2h_depth,
            ip        = args.ip,
        )
        if args.debug:
            cycle = Signal(64)
            w     = getattr(soc, ALGO)
            soc.sync += [
                cycle.eq(cycle + 1),
                If(w.sink.valid & w.sink.ready,
                    Display("[%0d] H2C %08x last=%d", cycle, w.sink.data, w.sink.last)),
                If(w.source.valid & w.source.ready,
                    Display("[%0d] C2H %02x last=%d", cycle, w.source.data, w.source.last)),
            ]

        soc.finalize()
        check_csrs(soc, ALGO)
        check_offsets(soc, ALGO, Wrapper)

        sim_config = SimConfig()
        sim_config.add_clocker("sys_clk", freq_hz=int(1e6))
        if args.bridge == "etherbone":
            sim_config.add_module("ethernet", "eth", args={"interface": args.tap or "tap0", "ip": args.host_ip or HOST_IP})
        else:
            sim_config.add_module("serial2tcp", "serial", args={"port": args.uart_port or UART_PORT})

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

    port = patch_sim_config(gateware, args)
    if args.build_only:
        print(f"[> Built {vsim}")
        return

    if args.bridge == "etherbone":
        print(f"[> Simulator up next. hashcat: --bridge-parameter1 udp:{args.ip}")
    else:
        print(f"[> Simulator up next. hashcat: --bridge-parameter1 tcp:127.0.0.1:{port}")
    print(f"[> CSR map: {os.path.join(output_dir, 'csr.csv')}")
    sys.stdout.flush()

    os.chdir(gateware)
    os.execvp("obj_dir/Vsim", ["obj_dir/Vsim"])

if __name__ == "__main__":
    main()
