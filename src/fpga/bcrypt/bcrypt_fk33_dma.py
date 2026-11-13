#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

import os
import argparse
import datetime

from migen import *

from litex.gen import *

from litex_boards.platforms import sqrl_fk33

from litex.soc.interconnect     import stream
from litex.soc.interconnect.csr import *
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *

from litex.soc.cores.clock import USPMMCM
from litex.soc.cores.dna   import XilinxDNA
from litex.soc.cores.led   import LedChaser
from litex.soc.cores.xadc  import XilinxSystemMonitor, XilinxSystemMonitorChannel

from litepcie.phy.usppciephy import USPHBMPCIEPHY
from litepcie.software       import generate_litepcie_software_headers

from gateware.bcrypt_dma_wrapper import BcryptDmaWrapper

from hcfpga_abi import fpga_abi_current
from hcfpga_litepcie import PCIE_CLASS_CODE, PCIE_CLASS_MENU_BASE, PCIE_CLASS_MENU_SUB, add_debug_jtagbone, vivado_build_args, clock_mhz

BOARD = "fk33"

BOARD_SHAPE = {
    "din_bits":       32,

    "init_batch":     0,

    "num_cores_dist": 0,

    "num_cores_uram": 160,

    "feed_group":     32,

    "feed_shard":     128,

    "collect_group":  50,

    "no_dump":        1,

    "no_cmp":         1,

    "cslow":          2,
}

# The register map that every LitePCIe board in this tree shares is the one the 7 series boards
# generate, and the driver and the tools are built against it. Three blocks differ on UltraScale+,
# so this board presents them in the 7 series shape. None of them changes what the hardware does.

# The PHY status registers. S7PCIEPHY has an MSI-X enable register the UltraScale+ PHY lacks, and its
# link status has narrower rate and width fields. MSI-X is not configured here, so it reads 0. Rate
# reads 1 for any link faster than 2.5 GT/s, and width keeps its x1 to x8 encoding.
class _PCIEPHY(USPHBMPCIEPHY):
    def __init__(self, *args, **kwargs):
        USPHBMPCIEPHY.__init__(self, *args, **kwargs)

        link = self._link_status.fields

        msi_enable        = self._msi_enable.status
        bus_master_enable = self._bus_master_enable.status
        max_request_size  = self._max_request_size.status
        max_payload_size  = self._max_payload_size.status

        self._link_status = CSRStatus(name="link_status", fields=[
            CSRField("status", size=1, values=[
                ("``0b0``", "Link Down."),
                ("``0b1``", "Link Up."),
            ]),
            CSRField("rate", size=1, values=[
                ("``0b0``", "2.5 Gb/s."),
                ("``0b1``", "5.0 Gb/s or faster."),
            ]),
            CSRField("width", size=2, values=[
                ("``0b00``", "1-Lane link."),
                ("``0b01``", "2-Lane link."),
                ("``0b10``", "4-Lane link."),
                ("``0b11``", "8-Lane link."),
            ]),
            CSRField("ltssm", size=6, description="LTSSM State"),
        ])
        self._msi_enable        = CSRStatus(name="msi_enable",        description="MSI Enable Status. ``1``: MSI is enabled.")
        self._msix_enable       = CSRStatus(name="msix_enable",       description="MSI-X Enable Status. ``1``: MSI-X is enabled.")
        self._bus_master_enable = CSRStatus(name="bus_master_enable", description="Bus Mastering Status. ``1``: Bus Mastering enabled.")
        self._max_request_size  = CSRStatus(16, name="max_request_size", description="Negotiated Max Request Size (in bytes).")
        self._max_payload_size  = CSRStatus(16, name="max_payload_size", description="Negotiated Max Payload Size (in bytes).")

        self.comb += [
            self._link_status.fields.status.eq(link.status),
            self._link_status.fields.rate.eq(link.rate != 0),
            self._link_status.fields.width.eq(link.width[:2]),
            self._link_status.fields.ltssm.eq(link.ltssm),

            self._msi_enable.status.eq(msi_enable),
            self._msix_enable.status.eq(0),
            self._bus_master_enable.status.eq(bus_master_enable),
            self._max_request_size.status.eq(max_request_size),
            self._max_payload_size.status.eq(max_payload_size),
        ]

# The system monitor. SYSMONE4 returns 16 bit codes on its own temperature scale. The registers carry
# 12 bit codes on the 7 series XADC scale, which is what the bridge and dma_ek_test convert. Supply
# codes are the top 12 bits, because both scales are 3 V full scale. Temperature is converted from
# UG580's SYSMONE4 transfer function, T = code * 507.5921310 / 65536 - 279.42657680, to the XADC code
# (T + 273.15) * 4096 / 503.975, as code * TEMP_MUL - TEMP_SUB in fixed point. The conversion is
# pipelined behind the DRP read, and a register only ever takes a converted value.
_SYSMON_CHANNELS = [
    XilinxSystemMonitorChannel(name="temperature", addr=0x0, bits=12, desc="Temperature on the 7 series XADC scale: Value x 503.975 / 4096 - 273.15."),
    XilinxSystemMonitorChannel(name="vccint",      addr=0x1, bits=12, desc="VCCINT (V) = Value x 3 / 4096."),
    XilinxSystemMonitorChannel(name="vccaux",      addr=0x2, bits=12, desc="VCCAUX (V) = Value x 3 / 4096."),
    XilinxSystemMonitorChannel(name="vccbram",     addr=0x6, bits=12, desc="VCCBRAM (V) = Value x 3 / 4096."),
]

_SYSMON_SHIFT    = 20
_SYSMON_TEMP_MUL = round((507.5921310 / 65536) * (4096 / 503.975) * (1 << _SYSMON_SHIFT))
_SYSMON_TEMP_SUB = round((279.42657680 - 273.15) * (4096 / 503.975) * (1 << _SYSMON_SHIFT))

# SYSMONE4 converts at up to 0.2 MSPS, 26 ADC clocks each, so its ADC clock must stay at or below
# 5.2 MHz. DCLK is the system clock, and INIT_42 divides it down.
_SYSMON_ADCCLK_MAX = 5e6

class _SystemMonitor(XilinxSystemMonitor):
    def __init__(self, sys_clk_freq):
        self.expose_hwmon(
            temp_scale      = 503975,
            temp_divisor    = 4096,
            temp_offset     = 273150,
            voltage_scale   = 3000,
            voltage_divisor = 4096,
        )

        for channel in _SYSMON_CHANNELS:
            self.add_channel(channel)

        self.eoc = CSRStatus(description="End of Conversion Status, ``1``: Conversion Done.")
        self.eos = CSRStatus(description="End of Sequence Status,   ``1``: Sequence Done.")

        divider = int(-(-sys_clk_freq // _SYSMON_ADCCLK_MAX))

        assert 2 <= divider <= 255

        channel = Signal(6)
        daddr   = Signal(8)
        eoc     = Signal()
        eos     = Signal()
        drdy    = Signal()
        do      = Signal(16)

        # DADDR is 8 bits wide and CHANNEL 6. Connected directly, the top two address inputs are left
        # unconnected, and on the part every read then misses the status registers and returns 0.
        self.comb += daddr.eq(channel)

        # The sequencer setup is LiteX's USSystemMonitor's, from UG580, with the clock divider above.
        self.specials += Instance("SYSMONE4",
            p_SIM_DEVICE = "ULTRASCALE_PLUS",
            p_INIT_40    = 0x9000, p_INIT_41 = 0x2fd0, p_INIT_42 = divider << 8,
            p_INIT_46    = 0x000f, p_INIT_48 = 0x4701, p_INIT_49 = 0x000f,
            p_INIT_47    = 0x000f, p_INIT_4A = 0x47e0, p_INIT_4B = 0x0000,
            p_INIT_4C    = 0x0000, p_INIT_4D = 0x0000,
            p_INIT_4E    = 0x0000, p_INIT_4F = 0x0000,
            p_INIT_50    = 0xb5ed, p_INIT_51 = 0x5999,
            p_INIT_52    = 0xa147, p_INIT_53 = 0xdddd,
            p_INIT_54    = 0xa93a, p_INIT_55 = 0x5111,
            p_INIT_56    = 0x91eb, p_INIT_57 = 0xae4e,
            p_INIT_58    = 0x5999, p_INIT_5C = 0x5111,
            o_ALM        = Signal(16),
            o_OT         = Signal(),
            o_BUSY       = Signal(),
            o_CHANNEL    = channel,
            o_EOC        = eoc,
            o_EOS        = eos,
            i_VAUXP      = 0,
            i_VAUXN      = 0,
            i_VP         = 0,
            i_VN         = 0,
            i_CONVST     = 0,
            i_CONVSTCLK  = 0,
            i_RESET      = ResetSignal("sys"),
            i_DCLK       = ClockSignal("sys"),
            i_DWE        = 0,
            i_DEN        = eoc,
            o_DRDY       = drdy,
            i_DADDR      = daddr,
            i_DI         = 0,
            o_DO         = do,
        )

        # Read each result as it completes: the address is the channel at end of conversion, the
        # code is DO at DRDY. Then multiply, then convert and write the register.
        addr    = Signal(6)
        raw     = Signal(16)
        raw_ok  = Signal()
        prod    = Signal(16 + bits_for(_SYSMON_TEMP_MUL))
        p_addr  = Signal(6)
        p_raw   = Signal(16)
        p_ok    = Signal()

        self.sync += [
            If(eoc, addr.eq(channel)),
            raw_ok.eq(drdy),
            If(drdy, raw.eq(do)),

            p_ok.eq(raw_ok),
            p_addr.eq(addr),
            p_raw.eq(raw),
            prod.eq(raw * _SYSMON_TEMP_MUL),
        ]

        temp      = Signal(len(prod))
        temp_code = Signal(12)

        self.comb += [
            temp.eq(prod - _SYSMON_TEMP_SUB),
            If(prod < _SYSMON_TEMP_SUB,
                temp_code.eq(0)
            ).Elif(temp[_SYSMON_SHIFT:] > 4095,
                temp_code.eq(4095)
            ).Else(
                temp_code.eq(temp[_SYSMON_SHIFT:])
            )
        ]

        cases = {}

        for c in _SYSMON_CHANNELS:
            if c.name == "temperature":
                cases[c.addr] = c.status.eq(temp_code)
            else:
                cases[c.addr] = c.status.eq(p_raw[4:])

        self.sync += [
            If(p_ok, Case(p_addr, cases)),

            self.eoc.status.eq((self.eoc.status & ~self.eoc.rd_stb) | eoc),
            self.eos.status.eq((self.eos.status & ~self.eos.rd_stb) | eos),
        ]

# The device DNA. DNA_PORTE2 holds 96 bits where DNA_PORT holds 57. The register keeps the 57 bit width,
# and the upper 39 bits are folded into it so that every bit still counts towards the serial.
class _DNA(XilinxDNA):
    def __init__(self, clk_divider):
        XilinxDNA.__init__(self, nbits=96, primitive="DNA_PORTE2", clk_divider=clk_divider)

        dna = self._id.status

        self._id = CSRStatus(57, name="id", description="Xilinx Device DNA identifier.")

        self.comb += self._id.status.eq(dna[:57] ^ dna[57:])

class _CRG(LiteXModule):
    def __init__(self, platform, sys_clk_freq, cslow=1):
        self.rst    = Signal()
        self.cd_sys = ClockDomain()

        self.pll = pll = USPMMCM(speedgrade=-2)
        self.comb += pll.reset.eq(self.rst)
        pll.register_clkin(platform.request("clk200"), 200e6)
        pll.create_clkout(cd=self.cd_sys, freq=sys_clk_freq)

        if cslow == 2:
            self.cd_core = ClockDomain()
            pll.create_clkout(self.cd_core, 2 * sys_clk_freq)
        else:
            platform.add_false_path_constraints(self.cd_sys.clk, pll.clkin)

class BcryptSoC(SoCMini):
    def __init__(self, sys_clk_freq=150e6, num_cores=1, startup_clock="Cclk", with_led=True, pcie_lanes=4, feed_group=0, feed_shard=0, collect_group=0, init_batch=0, num_cores_dist=0, num_cores_uram=0, with_dump=1, with_cmp=1, din_bits=32, abi=1, with_jtagbone=False, cslow=1):
        platform = sqrl_fk33.Platform()

        self.crg = _CRG(platform, sys_clk_freq, cslow)

        stamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = f"hcfpga/1;board={BOARD};algo=bcrypt;cores={num_cores};clk={int(sys_clk_freq/1e6)};abi={abi};build={stamp}",
            ident_version = False,
        )

        if with_jtagbone == True:
            add_debug_jtagbone(self, platform, self.crg.cd_sys)

        self.pcie_phy = _PCIEPHY(platform, platform.request(f"pcie_x{pcie_lanes}"),
            speed      = "gen3",
            data_width = {4: 128, 8: 256}[pcie_lanes],
            bar0_size  = 0x10_0000)
        # PF0_CLASS_CODE is derived in this IP and setting it is ignored, so the class goes in through the
        # menu parameters it is derived from.
        self.pcie_phy.update_config({
            "pf0_base_class_menu"          : PCIE_CLASS_MENU_BASE,
            "pf0_sub_class_interface_menu" : PCIE_CLASS_MENU_SUB,
            "pf0_class_code_base"          : "%02X" % ((PCIE_CLASS_CODE >> 8) & 0xff),
            "pf0_class_code_sub"           : "%02X" % ((PCIE_CLASS_CODE >> 0) & 0xff),
            "pf0_class_code_interface"     : "00",
        })
        self.add_pcie(phy=self.pcie_phy, ndmas=1, address_width=64)

        platform.add_false_path_constraints(self.crg.cd_sys.clk, self.pcie_phy.cd_pcie.clk)

        if cslow == 2:
            platform.add_false_path_constraints(self.crg.cd_core.clk, self.pcie_phy.cd_pcie.clk)

            platform.toolchain.pre_placement_commands.append("create_generated_clock -name sys_clk [get_pins MMCME4_ADV/CLKOUT0]")
            platform.toolchain.pre_placement_commands.append("create_generated_clock -name core_clk [get_pins MMCME4_ADV/CLKOUT1]")

            platform.toolchain.pre_placement_commands.append("set_false_path -from [get_clocks sys_clk] -to [get_clocks clk200_p]")
            platform.toolchain.pre_placement_commands.append("set_false_path -from [get_clocks clk200_p] -to [get_clocks sys_clk]")
        else:
            platform.add_period_constraint(self.crg.cd_sys.clk, 1e9/sys_clk_freq)

        platform.toolchain.pre_placement_commands.append("set_clock_uncertainty 0.500 [get_clocks sys_clk]")
        platform.toolchain.pre_routing_commands.append("set_clock_uncertainty 0 [get_clocks sys_clk]")

        platform.toolchain.bitstream_commands.append("set_property BITSTREAM.CONFIG.UNUSEDPIN PULLNONE [current_design]")

        if with_led:
            self.leds = LedChaser(pads=platform.request_all("user_led"), sys_clk_freq=sys_clk_freq)

        self.xadc = _SystemMonitor(sys_clk_freq)

        self.csr.add("dna", n=9)

        self.dna = _DNA(clk_divider=8)
        self.dna.add_timing_constraints(platform, sys_clk_freq, self.crg.cd_sys.clk)

        self.bcrypt = BcryptDmaWrapper(platform, num_cores=num_cores,
            num_cores_dist=num_cores_dist, num_cores_uram=num_cores_uram, din_bits=din_bits, feed_group=feed_group,
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

def make_programmer(platform):
    prog = platform.create_programmer()

    cable = os.environ.get("HCFPGA_CABLE")

    if cable:
        prog.cable = cable
        print(f"  using JTAG cable {cable} from HCFPGA_CABLE")

    return prog

def main():
    parser = argparse.ArgumentParser(description="hcfpga bcrypt on a SQRL ForestKitten 33.")
    parser.add_argument("--build", action="store_true", help="Build the bitstream.")
    parser.add_argument("--load",  action="store_true", help="Load the bitstream into SRAM over JTAG.")
    parser.add_argument("--cores",        type=int,   default=1,     help="Number of bcrypt cores.")
    parser.add_argument("--no-dump",      action="store_true",       help="Omit the unfinished S state dump logic, whose muxes affect the Feistel critical path.")
    parser.add_argument("--no-cmp",       action="store_true",       help="Omit the per-core comparator to save about 30 LUTs per core. Every candidate then returns to the host.")
    parser.add_argument("--din-bits",     type=int,   default=BOARD_SHAPE["din_bits"],     help="Feeder-to-core bus width, 8 or 32 bits. A 32-bit bus shortens initialization broadcasts.")
    parser.add_argument("--feed-group",   type=int,   default=BOARD_SHAPE["feed_group"],   help="Cores per feeder fanout group. An extra pipeline register per group splits the long broadcast route. Zero means NO fanout pipeline at all rather than one group: hcfpga_cores.v takes its nopipe branch, NBUS becomes NSH, and each core takes its feeder engine's bus directly.")
    parser.add_argument("--feed-shard",   type=int,   default=BOARD_SHAPE["feed_shard"],   help="Cores per feeder engine. Must be a multiple of --feed-group. Zero uses one engine.")
    parser.add_argument("--collect-group", type=int,  default=BOARD_SHAPE["collect_group"], help="Cores per collector engine. Zero uses one engine over the whole array.")
    parser.add_argument("--num-cores-dist", type=int, default=BOARD_SHAPE["num_cores_dist"], help="Cores whose S-boxes use distributed RAM. Zero uses block RAM for every core.")
    parser.add_argument("--num-cores-uram", type=int, default=BOARD_SHAPE["num_cores_uram"], help="Cores whose S-boxes use UltraRAM, with --cslow 2 only. A physical core takes one UltraRAM per S-box, four in all. Zero uses block RAM for every core.")
    parser.add_argument("--init-batch",   type=int,   default=BOARD_SHAPE["init_batch"],   help="Ready cores required to start an initialization broadcast. Zero starts immediately.")
    parser.add_argument("--sys-clk-freq", type=float, default=150e6, help="System clock (Hz).")
    parser.add_argument("--threads",      type=int,   default=os.cpu_count(), help="Vivado threads.")
    parser.add_argument("--with-jtagbone", action="store_true", help="Include JTAGBone for CSR access through litex_server --jtag. Excluded from published builds.")
    parser.add_argument("--place-directive", type=str, default="Explore", help="Vivado placer directive. The choice lands in the build directory name so two runs cannot overwrite each other.")
    parser.add_argument("--abi",          type=int,   default=fpga_abi_current(), help="Wire ABI version, stamped into the bitstream identity and refused by the bridge when it does not match. Read from FPGA_ABI_CURRENT in src/bridges/fpga/hcfpga.h, which the Makefile reads too, so a direct invocation builds what hashcat accepts.")
    parser.add_argument("--startup-clk",  type=str,   default="Cclk", choices=["JtagClk", "Cclk"], help="Accepted because the Makefile passes it to every board, and kept in the build name. Vivado has no BITSTREAM.STARTUP.STARTUPCLK for this device, so it changes nothing here.")
    parser.add_argument("--cslow",        type=int,   default=1, choices=[1, 2], help="2 builds the array from two hash cores on a second clock at twice --sys-clk-freq. --cores then counts virtual cores.")
    parser.add_argument("--pcie-lanes",   type=int,   default=4, choices=[4, 8], help="PCIe link width, Gen3. The card's edge is x16 and it trains whatever the slot offers up to this.")
    args = parser.parse_args()

    mhz  = clock_mhz(args.sys_clk_freq)

    fg_suffix = "" if args.feed_group == 0 else f"_fg{args.feed_group}"

    nd_suffix = "_nodump" if args.no_dump == True else ""
    nc_suffix = "_nocmp"  if args.no_cmp  == True else ""

    db_suffix = "" if args.din_bits == 8 else f"_din{args.din_bits}"

    fs_suffix = "" if args.feed_shard    == 0 else f"_fs{args.feed_shard}"
    cg_suffix = "" if args.collect_group  == 0 else f"_cg{args.collect_group}"
    ds_suffix = "" if args.num_cores_dist == 0 else f"_d{args.num_cores_dist}"
    us_suffix = "" if args.num_cores_uram == 0 else f"_u{args.num_cores_uram}"
    ib_suffix = "" if args.init_batch     == 0 else f"_ib{args.init_batch}"

    lanes_suffix = f"_x{args.pcie_lanes}"

    pd_suffix = "" if args.place_directive == "Explore" else f"_p{args.place_directive}"

    if args.cslow == 2: pd_suffix += "_cs2"

    name = f"bcrypt_{BOARD}_dma_c{args.cores}_{mhz}mhz_{args.startup_clk.lower()}{lanes_suffix}{fg_suffix}{nd_suffix}{nc_suffix}{db_suffix}{ds_suffix}{us_suffix}{fs_suffix}{cg_suffix}{ib_suffix}{pd_suffix}"

    soc = BcryptSoC(
        sys_clk_freq = args.sys_clk_freq,
        num_cores    = args.cores,
        feed_group   = args.feed_group,
        feed_shard   = args.feed_shard,
        with_dump    = 0 if args.no_dump else 1,
        with_cmp     = 0 if args.no_cmp  else 1,
        din_bits     = args.din_bits,
        collect_group  = args.collect_group,
        num_cores_dist = args.num_cores_dist,
        num_cores_uram = args.num_cores_uram,
        init_batch     = args.init_batch,
        startup_clock  = args.startup_clk,
        abi          = args.abi,
        pcie_lanes   = args.pcie_lanes,
        with_jtagbone = args.with_jtagbone,
        cslow        = args.cslow,
    )

    builder = Builder(soc, output_dir=os.path.join("build", name))

    builder.build(build_name=name, run=args.build, **vivado_build_args(args.threads, args.place_directive))

    hdr_dir = os.path.join("software", "kernel", BOARD)

    os.makedirs(hdr_dir, exist_ok=True)
    generate_litepcie_software_headers(soc, hdr_dir)

    if args.load:
        prog = make_programmer(soc.platform)
        prog.load_bitstream(builder.get_bitstream_filename(mode="sram"))

if __name__ == "__main__":
    main()
