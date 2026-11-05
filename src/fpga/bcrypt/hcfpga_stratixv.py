#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os
import shutil
import subprocess

from migen import *
from migen.genlib.cdc import MultiReg

from litex.gen import *

from litex.soc.interconnect.csr import CSRStatus, CSRConstant

# The register map the bridge and the driver read is the one every LiteX board in this tree shares,
# and on Xilinx parts the die temperature and the serial number come from LiteX's S7SystemMonitor
# (the XADC) and S7DNA. These two modules give a Stratix V the same registers, the same sizes and
# the same encodings, so it needs no special case on the host and passes check-headers.

# PCIe hard IP ------------------------------------------------------------------------------------

def sv_pcie_endpoint_params (speed="gen2", nlanes=8, data_width=128):
  # Receive credits and timers as Intel's generator derives them for an endpoint with the default
  # "balanced" allocation. LitePCIe's SVPCIEPHY leaves the hard IP at its Verilog defaults, which
  # advertise finite completion credits. With those, the hard IP occasionally drops the second
  # completion of a split read without reporting an error, and DMA stalls for good.
  return dict (
    p_vc0_rx_flow_ctrl_posted_header_hwtcl    = 50,
    p_vc0_rx_flow_ctrl_posted_data_hwtcl      = 333,
    p_vc0_rx_flow_ctrl_nonposted_header_hwtcl = 56,
    p_vc0_rx_flow_ctrl_nonposted_data_hwtcl   = 0,
    p_vc0_rx_flow_ctrl_compl_header_hwtcl     = 0,
    p_vc0_rx_flow_ctrl_compl_data_hwtcl       = 0,
    p_cpl_spc_header_hwtcl                    = 112,
    p_cpl_spc_data_hwtcl                      = 420,
    p_millisecond_cycle_count_hwtcl           = 248500 if (speed, nlanes, data_width) == ("gen2", 8, 128) else 124250,
  )

# Temperature --------------------------------------------------------------------------------------

XADC_TEMP_SCALE      = 503975
XADC_TEMP_DIVISOR    = 4096
XADC_TEMP_OFFSET     = 273150
XADC_VOLTAGE_SCALE   = 3000
XADC_VOLTAGE_DIVISOR = 4096

def xadc_temperature_code (celsius):
  # The host converts with code * 503.975 / 4096 - 273.15 and truncates, so aim at the middle of the
  # degree to land on it from either side.
  target = celsius + (0.5 if celsius >= 0 else -0.5)

  code = int (round ((target + XADC_TEMP_OFFSET / 1000) * XADC_TEMP_DIVISOR / (XADC_TEMP_SCALE / 1000)))

  return max (0, min (code, 4095))

def tsd_celsius (tsdcalo):
  # Stratix V temperature sensing diode: the 8-bit result is linear, 0x80 is 0 C and one step is one
  # degree, so 0xe4 is 100 C and 0xff is 127 C (Intel knowledge base, ALTTEMP_SENSE on Stratix V).
  return tsdcalo - 128

class StratixVTemperature (LiteXModule):
  """Die temperature from the internal temperature sensing diode, in XADC registers and encoding.

  The diode's ADC wants a clock between 1 and 80 MHz, divided by 40 or 80 down to roughly 1 MHz. The
  PCIe transceiver management clock is free running and in range, so it drives it. Supply rails are
  not measured on this part and read 0.
  """
  def __init__ (self, platform, cd="pcie_mgmt", clk_freq=50e6, period_ms=50):
    assert 1e6 <= clk_freq <= 80e6

    self.expose_hwmon ()

    self.temperature = CSRStatus (12, name="temperature", description="Die temperature, XADC encoding: code * 503.975 / 4096 - 273.15 C.")
    self.vccint      = CSRStatus (12, name="vccint",      description="Not measured, reads 0.")
    self.vccaux      = CSRStatus (12, name="vccaux",      description="Not measured, reads 0.")
    self.vccbram     = CSRStatus (12, name="vccbram",     description="Not measured, reads 0.")

    self.eoc = CSRStatus (description="End of Conversion Status, ``1``: Conversion Done.")
    self.eos = CSRStatus (description="End of Sequence Status,   ``1``: Sequence Done.")

    # # #

    tsdcalo    = Signal (8)
    tsdcaldone = Signal ()
    clr        = Signal (reset=1)

    self.specials += Instance ("hcfpga_sv_tsd",
      p_CLOCK_DIVIDER_VALUE = 80 if clk_freq > 40e6 else 40,
      i_clk                 = ClockSignal (cd),
      i_clr                 = clr,
      o_tsdcalo             = tsdcalo,
      o_tsdcaldone          = tsdcaldone,
    )

    platform.add_source (os.path.join (os.path.dirname (os.path.abspath (__file__)), "gateware", "stratixv", "hcfpga_sv_tsd.v"))

    # Clear, let one conversion complete, latch it, wait, repeat. A conversion takes on the order of
    # a millisecond, so the period only bounds how stale a reading can get.
    wait_max = int (clk_freq * period_ms / 1000)

    code  = Signal (8)
    done  = Signal ()
    wait  = Signal (max=wait_max + 1)

    fsm = FSM (reset_state="CLEAR")
    fsm = ClockDomainsRenamer (cd) (fsm)

    self.fsm = fsm

    fsm.act ("CLEAR",
      clr.eq (1),
      NextValue (wait, wait + 1),
      If (wait == 15,
        NextValue (wait, 0),
        NextState ("CONVERT"),
      )
    )
    fsm.act ("CONVERT",
      clr.eq (0),
      If (tsdcaldone,
        NextValue (code, tsdcalo),
        NextValue (done, 1),
        NextState ("HOLD"),
      )
    )
    fsm.act ("HOLD",
      clr.eq (0),
      NextValue (wait, wait + 1),
      If (wait == wait_max,
        NextValue (wait, 0),
        NextState ("CLEAR"),
      )
    )

    code_sys = Signal (8)
    done_sys = Signal ()

    self.specials += MultiReg (code, code_sys)
    self.specials += MultiReg (done, done_sys)

    table = Array ([Constant (xadc_temperature_code (tsd_celsius (c)), 12) for c in range (256)])

    self.comb += [
      self.temperature.status.eq (Mux (done_sys, table[code_sys], 0)),
      self.eoc.status.eq (done_sys),
      self.eos.status.eq (done_sys),
    ]

  def expose_hwmon (self):
    self.hwmon_temp_scale      = CSRConstant (XADC_TEMP_SCALE,      name="hwmon_temp_scale")
    self.hwmon_temp_divisor    = CSRConstant (XADC_TEMP_DIVISOR,    name="hwmon_temp_divisor")
    self.hwmon_temp_offset     = CSRConstant (XADC_TEMP_OFFSET,     name="hwmon_temp_offset")
    self.hwmon_voltage_scale   = CSRConstant (XADC_VOLTAGE_SCALE,   name="hwmon_voltage_scale")
    self.hwmon_voltage_divisor = CSRConstant (XADC_VOLTAGE_DIVISOR, name="hwmon_voltage_divisor")

# Chip ID ------------------------------------------------------------------------------------------

def altchip_id_source ():
  quartus_sh = shutil.which ("quartus_sh")

  if quartus_sh is None:
    raise SystemExit ("quartus_sh is not on PATH. The Stratix V chip ID reader is Intel's altchip_id, which ships with Quartus.")

  path = os.path.join (os.path.dirname (os.path.dirname (os.path.dirname (quartus_sh))), "ip", "altera", "altchip_id", "source", "altchip_id.v")

  if os.path.exists (path) == False:
    raise SystemExit ("Intel's altchip_id is not where Quartus keeps it: %s" % path)

  return path

class StratixVChipID (LiteXModule):
  """The 64-bit chip ID, exposed like LiteX's XilinxDNA: one 57-bit register named id.

  The bridge reads exactly 57 bits and prints them as the board's serial, so the low 57 bits of the
  ID are kept. Intel's own altchip_id does the load and shift sequence.
  """
  def __init__ (self, platform, cd="pcie_mgmt", nbits=57):
    self._id = CSRStatus (nbits, description="Stratix V chip ID, low 57 bits.")

    # # #

    chip_id    = Signal (64)
    data_valid = Signal ()

    self.specials += Instance ("altchip_id",
      p_DEVICE_FAMILY = "Stratix V",
      i_clkin         = ClockSignal (cd),
      i_reset         = ResetSignal (cd),
      o_chip_id       = chip_id,
      o_data_valid    = data_valid,
    )

    platform.add_source (altchip_id_source ())

    chip_id_sys    = Signal (64)
    data_valid_sys = Signal ()

    self.specials += MultiReg (chip_id,    chip_id_sys)
    self.specials += MultiReg (data_valid, data_valid_sys)

    self.comb += If (data_valid_sys, self._id.status.eq (chip_id_sys[:nbits]))

# Configuration flash -----------------------------------------------------------------------------

# The card boots in Active Serial x4 from a 256 Mbit Micron N25Q256A. Quartus' .rbf is the
# uncompressed passive image and is the wrong thing to write there: quartus_cpf converts the .sof
# into a compressed AS x4 image instead, which needs no license. The .rpd it writes is LSB first
# within each byte, the order openFPGALoader expects for .rpd and reverses while writing, so the
# flash ends up holding the same layout as the factory image (sync word 0x56565656 at 0x80).

SV_FLASH_DEVICE = "EPCQ256"
SV_FLASH_LOADER = "5SGSMD5K1"

def sv_flash_image (sof, out_dir=None):
  out_dir  = out_dir or os.path.dirname (os.path.abspath (sof))
  base     = os.path.splitext (os.path.basename (sof))[0] + "_flash"
  cof_path = os.path.join (out_dir, base + ".cof")

  cof = f"""<?xml version="1.0" encoding="US-ASCII" standalone="yes"?>
<cof>
	<eprom_name>{SV_FLASH_DEVICE}</eprom_name>
	<flash_loader_device>{SV_FLASH_LOADER}</flash_loader_device>
	<output_filename>{base}.jic</output_filename>
	<n_pages>1</n_pages>
	<width>1</width>
	<mode>13</mode>
	<sof_data>
		<user_name>Page_0</user_name>
		<page_flags>1</page_flags>
		<bit0>
			<sof_filename>{os.path.abspath (sof)}<compress_bitstream>1</compress_bitstream></sof_filename>
		</bit0>
	</sof_data>
	<version>10</version>
	<create_cvp_file>0</create_cvp_file>
	<create_hps_iocsr>0</create_hps_iocsr>
	<auto_create_rpd>1</auto_create_rpd>
	<rpd_little_endian>1</rpd_little_endian>
	<options>
		<map_file>1</map_file>
	</options>
</cof>
"""

  with open (cof_path, "w") as f:
    f.write (cof)

  if shutil.which ("quartus_cpf") is None:
    raise OSError ("quartus_cpf not on PATH. It ships with Quartus and the Quartus Programmer.")

  subprocess.check_call (["quartus_cpf", "-c", os.path.basename (cof_path)], cwd=out_dir)

  rpd = os.path.join (out_dir, base + "_auto.rpd")

  with open (rpd, "rb") as f:
    head = f.read (0x84)

  if head[0x80:0x84] != b"\x6a\x6a\x6a\x6a":
    raise ValueError (f"{rpd} has no AS sync word at 0x80, refusing to hand it to a flash writer")

  return rpd

# The flash's nonvolatile configuration register selects 4-byte address mode at power-up, which AS
# x4 boot needs. openFPGALoader through v1.2.0 addresses it with 3-byte opcodes below 16 MiB, so
# those reads and writes land at the wrong addresses without an error. OFL_SPI_4BYTE is honoured by
# a patched openFPGALoader that uses the 4-byte opcodes everywhere. Released versions ignore it.

def sv_flash_command (rpd, cable="ft232"):
  return ["openFPGALoader", "-c", cable, "--fpga-part", "5sgsd5", "-f", "--verify", rpd]
