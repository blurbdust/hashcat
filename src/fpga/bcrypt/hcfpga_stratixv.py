#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os
import shutil

from migen import *
from migen.genlib.cdc import MultiReg

from litex.gen import *

from litex.soc.interconnect.csr import CSRStatus, CSRConstant

# The register map the bridge and the driver read is the one every LiteX board in this tree shares,
# and on Xilinx parts the die temperature and the serial number come from LiteX's S7SystemMonitor
# (the XADC) and S7DNA. These two modules give a Stratix V the same registers, the same sizes and
# the same encodings, so it needs no special case on the host and passes check-headers.

# Temperature --------------------------------------------------------------------------------------

XADC_TEMP_SCALE      = 503975
XADC_TEMP_DIVISOR    = 4096
XADC_TEMP_OFFSET     = 273150
XADC_VOLTAGE_SCALE   = 3000
XADC_VOLTAGE_DIVISOR = 4096

def xadc_temperature_code(celsius):
  # The host converts with code * 503.975 / 4096 - 273.15 and truncates, so aim at the middle of the
  # degree to land on it from either side.
  target = celsius + (0.5 if celsius >= 0 else -0.5)

  code = int (round ((target + XADC_TEMP_OFFSET / 1000) * XADC_TEMP_DIVISOR / (XADC_TEMP_SCALE / 1000)))

  return max (0, min (code, 4095))

def tsd_celsius(tsdcalo):
  # Stratix V temperature sensing diode: the 8-bit result is linear, 0x80 is 0 C and one step is one
  # degree, so 0xe4 is 100 C and 0xff is 127 C (Intel knowledge base, ALTTEMP_SENSE on Stratix V).
  return tsdcalo - 128

class StratixVTemperature(LiteXModule):
  """Die temperature from the internal temperature sensing diode, in XADC registers and encoding.

  The diode's ADC wants a clock between 1 and 80 MHz, divided by 40 or 80 down to roughly 1 MHz. The
  PCIe transceiver management clock is free running and in range, so it drives it. Supply rails are
  not measured on this part and read 0.
  """
  def __init__(self, cd="pcie_mgmt", clk_freq=50e6, period_ms=50):
    assert 1e6 <= clk_freq <= 80e6

    self.expose_hwmon()

    self.temperature = CSRStatus(12, name="temperature", description="Die temperature, XADC encoding: code * 503.975 / 4096 - 273.15 C.")
    self.vccint      = CSRStatus(12, name="vccint",      description="Not measured, reads 0.")
    self.vccaux      = CSRStatus(12, name="vccaux",      description="Not measured, reads 0.")
    self.vccbram     = CSRStatus(12, name="vccbram",     description="Not measured, reads 0.")

    self.eoc = CSRStatus(description="End of Conversion Status, ``1``: Conversion Done.")
    self.eos = CSRStatus(description="End of Sequence Status,   ``1``: Sequence Done.")

    # # #

    tsdcalo    = Signal(8)
    tsdcaldone = Signal()
    clr        = Signal(reset=1)

    self.specials += Instance("stratixv_tsdblock",
      p_clock_divider_enable = "on",
      p_clock_divider_value  = 80 if clk_freq > 40e6 else 40,
      i_clk                  = ClockSignal(cd),
      i_ce                   = 1,
      i_clr                  = clr,
      o_tsdcalo              = tsdcalo,
      o_tsdcaldone           = tsdcaldone,
    )

    # Clear, let one conversion complete, latch it, wait, repeat. A conversion takes on the order of
    # a millisecond, so the period only bounds how stale a reading can get.
    wait_max = int (clk_freq * period_ms / 1000)

    code  = Signal(8)
    done  = Signal()
    wait  = Signal(max=wait_max + 1)

    fsm = FSM(reset_state="CLEAR")
    fsm = ClockDomainsRenamer(cd)(fsm)

    self.fsm = fsm

    fsm.act("CLEAR",
      clr.eq(1),
      NextValue(wait, wait + 1),
      If(wait == 15,
        NextValue(wait, 0),
        NextState("CONVERT"),
      )
    )
    fsm.act("CONVERT",
      clr.eq(0),
      If(tsdcaldone,
        NextValue(code, tsdcalo),
        NextValue(done, 1),
        NextState("HOLD"),
      )
    )
    fsm.act("HOLD",
      clr.eq(0),
      NextValue(wait, wait + 1),
      If(wait == wait_max,
        NextValue(wait, 0),
        NextState("CLEAR"),
      )
    )

    code_sys = Signal(8)
    done_sys = Signal()

    self.specials += MultiReg(code, code_sys)
    self.specials += MultiReg(done, done_sys)

    table = Array([Constant(xadc_temperature_code(tsd_celsius(c)), 12) for c in range(256)])

    self.comb += [
      self.temperature.status.eq(Mux(done_sys, table[code_sys], 0)),
      self.eoc.status.eq(done_sys),
      self.eos.status.eq(done_sys),
    ]

  def expose_hwmon(self):
    self.hwmon_temp_scale      = CSRConstant(XADC_TEMP_SCALE,      name="hwmon_temp_scale")
    self.hwmon_temp_divisor    = CSRConstant(XADC_TEMP_DIVISOR,    name="hwmon_temp_divisor")
    self.hwmon_temp_offset     = CSRConstant(XADC_TEMP_OFFSET,     name="hwmon_temp_offset")
    self.hwmon_voltage_scale   = CSRConstant(XADC_VOLTAGE_SCALE,   name="hwmon_voltage_scale")
    self.hwmon_voltage_divisor = CSRConstant(XADC_VOLTAGE_DIVISOR, name="hwmon_voltage_divisor")

# Chip ID ------------------------------------------------------------------------------------------

def altchip_id_source():
  quartus_sh = shutil.which ("quartus_sh")

  if quartus_sh is None:
    raise SystemExit ("quartus_sh is not on PATH. The Stratix V chip ID reader is Intel's altchip_id, which ships with Quartus.")

  path = os.path.join (os.path.dirname (os.path.dirname (os.path.dirname (quartus_sh))), "ip", "altera", "altchip_id", "source", "altchip_id.v")

  if os.path.exists (path) == False:
    raise SystemExit ("Intel's altchip_id is not where Quartus keeps it: %s" % path)

  return path

class StratixVChipID(LiteXModule):
  """The 64-bit chip ID, exposed like LiteX's XilinxDNA: one 57-bit register named id.

  The bridge reads exactly 57 bits and prints them as the board's serial, so the low 57 bits of the
  ID are kept. Intel's own altchip_id does the load and shift sequence.
  """
  def __init__(self, platform, cd="pcie_mgmt", nbits=57):
    self._id = CSRStatus(nbits, description="Stratix V chip ID, low 57 bits.")

    # # #

    chip_id    = Signal(64)
    data_valid = Signal()

    self.specials += Instance("altchip_id",
      p_DEVICE_FAMILY = "Stratix V",
      i_clkin         = ClockSignal(cd),
      i_reset         = ResetSignal(cd),
      o_chip_id       = chip_id,
      o_data_valid    = data_valid,
    )

    platform.add_source (altchip_id_source ())

    chip_id_sys    = Signal(64)
    data_valid_sys = Signal()

    self.specials += MultiReg(chip_id,    chip_id_sys)
    self.specials += MultiReg(data_valid, data_valid_sys)

    self.comb += If(data_valid_sys, self._id.status.eq(chip_id_sys[:nbits]))
