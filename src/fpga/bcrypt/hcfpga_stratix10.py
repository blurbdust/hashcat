#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os
import shutil
import hashlib
import subprocess

from migen import *
from migen.genlib.cdc import MultiReg, BusSynchronizer

from litex.gen import *

from litex.soc.interconnect.csr import CSRStatus

from hcfpga_stratixv import StratixVTemperature, xadc_temperature_code

# A Stratix 10 has no temperature diode or chip ID block in the fabric. Both live behind the Secure
# Device Manager, which answers mailbox commands from the fabric, and Intel's Temperature Sensor and
# Chip ID IPs are the mailbox clients for them. These modules give the same registers, sizes and
# encodings the Stratix V helper gives, so a Stratix 10 board needs no special case on the host.

# Secure Device Manager clients --------------------------------------------------------------------

SDM_SYSTEM = "hcfpga_s10_sdm"

def sdm_system_tcl (device, name=SDM_SYSTEM):
  # One Platform Designer system holds every SDM client the design uses. Two of them, the
  # Temperature Sensor and the Chip ID, have no plain RTL to point at: Platform Designer composes
  # them around a configuration stream endpoint. The Reset Release IP is here too, because it is
  # also expanded from a template and is the third SDM function a design needs. The clock and reset
  # bridges make this a system rather than a standalone IP variation, which Platform Designer would
  # save as .ip rather than .qsys.
  return "\n".join ([
    "package require -exact qsys 16.0",
    f"create_system {name}",
    "set_project_property DEVICE_FAMILY {Stratix 10}",
    f"set_project_property DEVICE {{{device}}}",

    "add_instance clk_bridge altera_clock_bridge",
    "add_instance rst_bridge altera_reset_bridge",
    "set_instance_parameter_value rst_bridge ACTIVE_LOW_RESET 0",
    "set_instance_parameter_value rst_bridge SYNCHRONOUS_EDGES deassert",
    "add_connection clk_bridge.out_clk rst_bridge.clk",

    "add_instance rr altera_s10_user_rst_clkgate",
    "set_instance_parameter_value rr outputType {Conduit Interface}",

    "add_instance ts altera_s10_temperature_sensor",
    "add_connection clk_bridge.out_clk ts.clk",
    "add_connection rst_bridge.out_reset ts.reset",

    "add_instance cid altera_s10_chip_id",
    "add_connection clk_bridge.out_clk cid.clk",
    "add_connection rst_bridge.out_reset cid.reset",

    "add_interface clk clock sink",
    "set_interface_property clk EXPORT_OF clk_bridge.in_clk",
    "add_interface reset reset sink",
    "set_interface_property reset EXPORT_OF rst_bridge.in_reset",
    "add_interface ninit_done conduit end",
    "set_interface_property ninit_done EXPORT_OF rr.ninit_done",
    "add_interface temp_cmd avalon_streaming sink",
    "set_interface_property temp_cmd EXPORT_OF ts.cmd",
    "add_interface temp_rsp avalon_streaming source",
    "set_interface_property temp_rsp EXPORT_OF ts.rsp",
    "add_interface chip_id avalon_streaming source",
    "set_interface_property chip_id EXPORT_OF cid.output",
    "add_interface chip_id_read conduit end",
    "set_interface_property chip_id_read EXPORT_OF cid.readid",

    f"save_system {name}.qsys",
  ]) + "\n"

def qsys_tool (name):
  # The Platform Designer tools live in qsys/bin of a Quartus Prime Pro installation, beside
  # quartus/bin, and only quartus/bin is usually on PATH.
  found = shutil.which (name)

  if found is not None:
    return found

  quartus_sh = shutil.which ("quartus_sh")

  if quartus_sh is not None:
    root = os.path.dirname (os.path.dirname (os.path.dirname (os.path.realpath (quartus_sh))))

    for sub in ["qsys", os.path.join ("quartus", "sopc_builder")]:
      path = os.path.join (root, sub, "bin", name)

      if os.path.exists (path):
        return path

  raise SystemExit (f"{name} is not on PATH. It ships with Quartus Prime Pro, in qsys/bin.")

def generate_sdm_system (device, output_dir, name=SDM_SYSTEM):
  """Generate the system once per Tcl and return every .qip it wrote.

  Platform Designer writes one .qip for the system and one per instance under ip/<system>/, and the
  system's .qip does not pull the others in, so all of them go to Quartus.
  """
  tcl  = sdm_system_tcl (device, name)
  hash = hashlib.sha256 (tcl.encode ()).hexdigest ()[:16]

  output_dir = os.path.abspath (output_dir)
  stamp      = os.path.join (output_dir, name + ".hash")
  top        = os.path.join (output_dir, name, "synth", name + ".v")

  fresh = os.path.exists (top) and os.path.exists (stamp) and (open (stamp).read ().strip () == hash)

  if fresh == False:
    # qsys-script refuses to overwrite the project it creates beside the system, and a stale
    # instance .qip would be collected below, so a new generation starts from an empty directory.
    shutil.rmtree (output_dir, ignore_errors=True)
    os.makedirs (output_dir)

    with open (os.path.join (output_dir, name + ".tcl"), "w") as f:
      f.write (tcl)

    for cmd in [
      [qsys_tool ("qsys-script"),   f"--script={name}.tcl"],
      [qsys_tool ("qsys-generate"), f"{name}.qsys", "--synthesis=VERILOG"],
    ]:
      subprocess.check_call (cmd, cwd=output_dir)

    if os.path.exists (top) == False:
      raise SystemExit (f"Platform Designer reported success, but {top} is missing.")

    with open (stamp, "w") as f:
      f.write (hash)

  qips = []

  for root, _, files in os.walk (output_dir):
    qips += [os.path.join (root, f) for f in files if f.endswith (".qip")]

  return sorted (qips)

class Stratix10SDM (LiteXModule):
  """The Reset Release, Temperature Sensor and Chip ID IPs in one Platform Designer system.

  Generated at elaboration and kept in output_dir, where builds of every shape reuse it. Needs
  Quartus Prime Pro. ninit_done stays high until the device has finished initialising, after the
  fabric is already running, and holds everything that must not start early.
  """
  def __init__ (self, platform, cd="mgmt", output_dir=None):
    self.ninit_done = Signal ()

    self.temp_cmd_valid = Signal ()
    self.temp_cmd_ready = Signal ()
    self.temp_cmd_data  = Signal (9)
    self.temp_rsp_valid = Signal ()
    self.temp_rsp_data  = Signal (32)
    self.temp_rsp_chan  = Signal (4)

    self.chip_id_read  = Signal ()
    self.chip_id_valid = Signal ()
    self.chip_id       = Signal (64)

    # # #

    if output_dir is None:
      output_dir = os.path.join (os.getcwd (), "build", "s10_sdm_ip")

    for qip in generate_sdm_system (platform.device, output_dir):
      platform.add_ip (qip)

    # The port names are Platform Designer's, <interface>_<role>, for the interfaces exported above.
    self.specials += Instance (SDM_SYSTEM,
      i_clk_clk                = ClockSignal (cd),
      i_reset_reset            = ResetSignal (cd),
      o_ninit_done_ninit_done  = self.ninit_done,
      i_temp_cmd_valid         = self.temp_cmd_valid,
      o_temp_cmd_ready         = self.temp_cmd_ready,
      i_temp_cmd_data          = self.temp_cmd_data,
      o_temp_rsp_valid         = self.temp_rsp_valid,
      o_temp_rsp_data          = self.temp_rsp_data,
      o_temp_rsp_channel       = self.temp_rsp_chan,
      o_temp_rsp_startofpacket = Signal (),
      o_temp_rsp_endofpacket   = Signal (),
      i_chip_id_read_readid    = self.chip_id_read,
      o_chip_id_valid          = self.chip_id_valid,
      o_chip_id_data           = self.chip_id,
    )

# Temperature --------------------------------------------------------------------------------------

# The Temperature Sensor IP takes a bitmask of sensor locations. Bit 0 is the core fabric, bits 1 to
# 6 the transceiver tiles and bits 7 and 8 the UIBs of the parts that have them. Each selected
# location answers with one word, a signed fixed point number of degrees with 8 fractional bits, or
# 0x80000000 when the location has no sensor. A command the SDM rejects returns no word at all.

S10_TEMP_CORE    = 0x001
S10_TEMP_INVALID = 0x80000000

def s10_celsius (index):
  # The table below is indexed by the reading's integer degrees as an 8-bit two's complement value.
  return index - 256 if index >= 128 else index

class Stratix10Temperature (LiteXModule):
  """Die temperature from the SDM's core fabric sensor, in XADC registers and encoding.

  Supply rails are not read and report 0, as on the Stratix V.
  """
  def __init__ (self, sdm, cd="mgmt", clk_freq=100e6, period_ms=100, timeout_ms=1000):
    self.expose_hwmon ()

    self.temperature = CSRStatus (12, name="temperature", description="Die temperature, XADC encoding: code * 503.975 / 4096 - 273.15 C.")
    self.vccint      = CSRStatus (12, name="vccint",      description="Not measured, reads 0.")
    self.vccaux      = CSRStatus (12, name="vccaux",      description="Not measured, reads 0.")
    self.vccbram     = CSRStatus (12, name="vccbram",     description="Not measured, reads 0.")

    self.eoc = CSRStatus (description="End of Conversion Status, ``1``: Conversion Done.")
    self.eos = CSRStatus (description="End of Sequence Status,   ``1``: Sequence Done.")

    # # #

    wait_max    = int (clk_freq * period_ms  / 1000)
    timeout_max = int (clk_freq * timeout_ms / 1000)

    wait = Signal (max=max (wait_max, timeout_max) + 1)

    # The reading's integer degrees, clamped into -128 to 127, as an 8-bit two's complement code.
    raw      = sdm.temp_rsp_data
    in_range = Signal ()
    deg      = Signal (8)

    self.comb += [
      in_range.eq ((raw[15:32] == 0) | (raw[15:32] == 2**17 - 1)),
      If (in_range,
        deg.eq (raw[8:16]),
      ).Elif (raw[31],
        deg.eq (0x80),
      ).Else (
        deg.eq (0x7f),
      )
    ]

    code = Signal (8)
    done = Signal ()

    fsm = FSM (reset_state="WAIT")
    fsm = ClockDomainsRenamer (cd) (fsm)

    self.fsm = fsm

    # Ask, wait for the answer, latch it, wait, repeat. A command that gets no answer is given up
    # after the timeout and asked again.
    fsm.act ("WAIT",
      NextValue (wait, wait + 1),
      If (wait == wait_max,
        NextValue (wait, 0),
        NextState ("ASK"),
      )
    )
    fsm.act ("ASK",
      sdm.temp_cmd_valid.eq (1),
      sdm.temp_cmd_data.eq (S10_TEMP_CORE),
      If (sdm.temp_cmd_ready,
        NextState ("ANSWER"),
      )
    )
    fsm.act ("ANSWER",
      NextValue (wait, wait + 1),
      If (sdm.temp_rsp_valid,
        NextValue (wait, 0),
        If (raw == S10_TEMP_INVALID,
          NextValue (done, 0),
        ).Else (
          NextValue (code, deg),
          NextValue (done, 1),
        ),
        NextState ("WAIT"),
      ).Elif (wait == timeout_max,
        NextValue (wait, 0),
        NextState ("WAIT"),
      )
    )

    # A torn multi-bit value could read as a much higher temperature for a cycle and abort a run,
    # so the code crosses with a handshake rather than one MultiReg per bit.
    code_sys = Signal (8)
    done_sys = Signal ()

    self.code_sync = BusSynchronizer (8, cd, "sys")
    self.comb += [
      self.code_sync.i.eq (code),
      code_sys.eq (self.code_sync.o),
    ]

    self.specials += MultiReg (done, done_sys)

    table = Array ([Constant (xadc_temperature_code (s10_celsius (c)), 12) for c in range (256)])

    self.comb += [
      self.temperature.status.eq (Mux (done_sys, table[code_sys], 0)),
      self.eoc.status.eq (done_sys),
      self.eos.status.eq (done_sys),
    ]

  expose_hwmon = StratixVTemperature.expose_hwmon

# Chip ID ------------------------------------------------------------------------------------------

class Stratix10ChipID (LiteXModule):
  """The 64-bit chip ID from the SDM, exposed like LiteX's XilinxDNA: one 57-bit register named id.

  The Chip ID IP starts a read on a falling edge of readid. A read the SDM does not answer, or
  answers with an error, is retried until one succeeds.
  """
  def __init__ (self, sdm, cd="mgmt", clk_freq=100e6, retry_ms=100, nbits=57):
    self._id = CSRStatus (nbits, description="Stratix 10 chip ID, low 57 bits.")

    # # #

    wait_max = int (clk_freq * retry_ms / 1000)

    wait    = Signal (max=wait_max + 1)
    chip_id = Signal (64)
    done    = Signal ()

    fsm = FSM (reset_state="HIGH")
    fsm = ClockDomainsRenamer (cd) (fsm)

    self.fsm = fsm

    fsm.act ("HIGH",
      sdm.chip_id_read.eq (1),
      NextValue (wait, wait + 1),
      If (wait == 15,
        NextValue (wait, 0),
        NextState ("READ"),
      )
    )
    fsm.act ("READ",
      NextValue (wait, wait + 1),
      If (sdm.chip_id_valid,
        NextValue (chip_id, sdm.chip_id),
        NextState ("LATCHED"),
      ).Elif (wait == wait_max,
        NextValue (wait, 0),
        NextState ("HIGH"),
      )
    )
    # The IP sets data_valid on the edge that writes the upper word, so the value is taken here one
    # cycle later and the flag only after it, to reach sys no later than the value does.
    fsm.act ("LATCHED",
      NextValue (done, 1),
      NextState ("DONE"),
    )
    fsm.act ("DONE")

    chip_id_sys = Signal (64)
    done_sys    = Signal ()

    self.specials += MultiReg (chip_id, chip_id_sys)
    self.specials += MultiReg (done,    done_sys)

    self.comb += If (done_sys, self._id.status.eq (chip_id_sys[:nbits]))
