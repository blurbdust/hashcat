# wpa2 FPGA provenance

The PBKDF2 and SHA-1 cores in this design are OpenCiphers' (David Hulton, for Pico Computing): the WPA-PSK PBKDF2 core of OpenCiphers' `wpapsk` module and the SHA-1 core of its `sha1` module, from which the `wpapsk` one was derived. OpenCiphers states that its cores are under the BSD license (below). hashcat has modified the files listed below. Every file taken keeps its original text, and each modified file adds a notice pointing here (the files have no header to put it under). This page lists every change.

The rest of the design was written for hashcat: the engine, the datapath top, the LiteX wrapper and the bench here, and the H2C intake, generation counter, end-of-batch tail, wrapper base, simulated board and bench they use (identical in every algorithm after bcrypt).

## Origin

OpenCiphers, https://openciphers.sourceforge.net (SourceForge project `openciphers`). The project's download page offers release tarballs (`oc-v0.3.tgz`, `oc-v0.4-win.zip`, `oc-v0.5.tgz`); those hold bitstreams, drivers and host software (coWPAtty with FPGA support) but no HDL. The Verilog is in the project's CVS repository, which SourceForge publishes as a read-only snapshot, `https://sourceforge.net/code-snapshots/cvs/o/op/openciphers.zip` (SHA-256 `a239e3a71ed537042bc7b744ab76b246d4cf8fc207594669aa44810477bbcb0d` as fetched). The files were taken from it at their head revisions, all committed by `h1kari` (David Hulton):

| File | CVS revision | SHA-256 as taken |
|---|---|---|
| `wpapsk/PBKDF2.v` | 1.1 | `7814af4c377d56cf85ec0176068e192404e1e684e86ca450a0cc6591dfd3a1cf` |
| `wpapsk/Sha1.v` | 1.2 | `8cfbe3278067d4e661ff80897e17ecc6cad19a553edbc9dc2b0cd226c678efb2` |
| `wpapsk/Sha1BRAM.v` | 1.1 | `3b2b83e3b97f8dd5a9f120e7f549da1ae9740f71222333c930d7f9da6c51c6c9` |
| `wpapsk/R.v` | 1.1 | `909d4e636852288b9b8b3988e18cf3d64bf9850bbe6819e6ff180e22f3ab8459` |
| `wpapsk/Add32.v` | 1.1 | `9aab63f05d8e0cd6f47bde429444efa9c2d5932099712baac65b37ef992d11b7` |
| `sha1/Sha1.v` | 1.1 | `b609e8cbc68066b4f2421ab0aa887b15725f0ef0ac5312a723ce606b86699b92` |

The files had LF line endings. The commit that imports them changes nothing, so `git diff` from that commit shows every hashcat change.

### License

The files carry no header, and the `wpapsk` and `sha1` modules have no license file. The project states the license on its home page (`oc.html`), verbatim: "All of the cores and software provided are licensed under the BSD License", the last three words linking to `http://www.opensource.org/licenses/bsd-license.php`. The release tarball `oc-v0.5.tgz` ships David Hulton's text of that license with his projects (`btpincrack-v0.3/LICENSE`), which this port takes as the terms of the cores, verbatim:

```
Copyright (c) 2006, David Hulton <dhulton@openciphers.org>
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of David Hulton nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY DAVID HULTON AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Files taken from OpenCiphers

All under `gateware/wpa2/`, in upstream's module directories (`wpapsk/`, `sha1/`). The set is the PBKDF2 core, `wpapsk/PBKDF2.v`, and every file it instantiates (`Sha1`, `Sha1BRAM`, `R`, `Add32`), found by linting it alone; and the general SHA-1 core, `sha1/Sha1.v`, which the engine uses for the HMAC setup. That core instantiates `R` and `Add32` and reads its message from a `Sha1BRAM`; `sha1/` and `wpapsk/` hold byte-identical copies of those three, taken once, from `wpapsk/`.

| File | Change |
|---|---|
| `wpapsk/Sha1.v`, `wpapsk/Sha1BRAM.v`, `wpapsk/R.v`, `wpapsk/Add32.v` | none |
| `wpapsk/PBKDF2.v` | the result accumulator is cleared on `Rst` (below) |
| `sha1/Sha1.v` | the module is renamed `Sha1Full` (below) |

Not taken: `wpapsk/PBKDF2Bridge.v` (the Pico bus bridge and the core array), `wpapsk/PBKDF2BRAM.v` and `wpapsk/BRAM.v` (the host-written ipad, opad and U1 tables; `BRAM.v` is a Xilinx `RAMB16` unless `SIMULATION` is defined), `wpapsk/PBKDF2BridgeTest.v`, `wpapsk/Sha1Defines.v` (empty), `wpapsk/wpapsk.ise`, `wpapsk/Attic/`, `sha1/Sha1Top.v` (the bus wrapper of the SHA-1 core), `sha1/Sha1Test.v`, `sha1/sha1.ise`, `sha1/README` and `sha1/Sha1Defines.v`. Upstream's host computed the HMAC setup (ipad, opad and U1 of each block) and wrote it into the tables; hashcat's engine computes it on the device from the password and the ESSID instead.

### `sha1/Sha1.v`: `Sha1Full`

`sha1/Sha1.v` and `wpapsk/Sha1.v` both define `module Sha1`, and the design needs both: `wpapsk`'s is specialised for PBKDF2's 20-byte messages (it builds their padding and length itself), `sha1`'s compresses any 16-word block. `sha1/Sha1.v`'s module is renamed `Sha1Full`; nothing else in the file changes.

### `wpapsk/PBKDF2.v`: a clear accumulator on `Rst`

`PBKDF2.v` XORs every U into its outputs, `mac_Fo..mac_Jo`, and `Rst` reloads ipad, opad and U1 and restarts the count but leaves those outputs as they are. So every run after the first returned the previous run's result XORed with its own. A bench of the core alone, driven as the engine drives it, gave the right block for the first of 12 runs and wrong ones for the other 11; with the outputs cleared on `Rst`, all 12. How upstream's own bridge (`PBKDF2Bridge.v`) and host software lived with this was not followed further. An older LiteX port of this core made the same change. The five `<= 0` assignments are the whole change.

### Left as upstream wrote it

- `PBKDF2.v` starts one more SHA-1 compression in the cycle its count reaches the end (`Sha1Done & GoLatch` still starts the core), and a run started before that compression ends goes wrong: the core is busy and does not take the new run's first `Go`. The bench of the core alone found every restart 80 cycles or more after `Done` right, and restarts at 78 and fewer wrong. That is not changed in the core: the engine lets a pair rest 128 cycles after `Done` before it starts it again.

- Verilator's width warnings in both `Sha1.v` files: `WAddr0..3` (`T + 13`, `T + 8`, `T + 2`, `T`) and `WAddr4` (`T_0`) truncate the 7-bit round counter to 4 bits. They address the 16-word window of the message schedule, which wraps; that is intended.
- Non-blocking assignments in `PBKDF2.v`'s `initial` block, and the `//synthesis attribute init` comments (Xilinx XST) beside each register.

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/wpa2/hcfpga_wpa2_engine.v` | the setup unit (the HMAC setup on `Sha1Full`), the PBKDF2 pairs, the generation, the collector with two C2H records per candidate |
| `gateware/wpa2/hcfpga_wpa2_top.sv` | the datapath top |
| `gateware/wpa2_dma_wrapper.py` | the LiteX wrapper |
| `gateware/wpa2/tb_datapath.py`, `tb_dut.vh`, `wpa2_ref.py` | the datapath bench and its reference |
| `src/bridges/bridge_fpga_wpa2.c`, `src/bridges/fpga/hcfpga_wpa2_ref.h` | the bridge (bcrypt's with wpa2's specifics) and the canary's reference |
| `src/modules/module_75600.c`, `OpenCL/m75600-pure.cl`, `tools/test_modules/m75600.py` | mode 22000's module, kernel and test module, bridged |

Shared with every algorithm after bcrypt, identical in each: `hcfpga_*.py` and `hcfpga_iface.vh` here, the shared RTL and bench in `gateware/wpa2/`.

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. No board has been built yet.
