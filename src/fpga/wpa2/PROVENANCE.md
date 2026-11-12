# wpa2 FPGA provenance

All of this design was written for hashcat. No part of it is OpenCiphers' any more: the engine that computes the PMK, its PBKDF2 pipes, the SHA-1 core of its setup unit, the datapath top, the LiteX wrapper, the Storey Peak target and the bench here, and the H2C intake, generation counter, end-of-batch tail, wrapper base, simulated board and bench they use (identical in every algorithm after bcrypt).

## History: OpenCiphers' cores

The first version of this port (up to commit `6a071f6d4`) was built around OpenCiphers' WPA-PSK cores (David Hulton, for Pico Computing, under the BSD license): the PBKDF2 core `wpapsk/PBKDF2.v` with the SHA-1 core and helpers it instantiates (`wpapsk/Sha1.v`, `Sha1BRAM.v`, `R.v`, `Add32.v`), and the general SHA-1 core `sha1/Sha1.v` (renamed `Sha1Full`) for the HMAC setup, taken from the project's CVS repository. That version of this file names the revisions and hashes taken, the license and the two changes made (the PBKDF2 core's accumulator cleared on `Rst`, the module rename).

Those cores compress a block in 83 cycles, one SHA-1 round a cycle on one set of registers, and a pair of PBKDF2 cores held one candidate for 8191 compressions. The engine was rewritten around an unrolled SHA-1 that does a compression a cycle (below), and the OpenCiphers files were removed with it. What the rewrite kept is hashcat's own work from the first version: the HMAC setup computed on the device from the password and the ESSID (upstream's host had computed it), the salt block's layout, the two-part result and the generation handling.

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/wpa2/hcfpga_wpa2_engine.v` | the engine: the setup unit (the HMAC setup on two `hcfpga_wpa2_sha1` cores), the hand-off of each candidate to a pipe, the flush on a framing reset, the thermal stop on the die temperature, the collector with two C2H records per candidate |
| `gateware/wpa2/hcfpga_wpa2_pipe.v` | one PBKDF2 pipe: 80 rounds, two a stage by default (or one), closed into a ring of 44 stages (or 84), 22 candidates in flight (or 42), both PMK blocks of each; the chains' midstates, accumulators and counts in memories, the result FIFO; an empty ring holds still |
| `gateware/wpa2/hcfpga_wpa2_round.v` | one stage of the pipe, one or two SHA-1 rounds, specialised for the PBKDF2 loop's 20-byte messages (message words 5..15 are constants) |
| `gateware/wpa2/hcfpga_wpa2_sha1.v` | the setup unit's SHA-1 compression of a full 512-bit block, a round a cycle |
| `gateware/wpa2/hcfpga_wpa2_top.sv` | the datapath top |
| `gateware/wpa2_dma_wrapper.py` | the LiteX wrapper |
| `gateware/wpa2/tb_datapath.py`, `tb_dut.vh`, `tb_restart.v`, `wpa2_ref.py` | the datapath bench, its restart bench (batches abandoned with candidates in flight) and the reference |
| `wpa2_storeypeak_dma.py`, `hcfpga_litepcie.py`, `hcfpga_stratixv.py`, `gateware/stratixv/hcfpga_sv_tsd.v` | the Microsoft Storey Peak (Stratix V) target, as the crypt(3) ports have it, with wpa2's tested build as its default |
| `src/bridges/bridge_fpga_wpa2.c`, `src/bridges/fpga/hcfpga_wpa2_ref.h` | the bridge (bcrypt's with wpa2's specifics) and the canary's reference |
| `src/modules/module_75600.c`, `OpenCL/m75600-pure.cl`, `tools/test_modules/m75600.py` | mode 22000's module, kernel and test module, bridged |

Shared with every algorithm after bcrypt, identical in each: the other `hcfpga_*.py` and `hcfpga_iface.vh` here, the shared RTL and bench in `gateware/wpa2/`.

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. Quartus Prime Standard for the Microsoft Storey Peak (Stratix V) target, `wpa2_storeypeak_dma.py`.
