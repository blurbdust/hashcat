# descrypt FPGA provenance

HCFPGA-TODO: who wrote the core, under which license, and what hashcat changed. Every file taken from upstream keeps its original header verbatim, and each modified file adds a notice under that header pointing here.

## Origin

HCFPGA-TODO: the upstream repository and path, the commit, the copyright line and the license terms. The commit that imports the files changes nothing but line endings, so `git diff` from that commit shows every hashcat change.

## Files taken from upstream

| File | Change |
|---|---|
| HCFPGA-TODO | none |

Not taken: HCFPGA-TODO (upstream's packet layer, arbiters, comparator, board shell, constraints, benches).

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/descrypt/hcfpga_descrypt_top.sv` | the datapath top |
| `gateware/descrypt_dma_wrapper.py` | the LiteX wrapper |
| `gateware/descrypt/tb_datapath.py`, `tb_dut.vh`, `descrypt_ref.py` | the datapath bench and its reference |

Shared with every algorithm on the template: `src/fpga/common/` (see its README).

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. No board has been built yet.
