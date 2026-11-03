# sha512crypt on FPGA

Hash mode 91800 (bridge `fpga_sha512crypt`) computes sha512crypt (mode 1800's format) on an FPGA, on the shared hcfpga template (`src/fpga/common`). HCFPGA-TODO: one paragraph: where the core comes from and what it is.

Scaffolded by `src/fpga/common/new_fpga_algo.py --name sha512crypt --mode 1800 --core jtr-unit`.

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/common/hcfpga_sim.py --algo sha512crypt`), which hashcat reaches through the litexbone transport.

## Layout

| Path | What |
|---|---|
| `gateware/sha512crypt/` | the core (see `PROVENANCE.md`) and the top around it |
| `gateware/sha512crypt/hcfpga_sha512crypt_top.sv` | datapath top: the shared feeder/collector (or this algorithm's), the cores, the end-of-batch tail |
| `gateware/sha512crypt_dma_wrapper.py` | the LiteX wrapper (an `HcfpgaDmaWrapper`) and its extra registers |
| `gateware/sha512crypt/tb_datapath.py`, `tb_dut.vh`, `sha512crypt_ref.py` | the datapath bench (`make -C src/fpga sim ALGO=sha512crypt`) and its reference |

Host side: `src/bridges/bridge_fpga_sha512crypt.c` (the hooks of `src/bridges/fpga/hcfpga_bridge.c`), `src/bridges/fpga/hcfpga_sha512crypt_ref.h` (the canary's reference), `src/modules/module_91800.c`, `OpenCL/m91800-pure.cl`, `tools/test_modules/m91800.py`.

## Decisions

HCFPGA-TODO: answer each, with the reason:

- Longest password: 64 bytes (why: ...).
- Salt length range and cost range the core computes.
- Digest: which bytes the device returns at C2H bytes 4.., in which order, and how the bridge turns them into hashcat's `digest_buf` words (`digest_from_c2h`); which byte indexes the comparator bitmap.
- What `core_id` names (a core, or a unit when the unit picks the thread).
- Can the core be reset in the middle of a job? If not, the generation (`hcfpga_gen.v`) rides in the candidate and stale results are dropped.
- Extra registers from 0x3c, in order.
- Batch grain: candidates in flight per identity core (`grain_per_core`).

## Registers

The shared block (`src/fpga/common/hcfpga_dma_wrapper.py`), plus:

| Offset | Name | Use |
|---|---|---|
| 0x3c | HCFPGA-TODO | |

## Limits

HCFPGA-TODO.

## Running it in simulation

```
src/fpga/common/hcfpga_sim.py --algo sha512crypt --bridge uartbone --build-only
src/fpga/common/hcfpga_sim.py --algo sha512crypt --bridge uartbone --no-build &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 91800 hash.txt words.txt
```

The bench, which needs Verilator only: `make -C src/fpga sim ALGO=sha512crypt`.
