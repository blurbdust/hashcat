# sha256crypt on FPGA

Hash mode 97400 (bridge `fpga_sha256crypt`) computes sha256crypt (mode 7400's format) on an FPGA, on the shared hcfpga template (`src/fpga/common`). HCFPGA-TODO: one paragraph: where the core comes from and what it is.

Scaffolded by `src/fpga/common/new_fpga_algo.py --name sha256crypt --mode 7400 --core jtr-unit`. Every `HCFPGA-TODO` in this tree marks something the port has to decide or fill in; `grep -rn HCFPGA-TODO` lists what is left.

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/common/hcfpga_sim.py --algo sha256crypt`), which hashcat reaches through the litexbone transport.

## Layout

| Path | What |
|---|---|
| `gateware/sha256crypt/` | the core (see `PROVENANCE.md`) and the top around it |
| `gateware/sha256crypt/hcfpga_sha256crypt_top.sv` | datapath top: the shared feeder/collector (or this algorithm's), the cores, the end-of-batch tail |
| `gateware/sha256crypt_dma_wrapper.py` | the LiteX wrapper (an `HcfpgaDmaWrapper`) and its extra registers |
| `gateware/sha256crypt/tb_datapath.py`, `tb_dut.vh`, `sha256crypt_ref.py` | the datapath bench (`make -C src/fpga sim ALGO=sha256crypt`) and its reference |

Host side: `src/bridges/bridge_fpga_sha256crypt.c` (the hooks of `src/bridges/fpga/hcfpga_bridge.c`), `src/bridges/fpga/hcfpga_sha256crypt_ref.h` (the canary's reference), `src/modules/module_97400.c`, `OpenCL/m97400-pure.cl`, `tools/test_modules/m97400.py`.

## Decisions

HCFPGA-TODO: answer each, with the reason:

- Longest password: 32 bytes (why: ...).
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
src/fpga/common/hcfpga_sim.py --algo sha256crypt --bridge uartbone --build-only
src/fpga/common/hcfpga_sim.py --algo sha256crypt --bridge uartbone --no-build &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 97400 hash.txt words.txt
```

The bench, which needs Verilator only: `make -C src/fpga sim ALGO=sha256crypt`.
