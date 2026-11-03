# descrypt on FPGA

Hash mode 91500 (bridge `fpga_descrypt`) computes descrypt (mode 1500's format) on an FPGA, on the shared hcfpga template (`src/fpga/common`). HCFPGA-TODO: one paragraph: where the core comes from and what it is.

Scaffolded by `src/fpga/common/new_fpga_algo.py --name descrypt --mode 1500 --core custom`.

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/common/hcfpga_sim.py --algo descrypt`), which hashcat reaches through the litexbone transport.

## Layout

| Path | What |
|---|---|
| `gateware/descrypt/` | the core (see `PROVENANCE.md`) and the top around it |
| `gateware/descrypt/hcfpga_descrypt_top.sv` | datapath top: the shared feeder/collector (or this algorithm's), the cores, the end-of-batch tail |
| `gateware/descrypt_dma_wrapper.py` | the LiteX wrapper (an `HcfpgaDmaWrapper`) and its extra registers |
| `gateware/descrypt/tb_datapath.py`, `tb_dut.vh`, `descrypt_ref.py` | the datapath bench (`make -C src/fpga sim ALGO=descrypt`) and its reference |

Host side: `src/bridges/bridge_fpga_descrypt.c` (the hooks of `src/bridges/fpga/hcfpga_bridge.c`), `src/bridges/fpga/hcfpga_descrypt_ref.h` (the canary's reference), `src/modules/module_91500.c`, `OpenCL/m91500-pure.cl`, `tools/test_modules/m91500.py`.

## Decisions

HCFPGA-TODO: answer each, with the reason:

- Longest password: 8 bytes (why: ...).
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
src/fpga/common/hcfpga_sim.py --algo descrypt --bridge uartbone --build-only
src/fpga/common/hcfpga_sim.py --algo descrypt --bridge uartbone --no-build &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 91500 hash.txt words.txt
```

The bench, which needs Verilator only: `make -C src/fpga sim ALGO=descrypt`.
