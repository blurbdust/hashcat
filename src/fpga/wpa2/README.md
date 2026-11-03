# wpa2 on FPGA

Hash mode 92500 (bridge `fpga_wpa2`) computes wpa2 (mode 22000's format) on an FPGA, on the shared hcfpga template (`src/fpga/common`). HCFPGA-TODO: one paragraph: where the core comes from and what it is.

Scaffolded by `src/fpga/common/new_fpga_algo.py --name wpa2 --mode 22000 --fpga-mode 92500 --core custom --pw-max 63 --digest-words 8 --digest-bytes 32 --grain 1 --salt-min 0 --salt-max 32 --iter-min 4095 --iter-max 4095`.

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/common/hcfpga_sim.py --algo wpa2`), which hashcat reaches through the litexbone transport.

## Layout

| Path | What |
|---|---|
| `gateware/wpa2/` | the core (see `PROVENANCE.md`) and the top around it |
| `gateware/wpa2/hcfpga_wpa2_top.sv` | datapath top: the shared feeder/collector (or this algorithm's), the cores, the end-of-batch tail |
| `gateware/wpa2_dma_wrapper.py` | the LiteX wrapper (an `HcfpgaDmaWrapper`) and its extra registers |
| `gateware/wpa2/tb_datapath.py`, `tb_dut.vh`, `wpa2_ref.py` | the datapath bench (`make -C src/fpga sim ALGO=wpa2`) and its reference |

Host side: `src/bridges/bridge_fpga_wpa2.c` (the hooks of `src/bridges/fpga/hcfpga_bridge.c`), `src/bridges/fpga/hcfpga_wpa2_ref.h` (the canary's reference), `src/modules/module_92500.c`, `OpenCL/m92500-pure.cl`, `tools/test_modules/m92500.py`.

## Decisions

HCFPGA-TODO: answer each, with the reason:

- Longest password: 63 bytes (why: ...).
- Salt length range and cost range the core computes.
- Digest: which bytes the device returns at C2H bytes 4.., in which order, and how the bridge turns them into hashcat's `digest_buf` words (`digest_from_c2h`); which byte indexes the comparator bitmap. Scaffolded with 2 C2H record(s) per candidate (`PARTS`, `c2h_parts`): more than 24 digest bytes take one record per 24.
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
src/fpga/common/hcfpga_sim.py --algo wpa2 --bridge uartbone --build-only
src/fpga/common/hcfpga_sim.py --algo wpa2 --bridge uartbone --no-build --uart-port 2430 &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 92500 hash.txt words.txt
```

The bench, which needs Verilator only: `make -C src/fpga sim ALGO=wpa2`.
