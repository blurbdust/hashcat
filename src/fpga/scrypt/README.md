# scrypt on FPGA

Hash mode 98900 (bridge `fpga_scrypt`) computes scrypt (mode 8900's format) on an FPGA, on the shared hcfpga template (`src/fpga/common`). HCFPGA-TODO: one paragraph: where the core comes from and what it is.

Scaffolded by `src/fpga/common/new_fpga_algo.py --name scrypt --mode 8900 --core custom --pw-max 64 --digest-words 4 --digest-bytes 16 --grain 1 --salt-min 0 --salt-max 32 --iter-min 2 --iter-max 32768`.

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/common/hcfpga_sim.py --algo scrypt`), which hashcat reaches through the litexbone transport.

## Layout

| Path | What |
|---|---|
| `gateware/scrypt/` | the core (see `PROVENANCE.md`) and the top around it |
| `gateware/scrypt/hcfpga_scrypt_top.sv` | datapath top: the shared feeder/collector (or this algorithm's), the cores, the end-of-batch tail |
| `gateware/scrypt_dma_wrapper.py` | the LiteX wrapper (an `HcfpgaDmaWrapper`) and its extra registers |
| `gateware/scrypt/tb_datapath.py`, `tb_dut.vh`, `scrypt_ref.py` | the datapath bench (`make -C src/fpga sim ALGO=scrypt`) and its reference |

Host side: `src/bridges/bridge_fpga_scrypt.c` (the hooks of `src/bridges/fpga/hcfpga_bridge.c`), `src/bridges/fpga/hcfpga_scrypt_ref.h` (the canary's reference), `src/modules/module_98900.c`, `OpenCL/m98900-pure.cl`, `tools/test_modules/m98900.py`.

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
src/fpga/common/hcfpga_sim.py --algo scrypt --bridge uartbone --build-only
src/fpga/common/hcfpga_sim.py --algo scrypt --bridge uartbone --no-build --uart-port 2430 &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 98900 hash.txt words.txt
```

The bench, which needs Verilator only: `make -C src/fpga sim ALGO=scrypt`.
