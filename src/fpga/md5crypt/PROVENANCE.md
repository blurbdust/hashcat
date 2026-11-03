# md5crypt FPGA provenance

The md5crypt computing unit in this design is John the Ripper's ZTEX md5crypt unit, written by Denis Burykin: three MD5 cores, a 12-thread CPU that runs the md5crypt program, and the engine that builds MD5 blocks from the CPU's instructions. hashcat uses it under its own permissive license and has modified it. Every file taken from it keeps its original header verbatim, and each modified file adds a notice under that header pointing here. This page lists every change.

The rest of the design was written for hashcat: the feeder, the collector, the end-of-batch tail, the datapath top, the LiteX wrapper, the simulated board, the bench and the host interface. `README.md` describes it.

## Origin

Upstream is **openwall/john**, `src/ztex/fpga-md5crypt/md5crypt/` and `src/ztex/fpga-md5crypt/util/`. The files are Copyright (c) 2016-2018 Denis Burykin, as each header states, and carry the same permissive terms: "Redistribution and use in source and binary forms, with or without modification, are permitted."

The commit that imports them changes nothing but line endings (CRLF to LF), so `git diff` from that commit shows every hashcat change.

## Files taken from John the Ripper

All under `gateware/md5crypt/`.

| File | Change |
|---|---|
| `md5unit.v`, `unit_ctrl.v`, `core_ctrl.v`, `unit_input_async.v`, `uob16pq.v` | none |
| `cpu/program.vh`, `md5core/md5_Kt_bram.v`, `md5core/md5_Kt_dram.v`, `md5engine/next_thread_num.v` | none |
| `util/sync.v`, `util/delay.v`, `util/asymm_bram.v`, `util/log2.vh` | none |
| `md5.vh` | `SIMULATION` enabled, `log2.vh` included |
| the 23 other files in `cpu/`, `md5core/` and `md5engine/` | the include path |
| `md5core/shreg.v`, `md5core/shreg_ff.v` | behavioural shift registers instead of `SRL16E` |

Not taken: upstream's packet layer (`pkt_comm/`), its arbiters (`arbiter_tx.v`, `arbiter_rx.v`), comparator (`comparator.v`, `md5crypt_cmp_config.v`), broadcast network (`bcast_net.v`), top (`md5crypt.v`), the ZTEX shell (`ztex_inouttraffic/`), the constraint files and the test benches. hashcat's feeder and collector replace the arbiters and the comparator.

### The include path

The files write `` `include "md5.vh" `` where upstream writes `` `include "../md5.vh" ``. It is the same file, found through an include path rather than a relative directory, as bcrypt does: the flat form also resolves where a tool copies HDL into a flat directory.

### `SIMULATION`

`md5.vh` defines `SIMULATION`, which upstream leaves commented out. The name is upstream's and misleads: it selects the real, synthesisable cores, CPU and engine instead of the empty stubs upstream uses for its partitioned ISE flow.

### `log2.vh`

`md5.vh` includes `log2.vh`, which defines the `` `MSB`` macro every unit file uses. Upstream lists `log2.vh` as a global file in its ISE project instead, which other tools do not have.

### The shift registers

Upstream's `shreg.v` and `shreg_ff.v` instantiate the Xilinx `SRL16E` primitive once per bit, with the address fixed at `DEPTH-1` (`DEPTH-2` in `shreg_ff`). That ties the cores to Xilinx and leaves Verilator without a model. Both now hold the same delay line as a behavioural register array, zero at start as `SRL16E` with `INIT` 0 is, which Vivado and Quartus infer as shift register LUTs or registers. The ports, the delay and `shreg_ff`'s output register are unchanged.

Apart from the changes above, the MD5 cores, the CPU and its md5crypt program, the engine, the unit's input and output buffers and the thread scheduling are upstream's. The unit's I/O protocol is not documented upstream. What this design relies on is written up in `README.md` and in the headers of `hcfpga_md5crypt_feed.v` and `hcfpga_md5crypt_collect.v`.

## Other material derived from John the Ripper

| Where | Derived from |
|---|---|
| `gateware/md5crypt/hcfpga_md5crypt_feed.v`, the unit packet | upstream `arbiter_tx.v`: the type byte, the 40-byte header (count, salt length, 16 salt bytes, 8 ID bytes, key length, 7 zero bytes) and the key rounded up to whole words |
| `gateware/md5crypt/hcfpga_md5crypt_collect.v`, the unit read | upstream `arbiter_rx.v`: one `rd_en` cycle, the `2'b11` start marker, 12 16-bit words two bits at a time, and the closing `2'b00` |

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/md5crypt/hcfpga_md5crypt_top.sv` | the datapath top and the generation counter |
| `gateware/md5crypt/hcfpga_md5crypt_feed.v` | H2C record intake, unit selection and the unit packet |
| `gateware/md5crypt/hcfpga_md5crypt_collect.v` | unit polling, the generation check, the comparator bitmap and the C2H record |
| `gateware/md5crypt/hcfpga_c2h_eob.v` | retired count, end-of-batch record and granule padding, bcrypt's accounting on its own |
| `gateware/md5crypt_dma_wrapper.py` | the LiteX wrapper |
| `md5crypt_sim.py` | the simulated board |
| `hcfpga_abi.py` | a copy of bcrypt's ABI reader |
| `hcfpga_iface.vh` | the frame contract between host and gateware |
| `gateware/md5crypt/tb_datapath.v`, `tb_datapath.py`, `md5crypt_ref.py` | the datapath bench and its md5crypt reference |

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. No board has been built yet.
