# sha256crypt FPGA provenance

The sha256crypt computing unit in this design is John the Ripper's ZTEX sha256crypt unit, written by Denis Burykin: three SHA-256 cores, a 12-thread CPU that runs the sha256crypt program, and the engine that builds SHA-256 blocks from the CPU's instructions. hashcat uses it under its own permissive license and has modified it. Every file taken from it keeps its original header verbatim, and each modified file adds a notice under that header pointing here. This page lists every change.

The rest of the design was written for hashcat: the datapath top, the LiteX wrapper and the bench here, and the feeder, collector, generation counter, end-of-batch tail, wrapper base, simulated board and bench they use (identical in every algorithm after bcrypt).

## Origin

Upstream is **openwall/john**, `src/ztex/fpga-sha256crypt/sha256crypt/` and `src/ztex/fpga-sha256crypt/util/`, taken from commit `ad3c92343bfebf02bd36f893689f1e7223b02e58` (the design itself last changed upstream in `67997cbd7`, 2020-08-18). The files are Copyright (c) 2016-2018 Denis Burykin, as each header states, and carry the same permissive terms: "Redistribution and use in source and binary forms, with or without modification, are permitted."

The commit that imports them changes nothing but line endings (CRLF to LF), so `git diff` from that commit shows every hashcat change.

## Files taken from John the Ripper

All under `gateware/sha256crypt/`, in upstream's directories.

| File | Change |
|---|---|
| `cpu/program.vh`, `sha256core/sha256_Kt_bram.v`, `sha256engine/next_thread_num.v` | none |
| `util/sync.v`, `util/delay.v`, `util/log2.vh` | none |
| `sha256.vh` | `log2.vh` included |
| `util/asymm_bram.v` | `log2.vh` included |
| the 28 other files in `unit/`, `cpu/`, `sha256core/` and `sha256engine/` | the include path |
| `sha256core/shreg.v` | behavioural shift register instead of `SRL16E` (it includes nothing, so the include path does not apply) |

Not taken: upstream's packet layer (`pkt_comm/`), its arbiters (`arbiter_tx.v`, `arbiter_rx.v`), comparator (`comparator.v`, `xcrypt_cmp_config.v`), broadcast network (`bcast_net.v`), top (`sha256crypt.v`), the ZTEX shell (`ztex_inouttraffic/`), `main.vh`, `util/fifo_sync.v` and `util/regs2d.v` (the unit does not use them), the constraint and partition files, and the test benches (`sha256crypt_test.v`, `unit/sha256unit_test.v`, `sha256core/sha256core_test.v`, `sha256engine/sha256engine_test.v`). hashcat's feeder and collector replace the arbiters and the comparator.

### The include path

The files write `` `include "sha256.vh" `` where upstream writes `` `include "../sha256.vh" ``. It is the same file, found through an include path rather than a relative directory, as bcrypt and md5crypt do: the flat form also resolves where a tool copies HDL into a flat directory. `cpu/instruction.v` keeps its `` `include "program.vh" ``, found through the same path (`cpu/`).

### `log2.vh`

`sha256.vh` and `util/asymm_bram.v` include `log2.vh`, which defines the `` `MSB`` macro the unit files use. Upstream lists `log2.vh` (and `main.vh`) as global files in its ISE project instead, which other tools do not have. `log2.vh` has an include guard, so including it twice is harmless.

### `SIMULATION`

Unlike md5crypt's `md5.vh`, upstream's `sha256.vh` already defines `SIMULATION`, so nothing changed there. The name is upstream's and misleads: it selects the real, synthesisable cores, CPU and engine instead of the empty stubs upstream uses for its partitioned ISE flow.

### The shift register

Upstream's `shreg.v` instantiates the Xilinx `SRL16E` primitive once per bit, with the address fixed at `DEPTH-1`. That ties the cores to Xilinx and leaves Verilator without a model. It now holds the same delay line as a behavioural register array, zero at start as `SRL16E` with `INIT` 0 is, which Vivado and Quartus infer as shift register LUTs or registers. The ports and the delay are unchanged. This is md5crypt's `shreg.v` change, made the same way.

### Left as upstream wrote it

A Verilator lint of `sha256unit` alone shows width, implicit-net and unsigned-comparison warnings only, all in upstream code. One looks like a bug and is harmless: `unit/core_ctrl.v` writes `cnt == A | B` where `cnt == A | cnt == B` was meant, so `seq_num` is cleared every cycle; the next statement sets it on the cycles that matter, and the cores only sample it with `start`. md5crypt's `core_ctrl.v` has the same line. It is not changed here.

Apart from the changes above, the SHA-256 cores, the CPU and its sha256crypt program, the engine, the unit's input and output buffers and the thread scheduling are upstream's. The unit's I/O protocol is not documented upstream. What this design relies on is written up in the headers of `gateware/sha256crypt/hcfpga_jtr_unit_feed.v` and `hcfpga_jtr_unit_collect.v`.

## Other material derived from John the Ripper

| Where | Derived from |
|---|---|
| `gateware/sha256crypt/hcfpga_jtr_unit_feed.v` (shared), the unit packet | upstream `arbiter_tx.v`: the type byte, the 40-byte header (count, salt length, 16 salt bytes, 8 ID bytes, key length, 7 zero bytes) and the key rounded up to whole words |
| `gateware/sha256crypt/hcfpga_jtr_unit_collect.v` (shared), the unit read | upstream `arbiter_rx.v`: one `rd_en` cycle, the `2'b11` start marker, `RESULT_LEN/2 + 4` = 20 16-bit words two bits at a time, and the closing `2'b00` |

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/sha256crypt/hcfpga_sha256crypt_top.sv` | the datapath top: the shared parts sized for the sha256crypt unit |
| `gateware/sha256crypt_dma_wrapper.py` | the LiteX wrapper, an `HcfpgaDmaWrapper` with `salt_len` |
| `gateware/sha256crypt/tb_datapath.py`, `tb_dut.vh`, `sha256crypt_ref.py` | the datapath bench on the shared one, and its sha256crypt reference |

Shared with every algorithm after bcrypt, identical in each: `hcfpga_*.py` and `hcfpga_iface.vh` here, the shared RTL and bench in `gateware/sha256crypt/`.

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. No board has been built yet.
