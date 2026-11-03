# sha512crypt FPGA provenance

The sha512crypt computing unit in this design is John the Ripper's ZTEX sha512crypt unit, written by Denis Burykin: four SHA-512 cores, a 16-thread CPU that runs the sha512crypt program (and a Drupal7 program this design does not use), and the engine that builds SHA-512 blocks from the CPU's instructions. hashcat uses it under its own permissive license and has modified it. Every file taken from it keeps its original header verbatim, and each modified file adds a notice under that header pointing here. This page lists every change.

The rest of the design was written for hashcat: the datapath top, the LiteX wrapper and the bench here, and the feeder, collector, generation counter, end-of-batch tail, wrapper base, simulated board and bench they use (copies of the LiteX hashcat Guide's `template/shared/`, which every algorithm after bcrypt has).

## Origin

Upstream is **openwall/john**, `src/ztex/fpga-sha512crypt/sha512crypt/` and `src/ztex/fpga-sha512crypt/util/`, taken from commit `ad3c92343bfebf02bd36f893689f1e7223b02e58` (the files taken last changed upstream in `8182161a1`, 2019-02-02). The files are Copyright (c) 2016-2019 Denis Burykin, as each header states, and carry the same permissive terms: "Redistribution and use in source and binary forms, with or without modification, are permitted."

The commit that imports them changes nothing but line endings (CRLF to LF), so `git diff` from that commit shows every hashcat change.

## Files taken from John the Ripper

All under `gateware/sha512crypt/`, in upstream's directories. The set is the unit, `unit/sha512unit.v`, and every file it instantiates or includes, found by linting the unit alone.

| File | Change |
|---|---|
| `cpu/program.vh`, `sha512core/sha512_Kt_bram.v`, `sha512engine/next_thread_num.v`, `util/log2.vh` | none |
| `sha512.vh` | `log2.vh` included; `SIMULATION` defined |
| `util/asymm_bram.v` | `log2.vh` included |
| the 27 other files in `unit/`, `cpu/`, `sha512core/` and `sha512engine/` | the include path |
| `sha512core/shreg.v` | behavioural shift register instead of `SRL16E` (it includes nothing, so the include path does not apply) |

Not taken: upstream's packet layer (`pkt_comm/`), its arbiters (`arbiter_tx.v`, `arbiter_rx.v`), comparator (`comparator.v`, `xcrypt_cmp_config.v`), broadcast network (`bcast_net.v`), top (`sha512crypt.v`), the ZTEX shell (`ztex_inouttraffic/`), `main.vh`, `sha512core/ff32.v`, `util/sync.v`, `util/delay.v`, `util/fifo_sync.v` and `util/regs2d.v` (the unit does not instantiate them: `uob.v` uses `sync_pulse` only when `ASYNC` is set, and the unit leaves it clear), the constraint and partition files, and the test benches (`sha512crypt_test.v`, `unit/sha512unit_test.v`, `sha512core/core_test.v`). hashcat's feeder and collector replace the arbiters and the comparator.

### The include path

The files write `` `include "sha512.vh" `` where upstream writes `` `include "../sha512.vh" ``. It is the same file, found through an include path rather than a relative directory, as bcrypt, md5crypt and sha256crypt do: the flat form also resolves where a tool copies HDL into a flat directory. `cpu/instruction.v` keeps its `` `include "program.vh" ``, found through the same path (`cpu/`).

### `log2.vh`

`sha512.vh` and `util/asymm_bram.v` include `log2.vh`, which defines the `` `MSB`` macro the unit files use. Upstream lists `log2.vh` (and `main.vh`) as global files in its ISE project instead, which other tools do not have. `log2.vh` has an include guard, so including it twice is harmless.

### `SIMULATION`

Upstream's `sha512.vh` leaves `` `define SIMULATION`` commented out. Without it, `sha512core/core.v`, `ff16.v`, `ff64.v`, `add3.v`, `sha512engine/process_bytes.v` and `unit/unit_ctrl.v` define empty modules with the right ports: upstream's partitioned ISE flow fills them from netlists, and any other tool builds a unit that computes nothing, without an error. `sha512.vh` now defines it, as md5crypt's `md5.vh` does and sha256crypt's `sha256.vh` already did upstream. The name misleads: it selects the real, synthesisable cores, CPU and engine. It also turns on a few cycle counters in `cpu/cpu.v`, `cpu/thread_number.v` and `sha512engine/process_bytes.v` (`X_*`), which nothing reads and synthesis removes.

### The shift register

Upstream's `shreg.v` instantiates the Xilinx `SRL16E` primitive once per bit, with the address fixed at `DEPTH-1`. That ties the cores to Xilinx and leaves Verilator without a model. It now holds the same delay line as a behavioural register array, zero at start as `SRL16E` with `INIT` 0 is, which Vivado and Quartus infer as shift register LUTs or registers. The ports and the delay are unchanged. This is md5crypt's and sha256crypt's `shreg.v` change, made the same way; only the default `WIDTH` (64) differs, as upstream's does.

### Left as upstream wrote it

A Verilator lint of `sha512unit` alone (`-Wall`) shows no errors. Its warnings are all in upstream code: 78 width expansions and 7 truncations, implicit nets, unsigned comparisons with 0, unused signals and parameters, and style. Those in control logic were read:

- `sha512engine/create_blk.v`: `len_effective = in_len >= blk_left ? blk_left : in_len` truncates an 8-bit result to 4 bits; the result is at most `in_len`, which is 4 bits, so nothing is lost.
- `sha512engine/realign8_pad.v`: `wr_off = ~off_eq0 ? 4'd8 - in_off : ...` truncates to 3 bits; with `in_off` non-zero the value is 1 to 7.
- `sha512core/core.v`: `cnte - 6`, `cnte - 7 - 22`, `cnto - 9`, `output_cnt - 4` are cut to the address width on purpose (they index a 16-entry buffer modulo its size), and `cnte >= 0` is always true.
- `unit/core_ctrl.v`, `cpu/thread_number.v`, `sha512engine/next_thread_num.v`: counters compared with wider constants, harmless. sha512crypt's `core_ctrl.v` does not have the `cnt == A | B` slip of md5crypt's and sha256crypt's.
- `cpu/cpu.v`: `iop_sets_cf` is assigned with `=` inside a clocked block; md5crypt's and sha256crypt's CPUs do the same, and it only feeds `cpu_flags` through a port.

None changes behaviour hashcat relies on, so none is changed.

`unit/sha512unit.v` passes `N_CORES` to its cores but not to `unit_ctrl`, which takes the 4 of `sha512.vh`; the design keeps 4 cores per unit (see `README.md`), so the two agree.

Apart from the changes above, the SHA-512 cores, the CPU and its sha512crypt program, the engine, the unit's input and output buffers and the thread scheduling are upstream's. The unit's I/O protocol is not documented upstream. What this design relies on is written up in `README.md` and in the headers of `gateware/sha512crypt/hcfpga_jtr_unit_feed.v` and `hcfpga_jtr_unit_collect.v`.

## Other material derived from John the Ripper

| Where | Derived from |
|---|---|
| `gateware/sha512crypt/hcfpga_jtr_unit_feed.v` (shared), the unit packet | upstream `arbiter_tx.v`: the type byte, the 40-byte header (count, salt length, 16 salt bytes, 8 ID bytes, key length, 7 zero bytes) and the key rounded up to 64 bits |
| `gateware/sha512crypt/hcfpga_jtr_unit_collect.v` (shared), the unit read | upstream `arbiter_rx.v`: one `rd_en` cycle, the `2'b11` start marker, `RESULT_LEN/2 + 4` = 36 16-bit words two bits at a time, and the closing `2'b00` |

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/sha512crypt/hcfpga_sha512crypt_top.sv` | the datapath top |
| `gateware/sha512crypt_dma_wrapper.py` | the LiteX wrapper |
| `gateware/sha512crypt/tb_datapath.py`, `tb_dut.vh`, `sha512crypt_ref.py` | the datapath bench and its reference |

Shared with every algorithm after bcrypt, as copies of the LiteX hashcat Guide's `template/shared/` (see its README): `hcfpga_*.py` and `hcfpga_iface.vh` here, the shared RTL and bench in `gateware/sha512crypt/`. Until the layout change they were one `src/fpga/common/`.

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. No board has been built yet.
