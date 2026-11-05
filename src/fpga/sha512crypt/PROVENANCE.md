# sha512crypt FPGA provenance

The sha512crypt computing unit in this design is John the Ripper's ZTEX sha512crypt unit, written by Denis Burykin: four SHA-512 cores, a 16-thread CPU that runs the sha512crypt program (and a Drupal7 program this design does not use), and the engine that builds SHA-512 blocks from the CPU's instructions. hashcat uses it under its own permissive license and has modified it. Every file taken from it keeps its original header verbatim, and each modified file adds a notice under that header pointing here. This page lists every change.

The rest of the design was written for hashcat: the datapath top, the LiteX wrapper and the bench here, and the feeder, collector, generation counter, end-of-batch tail, wrapper base, simulated board and bench they use (identical in every algorithm after bcrypt).

## Origin

Upstream is **openwall/john**, `src/ztex/fpga-sha512crypt/sha512crypt/` and `src/ztex/fpga-sha512crypt/util/`, taken from commit `ad3c92343bfebf02bd36f893689f1e7223b02e58` (the files taken last changed upstream in `8182161a1`, 2019-02-02). The files are Copyright (c) 2016-2019 Denis Burykin, as each header states, and carry the same permissive terms: "Redistribution and use in source and binary forms, with or without modification, are permitted."

The commit that imports them changes nothing but line endings (CRLF to LF), so `git diff` from that commit shows every hashcat change.

## Files taken from John the Ripper

All under `gateware/sha512crypt/`, in upstream's directories. The set is the unit, `unit/sha512unit.v`, and every file it instantiates or includes, found by linting the unit alone.

| File | Change |
|---|---|
| `cpu/program.vh`, `sha512core/sha512_Kt_bram.v`, `sha512engine/next_thread_num.v`, `util/log2.vh` | none |
| `sha512.vh` | `log2.vh` included; `SIMULATION` defined |
| `util/asymm_bram.v` | `log2.vh` included; `asymm_bram_min_rd` keeps wide words written by one process (Quartus) |
| `unit/sha512unit.v` | the include path; `generate` around a module-level `if` block (Quartus) |
| `unit/uob.v` | the include path; `generate` around module-level `if` blocks; output ports' nonzero initial values set in the body (Quartus) |
| `cpu/thread_number.v`, `sha512core/core.v`, `sha512engine/create_blk.v`, `sha512engine/procb_buf.v`, `sha512engine/process_bytes.v`, `unit/core_ctrl.v`, `unit/unit_input.v` | the include path; output ports' nonzero initial values set in the body (Quartus) |
| `unit/unit_ctrl.v` | the include path; `unit_ctrl_dummy` no longer drives its input `core_dout_en` (Quartus) |
| the 17 other files in `unit/`, `cpu/`, `sha512core/` and `sha512engine/` | the include path |
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

### Quartus

Quartus Prime Standard rejects three things in upstream's files that Vivado and Verilator accept, and silently drops a fourth. The changes leave the logic as it was; the datapath bench gives the same results in the same number of cycles before and after them.

- **Module-level `if` without `generate`.** Verilog-2005 allows a conditional generate block straight in a module body, but Quartus Standard stops with error 10170 ("expecting endmodule") unless it sits between `generate` and `endgenerate`. `unit/sha512unit.v` (the unit controls) and `unit/uob.v` (both `ASYNC` selections) now have the keywords around those blocks. Nothing inside them changed.
- **A memory written from several processes.** Upstream's `asymm_bram_min_rd` follows Xilinx's asymmetric block RAM template: a narrow memory, read one entry at a time, and written by one `always` block per narrow entry of the wide input. Quartus reports every entry as having multiple constant drivers (error 10028). The memory now holds one wide word per write address, written by one `always` block; narrow entry `{a, i}` of upstream's layout is slice `i` of word `a`. The read registers the word and the slice number when `rd_en` is high and selects the slice after the registers, so `dout` changes on the same edges with the same values as upstream's registered `dout`, and the power-up value is still `INIT`. Only `uob.v` uses it (512 words of 16 bits). `asymm_bram_min_wr`, unused here, is unchanged.
- **A dummy that drives an input.** `unit_ctrl_dummy`, the stand-in upstream uses for a unit marked dummy in `UNIT_CONF`, assigns 0 to its input port `core_dout_en`. Quartus stops on it with error 10231 although no unit here is a dummy (`UNIT_CONF` is 0). That one assignment is gone; the rest of the dummy, including its implicit nets, is upstream's.
- **Initial values in port declarations.** The unit has no reset; it starts from its registers' initial values. Many are written in the port list, as in `output reg thread_init = 1`. Quartus Standard ignores an initial value there, without a message, while it honours the same value on a register declared in the module body or set by an `initial` statement (found on sha256crypt's unit, which returned nothing on the card; its `thread_init` was reported "Stuck at GND"). Every output port of a module the unit uses that starts at a value other than 0 now has its value set by an `initial` statement right after the port list, and its port declaration no longer carries it: `thread_init` and `thread_num_ahead` (`cpu/thread_number.v`), `ready` (`sha512core/core.v`, the real core), `save_wr_en` and `len` (`sha512engine/create_blk.v`), `lookup_empty` (`sha512engine/procb_buf.v`), `ts_wr_en` (`sha512engine/process_bytes.v`, the real module), `ctx_num` and `seq_num` (`unit/core_ctrl.v`), `ready` (`unit_input`) and `empty` (`unit_input_fifo`, `regNxW`) in `unit/unit_input.v`, and `ready` and `empty` (`unit/uob.v`). Port initial values of 0 (among them `process_bytes`'s `ts_wr`, `` `THREAD_STATE_NONE ``, and `add3`'s `o`, whose `IV` no instance sets), and registers upstream leaves without one (which Xilinx starts at 0), are left alone: by default Quartus may give such a register either power-up level (Power-Up Don't Care; the first build made `cpu.v`'s `comp_dout[9]`, only ever written with 1, a constant 1), so the Storey Peak target turns that off (`ALLOW_POWER_UP_DONT_CARE OFF`), and every register without a value Quartus reads starts at 0, as on Xilinx. The stand-ins compiled only without `SIMULATION` (`core`'s and `process_bytes`'s), `core_dummy` and `asymm_bram_min_wr`, none of which a unit here uses, are unchanged.

Quartus warns about the Xilinx attributes (`RAM_STYLE`, `KEEP_HIERARCHY`, `FSM_EXTRACT` and the like) and ignores them; they are left in place.

### Left as upstream wrote it

A Verilator lint of `sha512unit` alone (`-Wall`) shows no errors. Its warnings are all in upstream code: 78 width expansions and 7 truncations, implicit nets, unsigned comparisons with 0, unused signals and parameters, and style. Those in control logic were read:

- `sha512engine/create_blk.v`: `len_effective = in_len >= blk_left ? blk_left : in_len` truncates an 8-bit result to 4 bits; the result is at most `in_len`, which is 4 bits, so nothing is lost.
- `sha512engine/realign8_pad.v`: `wr_off = ~off_eq0 ? 4'd8 - in_off : ...` truncates to 3 bits; with `in_off` non-zero the value is 1 to 7.
- `sha512core/core.v`: `cnte - 6`, `cnte - 7 - 22`, `cnto - 9`, `output_cnt - 4` are cut to the address width on purpose (they index a 16-entry buffer modulo its size), and `cnte >= 0` is always true.
- `unit/core_ctrl.v`, `cpu/thread_number.v`, `sha512engine/next_thread_num.v`: counters compared with wider constants, harmless. sha512crypt's `core_ctrl.v` does not have the `cnt == A | B` slip of md5crypt's and sha256crypt's.
- `cpu/cpu.v`: `iop_sets_cf` is assigned with `=` inside a clocked block; md5crypt's and sha256crypt's CPUs do the same, and it only feeds `cpu_flags` through a port.

None changes behaviour hashcat relies on, so none is changed.

`unit/sha512unit.v` passes `N_CORES` to its cores but not to `unit_ctrl`, which takes the 4 of `sha512.vh`; the design keeps 4 cores per unit, so the two agree.

Apart from the changes above, the SHA-512 cores, the CPU and its sha512crypt program, the engine, the unit's input and output buffers and the thread scheduling are upstream's. The unit's I/O protocol is not documented upstream. What this design relies on is written up in the headers of `gateware/sha512crypt/hcfpga_jtr_unit_feed.v` and `hcfpga_jtr_unit_collect.v`.

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

Shared with every algorithm after bcrypt, identical in each: `hcfpga_*.py` and `hcfpga_iface.vh` here, the shared RTL and bench in `gateware/sha512crypt/`.

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. Quartus Prime Standard 25.1std for the Microsoft Storey Peak (Stratix V), `sha512crypt_storeypeak_dma.py`.
