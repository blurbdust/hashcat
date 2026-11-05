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
| `util/delay.v`, `util/log2.vh` | none |
| `util/sync.v` | `generate` around a module-level `if` (Quartus) |
| `sha256.vh` | `log2.vh` included |
| `util/asymm_bram.v` | `log2.vh` included; `asymm_bram_min_rd` keeps wide words written by one process (Quartus) |
| `unit/sha256unit.v`, `sha256engine/memory.v` | the include path; `generate` around module-level `if` blocks (Quartus) |
| `unit/uob.v` | the include path; `generate` around module-level `if` blocks; output ports' nonzero initial values set in the body (Quartus) |
| `cpu/thread_number.v`, `sha256core/sha256core.v`, `sha256engine/create_blk.v`, `sha256engine/procb_buf.v`, `sha256engine/process_bytes.v`, `unit/unit_input.v` | the include path; output ports' nonzero initial values set in the body (Quartus) |
| `unit/unit_ctrl.v` | the include path; `unit_ctrl_dummy` no longer drives its input `core_dout_en` (Quartus) |
| the 18 other files in `unit/`, `cpu/`, `sha256core/` and `sha256engine/` | the include path |
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

### Quartus

Quartus Prime Standard rejects three things in upstream's files that Vivado and Verilator accept, and silently drops a fourth. The changes leave the logic as it was.

- **Module-level `if` without `generate`.** Verilog-2005 allows a conditional generate block straight in a module body, but Quartus Standard stops with error 10170 ("expecting endmodule") unless it sits between `generate` and `endgenerate`. `util/sync.v` (`sync_sig`), `unit/sha256unit.v` (the unit controls), `unit/uob.v` (both `ASYNC` selections) and `sha256engine/memory.v` (the `N_CORES == 3` selection) now have the keywords around those blocks. Nothing inside them changed.
- **A memory written from several processes.** Upstream's `asymm_bram_min_rd` follows Xilinx's asymmetric block RAM template: a narrow memory, read one entry at a time, and written by one `always` block per narrow entry of the wide input. Quartus reports every entry as having multiple constant drivers (error 10028). The memory now holds one wide word per write address, written by one `always` block; narrow entry `{a, i}` of upstream's layout is slice `i` of word `a`. The read registers the word and the slice number when `rd_en` is high and selects the slice after the registers, so `dout` changes on the same edges with the same values as upstream's registered `dout`, and the power-up value is still `INIT`. Only `uob.v` uses it (256 words of 16 bits). `asymm_bram_min_wr`, unused here, is unchanged.
- **A dummy that drives an input.** `unit_ctrl_dummy`, the stand-in upstream uses for a unit marked dummy in `UNIT_CONF`, assigns 0 to its input port `core_dout_en`. Quartus stops on it with error 10231 although no unit here is a dummy (`UNIT_CONF` is 0). That one assignment is gone; the rest of the dummy, including its implicit nets, is upstream's.

- **Initial values in port declarations.** The unit has no reset; it starts from its registers' initial values. Many are written in the port list, as in `output reg thread_init = 1`. Quartus Standard ignores an initial value there, without a message, as Verilog and as SystemVerilog, while it honours the same value on a register declared in the module body or set by an `initial` statement. On the Storey Peak the first build of one unit returned no result: Quartus reported `thread_number`'s `thread_init`, which walks the 12 threads once at start, as "Stuck at GND", the threads were never set up, and every read of the unit failed its framing. With the change below the same build cracks. Every output port of a unit module that starts at a value other than 0 now has its value set by an `initial` statement right after the port list, and its port declaration no longer carries it: `thread_init` and `thread_num_ahead` (`cpu/thread_number.v`), `ready` (`sha256core/sha256core.v`, the real core), `save_wr_en` and `len` (`sha256engine/create_blk.v`), `lookup_empty` (`sha256engine/procb_buf.v`), `ts_wr_en` (`sha256engine/process_bytes.v`), `ready` and `empty` (`unit/unit_input.v`, `unit/uob.v`). Port initial values of 0, and registers upstream leaves without one (which Xilinx starts at 0), are left alone: by default Quartus may give such a register either power-up level (Power-Up Don't Care), so the Storey Peak target turns that off (`ALLOW_POWER_UP_DONT_CARE OFF`), and every register without a value Quartus reads starts at 0, as on Xilinx. The modules no unit uses (`delay`, `asymm_bram_min_wr`, `sha256core_dummy`) are unchanged.

Quartus warns about the Xilinx attributes (`RAM_STYLE`, `KEEP_HIERARCHY`, `SHREG_EXTRACT`, `FSM_EXTRACT`) and ignores them; they are left in place.

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

LiteX and Verilator for the simulated board, Verilator for the bench, and LiteX with Quartus Prime Standard 25.1 for the Microsoft Storey Peak (Stratix V, `sha256crypt_storeypeak_dma.py`).
