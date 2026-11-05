# md5crypt FPGA provenance

The md5crypt computing unit in this design is John the Ripper's ZTEX md5crypt unit, written by Denis Burykin: three MD5 cores, a 12-thread CPU that runs the md5crypt program, and the engine that builds MD5 blocks from the CPU's instructions. hashcat uses it under its own permissive license and has modified it. Every file taken from it keeps its original header verbatim, and each modified file adds a notice under that header pointing here. This page lists every change.

The rest of the design was written for hashcat: the datapath top, the LiteX wrapper and the bench here, and the feeder, collector, end-of-batch tail, wrapper base, simulated board and bench they use (identical in every algorithm after bcrypt).

## Origin

Upstream is **openwall/john**, `src/ztex/fpga-md5crypt/md5crypt/` and `src/ztex/fpga-md5crypt/util/`. The files are Copyright (c) 2016-2018 Denis Burykin, as each header states, and carry the same permissive terms: "Redistribution and use in source and binary forms, with or without modification, are permitted."

The commit that imports them changes nothing but line endings (CRLF to LF), so `git diff` from that commit shows every hashcat change.

## Files taken from John the Ripper

All under `gateware/md5crypt/`.

| File | Change |
|---|---|
| `core_ctrl.v` | none |
| `cpu/program.vh`, `md5core/md5_Kt_bram.v`, `md5core/md5_Kt_dram.v`, `md5engine/next_thread_num.v` | none |
| `util/delay.v`, `util/log2.vh` | none |
| `md5.vh` | `SIMULATION` enabled, `log2.vh` included |
| `md5unit.v`, `util/sync.v` | `generate` around a module-level `if` (Quartus) |
| `md5engine/memory.v` | the include path; `generate` around a module-level `if` (Quartus) |
| `unit_ctrl.v` | `unit_ctrl_dummy` no longer drives its inputs `core_dout_en` and `core_dout_seq` (Quartus) |
| `util/asymm_bram.v` | `asymm_bram_min_rd` keeps one wide word per write address, written by one process (Quartus) |
| `unit_input_async.v`, `uob16pq.v` | nonzero initial values moved from the port list to `initial` (Quartus) |
| `cpu/thread_number.v`, `md5core/md5core.v`, `md5engine/create_blk.v`, `md5engine/process_bytes.v` | the include path; nonzero initial values moved from the port list to `initial` (Quartus) |
| the 18 other files in `cpu/`, `md5core/` and `md5engine/` | the include path |
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

### Quartus

Quartus Prime Standard rejects three things in upstream's files that Vivado and Verilator accept, and builds a fourth differently. The changes leave the logic as it was.

- **Module-level `if` without `generate`.** Verilog-2005 allows a conditional generate block straight in a module body, but Quartus Standard stops with error 10170 ("expecting endmodule") unless it sits between `generate` and `endgenerate`. `util/sync.v` (`sync_sig`'s `CLK1` selection), `md5unit.v` (the unit controls) and `md5engine/memory.v` (the `N_CORES == 3` selection) now have the keywords around those blocks. Nothing inside them changed.
- **A memory written from several processes.** Upstream's `asymm_bram_min_rd` follows Xilinx's asymmetric block RAM template: a narrow memory, read one entry at a time, and written by one `always` block per narrow entry of the wide input. Quartus reports every entry as having multiple constant drivers (error 10028). The memory is now an array of wide words, each a packed array of `RATIO` narrow entries, written whole by one `always` block; narrow entry `{a, i}` of upstream's layout is entry `i` of word `a`. The read takes `mem[a][i]` into the registered `dout` when `rd_en` is high, as upstream's does, so `dout` changes on the same edges with the same values and still powers up to `INIT`. This is Quartus's own mixed-width RAM template. Only `uob16pq.v` uses the module (256 words of 16 bits, read 2 bits at a time). `asymm_bram_min_wr`, unused here, is unchanged.
- **A dummy that drives its inputs.** `unit_ctrl_dummy`, the stand-in upstream uses for a unit marked dummy in `UNIT_CONF`, assigns 0 to its input ports `core_dout_en` and `core_dout_seq`. Quartus stops on it with error 10231 although no unit here is a dummy (`hcfpga_md5crypt_top.sv` passes `UNIT_CONF` 0). Those two assignments are gone; the rest of the dummy is upstream's.
- **Initial values in a port list.** The units have no reset: every register starts from its declared initial value, as on Xilinx parts, where a register without one starts at 0. Quartus Standard drops an initial value written in an ANSI port declaration (`output reg ready = 1`), and by default (`ALLOW_POWER_UP_DONT_CARE` on) lets synthesis start a register with no usable initial value at either level. A unit built that way can hang with no results. Every nonzero initial value in the port list of a module this design instantiates is now set by an `initial` statement right after the port list instead: `ready` and `empty` in `unit_input_async` and `uob16pq`, `thread_num_ahead` (1) and `thread_init` in `thread_number`, `ready` (`4'b1111`) in `md5core`, `rotate_opt` (`4'b1010`) in `cnto2rotate_opt`, `save_wr_en` and `len` (4) in `create_blk`, and `ts_wr_en` in `process_bytes`. The values are upstream's. The Storey Peak target sets `ALLOW_POWER_UP_DONT_CARE` off, so every register without an initial value, including those whose port-list value is 0, starts at 0. Port-list values that are parameters (`INIT` in `shreg_ff`, `asymm_bram`, `delay`, `IV` in `add3`) are 0 everywhere this design uses them and are left in place. So are those of modules this design never instantiates (`md5core_type1`, `md5core_type2`, `md5core_dummy`, and the stand-ins in the `else` branches of `` `ifdef SIMULATION``).

Quartus warns about the Xilinx attributes (`RAM_STYLE`, `KEEP_HIERARCHY`, `SHREG_EXTRACT`, `FSM_EXTRACT`) and ignores them; they are left in place. Its warnings about implicit nets are about upstream's one-bit control signals connected to ports without a declaration, which every tool creates as one-bit wires.

Apart from the changes above, the MD5 cores, the CPU and its md5crypt program, the engine, the unit's input and output buffers and the thread scheduling are upstream's. The unit's I/O protocol is not documented upstream. What this design relies on is written up in the headers of `gateware/md5crypt/hcfpga_jtr_unit_feed.v` and `hcfpga_jtr_unit_collect.v`.

## Other material derived from John the Ripper

| Where | Derived from |
|---|---|
| `gateware/md5crypt/hcfpga_jtr_unit_feed.v` (shared, started here as `hcfpga_md5crypt_feed.v`), the unit packet | upstream `arbiter_tx.v`: the type byte, the 40-byte header (count, salt length, 16 salt bytes, 8 ID bytes, key length, 7 zero bytes) and the key rounded up to whole words |
| `gateware/md5crypt/hcfpga_jtr_unit_collect.v` (shared, started here as `hcfpga_md5crypt_collect.v`), the unit read | upstream `arbiter_rx.v`: one `rd_en` cycle, the `2'b11` start marker, 12 16-bit words two bits at a time, and the closing `2'b00` |

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/md5crypt/hcfpga_md5crypt_top.sv` | the datapath top: the shared parts sized for the md5crypt unit |
| `gateware/md5crypt_dma_wrapper.py` | the LiteX wrapper, an `HcfpgaDmaWrapper` with `salt_len` |
| `gateware/md5crypt/tb_dut.vh`, `tb_datapath.py`, `md5crypt_ref.py` | the datapath bench on the shared one, and its md5crypt reference |

Shared with every algorithm after bcrypt, identical in each: the H2C intake, the JtR unit feeder and collector, the generation counter, the end-of-batch tail, the frame contract (`rtl/hcfpga_iface.vh`), the ABI reader, the wrapper base, HcfpgaMemStream, the simulated board and the bench.

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. LiteX, LitePCIe and Quartus Prime Standard 25.1std for the Microsoft Storey Peak (`md5crypt_storeypeak_dma.py`), the only board built so far.
