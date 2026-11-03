# descrypt FPGA provenance

The DES pipeline in this design is John the Ripper's ZTEX descrypt core, written by Denis Burykin: a ring of 16 registered DES rounds with the salt in the E-box, and the key preparation (crypt(3)'s 7-bit packing and permuted choice 1) its arbiter applies before a key enters the ring. hashcat uses them under their own permissive license and has changed one line of one header. Every file taken from upstream keeps its original header verbatim, and the modified file adds a notice under that header pointing here.

The rest of the design was written for hashcat: the engine (the ring's batch control, result banks, comparator and C2H records), the datapath top, the LiteX wrapper and the bench here, and the H2C intake, end-of-batch tail, wrapper base, simulated board and bench they use (identical in every algorithm after bcrypt).

## Origin

Upstream is **openwall/john**, `src/ztex/fpga-descrypt/descrypt/descrypt_core/`, taken from commit `ad3c92343bfebf02bd36f893689f1e7223b02e58` with `git archive` (the checkout the files came from had local edits in this directory, which were not taken). The files are Copyright (c) 2016, 2019 Denis Burykin, as each header states, and carry the same permissive terms: "Redistribution and use in source and binary forms, with or without modification, are permitted."

The commit that imports them changes nothing but line endings (CRLF to LF), so `git diff` from that commit shows every hashcat change.

## Files taken from John the Ripper

All under `gateware/descrypt/descrypt_core/`, upstream's directory.

| File | Change |
|---|---|
| `descrypt16.v`, `descrypt_round.v`, `rotate_1or2_pc2.v`, `des_loop.v`, `Eblock.v`, `SP_v2.v`, `IP1.v` | none: the DES ring |
| `crypt3_ascii2bin.v`, `pc1.v` | none: the key preparation upstream's `arbiter.v` instantiates |
| `descrypt.vh` | `COMPARE_35_BIT` off, so `HASH_MSB` is 63 (below) |

Not taken: upstream's core wrapper `descrypt_core.v` (the ring's control, a 35-bit binary-search comparator over up to 2047 hashes and a 4-bit serial output that reports only matches), `wrapper.v`, `core_dout_proc.v`, `arbiter.v`, `descrypt_unit.v`, `cmp_config.v`, `cmp_config_distrib.v`, the top `descrypt.v`, the candidate generators and packet layer (`pkt_comm/`), the ZTEX shell (`ztex_inouttraffic/`), `main.vh`, `util/`, the constraint and partition files and the test bench `descrypt_test.v`. hashcat compares on the host with its own bitmap prefilter on the device, so every result has to leave the ring; the engine replaces `descrypt_core.v`'s control and everything above it.

### `COMPARE_35_BIT`

Upstream's comparator compares the 35 low bits of each result ("64 is a remnant from earlier versions, may not work"), and `descrypt16`'s `hash_out` is `IP1_out[HASH_MSB:0]`, so with `COMPARE_35_BIT` the ring gives out only 35 of the 64 result bits. hashcat needs all 64 (mode 1500's digest is the whole block). The define is commented out, which makes `HASH_MSB` 63 and `DIN_MSB` 64; `descrypt16` is the only taken file that uses either, and its 64-bit output was checked against crypt(3) slot by slot before the engine was written. The "may not work" applies to upstream's comparator and core input bus, which are not taken.

### Lint

A Verilator lint of `descrypt16` alone is clean; `-Wall` adds style warnings only (a file name that does not match `descrypt_round0`, initial values on registers that are also assigned, the unused upper bits of `IP1_out` with the 35-bit define, `pc1`'s parity bits). No vendor primitives, no relative includes: the files include `descrypt.vh` by name, which the include path finds.

## Other material derived from John the Ripper

| Where | Derived from |
|---|---|
| `gateware/descrypt/hcfpga_descrypt_engine.v`, the ring's control | upstream `descrypt_core.v`: 16 keys on 16 consecutive cycles with `START_CRYPT`, `ENABLE_CRYPT` while the ring runs, 25 passes of 16 cycles, the results read from `hash_out` in the 16 cycles after; upstream `arbiter.v`: a short batch is filled with empty slots, never left waiting |
| `gateware/descrypt/hcfpga_descrypt_engine.v`, the key | upstream `pkt_comm/template_list.v`: a candidate's character k in bits 7k+6..7k of the 56-bit word (`CHAR_BITS` 7), zero past its end |

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/descrypt/hcfpga_descrypt_engine.v` | the engine: loader, per-ring control and two result banks, collector with the comparator |
| `gateware/descrypt/hcfpga_descrypt_top.sv` | the datapath top: the shared intake and end-of-batch tail around the engine |
| `gateware/descrypt_dma_wrapper.py` | the LiteX wrapper, an `HcfpgaDmaWrapper` with no extra register |
| `gateware/descrypt/tb_datapath.py`, `tb_dut.vh`, `descrypt_ref.py` | the datapath bench on the shared one, and its descrypt reference (crypt(3)'s DES from the tables) |

Shared with every algorithm after bcrypt, identical in each: `hcfpga_*.py` and `hcfpga_iface.vh` here, the shared RTL and bench in `gateware/descrypt/`.

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. No board has been built yet.
