# scrypt FPGA provenance

The scrypt computing unit in this design is LiteX-Scrypt's `scrypt_unit`: PBKDF2-HMAC-SHA256, ROMix over BlockMix and Salsa20/8 with the V table in block RAM, and PBKDF2 again, behind a byte-wide input FIFO and a 2-bit serial output in the style of John the Ripper's units. LiteX-Scrypt is the repository owner's own work. Its files carry no license header; they are offered here under the MIT license, as hashcat's FPGA code is. The unit's input FIFO (`util/fifo_sync.v`) and `util/log2.vh` are John the Ripper's, by Denis Burykin, under their own permissive terms. hashcat has modified the unit. Every file taken keeps its original header verbatim, and each modified file adds a notice under that header pointing here. This page lists every change.

The rest of the design was written for hashcat: the engine, the datapath top, the LiteX wrapper and the bench here, and the H2C intake, generation counter, JtR unit collector, end-of-batch tail, wrapper base, simulated board and bench they use from `src/fpga/common`, which every algorithm on the template shares.

## Origin

Upstream is the LiteX-Scrypt repository (`blurbdust/litex_scrypt`), `gateware/scrypt/` and `gateware/util/`. The files were taken from a checkout at commit `a2f24b3f645519f5fedb4f40a0606f6265425a71` with uncommitted edits to `scrypt/romix.v`, `scrypt/salsa20_8.v`, `scrypt/scrypt_unit.v` and `scrypt/main.vh` (the external V table option, `V_TABLE_EXTERNAL`, and the two-stage Salsa20/8). That working tree is the version this port is of, and no commit holds it, so the files are identified by their SHA-256 as taken:

| File | SHA-256 |
|---|---|
| `scrypt/scrypt_unit.v` | `76a93cc5f4c16d896c20488d1163a1f36c33a413717064039c7945eb2cac4e9b` |
| `scrypt/romix.v` | `0098a05234e9bc60f7c5ded707268e3755fe8b16d02557b892e546e2645d33e7` |
| `scrypt/v_table_bram.v` | `643bc1dfc073b726bfed82d31c2b1e4c84c5440417dd1dba99bf3f9637a96064` |
| `scrypt/blockmix.v` | `d1fb54c1bb2c03aac8df4223a44ea0eb7be0404e56f7151e9d37938ab0c620e5` |
| `scrypt/salsa20_8.v` | `491d2932f486ea8308cc141e2b8cc6edd8b70d39df082d65d79e9414ac84d48a` |
| `scrypt/pbkdf2_sha256.v` | `1b6de4c5a5fd7db3b927ec8e3b629355986d505ce347d83dc086b8e5e902db1c` |
| `scrypt/hmac_sha256.v` | `7ddc8df21ef51c97bb3beb82e21b4786b19e98e7954873d9e9cf2ca650b17ac8` |
| `scrypt/sha256_core.v` | `644c9beb77ba7b8bc732608f1b48d72756fbc977dff9f84c2fc75417b527aec2` |
| `scrypt/scrypt.vh` | `5df3a11b91c7309a5f48cf3ac12dabad6a094e771582b50f5e260e720da5c88d` |
| `scrypt/main.vh` | `52d590dce7308f8721228366af00652e8b677c7c62893c54f57aaec95f9c7fd1` |
| `util/fifo_sync.v` | `8bbb1641ace4defa6e8bd8ee04bea32cdf617cb0cdfc05250cdceb7b8e8bdaf2` |
| `util/log2.vh` | `aab08b866c85b73d909be8eb790b964250944a382fb4135c0e0f51841d424e90` |

`util/fifo_sync.v` and `util/log2.vh` are Copyright (c) 2016 Denis Burykin, as their headers state: "Redistribution and use in source and binary forms, with or without modification, are permitted."

The files already had LF line endings. The commit that imports them changes nothing, so `git diff` from that commit shows every hashcat change.

## Files taken from LiteX-Scrypt

All under `gateware/scrypt/`, in upstream's directories (`scrypt/`, `util/`). The set is the unit, `scrypt/scrypt_unit.v`, and every file it instantiates or includes, found by linting the unit alone.

| File | Change |
|---|---|
| `scrypt/scrypt.vh`, `scrypt/main.vh`, `util/fifo_sync.v`, `util/log2.vh` | none |
| `scrypt/v_table_bram.v` | one memory with a read enable (below, the V table) |
| `scrypt/salsa20_8.v`, `scrypt/hmac_sha256.v` | comments only: em dashes replaced by colons and commas, the project's style |
| `scrypt/blockmix.v` | the output index without a reversed range at `R` 1 (below, r at run time) |
| `scrypt/romix.v` | Integerify over the r values the build has (below, r at run time); the V table's read enable (below, the V table); a lookup gap (below); comment punctuation as above |
| `scrypt/pbkdf2_sha256.v` | r at run time, its blocks in `romix`'s byte order (below); comment punctuation as above |
| `scrypt/scrypt_unit.v` | `main.vh` included; full mode: byte order to and from `pbkdf2_sha256`, one start pulse per PBKDF2 call, r handed to `pbkdf2_sha256` (below); `GAP_LOG2` handed to `romix` (below, lookup gap); comment punctuation as above |
| `scrypt/sha256_core.v` | the message schedule of rounds 16 to 63 (below); comment punctuation as above |

Not taken: upstream's arbiters (`arbiter_tx.v`, `arbiter_rx.v`), comparator (`comparator.v`, `scrypt_cmp_config.v`), its stream top (`scrypt_axis_8b.sv`), the packet layer (`gateware/pkt_comm/`), the LiteX wrappers and the DDR3 V table controller (`gateware/*.py`), `util/SRL16E.v`, `util/asymm_bram.v`, `util/delay.v`, `util/ff32.v`, `util/sync.v` (the unit does not use them), the sim and board targets and the host scripts. hashcat's engine and the template's collector replace the arbiters and the comparator.

### `main.vh`

`scrypt_unit.v` takes its parameter defaults (`SCRYPT_R`, `N_LOG2_MAX`, `V_TABLE_EXTERNAL`) from `main.vh` without including it: upstream's LiteX wrapper adds `main.vh` as the first source, so the macros are global. The unit does not lint alone that way, so it now includes `main.vh` by name, found through the include path, as it already includes `scrypt.vh`. `main.vh` includes `log2.vh` by name.

### Full mode

hashcat uses the unit's full mode (`FULL_MODE` 1): password in, derived key out. Upstream's LiteX port only ran the SMix-only mode, where the host computes both PBKDF2 calls, and a bench of the unit alone against Python's `hashlib.scrypt` found that full mode computed no correct key. Three things were wrong, all fixed here; with them the unit agrees with `hashlib.scrypt` for every case the bench runs (keys of 0 to 64 bytes, salts of 0 to 32 bytes, N from 2 to 32768).

- **`sha256_core.v`: the message schedule.** Rounds 16 to 63 added `W[round mod 16]`, which still holds the word of round - 16, instead of the word expanded for this round (`W_new`, which the same cycle writes into that slot for later rounds). Every hash came out wrong (`SHA-256("abc")` gave `84c010ce...`). `Wt` now takes `W_new` from round 16 on.
- **`scrypt_unit.v`, `pbkdf2_sha256.v`: byte order.** `pbkdf2_sha256` took its key, its message and its result big-endian (byte 0 in the top bits, as SHA-256 reads a block); `romix` and the unit's registers keep byte 0 in bits 7:0 (the SMix-only mode feeds `romix` that way, and a bench of `romix` alone against a Python ROMix agreed, see `docs/fpga-porting-notes-scrypt.md`). The unit wired them together unchanged. The key is now stored byte 0 first in the top bits (SHA-256's order, as the HMAC pads want it), and `pbkdf2_sha256` takes `b_mixed` and gives `dk_out` in `romix`'s order: it turns each 64-byte block of `b_mixed` around as it hands it to SHA-256 and each 32-byte HMAC result around as it stores it. So the unit returns the key byte 0 first, as its SMix-only mode returns ROMix's result. (The first version of this fix turned the whole 128-byte blocks around in `scrypt_unit.v`; at 128 r bytes that reversal on `pbkdf2_sha256`'s input port cost Verilator a 1024-byte loop every cycle, most of a unit's simulation time.)
- **`scrypt_unit.v`: one start pulse per PBKDF2 call.** The unit held `pbkdf2_start_r` high until `done`. `pbkdf2_sha256` is idle again in the cycle its `done` shows and takes a start that is still high, so every call started a second, unwanted one, and the next call's `done` came from it. The start is now one cycle, set as the unit enters the state that waits for `done`, with the mode beside it.

The SMix-only path holds `romix_start` high until `done` in the same way (`ST_RUN`). hashcat does not use that mode, so it is left as upstream wrote it and was not checked.

The unit takes every payload byte before the 8 ID bytes as key and ignores the length (`pw_len_reg` is unused, `pbkdf2_sha256` ignores `password_len`). That is not changed: hashcat's engine sends the password zero filled to 64 bytes, which HMAC-SHA256 treats exactly as the password.

### r at run time

Upstream's `romix` and `blockmix` take r at run time up to their `R` parameter, but full mode was built for `R` 1: `pbkdf2_sha256` expanded the password and salt to exactly 128 bytes (4 HMAC blocks) and derived the key from exactly 128 bytes. hashcat's engine builds the unit with `R` = R_MAX (8) and sends the salt's r in the packet's r field (bytes 40..43), which the unit already parsed and handed to `romix`.

- **`pbkdf2_sha256.v`.** A parameter `R` and an input `r`, latched at start. EXPAND computes 4 r HMAC blocks, T(i) = HMAC (password, salt || INT32BE (i)) for i = 1..4 r, and stores T(i) at bytes 32 (i - 1).. of `dk_out` (`1024 R` bits wide). DERIVE hashes the inner chain ipad, the 2 r 64-byte blocks of `b_mixed`, then INT32BE (1) with the padding, whose length is (64 + 128 r + 4) * 8 bits (upstream had the r = 1 value, 0x620, fixed); then the outer chain as before. `b_mixed` is no longer copied into a register: the unit's `romix` output holds still until the next candidate, so `pbkdf2_sha256` reads its blocks from the port (1024 R flip-flops fewer).
- **`scrypt_unit.v`.** `pbkdf2_sha256` is built with the unit's `R` and given the packet's r (`r_reg_raw`), as `romix` already was.
- **`blockmix.v`.** The output index used `round_cnt[IDX_BITS-1:1]`, a reversed range at `R` = 1 (`round_cnt[0:1]` of a 1-bit counter). Verilator read it as 0, the right index, but a synthesis tool may refuse it. It is now `round_cnt >> 1`, and the r it adds is zero extended to the index's width (wider than r at `R` 3, 5, 6 and 7).
- **`romix.v`.** Integerify picked the word of the last 64-byte block by a case with arms for r = 1 to 8, which select past the end of `X` when `R` is below 8 (never taken, but constant out-of-range selects a synthesis tool may refuse). It is now a loop over the r values 2..`R` the build has, every select inside `X`.

With these the unit agrees with `hashlib.scrypt` for r = 1 to 8 (`tb_datapath.py`'s `rs`, `rcosts` and `example` cases: every r with salts of 4 r bytes, the longest key and the canary; r = 8 at N = 2 and 1024, then r = 1 on the same units; mode 8900's example hash, N = 16384, r = 8).

### The V table

`v_table_bram.v` built the table as `WIDTH / 32` memories of 32 bits, each read every cycle. At `R` 8 that is 256 memories per unit, and Verilator spent most of a unit's simulation time reading them (a profile of the bench showed the 512 read blocks of its two units on top; it ran at about 30 kHz). Quartus merges the 32-bit slices into one `WIDTH`-bit memory anyway, as its RAM summary for `WIDTH` 1024 shows. It is now one memory `WIDTH` bits wide with a read enable, `re`: `rdata` takes `mem[raddr]` in a cycle with `re` high and holds otherwise, which a block RAM's read enable does too. `romix.v` raises `re` for the one cycle in which upstream's table read `V[j]` (the cycle after `ST_MIX_ADDR` registers the address), so `rdata` holds `V[j]` from `ST_MIX_READ2` on as before. The bench runs at 110 to 180 kHz at `R` 8 since.

### Lookup gap

A time-memory trade-off for boards whose block RAM is short: `romix.v` takes a parameter `GAP_LOG2` (G = 2^`GAP_LOG2`, hashcat builds 1, 2, 4 or 8), and `scrypt_unit.v` passes its own down. With G above 1 the fill stores V[i] only when i mod G is 0, at address i / G, so the table is 2^(`N_LOG2_MAX` - `GAP_LOG2`) blocks deep, G times smaller. In the mix a read of V[j] loads V[j - j mod G] from address j / G and runs it through BlockMix j mod G times (a new state, `ST_MIX_RECOMP`, on the unit's one BlockMix) before X is mixed in. A step of the mix costs (G - 1) / 2 BlockMix calls more on average, so a candidate takes about 1 + (G - 1) / 4 times as long: 1.25, 1.74 and 2.74 times at N = 16384, r = 8 for G = 2, 4 and 8. G = 1 is upstream's ROMix, cycle for cycle. The gap applies to the block RAM table only; the external table's state machine (`V_TABLE_EXTERNAL` 1) is unchanged and stores every block.

### Left as upstream wrote it

A Verilator lint of `scrypt_unit` alone (`-Wall`, `FULL_MODE` 0 and 1) shows no errors. Its warnings are all in upstream code: width expansions and truncations, out-of-range selects, incomplete cases, unused signals and parameters, and style. Those in control logic were read:

- `scrypt/blockmix.v`: `{r_actual, 1'b0}` (2 r) is zero extended where it meets wider operands (`num_blocks_r`, the start block's index); harmless.
- `scrypt/scrypt_unit.v`: `pw_len_reg <= in_byte_cnt - 53` is cut to 8 bits; nothing reads it, and `pbkdf2_sha256.v` ignores its `password_len` port. The key is the 64 bytes the unit receives before the IDs, which is why hashcat's engine always sends 64.
- `scrypt/sha256_core.v`: the schedule's `(round - k) & 4'hF` and `K[round]` are wider than their targets on purpose (indices modulo 16 and 64).
- `util/fifo_sync.v`: `inptr + 2'b10` in John the Ripper's FIFO address arithmetic, harmless.

None of these changes behaviour hashcat relies on in simulation, so none is changed.

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/scrypt/hcfpga_scrypt_engine.v` | the engine: the units, the transmitter, the generation, the shared JtR collector |
| `gateware/scrypt/hcfpga_scrypt_top.sv` | the datapath top |
| `gateware/scrypt_dma_wrapper.py` | the LiteX wrapper |
| `gateware/scrypt/tb_datapath.py`, `tb_dut.vh`, `scrypt_ref.py` | the datapath bench and its reference |

Shared with every algorithm on the template: `src/fpga/common/` (see its README).

## Other material derived from LiteX-Scrypt

| Where | Derived from |
|---|---|
| `gateware/scrypt/hcfpga_scrypt_engine.v`, the unit packet | `scrypt_unit.v`'s header comment and its receive state: a type byte with `ctrl`, the 44 configuration bytes upstream's `arbiter_tx.v` reads from `scrypt_cmp_config.v` (log2 (N), salt length, 32 salt bytes, r), the payload, 8 ID bytes, an end byte with `ctrl` |
| `src/fpga/common/rtl/hcfpga_jtr_unit_collect.v` (shared), the unit read | the unit's output states, which follow John the Ripper's `arbiter_rx.v`: one `rd_en` cycle, `2'b11`, `4 + 32/2` 16-bit words two bits at a time, `2'b00` |

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. No board has been built yet.
