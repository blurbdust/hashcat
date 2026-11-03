# scrypt FPGA provenance

The scrypt computing unit in this design is LiteX-Scrypt's `scrypt_unit`: PBKDF2-HMAC-SHA256, ROMix over BlockMix and Salsa20/8 with the V table in block RAM, and PBKDF2 again, behind a byte-wide input FIFO and a 2-bit serial output in the style of John the Ripper's units. LiteX-Scrypt is the repository owner's own work. Its files carry no license header; they are offered here under the MIT license, as hashcat's FPGA code is. The unit's input FIFO (`util/fifo_sync.v`) and `util/log2.vh` are John the Ripper's, by Denis Burykin, under their own permissive terms. hashcat has modified the unit. Every file taken keeps its original header verbatim, and each modified file adds a notice under that header pointing here. This page lists every change.

The rest of the design was written for hashcat: the engine, the datapath top, the LiteX wrapper and the bench here, and the H2C intake, generation counter, JtR unit collector, end-of-batch tail, wrapper base, simulated board and bench they use (copies of the LiteX hashcat Guide's `template/shared/`, which every algorithm after bcrypt has).

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
| `scrypt/v_table_bram.v`, `scrypt/blockmix.v`, `scrypt/scrypt.vh`, `scrypt/main.vh`, `util/fifo_sync.v`, `util/log2.vh` | none |
| `scrypt/romix.v`, `scrypt/salsa20_8.v`, `scrypt/pbkdf2_sha256.v`, `scrypt/hmac_sha256.v` | comments only: em dashes replaced by colons and commas, the project's style |
| `scrypt/scrypt_unit.v` | `main.vh` included; full mode: byte order to and from `pbkdf2_sha256`, one start pulse per PBKDF2 call (below); comment punctuation as above |
| `scrypt/sha256_core.v` | the message schedule of rounds 16 to 63 (below); comment punctuation as above |

Not taken: upstream's arbiters (`arbiter_tx.v`, `arbiter_rx.v`), comparator (`comparator.v`, `scrypt_cmp_config.v`), its stream top (`scrypt_axis_8b.sv`), the packet layer (`gateware/pkt_comm/`), the LiteX wrappers and the DDR3 V table controller (`gateware/*.py`), `util/SRL16E.v`, `util/asymm_bram.v`, `util/delay.v`, `util/ff32.v`, `util/sync.v` (the unit does not use them), the sim and board targets and the host scripts. hashcat's engine and the template's collector replace the arbiters and the comparator.

### `main.vh`

`scrypt_unit.v` takes its parameter defaults (`SCRYPT_R`, `N_LOG2_MAX`, `V_TABLE_EXTERNAL`) from `main.vh` without including it: upstream's LiteX wrapper adds `main.vh` as the first source, so the macros are global. The unit does not lint alone that way, so it now includes `main.vh` by name, found through the include path, as it already includes `scrypt.vh`. `main.vh` includes `log2.vh` by name.

### Full mode

hashcat uses the unit's full mode (`FULL_MODE` 1): password in, derived key out. Upstream's LiteX port only ran the SMix-only mode, where the host computes both PBKDF2 calls, and a bench of the unit alone against Python's `hashlib.scrypt` found that full mode computed no correct key. Three things were wrong, all fixed here; with them the unit agrees with `hashlib.scrypt` for every case the bench runs (keys of 0 to 64 bytes, salts of 0 to 32 bytes, N from 2 to 32768).

- **`sha256_core.v`: the message schedule.** Rounds 16 to 63 added `W[round mod 16]`, which still holds the word of round - 16, instead of the word expanded for this round (`W_new`, which the same cycle writes into that slot for later rounds). Every hash came out wrong (`SHA-256("abc")` gave `84c010ce...`). `Wt` now takes `W_new` from round 16 on.
- **`scrypt_unit.v`: byte order.** `pbkdf2_sha256` takes its key, its message and its result big-endian (byte 0 in the top bits, as SHA-256 reads a block); `romix` and the unit's registers keep byte 0 in bits 7:0 (the SMix-only mode feeds `romix` that way, and a bench of `romix` alone against a Python ROMix agreed, see the LiteX hashcat Guide, `ports/scrypt/porting-notes.md`). The unit wired them together unchanged. The key is now stored byte 0 first in the top bits, and `rev_bytes128`/`rev_bytes32` turn the 128-byte blocks between `pbkdf2_sha256` and `romix` and the 32-byte derived key around, so the unit returns the key byte 0 first, as its SMix-only mode returns ROMix's result.
- **`scrypt_unit.v`: one start pulse per PBKDF2 call.** The unit held `pbkdf2_start_r` high until `done`. `pbkdf2_sha256` is idle again in the cycle its `done` shows and takes a start that is still high, so every call started a second, unwanted one, and the next call's `done` came from it. The start is now one cycle, set as the unit enters the state that waits for `done`, with the mode beside it.

The SMix-only path holds `romix_start` high until `done` in the same way (`ST_RUN`). hashcat does not use that mode, so it is left as upstream wrote it and was not checked.

The unit takes every payload byte before the 8 ID bytes as key and ignores the length (`pw_len_reg` is unused, `pbkdf2_sha256` ignores `password_len`). That is not changed: hashcat's engine sends the password zero filled to 64 bytes, which HMAC-SHA256 treats exactly as the password.

### Left as upstream wrote it

A Verilator lint of `scrypt_unit` alone (`-Wall`, `FULL_MODE` 0 and 1) shows no errors. Its warnings are all in upstream code: width expansions and truncations, out-of-range selects, incomplete cases, unused signals and parameters, and style. Those in control logic were read:

- `scrypt/blockmix.v`: with `R` = 1 the output index `round_cnt[IDX_BITS-1:1]` is `round_cnt[0:1]` of a 1-bit counter. Verilator reads it as 0, which is the right index (the bench checks BlockMix through ROMix and full scrypt); a synthesis tool may refuse the reversed range at `R` = 1.
- `scrypt/romix.v`: the Integerify case has arms for r = 2 to 8 that select past the 1024 bits `R` = 1 has. `r_actual_r` is 1 bit then, so they are never taken; a synthesis tool may refuse the constant out-of-range selects.
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

Shared with every algorithm after bcrypt, as copies of the LiteX hashcat Guide's `template/shared/` (see its README): `hcfpga_*.py` and `hcfpga_iface.vh` here, the shared RTL and bench in `gateware/scrypt/`. Until the layout change they were one `src/fpga/common/`.

## Other material derived from LiteX-Scrypt

| Where | Derived from |
|---|---|
| `gateware/scrypt/hcfpga_scrypt_engine.v`, the unit packet | `scrypt_unit.v`'s header comment and its receive state: a type byte with `ctrl`, the 44 configuration bytes upstream's `arbiter_tx.v` reads from `scrypt_cmp_config.v` (log2 (N), salt length, 32 salt bytes, r), the payload, 8 ID bytes, an end byte with `ctrl` |
| `gateware/scrypt/hcfpga_jtr_unit_collect.v` (shared), the unit read | the unit's output states, which follow John the Ripper's `arbiter_rx.v`: one `rd_en` cycle, `2'b11`, `4 + 32/2` 16-bit words two bits at a time, `2'b00` |

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. No board has been built yet.
