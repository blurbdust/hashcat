# scrypt on FPGA

Hash mode 98900 (bridge `fpga_scrypt`) computes scrypt (mode 8900's format) on an FPGA, on the shared hcfpga template (`src/fpga/common`). The computing unit is LiteX-Scrypt's `scrypt_unit` in its full mode: PBKDF2-HMAC-SHA256 expands the password and salt into 128 r bytes, ROMix runs BlockMix over Salsa20/8 with the V table in block RAM, and PBKDF2 derives the key from the 128 r bytes ROMix leaves, one candidate at a time per unit. r comes with each salt, from 1 to the build's `R_MAX` (8). hashcat keeps the unit and what it instantiates, fixed so that its full mode computes scrypt (see `PROVENANCE.md`), and replaces LiteX-Scrypt's arbiters, comparator and packet layer with an engine written for it (`hcfpga_scrypt_engine.v`) behind the template's H2C intake and end-of-batch tail. The engine reads results with the template's John the Ripper collector, whose read the unit's output matches. `docs/fpga-porting-notes-scrypt.md` explains how it was ported.

Scaffolded by `src/fpga/common/new_fpga_algo.py --name scrypt --mode 8900 --core custom --pw-max 64 --digest-words 4 --digest-bytes 16 --grain 1 --salt-min 0 --salt-max 32 --iter-min 2 --iter-max 32768`.

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/common/hcfpga_sim.py --algo scrypt`), which hashcat reaches through the litexbone transport.

## Layout

| Path | What |
|---|---|
| `gateware/scrypt/scrypt/`, `gateware/scrypt/util/` | LiteX-Scrypt's unit and what it instantiates, in upstream's directories (see `PROVENANCE.md`) |
| `gateware/scrypt/hcfpga_scrypt_engine.v` | the engine: `NUM_CORES` units, the transmitter that turns a record into a unit packet, the generation, the shared JtR collector |
| `gateware/scrypt/hcfpga_scrypt_top.sv` | datapath top: the shared H2C intake, the engine, the shared end-of-batch tail |
| `gateware/scrypt_dma_wrapper.py` | the LiteX wrapper (an `HcfpgaDmaWrapper`) and its extra registers |
| `gateware/scrypt/tb_datapath.py`, `tb_dut.vh`, `scrypt_ref.py` | the datapath bench (`make -C src/fpga sim ALGO=scrypt`) and its reference |

Host side: `src/bridges/bridge_fpga_scrypt.c` (the hooks of `src/bridges/fpga/hcfpga_bridge.c`), `src/bridges/fpga/hcfpga_scrypt_ref.h` (the canary's reference), `src/modules/module_98900.c`, `OpenCL/m98900-pure.cl`, `tools/test_modules/m98900.py`.

## The engine

- **Transmitter.** Takes a record from the intake when a unit is idle and writes the unit packet into that unit's input FIFO, one byte every other cycle (the FIFO reports full with no margin, so the transmitter checks the flag before each write as it is, not registered). The packet: a type byte with `ctrl`; log2 (N) from `iter_count`, the salt length, 32 salt bytes from `salt0..3` and `salt4..7` and r from the `r` register, each field little-endian as the unit reads them; the password zero filled to 64 bytes; the 8 ID bytes (candidate id, generation, zero); an end byte with `ctrl`. While a packet goes out the intake holds its record across a framing reset (`hold`), because a unit given half a packet would take the next packet's bytes as the rest of it.
- **Units.** `scrypt_unit` with `FULL_MODE` 1, `R` = `R_MAX` (8), `N_LOG2_MAX` 15, a lookup gap G = 2^`GAP_LOG2` (1) and the V table in block RAM, 2^`N_LOG2_MAX` / G blocks of 128 `R_MAX` bytes. `R_MAX`, `N_LOG2_MAX` and `GAP_LOG2` are parameters of the top (the wrapper's `r_max`, `n_log2_max` and `gap`); the simulated board uses these defaults, whose limits are the module's. A unit is idle (`unit_in_ready`) only before it takes a packet; it stays busy through PBKDF2, ROMix, PBKDF2 and until its result has been read.
- **Collector.** `src/fpga/common/rtl/hcfpga_jtr_unit_collect.v` with `RESULT_LEN` 32: one `rd_en` cycle, the `2'b11` marker, 160 dibits (the 8 ID bytes, then the 32-byte derived key), `2'b00`. It drops a result of another generation without retiring it, looks the low 7 bits of the key's byte 0 up in the bitmap, and sends a 32-byte C2H record for a hit or retires a miss at once.

A candidate takes 52 r + 11 cycles per step of N (two BlockMix calls of 2 r Salsa20/8 calls each, 13 cycles a call: 63 cycles at r = 1, 427 at r = 8) and about 1,230 r + 850 cycles more for PBKDF2 (EXPAND is 4 r HMAC calls of 4 SHA-256 blocks, DERIVE 2 r + 4 blocks, 66 cycles a block) and the packets. One candidate on one unit, from the bench's `cycles` case:

| N | r = 1 | r = 8 |
|---|---|---|
| 1024 | 66,589 cycles | 447,935 cycles |
| 16384 | 1,034,269 cycles | 7,006,655 cycles |

With a lookup gap G (below) the mix recomputes (G - 1) / 2 BlockMix calls per step on average, and a candidate takes about 1 + (G - 1) / 4 times as long. One candidate on one unit, cycles, from `--case cycles --gap G`:

| G | V table | N = 1024, r = 1 | N = 1024, r = 8 | N = 16384, r = 1 | N = 16384, r = 8 |
|---|---|---|---|---|---|
| 1 | N blocks | 66,589 | 447,935 | 1,034,269 | 7,006,655 |
| 2 | N / 2 | 81,669 | 550,271 | 1,272,157 | 8,744,451 |
| 4 | N / 4 | 110,843 | 768,445 | 1,750,715 | 12,200,209 |
| 8 | N / 8 | 169,771 | 1,207,325 | 2,702,379 | 19,175,025 |

## Decisions

- **Longest password: 64 bytes.** The unit keeps a 64-byte HMAC key and hands it to HMAC-SHA256 as it is. HMAC takes a key of up to one block (64 bytes) zero filled, so 64 bytes is exact; a longer key would have to be hashed first, which the unit does not do. The unit also takes every payload byte before the 8 ID bytes as key (it ignores the length), so the engine always sends 64 key bytes, the password zero filled. Mode 8900 takes up to 256; a longer candidate is rejected by hashcat (`module_pw_max` 64), never cut.
- **Salt: 0 to 32 bytes.** The unit's salt register is 32 bytes and its PBKDF2 builds the expand message (salt, block index, padding) in one SHA-256 block. Mode 8900's parser takes up to 33 bytes (45 base64 characters); mode 98900 refuses 33 with `Salt-length exception`.
- **Cost: r from 1 to 8, p = 1, N a power of two from 2 to 2^15.** r comes at run time, in the `r` register, up to the build's `R_MAX`: the unit's PBKDF2 expands to 128 r bytes and derives from 128 r bytes, and its ROMix and BlockMix take r up to their `R` (see `PROVENANCE.md`, r at run time). Most scrypt hashes in use have r = 8, mode 8900's example among them. The unit computes one SMix, which is p = 1. N is `iter_count` (mode 8900 sets `salt_iter` to N); the engine sends log2 (N), and the V table holds 2^`N_LOG2_MAX` = 32768 blocks of 128 `R_MAX` bytes (32 MiB per unit in the simulated board). A build's limits are hashcat's only when they match the module's (`FPGA_ITER_MAX`, `FPGA_SCRYPT_R_MAX`): a board built smaller needs the module changed with it, and until then the known-answer canary fails every salt the build cannot compute. Mode 98900 refuses r of 0 or above 8 and p other than 1 with `Salt-value exception` (mode 8900's own refusals of N use it too) and N above 32768 with `Salt-iteration count exception`.
- **Example hash: mode 8900's, `SCRYPT:16384:8:1:OTEyNzU0ODg=:Cc8SPjRH1hFQhuIPCdF51uNGtJ2aOY/isuoMlMUsJ8c=`** (password `hashcat`). One candidate is 7,006,657 cycles: 11.6 s on the simulated board over UARTBone (one unit), 39 s in the two-unit bench. The self-test batch (the candidate and the canary, one after the other on one unit) takes about 23 s, which every hashcat run pays; that is affordable, and the self-test then runs the parameters most hashes use. On a board at 200 MHz a candidate takes 35 ms.
- **Digest: the derived key's bytes 0..15, in order, at C2H bytes 4..19.** Mode 8900's parser stores the base64-decoded key as `digest_buf`, so these are `digest[0..3]` little-endian, and `digest_from_c2h` is NULL. The comparator indexes its bitmap with the low 7 bits of key byte 0, which is `digest[0] & 0x7f`. hashcat compares `digest[0..3]` (`DGST_POS0..3` 0 to 3), so key bytes 16..31 are read from the unit and dropped.
- **`core_id` names the unit** that computed the candidate (`core_name` "unit"). A unit is one core with one candidate in flight.
- **The units cannot be reset in the middle of a job.** The generation (`hcfpga_gen.v`) rides in the candidate's ID bytes, the unit echoes them ahead of its result, and the collector drops a result of another generation without retiring it. A packet once started is always finished.
- **Extra registers: `salt_len` at 0x3c, then `salt4..salt7` at 0x40..0x4c** (salt bytes 16..31, hashcat's `salt_buf[4..7]`), **then `r` at 0x50.** `salt0..3` carry bytes 0..15, and `iter_count` carries N. The register is `r`, not `scrypt_r` (which is how `csr.csv` shows it): the template's offset check takes the bank's name off any register name that starts with it.
- **Grain: 1 per identity core.** A unit holds one candidate, and the identity's `cores=` counts units. The bridge's batch grain is `cores * 1`.
- **Lookup gap: a build parameter, G = 1, 2, 4 or 8 (`GAP_LOG2` 0 to 3), 1 in the simulated board.** ROMix stores every G-th block of V, so the table shrinks by G, and a read of V[j] loads V[j - j mod G] and recomputes j mod G BlockMix steps (`PROVENANCE.md`, lookup gap). It trades time for block RAM on a board that cannot hold enough units otherwise. It changes nothing hashcat sees: the bridge, the module and the registers are the same for every G.
- **Batch timeout:** `wait_cycles_per_iter` 2000. One step of N takes 63 cycles at r = 1 and 427 at r = 8, and about 1,170 at r = 8 with G = 8; a candidate also spends 2,000 to 11,000 cycles in PBKDF2 and its packets, which the timeout has to cover at N = 2 as well; the simulated board runs below the 1 MHz it declares; the bridge multiplies by 4.

## H2C record (bcrypt's)

| Word | Content |
|---|---|
| 0 | `0xbc << 24 \| len`, len 0 to 64. Anything else in this position is a slip and is skipped |
| 1 | candidate id, echoed in the C2H record. `0xfffffffe` is a canary |
| 2..17 | the password, big-endian, four bytes per word, zero filled |

## Unit packet (engine to unit, one byte per write)

| Bytes | Content | Source |
|---|---|---|
| type | 0x00 with `ctrl` | |
| 0..3 | log2 (N), little-endian | `iter_count` |
| 4..7 | salt length, little-endian | `salt_len` |
| 8..39 | salt, zero filled | `salt0..3`, `salt4..7`, byte 0 in bits 7:0 of `salt0` |
| 40..43 | r, little-endian | `r` |
| 44..107 | password, zero filled to 64 bytes | H2C words 2.. |
| 108..111 | candidate id, little-endian | H2C word 1 |
| 112..113 | generation, little-endian | `hcfpga_gen.v` |
| 114..115 | zero | |
| end | 0x00 with `ctrl` | |

## Unit output

After one `rd_en` cycle: `2'b11`, then 160 dibits least significant first (the 8 ID bytes, then the 32-byte derived key, byte 0 first), then `2'b00`.

## C2H record (bcrypt's, with a 16-byte digest)

| Bytes | Content |
|---|---|
| 0..3 | candidate id, little-endian. An EOB record carries the retired count here |
| 4..19 | the derived key's bytes 0..15: hashcat's `digest[0..3]`, little-endian |
| 20..27 | zero |
| 28..29 | core_id, little-endian: the unit |
| 30..31 | flags, little-endian: 0x0000 OK, 0x0001 the unit's output framing was off, 0x8000 EOB |

## Registers

The shared block (`src/fpga/common/hcfpga_dma_wrapper.py`), plus:

| Offset | Name | Use |
|---|---|---|
| 0x00 | ctrl | bit 0 framing reset |
| 0x04..0x10 | salt0..3 | salt bytes 0..15 (hashcat's `salt_buf[0..3]`) |
| 0x14 | iter_count | N |
| 0x18 | status | bit 0 slip, bit 1 last_seen, 15:8 slip count, 23:16 unit results whose framing was off |
| 0x1c | core_count | scrypt units |
| 0x3c | salt_len | salt length in bytes, 0 to 32 |
| 0x40..0x4c | salt4..7 | salt bytes 16..31 (hashcat's `salt_buf[4..7]`) |
| 0x50 | r | scrypt's r, 1 to `R_MAX` (`csr.csv`: `scrypt_r`) |

## Limits

- Passwords up to 64 bytes; a longer candidate is `Rejected` by hashcat.
- Salts of 0 to 32 bytes; 33 is a `Salt-length exception`.
- r from 1 to 8 and p = 1; anything else is a `Salt-value exception`. N from 2 to 32768, a power of two; above 32768 is a `Salt-iteration count exception`, and N below 2 or not a power of two is mode 8900's own `Salt-value exception`.
- Digests of 16 bytes or more (mode 8900 takes 31 to 64): hashcat compares the first 16.

## Running it in simulation

```
src/fpga/common/hcfpga_sim.py --algo scrypt --bridge uartbone --build-only
src/fpga/common/hcfpga_sim.py --algo scrypt --bridge uartbone --no-build --uart-port 2430 &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 98900 hash.txt words.txt
```

`--uart-port` moves the UARTBone port when another sim has 2430, `--units` sets the number of scrypt units. Etherbone (`--bridge etherbone`, `HCFPGA_LITEXBONE=udp:192.168.9.50`) needs a tap, so run the sim and hashcat under the LiteX hashcat Guide's `debug/simns.sh`. The simulated board declares 1 MHz, and with this design (one unit, `R_MAX` 8) Verilator runs it at about 400 to 600 kHz: the example hash (N = 16384, r = 8, 7 million cycles) takes about 12 s a candidate there, so keep N and r small in tests (the test module uses N = 16).

The bench, which needs Verilator only: `make -C src/fpga sim ALGO=scrypt`. It builds the simulated board's parameters (2 units, `N_LOG2_MAX` 15, `R_MAX` 8); `tb_datapath.py --r-max <r> --n-log2-max <n> --gap <G> --units <u>` builds others, each in a directory of its own, `--case cycles` prints the cycles of one candidate at N = 1024 and 16384 with r = 1 and `R_MAX`, and `--case example` runs mode 8900's example hash.
