# scrypt on FPGA

Hash mode 98900 (bridge `fpga_scrypt`) computes scrypt (mode 8900's format) on an FPGA. The computing unit is LiteX-Scrypt's `scrypt_unit` in its full mode: PBKDF2-HMAC-SHA256 expands the password and salt into a 128-byte block, ROMix runs BlockMix over Salsa20/8 with the V table in block RAM, and PBKDF2 derives the key, one candidate at a time per unit. hashcat keeps the unit and what it instantiates, fixed so that its full mode computes scrypt (see `PROVENANCE.md`), and replaces LiteX-Scrypt's arbiters, comparator and packet layer with an engine written for it (`hcfpga_scrypt_engine.v`) behind the template's H2C intake and end-of-batch tail. The engine reads results with the template's John the Ripper collector, whose read the unit's output matches. `docs/fpga-porting-notes-scrypt.md` explains how it was ported.

Scaffolded by `new_fpga_algo.py --name scrypt --mode 8900 --core custom --pw-max 64 --digest-words 4 --digest-bytes 16 --grain 1 --salt-min 0 --salt-max 32 --iter-min 2 --iter-max 32768` (then in `src/fpga/common/`, now the LiteX hashcat Guide's `template/`).

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/scrypt/hcfpga_sim.py`), which hashcat reaches through the litexbone transport.

## Layout

| Path | What |
|---|---|
| `gateware/scrypt/scrypt/`, `gateware/scrypt/util/` | LiteX-Scrypt's unit and what it instantiates, in upstream's directories (see `PROVENANCE.md`) |
| `gateware/scrypt/hcfpga_scrypt_engine.v` | the engine: `NUM_CORES` units, the transmitter that turns a record into a unit packet, the generation, the shared JtR collector |
| `gateware/scrypt/hcfpga_scrypt_top.sv` | datapath top: the shared H2C intake, the engine, the shared end-of-batch tail |
| `gateware/scrypt_dma_wrapper.py` | the LiteX wrapper (an `HcfpgaDmaWrapper`) and its extra registers |
| `gateware/scrypt/tb_datapath.py`, `tb_dut.vh`, `scrypt_ref.py` | the datapath bench (`make -C src/fpga sim ALGO=scrypt`) and its reference |
| `gateware/scrypt/hcfpga_jtr_unit_collect.v`, `hcfpga_h2c_intake.v`, `hcfpga_gen.v`, `hcfpga_c2h_eob.v` | the shared RTL: the JtR unit collector, the H2C intake, the generation counter, the end-of-batch tail |
| `gateware/scrypt/tb_hcfpga.v`, `hcfpga_bench.py` | the shared bench the algorithm's `tb_datapath.py` runs |
| `hcfpga_dma_wrapper.py`, `hcfpga_sim.py`, `hcfpga_csr.py`, `hcfpga_memstream.py`, `hcfpga_abi.py`, `hcfpga_iface.vh` | the wrapper base, the simulated board (Verilator, Etherbone or UARTBone, memstream), CSR pinning, the ABI reader, the frame contract |

Host side: `src/bridges/bridge_fpga_scrypt.c` and `.mk` (bcrypt's bridge with scrypt's specifics: `diff` it against `bridge_fpga_bcrypt.c`), `src/bridges/fpga/hcfpga_scrypt_ref.h` (the canary's reference), `src/modules/module_98900.c`, `OpenCL/m98900-pure.cl`, `tools/test_modules/m98900.py`.

The shared pieces are copies of the LiteX hashcat Guide's `template/shared/`, as every algorithm after bcrypt has them; this directory needs nothing outside itself but `src/bridges/fpga/hcfpga.h` (the ABI). Until the layout change they were one shared `src/fpga/common/` and one shared bridge, `src/bridges/fpga/hcfpga_bridge.c`, which the porting notes name.

## The engine

- **Transmitter.** Takes a record from the intake when a unit is idle and writes the unit packet into that unit's input FIFO, one byte every other cycle (the FIFO reports full with no margin, so the transmitter checks the flag before each write as it is, not registered). The packet: a type byte with `ctrl`; log2 (N) from `iter_count`, the salt length, 32 salt bytes from `salt0..3` and `salt4..7` and r = 1, each field little-endian as the unit reads them; the password zero filled to 64 bytes; the 8 ID bytes (candidate id, generation, zero); an end byte with `ctrl`. While a packet goes out the intake holds its record across a framing reset (`hold`), because a unit given half a packet would take the next packet's bytes as the rest of it.
- **Units.** `scrypt_unit` with `FULL_MODE` 1, `R` 1, `N_LOG2_MAX` 15 and the V table in block RAM. A unit is idle (`unit_in_ready`) only before it takes a packet; it stays busy through PBKDF2, ROMix, PBKDF2 and until its result has been read.
- **Collector.** `gateware/scrypt/hcfpga_jtr_unit_collect.v` (shared) with `RESULT_LEN` 32: one `rd_en` cycle, the `2'b11` marker, 160 dibits (the 8 ID bytes, then the 32-byte derived key), `2'b00`. It drops a result of another generation without retiring it, looks the low 7 bits of the key's byte 0 up in the bitmap, and sends a 32-byte C2H record for a hit or retires a miss at once.

A candidate takes about 63 cycles per step of N (two BlockMix calls) and about 1800 cycles more for PBKDF2 and the packets: about 66,000 cycles at N = 1024 and 2.1 million at N = 32768.

## Decisions

- **Longest password: 64 bytes.** The unit keeps a 64-byte HMAC key and hands it to HMAC-SHA256 as it is. HMAC takes a key of up to one block (64 bytes) zero filled, so 64 bytes is exact; a longer key would have to be hashed first, which the unit does not do. The unit also takes every payload byte before the 8 ID bytes as key (it ignores the length), so the engine always sends 64 key bytes, the password zero filled. Mode 8900 takes up to 256; a longer candidate is rejected by hashcat (`module_pw_max` 64), never cut.
- **Salt: 0 to 32 bytes.** The unit's salt register is 32 bytes and its PBKDF2 builds the expand message (salt, block index, padding) in one SHA-256 block. Mode 8900's parser takes up to 33 bytes (45 base64 characters); mode 98900 refuses 33 with `Salt-length exception`.
- **Cost: r = 1, p = 1, N a power of two from 2 to 2^15.** The unit's PBKDF2 works on 128-byte blocks, which is r = 1 (its ROMix takes r up to its `R` parameter, but full mode is built for `R` 1), and it computes one SMix, which is p = 1. N is `iter_count` (mode 8900 sets `salt_iter` to N); the engine sends log2 (N), and the V table holds 2^`N_LOG2_MAX` = 32768 blocks of 128 bytes (4 MiB per unit). Mode 98900 refuses other r and p with `Salt-value exception` (mode 8900's own refusals of N use it too) and N above 32768 with `Salt-iteration count exception`.
- **Example hash: `SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=`.** Mode 8900's (`SCRYPT:16384:8:1:...`) has r = 8, which the device cannot compute, so the self-test uses this N = 1024, r = 1 hash of the same password, `hashcat`, checked with Python's `hashlib.scrypt`.
- **Digest: the derived key's bytes 0..15, in order, at C2H bytes 4..19.** Mode 8900's parser stores the base64-decoded key as `digest_buf`, so these are `digest[0..3]` little-endian, and the bridge takes the C2H words as received. The comparator indexes its bitmap with the low 7 bits of key byte 0, which is `digest[0] & 0x7f`. hashcat compares `digest[0..3]` (`DGST_POS0..3` 0 to 3), so key bytes 16..31 are read from the unit and dropped.
- **`core_id` names the unit** that computed the candidate (the bridge's messages say "unit"). A unit is one core with one candidate in flight.
- **The units cannot be reset in the middle of a job.** The generation (`hcfpga_gen.v`) rides in the candidate's ID bytes, the unit echoes them ahead of its result, and the collector drops a result of another generation without retiring it. A packet once started is always finished.
- **Extra registers: `salt_len` at 0x3c, then `salt4..salt7` at 0x40..0x4c** (salt bytes 16..31, hashcat's `salt_buf[4..7]`). `salt0..3` carry bytes 0..15, and `iter_count` carries N, so the cost needs no register of its own.
- **Grain: 1 per identity core.** A unit holds one candidate, and the identity's `cores=` counts units. The bridge's batch grain is `cores * 1`.
- **Batch timeout:** `WAVE_CYCLES_PER_ITER` 1000. One step of N takes about 63 cycles, but a candidate also spends about 1800 cycles in PBKDF2 and its packets, which the timeout has to cover at N = 2 as well (2 * 1000 per wave); the bridge multiplies by 4.

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
| 40..43 | r = 1, little-endian | |
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

The shared block (`hcfpga_dma_wrapper.py`), plus:

| Offset | Name | Use |
|---|---|---|
| 0x00 | ctrl | bit 0 framing reset |
| 0x04..0x10 | salt0..3 | salt bytes 0..15 (hashcat's `salt_buf[0..3]`) |
| 0x14 | iter_count | N |
| 0x18 | status | bit 0 slip, bit 1 last_seen, 15:8 slip count, 23:16 unit results whose framing was off |
| 0x1c | core_count | scrypt units |
| 0x3c | salt_len | salt length in bytes, 0 to 32 |
| 0x40..0x4c | salt4..7 | salt bytes 16..31 (hashcat's `salt_buf[4..7]`) |

## Limits

- Passwords up to 64 bytes; a longer candidate is `Rejected` by hashcat.
- Salts of 0 to 32 bytes; 33 is a `Salt-length exception`.
- r = 1 and p = 1; anything else is a `Salt-value exception`. N from 2 to 32768, a power of two; above 32768 is a `Salt-iteration count exception`, and N below 2 or not a power of two is mode 8900's own `Salt-value exception`.
- Digests of 16 bytes or more (mode 8900 takes 31 to 64): hashcat compares the first 16.

## Running it in simulation

```
src/fpga/scrypt/hcfpga_sim.py --bridge uartbone --build-only
src/fpga/scrypt/hcfpga_sim.py --bridge uartbone --no-build --uart-port 2430 &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 98900 hash.txt words.txt
```

`--uart-port` moves the UARTBone port when another sim has 2430, `--units` sets the number of scrypt units. Etherbone (`--bridge etherbone`, `HCFPGA_LITEXBONE=udp:192.168.9.50`) needs a tap, so run the sim and hashcat under the LiteX hashcat Guide's `debug/simns.sh`. The simulated board declares 1 MHz, and with this design Verilator runs it at about 230 kHz: the example hash (N = 1024, about 66,000 cycles) takes about 0.3 s a candidate there, so keep N small.

The bench, which needs Verilator only: `make -C src/fpga sim ALGO=scrypt`.
