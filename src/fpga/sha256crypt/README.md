# sha256crypt on FPGA

Hash mode 97400 (bridge `fpga_sha256crypt`) computes sha256crypt (`$5$`, mode 7400's format) on an FPGA, on the shared hcfpga template (`src/fpga/common`). The computing unit is John the Ripper's ZTEX sha256crypt unit (Denis Burykin): three SHA-256 cores, a 12-thread CPU that runs the sha256crypt program, and the engine that turns the CPU's instructions into SHA-256 blocks. hashcat keeps the unit and replaces JtR's arbiters, comparator and packet layer with the template's feeder, collector and records, the same cut md5crypt (mode 90500) made. `docs/fpga-porting-notes-sha256crypt.md` explains how it was ported.

Scaffolded by `src/fpga/common/new_fpga_algo.py --name sha256crypt --mode 7400 --core jtr-unit --pw-max 32 --result-len 32 --key-align 4 --salt-min 1 --salt-max 16 --iter-min 1 --iter-max 999999999`.

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/common/hcfpga_sim.py --algo sha256crypt`), which hashcat reaches through the litexbone transport.

## Layout

| Path | What |
|---|---|
| `gateware/sha256crypt/` | John the Ripper's sha256crypt unit (`unit/`, `cpu/`, `sha256core/`, `sha256engine/`, `util/`, `sha256.vh`, see `PROVENANCE.md`) and the top around it |
| `gateware/sha256crypt/hcfpga_sha256crypt_top.sv` | datapath top: the shared JtR unit feeder (32-byte keys in 4-byte steps), `NUM_UNITS` units, the shared collector (32-byte result, 16 forwarded), the generation, the end-of-batch tail |
| `gateware/sha256crypt_dma_wrapper.py` | the LiteX wrapper: the shared `HcfpgaDmaWrapper` plus `salt_len` |
| `gateware/sha256crypt/tb_datapath.py`, `tb_dut.vh`, `sha256crypt_ref.py` | the datapath bench (`make -C src/fpga sim ALGO=sha256crypt`) and its reference |

Host side: `src/bridges/bridge_fpga_sha256crypt.c` (the hooks of `src/bridges/fpga/hcfpga_bridge.c`), `src/bridges/fpga/hcfpga_sha256crypt_ref.h` (the canary's reference), `src/modules/module_97400.c`, `OpenCL/m97400-pure.cl`, `tools/test_modules/m97400.py`.

## The computing unit

A unit is three SHA-256 cores, a 16-bit CPU with 12 hardware threads that runs the sha256crypt program in `cpu/program.vh`, and the engine that turns the CPU's `PROCESS_BYTES` instructions into SHA-256 blocks. Each core interleaves four computations and finishes four blocks every 288 cycles, so a unit has 12 candidates in flight and a thread finishes one block every 288 cycles at best. A round hashes the previous result or the P sequence, in most rounds the S sequence, and the P sequence again: one block up to 55 bytes, two beyond (at most 32 + 16 + 32 + 32 bytes). Before the rounds the program hashes the P sequence (the key key_len times, up to 1024 bytes) and the S sequence (the salt 16 + A[0] times, up to 4336 bytes). 5000 rounds of a short password take about 1.5 to 3 million cycles. The unit has no reset.

The whole unit runs on one clock. Upstream clocks it with `CORE_CLK` and crosses to the packet clock in its arbiters; here the units run on the stream clock, so the top has no `CLK_CORE` (md5crypt's unit has its own core clock input, sha256crypt's does not).

## Decisions

- **Longest password: 32 bytes.** The program keeps the key in thread memory words 10 to 17 and writes the P byte sequence over it (`NEW_CTX(ADDR_p_bytes, 8)`), the result sits in words 24 to 31, and its own comment says "max. key_len is 32". JtR's `PLAINTEXT_LEN` and its host format's `PLAINTEXT_LENGTH` are 32 too. Mode 7400 takes 256.
- **Salt: 1 to 16 bytes.** The packet carries 16 salt bytes (thread memory words 2 to 5), and the program says "salt_len=0 ... NOT supported"; JtR's format skips empty salts. Mode 7400's parser takes 0 to 20 and hashes all 20 (libc stops at 16). Mode 97400 refuses an empty salt and salts over 16 bytes at parse time.
- **Rounds: 1 to 999999999.** The CPU reads a 32-bit count into two 16-bit registers and borrows from the upper one (the bench runs 65537 rounds to cover it); "cnt=0 NOT supported". 999999999 is sha256crypt's own limit, which JtR's format keeps. The device and mode 7400 take the count as given; libc raises counts below 1000 to 1000, so a `$5$rounds=10$` hash made by libc is a 1000-round hash with a misleading label, and neither mode cracks it as written.
- **Digest.** The unit returns the 32 result bytes in SHA-256 output order. hashcat compares digest words 0 to 3 (mode 7400's `DGST_POS0..3`), so the collector forwards result bytes 0 to 15 to C2H bytes 4 to 19 and drops the rest. They are hashcat's `digest_buf` as bytes: `digest[k]` is the little-endian word at C2H 4+4k, so `digest_from_c2h` is NULL (no swap). The comparator indexes its bitmap with the low 7 bits of result byte 0, which is `digest[0] & 0x7f`. The tmp struct holds 4 digest words; the module keeps mode 7400's 8-word digest for its encoder.
- **`core_id` names the computing unit.** The unit picks the thread (S10), so no core can be named; `core_name` is "unit".
- **No reset in the middle of a job.** JtR's unit cannot be reset, so the shared adapter's generation (`hcfpga_gen.v`) rides in the candidate's ID bytes and the collector drops results of another generation without retiring them. A packet already started is always finished.
- **Extra registers: `salt_len` at 0x3c**, nothing else. The JtR unit packet carries the salt length; rounds go in the shared `iter_count`, the salt in the shared `salt0..3`.
- **Grain: 4 per identity core.** A SHA-256 core interleaves 4 computations, and the identity's `cores=` counts SHA-256 cores, 3 per unit (`CORES_PER_UNIT` stays 3: `core_ctrl.v` spaces the cores' start slots for exactly 12 threads, `COMP_INTERVAL = 288 / N_THREADS // must be 24`). A unit's input buffer takes a packet only once a thread is free, so nothing waits beyond the 12.
- **Batch timeout:** `wait_cycles_per_iter` 800, for at most two blocks per round (576 cycles) and the CPU's overhead; the bridge multiplies it by 4.

## H2C record (bcrypt's)

| Word | Content |
|---|---|
| 0 | `0xbc << 24 \| len`, len 0 to 32. Anything else in this position is a slip and is skipped |
| 1 | candidate id, echoed in the C2H record. `0xfffffffe` is a canary |
| 2.. | the password, big-endian, four bytes per word, zero filled |

The feeder hands each record to a ready unit as one packet: a type byte 0 with `ctrl`, 40 header bytes and the key rounded up to whole words, the last byte with `ctrl`. The unit stores it at the start of a free thread's memory:

| Bytes | Content |
|---|---|
| 0..3 | rounds, from `iter_count` |
| 4..7 | salt length, from `salt_len` |
| 8..23 | salt, `salt0..3`, byte 0 in bits 7:0 of `salt0` |
| 24..27 | candidate id |
| 28..29 | generation |
| 30..31 | zero |
| 32 | key length |
| 33..39 | zero |
| 40..71 | key, rounded up to 4 bytes |

The unit writes back 20 16-bit words after a `2'b11` marker, least significant dibit first: words 0..1 the id, 2 the generation, 3 zero, 4..19 the 32 result bytes.

## C2H record (bcrypt's, with a 16-byte digest)

| Bytes | Content |
|---|---|
| 0..3 | candidate id, little-endian. An EOB record carries the retired count here |
| 4..19 | result bytes 0..15 in SHA-256 output order: hashcat's `digest[k]` is the little-endian word at 4+4k, no byte swap |
| 20..27 | zero |
| 28..29 | core_id, little-endian: the computing unit |
| 30..31 | flags, little-endian: 0x0000 OK, 0x0001 CORE_ERR (the unit's output framing was off), 0x8000 EOB |

## Registers

The shared block (`src/fpga/common/hcfpga_dma_wrapper.py`), plus one:

| Offset | Name | sha256crypt use |
|---|---|---|
| 0x00 | ctrl | bit 0 framing reset |
| 0x04..0x10 | salt0..3 | hashcat's `salt_buf[0..3]` unchanged: the raw salt, byte 0 in bits 7:0 |
| 0x14 | iter_count | rounds, 1 to 999999999 |
| 0x18 | status | bit 0 slip, bit 1 last_seen, 15:8 slip count, 23:16 unit framing errors |
| 0x1c | core_count | SHA-256 cores |
| 0x20..0x2c | cmp_bm0..3 | comparator bitmap, indexed by `digest[0] & 0x7f`, loaded on the write of cmp_bm3 |
| 0x30 | batch_target | arm |
| 0x34 | pad_recs | records per DMA granule |
| 0x38 | retired | records retired since the arm |
| 0x3c | salt_len | salt length, 1 to 16 (sha256crypt only) |

## Limits

- Passwords up to 32 bytes.
- Salts of 1 to 16 bytes. Mode 7400 also takes an empty salt and salts of 17 to 20 bytes; mode 97400 refuses them at parse time (`Salt-length exception`).
- 1 to 999999999 rounds (`Salt-iteration count exception` outside).
- `CORES_PER_UNIT` stays 3.

## Running it in simulation

```
src/fpga/common/hcfpga_sim.py --algo sha256crypt --bridge uartbone --build-only
src/fpga/common/hcfpga_sim.py --algo sha256crypt --bridge uartbone --no-build &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 97400 hash.txt words.txt
```

`--uart-port` moves the UARTBone port when another sim has 2430. Etherbone (`--bridge etherbone`, `HCFPGA_LITEXBONE=udp:192.168.9.50`) needs a tap, so run the sim and hashcat under the LiteX hashcat Guide's `debug/simns.sh`. The simulated board runs at about 1 MHz, so mode 7400's example hash (5000 rounds) takes a few seconds per batch.

The bench, which needs Verilator only: `make -C src/fpga sim ALGO=sha256crypt` (about two minutes, most of it the 65537-round case).
