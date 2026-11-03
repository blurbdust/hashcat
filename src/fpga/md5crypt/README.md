# md5crypt on FPGA

Hash mode 90500 (bridge `fpga_md5crypt`) computes md5crypt (`$1$`, mode 500's format) on an FPGA. It is the second algorithm on the hcfpga framework bcrypt (mode 75000) introduced, and it keeps every generic part of bcrypt's design: the H2C record, the C2H record and its end-of-batch flag, the register block, the identity string and the transports. `docs/fpga-porting-notes-md5crypt.md` explains how it was ported and what a later algorithm can reuse.

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/common/hcfpga_sim.py --algo md5crypt`), which hashcat reaches through the litexbone transport.

md5crypt was the first port onto the shared template in `src/fpga/common` (gateware) and `src/bridges/fpga/hcfpga_bridge.c` (host). What is md5crypt's own is the unit, the top that sizes the shared parts for it, one extra register and the bridge hooks; the rest is shared.

## Layout

| Path | What |
|---|---|
| `gateware/md5crypt/` | John the Ripper's md5crypt unit (`md5unit.v` and below, see `PROVENANCE.md`) and hashcat's datapath around it |
| `gateware/md5crypt/hcfpga_md5crypt_top.sv` | datapath top: the shared JtR unit feeder (64-byte keys, 4-byte steps), `NUM_UNITS` units, the shared collector (16-byte result), the generation, the end-of-batch tail |
| `gateware/md5crypt_dma_wrapper.py` | the LiteX wrapper: the shared `HcfpgaDmaWrapper` plus `salt_len` |
| `gateware/md5crypt/tb_datapath.py`, `tb_dut.vh` | the datapath bench on the shared one, the merge gate (`make -C src/fpga sim ALGO=md5crypt`) |
| `src/fpga/common/rtl/hcfpga_jtr_unit_feed.v` | (shared) H2C intake and the unit input packet |
| `src/fpga/common/rtl/hcfpga_jtr_unit_collect.v` | (shared) unit output, generation check, comparator, C2H record |
| `src/fpga/common/rtl/hcfpga_gen.v`, `hcfpga_c2h_eob.v` | (shared) the generation counter; retired count, EOB record, granule padding |
| `src/fpga/common/hcfpga_sim.py` | (shared) the simulated board (Verilator, Etherbone or UARTBone, memstream) |

Host side: `src/bridges/bridge_fpga_md5crypt.c` (the hooks of the shared `src/bridges/fpga/hcfpga_bridge.c`), `src/bridges/fpga/hcfpga_md5crypt_ref.h` (the canary's reference), `src/modules/module_90500.c`, `OpenCL/m90500-pure.cl`, `tools/test_modules/m90500.py`.

## The computing unit

A unit is three MD5 cores, a 16-bit CPU with 12 hardware threads that runs the md5crypt program in `cpu/program.vh`, and the engine that turns the CPU's `PROCESS_BYTES` instructions into MD5 blocks. Each core interleaves four computations, so a unit has 12 candidates in flight and one more waiting in its input buffer. One md5crypt round hashes the previous digest and the password, in most rounds also the salt and the password again, which is one MD5 block for passwords up to 15 bytes with an 8-byte salt and two blocks beyond. A thread finishes a block every 288 cycles, so 1000 rounds of a short password take about 290,000 cycles. The unit has no reset.

The identity's `cores=` counts MD5 cores (3 per unit). The bridge multiplies by 4 for the batch grain.

## H2C record (bcrypt's)

| Word | Content |
|---|---|
| 0 | `0xbc << 24 \| len`, len 0 to 64. Anything else in this position is a slip and is skipped |
| 1 | candidate id, echoed in the C2H record. `0xfffffffe` is a canary |
| 2.. | the password, big-endian, four bytes per word, zero filled |

Words travel as the host buffer's bytes four at a time, first byte in bits 7:0. hashcat pads a batch to 32 bytes with zero words, which the feeder counts as slips.

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
| 40.. | key |

## C2H record (bcrypt's, with a 16-byte digest)

| Bytes | Content |
|---|---|
| 0..3 | candidate id, little-endian. An EOB record carries the retired count here |
| 4..19 | the 16 digest bytes in MD5 output order: hashcat's `digest[k]` is the little-endian word at 4+4k, no byte swap (bcrypt's 24 bytes are big-endian words) |
| 20..27 | zero |
| 28..29 | core_id, little-endian: the computing unit |
| 30..31 | flags, little-endian: 0x0000 OK, 0x0001 CORE_ERR (the unit's output framing was off), 0x8000 EOB |

## Registers

bcrypt's block at the same offsets, plus one:

| Offset | Name | md5crypt use |
|---|---|---|
| 0x00 | ctrl | bit 0 framing reset |
| 0x04..0x10 | salt0..3 | hashcat's `salt_buf[0..3]` unchanged: the raw salt, byte 0 in bits 7:0 |
| 0x14 | iter_count | rounds, 1 to 65535 (the CPU counts in 16 bits) |
| 0x18 | status | bit 0 slip, bit 1 last_seen, 15:8 slip count, 23:16 unit framing errors |
| 0x1c | core_count | MD5 cores |
| 0x20..0x2c | cmp_bm0..3 | comparator bitmap, indexed by `digest[0] & 0x7f`, loaded on the write of cmp_bm3 |
| 0x30 | batch_target | arm |
| 0x34 | pad_recs | records per DMA granule |
| 0x38 | retired | records retired since the arm |
| 0x3c | salt_len | salt length, 1 to 8 (md5crypt only) |

## Resets and the generation

A framing reset or an arm bumps a 16-bit generation. Each packet carries the generation it was sent under, and the collector drops results of any other: they belong to a batch the host gave up on, and the units, which cannot be reset, finish them anyway. A packet already being sent to a unit is always finished, because a unit given half a packet would take the next one's bytes as the rest of it.

## Limits

- Passwords up to 64 bytes (the thread memory holds the key in words 10 to 25).
- Salts of 1 to 8 bytes. Mode 500 also takes an empty salt; the unit cannot hash one, and mode 90500 refuses it at parse time, as John the Ripper's ZTEX format skips such hashes.
- 1 to 65535 rounds (`$1$rounds=N$`, a hashcat extension, works in that range).
- `CORES_PER_UNIT` stays 3: `core_ctrl.v` spaces the cores' start slots for exactly 12 threads.

## Running it in simulation

```
src/fpga/common/hcfpga_sim.py --algo md5crypt --bridge uartbone --build-only
src/fpga/common/hcfpga_sim.py --algo md5crypt --bridge uartbone --no-build &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 90500 hash.txt words.txt
```

`--uart-port` moves the UARTBone port when another sim has 2430. Etherbone (`--bridge etherbone`, `HCFPGA_LITEXBONE=udp:192.168.9.50`) needs a tap, so run the sim and hashcat under the LiteX hashcat Guide's `debug/simns.sh`.

The bench, which needs Verilator only:

```
src/fpga/md5crypt/gateware/md5crypt/tb_datapath.py
```
