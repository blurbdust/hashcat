# descrypt on FPGA

Hash mode 91500 (bridge `fpga_descrypt`) computes descrypt (traditional DES crypt(3), mode 1500's format) on an FPGA. The DES pipeline is John the Ripper's ZTEX descrypt core (Denis Burykin): a ring of 16 registered DES rounds through which 16 candidates circle 25 times. Upstream wraps the ring in a batch control and a 35-bit comparator that reports only matches; hashcat keeps the ring and the key preparation, and replaces the rest with an engine written for it (`hcfpga_descrypt_engine.v`) behind the template's H2C intake and end-of-batch tail. `docs/fpga-porting-notes-descrypt.md` explains how it was ported.

Scaffolded by `new_fpga_algo.py --name descrypt --mode 1500 --core custom --pw-max 8 --digest-words 4 --digest-bytes 8 --grain 16 --salt-min 4 --salt-max 4 --iter-min 25 --iter-max 25` (then in `src/fpga/common/`, now the LiteX hashcat Guide's `template/`).

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/descrypt/hcfpga_sim.py`), which hashcat reaches through the litexbone transport.

## Layout

| Path | What |
|---|---|
| `gateware/descrypt/descrypt_core/` | John the Ripper's DES ring and key preparation (see `PROVENANCE.md`) |
| `gateware/descrypt/hcfpga_descrypt_engine.v` | the engine: loader, `NUM_CORES` rings with their control and result banks, collector and comparator |
| `gateware/descrypt/hcfpga_descrypt_top.sv` | datapath top: the shared H2C intake, the engine, the shared end-of-batch tail |
| `gateware/descrypt_dma_wrapper.py` | the LiteX wrapper: the shared `HcfpgaDmaWrapper`, no extra register |
| `gateware/descrypt/tb_datapath.py`, `tb_dut.vh`, `descrypt_ref.py` | the datapath bench (`make -C src/fpga sim ALGO=descrypt`) and its reference |
| `gateware/descrypt/hcfpga_h2c_intake.v`, `hcfpga_gen.v`, `hcfpga_c2h_eob.v` | the shared RTL: the H2C intake, the generation counter, the end-of-batch tail |
| `gateware/descrypt/tb_hcfpga.v`, `hcfpga_bench.py` | the shared bench the algorithm's `tb_datapath.py` runs |
| `hcfpga_dma_wrapper.py`, `hcfpga_sim.py`, `hcfpga_csr.py`, `hcfpga_memstream.py`, `hcfpga_abi.py`, `hcfpga_iface.vh` | the wrapper base, the simulated board (Verilator, Etherbone or UARTBone, memstream), CSR pinning, the ABI reader, the frame contract |

Host side: `src/bridges/bridge_fpga_descrypt.c` and `.mk` (bcrypt's bridge with descrypt's specifics: `diff` it against `bridge_fpga_bcrypt.c`), `src/bridges/fpga/hcfpga_descrypt_ref.h` (the canary's reference), `src/modules/module_91500.c`, `OpenCL/m91500-pure.cl`, `tools/test_modules/m91500.py`.

The shared pieces are copies of the LiteX hashcat Guide's `template/shared/`, as every algorithm after bcrypt has them; this directory needs nothing outside itself but `src/bridges/fpga/hcfpga.h` (the ABI). Until the layout change they were one shared `src/fpga/common/` and one shared bridge, `src/bridges/fpga/hcfpga_bridge.c`, which the porting notes name.

## The engine

A core is `descrypt16`: 16 DES rounds, each a register stage, closed into a ring. Keys enter round 0 on 16 consecutive cycles (`START_CRYPT`), each with a zero block; every 16 cycles a slot passes all 16 rounds, which is one DES encryption, and the next pass starts from its output with the halves swapped (FP and IP between passes cancel). After 25 passes, 400 cycles after the first key went in, slot i's result block (after the final permutation) is on `hash_out` in cycle 400 + i. The salt swaps E-box bits in every round. Only round 0 has an enable; rounds 1 to 15 run free.

- **Loader.** Takes a record from the intake every 2 cycles (the password is 2 words), packs the 8 bytes into upstream's 56-bit word (7 low bits per byte, byte 0 in bits 6:0, zero past the length) and writes it with the id into the input buffer of the core it is filling. It hands the buffer over when it holds 16, when the armed batch has no record left (records taken since the arm reach `batch_target`), or when no record came for `IDLE_FLUSH` (4096) cycles, the last for transports that do not arm.
- **Core.** Starts when its input buffer is handed over and one of its two result banks is free: 16 cycles loading keys (through `crypt3_ascii2bin` and `pc1`) and ids into the ring and the bank, 400 cycles of DES, then 16 cycles writing results into the bank. A new batch can start in the cycle the previous one's results begin to come out, so a core that is kept fed computes 16 candidates every 400 cycles. Empty slots of a short batch run too and are not candidates.
- **Collector.** Drains banks whose results are in, one slot per cycle: the comparator looks up the low 7 bits of hashcat's `digest[0]` in the 128-bit bitmap; a hit leaves as a 32-byte C2H record and then retires, a miss retires at once.

## Decisions

- **Longest password: 8 bytes.** A DES key is 8 bytes of 7 bits; crypt(3) drops each byte's top bit and everything past 8. Mode 1500's `module_pw_max` is 8 too, so a longer candidate is rejected by hashcat, never cut. Bytes above 0x7f lose their top bit as in crypt(3); a zero byte inside a key is a key byte of 0, as in hashcat's own kernel (libc's crypt () would stop there).
- **Salt: the 12-bit value of the 2 salt characters, every one of them.** Mode 1500's parser stores it in `salt_buf[0]` bits 11:0 and the 2 characters in bits 31:16 (`salt_len` 4), so every hash it parses is one the device computes. `salt0` carries `salt_buf[0]` and the core takes bits 11:0; salt1..3 are unused.
- **Cost: crypt(3)'s 25 encryptions, fixed in the ring.** Mode 1500 leaves `salt_iter` at 0 (its kernel loops 25 times itself); mode 91500's parser sets it to 25, because the bridge spreads a launch's candidates over hashcat's loop calls by it (a zero would divide by zero). `iter_count` is written and unused, and `kernel_loops_max` is 25.
- **A slow-hash mode for a fast hash.** Mode 1500 is `ATTACK_EXEC_INSIDE_KERNEL` with a bitsliced kernel (`KERN_BIT_TM`); mode 91500 is `ATTACK_EXEC_OUTSIDE_KERNEL` with the template's pass-through kernel, so hashcat runs init, the loop the bridge replaces, and comp. Mode 1500's `OPTS_TYPE_SELF_TEST_DISABLE` is dropped: the device computes the example hash, so the self-test runs.
- **Digest: hashcat's `digest_buf[0..1]`, built in the gateware.** Mode 1500 stores a hash as the base64-decoded output block, loaded as two little-endian words, through `DES_IP`; words 2 and 3 are zero. The engine wires `hash_out` to exactly those words (bit 8a + b of the digest is block bit 8 (7 - b) + {0,2,4,6,1,3,5,7}[a]) and returns them little-endian at C2H bytes 4..11, so the bridge takes the C2H words as received and the comparator's bitmap index, the low 7 bits of C2H byte 4, is `digest[0] & 0x7f` as the bridge computes it. Upstream's ring gives out 64 bits only with `COMPARE_35_BIT` off (`PROVENANCE.md`).
- **`core_id` names the ring** that computed the candidate (the bridge's messages say "core").
- **The core can be reset in the middle of a job.** The ring holds no state that survives a new batch (`START_CRYPT` reloads all 16 slots and zeroes the block), and everything else is the engine's, which a framing reset clears: input buffers, banks, the loader and the collector. No generation is needed.
- **No extra registers.**
- **Grain: 16 per identity core.** A ring holds 16 candidates, and the identity's `cores=` counts rings. The bridge's batch grain is `cores * 16`.
- **Batch timeout:** `WAVE_CYCLES_PER_ITER` 100: a pass of 16 candidates takes 16 cycles, and returning 16 unfiltered results takes 512 more; the bridge multiplies by 4.

## H2C record (bcrypt's)

| Word | Content |
|---|---|
| 0 | `0xbc << 24 \| len`, len 0 to 8. Anything else in this position is a slip and is skipped |
| 1 | candidate id, echoed in the C2H record. `0xfffffffe` is a canary |
| 2..3 | the password, big-endian, four bytes per word, zero filled |

## C2H record (bcrypt's, with an 8-byte digest)

| Bytes | Content |
|---|---|
| 0..3 | candidate id, little-endian. An EOB record carries the retired count here |
| 4..11 | hashcat's `digest[0]`, `digest[1]`, little-endian |
| 12..27 | zero (`digest[2..3]` are zero in mode 1500) |
| 28..29 | core_id, little-endian: the ring |
| 30..31 | flags, little-endian: 0x0000 OK, 0x8000 EOB |

## Registers

The shared block (`hcfpga_dma_wrapper.py`), nothing else:

| Offset | Name | descrypt use |
|---|---|---|
| 0x00 | ctrl | bit 0 framing reset |
| 0x04 | salt0 | hashcat's `salt_buf[0]`: the 12-bit salt in bits 11:0 |
| 0x08..0x10 | salt1..3 | unused |
| 0x14 | iter_count | unused (25, fixed) |
| 0x18 | status | bit 0 slip, bit 1 last_seen, 15:8 slip count |
| 0x1c | core_count | DES rings |
| 0x20..0x2c | cmp_bm0..3 | comparator bitmap, indexed by `digest[0] & 0x7f`, loaded on the write of cmp_bm3 |
| 0x30 | batch_target | arm; the engine also starts a short last ring once this many records are in |
| 0x34 | pad_recs | records per DMA granule |
| 0x38 | retired | records retired since the arm |

## Limits

- Passwords up to 8 bytes; a longer candidate is `Rejected` by hashcat.
- Any 2-character salt and the fixed 25 encryptions: mode 91500 takes every hash mode 1500 takes. A hash with the wrong length is a `Token length exception`, a character outside the alphabet a `Token encoding exception`, a last character whose low 2 bits are set a `Hash-value exception`, as in mode 1500.

## Running it in simulation

```
src/fpga/descrypt/hcfpga_sim.py --bridge uartbone --build-only
src/fpga/descrypt/hcfpga_sim.py --bridge uartbone --no-build &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 91500 hash.txt words.txt
```

`--uart-port` moves the UARTBone port when another sim has 2430, `--units` sets the number of rings. Etherbone (`--bridge etherbone`, `HCFPGA_LITEXBONE=udp:192.168.9.50`) needs a tap, so run the sim and hashcat under the LiteX hashcat Guide's `debug/simns.sh`. The simulated board runs at about 1 MHz.

The bench, which needs Verilator only: `make -C src/fpga sim ALGO=descrypt` (about a minute, most of it the Verilator build).
