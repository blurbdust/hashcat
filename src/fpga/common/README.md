# Shared FPGA template

What every hcfpga algorithm after bcrypt shares, gateware and Python. bcrypt (`src/fpga/bcrypt`) predates it and keeps its own copies, so it is unchanged; md5crypt (`src/fpga/md5crypt`) was the first algorithm on it. The host side is `src/bridges/fpga/hcfpga_bridge.c` (see `hcfpga_bridge.h`).

A new algorithm starts with `new_fpga_algo.py`, which writes every file a port needs from `template/`, each with `HCFPGA-TODO` where a decision or the core goes. The procedure for porting a core is `AGENTS.md` in the LiteX hashcat Guide.

## Contents

| File | What |
|---|---|
| `rtl/hcfpga_iface.vh` | the frame contract: H2C tag, C2H record size, flags, part index, canary id |
| `rtl/hcfpga_h2c_intake.v` | H2C records in, one whole record out (length, id, password words), slip count, last_seen; `PW_MAX` |
| `rtl/hcfpga_c2h_eob.v` | retired count, end-of-batch record, granule padding; a collector in front of it only produces records and retire pulses |
| `rtl/hcfpga_gen.v` | the batch generation, for cores that cannot be reset mid-job: tag each candidate, drop stale results |
| `rtl/hcfpga_jtr_unit_feed.v` | John the Ripper crypt-family units: H2C record to unit packet (`PW_MAX`, `KEY_ALIGN`), in place of JtR's `arbiter_tx.v` |
| `rtl/hcfpga_jtr_unit_collect.v` | JtR units: 2-bit result read (`RESULT_LEN`), generation check, comparator, C2H record with `DIGEST_BYTES` from `DIGEST_OFF`, in place of `arbiter_rx.v` and `comparator.v` |
| `rtl/hcfpga_jtr_unit_stub.v` | a JtR unit with the same protocol and a toy hash, for benches and scaffolds |
| `rtl/tb_hcfpga.v` | the datapath bench; an algorithm supplies `tb_dut.vh` (its top's instance) |
| `hcfpga_bench.py` | the bench's Python side: H2C records as the bridge builds them, run, check the C2H stream (multi-part results included); run alone, it checks its own checker against broken parts |
| `hcfpga_dma_wrapper.py` | `HcfpgaDmaWrapper`: the 15 shared registers at bcrypt's offsets, extras from 0x3c, the streams, the framing reset, `check_offsets()` |
| `hcfpga_csr.py` | the CSR locations hashcat hardcodes, the algorithm bank named after the algorithm: `pin_csrs()`, `check_csrs()` |
| `hcfpga_memstream.py` | `HcfpgaMemStream`: the two streams over register accesses, for LiteX bus bridges (from the LiteX hashcat Guide) |
| `hcfpga_sim.py` | any algorithm on a simulated LiteX board: `--algo <name>`, Etherbone or UARTBone, `--uart-port` |
| `hcfpga_abi.py` | `FPGA_ABI_CURRENT` from the bridge header |
| `new_fpga_algo.py`, `template/` | the scaffold |

The Python here is plain modules named `hcfpga_*`, not a package: hashcat's `src/fpga/<algo>/gateware/` and the Guide's `gateware/` are both namespace packages called `gateware`, and a third would make imports depend on path order. The Verilog lives in `rtl/` for the same reason.

## The contract

Records and registers are bcrypt's, so the transports and the shared CSR map drive every algorithm the same way.

H2C, 32-bit words, first host byte in bits 7:0: word 0 `0xbc << 24 | len`, word 1 the candidate id (`0xfffffffe` a canary), then the password big-endian four bytes per word. hashcat pads a batch to 32 bytes with zero words, which count as slips.

C2H, 32 bytes: id at 0..3 (EOB: the retired count), digest from byte 4 (at most 24 bytes, zero after), core_id at 28..29, flags at 30..31 (0x0001 CORE_ERR, 0x8000 EOB). The bridge turns C2H words 1.. into hashcat's `digest_buf` words 0.. with the algorithm's `digest_from_c2h` (none: as received). The comparator indexes its 128-bit bitmap with the low 7 bits of what becomes `digest[0]`.

Multi-part results, for a device that returns more than 24 digest bytes (WPA's 32-byte PMK): a candidate's result is P records (P = 2 to 4) sent one after the other with the same id. Record k carries digest bytes 24k..24k+23 at bytes 4..27 and its part index k in flag bits 8..11; core_id is the same in each. The comparator decides on the candidate as a whole from the first part, as it does on a single record, and a filtered candidate sends no record at all. The candidate retires once, after its last part, so `retired` and the EOB count stay candidate counts, and the EOB tail never comes between two parts. P = 1 is the single record above, part index 0. The bridge (`hcfpga_algo_t.c2h_parts`) puts part k's words after part k-1's before `digest_from_c2h`, sizes its C2H buffers for P records per candidate, and fails the batch (it is redone) on a missing, repeated or out-of-order part. The custom engine template (`template/gateware/engine_custom.v.in`) states this contract; `hcfpga_jtr_unit_collect.v` sends one record per candidate.

Registers at the algorithm bank (location 0): ctrl 0x00, salt0..3 0x04..0x10, iter_count 0x14, status 0x18, core_count 0x1c, cmp_bm0..3 0x20..0x2c, batch_target 0x30, pad_recs 0x34, retired 0x38, then the algorithm's own from 0x3c.

Identity: `hcfpga/1;board=<board>;algo=<name>;cores=<n>;clk=<MHz>;abi=<FPGA_ABI_CURRENT>;build=<stamp>`, plus `parts=<P>` when a candidate returns P > 1 C2H records (the wrapper's `PARTS`; no key means 1). The bridge refuses a board whose parts disagree with its `c2h_parts`. The bridge's batch grain is `cores * grain_per_core`.
