# wpa2 on FPGA

Hash mode 92500 (bridge `fpga_wpa2`) computes the PMK of WPA-PBKDF2-PMKID+EAPOL (mode 22000's format, hcxtools' `WPA*01*` PMKID and `WPA*02*` EAPOL lines) on an FPGA. The device computes the PMK, PBKDF2-HMAC-SHA1 (passphrase, ESSID, 4096 iterations, 32 bytes), from the password and the ESSID; everything after it (the PMKID, the PTK and the MIC of each key version, the FT key hierarchy, nonce error corrections) stays in hashcat's kernels, which are mode 22000's comp kernels reading the PMK from the bridge's tmp struct. The PBKDF2 and SHA-1 cores are OpenCiphers' (David Hulton, for Pico Computing; BSD, see `PROVENANCE.md`); the engine around them, which computes the HMAC setup on the device, was written for hashcat.

Scaffolded by `new_fpga_algo.py --name wpa2 --mode 22000 --fpga-mode 92500 --core custom --pw-max 63 --digest-words 8 --digest-bytes 32 --grain 1 --salt-min 0 --salt-max 32 --iter-min 4095 --iter-max 4095` (then in `src/fpga/common/`, now the LiteX hashcat Guide's `template/`). 90000 + 22000 is past the unofficial range (90000 to 99998), so the mode number is the project owner's choice.

No bitstream is published. The design runs on a simulated LiteX board (`src/fpga/wpa2/hcfpga_sim.py`), which hashcat reaches through the litexbone transport.

## Layout

| Path | What |
|---|---|
| `gateware/wpa2/wpapsk/`, `gateware/wpa2/sha1/` | OpenCiphers' PBKDF2 core and SHA-1 cores (see `PROVENANCE.md`) |
| `gateware/wpa2/hcfpga_wpa2_engine.v` | the setup unit, the PBKDF2 pairs, the generation and the collector |
| `gateware/wpa2/hcfpga_wpa2_top.sv` | datapath top: the shared H2C intake, the engine, the end-of-batch tail |
| `gateware/wpa2_dma_wrapper.py` | the LiteX wrapper (an `HcfpgaDmaWrapper`) and its extra registers |
| `gateware/wpa2/tb_datapath.py`, `tb_dut.vh`, `wpa2_ref.py` | the datapath bench (`make -C src/fpga sim ALGO=wpa2`) and its reference |
| `gateware/wpa2/hcfpga_h2c_intake.v`, `hcfpga_gen.v`, `hcfpga_c2h_eob.v` | the shared RTL: the H2C intake, the generation counter, the end-of-batch tail |
| `gateware/wpa2/tb_hcfpga.v`, `hcfpga_bench.py` | the shared bench the algorithm's `tb_datapath.py` runs |
| `hcfpga_dma_wrapper.py`, `hcfpga_sim.py`, `hcfpga_csr.py`, `hcfpga_memstream.py`, `hcfpga_abi.py`, `hcfpga_iface.vh` | the wrapper base, the simulated board (Verilator, Etherbone or UARTBone, memstream), CSR pinning, the ABI reader, the frame contract |

Host side: `src/bridges/bridge_fpga_wpa2.c` and `.mk` (bcrypt's bridge with wpa2's specifics: `diff` it against `bridge_fpga_bcrypt.c`), `src/bridges/fpga/hcfpga_wpa2_ref.h` (the canary's reference), `src/modules/module_92500.c`, `OpenCL/m92500-pure.cl`, `tools/test_modules/m92500.py`.

The shared pieces are copies of the LiteX hashcat Guide's `template/shared/`, as every algorithm after bcrypt has them; this directory needs nothing outside itself but `src/bridges/fpga/hcfpga.h` (the ABI). Until the layout change they were one shared `src/fpga/common/` and one shared bridge, `src/bridges/fpga/hcfpga_bridge.c`, which the porting notes name.

## How a candidate is computed

1. The setup unit takes the H2C record and computes the HMAC setup on OpenCiphers' general SHA-1 core (`sha1/Sha1.v`, `Sha1Full`), one 16-word block at a time through its message memory (`Sha1BRAM`): ipad = SHA1-compress (IV, K ^ 0x36..), opad = SHA1-compress (IV, K ^ 0x5c..), then for block i = 1 and 2, inner = SHA1-compress (ipad, ESSID || INT (i) || padding) and U1 (i) = SHA1-compress (opad, inner || padding). K is the password zero filled to 64 bytes. Six compressions, about 600 cycles.
2. It hands ipad, opad, U1 (1) and U1 (2) to a free pair of OpenCiphers' PBKDF2 cores (`wpapsk/PBKDF2.v`), which run blocks 1 and 2 side by side: 4095 more HMACs each, the XOR of all 4096, about 680,000 cycles.
3. The collector sends the PMK, block 1's 20 bytes and the first 12 of block 2's, as two C2H records.

The setup unit is shared: one candidate's setup takes about 600 cycles against the pair's 680,000, so one setup unit can feed about a thousand pairs.

## Decisions

- Longest password: 63 bytes. WPA passphrases are 8 to 63 bytes (mode 22000's `module_pw_min` and `module_pw_max`), so the HMAC key is always one block, never hashed first. The device takes 0 to 63 bytes and zeroes every key byte from the record's length on; hashcat sends only 8 to 63.
- Salt and cost: the ESSID, 0 to 32 bytes, mode 22000's own range (its parser's salt is the ESSID, `salt_len` its length). The iteration count is the format's, 4096; mode 22000 stores 4095 as `salt_iter` (the count after U1), which the module refuses to be anything else and the device does not read.
- Digest: the PMK's 32 bytes in order, bytes 0..23 at C2H bytes 4..27 of the first record, 24..31 at bytes 4..11 of the second (bytes 12..27 zero). The bridge byte-swaps each C2H word (`byte_swap_32`, as bcrypt's), so `digest_buf[k]` is PMK bytes 4k..4k+3 big-endian: mode 22000's `tmps.out[k]`, which its comp kernels read. The comparator byte would be PMK byte 3 (the low byte of `digest[0]`), but hashcat builds the device without the comparator (`WITH_CMP = 0`): hashcat's digest is the MIC or PMKID, which only the comp kernels compute, so no bit of the PMK can be looked up in a bitmap of digests. Every candidate returns.
- Two C2H records per candidate (`PARTS = 2`, the bridge's `C2H_PARTS` 2, `parts=2` in the identity): the template's multi-part results, since a record carries 24 digest bytes and the PMK is 32.
- `core_id` names the PBKDF2 pair.
- Reset in the middle of a job: a PBKDF2 core cannot be stopped cleanly mid-run, so nothing is stopped. The generation (`hcfpga_gen.v`) is taken when the setup unit takes the record; a pair runs to the end and the collector drops a result of another generation without retiring it, and the setup unit drops a candidate it finished after the generation moved on. The setup unit holds the intake's record while it reads the password (`hold`).
- Extra registers: `salt_len` (0x3c), `salt4..7` (0x40..0x4c, ESSID bytes 16..31; `salt0..3` carry bytes 0..15).
- Batch grain: one candidate per pair (the bridge has no `GRAIN_PER_CORE`: 1); the identity's `cores=` counts pairs.
- PBKDF2.v starts one more SHA-1 compression as it finishes; a core restarted before it ends computes a wrong result. A pair rests 128 cycles after it finishes before it takes the next candidate (80 is the least a bench of the core alone found right).

## Registers

The shared block (`hcfpga_dma_wrapper.py`), plus:

| Offset | Name | Use |
|---|---|---|
| 0x3c | `salt_len` | ESSID length in bytes, 0 to 32 |
| 0x40 | `salt4` | ESSID bytes 16..19 (`salt_buf[4]`) |
| 0x44 | `salt5` | ESSID bytes 20..23 |
| 0x48 | `salt6` | ESSID bytes 24..27 |
| 0x4c | `salt7` | ESSID bytes 28..31 |

`salt0..3` carry ESSID bytes 0..15, byte 0 in bits 7:0 of `salt0`. `iter_count` is written (4095) and not used. The comparator bitmap is written and not used.

## Limits

- Password 0 to 63 bytes on the device; hashcat sends 8 to 63 (a shorter or longer candidate is `Rejected`).
- ESSID 0 to 32 bytes: mode 22000's parser refuses a longer one (`Token length exception`), so the module has no limit of its own.
- 4096 iterations, the format's.
- Every record type of mode 22000 (PMKID, EAPOL with key versions 1 to 3, FT PMKID, FT EAPOL): the device computes only the PMK they share.

## Running it in simulation

```
src/fpga/wpa2/hcfpga_sim.py --bridge uartbone --units 2 --build-only
src/fpga/wpa2/hcfpga_sim.py --bridge uartbone --units 2 --no-build --uart-port 2430 &
HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 92500 hash.txt words.txt
```

A simulated candidate is about 680,000 cycles, a second or two at the simulator's speed per pair, so keep word lists short.

The bench, which needs Verilator only: `make -C src/fpga sim ALGO=wpa2`.
