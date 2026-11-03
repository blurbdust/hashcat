# Porting notes: md5crypt on the hcfpga framework

md5crypt (`$1$`, hashcat mode 500) is the first algorithm after bcrypt on the FPGA framework hashcat 8 introduced. These notes record how it was ported, in order, what was generic and what md5crypt forced, every snag, and what should become the template for the next ports (descrypt, sha256crypt, sha512crypt, scrypt). The design itself is described in `src/fpga/md5crypt/README.md`, its sources in `src/fpga/md5crypt/PROVENANCE.md`.

Result: hash mode 90500 (bridge `fpga_md5crypt`) cracks md5crypt through hashcat's litexbone transport against a Verilator simulation of a LiteX board, over UARTBone and Etherbone, with the self-test on. `tools/test.py -m 90500 -P` passes with `HCFPGA_TEST=1`. No bitstream has been built for a real board.

## 1. What was ported

John the Ripper's ZTEX md5crypt design (`src/ztex/fpga-md5crypt/` in openwall/john, Denis Burykin) has three layers:

| Layer | JtR files | Kept? |
|---|---|---|
| Computing unit: 3 MD5 cores, a 12-thread CPU running the md5crypt program, the MD5 block engine, the unit's input and output buffers | `md5unit.v`, `unit_ctrl.v`, `core_ctrl.v`, `unit_input_async.v`, `uob16pq.v`, `cpu/`, `md5core/`, `md5engine/`, `util/{sync,delay,asymm_bram}.v`, `md5.vh`, `log2.vh` | yes, nearly verbatim |
| Arbiters and comparator: hand candidates to units, read results, compare 32 bits against up to 512 hashes | `arbiter_tx.v`, `arbiter_rx.v`, `comparator.v`, `md5crypt_cmp_config.v`, `bcast_net.v`, `md5crypt.v` | no, replaced by hcfpga's feeder and collector |
| Packet layer and board shell: pkt_comm (word lists, generator, CMP_CONFIG), ZTEX USB | `pkt_comm/`, `ztex_inouttraffic/` | no, replaced by hcfpga's records and transports |

An earlier LiteX port (`litex_md5crypt`, kept outside this tree) wrapped all three layers (pkt_comm over two 1 KiB SRAMs). This port keeps only the unit, the same cut bcrypt made (hashcat keeps JtR's `bcrypt_core`, not its arbiter or pkt_comm).

## 2. Steps, in order

1. **Read the framework.** `docs/hashcat-fpga-setup.md`, `src/fpga/bcrypt/PROVENANCE.md`, `hcfpga_iface.vh`, `gateware/bcrypt_dma_wrapper.py`, `gateware/bcrypt/hcfpga_{top,feed,collect,collect_group}.*`, `src/bridges/bridge_fpga_bcrypt.c`, `src/bridges/fpga/hcfpga.h`, `transport_litexbone.c`, `module_75000.c`, `m75000-pure.cl`, `tools/test.py` (`HARDWARE_MODES`), and from the guide repo `debug/bcrypt_sim.py`, `debug/simns.sh`, `gateware/hcfpga_memstream.py`, `gateware/hcfpga_csr.py`, `docs/transport_litexbone.md`.
2. **Rerun the old port's sim before changing anything.** Copied it to a scratch directory (its build writes `build/` next to the script), built it with the current LiteX venv and ran it under `debug/simns.sh` (it uses Etherbone on a tap). `cleanup_test.py` cracked `$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1:hashcat` from 8 words in 32.6 s (1 unit, 1 core). Two snags, S1 and S2 below.
3. **Read JtR's unit interface,** because upstream does not document it: `arbiter_tx.v` (the input packet), `unit_input_async.v` (how a packet lands in thread memory, when `ready` drops and returns), `uob16pq.v` and `arbiter_rx.v` (the 2-bit output, its `2'b11` marker and closing `2'b00`), `cpu/program.vh` (thread memory layout, what the CPU reads, what it writes out), `core_ctrl.v` (the thread count), and JtR's host `src/ztex_md5crypt.c` (64-byte passwords, empty salts skipped, rounds sent as 1000).
4. **Import the unit verbatim** into `src/fpga/md5crypt/gateware/md5crypt/`, LF line endings only (commit `39667d3ab`), so `git diff` from that commit is the complete list of hashcat changes.
5. **Make it build outside ISE** (commit `908a792a7`): flat `` `include "md5.vh" ``, `md5.vh` defines `SIMULATION` and includes `log2.vh`, and `shreg.v`/`shreg_ff.v` lose the Xilinx `SRL16E` primitive (S3, S4). Verilator lint of `md5unit` is clean apart from style warnings. `PROVENANCE.md` lists every change.
6. **Write the hcfpga datapath** (commit `f2b7fad83`): `hcfpga_md5crypt_feed.v` (H2C records in, unit packets out), `hcfpga_md5crypt_collect.v` (unit results in, comparator, C2H records out), `hcfpga_c2h_eob.v` (retired count, EOB, padding; bcrypt's accounting on its own) and `hcfpga_md5crypt_top.sv` (the generation counter, S6).
7. **Bench it before any SoC.** `tb_datapath.v` + `tb_datapath.py` (Verilator, about 15 s to build, 6 s to run) with `md5crypt_ref.py`: every password length class 0..64, a 30-candidate comparator batch, a wrong salt, granule padding. All passed on the first run.
8. **LiteX wrapper and simulated board.** `gateware/md5crypt_dma_wrapper.py` (bcrypt's CSRs in bcrypt's order, plus `salt_len` at 0x3c) and `md5crypt_sim.py` (SoCMini on SimPlatform, UARTBone or Etherbone, HcfpgaMemStream from the guide, CSRs pinned). The generated `csr.csv` was checked against the offsets in section 4. Snags S7, S8.
9. **Host side** (commit `299a873ed`): `bridge_fpga_md5crypt.c` generated from `bridge_fpga_bcrypt.c` by a script of asserted text replacements (each fails if its text is not found exactly as often as expected), then read through; `hcfpga_md5crypt_ref.h` (MD5 and md5crypt in C for the canary, checked against the Python reference); `module_90500.c` (mode 500's parser and encoder with the device's limits); `OpenCL/m90500-pure.cl` (75000's pass-through kernel with a 16-word password and a 4-word digest); `tools/test_modules/m90500.py`; `HARDWARE_MODES = {75000, 90500}`. Everything compiled without warnings on the first build.
10. **hashcat against the sim.** The first `hashcat -m 90500` run cracked mode 500's example hash with the self-test on; then `$1$ehAsHC4t$...`, then `test.py`, then Etherbone, the comparator and no-compare paths, a wrong salt and injected failures (section 7).
11. **Gate and docs** (commit `c8a8ec7c8` and the docs commit): `make -C src/fpga sim ALGO=md5crypt` runs the bench (S9), this file, the README, the setup doc's mode table.

## 3. Generic versus md5crypt-specific

| Piece | Kept identical to bcrypt | Changed for md5crypt, and why |
|---|---|---|
| H2C record | `0xbc<<24 \| len`, id, big-endian password words, zero fill, 32-byte batch padding counted as slips | `len` limit 64, not 72: the unit keeps the key in thread memory words 10..25 |
| C2H record | 32 bytes; id at 0..3, core_id at 28..29, flags at 30..31, EOB 0x8000 carrying the retired count | digest is 16 bytes at 4..19 in MD5 output order (hashcat's `digest[k]` is the LE word at 4+4k, no byte swap); 20..27 zero; core_id names the unit, not a core (S10) |
| CSR block | every offset 0x00..0x38, their meaning, the bitmap index `digest[0] & 0x7f`, load on cmp_bm3, arm on batch_target | `salt_len` added at 0x3c; salt0..3 carry `salt_buf` unswapped (raw bytes); iter_count is rounds, 16 bits used; ctrl bit 1 unused; status bits 23:16 count unit framing errors |
| Identity | `hcfpga/1;board=..;algo=..;cores=..;clk=..;abi=4;build=..` | `algo=md5crypt`; `cores=` counts MD5 cores, the bridge multiplies by 4 threads for its grain |
| Feeder | intake framing, slip and last_seen status | packet to a JtR unit instead of a key expansion; a started packet is always finished (S6) |
| Collector | poll, emit 32-byte records, retire per result | 2-bit unit read; generation check (S6); one comparator in the collector instead of one per core |
| EOB tail | arm, retired, EOB, pad_recs | none (`hcfpga_c2h_eob.v` is algorithm independent) |
| Bridge | everything around the batch: units, pool, faults, retries, canaries, timing, temperature, link | ALGO_NAME; `CSR_SALT_LEN`; digest 4 words without swap; pw max 64; `THREADS_PER_CORE`; salt/rounds limits; md5crypt canary; no ZTEX pkt_comm dialect; no wave models; no ypcb quirk |
| Module | 75000's bridge type, options, tmp struct pattern, kernel_loops_max | mode 500's format; salt 1..8 (`module_salt_min/max`); rounds 1..65535 at parse time; pw max 64 |
| Kernel | 75000's init (copy password), empty loop, comp | tmp struct sizes; comp uses `DGST_R0..3` |
| Transports | all of `src/bridges/fpga/` unchanged | none |

## 4. Layouts

H2C record, 32-bit words, first host byte in bits 7:0:

| Word | Content |
|---|---|
| 0 | `0xbc << 24 \| len` (len 0..64) |
| 1 | candidate id (`0xfffffffe` canary) |
| 2..17 | password, big-endian four bytes per word |

Unit input packet (feeder to unit, one byte per cycle, `ctrl` on the type byte and the last byte), as stored in thread memory:

| Bytes | Content | Source |
|---|---|---|
| 0..3 | rounds | iter_count |
| 4..7 | salt length | salt_len |
| 8..23 | salt | salt0..3 |
| 24..27 | candidate id | H2C word 1 |
| 28..29 | generation | top's counter |
| 30..31 | 0 | |
| 32 | key length | H2C len |
| 33..39 | 0 | |
| 40..103 | key, rounded up to 4 bytes | H2C words 2.. |

Unit output, 12 16-bit words LSB dibit first after `2'b11`: words 0..1 id, 2 generation, 3 zero, 4..11 the digest bytes.

C2H record:

| Bytes | Content |
|---|---|
| 0..3 | id LE (EOB: retired count) |
| 4..19 | digest bytes 0..15 |
| 20..27 | 0 |
| 28..29 | unit LE |
| 30..31 | flags LE: 0x0000, 0x0001 CORE_ERR, 0x8000 EOB |

CSRs (bank at 0x0000; `ctrl` 0x0800, `identifier_mem` 0x1000, memstream 0xc000/0xc800/0xd000 as on bcrypt boards):

| Offset | Name | Offset | Name |
|---|---|---|---|
| 0x00 | ctrl | 0x20 | cmp_bm0 |
| 0x04 | salt0 | 0x24 | cmp_bm1 |
| 0x08 | salt1 | 0x28 | cmp_bm2 |
| 0x0c | salt2 | 0x2c | cmp_bm3 |
| 0x10 | salt3 | 0x30 | batch_target |
| 0x14 | iter_count | 0x34 | pad_recs |
| 0x18 | status | 0x38 | retired |
| 0x1c | core_count | 0x3c | salt_len (new) |

## 5. Snags

Times are wall clock in this session.

| # | Snag | Took | Fix | What would have prevented it |
|---|---|---|---|---|
| S1 | The old sim's Verilator build failed: `ccache: error: Failed to create temporary file ... Permission denied`. The user's `.cache/ccache/tmp` was owned by root from an earlier sudo build | 5 min | `CCACHE_DIR=<scratch>/ccache` for every build | Say in the guide's debug README that sim builds need a writable ccache, or set `CCACHE_DIR` in `simns.sh` |
| S2 | The old sim then failed to run: LiteX runs the simulator through `sudo` whenever the ethernet sim module is present, and sudo cannot work inside `simns.sh`'s user namespace (`/etc/sudo.conf is owned by uid 65534`) | 3 min | Ran the built `obj_dir/Vsim` directly inside the namespace, as `bcrypt_sim.py` does with `run=False` | Every sim target builds with `run=False` and execs Vsim itself (the md5crypt one does) |
| S3 | JtR's `shreg.v` and `shreg_ff.v` instantiate Xilinx `SRL16E` per bit. Verilator has no model, Quartus has no primitive. The old port added an `SRL16E.v` model, which would shadow the unisim cell in Vivado | 10 min | Behavioural delay line with the same fixed tap | A porting checklist step: grep the imported core for vendor primitives (`SRL16E`, `RAMB*`, `RAM64M`, `BUFG`, `LUT6`, `DSP48`) before anything else |
| S4 | The unit files use `` `MSB`` from `log2.vh` without including it (ISE's project lists it as a global file), and include `../md5.vh` relatively | 5 min | `md5.vh` includes `log2.vh`; includes flattened as bcrypt did | Same checklist step: lint the unit alone with Verilator, top = the unit, include dirs explicit |
| S5 | `core_ctrl.v` hardcodes the start slots for 12 threads (`COMP_INTERVAL = 288 / N_THREADS // must be 24`), so `N_CORES` must be 3. The old port's README ran `--cores-per-unit 1`, which happens to work but is outside what upstream supports | 5 min (reading) | `CORES_PER_UNIT` fixed at 3, documented | Read every `// must` comment in the core's control logic before choosing parameters |
| S6 | JtR's unit has no reset, but hashcat resets framing after every failed batch, with candidates still in the units. Their results would come back during the next batch, be retired and end it early | 15 min (design) | A 16-bit generation, bumped by every framing reset and arm, rides in the candidate's ID bytes; the collector drops results of another generation without retiring them. A packet already started is always finished. Proven by `HCFPGA_INJECT_FAULT=send` (section 7) | Ask early: can the core be reset mid-job, and does it echo an opaque tag? If no and yes, use the generation |
| S7 | The guide's `pin_csrs` pins the bank named `bcrypt` at 0; md5crypt's bank is `md5crypt` | 5 min | `md5crypt_sim.py` maps the location-0 entry to the algorithm's name and checks the map itself | `pin_csrs(soc, algo=...)` in the guide |
| S8 | hashcat's `src/fpga/<algo>/gateware/` and the guide's `gateware/` are both namespace packages called `gateware`; importing the guide's after hashcat's finds the wrong one | 5 min (caught while writing) | The sim loads the guide's two modules by file path | Move HcfpgaMemStream into hashcat (`src/fpga/common/`), so a sim target imports from one tree |
| S9 | `make -C src/fpga sim` checks for iverilog unconditionally; the md5crypt bench needs Verilator (the unit runs about 290,000 cycles per 1000-round hash, too slow for Icarus). The bench script also needed its execute bit | 5 min | `SIM_TOOL_<algo>` in the Makefile, default iverilog | Template: the gate script and its tool are declared per algorithm |
| S10 | md5crypt's unit decides which of its 12 threads takes a candidate, so the collector cannot name a core | 2 min | `core_id` is the unit index; the canary message says "unit" | Decide per algorithm what core_id names and write it in the README |
| S11 | `make -C src/fpga sim ALGO=bcrypt` fails to build every bench with Icarus Verilog 11.0 on this machine (`fsm.v:24: syntax error`, `bcrypt_core_c2.v:309`). The bcrypt files are byte-identical to the base commit, so this predates the branch | 5 min | none; bcrypt regression was shown with its Verilator sim and hashcat instead | Pin the Icarus version the gate needs (the syntax is an initialised `output reg` port) |
| S12 | The build host has no system OpenCL. hashcat needs a backend to generate candidates even when the FPGA hashes | 2 min (reused) | The PoCL 3.0 ICD from the bcrypt transport work (an ICD file in a scratch directory naming the wheel's `libpocl`, found through `OCL_ICD_VENDORS`), which needs `--force` (hashcat refuses PoCL older than 5.0), so `test.py` runs need `-f` | Install `intel-oneapi-runtime-opencl` or a current PoCL on the build host |
| S13 | Two UARTBone sims both listen on TCP 2430 | 2 min | The second sim (and the bcrypt regression sim) ran in its own network namespace (`simns.sh` with its own `SIMNS_DIR`) | A `--uart-port` option on the sim targets |
| S14 | The first `test.py -a all` run reported 26 errors (`The bridge plugin '.../bridge_fpga_md5crypt.so' couldn't be found`, return code 243): the plugins had been deleted and rebuilt, for the bcrypt regression check, while it was running | 10 min (a rerun) | Reran with the tree left alone | Never rebuild plugins in a tree a test run is using; rebuild first, or use a second build tree |

What went right the first time, and why: the datapath bench passed every case on its first run, the SoC built and its CSR map matched on the first build, the bridge compiled without warnings, and hashcat cracked on its first run. Each of those followed from reading JtR's arbiters and buffers for exact cycle behaviour before writing the replacements, from checking the gateware against a Python reference in a bench before any SoC existed, and from generating the bridge from bcrypt's by asserted replacements rather than by hand.

## 6. What should become the template

### Gateware

- **`hcfpga_c2h_eob.v`** is algorithm independent already: retired count, arm, EOB record, pad_recs. Move it to `src/fpga/common/` and have bcrypt's `hcfpga_collect_group.v` use it too (bcrypt keeps its engines and arbiter; the tail is the shared part). A new collector then only produces 32-byte records and `retire` pulses.
- **The H2C intake** (tag, length, id, password words, slip count, last_seen) is the same in bcrypt and md5crypt. Factor it into `hcfpga_h2c_intake.v` with a `PW_MAX` parameter and a record-ready handshake; the algorithm part starts at "a record is ready".
- **The generation pattern** (S6) for any core without a mid-job reset: counter in the top, tag in the candidate, drop in the collector. sha256crypt and sha512crypt are JtR designs of the same family (CPU-based units whose `unit/unit_input.v` and `unit/uob.v` have the same `unit_in`/`ctrl`/`wr_en` input and `2'b11`-marked serial output) and will need it as is.
- **A JtR unit adapter.** JtR's sha256crypt and sha512crypt arbiters carry the same packet layout as md5crypt's (their `arbiter_tx.v` headers list the same count, salt length, 16 salt bytes, IDs, key length and key) and read results the same way, `PKT_NUM_WORDS = RESULT_LEN/2 + 4` 16-bit words. `hcfpga_md5crypt_feed.v` and `_collect.v` could become `hcfpga_jtr_unit_feed.v` and `_collect.v` parameterised by the output word count. sha512crypt's 64-byte result does not fit the 32-byte C2H record, and need not: hashcat's comp kernel compares only the four words `DGST_POS0..3` select, so the collector sends those 16 bytes (and the module's comparison must not need more). descrypt's JtR design is different (bitsliced, one `arbiter.v`), and scrypt has no JtR FPGA core.
- **`hcfpga_iface.vh` and `hcfpga_abi.py`**: the generic lines are copies. One shared file with per-algorithm `PW_MAX` and digest size defines.

### LiteX wrapper

`Md5cryptDmaWrapper` and `BcryptDmaWrapper` differ only in the Instance parameters, one extra CSR and the source list. A base class `HcfpgaDmaWrapper` that creates the 15 shared CSRs in their fixed order, the sink/source endpoints, the framing reset, the status/retired wiring, and takes `extra_csrs` (appended from 0x3c) and the HDL top name, would make the next wrapper about 30 lines. It should assert the CSR offsets after finalize, which `md5crypt_sim.py` currently checks from `csr.csv` by hand.

### Simulated board

`md5crypt_sim.py` and the guide's `bcrypt_sim.py` are the same file apart from the wrapper. One `hcfpga_sim.py` taking `--algo` (import the wrapper by name), with `run=False`, the CSR pinning by algorithm name, `--uart-port`, and HcfpgaMemStream imported from hashcat's tree once it lives there.

### Bridge skeleton

`bridge_fpga_md5crypt.c` is 2583 lines; `diff` against `bridge_fpga_bcrypt.c` shows 410 changed lines, most of them deletions of bcrypt's ZTEX pkt_comm path and type renames. The algorithm-specific parts are few and could be hooks in a shared `src/bridges/fpga/hcfpga_bridge.c`:

| Hook | bcrypt | md5crypt |
|---|---|---|
| `ALGO_NAME`, `DIGEST_WORDS`, `PW_MAX` | "bcrypt", 6, 72 | "md5crypt", 4, 64 |
| grain per identity core | 1 | 4 |
| `send_config` extra registers | none | salt_len |
| digest word from C2H word | `byte_swap_32` | as is |
| canary reference | `hcfpga_bcrypt_canary` | `hcfpga_md5crypt` |
| salt/cost limits check | none | salt 1..8, rounds 1..65535 |
| wave models, wait cycles per iteration | measured table, 26000 | none yet, 400 |
| non-hcfpga dialects | ZTEX 1.15y pkt_comm | refused |

Until that refactor, deriving the next bridge from bcrypt's by a script of asserted replacements, each of which fails loudly if bcrypt's bridge has changed under it, is what worked here. The script was a one-off; `diff bridge_fpga_bcrypt.c bridge_fpga_md5crypt.c` shows every replacement it made.

### Module, kernel, test module

- Module: 75000's bridged header (ATTACK_EXEC_OUTSIDE_KERNEL, `OPTS_TYPE_NATIVE_THREADS | AUTODETECT_DISABLE`, `BRIDGE_TYPE_REPLACE_LOOP | LOOP_CHUNKED`, `module_bridge_name/type`, `kernel_loops_max`, tmp struct `{pw_len, pw_buf[N], digest[M]}`) plus the upstream mode's `hash_decode`/`hash_encode` verbatim plus the device's limits as parser errors and `module_salt_min/max`, `module_pw_max`. Mode number 90000 + upstream mode.
- Kernel: `m75000-pure.cl` with N and M changed and comp using `DGST_R0..3`. Could be one generated file per mode.
- Test module: the upstream mode's `.py` with `module_constraints` narrowed to the device's limits, and the mode added to `HARDWARE_MODES`.

### Bench

`tb_datapath.v` + `tb_datapath.py` (files in, records out, Python checks) carry over as they are: only the reference function and the length classes change.

## 7. Proof

All commands from the worktree root unless noted, with `S=<scratch>`, `OCL_ICD_VENDORS=$S/icd` (PoCL 3.0, hence `--force`/`-f`) and the sim built by `src/fpga/md5crypt/md5crypt_sim.py --bridge uartbone --build-only --output-dir $S/md5crypt/sim_ub` and started with `--no-build`.

| What | Command | Result |
|---|---|---|
| Old port's sim, before any change | `cleanup_test.py -c '$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1' -w words8.txt` under `simns.sh` with `litex_server --udp` | `*** CRACKED *** $1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1:hashcat`, 8 passwords in 32.611 s |
| Datapath bench | `make -C src/fpga sim ALGO=md5crypt` | lengths 0..64 (18 candidates, all digests right), cmp (30 candidates, 1 returned, 29 filtered), wrong salt (6 filtered, 0 matching), pad (EOB to a multiple of 4): `ALL PASS` |
| Mode 500's example hash | `HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 ./hashcat -m 90500 -a 0 --force --potfile-disable example.hash words8.txt` | self-test batch `recs=4 ... canaries=3`, `$1$38652870$DUjsu4TTlTsOe/xxZ05uf/:hashcat`, `Status...........: Cracked` |
| The old port's hash | same with `$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1` | `Cracked`, self-test on |
| test.py | `HCFPGA_TEST=1 HCFPGA_LITEXBONE=tcp:127.0.0.1:2430 python3 tools/test.py -m 90500 -P -f` | attack 0, single (8 vectors) and multi (8 hashes, 6 salts), vector width 1 and 4: 4 OK, 0 errors, 3 min 18 s |
| test.py, every attack a slow mode runs | same with `-a all` | attacks 0, 4, 8, 9, single and multi, vector width 1 and 4: 14 OK, 0 errors, 11 min |
| Etherbone, comparator path | under `simns.sh`: `HCFPGA_LITEXBONE=udp:192.168.9.50 HCFPGA_TIMING=1 ./hashcat -m 90500 ... -n 3 -u 1000 ehash.hash words30.txt` (29 wrong, `hashcat` 18th) | attack batch `recs=30 recv=2` (the target and one bitmap collision; 28 dropped on the device), `Cracked` |
| No-compare path | same with `HCFPGA_CMP_OFF=1` | bitmap all ones, `recs=30 recv=30`, `Cracked` |
| Wrong salt | `$1$ehAsHC4u$4IbK3fHS/H1YGtNYBrIEB1` (one salt character changed), same 30 words | `recs=30 recv=0`, `Status...........: Exhausted` |
| Rounds and the parser limits | `$1$rounds=5$ab$...`, `$1$rounds=65535$x$...`, `$1$rounds=70000$...`, `$1$$...` in one file | the first two `Cracked` (2/2 salts, 1- and 2-byte salts); line 3 `Salt-iteration count exception`, line 4 `Salt-length exception` |
| Failed batches with candidates in flight | `HCFPGA_INJECT_FAULT=send HCFPGA_INJECT_PERIOD=2`, same 30 words | `5 failures, none a wrong answer`, every redone batch with 3 canaries passed, `No candidates were skipped`, `Cracked` |
| bcrypt still works | `git diff 6b44b5399 -- src/fpga/bcrypt src/bridges/fpga src/bridges/bridge_fpga_bcrypt.*` shows only the new `hcfpga_md5crypt_ref.h`; both bridges and modules deleted and rebuilt with `make`; guide's `debug/bcrypt_sim.py --hashcat <this worktree>` (Etherbone, under `simns.sh`), then `./hashcat -m 75000 -a 0 --force -n 1 -u 32 hash.txt words.txt` and `HCFPGA_TEST=1 tools/test.py -S -m 75000 -f -D 1` | `$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou:hashcat`, `Cracked`; `1/1 hash-modes cracked their own self-test vector`. bcrypt's Icarus gate does not build on this host before or after the branch (S11) |

## 8. Not done

- No real board. The next step is a LiteX board target (the ULX3S bcrypt target in the guide is the model) and timing on silicon. The units ran at one clock in simulation; JtR clocks the cores (`CLK_CORE`) faster than the I/O, which the top supports but nothing has exercised.
- No wave model. hashcat autotunes md5crypt, with real batches, and the bridge's batch timeout uses a generous 400 cycles per round per wave.
- No md5crypt host tool (`dma_ek_test` or `hcfpga_step` equivalent). The bench and hashcat with `HCFPGA_DEBUG`/`HCFPGA_TIMING` cover the simulator; a board will want one.
- JtR's unit also runs phpass (entry point 1 in `program.vh`); a phpass mode would reuse this datapath with the entry point set by an init packet.
- The template refactors in section 6 are proposals; nothing shared was changed except the Makefile's `SIM_TOOL` hook.
- `md5crypt_sim.py` lives in this tree but takes HcfpgaMemStream and the CSR locations from the LiteX hashcat Guide (`--guide`, `HCFPGA_GUIDE`, or a `litex_hashcat_guide` checkout beside this one). The guide itself was not changed.
- The ZTEX 1.15y is not driven. JtR ships an md5crypt bitstream for it (pkt_comm, like the bcrypt one hashcat redistributes); the md5crypt bridge refuses the ZTEX dialect rather than carry bcrypt's pkt_comm path over untested.

## 9. Draft checklist for the next algorithm

1. Pick the upstream mode N; the FPGA mode is 90000 + N. Note its hash format, salt and cost ranges, digest size, and what the upstream module's `hash_decode` stores in `salt_buf`/`digest_buf` and in which byte order.
2. Find the core. JtR: `src/ztex/fpga-<algo>/`. Read its arbiters and buffers for the exact unit protocol, its program or FSM for limits, `// must` comments, and JtR's host format (`src/ztex_<algo>.c`) for the limits JtR enforces.
3. Run any existing port or JtR bench first, so the core is known good. Use `CCACHE_DIR` in scratch; run Etherbone sims under `simns.sh` with `run=False` and Vsim exec'd directly.
4. Import the core files verbatim (LF only) in one commit. Then grep for vendor primitives, relative includes and ISE global includes; fix, lint the unit alone with Verilator, add the "Modified for hashcat" notice to each changed file and a `PROVENANCE.md` row for each change.
5. Decide, and write in the README: password max, salt and cost ranges, digest bytes and byte order in C2H 4..27, what core_id names, whether cores reset mid-job (if not, use a generation), what extra CSRs are needed (append from 0x3c, never reorder 0x00..0x38).
6. Write feed and collect around `hcfpga_c2h_eob.v`; keep the H2C intake and C2H record byte-identical to bcrypt's except the digest bytes.
7. Bench with a Python reference: every length class the core branches on, max length, a comparator batch with one hit, a wrong salt, padding. Wire it to `make -C src/fpga sim ALGO=<algo>` (`SIM_SCRIPT_<algo>`, `SIM_TOOL_<algo>`).
8. LiteX wrapper with the shared CSRs in bcrypt's order; sim target with ident `hcfpga/1;board=sim;algo=<algo>;cores=..;clk=1;abi=<FPGA_ABI_CURRENT>`; check `csr.csv` against the offsets.
9. Bridge from bcrypt's (or the shared skeleton once it exists): ALGO_NAME, digest words and swap, PW_MAX, grain, extra config registers, limits, canary reference in C checked against the Python reference.
10. Module 9xxxx, kernel `m9xxxx-pure.cl`, test module with narrowed constraints, `HARDWARE_MODES`.
11. Prove, in this order: the upstream example hash with the self-test on; `HCFPGA_TEST=1 tools/test.py -m 9xxxx -P -f` (and `-a all`); a batch with one right candidate among many (`HCFPGA_TIMING=1` shows `recv`); `HCFPGA_CMP_OFF=1`; a wrong salt; `HCFPGA_INJECT_FAULT=send`; both bridges (UARTBone, Etherbone); bcrypt's sim still cracks.
12. Docs: README, PROVENANCE, the setup doc's mode table, porting notes with every snag.

## 10. Template outcome

Sections 6 and 9 were carried out on branch `fpga-template`. md5crypt now runs on shared pieces that the next algorithm reuses, bcrypt's files are unchanged, and the draft checklist became `AGENTS.md` in the LiteX hashcat Guide (with `docs/porting-algorithm.md` there for humans).

### What moved where

| Was (md5crypt) | Now |
|---|---|
| `gateware/md5crypt/hcfpga_c2h_eob.v` | `src/fpga/common/rtl/hcfpga_c2h_eob.v`, unchanged logic |
| the intake half of `hcfpga_md5crypt_feed.v` | `rtl/hcfpga_h2c_intake.v`: `PW_MAX` parameter, a password read port, `hold` for a send in progress |
| the transmitter half of `hcfpga_md5crypt_feed.v` | `rtl/hcfpga_jtr_unit_feed.v`: `PW_MAX`, `KEY_ALIGN` (4, or 8 for sha512crypt's 64-bit thread memory) |
| `hcfpga_md5crypt_collect.v` | `rtl/hcfpga_jtr_unit_collect.v`: `RESULT_LEN` (16, 32, 64), forwards `DIGEST_BYTES` from `DIGEST_OFF`, `CMP_BYTE` |
| the generation counter in `hcfpga_md5crypt_top.sv` | `rtl/hcfpga_gen.v` |
| `tb_datapath.v`, the plumbing of `tb_datapath.py` | `rtl/tb_hcfpga.v` (the top comes from the algorithm's `tb_dut.vh`), `hcfpga_bench.py` |
| `Md5cryptDmaWrapper`'s registers and wiring | `hcfpga_dma_wrapper.py`: `HcfpgaDmaWrapper`, `EXTRA_CSRS` from 0x3c, `check_offsets()` |
| `md5crypt_sim.py` | `hcfpga_sim.py --algo md5crypt` (also `--algo bcrypt`), `--uart-port`, `--tap`, `--host-ip` |
| `hcfpga_abi.py`, `hcfpga_iface.vh` | `common/hcfpga_abi.py`, `common/rtl/hcfpga_iface.vh` |
| HcfpgaMemStream and the CSR pinning, loaded from the Guide | `common/hcfpga_memstream.py`, `common/hcfpga_csr.py` (`pin_csrs(soc, algo)`) |
| `bridge_fpga_md5crypt.c` | `src/bridges/fpga/hcfpga_bridge.c` and `hcfpga_bridge.h` (`hcfpga_algo_t`), plus a 91-line hook file |

New: `new_fpga_algo.py` and `template/` (the scaffold), `rtl/hcfpga_jtr_unit_stub.v` (a JtR unit with a toy hash), and a hook check in the bridge (`algo_valid`).

The hooks are the table in section 6: name, tmp struct (`HCFPGA_TMP_LAYOUT`), `pw_max`, `grain_per_core`, `core_name`, salt and iteration limits, `wait_cycles_per_iter`, `wave_models`, `canary_pw`, `canary_digest`, `config_regs`, `config_extra`, `digest_from_c2h`, `salt_check`, `diag_hint`. The configuration and canary caches now key on the whole salt (`salt_buf`, length, iterations, `salt_sign`) rather than four words, so an algorithm with more salt state needs no change there.

### Line counts, hashcat-written md5crypt files

| | Before | After |
|---|---|---|
| Bridge | `bridge_fpga_md5crypt.c` 2583 | `bridge_fpga_md5crypt.c` 91 (shared: `hcfpga_bridge.c` 2676, `hcfpga_bridge.h` 186) |
| Gateware and sim | feed 264, collect 207, EOB 140, top 141, wrapper 132, sim 275, `hcfpga_abi.py` 35, `hcfpga_iface.vh` 30: 1224 | top 138, wrapper 69: 207 |
| Bench | `tb_datapath.v` 154, `tb_datapath.py` 229, `md5crypt_ref.py` 78: 461 | `tb_dut.vh` 8, `tb_datapath.py` 130, `md5crypt_ref.py` 78: 216 |
| All | 4268 | 514 |

### Same behaviour

- The bench cycle counts are identical before and after (lengths 827871, cmp 581090, salt 290015, pad 3381).
- The simulated board's `csr.csv` is identical to `md5crypt_sim.py`'s apart from the build stamp.
- `git diff 6b44b5399 -- src/fpga/bcrypt src/bridges/bridge_fpga_bcrypt.c src/bridges/bridge_fpga_bcrypt.mk src/modules/module_75000.c OpenCL/m75000-pure.cl` is empty; `src/bridges/fpga/` only gained `hcfpga_bridge.c` and `hcfpga_bridge.h`.

### Proofs, rerun on the template

Same environment as section 7 (`OCL_ICD_VENDORS` to the PoCL 3.0 ICD, `--force`), sims built by `src/fpga/common/hcfpga_sim.py --algo md5crypt --bridge <uartbone|etherbone> --build-only --output-dir <dir>`, the UARTBone one run with `--uart-port 2531`, the Etherbone one under `simns.sh` with its own `SIMNS_DIR`. Hashcat, bridges and modules rebuilt from the branch (`make` after deleting both FPGA bridges and modules 75000 and 90500).

| What | Command | Result |
|---|---|---|
| Datapath bench | `make -C src/fpga sim ALGO=md5crypt` | lengths, cmp, salt, pad: `ALL PASS` |
| Mode 500's example hash, UARTBone, self-test on | `HCFPGA_DEBUG=1 HCFPGA_LITEXBONE=tcp:127.0.0.1:2531 ./hashcat -m 90500 -a 0 --force --potfile-disable example.hash words8.txt` | self-test batch `recs=4 ... canaries=3`, `$1$38652870$DUjsu4TTlTsOe/xxZ05uf/:hashcat`, `Cracked` |
| Same, Etherbone | `HCFPGA_LITEXBONE=udp:192.168.9.50` under `simns.sh` | same batches, `Cracked` |
| test.py | `HCFPGA_TEST=1 HCFPGA_LITEXBONE=tcp:127.0.0.1:2531 python3 tools/test.py -m 90500 -P -f` | attack 0, single and multi, vector width 1 and 4: 4 OK, 3 min 9 s |
| test.py, every attack | same with `-a all` | attacks 0, 4, 8, 9, single and multi, vector width 1 and 4: 14 OK, 0 errors, 10 min 48 s |
| Comparator | Etherbone, `HCFPGA_TIMING=1 ... -n 3 -u 1000 ehash.hash words30.txt` | `recs=30 recv=2`, `Cracked` |
| No compare | same with `HCFPGA_CMP_OFF=1` | `recs=30 recv=30`, `Cracked` |
| Wrong salt | `$1$ehAsHC4u$...`, same 30 words | `recs=30 recv=1` (a bitmap collision, not a match), `Exhausted` |
| Failed batches | `HCFPGA_INJECT_FAULT=send HCFPGA_INJECT_PERIOD=2` | `5 failures, none a wrong answer`, `No candidates were skipped`, `Cracked` |
| bcrypt | the Guide's `debug/bcrypt_sim.py --hashcat <this tree>` (Etherbone, `simns.sh`), `./hashcat -m 75000 -a 0 --force --potfile-disable -n 1 -u 32` and `HCFPGA_TEST=1 tools/test.py -S -m 75000 -f -D 1` | `Cracked`; `1/1 hash-modes cracked their own self-test vector` |
| bcrypt through the generic sim | `hcfpga_sim.py --algo bcrypt --units 4 --bridge uartbone --uart-port 2532`, then `./hashcat -m 75000 -a 0 --force --potfile-disable -n 1 -u 32` | `Cracked` (the CSR map equals `bcrypt_sim.py`'s) |

None of the rows above ran with fewer loops per kernel call than the hash's rounds, so they missed a bug in `hcfpga_bridge.c`: `launch_loop` offset the first candidate of a loop chunk by bytes, not by tmp structs, and every chunk after the first sent the wrong candidates. The sha256crypt port found it (its parser-limit row forced `Loops:1`); `affaa7010` fixes it. After the fix, the bench and every row above except the bcrypt ones passed again, and so did two runs through the fixed path:

| What | Command | Result |
|---|---|---|
| Loops below rounds | UARTBone, `-u 100` on mode 500's example hash (1000 rounds), eight words | `Loops:100`, `Cracked` |
| Three salts, loops below rounds | UARTBone, `-n 1 -u 250`, three hashes with salts of 6, 5 and 1 bytes, their passwords 14th, 20th and 23rd of 24 words | `Loops:250`, `3/3 ... Salts`, `Cracked` |

### The scaffold, proved on throwaway algorithms

In a copy of this tree (never the one under test):

- `new_fpga_algo.py --name sha512crypt_try --mode 1800 --core jtr-unit --pw-max 64 --result-len 64 --key-align 8 --salt-min 1 --salt-max 16 --iter-min 1000 --iter-max 999999999`: bridge and module build without warnings; the untouched bench (stub unit, sha512crypt's geometry) prints `ALL PASS`; the top lints clean with Verilator; the simulated board builds with `salt_len` at 0x3c; and `hashcat -m 91800 --self-test-disable` against that board runs batches whose canaries match the generated C reference, ending `Exhausted` (the stub hashes a toy, so nothing cracks).
- `new_fpga_algo.py --name descrypt_try --mode 1500 --core custom --pw-max 8 --digest-words 4 --digest-bytes 8 --iter-min 0`: bridge and module build, the bench passes with the engine stub, the top lints clean, the board builds, and the canary password is cut to 8 bytes.

Two fixes came out of this: the generated canary reference wrote past its buffer when the device returns fewer digest bytes than the tmp struct holds, and a canary password longer than `pw_max` would have been a slip on the device. The second is now refused by the bridge at init.

### Snags of the template work

| # | Snag | Fix |
|---|---|---|
| T1 | `pkill -f` with a pattern that was also in the agent's own command line killed its shell | stop sims by PID (by their working directory) |
| T2 | `self.wrapper = wrapper` in the sim SoC made a second CSR bank at location 3 | the wrapper is only the attribute named after the algorithm |
| T3 | Register names inside a LiteX bank have no bank prefix; `csr.csv` adds it | `check_offsets()` strips the prefix if present |
| T4 | Canary password longer than `pw_max` | `canary_pw` hook, scaffold truncates, bridge refuses at init |
| T5 | Module, kernel and bridge each declare the tmp struct | `HCFPGA_TMP_LAYOUT`, the bridge checks `hashconfig->tmp_size` at launch |
| T6 | `tmps.digest[DGST_R0..3]` past a short digest | the tmp digest has at least `DGST_POS3 + 1` words; unused device words are zero |

### Not done by the template

- bcrypt is not on it, on purpose: its files stay upstream's. `hcfpga_sim.py --algo bcrypt` builds bcrypt's own wrapper the way the Guide's `bcrypt_sim.py` does.
- The Guide keeps its bcrypt-only `gateware/hcfpga_memstream.py` and `hcfpga_csr.py` for `debug/bcrypt_sim.py`, which has to work against an upstream hashcat without `src/fpga/common`.
- No board target for any template algorithm yet, and no wave model; the next step for md5crypt is unchanged (section 8).
