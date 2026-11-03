# Porting notes: sha512crypt on the hcfpga framework

sha512crypt (`$6$`, hashcat mode 1800) is the third algorithm on the shared FPGA template (`src/fpga/common`, `src/bridges/fpga/hcfpga_bridge.c`) and the second ported with the LiteX hashcat Guide's `AGENTS.md` alone. These notes follow md5crypt's and sha256crypt's (`docs/fpga-porting-notes-md5crypt.md`, `docs/fpga-porting-notes-sha256crypt.md`): what was ported, the steps in order, what was generic and what sha512crypt forced, the layouts, every snag, the proofs and what is not done. The design is described in `src/fpga/sha512crypt/README.md`, its sources in `src/fpga/sha512crypt/PROVENANCE.md`.

Result: hash mode 91800 (bridge `fpga_sha512crypt`) cracks sha512crypt through hashcat's litexbone transport against a Verilator simulation of a LiteX board, over UARTBone and Etherbone, with the self-test on. `tools/test.py -m 91800 -P` passes with `HCFPGA_TEST=1`, with every attack. This port found nothing wrong in the template: everything sha512crypt needed was a parameter or a hook it already had. The branch carries one template fix from the descrypt port, cherry-picked during the proofs (`dca3b6c14`, the framing reset held while a failed board's rings are emptied); section 6 says which rows ran with it. bcrypt's files did not change. No bitstream has been built for a real board.

**Layout changed after these notes.** The template they describe was replaced by hashcat's documented layout. `src/bridges/bridge_fpga_sha512crypt.c` is one complete bridge, upstream's `bridge_fpga_bcrypt.c` with sha512crypt's specifics (`diff` the two), in place of a hook file on the shared `src/bridges/fpga/hcfpga_bridge.c`; and `src/fpga/sha512crypt/` carries its own copies of the shared RTL, bench, wrapper base and simulated board (`src/fpga/sha512crypt/hcfpga_sim.py`, without `--algo`) in place of `src/fpga/common/`. The template and the scaffold moved to the LiteX hashcat Guide (`template/`). The paths and hook names below are as they were when the notes were written. On the new layout, the bench, the example hash with the self-test on over UARTBone, `test.py` and the injected-failure row were rerun and passed.

## 1. What was ported

John the Ripper's ZTEX sha512crypt design (`src/ztex/fpga-sha512crypt/` in openwall/john, Denis Burykin) has the same three layers as its md5crypt and sha256crypt designs:

| Layer | JtR files | Kept? |
|---|---|---|
| Computing unit: 4 SHA-512 cores, a 16-thread CPU running the sha512crypt program (and a Drupal7 one), the SHA-512 block engine, the unit's input and output buffers | `unit/{sha512unit,unit_ctrl,core_ctrl,unit_input,uob}.v`, `cpu/`, `sha512core/` (without `ff32.v` and `core_test.v`), `sha512engine/`, `sha512.vh`, `../util/asymm_bram.v`, `../util/log2.vh` | yes, nearly verbatim |
| Arbiters and comparator | `arbiter_tx.v`, `arbiter_rx.v`, `comparator.v`, `xcrypt_cmp_config.v`, `bcast_net.v`, `sha512crypt.v` | no, replaced by the template's JtR unit feeder and collector |
| Packet layer and board shell | `pkt_comm/`, `ztex_inouttraffic/`, `main.vh` | no, replaced by hcfpga's records and transports |

An older LiteX port (`~/claude/litex_sha512crypt`, kept outside this tree) wrapped all three layers (pkt_comm over two 1 KiB SRAMs, one unit). This port keeps only the unit.

## 2. Steps, in order

Wall-clock times from the start of the session (03:17).

1. **Branch** (step 1): skipped; the worktree was already on branch `sha512crypt`, built on `sha256crypt`.
2. **Read** (step 2, 6 min): both porting notes, `src/fpga/common/README.md`, `hcfpga_bridge.h`, sha256crypt's top, wrapper, bench, references, bridge and module, md5crypt's bridge, the shared feeder and collector; then JtR's `README.md`, `sha512.vh` (`N_CORES` 4, `N_THREADS` 16, 64-bit thread memory, `ENTRY_PTS_EN`, and `SIMULATION` commented out), `unit/sha512unit.v`, `core_ctrl.v` (`COMP_INTERVAL = TOTAL_CYCLES / N_THREADS // must be 22`), `unit_input.v` ("Data size must be divisible by MEM_WIDTH bits", the program selector: type 1 packets set the entry point), `uob.v` (`PKT_LEN` 36), `cpu/instruction.v` (entry point 0 is sha512crypt, 1 Drupal7), `cpu/program.vh` (thread memory layout, "key_len=0 is supported", "salt_len=0, cnt=0 NOT supported", a 32-bit round count in two 16-bit registers, 36 output words), `arbiter_tx.v` (the same 40-byte header as sha256crypt's, the key "rounded up to 64 bits"), `arbiter_rx.v` (`PKT_NUM_WORDS = RESULT_LEN/2 + 4`), `main.vh` (`PLAINTEXT_LEN 64`, `RESULT_LEN 64`) and JtR's host format `src/ztex_sha512crypt.c` (64-byte keys, salts 1 to 16, rounds 1 to 999999999 sent as given, empty salts skipped). Mode 1800's module and test module.
3. **Ran the older LiteX port first** (step 3, 3 min). Copied it to scratch, built its sim under `simns.sh` (the build's run step fails at `sudo`, as N1 said), started `build/sim/gateware/obj_dir/Vsim` and `litex_server --udp --udp-ip 192.168.9.50` in the namespace and ran its `cleanup_test.py` with the command its README gives (`--num-units 1 --cores-per-unit 1`): `*** CRACKED *** $6$qdMgClgO2dQWB37F$...:hashcat`, 10 passwords in 48.3 s. The unit is known good. Reading that port's diff against upstream showed two things this port then used: it passes `N_CORES`/`N_THREADS` down through `sha512unit.v`, which upstream does not (P6), and it defines `SIMULATION` from an extra `util/ff32.v` (P1).
4. **Scaffold** (step 4, 1 min, commit `67c196f84`): `new_fpga_algo.py --name sha512crypt --mode 1800 --core jtr-unit --pw-max 64 --result-len 64 --key-align 8 --cores-per-unit 4 --grain 4 --salt-min 1 --salt-max 16 --iter-min 1 --iter-max 999999999`. The untouched bench passed with the stub unit (`ALL PASS`, 8 s), the bridge and module compiled without warnings from the scaffold's files.
5. **Import** (step 5, 2 min, commit `e76e572aa`): 34 files, CRLF to LF and nothing else (checked with `diff --strip-trailing-cr` against upstream). The set came from a lint of `sha512unit` alone, after P2. The files were copied from the JtR checkout's working tree; a later check found no local edits under `src/ztex/fpga-sha512crypt` there and all 34 files equal to `git archive ad3c92343` of it, the commit `PROVENANCE.md` names.
6. **Build outside ISE** (step 5, 3 min, commit `2ae072cf4`): one `SRL16E` (`sha512core/shreg.v`, replaced the way md5crypt's and sha256crypt's were), 27 relative includes flattened, `log2.vh` included by `sha512.vh` and `util/asymm_bram.v`, and `SIMULATION` defined in `sha512.vh` (P1). Verilator lint of `sha512unit` alone: no errors; width, implicit-net and unsigned warnings only, all upstream (see `PROVENANCE.md`, "Left as upstream wrote it").
7. **Decide** (step 6, 3 min): written in the README's Decisions section.
8. **Gateware** (step 7, 2 min): `sha512unit` in place of the stub, `CORES_PER_UNIT` 4, geometry 64/8/64/0/16, the unit's files in the wrapper and the bench, the stub out of `COMMON_RTL` and of the bench's `SOURCES`. No core clock: the unit has one clock.
9. **References** (step 8, 3 min): the Python reference is hashcat's own oracle (`tools/test_modules/lib/shacrypt.py`), whose result is decoded from the `$6$` string with mode 1800's decoder permutation; it reproduces mode 1800's example hash, the older port's hash and three JtR ZTEX vectors (salt 1 and 16, keys of 48 and 56 bytes), and libc `crypt ()` for three more (a 64-byte key among them). The C reference (`hcfpga_sha512crypt_ref.h`, self-contained SHA-512 and sha512crypt) agreed with it on 45 cases (random passwords 0 to 64 bytes, binary ones included, salts 1 to 16, rounds 1 to 65537, the canary password, mode 1800's example).
10. **Bench** (step 9, 4 min with the run): every key length 0 to 64, every salt length 1 to 16, rounds 1 and 65537, the comparator batch, a wrong salt, padding. `ALL PASS` on the first run; the device's bytes are SHA-512 output order, no swap.
11. **Simulated board** (step 10, 1 min): both bridges built, `csr.csv` has `salt_len` at 0x3c, identity `hcfpga/1;board=sim;algo=sha512crypt;cores=4;clk=1;abi=4`.
12. **Host side** (step 11, 3 min, commit `9a8d93251`): hooks, the module's limits placed where the parser sets what they check, the test module's comments (the scaffold had already narrowed its constraints). No warnings. A full `make` then built `./hashcat`, which the fresh worktree did not have (P3).
13. **Proofs** (step 12, section 6 below). hashcat cracked on its first run, over both bridges.
14. **Docs** (step 13): README, PROVENANCE, the setup doc's paragraph for mode 91800 (and the mode table in numeric order), these notes.

## 3. Generic versus sha512crypt-specific

| Piece | As the template has it | Changed for sha512crypt, and why |
|---|---|---|
| H2C record | bcrypt's | `len` limit 64 |
| Unit packet | the JtR adapter's 40-byte header and key | `KEY_ALIGN` 8: the thread memory is 64 bits wide and `unit_input.v` stores whole 64-bit words |
| Unit read | 2-bit, `2'b11` marker, generation check | `RESULT_LEN` 64: 36 16-bit words; result bytes 16..63 read and dropped |
| C2H record | bcrypt's | digest is result bytes 0..15 at 4..19 in SHA-512 output order, no swap; core_id is the unit |
| CSR block | the shared registers, extras from 0x3c | `salt_len` at 0x3c, the scaffold's default |
| Identity | `hcfpga/1;...` | `cores=` counts SHA-512 cores (4 per unit), grain 4 per core |
| Top | the scaffold's JtR top | the unit instance and `CORES_PER_UNIT` 4; no core clock |
| Bridge | `hcfpga_bridge.c` | the hook values; no hook beyond `config_extra` and `canary_digest` |
| Module | the scaffold's bridged copy of module_01800.c | limits: password 64, salt 1..16, rounds 1..999999999 |
| Kernel | the scaffold's pass-through | none |
| Template, transports, bcrypt, md5crypt, sha256crypt | | none |

Everything sha512crypt needed was a parameter or a hook the template already had. The new code is the C reference (about 250 lines), the Python reference (about 110), the bench cases and the documentation; the top, wrapper, bridge, module, kernel and test module are the scaffold's with values filled in.

## 4. Layouts

H2C record, unit packet, unit output, C2H record and registers: `src/fpga/sha512crypt/README.md`. The thread memory (32 words of 64 bits, `cpu/program.vh`):

| Words | Content |
|---|---|
| 0 | rounds (bytes 0..3), salt length (bytes 4..7) |
| 1..2 | salt, later the S byte sequence (`ADDR_s_bytes`, 2 words saved) |
| 3 | candidate id, generation, zero |
| 4 | key length (byte 32), unused |
| 5..12 | key, later the P byte sequence (`ADDR_p_bytes`, 8 words saved) |
| 13..23 | unused |
| 24..31 | the alternate sum, then the result (`ADDR_alt_result`) |

## 5. Snags

Times are wall clock in this session. Numbered P (this port) after md5crypt's S, the template's T and sha256crypt's N.

| # | Snag | Took | Fix | What would have prevented it |
|---|---|---|---|---|
| P1 | Upstream's `sha512.vh` has `` `define SIMULATION`` commented out. Without it `sha512core/core.v`, `ff16.v`, `ff64.v`, `add3.v`, `sha512engine/process_bytes.v` and `unit/unit_ctrl.v` are empty modules with the right ports (upstream's ISE flow fills them from partition netlists). A Verilator lint of the unit then passes with no error, and the unit computes nothing. sha256crypt's header had it defined upstream, md5crypt's did not | 2 min (caught while reading `sha512.vh` and grepping for it) | `` `define SIMULATION`` in `sha512.vh`, recorded in `PROVENANCE.md` | AGENTS.md step 5: grep the unit for `ifdef SIMULATION`/`ifndef SIMULATION`; if a header leaves it undefined, define it there: JtR designs use it to choose the real modules over empty ISE stubs, and no lint error shows the difference |
| P2 | Finding the import set by "linting the unit alone until it stops reporting missing modules" (step 5) did not work as written. Verilator's `-I<dir>` also searches `<dir>` for a missing module by file name, so with `-I` on the unit's own directories nothing is ever reported missing; and without them, upstream's `` `include "../sha512.vh"`` is not found (Verilator resolves includes against the include path, not the including file) | 3 min | Linted a scratch copy of upstream with only a header directory on the include path (a directory holding `program.vh` and nothing else, one level below `sha512.vh`), then dropped one file at a time to see which were needed: `sha512core/ff32.v`, `util/sync.v`, `util/delay.v`, `util/fifo_sync.v`, `util/regs2d.v` are not (sha256crypt imported `sync.v` and `delay.v` all the same) | Step 5: find the set with the source files named on the command line and include directories that hold headers only (copy the `.vh` files to `$S/inc`), because `-I` on a source directory finds modules by file name and hides a missing file |
| P3 | A fresh worktree has no `./hashcat`: step 11's `make -j bridges/... modules/...` builds `libhashcat.so` and the two plugins only, and the proofs run `./hashcat` | 1 min | `make -j8` once before the proofs (41 s) | Step 11: end with a full `make -j` (it also builds the bcrypt plugins row 13 needs), before any proof starts (S14) |
| P4 | Row 6 says "k so one batch holds all 30 (k x grain >= 30)". The grain there is the bridge's batch grain (identity cores x `grain_per_core`, 16 here), not the scaffold's `--grain` (4 per core) | 1 min | `-n 2` (32 candidates) | Row 6: "k x cores x grain_per_core >= 30 (sha512crypt: 4 x 4, so -n 2)" |
| P5 | The scaffold's README template shows `HCFPGA_LITEXBONE=tcp:127.0.0.1:2430` and no `--uart-port`, which section 3 says never to use | 1 min | This README shows `--uart-port <port>` and `ss -ltn` | `template/README.md.in`: the same text |
| P6 | Upstream's `sha512unit.v` passes `N_CORES` to its cores but not to `unit_ctrl.v`, which takes `` `N_CORES`` (4) from `sha512.vh`. A `CORES_PER_UNIT` other than 4 would build cores and controls of different widths without an error. The older LiteX port, which ran one core per unit, patched every instance to pass it down | 2 min (reading the older port's diff) | `CORES_PER_UNIT` stays 4, upstream's; written in the top's header, the README and `PROVENANCE.md` | Step 7 already says to keep upstream's value; the reason here is a second one besides the `// must` comment |
| P7 | The unit has two programs (sha512crypt at entry point 0, Drupal7 at 1), chosen by a type 1 initialization packet that upstream's arbiter broadcasts after startup (`ENTRY_PTS_EN`). Nothing in AGENTS.md asks which program a unit runs without that packet | 2 min (reading `unit_input.v` and `cpu/instruction.v`) | None needed: a unit starts at entry point 0, and the shared feeder only sends type 0 packets. Written in the top's header and the README | Step 2's JtR reading list: `cpu/instruction.v`'s entry points, and which one a unit runs without an initialization packet |
| P8 | Making `multi.txt` with `m91800.module_generate_hash ("fourteen14", ...)` failed with `TypeError: can only concatenate str (not "bytes") to str`: test.py passes the word as bytes and the salt as str | 1 min | Called it with bytes | Section 5's list: "`module_generate_hash (word as bytes, salt as str, iterations)`" |

What went right the first time, and why: the bench passed every case on its first run with the real unit, the board's CSR map matched, the bridge and module compiled without warnings, hashcat cracked on its first run over both bridges, and this port needed no template change. The JtR adapter's `KEY_ALIGN` and `RESULT_LEN` parameters had been written for this unit, the references were checked against each other and against independent hashes before the bench ran, and P1 was caught by reading before it could show as a bench that returns nothing. Row 9 passed before the descrypt port's template fix too: the sha512crypt unit, thousands of cycles per round, put no result into the emptied ring during a board restart, so it did not show what descrypt's fast pipeline showed.

## 6. Proofs

All commands from the worktree root, with `S=<scratch>`, `OCL_ICD_VENDORS=$S/icd` (PoCL 3.0, hence `--force`/`-f`), `M=91800`, `HCM="./hashcat -m 91800 -a 0 --force --potfile-disable"` plus a `--session` per run. The sims were built by `src/fpga/common/hcfpga_sim.py --algo sha512crypt --bridge <uartbone|etherbone> --build-only --output-dir $S/sha512crypt/sim_<ub|eb>` and started with `--no-build` (one unit, so the identity says `cores=4` and a batch grain is 16), the UARTBone one with `--uart-port 2611` (`U="env HCFPGA_LITEXBONE=tcp:127.0.0.1:2611"`), the Etherbone one under `SIMNS_DIR=$S/sha512crypt/ns $GUIDE/debug/simns.sh` (`E="<that> env HCFPGA_LITEXBONE=udp:192.168.9.50"`). `hash.txt` holds mode 1800's `ST_HASH` (`$6$72820166$U4DVzpcYxgw7MVVDGGvB2/...829kD1`, 5000 rounds), `words8.txt` eight words with `hashcat`, `words30.txt` 29 wrong words and `hashcat` 18th, `wrong.txt` the same hash with salt `72820167`, `multi.txt` three hashes from `m91800.py`'s `module_generate_hash` at 1000 rounds with salts of 3, 9 and 16 bytes, `words24.txt` 24 words with their passwords 14th, 20th and 23rd. The UARTBone rows (2, 4, 5, 10) and the Etherbone rows (3, 6 to 9, 11) ran side by side, each in order on its own sim, and the bcrypt rows on a third sim beside them.

| # | What | Command | Result |
|---|---|---|---|
| 0 | Older LiteX port, before any change | its `sha512crypt_sim.py --num-units 1 --cores-per-unit 1` under `simns.sh`, then `obj_dir/Vsim`, `litex_server --udp --udp-ip 192.168.9.50`, `cleanup_test.py -c '$6$qdMgClgO2dQWB37F$jhex...ZCbt/' -w <10 words>` | `*** CRACKED *** ...:hashcat`, 10 passwords in 48.3 s |
| 1 | Bench | `SIM_WORK=$S/sha512crypt/tb make -C src/fpga sim ALGO=sha512crypt` | lengths (67 candidates: every key length 0..64, `hashcat`, the canary), salt1..salt16 (4 candidates each, keys 0, 7, 39, 64 bytes), rounds1, rounds65537 (46,155,539 cycles), cmp (30 candidates, 1 returned, 29 filtered), salt (0 returned), pad: `ALL PASS`, 3 min 7 s |
| 2 | Example hash, self-test on, UARTBone | `$U HCFPGA_DEBUG=1 $HCM hash.txt words8.txt` | identity `hcfpga/1;board=sim;algo=sha512crypt;cores=4;clk=1;abi=4`, self-test batch `recs=5 ... canaries=4`, no canary error, `$6$72820166$...:hashcat`, `Status...........: Cracked` (44 s) |
| 3 | Same over Etherbone | `$E HCFPGA_DEBUG=1 $HCM hash.txt words8.txt` | `canaries=4`, `Cracked` (66 s) |
| 4 | test.py | `$U HCFPGA_TEST=1 python3 tools/test.py -m 91800 -P -f` | attack 0, single (8) and multi, vector width 1 and 4: 4 `OK`, 0 errors, 11 min 29 s |
| 5 | test.py, every attack | same with `-a all` | attacks 0, 4, 8 and 9, single and multi (attack 9 single only), vector width 1 and 4: 14 `OK`, 0 errors, 39 min 30 s |
| 6 | Comparator | `$E HCFPGA_TIMING=1 $HCM -n 2 -u 5000 hash.txt words30.txt` (batch grain 16, so `-n 2` holds 32; `-u` equal to the rounds so one loop call holds them all) | `recs=30 recv=1`, `Cracked` |
| 7 | No compare | row 6 with `HCFPGA_CMP_OFF=1` | `recs=30 recv=30`, `Cracked` |
| 8 | Wrong salt | row 6 with `wrong.txt` | `recs=30 recv=0`, `Status...........: Exhausted` |
| 9 | Failed batches | row 6 with `HCFPGA_INJECT_FAULT=send HCFPGA_INJECT_PERIOD=2` | `5 failures, none a wrong answer`, `No candidates were skipped`, `Cracked` |
| 10 | Loops below rounds, several salts | `HCFPGA_LITEXBONE=tcp:127.0.0.1:2612 HCFPGA_DEBUG=1 $HCM -n 1 -u 250 multi.txt words24.txt`, on a second UARTBone sim (a copy of the first build, `--uart-port 2612`) so it ran beside row 5 | `Loops:250` on the 1000-round hashes, 25 batches, `3/3 (100.00%) Salts`, `Status...........: Cracked` (38 s) |
| 11 | Limits | `$E $HCM limits.txt limits_words.txt`; lines: (1) salt 1 byte, rounds 1; (2) salt 16 bytes, 64-byte password, rounds 1000; (3) rounds 65537; (4) empty salt; (5) salt 17 bytes; (6) rounds 0; (7) rounds 1000000000; (8) a 65-byte password. Words: `password`, `hashcat`, the 64- and 65-byte passwords, `letmein` | lines 1, 2, 3 `Cracked` (`3/4 ... Salts`); line 4 `Salt-length exception`; line 5 `Token length exception ... (only 16 allowed but 17 entered)`, mode 1800's own tokenizer; lines 6, 7 `Salt-iteration count exception`; line 8 parses, its password is `Rejected` (`4/20`: the 65-byte word under each salt), `Exhausted` (9 min 27 s). hashcat ran `Loops:1` here, so the 1000- and 65537-round salts went in one-round slices (N7's path). `./hashcat -m 91800 --left --potfile-path <empty> limits_max.txt` lists `$6$rounds=999999999$abc$...` (the top of the range parses; it is too slow to crack at 1 MHz), and `-m 1800 --left` on `limits.txt` lists seven lines (all but line 5), so lines 4, 6 and 7 are refused by mode 91800's limits, not by mode 1800's parser |
| 12 | bcrypt untouched | `git diff fpga-template -- src/fpga/bcrypt src/bridges/bridge_fpga_bcrypt.c src/bridges/bridge_fpga_bcrypt.mk src/modules/module_75000.c OpenCL/m75000-pure.cl` | prints nothing (also before every commit). `git diff fpga-template --stat -- src/fpga/common src/bridges/fpga/hcfpga_bridge.c src/bridges/fpga/hcfpga_bridge.h` prints nothing: the template did not change |
| 13 | bcrypt still works | the Guide's `debug/bcrypt_sim.py --hashcat <this tree> --output-dir $S/bc_eb` under `SIMNS_DIR=$S/bc_ns`, `./hashcat -m 75000 -a 0 --force --potfile-disable -n 1 -u 32 bc.hash bc_words.txt` and `HCFPGA_TEST=1 python3 tools/test.py -S -m 75000 -f -D 1` | `$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou:hashcat`, `Cracked`; `1/1 hash-modes cracked their own self-test vector` |
| 14 | md5crypt still works | not run: the template did not change | |

The rows above ran with the bridge as the template stood at `fc8027414`. During the proofs, the descrypt port's template fix (`446a55313` on `fpga-template`, cherry-picked here as `dca3b6c14`: `run_range` holds the datapath in its framing reset while a failed board's rings are emptied) came in. Its rows were rerun with the bridge rebuilt on it, first from a second tree (`rsync -a --exclude .git` of the worktree to `$S/tree`, so row 5, still running in the worktree, kept its plugins, S14), then in the worktree once row 5 had ended:

| # | With the fix | Result |
|---|---|---|
| 2 | second tree, second UARTBone sim (`--uart-port 2612`) | `canaries=4`, `Cracked` (32 s) |
| 3 | second tree, Etherbone | `canaries=4`, `Cracked` (53 s) |
| 9 | second tree, Etherbone | `5 failures, none a wrong answer`, `No candidates were skipped`, `Cracked` (2 min 53 s) |
| 6 | worktree, Etherbone | `recs=30 recv=1`, `Cracked` |
| 7 | worktree, Etherbone | `recs=30 recv=30`, `Cracked` |
| 8 | worktree, Etherbone | `recs=30 recv=0`, `Status...........: Exhausted` |
| 10 | worktree, UARTBone (`--uart-port 2611`) | `Loops:250`, `3/3 (100.00%) Salts`, `Cracked` (39 s) |

Rows 1, 11 and 13 do not go through the changed code (the bench has no bridge, row 11 has no failed batch, bcrypt has its own bridge), and rows 4 and 5 (test.py) ran only before it; none of them had a failed batch. md5crypt's proofs for the fix were run by the descrypt port.

## 7. Not done

- No real board. sha512crypt's unit runs at one clock here; upstream runs the units at a faster `CORE_CLK` than the packet logic. A board target that wants that needs clock-domain crossings in the JtR feeder and collector, as sha256crypt's notes say.
- No wave model: hashcat autotunes, and the batch timeout uses 1000 cycles per round per wave.
- Rounds near the top of the range (999999999) were not run; the parser accepts them (row 11) and the bench ran 65537, which covers the borrow into the upper count register.
- The Drupal7 program in the unit (entry point 1) is not used: the feeder never sends the type 1 initialization packet that selects it. A Drupal7 mode (hashcat 7900) would reuse this datapath with that packet sent at arm time.
- The proof rows ran partly side by side (UARTBone and Etherbone sims at once, row 10 on a second UARTBone sim beside row 5), not strictly in order.
- Rows 4, 5 and 11 ran before the cherry-picked template fix only (section 6).
