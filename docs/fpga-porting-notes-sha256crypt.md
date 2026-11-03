# Porting notes: sha256crypt on the hcfpga framework

sha256crypt (`$5$`, hashcat mode 7400) is the second algorithm on the shared FPGA template (`src/fpga/common`, `src/bridges/fpga/hcfpga_bridge.c`) and the first ported with the LiteX hashcat Guide's `AGENTS.md` alone. These notes follow md5crypt's (`docs/fpga-porting-notes-md5crypt.md`): what was ported, the steps in order, what was generic and what sha256crypt forced, the layouts, every snag, the proofs and what is not done. The design is described in `src/fpga/sha256crypt/README.md`, its sources in `src/fpga/sha256crypt/PROVENANCE.md`.

Result: hash mode 97400 (bridge `fpga_sha256crypt`) cracks sha256crypt through hashcat's litexbone transport against a Verilator simulation of a LiteX board, over UARTBone and Etherbone, with the self-test on. `tools/test.py -m 97400 -P` passes with `HCFPGA_TEST=1`, with every attack. The port found one bug in the shared bridge, which hit every algorithm on the template whenever hashcat's loop count is lower than a hash's rounds; it is fixed in a commit of its own (`affaa7010`) and md5crypt's proofs and the bcrypt regression were rerun on the fix. bcrypt's files did not change. No bitstream has been built for a real board.

## 1. What was ported

John the Ripper's ZTEX sha256crypt design (`src/ztex/fpga-sha256crypt/` in openwall/john, Denis Burykin) has the same three layers as its md5crypt design:

| Layer | JtR files | Kept? |
|---|---|---|
| Computing unit: 3 SHA-256 cores, a 12-thread CPU running the sha256crypt program, the SHA-256 block engine, the unit's input and output buffers | `unit/{sha256unit,unit_ctrl,core_ctrl,unit_input,uob}.v`, `cpu/`, `sha256core/`, `sha256engine/`, `sha256.vh`, `../util/{sync,delay,asymm_bram}.v`, `../util/log2.vh` | yes, nearly verbatim |
| Arbiters and comparator | `arbiter_tx.v`, `arbiter_rx.v`, `comparator.v`, `xcrypt_cmp_config.v`, `bcast_net.v`, `sha256crypt.v` | no, replaced by the template's JtR unit feeder and collector |
| Packet layer and board shell | `pkt_comm/`, `ztex_inouttraffic/`, `main.vh` | no, replaced by hcfpga's records and transports |

An older LiteX port (`~/claude/litex_sha256crypt`, kept outside this tree) wrapped all three layers (pkt_comm over two 1 KiB SRAMs, one unit of one core). This port keeps only the unit.

## 2. Steps, in order

Wall-clock times from the start of the session (01:42).

1. **Read** (`AGENTS.md` step 2, 10 min): md5crypt's porting notes, `src/fpga/common/README.md`, `hcfpga_bridge.h`, md5crypt's top, wrapper, bench, bridge and module, the shared feeder and collector; then JtR's `unit/sha256unit.v`, `unit_input.v` (32-byte input buffer, `ready` drops at the packet start and returns once an idle thread is found, so 12 candidates in flight and none waiting), `uob.v`, `unit_ctrl.v`, `core_ctrl.v` (`// must be 24`, so 3 cores), `cpu/program.vh` (thread memory layout, "max. key_len is 32", "salt_len=0, cnt=0 NOT supported", a 32-bit round count in two 16-bit registers, 20 output words), `arbiter_tx.v`, `arbiter_rx.v` (`PKT_NUM_WORDS = RESULT_LEN/2 + 4`), `main.vh` (`PLAINTEXT_LEN 32`, `RESULT_LEN 32`), `sha256.vh` (`SIMULATION` already defined) and JtR's host format `src/ztex_sha256crypt.c` (32-byte keys, salts 1 to 16, rounds 1 to 999999999, empty salts skipped). Mode 7400's module and test module.
2. **Ran the older LiteX port first** (step 3, 5 min). Copied it to scratch, built its sim under `simns.sh` (the build's run step fails at `sudo`, S2), started `build/sim/gateware/obj_dir/Vsim` and `litex_server --udp` in the namespace and ran its `cleanup_test.py`: `*** CRACKED *** $5$rounds=1000$abcdsalt$yfziOgfoH86GH0s1Vh6oyLldzpxZYJtVbGO8/BOKLr8:testpw`, 10 passwords in 33.0 s. The unit is known good.
3. **Scaffold** (step 4, 2 min, commit `1bba6a8b6`): `new_fpga_algo.py --name sha256crypt --mode 7400 --core jtr-unit --pw-max 32 --result-len 32 --key-align 4 --salt-min 1 --salt-max 16 --iter-min 1 --iter-max 999999999`. The untouched bench passed with the stub unit (`ALL PASS`), the bridge and module compiled without warnings.
4. **Import** (step 5, 3 min, commit `52d2055fe`): 37 files, CRLF to LF and nothing else (checked with `diff --strip-trailing-cr` against upstream).
5. **Build outside ISE** (step 5, 10 min, commit `7d466f079`): one `SRL16E` (`sha256core/shreg.v`, replaced the way md5crypt's was), 28 relative includes flattened, `log2.vh` included by `sha256.vh` and `util/asymm_bram.v`. Verilator lint of `sha256unit` alone: width, implicit-net and unsigned warnings only, all upstream (see `PROVENANCE.md`, "Left as upstream wrote it").
6. **Decide** (step 6, 5 min): written in the README's Decisions section.
7. **Gateware** (step 7, 5 min): `sha256unit` in place of the stub, `CORES_PER_UNIT` 3, geometry 32/4/32/0/16, the unit's files in the wrapper and the bench, the stub out of `COMMON_RTL`. No core clock: the unit has one clock.
8. **References** (step 8, 15 min): the Python reference is hashcat's own oracle (`tools/test_modules/lib/shacrypt.py`), whose result is decoded from the `$5$` string with mode 7400's decoder permutation; it reproduces mode 7400's example hash, the older port's hash and four JtR vectors, and libc `crypt ()`. The C reference (`hcfpga_sha256crypt_ref.h`, self-contained SHA-256 and sha256crypt) agreed with it on 47 cases (random passwords 0 to 32 bytes, salts 1 to 16, rounds 1 to 65537, the canary password).
9. **Bench** (step 9, 5 min): every key length 0 to 32, every salt length 1 to 16, rounds 1 and 65537, the comparator batch, a wrong salt, padding. `ALL PASS` on the first run; the device's bytes are SHA-256 output order, no swap.
10. **Simulated board** (step 10, 1 min): both bridges built, `csr.csv` has `salt_len` at 0x3c, identity `hcfpga/1;board=sim;algo=sha256crypt;cores=3;clk=1;abi=4`.
11. **Host side** (step 11, 5 min, commit `2134df737`): hooks, the module's limits placed where the parser sets what they check, the test module's constraints. No warnings.
12. **Proofs** (step 12, section 6 below). hashcat cracked on its first run. Row 10 then failed: two of its three in-range hashes did not crack (N7). The cause was in the shared bridge; fixed in `affaa7010`, after which every sha256crypt proof was run again, and md5crypt's (row 13) and bcrypt's (row 12) as the template rule asks.
13. **Docs** (step 13): README, PROVENANCE, the setup doc's paragraph for mode 97400, these notes.

## 3. Generic versus sha256crypt-specific

| Piece | As the template has it | Changed for sha256crypt, and why |
|---|---|---|
| H2C record | bcrypt's | `len` limit 32 |
| Unit packet | the JtR adapter's 40-byte header and key | none: sha256crypt's `arbiter_tx.v` sends the same header as md5crypt's; key in 4-byte steps |
| Unit read | 2-bit, `2'b11` marker, generation check | `RESULT_LEN` 32: 20 16-bit words; result bytes 16..31 read and dropped |
| C2H record | bcrypt's | digest is result bytes 0..15 at 4..19 in SHA-256 output order, no swap; core_id is the unit |
| CSR block | the shared registers, extras from 0x3c | `salt_len` at 0x3c, the scaffold's default |
| Identity | `hcfpga/1;...` | `cores=` counts SHA-256 cores (3 per unit), grain 4 per core |
| Top | the scaffold's JtR top | the unit instance and `CORES_PER_UNIT`; no core clock |
| Bridge | `hcfpga_bridge.c` | the hook values; no hook beyond `config_extra` and `canary_digest` |
| Module | the scaffold's bridged copy of module_07400.c | limits: password 32, salt 1..16, rounds 1..999999999 |
| Kernel | the scaffold's pass-through | none |
| Template | | one fix in `hcfpga_bridge.c` (N7), wrong for every algorithm, in its own commit |
| Transports, bcrypt, md5crypt | | none |

Everything sha256crypt needed was a parameter or a hook the template already had. The new code is the C reference (239 lines), the Python reference (104), the bench cases and the documentation; the top, wrapper, bridge, module, kernel and test module are the scaffold's with values filled in.

## 4. Layouts

H2C record, unit packet, unit output, C2H record and registers: `src/fpga/sha256crypt/README.md`. The thread memory (32 words of 32 bits, `cpu/program.vh`):

| Words | Content |
|---|---|
| 0 | rounds |
| 1 | salt length |
| 2..5 | salt, later the S byte sequence (`ADDR_s_bytes`, 4 words saved) |
| 6..7 | candidate id, generation |
| 8 | key length |
| 9 | unused |
| 10..17 | key, later the P byte sequence (`ADDR_p_bytes`, 8 words saved) |
| 18..23 | unused |
| 24..31 | the alternate sum, then the result (`ADDR_alt_result`) |

## 5. Snags

Times are wall clock in this session.

| # | Snag | Took | Fix | What would have prevented it |
|---|---|---|---|---|
| N1 | The older port's `sha256crypt_sim.py` builds and then runs `sudo obj_dir/Vsim` (it has the ethernet module), which fails inside `simns.sh`'s namespace. S2 again, on a script that is not `hcfpga_sim.py` | 3 min | Started `build/sim/gateware/obj_dir/Vsim`, then `litex_server --udp --udp-ip 192.168.9.50` and the test, all under the same `SIMNS_DIR` | AGENTS.md step 3: say how to run an older LiteX port's Etherbone sim (build under `simns.sh`, ignore the failed run, start Vsim and `litex_server` by hand) and how to stop `litex_server` by PID |
| N2 | `AGENTS.md` names the whole `fpga-sha256crypt/sha256crypt/` directory as "the core", which holds the arbiters, comparator and top; the unit also needs `../util/`. md5crypt flattened its `unit/` files, sha256crypt's are in a `unit/` directory | 5 min | Imported the unit and what it instantiates (closure checked with a Verilator lint of `sha256unit`), plus `util/{sync,delay,asymm_bram}.v` and `log2.vh`, in upstream's directories; no arbiters, pkt_comm, top or test benches | Step 5: "the unit and what it instantiates, found with a lint of the unit; keep upstream's directories; not the arbiters, comparator, pkt_comm, top, test benches" |
| N3 | The lint shows about 70 width warnings in upstream code. One is a real slip (`core_ctrl.v`: `cnt == A \| B`), harmless and also in md5crypt's copy | 5 min (reading) | Left as upstream wrote it, written up in `PROVENANCE.md` | Step 5: width warnings in upstream code are expected; read those in control logic, change only what alters behaviour hashcat relies on, note the rest |
| N4 | hashcat's sha256crypt oracle (`lib/shacrypt.crypt_bin`) returns only the base64 field, not the raw digest the device returns | 3 min | Decode it with mode 7400's decoder permutation in `sha256crypt_ref.py`, which also pins the byte order | Step 8: "if the oracle returns the encoded string, decode it the way the module's parser does" |
| N5 | Proof row 10: the highest round count (999999999) cannot crack in a 1 MHz simulation, and a password longer than 32 bytes is not a parser error: hashcat rejects the candidate | 5 min | Parser acceptance of rounds=999999999 shown with `--left --potfile-path <empty>`; the 33-byte password shows as a rejected candidate | Row 10's wording: cost maximum by `--left` when it is too slow; password limit by the `Rejected` count |
| N6 | Section 5 fixes the UARTBone port at 2531 while other agents may follow the same text on this machine | 1 min | Port 2574 (md5crypt's rerun: 2575) | Section 5: pick an unused port (`ss -ltn`) |
| N7 | Row 10: of `$5$rounds=1$a$...`, `$5$rounds=1000$<16 bytes>$...` and `$5$rounds=65537$...` in one file, only the first cracked. Alone, the second cracked. With several salts hashcat ran `Loops:1`, so the bridge was called once per round with a slice of the candidates, and every slice after the first sent the wrong candidates (`h2c=64 B` batches for 7-byte passwords). `hcfpga_bridge.c`'s `launch_loop` did `lc.tmps = tmps + pw_from` on a `u8 *`, a byte offset; bcrypt's and the pre-template md5crypt bridge had a typed pointer there, so the move to the template turned it into a bug. Every earlier proof ran with loops equal to the rounds (`pw_from` 0), so nothing caught it | 15 min | `lc.tmps = tmp_at (tmps, pw_from)` (`affaa7010`). The two-salt file then cracks both, with the right batch sizes; md5crypt with `-u 100` on a 1000-round hash (ten slices) cracks too | A proof where hashcat's loops are fewer than the rounds: row 6 with `-u` below the rounds, or row 10's file with salts of different rounds. Rerun md5crypt's row 10 when the template changes (its template proofs left it out) |
| N8 | A `Monitor` loop `while pgrep -f "session sc_row10"` never ended: the pattern is in the loop's own command line (T1's cousin) | 2 min | Stopped it; waited with a bounded loop | Section 3: `pgrep -f` matches the shell that runs it too, as `pkill -f` does |

What went right the first time, and why (N7 aside): the bench passed every case on its first run with the real unit, the board's CSR map matched, the bridge and module compiled without warnings, and hashcat cracked on its first run. The JtR adapter in `src/fpga/common` already spoke sha256crypt's unit protocol (md5crypt's notes had checked `arbiter_tx.v`'s header), and the references were checked against each other and against independent hashes before the bench ran.

## 6. Proofs

All commands from the worktree root, after the template fix (`affaa7010`) with the bridges rebuilt, with `S=<scratch>`, `OCL_ICD_VENDORS=$S/icd` (PoCL 3.0, hence `--force`/`-f`), `M=97400`, `HCM="./hashcat -m 97400 -a 0 --force --potfile-disable"` plus a `--session` per run. The sims were built by `src/fpga/common/hcfpga_sim.py --algo sha256crypt --bridge <uartbone|etherbone> --build-only --output-dir $S/sha256crypt/sim_<ub|eb>` and started with `--no-build`, the UARTBone one with `--uart-port 2574` (`U="env HCFPGA_LITEXBONE=tcp:127.0.0.1:2574"`), the Etherbone one under `SIMNS_DIR=$S/sha256crypt/ns $GUIDE/debug/simns.sh` (`E="<that> env HCFPGA_LITEXBONE=udp:192.168.9.50"`). `hash.txt` holds mode 7400's `ST_HASH` (`$5$7777657035274252$XftMj84MW.New1/ViLY5V4CM4Y7EBvfETaZsCW9vcJ8`, 5000 rounds), `words8.txt` eight words with `hashcat`, `words30.txt` 29 wrong words and `hashcat` 18th, `wrong.txt` the same hash with salt `7777657035274253`. The UARTBone rows (2, 4, 5) and the Etherbone rows (3, 6 to 10) ran side by side, each in order on its own sim.

| # | What | Command | Result |
|---|---|---|---|
| 0 | Older LiteX port, before any change | its `sha256crypt_sim.py --num-units 1 --cores-per-unit 1` under `simns.sh`, then `obj_dir/Vsim`, `litex_server --udp --udp-ip 192.168.9.50`, `cleanup_test.py -c '$5$rounds=1000$abcdsalt$yfziOgfoH86GH0s1Vh6oyLldzpxZYJtVbGO8/BOKLr8' -w <10 words>` | `*** CRACKED *** ...:testpw`, 10 passwords in 33.0 s |
| 1 | Bench | `SIM_WORK=$S/sha256crypt/tb make -C src/fpga sim ALGO=sha256crypt` | lengths (35 candidates: every key length 0..32, `hashcat`, the canary), salt1..salt16 (4 candidates each, keys 0, 7, 19, 32 bytes), rounds1, rounds65537 (37,768,921 cycles), cmp (30 candidates, 1 returned, 29 filtered), salt (0 returned), pad: `ALL PASS`, 2 min 25 s |
| 2 | Example hash, self-test on, UARTBone | `$U HCFPGA_DEBUG=1 $HCM hash.txt words8.txt` | self-test batch `recs=4 ... canaries=3`, no canary error, `$5$7777657035274252$...:hashcat`, `Status...........: Cracked` (32 s) |
| 3 | Same over Etherbone | `$E HCFPGA_DEBUG=1 $HCM hash.txt words8.txt` | `canaries=3`, `Cracked` (69 s) |
| 4 | test.py | `$U HCFPGA_TEST=1 python3 tools/test.py -m 97400 -P -f` | attack 0, single (8) and multi, vector width 1 and 4: 4 `OK`, 0 errors, 8 min 18 s |
| 5 | test.py, every attack | same with `-a all` | attacks 0, 4, 8 and 9, single and multi (attack 9 single only), vector width 1 and 4: 14 `OK`, 0 errors, 28 min 30 s |
| 6 | Comparator | `$E HCFPGA_TIMING=1 $HCM -n 3 -u 5000 hash.txt words30.txt` (grain 12, so `-n 3` holds 36; `-u` equal to the rounds so one loop call holds them all) | `recs=30 recv=1`, `Cracked` |
| 7 | No compare | row 6 with `HCFPGA_CMP_OFF=1` | `recs=30 recv=30`, `Cracked` |
| 8 | Wrong salt | row 6 with `wrong.txt` | `recs=30 recv=1` (a bitmap collision, not a match), `Status...........: Exhausted` |
| 9 | Failed batches | row 6 with `HCFPGA_INJECT_FAULT=send HCFPGA_INJECT_PERIOD=2` | `5 failures, none a wrong answer`, `No candidates were skipped`, `Cracked` |
| 10 | Parser limits | `$E $HCM limits.txt limits_words.txt`; lines: (1) salt 1 byte, rounds 1; (2) salt 16 bytes, 32-byte password, rounds 1000; (3) rounds 65537; (4) empty salt; (5) salt 17 bytes; (6) rounds 0; (7) rounds 1000000000; (8) a 33-byte password. Words: `password`, `hashcat`, the 32- and 33-byte passwords, `letmein` | lines 1, 2, 3 `Cracked` (3/4 salts); lines 4, 5 `Salt-length exception`; lines 6, 7 `Salt-iteration count exception`; line 8 parses, its password is `Rejected` (4/20: the 33-byte word under each salt), `Exhausted`. hashcat ran `Loops:1` here, so the 1000- and 65537-round salts went in slices (N7). `./hashcat -m 97400 --left --potfile-path <empty> limits_max.txt` lists `$5$rounds=999999999$abc$...` (the top of the range parses; it is too slow to crack at 1 MHz), and `-m 7400 --left` on `limits.txt` lists all eight lines, so lines 4 to 7 are refused by mode 97400's limits, not by mode 7400's parser |
| 11 | bcrypt untouched | `git diff fpga-template -- src/fpga/bcrypt src/bridges/bridge_fpga_bcrypt.c src/bridges/bridge_fpga_bcrypt.mk src/modules/module_75000.c OpenCL/m75000-pure.cl` | prints nothing |
| 12 | bcrypt still works | the Guide's `debug/bcrypt_sim.py --hashcat <this tree> --output-dir $S/bc_eb` under `SIMNS_DIR=$S/bc_ns`, `./hashcat -m 75000 -a 0 --force --potfile-disable -n 1 -u 32 bc.hash bc_words.txt` and `HCFPGA_TEST=1 python3 tools/test.py -S -m 75000 -f -D 1` | `$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou:hashcat`, `Cracked`; `1/1 hash-modes cracked their own self-test vector` |
| 13 | md5crypt still works (the template changed) | `SIM_WORK=$S/md5crypt/tb make -C src/fpga sim ALGO=md5crypt`, then rows 2 to 9 for `-m 90500` on its own sims (UARTBone `--uart-port 2575`, Etherbone under `SIMNS_DIR=$S/md5crypt/ns`), with mode 500's example hash `$1$38652870$DUjsu4TTlTsOe/xxZ05uf/`, `-n 3 -u 1000`, wrong salt `38652871` | bench `ALL PASS` with the cycle counts of md5crypt's notes (827871, 581090, 290015, 3381); row 2 `canaries=3`, `Cracked`; row 3 `Cracked`; row 4 4 `OK`, 3 min 25 s; row 5 14 `OK` (attacks 0, 4, 8, 9), 0 errors, 11 min 29 s; row 6 `recs=30 recv=1`, `Cracked`; row 7 `recs=30 recv=30`, `Cracked`; row 8 `recs=30 recv=0`, `Exhausted`; row 9 `5 failures, none a wrong answer`, `No candidates were skipped`, `Cracked` |
| 13a | md5crypt in slices (what N7 broke) | `$E HCFPGA_DEBUG=1 ./hashcat -m 90500 ... -n 1 -u 100 hash.txt words8.txt` | `Loops:100` on a 1000-round hash, ten one-candidate batches, `Cracked` |

Before the fix, rows 2 to 9 and 12 had passed in the same form (row 4: 4 `OK`, 8 min 15 s; row 6 `recs=30 recv=1`; row 9 `5 failures, none a wrong answer`); row 10 cracked only line 1, which is how N7 showed.

## 7. Not done

- No real board. sha256crypt's unit runs at one clock here; upstream runs the units at a faster `CORE_CLK` than the packet logic. A board target that wants that needs clock-domain crossings in the JtR feeder and collector (md5crypt's unit crosses inside, sha256crypt's does not).
- No wave model: hashcat autotunes, and the batch timeout uses 800 cycles per round per wave.
- Rounds near the top of the range (999999999) were not run; the parser accepts them and the bench ran 65537, which covers the borrow into the upper count register.
- md5crypt's notes (`docs/fpga-porting-notes-md5crypt.md`) still describe the template proofs without the fix; this file and the fix's commit are the record of it.
- The proof rows ran partly side by side (UARTBone and Etherbone sims at once), not strictly in order.
