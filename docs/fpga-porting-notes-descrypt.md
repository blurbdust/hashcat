# Porting notes: descrypt on the hcfpga framework

descrypt (traditional DES crypt(3), hashcat mode 1500) is the fourth algorithm on the FPGA framework hashcat 8 introduced, the third on the shared template (`src/fpga/common`, `src/bridges/fpga/hcfpga_bridge.c`), and the first on the template's `--core custom` path, ported with the LiteX hashcat Guide's `AGENTS.md`. These notes follow md5crypt's and sha256crypt's: what was ported, the steps in order, what was generic and what descrypt forced, the layouts, every snag, the proofs and what is not done. The design is described in `src/fpga/descrypt/README.md`, its sources in `src/fpga/descrypt/PROVENANCE.md`.

Result: hash mode 91500 (bridge `fpga_descrypt`) cracks descrypt through hashcat's litexbone transport against a Verilator simulation of a LiteX board, over UARTBone and Etherbone, with the self-test on. `tools/test.py -m 91500 -P` passes with `HCFPGA_TEST=1`, with every attack. The port found one bug in the shared bridge, which can hit every algorithm on the template after a failed batch: the transport's rings were emptied while the datapath was still running the failed batch. It is fixed in a commit of its own (`7ef19a176`), and md5crypt's proofs and the bcrypt regression were rerun on the fix. bcrypt's files did not change. No bitstream has been built for a real board.

## 1. What was ported

John the Ripper's ZTEX descrypt design (`src/ztex/fpga-descrypt/` in openwall/john, Denis Burykin) is not one of JtR's crypt-family units. It has four layers:

| Layer | JtR files | Kept? |
|---|---|---|
| DES ring: 16 registered DES rounds closed into a ring, the salt in the E-box; the key preparation (crypt(3)'s 7-bit packing, PC-1) | `descrypt_core/{descrypt16,descrypt_round,rotate_1or2_pc2,des_loop,Eblock,SP_v2,IP1,crypt3_ascii2bin,pc1}.v`, `descrypt.vh` | yes, verbatim apart from one define |
| Core wrapper: the ring's batch control (16 keys in, 25 passes, 16 results out), a 35-bit binary-search comparator over up to 2047 hashes in BRAM, a 4-bit serial output that reports only matches | `descrypt_core/descrypt_core.v`, `wrapper.v`, `core_dout_proc.v` | no: the control is rewritten in the engine, the comparator and output are replaced |
| Arbiter, comparator configuration, on-chip candidate generators | `arbiter.v`, `descrypt_unit.v`, `cmp_config*.v`, `descrypt.v`, `pkt_comm/word_gen*.v` | no: replaced by the template's intake and the engine |
| Packet layer and board shell | `pkt_comm/`, `ztex_inouttraffic/`, `main.vh` | no |

The hcfpga contract wants a digest back for every candidate (the device prefilters with a 7-bit bitmap, hashcat compares on the host). Upstream's core gives out only "equal on 35 bits, at hash RAM address n". So the cut is below the core wrapper: the ring is kept, and its control is written again in `hcfpga_descrypt_engine.v` with the timing upstream's `descrypt_core.v` uses, checked slot by slot against crypt(3) before the engine existed.

An older LiteX port (`~/claude/litex_descrypt`) wrapped all four layers (pkt_comm over two 1 KiB SRAMs).

## 2. Steps, in order

Wall-clock times from the start of the session (03:17).

1. **Read** (`AGENTS.md` step 2, 15 min with the core): md5crypt's and sha256crypt's porting notes, `src/fpga/common/README.md`, `hcfpga_bridge.h`, the template's custom top, engine stub, wrapper and bench, `hcfpga_h2c_intake.v`, `hcfpga_c2h_eob.v`, the shared bridge's batch path (`fill_batch`, `run_range`, `launch_loop`), md5crypt's top and sha256crypt's bridge and wrapper; then JtR's `descrypt_core.v` (the ring's control and timing, the comparator), `descrypt16.v` and the round modules, `wrapper.v`, `core_dout_proc.v`, `arbiter.v` (batches of 16, "write empty candidates", the key path `crypt3_ascii2bin` then `pc1`), `cmp_config.v` (the 12-bit salt, the 35-bit hash order), `template_list.v` (7 bits per character), `descrypt.vh`, and the host format `src/ztex_descrypt.c` (8-byte keys, 12-bit salt, the raw 64-bit binary, 35 bits compared on chip). Mode 1500's module and test module.
2. **Ran the older LiteX port first** (step 3, 15 min, snag D1). Built under `simns.sh` (the run step fails at `sudo`, as expected), started `obj_dir/Vsim` and `litex_server --udp`, ran its `cleanup_test.py` against `48c/R8JAv757A`. The core matched: a CMP_EQUAL packet for the right word every time. The script's own verdict line was wrong twice (it maps word ids as 1-based).
3. **Scaffold** (step 4, 3 min, commit `30f6cdf55`): `new_fpga_algo.py --name descrypt --mode 1500 --core custom --pw-max 8 --digest-words 4 --digest-bytes 8 --grain 16 --salt-min 4 --salt-max 4 --iter-min 25 --iter-max 25`. The untouched bench passed with the engine stub (`ALL PASS`), the bridge and module compiled without warnings.
4. **Import** (step 5, 3 min, commit `113b0029d`): 10 files from `git archive` of upstream commit `ad3c92343` (the checkout had local edits in this directory, snag D2), CRLF to LF and nothing else. The unit is `descrypt16` and what it instantiates, plus the two key preparation modules. Lint of `descrypt16` alone: clean. No vendor primitives, no relative includes, so step 5's second commit had nothing to do (D3).
5. **Checked the ring before writing the engine** (10 min, D4): a 40-line Verilator bench of `descrypt16` alone, `COMPARE_35_BIT` off, 16 keys on 16 cycles, compared `hash_out` with JtR's raw binary of libc's crypt (): slot i comes out in cycle 400 + i, all 64 bits right. A Python search over 200 hashes found the bit permutation from that block to mode 1500's `digest_buf[0..1]`.
6. **Decide** (step 6, 10 min): written in the README's Decisions section.
7. **Gateware** (step 7, 20 min): `hcfpga_descrypt_engine.v` (loader, per-ring control with two result banks, collector and comparator), the top, `descrypt.vh`'s `COMPARE_35_BIT` off, the wrapper's sources. Lint with `-Wall` for 1 to 4 rings: my width warnings fixed (D5).
8. **References** (step 8, 10 min): `descrypt_ref.py` (crypt(3)'s DES from the tables, then module_01500's decode: base64 and `DES_IP`), checked against mode 1500's example hash, the 15 vectors of JtR's format, 200 random libc crypt () hashes, and bytes above 0x7f. `hcfpga_descrypt_ref.h`, the same in C, agreed with it on 64 cases (random bytes 0 to 255, lengths 0 to 8, random salts, the canary).
9. **Bench** (step 9, 5 min): key lengths 0 to 8, top-bit and zero bytes, more candidates than the rings hold (both banks, short last ring), six salts, the comparator batch, a wrong salt (D6), padding. `ALL PASS` on the first run, also with 1 and 3 rings.
10. **Simulated board** (step 10, 2 min): both bridges built, the bank has the 15 shared registers and nothing else, identity `hcfpga/1;board=sim;algo=descrypt;cores=1;clk=1;abi=4`.
11. **Host side** (step 11, 15 min, commit `70c930a15`): the module became a slow-hash bridged mode (D7), `salt_iter` 25 (D8), the self-test on, the test module's salt constraint back to 2 characters (D9), the hooks. No warnings.
12. **Proofs** (step 12, section 6). hashcat cracked on its first run, over both links. Row 9 then failed: the board was dropped after 18 failed restarts (D10). The cause was in the shared bridge; fixed in `7ef19a176`, after which every descrypt row was run again, and md5crypt's (row 14) and bcrypt's (rows 12, 13).
13. **Docs** (step 13): README, PROVENANCE, the setup doc's paragraph for mode 91500, these notes.

## 3. Generic versus descrypt-specific

| Piece | As the template has it | Changed for descrypt, and why |
|---|---|---|
| H2C record | bcrypt's, through `hcfpga_h2c_intake.v` | `len` limit 8 |
| Engine | the custom scaffold's one-candidate stub | replaced: a loader packing 8 bytes into a 56-bit word, rings of 16 started on a full buffer or on the batch's last record, two result banks per ring, a collector with the bitmap comparator. It also takes `batch_target`/`batch_arm` (the stub does not), to start a short last ring without waiting |
| Generation | `hcfpga_gen.v` for cores without a reset | not used: the ring keeps nothing across a new batch, and a framing reset clears all the engine's state |
| C2H record | bcrypt's | digest is hashcat's `digest_buf[0..1]` at bytes 4..11, made by a wire permutation in the gateware, so no `digest_from_c2h`; core_id is the ring |
| CSR block | the shared registers, extras from 0x3c | no extras: the 12-bit salt is in `salt0`, the count is fixed |
| Identity | `cores=` | counts rings; grain 16 per ring |
| Bridge | `hcfpga_bridge.c` | the hook values only; the canary password is the default cut to 8 bytes (`hcfpga-z`) |
| Module | the scaffold's bridged copy of module_01500.c | ATTACK_EXEC_OUTSIDE_KERNEL, `KERN_BIT_TM`, `module_jit_cache_disable`, `OPTI_TYPE_REGISTER_LIMIT` and `OPTS_TYPE_SELF_TEST_DISABLE` dropped, `salt_iter` 25 |
| Kernel | the scaffold's pass-through | none |
| Test module | the scaffold's copy of m01500.py | the salt constraint back to upstream's 2 characters |
| Template | | one fix in `hcfpga_bridge.c` (D10), in its own commit |
| Transports, bcrypt, md5crypt, sha256crypt | | none |

## 4. Layouts

H2C record, C2H record and registers: `src/fpga/descrypt/README.md`. The ring (`descrypt16`), per cycle T + k after the first key went in at T:

| Cycles | What |
|---|---|
| T .. T+15 | `START_CRYPT`: slot k's key enters round 0 with a zero block (Ti), `ENABLE_CRYPT` high |
| T+1 .. T+399 | `ENABLE_CRYPT` high: round 0 takes each slot back from round 15 with its halves swapped; rounds 1 to 15 run free |
| T+16p+15+k | `hash_out` holds slot k after pass p (p = 0..24); the result is pass 24, at T+400+k |
| T+400 | the earliest next `START_CRYPT`: slot 0 of the new batch replaces slot 0 of the old one as its result is read |

The 56-bit word the key preparation takes: byte k of the password in bits 7k+6..7k (its low 7 bits), zero past the length. `crypt3_ascii2bin` turns it into crypt(3)'s 64-bit key (each byte shifted left by one), `pc1` into C and D.

The digest: `digest[0..1]` bit 8a + b (a the byte of the 8 little-endian bytes, b the bit) is `hash_out` bit 8 (7 - b) + {0,2,4,6,1,3,5,7}[a], where `hash_out` is the output block after the final permutation as JtR's raw binary orders it (`get_binary_full` in `src/ztex_descrypt.c`).

## 5. Snags

Times are wall clock in this session.

| # | Snag | Took | Fix | What would have prevented it |
|---|---|---|---|---|
| D1 | The older port's `cleanup_test.py` reported "Match found but could not determine password" on its repository's word list (a 9-byte word shifts the ids) and named the wrong word ("pass") when `hashcat` was third of five: it reads the device's word id as 1-based, the device counts from 0 | 15 min | Ran three lists with `-v` and read the raw CMP_EQUAL packet: the id was always the right word's | AGENTS.md step 3: judge the core by the raw result the old test prints (ids, digests), not by its verdict line, and keep the candidates within the core's limits |
| D2 | The John the Ripper checkout had uncommitted edits in `fpga-descrypt` (`descrypt.vh`, `descrypt_core.v` with `CORE_INCLUDE_SRC` defined, `descrypt_unit.v`, CRLF changes) | 2 min | Imported from `git archive ad3c92343` instead of the working tree | Step 5: import from a commit, check `git status` of the upstream checkout first, and name the commit in PROVENANCE.md |
| D3 | Step 5's second commit ("make it build outside the vendor flow") had nothing to do: the ring lints clean, has no primitives and includes `descrypt.vh` by name. The one change hashcat needs, a 64-bit result, is functional | 2 min | No second commit; the define went in with the gateware, with a notice and a PROVENANCE row | Step 5: no second commit when the lint and the greps are clean; functional changes to upstream files go with the gateware |
| D4 | Upstream's core (`descrypt_core.v`) compares on chip and returns only matches, so "the computing unit" cannot be imported whole the way a JtR crypt unit is; and `descrypt16` gives out only 35 result bits (`COMPARE_35_BIT`) | 30 min (reading, an experiment) | The ring and the key preparation are the unit; the control is written again; `COMPARE_35_BIT` off. A minimal bench of the ring against crypt(3) settled the timing (slot k at T+400+k) and the 64-bit output before the engine was written | Steps 4 and 5 for `--core custom`: when the upstream core compares on chip, cut below its comparator, and check the kept pipeline's timing and output against a reference in a small bench first |
| D5 | Width warnings in the engine at 1 and 3 rings (`NUM_CORES - 1` compared with a narrow index, the collector's per-core arrays indexed past their size at 1 ring) | 5 min | Index widths from `$clog2`, arrays padded to a power of two | Lint the top with `-Wall` at more than one `NUM_CORES` (step 7) |
| D6 | The bench template's wrong-salt case flips the last salt byte; descrypt's `salt_buf[0]` has the salt characters there, which the core does not use, so the case would have expected no match and got one | 1 min (caught while writing) | Flip a bit of the 12-bit salt instead | The bench template: a wrong salt per algorithm, in the reference (a function next to `SALT`) |
| D7 | Mode 1500 is a fast hash (`ATTACK_EXEC_INSIDE_KERNEL`, a bitsliced kernel with `KERN_BIT_TM`, JIT options, `OPTS_TYPE_SELF_TEST_DISABLE`). The scaffold kept the attack type and the TM kernel bits with one TODO line ("a fast hash needs a different bridge type"); AGENTS.md does not mention fast modes | 10 min | ATTACK_EXEC_OUTSIDE_KERNEL (hashcat then runs init, the loop the bridge replaces, comp), `module_kern_bits`, `module_jit_cache_disable` and `OPTI_TYPE_REGISTER_LIMIT` dropped, the self-test flag dropped so row 2 can run | The scaffold: for an INSIDE_KERNEL upstream mode, write OUTSIDE_KERNEL and drop `module_kern_bits`/`KERN_BITS`, `module_jit_cache_disable` with the other upstream-kernel functions; keep a note. AGENTS.md step 11: say what to do about `OPTS_TYPE_SELF_TEST_DISABLE` |
| D8 | Mode 1500 leaves `salt_iter` at 0; the shared bridge divides by it (`launch_loop`: `pws_cnt * loop_pos / salt->salt_iter`) | 5 min (reading, before any run) | The parser sets `salt_iter` to crypt(3)'s 25; `kernel_loops_max` 25, so `-u` below 25 exercises the loop chunks | The scaffold or the bridge: refuse `iter_min` 0 (`--iter-min` must be at least 1), and AGENTS.md step 11: a mode whose parser leaves `salt_iter` 0 sets it |
| D9 | The scaffold put `--salt-min/--salt-max` (hashcat's `salt_len`, 4 for descrypt: the 12 bits plus the 2 characters) into the test module's salt constraint, which is the length of the salt string `module_generate_hash` gets (2) | 2 min | Constraint back to upstream's `[2, 2]` | The scaffold: keep the upstream test module's salt constraint and only narrow it, or take a separate `--test-salt` range |
| D10 | Row 9: after an injected send failure the bridge restarts the board: `session_refresh` empties the transport's rings and checks that all four ring pointers are 0, then `reset_framing`. descrypt's engine finishes a batch in about 1000 cycles, so results of the failed batch reached the C2H ring between the two, the pointer check failed, the next batch was injected again, and after 18 failures the board was dropped (`Status...........: Error`). A result landing after the check and before `reset_framing` would have been read by the next batch as its own: a wrong crack is possible for any algorithm. md5crypt and sha256crypt never showed it because their units take thousands of cycles per hash | 15 min | `hcfpga_bridge.c` asserts the framing reset before `session_refresh` and releases it with the verified `reset_framing` after (`7ef19a176`). Found with a pointer print in `lxb_ms_reset` in a scratch copy of the tree, the fix tried there first | A fast core in the template's proofs: the custom stub engine could run a short computation per candidate, or a proof row with a core that answers within the refresh |
| D11 | Section 5's limits row (`$HCM --left ...`) cannot run as written: `--left cannot be combined with --potfile-disable`, which `$HCM` holds | 1 min | `./hashcat -m 91500 --left --potfile-path <empty file>` (sha256crypt's notes did the same) | Row 11: write the `--left` command without `$HCM` |
| D12 | Section 5's proof files assume a salt length range and a cost (`multi.txt` "each with a different salt length and the same cost", `limits.txt` "salt length, cost"). descrypt has neither: every salt is 2 characters, the count is fixed | 5 min | `multi.txt`: three salts; `limits.txt`: the 12-bit salt at both ends, a short key, the parser's own refusals (hash value, token length, token encoding), and a hash only a 9-byte password's first 8 bytes crack, with that 9-byte password in the words | Section 5: "for an algorithm without a salt length or cost range, the limits are the password length and the parser's own refusals" |

What went right the first time, and why: the bench passed every case on its first run with the real ring, the board's CSR map matched, the bridge and module compiled without warnings, and hashcat cracked on its first run over both links. Each followed from checking the ring alone against crypt(3) before writing the engine, and from two references written from the DES tables and mode 1500's parser, not from the core, that agreed with libc and with each other before the bench ran.

## 6. Proofs

All commands from the worktree root, after the template fix (`7ef19a176`) with hashcat and every plugin rebuilt (`make`), with `S=<scratch>`, `OCL_ICD_VENDORS=$S/icd` (PoCL 3.0, hence `--force`/`-f`), `M=91500`, `HCM="./hashcat -m 91500 -a 0 --force --potfile-disable"` plus a `--session` per run. The sims were built by `src/fpga/common/hcfpga_sim.py --algo descrypt --bridge <uartbone|etherbone> --build-only --output-dir $S/descrypt/sim_<ub|eb>` (one ring, `cores=1`) and started with `--no-build`, the UARTBone one with `--uart-port 2687` (`U="env HCFPGA_LITEXBONE=tcp:127.0.0.1:2687"`), the Etherbone one under `SIMNS_DIR=$S/descrypt/ns $GUIDE/debug/simns.sh` (`E="<that> env HCFPGA_LITEXBONE=udp:192.168.9.50"`).

Files in `$S/descrypt/`: `hash.txt` mode 1500's `ST_HASH` `24leDr0hHfb3A` (password `hashcat`); `words8.txt` eight words with `hashcat`; `ROUNDS` 25; `words30.txt` 29 wrong words and `hashcat` 18th; `wrong.txt` `25leDr0hHfb3A` (one salt character changed, so another 12-bit salt); `multi.txt` three hashes from `m91500.py`'s `module_generate_hash` with salts `ab`, `Z9` and `./` (descrypt has one salt length and one count, so the three differ in salt only), `words24.txt` with their passwords 14th, 20th and 23rd; `limits.txt` the 12-bit salt at both ends with an 8-byte password (`..`, `12345678`; `zz`, `zzzzzzzz`), a 1-byte password (`/z`, `x`), a hash whose last character has its low bits set, hashes of 12 and 14 characters, a salt character outside the alphabet, and `q1` with the 9-byte password `abcdefghi` (crypt(3) uses its first 8 bytes), `limits_words.txt` `12345678`, `zzzzzzzz`, `x`, `abcdefghi`, `hashcat`.

The UARTBone rows (2, 4, 5, 10) and the Etherbone rows (3, 6 to 9, 11) ran side by side, each in order on its own sim.

| # | What | Command | Result |
|---|---|---|---|
| 0 | Older LiteX port, before any change | its `descrypt_sim.py --num-proxies 1 --cores-per-proxy 1` under `simns.sh`, then `obj_dir/Vsim`, `litex_server --udp --udp-ip 192.168.9.50`, `cleanup_test.py -c '48c/R8JAv757A' -w <5 words, hashcat third> -v` | CMP_EQUAL packet with word id 2 (0-based: `hashcat`), 5 passwords in 30.7 s; the script printed `pass` (D1) |
| 1 | Bench | `SIM_WORK=$S/descrypt/tb make -C src/fpga sim ALGO=descrypt` | lengths (15 candidates: key lengths 0 to 8, top-bit bytes, a zero byte inside, the canary), rings (133 candidates on 2 rings: full rings, both banks, a short last ring, 5196 cycles), salts `..`, `zz`, `./`, `/.`, `Az`, `24`, cmp (30 candidates, 1 returned, 29 filtered), salt (0 returned), pad: `ALL PASS`. Also `ALL PASS` with `--units 1` and `--units 3` |
| 2 | Example hash, self-test on, UARTBone | `$U HCFPGA_DEBUG=1 $HCM $S/descrypt/hash.txt $S/descrypt/words8.txt` | self-test batch `recs=2 h2c=32 B c2h=96 B canaries=1`, no canary error, `24leDr0hHfb3A:hashcat`, `Status...........: Cracked` (7 s) |
| 3 | Same over Etherbone | `$E HCFPGA_DEBUG=1 $HCM $S/descrypt/hash.txt $S/descrypt/words8.txt` | `canaries=1`, `Cracked` (3 s) |
| 4 | test.py | `$U HCFPGA_TEST=1 python3 tools/test.py -m 91500 -P -f` | attack 0, single (8 vectors) and multi, vector width 1 and 4: 4 `OK`, 0 errors, 2 min 24 s |
| 5 | test.py, every attack | same with `-a all` | attacks 0, 4, 8 and 9, single and multi (attack 9 single only), vector width 1 and 4: 14 `OK`, 0 errors, 8 min 29 s |
| 6 | Comparator | `$E HCFPGA_TIMING=1 $HCM -n 2 -u 25 $S/descrypt/hash.txt $S/descrypt/words30.txt` (grain 16, so `-n 2` holds 32) | `recs=30 recv=2` (the target and one bitmap collision), `Cracked` |
| 7 | No compare | row 6 with `HCFPGA_CMP_OFF=1` | `recs=30 recv=30`, `Cracked` |
| 8 | Wrong salt | row 6 with `wrong.txt` | `recs=30 recv=0`, `Status...........: Exhausted` |
| 9 | Failed batches | row 6 with `HCFPGA_INJECT_FAULT=send HCFPGA_INJECT_PERIOD=2` | `5 failures, none a wrong answer`, `No candidates were skipped`, `Cracked` |
| 10 | Loops below the count, several salts | `$U HCFPGA_DEBUG=1 $HCM -n 1 -u 6 $S/descrypt/multi.txt $S/descrypt/words24.txt` (25 / 4 = 6) | `Loops:6`, batches of 1 to 4 records, `3/3 (100.00%) Salts`, `Cracked` |
| 11 | Limits | `$E $HCM $S/descrypt/limits.txt $S/descrypt/limits_words.txt`; `./hashcat -m 91500 --left --potfile-path <empty> limits.txt` and the same with `-m 1500` | the three in-range hashes `Cracked` (3/4 salts); line 4 `Hash-value exception`, lines 5 and 6 `Token length exception`, line 7 `Token encoding exception`; the 9-byte password is `Rejected` (4/20: under each of 4 salts) and `q1...` stays uncracked, `Exhausted`. `--left` lists the same four lines for mode 91500 and mode 1500: mode 91500 refuses exactly what mode 1500 refuses |
| 12 | bcrypt untouched | `git diff fpga-template -- src/fpga/bcrypt src/bridges/bridge_fpga_bcrypt.c src/bridges/bridge_fpga_bcrypt.mk src/modules/module_75000.c OpenCL/m75000-pure.cl` | prints nothing |
| 13 | bcrypt still works | the Guide's `debug/bcrypt_sim.py --hashcat <this tree> --output-dir $S/bc_eb` under `SIMNS_DIR=$S/bc_ns`, `./hashcat -m 75000 -a 0 --force --potfile-disable -n 1 -u 32 bc.hash bc_words.txt` and `HCFPGA_TEST=1 python3 tools/test.py -S -m 75000 -f -D 1` | `$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou:hashcat`, `Cracked`; `1/1 hash-modes cracked their own self-test vector` |
| 14 | md5crypt still works (the template changed) | `SIM_WORK=$S/md5crypt/tb make -C src/fpga sim ALGO=md5crypt`, then rows 2 to 10 for `-m 90500` on its own sims (UARTBone `--uart-port 2689`, Etherbone under `SIMNS_DIR=$S/md5crypt/ns`), with mode 500's example hash `$1$38652870$DUjsu4TTlTsOe/xxZ05uf/`, `-n 3 -u 1000`, wrong salt `38652871`, and three hashes with salts of 6, 5 and 1 bytes for row 10 (`-n 1 -u 250`) | bench `ALL PASS` with md5crypt's cycle counts (827871, 581090, 290015, 3381); row 2 `canaries=3`, `Cracked`; row 3 `Cracked`; row 4 4 `OK`, 3 min 26 s; row 5 14 `OK` (attacks 0, 4, 8, 9), 0 errors, 11 min 1 s; row 6 `recs=30 recv=1`, `Cracked`; row 7 `recs=30 recv=30`, `Cracked`; row 8 `recs=30 recv=0`, `Exhausted`; row 9 `5 failures, none a wrong answer`, `No candidates were skipped`, `Cracked`; row 10 `Loops:250`, `3/3 ... Salts`, `Cracked` |

Before the fix, rows 2 to 8 and 11 had passed in the same form (row 4: 4 `OK`, 2 min 40 s; row 6 `recs=30 recv=2`). Row 9 ended `Status...........: Error` after `FPGA bridge: board ... could not be restarted after a failure.` 18 times and the board was dropped, which is how D10 showed. With the fix tried in a scratch copy of the tree first, row 9 passed there, then here.

## 7. Not done

- No real board. JtR clocks its cores at about 190 MHz with the comparator on a second clock; here everything runs on one clock. The ring is one register per DES round, as upstream, so timing should be close to upstream's, but nothing was synthesised.
- No wave model: hashcat autotunes, and the batch timeout uses 100 cycles per iteration per wave.
- The engine's idle flush (a partly filled ring starts after 4096 cycles without a record, for transports that do not arm) is not exercised by the bench, which always arms; the simulated board arms too.
- The H2C stream is the limit on a board: a record is 4 words, so one 32-bit word per cycle feeds about 6 rings. JtR's design generates candidates on chip for that reason; hashcat sends every candidate.
- `iter_count` is written and unused, so a hash with another count cannot exist in mode 1500's format; nothing checks it on the device.
