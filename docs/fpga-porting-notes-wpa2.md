# Porting notes: wpa2 on the hcfpga framework

WPA-PBKDF2-PMKID+EAPOL (hashcat mode 22000, hcxtools' `WPA*01*` and `WPA*02*` lines) is the sixth algorithm on the shared FPGA template (`src/fpga/common`, `src/bridges/fpga/hcfpga_bridge.c`) and the third on its `--core custom` path, ported with the LiteX hashcat Guide's `AGENTS.md`. These notes follow the earlier ports' (`docs/fpga-porting-notes-md5crypt.md`, `-sha256crypt.md`, `-descrypt.md`, `-sha512crypt.md`, `-scrypt.md`): what was ported, the steps in order, what was generic and what wpa2 forced, the layouts, every snag, the proofs and what is not done. The design is described in `src/fpga/wpa2/README.md`, its sources in `src/fpga/wpa2/PROVENANCE.md`.

Result: hash mode 92500 (bridge `fpga_wpa2`) cracks mode 22000's PMKID and EAPOL lines, FT forms included, through hashcat's litexbone transport against a Verilator simulation of a LiteX board, over UARTBone and Etherbone, with the self-test on. The device computes the PMK, PBKDF2-HMAC-SHA1 (passphrase, ESSID, 4096 iterations, 32 bytes), from the password and the ESSID, and hashcat's kernels compute everything after it as mode 22000's do. The PMK is 32 bytes and a C2H record carries 24, so this port came with a template extension, multi-part C2H results, in two commits of its own before the wpa2 commits. No bitstream has been built for a real board.

## 1. What was ported

OpenCiphers (David Hulton, for Pico Computing, 2006; BSD) published a WPA-PSK cracker for Pico's Virtex-4 cards in three layers:

| Layer | OpenCiphers files | Kept? |
|---|---|---|
| PBKDF2 core: one PBKDF2-HMAC-SHA1 block from ipad, opad and U1, on a SHA-1 core specialised for 20-byte messages | `wpapsk/{PBKDF2,Sha1,Sha1BRAM,R,Add32}.v` | yes; the accumulator is cleared on `Rst` |
| General SHA-1 core (the one `wpapsk`'s was derived from) | `sha1/Sha1.v` (with the same `Sha1BRAM`, `R`, `Add32`) | yes, renamed `Sha1Full`, for the HMAC setup on the device |
| Bus bridge, ipad/opad/U1 tables, Xilinx block RAM, the Pico card shell, the host (coWPAtty) computing the HMAC setup | `wpapsk/{PBKDF2Bridge,PBKDF2BRAM,BRAM}.v`, `sha1/Sha1Top.v`, `cowpatty/` | no: hashcat's engine computes the setup on the device and the template carries the records |

The release tarballs (`oc-v0.3.tgz`, `oc-v0.5.tgz`) hold bitstreams and host software, no HDL; the Verilog is in the project's CVS repository, taken from SourceForge's snapshot of it (`PROVENANCE.md`). An older LiteX port of the same core (`~/claude/litex_wpa2`, kept outside this tree) took host-computed ipad, opad and U1 for one block per JtR-style packet. This port takes the password: the H2C record carries it and the bridge builds its canaries from one, so the device computes the HMAC setup itself.

## 2. Steps, in order

Wall-clock times from the start of the session (06:48).

1. **Branch** (step 1): skipped; the worktree was already on branch `wpa2`, built on `scrypt`.
2. **Read** (step 2, 10 min with the core): the porting notes of md5crypt, scrypt and descrypt (the custom-engine ports), `src/fpga/common/README.md`, `hcfpga_bridge.h`, the shared bridge's batch path (record loop, sizing, fault injection), the scaffold and its custom templates, `hcfpga_c2h_eob.v`, `hcfpga_jtr_unit_collect.v`, scrypt's engine, top and wrapper; then mode 22000's module and kernel (tmp struct, aux kernels, `module_deep_comp_kernel`, the potfile functions that read the tmps) and test module; then the core (below).
3. **Found the original** (5 min): the project's download page offers `oc-v0.3.tgz` and `oc-v0.5.tgz`, which hold no HDL (snag W1). The project's CVS repository, as SourceForge's read-only snapshot, holds `wpapsk/` and `sha1/` as RCS files; the head revisions were read out with a small RCS reader in scratch (no RCS tools on the host), all as untrusted data. The `litex_wpa2` copies of `Sha1.v`, `Sha1BRAM.v`, `R.v` and `Add32.v` are byte-identical to the head revisions (`Sha1.v` apart from a final newline); its `PBKDF2.v` adds an `ITERATIONS` guard and clears the accumulator on `Rst`.
4. **Ran the older LiteX port first** (step 3, 3 min). Copied it to scratch, built its sim under `simns.sh` (the run step fails at `sudo`, N1), started `obj_dir/Vsim` and `litex_server --udp` in the namespace and ran `cleanup_test.py -c hashcat.hccapx -w wordlist.txt -v`: `*** CRACKED *** Passphrase: hashcat!`, 4 passphrases in 17.5 s, every PMK it printed equal to `hashlib.pbkdf2_hmac` (judged by the raw PMKs, D1). It ran one unit, 4096 iterations, host-computed setup, a 25-byte ESSID and 8-byte passwords; so it proved the PBKDF2 core as that port changed it, and nothing of a setup on the device, of the general SHA-1 core, or of a core restarted without the gap its packets left.
5. **Benched what the old port did not run** (step 3, 10 min): the general SHA-1 core alone (`sha1/Sha1.v` with `Sha1BRAM`, loaded as `Sha1Top` does) against a Python SHA-1 compression: 41 of 41 blocks right, `SHA1("abc")` included, 82 cycles each. OpenCiphers' `PBKDF2.v` alone, driven as an engine would: the first of 12 runs right, the other 11 wrong, the accumulator is never cleared (W2); with the older port's clear, 12 of 12 with a 128-cycle gap between runs, but 1 of 12 with none: the core starts one more SHA-1 compression as it finishes, and a run started before it ends goes wrong. Gaps of 80 cycles and more were right, 78 and less wrong (W3). 679,771 cycles per block.
6. **The template extension** (15 min, commits `a8f64bc21`, `692a84764`): multi-part C2H results, section 3.
7. **Scaffold** (step 4, 1 min, commit `6ab8fc95f`): `new_fpga_algo.py --name wpa2 --mode 22000 --fpga-mode 92500 --core custom --pw-max 63 --digest-words 8 --digest-bytes 32 --grain 1 --salt-min 0 --salt-max 32 --iter-min 4095 --iter-max 4095` (two parts from 32 digest bytes). The untouched bench passed with the two-part engine stub (`ALL PASS`), the bridge and module compiled without warnings.
8. **Import** (step 5, 2 min, commit `256385428`): six files verbatim (already LF): `wpapsk/{PBKDF2,Sha1,Sha1BRAM,R,Add32}.v` and `sha1/Sha1.v`, found by linting `PBKDF2` alone and `sha1/Sha1.v` alone. No vendor primitives, no includes, no `SIMULATION`.
9. **Build outside the vendor flow** (step 5, 3 min, commit `bbaa15802`): both `Sha1.v` define `module Sha1`, so the general one is `Sha1Full` (W4); `PROVENANCE.md` with the origin, the CVS revisions and SHA-256 of each file, and the license text.
10. **Decide** (step 6, 5 min): written in the README's Decisions section. The one that is new on the template: the device returns the PMK, not hashcat's digest, so it cannot compare (W5).
11. **Gateware** (step 7, 15 min): `hcfpga_wpa2_engine.v` (the setup unit on `Sha1Full`, `NUM_CORES` pairs of `PBKDF2`, the generation, the collector with two records per PMK), the accumulator clear in `PBKDF2.v`, the top's extra registers, the wrapper (`WITH_CMP` 0 always), `tb_dut.vh`. Lint of the top with `-Wall` at 1, 2, 3 and 5 pairs: two of my unused signals, waived.
12. **References** (step 8, 5 min): `wpa2_ref.py` is `hashlib.pbkdf2_hmac`, as `m22000.py`'s `_pmk` is; it reproduces mode 22000's example PMKID, and a second path written the device's way (six compressions, then 4095 HMACs per block) agrees with it on four cases. `hcfpga_wpa2_ref.h`, self-contained SHA-1, HMAC and PBKDF2, agreed with `hashlib` on 19 cases (passwords of 0 to 63 bytes, ESSIDs of 0 to 32, binary bytes, the canary password).
13. **Bench** (step 9, 2 min): password lengths 0 to 63 with zero and top-bit bytes and the canary, every ESSID length 0 to 32, a comparator batch with one right candidate among 16 (two records back, 15 filtered, pairs restarted back to back), a wrong ESSID, padding, and the `WITH_CMP` 0 build. `ALL PASS` on the first run, 62 s with both builds.
14. **Simulated board** (step 10, 3 min): both bridges built with 2 pairs, `salt_len` at 0x3c and `salt4..7` at 0x40..0x4c, identity `hcfpga/1;board=sim;algo=wpa2;cores=2;parts=2;clk=1;abi=4`.
15. **Host side** (step 11, 10 min, commit `f1244c888`): the hooks (`config_extra` for the ESSID registers, `hcfpga_digest_swap32`, `c2h_parts` 2), the kernel (mode 22000's aux kernels reading `digest[0..7]`), the module (the comp path and the module options restored, the potfile functions on the bridged tmp struct, W6, W7), the test module's comments. No warnings. A full `make` then built `./hashcat` (P3).
16. **Proofs** (step 12, section 6). hashcat cracked on its first run over both links.
17. **Docs** (step 13): README, PROVENANCE, the setup doc's paragraph for mode 92500, these notes.

## 3. The template extension: multi-part C2H results

A C2H record carries 24 digest bytes and the PMK is 32. Every format stays as it was (the C2H record is 32 bytes: id, 24 digest bytes, core_id, flags 0x0001 error and 0x8000 end of batch); a candidate may now return P records, P = 1 to 4:

- The P records go one after the other with the same id; record k carries digest bytes 24k..24k+23 at C2H bytes 4..27 and its part index k in flag bits 8..11. P = 1 is the record as it was, part index 0.
- The comparator decides on the candidate from the first part, as on a single record; a filtered candidate sends no record. The candidate retires once, after its last part, so `retired` and the end-of-batch count stay candidate counts, and the end-of-batch tail never comes between two parts.
- `hcfpga_algo_t.c2h_parts` (0 or 1: one record). The bridge puts part k's six words after part k - 1's before `digest_from_c2h`, counts candidates, not records, sizes its C2H buffers for P records per candidate, and fails the batch (it is redone) on a missing, repeated or out-of-order part, or an end-of-batch record between parts (`MEMBER_FAULT_PARTS`, "returned a result in broken parts"). `HCFPGA_DIGEST_WORDS_MAX` is 24.
- The identity says `parts=P` when P > 1 (the wrapper's `PARTS`, added by `hcfpga_sim.py`); the bridge refuses a board whose parts disagree with its hooks, and a missing key means 1. `fpga_ident_t` gained `parts`, parsed in `hcfpga.c`.
- Fault injection: `HCFPGA_INJECT_FAULT=part_lose|part_dup|part_swap` drops a batch's first part 1, reads its first part 0 twice, or reads it after the record that follows it.
- Gateware: `hcfpga_iface.vh` defines `HCFPGA_PARTS_MAX` and `HCFPGA_FLAG_PART_LSB`; the custom engine template's contract and its stub send PARTS records (the stub latches the id: its first version took the next record's id for the second part, which its own bench caught); `hcfpga_c2h_eob.v`'s header says why parts are safe there; `hcfpga_jtr_unit_collect.v` is unchanged (one record).
- Scaffold: `--parts`, or derived from `--digest-bytes` above 24 (at most 96, `--digest-words` at most 24 and 6 per part); `--core jtr-unit` refuses parts. The bench's checker (`hcfpga_bench.check`) reads parts and checks their order, ids, flags and zero fill; `python3 src/fpga/common/hcfpga_bench.py` checks the checker itself against broken streams.
- Sizing: the bridge used to take its candidate limit from the H2C capacity alone. It now also keeps the C2H bytes of a full batch (P records per candidate, the end-of-batch record and a granule of padding) within the transport's capacity, which LitePCIe's and XRT's `batch_begin` check. That is the tighter limit for P > 1, and also for descrypt with P = 1: its H2C record is 16 bytes and its C2H record 32, so a full descrypt batch on LitePCIe would have been refused at `batch_begin`. No proof had run descrypt on PCIe.

The extension was proven before wpa2's gateware existed: in a throwaway copy of the tree, a scaffold with 40 digest bytes (two parts) passed its bench with the stub, hashcat ran against its simulated board (`parts=2` in the identity) with every canary right, each of the three part faults failed its batches and had them redone (`9 failures, none a wrong answer`, `No candidates were skipped`), and a bridge built for three parts refused the board (`returns 2 C2H records per candidate ... but the ptry bridge reads 3, and it is not used`). Then the regressions in section 6.

## 4. Generic versus wpa2-specific

| Piece | As the template has it | Changed for wpa2, and why |
|---|---|---|
| H2C record | bcrypt's, through `hcfpga_h2c_intake.v` | `len` limit 63; the engine drives `hold` while the setup unit reads the password |
| Engine | the custom scaffold's one-candidate stub | replaced: setup unit, PBKDF2 pairs, generation, collector |
| Generation | `hcfpga_gen.v` for cores without a reset | used: a PBKDF2 core is never stopped |
| C2H record | bcrypt's, now with parts | two records per candidate (the PMK's 32 bytes), core_id the pair |
| Comparator | the low 7 bits of `digest[0]` | built out (`WITH_CMP` 0): hashcat's digest is a MIC or PMKID, not the PMK (W5) |
| CSR block | the shared registers, extras from 0x3c | `salt_len`, `salt4..7` (ESSID bytes 16..31), as scrypt; `iter_count` written and not used |
| Identity | `cores=` | counts pairs, grain 1; `parts=2` |
| Bridge | `hcfpga_bridge.c` | the hook values, `config_extra`, `hcfpga_digest_swap32`, `c2h_parts` 2 |
| Module | the scaffold's bridged copy of module_22000.c | the comp path back (`OPTS_TYPE_DEEP_COMP_KERNEL`, `module_deep_comp_kernel`, `KERN_BITS` AUX1..6), the module options back (`wpa_module_register_options`), the bridged kernel included in place of `m22000-pure.cl` and the potfile functions on its tmp struct, `OPTI_TYPE_SLOW_HASH_SIMD_LOOP` out |
| Kernel | the scaffold's pass-through | pass-through init and loop, mode 22000's aux1 to aux6 reading `digest[0..7]` for `out[0..7]` (48 reads; otherwise byte-identical to upstream's) |
| Test module | the scaffold's copy of m22000.py | comments only: the device takes what mode 22000 takes |
| Template | | the multi-part extension (section 3), in two commits of its own |

## 5. Layouts

H2C record: bcrypt's, the password big-endian four bytes per word, which is how SHA-1 reads the key block.

C2H records of one candidate:

| Record | Bytes 0..3 | Bytes 4..27 | Bytes 28..29 | Bytes 30..31 |
|---|---|---|---|---|
| 0 | id | PMK bytes 0..23 | pair | 0x0000 |
| 1 | id | PMK bytes 24..31, then 16 zero bytes | pair | 0x0100 |

Registers: `src/fpga/wpa2/README.md`. Timing, from the benches: the setup unit takes about 600 cycles a candidate (six compressions of 82 cycles plus 16-word loads), a pair 679,771 cycles a block, both blocks side by side; the bench's 21-candidate batch on two pairs took 7,479,620 cycles (11 rounds of about 680,000). On the simulated board a round of two candidates took about 1.5 s over UARTBone with nothing else running.

## 6. Snags

Times are wall clock in this session.

| # | Snag | Took | Fix | What would have prevented it |
|---|---|---|---|---|
| W1 | OpenCiphers' release tarballs (`oc-v0.3.tgz`, `oc-v0.5.tgz`) hold bitstreams and host software but no HDL. The Verilog is only in the project's CVS repository, which SourceForge serves as a snapshot of RCS `,v` files; the host has no RCS tools, and `AGENTS.md` step 5 assumes git (`git archive <commit>`) | 10 min | A small RCS reader in scratch took the head revision of each file (RCS stores the head whole); `PROVENANCE.md` names each file's CVS revision and SHA-256 and the snapshot's SHA-256, and quotes the project's license statement and David Hulton's BSD text from the release tarball | `AGENTS.md` step 5: when upstream is not git (CVS, SVN, a tarball), name each file's revision or the archive, and the SHA-256 of what you took; look in the project's version control when a release holds no HDL |
| W2 | OpenCiphers' `PBKDF2.v` never clears its result accumulator: `Rst` reloads ipad, opad and U1 and restarts the count, but every run after the first returns the previous run's result XORed with its own (1 of 12 right in a bench of the core alone) | 5 min | The five outputs cleared on `Rst`, the change the older LiteX port had made (the diff step 3 asks for showed it) | Step 3's diff against upstream and its bench of what the old port did not run, as written; both caught it |
| W3 | `PBKDF2.v` starts one more SHA-1 compression as it finishes; a run started before that compression ends goes wrong (restarts 80 cycles or more after `Done` right, 78 or fewer wrong). The older port's packet traffic between runs always left more than that, so its test could not show it | 5 min | The engine lets a pair rest 128 cycles after `Done`; the core is unchanged | Bench a core that is restarted by its own engine back to back, with no gap, before writing the engine (proposed for `AGENTS.md` step 3) |
| W4 | `sha1/Sha1.v` and `wpapsk/Sha1.v` both define `module Sha1`, and the design needs both (the HMAC setup needs a general block, PBKDF2 a 20-byte message) | 2 min | `sha1/Sha1.v`'s module renamed `Sha1Full`, in step 5's second commit, with a `PROVENANCE.md` section | `AGENTS.md` step 5: two imported files defining one module name: rename one, in the second commit |
| W5 | The device returns the PMK, an intermediate: hashcat's digest is a MIC or PMKID that its comp kernels compute from it. The template's comparator indexes a bitmap of hashcat's digests with a byte of what the device returns, so on wpa2 it would drop the right candidate. Nothing in `AGENTS.md` or `hcfpga_algo_t` covers a device that cannot compare | 5 min (design) | The wrapper builds the engine with `WITH_CMP` 0 always (the engine keeps the comparator for the template's contract, proven in the bench); every candidate returns, so rows 6 and 7 both show `recv` equal to the batch. The bridge notices a device that returns everything after its first batch with more unfiltered results than its grain and counts every candidate from then on | `AGENTS.md` step 6: say what to do when the device's result is not hashcat's digest; and a hook (`hcfpga_algo_t.cmp_none`) so the bridge writes an all-ones bitmap and counts every candidate from the first batch, as it does under `HCFPGA_CMP_OFF` |
| W6 | The scaffold dropped `module_ctx->module_register_options = wpa_module_register_options` as a helper "of the upstream kernel"; it registers the module's own options (`--eapol-message-pair`, `--nonce-error-corrections`), which `module_hash_decode_postprocess` reads. It also dropped `OPTS_TYPE_DEEP_COMP_KERNEL` and `module_deep_comp_kernel`, which a mode that keeps the upstream comp kernels needs, and kept `OPTI_TYPE_SLOW_HASH_SIMD_LOOP` for a pass-through kernel without vector code | 5 min | All three restored or dropped by hand, listed in the module's header comment | The scaffold: keep `module_register_options`; drop `OPTI_TYPE_SLOW_HASH_SIMD_*`; for a mode with AUX kernels, keep the deep comp kernel and say so. `AGENTS.md` step 11: a device that computes an intermediate keeps the upstream comp kernels |
| W7 | Mode 22000's module includes its kernel (`m22000-pure.cl`) and runs the aux kernels in C to check potfile entries (`module_potfile_custom_check`); the potfile functions read the PMK from the upstream tmp struct (`out[]`). The scaffold leaves that include and those functions as they are, and declares its own tmp struct, which would collide with the bridged kernel's once that is included | 10 min | The module includes `m92500-pure.cl`, takes the tmp struct from it (no second declaration), and the potfile functions and the custom check use `digest[]` and `m92500_aux*` | `AGENTS.md` step 11: check the module for an included upstream kernel and for functions that read the tmps (potfile, custom checks); move them to the bridged kernel and tmp struct |
| W8 | `test.py` imports `m92500.py`, which imports pycryptodome (`Crypto`, for the key version 3 CMAC); the LiteX venv has none (`ModuleNotFoundError: No module named 'Crypto'`) | 3 min | `pip install --no-deps --target $S/pydeps pycryptodome`, `PYTHONPATH=$S/pydeps` for every test.py run | `AGENTS.md` section 3: a test module may import packages the venv lacks; install them under `$S` |
| W9 | `multi.txt` wants three salt lengths, but `m22000.py` makes the ESSID itself (random, 0 to 30 bytes) and ignores the salt argument | 3 min | `essid=` passed by keyword: 0, 5 and 32 bytes, and three record types (PMKID, EAPOL, FT EAPOL) | Section 5's file list: when the test module makes the salt itself, pass it by its own keyword |
| W10 | The extension's engine stub first sent part 1 with the next record's id (it had pulsed `rec_taken`, so the intake had moved on) | 3 min | The stub latches the id | (caught by the stub's own bench, as intended) |
| W11 | Rows 6 to 9 each take about 3 min on this design: hashcat's autotune runs four full batches (30 candidates, 33 s each over Etherbone) before the attack batch | 0 (waiting) | none | Section 5: expect autotune batches of the row's size; for a slow algorithm, a smaller word list would keep those rows short |

What went right the first time, and why: the bench passed every case on its first run, the board's CSR map matched, the bridge and module compiled without warnings, and hashcat cracked on its first run over both links. Each followed from benching both cores alone before writing the engine (which found W2 and W3 before they could show up as wrong digests), from a reference that reproduced the format's example PMKID and a second one written the device's way, and from reusing mode 22000's aux kernels unchanged apart from where they read the PMK.

## 7. Proofs

All commands from the worktree root, with hashcat and every plugin built from this branch (`make`), `S=<scratch>`, `OCL_ICD_VENDORS=$S/icd` (PoCL 3.0, hence `--force`/`-f`), `PYTHONPATH=$S/pydeps` (pycryptodome, W8), `M=92500`, `HCM="./hashcat -m 92500 -a 0 --force --potfile-disable"` plus a `--session` per run. The sims were built by `src/fpga/common/hcfpga_sim.py --algo wpa2 --bridge <uartbone|etherbone> --units 2 --build-only --output-dir $S/wpa2/sim_<ub|eb>` (two pairs, `cores=2;parts=2`) and started with `--no-build`, the UARTBone one with `--uart-port 2871` (`U="env HCFPGA_LITEXBONE=tcp:127.0.0.1:2871"`), the Etherbone one under `SIMNS_DIR=$S/wpa2/ns $GUIDE/debug/simns.sh` (`E="<that> env HCFPGA_LITEXBONE=udp:192.168.9.50"`). The UARTBone rows (2, 10, 4, 5) and the Etherbone rows (3, 6 to 9, the part rows, 11) ran side by side.

Files in `$S/wpa2/`: `hash.txt` mode 22000's `ST_HASH` (`WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***`, password `hashcat!`, ESSID `hashcat-essid`); `words8.txt` eight words with `hashcat!`; `ROUNDS` 4095 (`salt_iter`); `words30.txt` 29 wrong words and `hashcat!` 18th; `wrong.txt` the same line with the ESSID's last byte changed (`hashcat-essie`); `multi.txt` three lines from `m92500.py`'s `module_generate_hash` (the word as bytes, the ESSID by keyword, W9): a PMKID with an empty ESSID, an EAPOL with a 5-byte ESSID, an FT EAPOL with a 32-byte ESSID (`ROUNDS3` 4095); `words24.txt` with their passwords 14th, 20th and 23rd; `limits.txt`: (1) a PMKID with an empty ESSID, password 8 bytes; (2) an EAPOL with a 32-byte ESSID, password 63 bytes; (3) line 2 with a 33-byte ESSID; (4) line 1 as record type 05; `limits_words.txt` a 7-byte password, the 8-byte one, the 63-byte one, it plus a 64th byte, `hashcat!`.

| # | What | Command | Result |
|---|---|---|---|
| 0 | Older LiteX port, before any change | its `wpa2_sim.py --num-units 1` under `simns.sh`, then `obj_dir/Vsim`, `litex_server --udp --udp-ip 192.168.9.50`, `cleanup_test.py -c hashcat.hccapx -w wordlist.txt -v` | `*** CRACKED *** Passphrase: hashcat!`, 4 passphrases in 17.5 s; the four PMKs it printed equal `hashlib.pbkdf2_hmac` |
| 0a | The cores alone | Verilator benches in scratch: `sha1/Sha1.v` with `Sha1BRAM` against a Python SHA-1 compression; `wpapsk/PBKDF2.v` driven as the engine drives it, 12 blocks from six passwords and ESSIDs, gaps of 0 to 128 cycles between runs | SHA-1: 41 of 41 right, 82 cycles. PBKDF2 as upstream wrote it: 1 of 12 (W2); with the accumulator cleared: 12 of 12 at gaps of 80 cycles and more, 1 of 12 at 78 and less (W3); 679,771 cycles a block |
| 1 | Bench | `SIM_WORK=$S/wpa2/tb make -C src/fpga sim ALGO=wpa2` | lengths (21 candidates: passwords of 0 to 63 bytes, binary ones, a zero byte inside, `hashcat!`, the canary; 42 records), essid0 to essid32 (one candidate each), cmp (16 candidates, 1 returned in 2 records, 15 filtered), salt (0 matching), pad, nocmp (the `WITH_CMP` 0 build, an empty bitmap, 4 of 4 returned in 8 records): `ALL PASS`, 1 min 3 s with both builds |
| 2 | Example hash, self-test on, UARTBone | `$U HCFPGA_DEBUG=1 $HCM $S/wpa2/hash.txt $S/wpa2/words8.txt` | self-test batch `recs=3 h2c=96 B c2h=224 B canaries=2`, no canary error, `...686173686361742d6573736964***:hashcat!`, `Status...........: Cracked` (45 s) |
| 3 | Same over Etherbone | `$E HCFPGA_DEBUG=1 $HCM $S/wpa2/hash.txt $S/wpa2/words8.txt` | `canaries=2`, no canary error, `Cracked` (24 s) |
| 4 | test.py | `$U HCFPGA_TEST=1 python3 tools/test.py -m 92500 -P -f` | attack 0, single (8 vectors) and multi, vector width 1 and 4: 4 `OK`, 0 errors, 4 min 51 s |
| 5 | test.py, every attack | same with `-a all` | attacks 0, 4, 8 and 9, single, and multi for attacks 0 and 8 (test.py runs no multi for 4 and 9 here), vector width 1 and 4: 12 `OK`, 0 errors, 16 min 39 s |
| 6 | Comparator | `$E HCFPGA_TIMING=1 HCFPGA_DEBUG=1 $HCM -n 15 -u 4095 $S/wpa2/hash.txt $S/wpa2/words30.txt` (2 pairs, grain 1: 15 × 2 = 30) | the attack batch `recs=30 h2c=576 B c2h=1952 B`, `recs=30 recv=30`: every candidate returns, the device has no comparator (W5); `Cracked` (2 min 54 s, of which four autotune batches of 30, W11) |
| 7 | No compare | row 6 with `HCFPGA_CMP_OFF=1` | `recs=30 recv=30`, `Cracked` (2 min 51 s) |
| 8 | Wrong salt | row 6 with `wrong.txt` | `recs=30 recv=30`, `Status...........: Exhausted` (2 min 56 s) |
| 9 | Failed batches | row 6 with `HCFPGA_INJECT_FAULT=send HCFPGA_INJECT_PERIOD=2` | `5 failures, none a wrong answer`, `No candidates were skipped`, the redone batches `recs=32 recv=30` (two canaries), `Cracked` (3 min 19 s). The failed batches had candidates in the pairs when the board was restarted; their results came back under the old generation and were dropped |
| 9a | Missing part | `$E HCFPGA_TIMING=1 HCFPGA_INJECT_FAULT=part_lose HCFPGA_INJECT_PERIOD=2 $HCM -n 4 -u 4095 $S/wpa2/hash.txt $S/wpa2/words8.txt` | 5 batches `returned a candidate's result in broken parts`, `5 failures, none a wrong answer`, `No candidates were skipped`, `Cracked` (2 min 20 s) |
| 9b | Repeated part | 9a with `part_dup` | the same, `Cracked` (2 min 45 s) |
| 9c | Parts out of order | 9a with `part_swap` | the same, `Cracked` (2 min 49 s) |
| 10 | Loops below the count, several salts | `$U HCFPGA_DEBUG=1 $HCM -n 1 -u 1023 $S/wpa2/multi.txt $S/wpa2/words24.txt` (4095 / 4) | `Loops:1023`, `3/3 (100.00%) Salts`: the PMKID, the EAPOL and the FT EAPOL lines, `Cracked` (1 min 32 s) |
| 11 | Limits | `$E $HCM $S/wpa2/limits.txt $S/wpa2/limits_words.txt`; `: > $S/wpa2/empty.pot; ./hashcat -m 92500 --left --potfile-path $S/wpa2/empty.pot $S/wpa2/limits.txt` and the same with `-m 22000` | lines 1 and 2 `Cracked` (2/2 salts: the empty and the 32-byte ESSID, the 8- and 63-byte passwords); line 3 `Token length exception`; line 4 `Salt-value exception`; the 7- and 64-byte passwords `Rejected` (28 s). `--left` lists lines 1 and 2 and refuses 3 and 4 for both modes: mode 92500 refuses nothing mode 22000 takes |
| 11a | hccapx | a second UARTBone sim (a copy of `sim_ub`, port 2872), `HCFPGA_DEBUG=1 $HCM $S/wpa2/hashcat.hccapx <old port's wordlist.txt>` (the older port's capture: a 25-byte ESSID, key version 1) | `canaries=2`, `HCPX:hashcat!`, `Cracked` (11 s) |
| 12 | bcrypt untouched | `git diff fpga-template -- src/fpga/bcrypt src/bridges/bridge_fpga_bcrypt.c src/bridges/bridge_fpga_bcrypt.mk src/modules/module_75000.c OpenCL/m75000-pure.cl` | prints nothing |
| 13 | bcrypt still works | the Guide's `debug/bcrypt_sim.py --hashcat <this tree> --output-dir $S/bc_eb` under `SIMNS_DIR=$S/bc_ns`, `./hashcat -m 75000 -a 0 --force --potfile-disable -n 1 -u 32 bc.hash bc_words.txt` and `HCFPGA_TEST=1 python3 tools/test.py -S -m 75000 -f -D 1` | `$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou:hashcat`, `Cracked` (27 s); `1/1 hash-modes cracked their own self-test vector` (42 s) |
| 14 | md5crypt still works (the template changed) | below | below |

### The extension's regressions

From a tree of its own (`git archive` of `692a84764`, the second extension commit, built with `make`), with md5crypt's row-14 files (its notes, section 10) and the descrypt, scrypt and bcrypt files of their ports. Sims as above, UARTBone on port 2862 (md5crypt) and 2863 (scrypt).

| What | Command | Result |
|---|---|---|
| md5crypt row 1 | `make -C src/fpga sim ALGO=md5crypt` | `ALL PASS`, cycle counts the same as before the template existed (lengths 827871, cmp 581090, salt 290015, pad 3381) (23 s) |
| md5crypt rows 2, 3 | example hash, UARTBone and Etherbone | `canaries=3`, `Cracked` both (25 s, 9 s) |
| md5crypt rows 4, 5 | `HCFPGA_TEST=1 tools/test.py -m 90500 -P -f`, and `-a all` | 4 `OK` (3 min 23 s); 14 `OK` (10 min 57 s) |
| md5crypt rows 6, 7, 8 | Etherbone, `-n 3 -u 1000`, words30; `HCFPGA_CMP_OFF=1`; wrong salt | `recs=30 recv=1`, `Cracked`; `recs=30 recv=30`, `Cracked`; `recs=30 recv=0`, `Exhausted` |
| md5crypt row 9 | `HCFPGA_INJECT_FAULT=send HCFPGA_INJECT_PERIOD=2` | `5 failures, none a wrong answer`, `No candidates were skipped`, `Cracked` (35 s) |
| md5crypt row 10 | UARTBone, `-n 1 -u 250`, three salts | `Loops:250`, `3/3 ... Salts`, `Cracked` (32 s) |
| descrypt bench | `make -C src/fpga sim ALGO=descrypt` | `ALL PASS` (1 min 23 s) |
| descrypt row 9 | Etherbone, `HCFPGA_INJECT_FAULT=send HCFPGA_INJECT_PERIOD=2 ... -n 2 -u 25` | `5 failures, none a wrong answer`, `No candidates were skipped`, `Cracked` (10 s) |
| scrypt bench | `make -C src/fpga sim ALGO=scrypt` | `ALL PASS` (49 s) |
| scrypt row 2 | UARTBone, example hash, self-test on | `recs=2 h2c=64 B c2h=96 B canaries=1`, `Cracked` (11 s) |
| bcrypt | as row 13 | `Cracked` (23 s); `1/1 hash-modes cracked their own self-test vector` (31 s) |
| The bench's checker | `python3 src/fpga/common/hcfpga_bench.py` | for 2, 3 and 4 parts: a good batch with a filtered candidate passes; a missing part, a repeated part, two parts swapped, parts of two candidates mixed, and a candidate returned that should have been filtered each fail: `ALL PASS` |
| The scaffold with two parts | in a throwaway tree, `new_fpga_algo.py --name ptry --mode 22000 --fpga-mode 92599 --core custom --digest-bytes 40 ...`, its bench, its board and hashcat with `--self-test-disable` | bench `ALL PASS` (17 candidates in 34 records; cmp 3 returned in 6 records, 27 filtered); hashcat's batches came back as two records a candidate (`recs=3 h2c=64 B c2h=224 B`) with every canary right, `Exhausted` (the stub's toy hash); `part_lose`, `part_dup`, `part_swap`: `9 failures, none a wrong answer` each; a bridge built for three parts refused the two-part board |
| One-part scaffolds | the same tree, a custom one (16 digest bytes) and a JtR one | bench `ALL PASS` both; `--core jtr-unit --digest-bytes 40` refused |

## 8. Not done

- No real board. The pairs run at one clock here. A board build picks the number of pairs (two SHA-1 cores, two 16-word schedule memories and about 1,000 flip-flops of state each); one setup unit feeds about a thousand of them.
- No wave model: hashcat autotunes, and the batch timeout uses 1000 cycles per iteration per wave (an iteration is two compressions of 83 cycles).
- The device never filters. A hook that tells the bridge so (W5) would let it count every candidate from the first batch and skip the bitmap writes; the bridge now finds out after its first batch with more unfiltered results than its grain.
- The trailing compression of `PBKDF2.v` (W3) is worked around, not removed; it costs 83 cycles in 680,000.
- The scaffold fixes W6 asks for are not made; the module was fixed by hand.
- `AGENTS.md` is not changed; its proposed changes are in the report of this port.
- The imported OpenCiphers files have no em dashes and no non-ASCII bytes, so there is nothing to clean up later.
