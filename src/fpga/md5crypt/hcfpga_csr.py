#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# CSR locations a LiteX board has to keep for hashcat's FPGA bridges.
#
# hashcat does not read a csr.csv. The bridges and the shared map (fpga_csr_map_no_cpu in
# src/bridges/fpga/hcfpga.c) hardcode the offsets the PCIe boards have, and the litexbone transport
# (src/bridges/fpga/transport_litexbone.c) adds fixed offsets for memstream. LiteX hands out CSR
# locations in order of first use, so a board that adds anything (an Etherbone PHY, LEDs, a second
# UART) shifts them unless every bank is pinned.
#
# With the default 0x800 paging, location n starts at n * 0x800:
#
#   0  0x0000  <algo>             the algorithm wrapper's registers (bcrypt, md5crypt, ...)
#   1  0x0800  ctrl               scratch at 0x0804 must read 0x12345678
#   2  0x1000  identifier_mem     the hcfpga/1;board=...;algo=...;abi=... identity
#  24  0xc000  memstream          ring pointers and status
#  25  0xc800  memstream_h2c_mem  H2C ring
#  26  0xd000  memstream_c2h_mem  C2H ring
#  27+         anything else the board adds (ethphy, ...)
#
# Locations 3 to 23 stay free: the PCIe boards keep pcie_dma0 (0x2000), pcie_endpoint (0x2800),
# xadc (0x4000) and dna (0x4800) there, and a register the bridge reads on those boards must not be
# something else on this one.
#
# The bank at 0 is named after the algorithm.

EXTRA_FIRST = 27

def csr_locations(algo):
    """The pinned banks, the algorithm's own named algo."""
    return {
        algo                :  0,
        "ctrl"              :  1,
        "identifier_mem"    :  2,
        "memstream"         : 24,
        "memstream_h2c_mem" : 25,
        "memstream_c2h_mem" : 26,
    }

def pin_csrs(soc, algo, extra=()):
    """Pin hashcat's banks and memstream, then each name in extra from location 27 up."""
    for name, n in csr_locations(algo).items():
        soc.csr.add(name, n=n)
    for i, name in enumerate(extra):
        soc.csr.add(name, n=EXTRA_FIRST + i)

def check_csrs(soc, algo):
    """After the SoC is finalized: fail if a bank landed somewhere hashcat does not expect it."""
    want = csr_locations(algo)
    locs = soc.csr.locs
    bad  = []
    for name, n in want.items():
        if locs.get(name) != n:
            bad.append(f"{name} at {locs.get(name)}, wants {n}")
    for name, n in locs.items():
        if (name not in want) and (n < EXTRA_FIRST):
            bad.append(f"{name} at {n}, below {EXTRA_FIRST}: pin it with pin_csrs(soc, algo, extra=[\"{name}\"])")
    if bad:
        raise SystemExit("CSR map does not match what hashcat's bridge expects:\n  " + "\n  ".join(bad))
