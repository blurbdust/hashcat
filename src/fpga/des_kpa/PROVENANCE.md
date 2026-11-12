# des_kpa FPGA provenance

Everything in this design was written for hashcat: the pipelined DES core, the engine around it (the amplifier generator, the waves, the comparator and the collector), the datapath top, the LiteX wrapper, the bench and its reference, and the standalone speed tool. The DES tables in `gateware/des_kpa/des_kpa_tables.vh` and `gateware/des_kpa/des_kpa_ref.py` are those of FIPS 46-3. The host's DES (`src/bridges/fpga/hcfpga_des_kpa_ref.h`) takes its tables from the descrypt reference beside it, and its PERM_OP and DES_FP follow hashcat's `OpenCL/inc_cipher_des.h`.

The shared parts are identical in every algorithm after bcrypt: `hcfpga_*.py` and `hcfpga_iface.vh` here, and the H2C intake, end-of-batch tail, generation counter, bench and simulated board in `gateware/des_kpa/`. `software/user/liblitepcie/` is the copy of LitePCIe's user library that bcrypt's tools use (`src/fpga/bcrypt/software/user/liblitepcie/`), unchanged.

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/des_kpa/hcfpga_des_kpa_core.v` | one core: 16 DES rounds unrolled, one key per clock, the key schedule wired from the key; the compare against the targets and the core's hit FIFO |
| `gateware/des_kpa/hcfpga_des_kpa_engine.v` | the loader, the waves (every core runs the same amplifier item each clock), the amplifier tables and digit counters, the bus to the cores, the collector, and the thermal stop |
| `gateware/des_kpa/hcfpga_des_kpa_top.sv` | the datapath top: the shared intake and end-of-batch tail around the engine |
| `gateware/des_kpa/des_kpa_tables.vh` | the FIPS 46-3 tables, generated from `des_kpa_ref.py` |
| `gateware/des_kpa_dma_wrapper.py` | the LiteX wrapper, an `HcfpgaDmaWrapper` with the amplifier and target registers |
| `gateware/des_kpa/tb_datapath.py`, `tb_dut.vh`, `des_kpa_ref.py` | the datapath bench on the shared one, and its reference: DES from the FIPS 46-3 tables, checked against OpenSSL |
| `des_kpa_storeypeak_dma.py` | the Microsoft Storey Peak (Stratix V) target, the crypt(3) ports' with the die temperature wired to the thermal stop |
| `software/user/des_kpa_speed.c` | the standalone speed and answer check |

## Toolchain

LiteX and Verilator for the simulated board, Verilator for the bench. Quartus Prime Standard for the Microsoft Storey Peak (Stratix V) target, `des_kpa_storeypeak_dma.py`.
