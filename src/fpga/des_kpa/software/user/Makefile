##
## Author......: See docs/credits.txt
## License.....: MIT
##

ABI := $(shell awk '$$2 == "FPGA_ABI_CURRENT" { print $$3 }' ../../../../bridges/fpga/hcfpga.h)

CFLAGS=-O2 -Wall -g -I../../../driver -I../../../driver/build -Iliblitepcie -MMD -fPIC $(if $(ABI),-DHCFPGA_ABI=$(ABI),)
LDFLAGS=-g
CC=$(CROSS_COMPILE)gcc
AR=ar

PROGS=des_kpa_speed

all: $(PROGS)

liblitepcie/liblitepcie.a: liblitepcie/litepcie_dma.o liblitepcie/litepcie_flash.o liblitepcie/litepcie_helpers.o
	ar rcs $@ $^
	ranlib $@

des_kpa_speed: liblitepcie/liblitepcie.a des_kpa_speed.o
	$(CC) $(LDFLAGS) -o $@ $^ -Lliblitepcie -llitepcie

clean:
	rm -f $(PROGS) *.o *.a *.d *~ liblitepcie/*.a liblitepcie/*.o liblitepcie/*.d

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

liblitepcie/%.o: liblitepcie/%.c
	$(CC) -c $(CFLAGS) -o $@ $<

-include $(wildcard *.d) $(wildcard liblitepcie/*.d)

.PHONY: all clean
