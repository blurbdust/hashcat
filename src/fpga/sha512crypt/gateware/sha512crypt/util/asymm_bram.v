`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Modified for hashcat from John the Ripper's original.
// src/fpga/sha512crypt/PROVENANCE.md lists every change.
`include "log2.vh"

/*
INFO:Xst:3229 - The RAM description <Mram_mem> will not be implemented on the device block RAM because actual implementation does not support asymetric block RAM larger than one block.
    -----------------------------------------------------------------------
    | ram_type           | Distributed                         |          |
    -----------------------------------------------------------------------
    | Port A                                                              |
    |     aspect ratio   | 1024-word x 32-bit                  |          |
    |     clkA           | connected to signal <wr_clk>        | rise     |
    |     weA            | connected to signal <wr_en>         | high     |
    |     addrA          | connected to signal <wr_addr>       |          |
    |     diA            | connected to signal <din>           |          |
    -----------------------------------------------------------------------
    | Port B                                                              |
    |     aspect ratio   | 512-word x 64-bit                   |          |
    |     addrB          | connected to signal <rd_addr>       |          |
    |     doB            | connected to internal node          |          |
    -----------------------------------------------------------------------
*/

//
// Asymmetric BRAM, 1 write port, 1 read port
// Write port has smaller data width
//
module asymm_bram_min_wr #(
	parameter minWIDTH = 8,
	parameter RATIO = 4,
	parameter maxDEPTH = 512,
	parameter INIT = 0
	)(
	input wr_clk,
	input [minWIDTH-1:0] din,
	input wr_en,
	input [`MSB(maxDEPTH*RATIO-1) :0] wr_addr,

	input rd_clk,
	output reg [minWIDTH*RATIO-1:0] dout = INIT,
	input rd_en,
	input [`MSB(maxDEPTH-1) :0] rd_addr
	);

	localparam log2RATIO = `MSB(RATIO);

	integer k;

	(* RAM_STYLE="BLOCK" *)
	reg [minWIDTH-1:0] mem [0:RATIO*maxDEPTH-1];
	initial
		for (k=0; k < RATIO*maxDEPTH; k=k+1)
			mem[k] = 0;

	genvar i;

	// Describe the port with the smaller data width exactly as you are used to
	// for symmetric block RAMs
	always @(posedge wr_clk)
		if (wr_en)
			mem[wr_addr] <= din;

	// A generate-for is used to describe the port with the larger data width in a
	// generic and compact way
	generate for (i = 0; i < RATIO; i = i+1)
		begin: portB
			localparam [log2RATIO-1:0] lsbaddr = i;
			always @(posedge rd_clk)
				if (rd_en)
					dout[(i+1)*minWIDTH-1:i*minWIDTH] <= mem[{rd_addr, lsbaddr}];
		end
	endgenerate

endmodule


//
// Asymmetric BRAM, 1 write port, 1 read port
// Read port has smaller data width
//
module asymm_bram_min_rd #(
	parameter minWIDTH = 8,
	parameter RATIO = 4,
	parameter maxDEPTH = 512,
	parameter INIT = 0
	)(
	input wr_clk,
	input [minWIDTH*RATIO-1:0] din,
	input wr_en,
	input [`MSB(maxDEPTH-1) :0] wr_addr,

	input rd_clk,
	output [minWIDTH-1:0] dout,
	input rd_en,
	input [`MSB(maxDEPTH*RATIO-1) :0] rd_addr
	);

	localparam log2RATIO = `MSB(RATIO);

	integer k;

	// hashcat: one memory of wide words, written whole. Narrow word {a, i} is
	// slice i of wide word a, as upstream's {wr_addr, lsbaddr} wrote it. The read
	// registers the wide word and the slice number on rd_en and selects after,
	// so dout changes on the same edges and holds the same values as upstream's
	// registered dout. Upstream wrote the narrow memory from RATIO always blocks,
	// which Quartus rejects as multiple drivers.
	(* RAM_STYLE="BLOCK" *)
	reg [minWIDTH*RATIO-1:0] mem [0:maxDEPTH-1];
	initial
		for (k=0; k < maxDEPTH; k=k+1)
			mem[k] = 0;

	always @(posedge wr_clk)
		if (wr_en)
			mem[wr_addr] <= din;

	reg [minWIDTH*RATIO-1:0] rd_word = INIT;
	reg [log2RATIO-1:0] rd_lsb = 0;

	always @(posedge rd_clk)
		if (rd_en) begin
			rd_word <= mem[rd_addr[`MSB(maxDEPTH*RATIO-1) :log2RATIO]];
			rd_lsb <= rd_addr[log2RATIO-1:0];
		end

	assign dout = rd_word[rd_lsb*minWIDTH +: minWIDTH];

endmodule

