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
// src/fpga/md5crypt/PROVENANCE.md lists every change.


module shreg_ff #(
	parameter WIDTH = 32,
	parameter DEPTH = 2, // Min. 2; adds FFs
	parameter INIT = 0
	)(
	input CLK,
	input [WIDTH-1:0] i,
	input en, rst,
	output reg [WIDTH-1:0] o = INIT
	);

	// hashcat: behavioural form of upstream's per-bit SRL16E with the address fixed at DEPTH-2, see
	// shreg.v. shreg_out is i delayed by DEPTH-1 enabled clock edges, the register below adds one.
	reg [WIDTH-1:0] r [0:DEPTH-2];

	integer k;
	initial
		for (k=0; k < DEPTH-1; k=k+1)
			r[k] = {WIDTH{1'b0}};

	always @(posedge CLK)
		if (en) begin
			r[0] <= i;
			for (k=1; k < DEPTH-1; k=k+1)
				r[k] <= r[k-1];
		end

	wire [WIDTH-1:0] shreg_out = r[DEPTH-2];

	always @(posedge CLK)
		if (rst)
			o <= INIT;
		else if (en)
			o <= shreg_out;

endmodule
