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

module shreg #(
	parameter WIDTH = 32,
	parameter DEPTH = 1 // 1+
	)(
	input CLK,
	input [WIDTH-1:0] i,
	input en,
	output [WIDTH-1:0] o
	);

	// hashcat: behavioural form of upstream's per-bit SRL16E with the address fixed at DEPTH-1, so
	// that no vendor primitive is needed. o is i delayed by DEPTH enabled clock edges, from an all
	// zero start, as SRL16E with INIT 0 gives. Synthesis infers shift register LUTs from it.
	reg [WIDTH-1:0] r [0:DEPTH-1];

	integer k;
	initial
		for (k=0; k < DEPTH; k=k+1)
			r[k] = {WIDTH{1'b0}};

	always @(posedge CLK)
		if (en) begin
			r[0] <= i;
			for (k=1; k < DEPTH; k=k+1)
				r[k] <= r[k-1];
		end

	assign o = r[DEPTH-1];

endmodule
