/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Modified for hashcat from John the Ripper's original.
// src/fpga/bcrypt/PROVENANCE.md lists every change.

//
// The body of the S module, included once per storage style by S.v.
//
// `HC_S_MODULE is the name to give this copy, and `HC_S_RAM_STYLE and `HC_S_RAMSTYLE are the
// literals the Vivado and Quartus storage attributes carry. Everything else is the file as it came
// from John the Ripper, plus the state dump read path and the HC_S_READ_FLAG form of the read
// register described in PROVENANCE.md. There is no second copy of the logic: this file is the only
// one, and S.v includes it twice.
//
module `HC_S_MODULE #(
	parameter MSB = 31,
	parameter ADDR_NBITS = 8
	)(
	input CLK,
	input [MSB:0] din,
	input wr_en,
	input [9:0] addr_wr,

	input rd_en,
	input rst_rd,
	input [MSB:0] addr_rd,

	// State dump.
	//
	// The normal read channel IS the round function: all four banks are read at once, each at a
	// different byte of addr_rd, and 'out' is S3 + (S2 ^ (S1 + S0)). That can never yield an
	// individual word, so there is no way to read S back out for a chunk boundary without a second
	// view of it.
	//
	// With dump_en high the four banks are all read at dump_entry instead, and 'out' returns the one
	// dump_bank selects, raw. The walk steps the entry on every word and the bank every 256 words, so
	// it is 1024 reads for 1024 words. See the dump defines in bcrypt.vh.
	input dump_en,
	input [ADDR_NBITS-1:0] dump_entry,
	input [1:0] dump_bank,

	output [MSB:0] out
	);

	(* RAM_STYLE = `HC_S_RAM_STYLE, ramstyle = `HC_S_RAMSTYLE *) reg [MSB:0] S0 [255:0];
	(* RAM_STYLE = `HC_S_RAM_STYLE, ramstyle = `HC_S_RAMSTYLE *) reg [MSB:0] S1 [255:0];
	(* RAM_STYLE = `HC_S_RAM_STYLE, ramstyle = `HC_S_RAMSTYLE *) reg [MSB:0] S2 [255:0];
	(* RAM_STYLE = `HC_S_RAM_STYLE, ramstyle = `HC_S_RAMSTYLE *) reg [MSB:0] S3 [255:0];

	reg [MSB:0] S0_out = 0, S1_out = 0, S2_out = 0, S3_out = 0;

`ifdef HC_S_READ_FLAG
	// Upstream resets the read register itself, which a Xilinx block RAM does on its own output
	// latch. An M20K has no synchronous clear there, and Quartus then builds each bank from 8192 flops
	// and a 256:1 mux. So under HC_S_READ_FLAG the register only loads, and the reset is a flag beside
	// it, set exactly when upstream's register would hold zero, that masks what it holds. 'out' is the
	// same on every cycle. On Vivado the mask costs LUTs on the round loop, so S.v sets this for
	// Quartus only.
	reg zero = 1;
`endif

	always @(posedge CLK) begin
		// Write channel
		if (wr_en && addr_wr[9:8] == 2'b00)
			S0 [addr_wr[7:0]] <= din;
		if (wr_en && addr_wr[9:8] == 2'b01)
			S1 [addr_wr[7:0]] <= din;
		if (wr_en && addr_wr[9:8] == 2'b10)
			S2 [addr_wr[7:0]] <= din;
		if (wr_en && addr_wr[9:8] == 2'b11)
			S3 [addr_wr[7:0]] <= din;

		// Read channel
`ifdef HC_S_READ_FLAG
		if (rst_rd)
			zero <= 1;
		else if (rd_en)
			zero <= 0;

		if (rd_en) begin
`else
		if (rst_rd) begin
			S0_out <= 0;
			S1_out <= 0;
			S2_out <= 0;
			S3_out <= 0;
		end
		else if (rd_en) begin
`endif
			S0_out <= S0 [ dump_en ? dump_entry : addr_rd[4*ADDR_NBITS-1 : 3*ADDR_NBITS] ];
			S1_out <= S1 [ dump_en ? dump_entry : addr_rd[3*ADDR_NBITS-1 : 2*ADDR_NBITS] ];
			S2_out <= S2 [ dump_en ? dump_entry : addr_rd[2*ADDR_NBITS-1 : ADDR_NBITS] ];
			S3_out <= S3 [ dump_en ? dump_entry : addr_rd[ADDR_NBITS-1 : 0] ];
		end
	end

`ifdef HC_S_READ_FLAG
	wire [MSB:0] mask = {(MSB+1){~zero}};

	wire [MSB:0] S0_q = S0_out & mask;
	wire [MSB:0] S1_q = S1_out & mask;
	wire [MSB:0] S2_q = S2_out & mask;
	wire [MSB:0] S3_q = S3_out & mask;
`else
	wire [MSB:0] S0_q = S0_out;
	wire [MSB:0] S1_q = S1_out;
	wire [MSB:0] S2_q = S2_out;
	wire [MSB:0] S3_q = S3_out;
`endif


	wire [MSB:0] dump_word =
		(dump_bank == 2'd0) ? S0_q :
		(dump_bank == 2'd1) ? S1_q :
		(dump_bank == 2'd2) ? S2_q : S3_q;

	assign out = dump_en ? dump_word : (S3_q + (S2_q ^ (S1_q + S0_q)));


endmodule
