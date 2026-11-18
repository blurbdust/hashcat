`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Derived for hashcat from John the Ripper's bcrypt core files named below. The lockstep group and
// the changes described here are hashcat's. src/fpga/bcrypt/PROVENANCE.md lists every change.

//
// bcrypt_simd_group: LANES bcrypt hashes in lockstep under one controller.
//
// Every hash in a batch has the same salt and cost, so every core in the original array runs the
// same microcode with the same branches. The one exception is the S read collision of fsm.v MC[51],
// which is data dependent. So one fsm, one microcode ROM and one set of address registers drive a
// group of lanes here, and each lane keeps only what differs per hash: L, R, Ltmp, the four S-boxes,
// PD and PN. In the original that control is about 150 of a core's 380 ALMs.
//
// What changes against bcrypt_core:
//
//   Collision. Any lane's collision raises the exception for the whole group. A lane that did not
//   collide repeats its round 0 read and gets the same word, so the repeat is harmless.
//
//   Data load. The init broadcast reaches every lane at once, as before. The 31 data words reach one
//   lane at a time, so the PD write is per lane, steered by the one bus word pointer ld_ptr: one group
//   never spans two feed engines, so at most one of its lanes loads at a time. The group starts when
//   every lane has its data, or, when some have it and none has been loaded for IDLE_WAIT cycles, it
//   closes: it drops crypt_ready, waits QUIET_WAIT cycles for a load already on its way, and starts
//   with the lanes it has. A lane without data computes nothing anyone reads and returns no result.
//
//   Cost counter. PN[18] counted the iterations per core. Every lane has the same count, so it is one
//   counter here, loaded from the iter_count word of the data loads, and ZF comes from it.
//
//   Output. The lanes leave one at a time over the original handshake: empty, rd_en, then header and
//   digest on that lane's dout. MC[77] loops back to MC[65] until every lane that had data is out.
//
//   PN is a LUTRAM here, where Quartus made the original's an M20K with pass-through logic. A LUTRAM
//   cannot promise what it returns for an address in the cycle after that address was written, and
//   the original reads PN[0] in exactly that cycle in one place: MC[46], the last P write of a pair,
//   then MC[42], round 0 of the next encryption. MC[39] is an idle step between the two. It costs one
//   cycle per P pair, 512 per hash at cost 5, out of about 618K.
//
// The S state dump is not carried.
//

`include "bcrypt.vh"

// A register copy that synthesis must keep apart from its twins, which have the same input and
// would otherwise be merged back into one register driving every load. Quartus reads preserve for
// this and Vivado reads keep.
`ifndef HC_KEEP
`ifdef ALTERA_RESERVED_QIS
`define HC_KEEP (* preserve *)
`else
`define HC_KEEP (* keep = "true" *)
`endif
`endif

// Condition slots that mean something else in a group: the PD load exit (MC[5] no longer loads) and
// the state dump (not carried).
`ifndef JMP_go
`define	JMP_go		`JMP_PDAR_eq30_b2
`define	JMP_more_out	`JMP_mode_dump
`endif


module bcrypt_simd_group #(
	parameter LANES = 8,
	parameter IDLE_WAIT = 4096,
	parameter QUIET_WAIT = 32
	)(
	input CLK,
	input rst,

	// The feed bus of this group's feed group, and the bits of c_wr_en for these lanes.
	input [31:0] din,
	input [3:0] bwe,
	input start,
	input [LANES-1:0] wr_en,

	output [LANES-1:0] init_ready,
	output [LANES-1:0] crypt_ready,

	input [LANES-1:0] rd_en,
	output [LANES-1:0] empty,
	output [LANES-1:0] dout
	);

	localparam OW = (LANES <= 1) ? 1 : $clog2(LANES);
	localparam IW = $clog2(IDLE_WAIT + 1);
	localparam QW = $clog2(QUIET_WAIT + 1);

	//
	// Input. The bus is shared by the feed group; it is this group's when one of its wr_en bits is set.
	//
	wire gsel = |wr_en;

	reg start_r = 0, wr_b3 = 0, wr_b2 = 0, sb = 0;
	reg [LANES-1:0] sel_r = 0;
	reg [19:0] din_lo = 0;

	always @(posedge CLK) begin
		if (bwe[0] & gsel)
			start_r <= start;
		wr_b3 <= bwe[3] & gsel;
		wr_b2 <= bwe[2] & gsel;
		sb    <= bwe[0] & gsel & start;
		sel_r <= wr_en;

		if (bwe[0]) din_lo[7:0]   <= din[7:0];
		if (bwe[1]) din_lo[15:8]  <= din[15:8];
		if (bwe[2]) din_lo[19:16] <= din[19:16];
	end

	reg rd_en_r = 0;
	always @(posedge CLK)
		rd_en_r <= |rd_en;


	//
	// Microcode and control. As fsm.v, with the group's condition signals.
	//
	reg [`MC_ADDR_MSB:0] IP = 0, IP_saved = 0;

	wire [`MC_NBITS_TOTAL-1:0] MC_output;
	MC_simd MC(
		.addr(IP), .out(MC_output)
	);

	wire [`MC_NBITS_E-1:0] MC_E;
	wire [1:0] MC_PN_input_select;
	wire [`MC_NBITS_P-1:0] MC_P;
	wire [`MC_NBITS_LR-1:0] MC_LR;
	wire [`MC_NBITS_S-1:0] MC_S;
	wire [`MC_ADDR_MSB:0] MC_jump_addr;
	wire [`MC_NBITS_CONDITION-1:0] MC_condition;
	wire [`MC_NBITS_FLOW-1:0] MC_flow;

	assign {
		MC_E, MC_PN_input_select,
		MC_P,
		MC_LR, MC_S,
		MC_jump_addr, MC_condition, MC_flow
	} = MC_output;

	reg [`MC_NBITS_E-1:0] Extra_Controls = `E_X_;
	reg PS_input_select = 0, decr = 0;
	reg PN_wr_en = 0, PD_wr_en = 0;
	reg [3:0] PNWAR_op = `PNWAR_X_;
	reg [3:0] PNAR_op = `PNAR_X_;
	reg [4:0] PDAR_op = `PDAR_X_;
	reg L_input_select = 0, Ltmp_wr_en = 0, L_wr_en = 0, R_wr_en = 0, LR_zero = 0;
	reg S_wr_en = 0, S_rd_en = 0, S_rst = 0;
	reg [2:0] SWAR_op = 0;

	// What every lane registers as its own copy of the per lane controls, in the order lane_ctl
	// unpacks them: L_input_select, Ltmp_wr_en, LR_zero, L_wr_en, R_wr_en, PS_input_select, PN_wr_en,
	// S_wr_en, S_rd_en, S_rst.
	wire [9:0] lane_ctl_next = rst ? 10'd0 :
		{ MC_LR, MC_PN_input_select[0], MC_P[14], MC_S[5:3] };

	reg Exception_S_rd = 0;
	wire [2**`MC_NBITS_CONDITION-1:0] Condition_Signals;

	wire [`MC_ADDR_MSB:0] IP_next =
		(MC_flow == `FLOW_CALL) ? MC_jump_addr :
		(Exception_S_rd) ? 7'd80 :
		(MC_flow == `FLOW_RETURN) ? (IP_saved + 1'b1) :
		(Condition_Signals [MC_condition] == 1'b1) ? MC_jump_addr :
		(MC_flow == `FLOW_NEXT) ? (IP + 1'b1) :
		IP;

	always @(posedge CLK) begin
		if (rst) begin
			Extra_Controls <= 0;
			decr <= 0; PS_input_select <= 0;
			PN_wr_en <= 0; PD_wr_en <= 0; PNWAR_op <= 0; PNAR_op <= 0; PDAR_op <= 0;
			L_input_select <= 0; Ltmp_wr_en <= 0; LR_zero <= 0; L_wr_en <= 0; R_wr_en <= 0;
			S_wr_en <= 0; S_rd_en <= 0; S_rst <= 0; SWAR_op <= 0;
			IP <= 0; IP_saved <= 0;
		end
		else begin
			Extra_Controls <= MC_E;
			{ decr, PS_input_select } <= MC_PN_input_select;
			{ PN_wr_en, PD_wr_en, PNWAR_op, PNAR_op, PDAR_op } <= MC_P;
			{ L_input_select, Ltmp_wr_en, LR_zero, L_wr_en, R_wr_en } <= MC_LR;
			{ S_wr_en, S_rd_en, S_rst, SWAR_op } <= MC_S;

			if (MC_flow == `FLOW_CALL)
				IP_saved <= IP;
			IP <= IP_next;
		end
	end


	//
	// Counters and flags, as bcrypt_core.
	//
	reg [1:0] MW_count = 0;
	always @(posedge CLK)
		if (Extra_Controls == `E_MW_COUNT_RST)
			MW_count <= 0;
		else if (Extra_Controls == `E_MW_COUNT_INC)
			MW_count <= MW_count + 1'b1;

	reg [4:0] output_cnt = 0;
	always @(posedge CLK)
		if (Extra_Controls == `E_RST)
			output_cnt <= 0;
		else if (Extra_Controls == `E_OUTPUT_DATA)
			output_cnt <= output_cnt + 1'b1;

	reg init_ready_r = 1;
	always @(posedge CLK)
		if (rst)
			init_ready_r <= 1;
		else if (Extra_Controls == `E_SET_INIT_READY)
			init_ready_r <= 1;
		else if (Extra_Controls == `E_RST_INIT_READY)
			init_ready_r <= 0;

	assign init_ready = {LANES{init_ready_r}};


	//
	// Address registers, as addr_regs.v, each with its next value exposed for the lane copies.
	//
	reg [9:0] S_wr_addr = 10'b01;
	reg [4:0] PN_wr_addr = `PN_ADDR_P;
	reg [4:0] PN_addr = `PN_ADDR_P;
	reg [4:0] PD_addr = `PD_ADDR_EK;

	wire [1:0] PN_addr_mw10 = `PN_ADDR_MW / 8;
	wire [2:0] PD_addr_salt20 = `PD_ADDR_SALT / 4;

	wire [1:0] swar_c =
		SWAR_op[2:1] == `SWAR_INC_B3/2 ? S_wr_addr[0] + wr_b3 :
		SWAR_op[2:1] == `SWAR_ADD2B1SET/2 ? 2'b11 :
		2'b00;

	wire [9:0] S_wr_addr_next = ~SWAR_op[0] ? S_wr_addr :
		SWAR_op == `SWAR_1 ? 10'b01 :
		{ S_wr_addr[9:1] + swar_c[1], swar_c[0] };

	wire [4:0] PN_wr_addr_next = ~PNWAR_op[0] ? PN_wr_addr :
		PNWAR_op == `PNWAR_LD_ADDR_P ? `PN_ADDR_P :
		PNWAR_op == `PNWAR_LD_ADDR_P_PLUS1 ? `PN_ADDR_P + 1'b1 :
		PNWAR_op == `PNWAR_INC ? PN_wr_addr + 1'b1 :
		PNWAR_op == `PNWAR_INC_B3 ? PN_wr_addr + wr_b3 :
		PNWAR_op == `PNWAR_B0RST ? { PN_wr_addr[4:1], 1'b0 } :
		PNWAR_op == `PNWAR_LD_ADDR_ITER_CURR ? `PN_ADDR_ITER_CURR :
		PNWAR_op == `PNWAR_LD_ADDR_MW1 ? { PN_addr_mw10, MW_count, 1'b1 } :
		{ PN_wr_addr[4:1] + 1'b1, 1'b1 };

	wire [4:0] PN_addr_next = ~PNAR_op[0] ? PN_addr :
		PNAR_op == `PNAR_LD_ADDR_P ? `PN_ADDR_P :
		PNAR_op == `PNAR_LD_ADDR_ZERO ? `PN_ADDR_ZERO :
		PNAR_op == `PNAR_LD_ADDR_ITER_CURR ? `PN_ADDR_ITER_CURR :
		PNAR_op == `PNAR_INC ? PN_addr + 1'b1 :
		{ PN_addr_mw10, MW_count, 1'b0 };

	wire [4:0] PD_addr_next = ~PDAR_op[0] ? PD_addr :
		PDAR_op == `PDAR_LD_ADDR_EK ? `PD_ADDR_EK :
		PDAR_op == `PDAR_LD_ADDR_ITER ? `PD_ADDR_ITER :
		PDAR_op == `PDAR_LD_ADDR_ZERO ? `PD_ADDR_ZERO :
		PDAR_op == `PDAR_LD_ADDR_LR_XOR_SALT0_P ? { PD_addr_salt20, PN_wr_addr[1], 1'b1 } :
		PDAR_op == `PDAR_LD_ADDR_LR_XOR_SALT1_P ? { PD_addr_salt20, PN_wr_addr[1], 1'b0 } :
		PDAR_op == `PDAR_LD_ADDR_LR_XOR_SALT0_S ? { PD_addr_salt20, ~S_wr_addr[1], 1'b1 } :
		PDAR_op == `PDAR_LD_ADDR_LR_XOR_SALT1_S ? { PD_addr_salt20, ~S_wr_addr[1], 1'b0 } :
		PDAR_op == `PDAR_LD_ADDR_SALT ? `PD_ADDR_SALT :
		PDAR_op == `PDAR_LD_ADDR_64 ? `PD_ADDR_64 :
		PDAR_op == `PDAR_INC ? PD_addr + 1'b1 :
		PDAR_op == `PDAR_INC_ADDR_SALT ? { PD_addr_salt20, (PD_addr[1:0] + 1'b1) } :
		PDAR_op == `PDAR_INC_B3 ? PD_addr + wr_b3 :
		`PD_ADDR_IDS;

	always @(posedge CLK) begin
		S_wr_addr  <= S_wr_addr_next;
		PN_wr_addr <= PN_wr_addr_next;
		PN_addr    <= PN_addr_next;
		PD_addr    <= PD_addr_next;
	end

	wire SWAR_eq1022 = S_wr_addr[9:1] == 1022/2;
	wire SWAR_eq1023 = SWAR_eq1022 & S_wr_addr[0];
	wire PNWAR_eq29 = PN_wr_addr == `PN_ADDR_P + 29;
	wire PNWAR_eq15 = PN_wr_addr == `PN_ADDR_P + 15;
	wire PNWAR41_ne8 = PN_wr_addr[4:1] != (`PN_ADDR_P + 16)/2;
	wire PNAR_eq14 = PN_addr == 14;
	wire PNAR_eq29 = PN_addr == `PNAR_LD_ADDR_MW + 5;


	//
	// Cost counter. The data load's iter_count word, or the constant 64, as the microcode saves either
	// into PN[18]; then decremented with ZF as MC[40] does it.
	//
	reg [`SETTING_MAX:0] iter_load = 0;
	reg [`SETTING_MAX:0] iter_cnt = 0;
	reg ZF = 0;

	always @(posedge CLK) begin
		if (PN_wr_en & decr)
			iter_cnt <= iter_cnt - 1'b1;
		else if (PN_wr_en & (PN_wr_addr == `PN_ADDR_ITER_CURR))
			iter_cnt <= (PD_addr == `PD_ADDR_ITER) ? iter_load : 64;

		if (Extra_Controls == `E_WR_ZF)
			ZF <= (iter_cnt - 1'b1) == 0;
	end


	//
	// Data load, lane by lane, and the start of a group.
	//
	wire in_load = (IP == 7'd4);

	reg ld_busy = 0;
	reg [4:0] ld_ptr = 0;
	reg [LANES-1:0] ld_lane = 0;
	reg [LANES-1:0] ld_done = 0;
	reg [LANES-1:0] cr = 0;
	reg closing = 0;
	reg [IW-1:0] idle = 0;
	reg [QW-1:0] quiet = 0;

	reg [LANES-1:0] active = 0;
	reg [LANES-1:0] out_done = 0;
	reg [OW-1:0] oc = 0;

	wire activity = sb | ld_busy;
	wire any_done = |ld_done;
	wire all_done = &ld_done;

	wire go = in_load & ~activity &
		(all_done | (closing & (quiet == QUIET_WAIT) & any_done));

	function [OW-1:0] first1;
		input [LANES-1:0] v;
		integer k;
		begin
			first1 = 0;
			for (k = LANES - 1; k >= 0; k = k - 1)
				if (v[k]) first1 = k;
		end
	endfunction

	wire [LANES-1:0] pend = active & ~out_done;

	always @(posedge CLK) begin
		if (rst) begin
			ld_busy <= 0;
			ld_done <= 0;
			active <= 0;
		end
		else if (in_load) begin
			if (go) begin
				active <= ld_done;
				ld_done <= 0;
			end
			else if (sb) begin
				ld_busy <= 1;
				ld_ptr <= 0;
				ld_lane <= sel_r;
			end
			else if (ld_busy & wr_b3) begin
				ld_ptr <= ld_ptr + 1'b1;
				if (ld_ptr == `PD_ADDR_ITER)
					iter_load <= din_lo;
				if (ld_ptr == 5'd30) begin
					ld_busy <= 0;
					ld_done <= ld_done | ld_lane;
				end
			end
		end

		if (rst || !in_load) begin
			closing <= 0;
			idle <= 0;
			quiet <= 0;
		end
		else begin
			if (activity || !any_done)
				idle <= 0;
			else if (idle != IDLE_WAIT)
				idle <= idle + 1'b1;

			if (idle == IDLE_WAIT)
				closing <= 1;

			if (activity)
				quiet <= 0;
			else if (closing && (quiet != QUIET_WAIT))
				quiet <= quiet + 1'b1;
		end

		// A group that starts drops every lane's crypt_ready in the same cycle. MC[5] does it a cycle
		// later, after closing has let go of crypt_ready, which showed the lanes a part loaded group
		// started without as ready for that cycle: the feed could send one of them a candidate that
		// the running group then never loads.
		if (rst || (Extra_Controls == `E_RST) || (Extra_Controls == `E_RST_CRYPT_READY) || (in_load & go))
			cr <= 0;
		else if (Extra_Controls == `E_SET_CRYPT_READY)
			cr <= {LANES{1'b1}};
		else if (sb)
			cr <= cr & ~sel_r;

		if (rst) begin
			out_done <= 0;
			oc <= 0;
		end
		else if (in_load & go) begin
			out_done <= 0;
			oc <= first1(ld_done);
		end
		else begin
			if (Extra_Controls == `E_SET_EMPTY)
				out_done[oc] <= 1'b1;
			if ((IP == 7'd77) && (pend != 0))
				oc <= first1(pend);
		end
	end

	assign crypt_ready = cr & {LANES{~closing}};


	//
	// Output, one lane at a time.
	//
	reg [LANES-1:0] emp = {LANES{1'b1}};
	always @(posedge CLK)
		if (rst)
			emp <= {LANES{1'b1}};
		else if (Extra_Controls == `E_SET_EMPTY)
			emp[oc] <= 1'b1;
		else if (Extra_Controls == `E_RST_EMPTY)
			emp[oc] <= 1'b0;

	assign empty = emp;

	wire [LANES-1:0] obit;

	wire [LANES-1:0] lane0 = 1;

	reg e_hdr1 = 0, e_dat1 = 0, dout_g = 0;
	reg [LANES-1:0] oc_hot = 0;
	always @(posedge CLK) begin
		e_hdr1 <= Extra_Controls == `E_OUTPUT_HEADER;
		e_dat1 <= Extra_Controls == `E_OUTPUT_DATA;
		dout_g <= e_hdr1 | (e_dat1 & obit[oc]);
		oc_hot <= lane0 << oc;
	end

	assign dout = {LANES{dout_g}} & oc_hot;


	//
	// Collision: any lane with data raises it for all.
	//
	wire [LANES-1:0] coll;
	wire exc_any = S_rd_en & S_wr_en & |(coll & active);

	always @(posedge CLK)
		Exception_S_rd <= exc_any;


	assign Condition_Signals = {
		// 16
		|pend, // #15 JMP_more_out
		rd_en_r,
		output_cnt == 26,
		~PNAR_eq29,
		~MW_count[1],
		~ZF,
		~SWAR_eq1022,
		PNWAR41_ne8,
		// 8
		PNAR_eq14,
		PNWAR_eq15,
		go, // #5 JMP_go
		SWAR_eq1023 & wr_b2,
		PNWAR_eq29 & wr_b2,
		start_r,
		1'b1, 1'b0
	};


	//
	// The lanes.
	//
	genvar i;
	generate
	for (i = 0; i < LANES; i = i + 1) begin : lane
		bcrypt_simd_lane l (
			.CLK(CLK),
			.din(din), .bwe(bwe),
			.ctl_next(lane_ctl_next),
			.PN_addr_next(PN_addr_next), .PN_wr_addr_next(PN_wr_addr_next),
			.PD_addr_next(PD_addr_next), .S_wr_addr_next(S_wr_addr_next),
			.pd_we(ld_busy & wr_b3 & ld_lane[i] & in_load), .pd_wa(ld_ptr),
			.exc_next(exc_any),
			.output_cnt(output_cnt),
			.coll(coll[i]), .obit(obit[i])
		);
	end
	endgenerate

endmodule


//
// One lane: the per hash state of bcrypt_core's unit, P_2x32 and S, driven by the group's controls.
// Every control it uses is its own registered copy, so no group register drives every lane.
//
module bcrypt_simd_lane (
	input CLK,

	input [31:0] din,
	input [3:0] bwe,

	input [9:0] ctl_next,
	input [4:0] PN_addr_next,
	input [4:0] PN_wr_addr_next,
	input [4:0] PD_addr_next,
	input [9:0] S_wr_addr_next,

	input pd_we,
	input [4:0] pd_wa,

	input exc_next,
	input [4:0] output_cnt,

	output coll,
	output reg obit = 0
	);

	`HC_KEEP reg L_input_select = 0, Ltmp_wr_en = 0, LR_zero = 0, L_wr_en = 0, R_wr_en = 0;
	`HC_KEEP reg PS_input_select = 0, PN_wr_en = 0;
	`HC_KEEP reg S_wr_en = 0, S_rd_en = 0, S_rst = 0;
	`HC_KEEP reg [4:0] PN_addr = `PN_ADDR_P, PN_wr_addr = `PN_ADDR_P, PD_addr = `PD_ADDR_EK;
	`HC_KEEP reg [9:0] S_wr_addr = 10'b01;
	`HC_KEEP reg exc = 0, exc_r = 0;

	reg [31:0] din_r;

	always @(posedge CLK) begin
		{ L_input_select, Ltmp_wr_en, LR_zero, L_wr_en, R_wr_en,
		  PS_input_select, PN_wr_en, S_wr_en, S_rd_en, S_rst } <= ctl_next;
		PN_addr    <= PN_addr_next;
		PN_wr_addr <= PN_wr_addr_next;
		PD_addr    <= PD_addr_next;
		S_wr_addr  <= S_wr_addr_next;
		exc   <= exc_next;
		exc_r <= exc;

		if (bwe[0]) din_r[7:0]   <= din[7:0];
		if (bwe[1]) din_r[15:8]  <= din[15:8];
		if (bwe[2]) din_r[23:16] <= din[23:16];
		if (bwe[3]) din_r[31:24] <= din[31:24];
	end


	//
	// PD and PN. PD[31] and PN[30], PN[31] are the zero words and nothing writes them. no_rw_check:
	// PD is written only while the group waits for its loads, and nothing then reads it. PN is never
	// read in the cycle after a write to the same word, see MC[39], and in the cycle of a write it
	// returns the old word, as the original's asynchronous read does.
	//
`ifdef ALTERA_RESERVED_QIS
	(* RAM_STYLE="DISTRIBUTED", ramstyle = "MLAB, no_rw_check" *)
`else
	(* RAM_STYLE="DISTRIBUTED" *)
`endif
	reg [31:0] PD [31:0];

`ifdef ALTERA_RESERVED_QIS
	(* RAM_STYLE="DISTRIBUTED", ramstyle = "MLAB, no_rw_check" *)
`else
	(* RAM_STYLE="DISTRIBUTED" *)
`endif
	reg [31:0] PN [31:0];

	initial begin
		PD[31] = 0;
		PN[30] = 0;
		PN[31] = 0;
	end

	reg [31:0] L, R, Ltmp;

	wire [31:0] PN_input = PS_input_select ? Ltmp : din_r;

	always @(posedge CLK) begin
		if (pd_we)
			PD[pd_wa] <= din_r;
		if (PN_wr_en)
			PN[PN_wr_addr] <= PN_input;
	end

	wire [31:0] PD_out = PD[PD_addr];
	wire [31:0] PN_out = PN[PN_addr];


	//
	// S: the four boxes in block RAM, as the original.
	//
	wire [31:0] S_dout;
	wire [31:0] L_in;

	S #( .MSB(31), .ADDR_NBITS(8), .S_STYLE("block")
	) S(
		.CLK(CLK),
		.din(PN_input),
		.addr_wr(S_wr_addr), .wr_en(S_wr_en),
		.addr_rd(L_in), .out(S_dout), .rd_en(S_rd_en), .rst_rd(S_rst),
		.dump_en(1'b0), .dump_entry(8'd0), .dump_bank(2'd0)
	);


	//
	// L, R, Ltmp, as unit.v.
	//
	assign L_in = (L_input_select ? L : R ^ S_dout) ^ PD_out ^ PN_out;

	always @(posedge CLK) begin
		if (Ltmp_wr_en)
			Ltmp <= L_in;

		if (LR_zero)
			L <= 0;
		else if (L_wr_en & ~exc & ~exc_r)
			L <= L_in;

		if (LR_zero)
			R <= 0;
		else if (R_wr_en & ~exc & ~exc_r)
			R <= L;

		obit <= Ltmp[output_cnt];
	end

	S_rd_collision_detector S_rd_collision_detector(
		.din(L ^ PN_out), .S_wr_addr(S_wr_addr),
		.en(1'b1), .dout(coll)
	);


`ifdef HC_SIM_CHECKS
	// The LUTRAM rule above. A consumer of PN_out in the cycle after a write to the same word would
	// read a word a LUTRAM does not promise.
	reg pn_w1 = 0;
	reg [4:0] pn_wa1 = 0;
	always @(posedge CLK) begin
		pn_w1  <= PN_wr_en;
		pn_wa1 <= PN_wr_addr;
		if (pn_w1 && (pn_wa1 == PN_addr) && (L_wr_en || Ltmp_wr_en || S_rd_en)) begin
			$display("[simd] PN read of a word written the cycle before, at %0d: LUTRAM hazard", PN_addr);
			$finish;
		end
	end
`endif

endmodule


// The microcode of fsm.v with the group's changes, see the top of this file.
module MC_simd(
	input [`MC_ADDR_MSB:0] addr,
	output [`MC_NBITS_TOTAL-1:0] out
	);

	wire [`MC_NBITS_TOTAL-1:0] base;

	MC MC(
		.addr(addr), .out(base)
	);

	// crypt_ready once, then wait for the group to start: MC[3] repeated set it on every cycle.
	localparam [`MC_NBITS_TOTAL-1:0] MC3 = { `E_SET_CRYPT_READY, `INPUT_DIN,
		`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
		`LR_X_, `S_X_, `SWAR_X_,
		`MC_X_, `JMP_X_, `FLOW_NEXT };

	localparam [`MC_NBITS_TOTAL-1:0] MC4 = { `E_X_, `INPUT_DIN,
		`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
		`LR_X_, `S_X_, `SWAR_X_,
		7'd5, `JMP_go, `FLOW_X_ };

	// The loads are done. PD_addr is still PD_ADDR_EK from MC[0] or MC[78].
	localparam [`MC_NBITS_TOTAL-1:0] MC5 = { `E_RST_CRYPT_READY, `INPUT_DIN,
		`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
		`LR_X_, `S_X_, `SWAR_X_,
		`MC_X_, `JMP_X_, `FLOW_NEXT };

	// MC[46] as fsm.v, but back to round 0 through MC[39].
	localparam [`MC_NBITS_TOTAL-1:0] MC46 = { `E_X_, `INPUT_X_,
		`PN_WR, `PNWAR_ADD2B1SET, `PNAR_X_, `PDAR_X_,
		`LR_X_, `S_X_, `SWAR_X_,
		7'd39, `JMP_not_end_wr_P, `FLOW_NEXT };

	localparam [`MC_NBITS_TOTAL-1:0] MC39 = { `E_X_, `INPUT_X_,
		`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
		`LR_X_, `S_X_, `SWAR_X_,
		7'd42, `JMP_UNCONDITIONAL, `FLOW_X_ };

	// No state dump.
	localparam [`MC_NBITS_TOTAL-1:0] MC67 = { `E_X_, `INPUT_X_,
		`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
		`LR_X_, `S_X_, `SWAR_X_,
		`MC_X_, `JMP_X_, `FLOW_NEXT };

	// The next lane out, or the end. E_RST restarts output_cnt, which MC[70] needs at 0 for a lane's
	// first bit, as MC[0] leaves it for the first lane.
	localparam [`MC_NBITS_TOTAL-1:0] MC77 = { `E_RST, `INPUT_X_,
		`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
		`LR_X_, `S_X_, `SWAR_X_,
		7'd65, `JMP_more_out, `FLOW_NEXT };

	localparam [`MC_NBITS_TOTAL-1:0] MC78 = { `E_SET_INIT_READY, `INPUT_X_,
		`P_X_, `PNWAR_LD_ADDR_P, `PNAR_X_, `PDAR_LD_ADDR_EK,
		`LR_X_, `S_X_, `SWAR_X_,
		7'd0, `JMP_UNCONDITIONAL, `FLOW_X_ };

	assign out =
		(addr == 7'd3) ? MC3 :
		(addr == 7'd4) ? MC4 :
		(addr == 7'd5) ? MC5 :
		(addr == 7'd39) ? MC39 :
		(addr == 7'd46) ? MC46 :
		(addr == 7'd67) ? MC67 :
		(addr == 7'd77) ? MC77 :
		(addr == 7'd78) ? MC78 :
		base;

endmodule
