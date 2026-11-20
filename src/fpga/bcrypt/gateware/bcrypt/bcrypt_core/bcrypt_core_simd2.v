`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Derived for hashcat from John the Ripper's bcrypt core files named below. The lockstep group, the
// C-slowing and the changes described here are hashcat's. src/fpga/bcrypt/PROVENANCE.md lists every
// change.

//
// bcrypt_simd2_group: bcrypt_simd_group C-slowed by two, as bcrypt_core_c2 C-slows bcrypt_core.
//
// Two contexts take turns cycle by cycle, each a lockstep group of LANES hashes with its own microcode
// state, so one group is 2 x LANES virtual cores: context 0 on wr_en[LANES-1:0] and the matching
// outputs, context 1 above. Every register is a two stage chain, the _1 stage taking the next value
// and the unsuffixed stage being what the logic reads, and every memory takes the context as its top
// address bit, so each S bank fills a 512 deep M20K and PD and PN are 64 deep. phase names the context
// in the second stage this cycle, and the bus contract is bcrypt_core_c2's: every beat is held for a
// phase 0 cycle then a phase 1 cycle and each context takes it in its own; context 0's outputs are
// captured at the end of its cycle and held, context 1's are live in its own.
//
// What C-slowing buys is a second register inside the round loop, so the core clock runs at about
// twice the rate of a single hash. Here the loop is split as bcrypt_core_c2 splits it, after the first
// adder. Against bcrypt_simd_group:
//
//   PD and PN are read a cycle early, from the address the context will use, and their XOR is
//   registered, so the round loop sees one register where it saw two LUTRAM reads. The early read is
//   why MC[39] stays: PN[0] is still read two cycles after MC[46] writes it, never one.
//
//   The collision is registered in the lane, ORed across the group in the next cycle and registered
//   again, which is the two stage chain of Exception_S_rd with the OR placed between its stages.
//
//   The collision re-read moves from MC[81] to MC[82], as in bcrypt_core_c2, because the S read latch
//   cannot keep one context's word across the other's cycle.
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

`ifndef JMP_go
`define	JMP_go		`JMP_PDAR_eq30_b2
`define	JMP_more_out	`JMP_mode_dump
`endif

`ifndef PNAR_LD_ADDR_P_PLUS1
`define	PNAR_LD_ADDR_P_PLUS1	4'b1011
`endif


module bcrypt_simd2_group #(
	parameter LANES = 4,
	parameter PD_M20K = 1,
	// The last LANES_DIST lanes keep their S banks in distributed RAM and the LANES_ULTRA before
	// them in UltraRAM, see S_bank_simd2. The others use block RAM.
	parameter LANES_ULTRA = 0,
	parameter LANES_DIST = 0,
	parameter IDLE_WAIT = 4096,
	parameter QUIET_WAIT = 32
	)(
	input CLK,
	input rst,
	input phase,
	input phase_next,

	input [31:0] din,
	input [3:0] bwe,
	input start,
	input [2*LANES-1:0] wr_en,

	output [2*LANES-1:0] init_ready,
	output [2*LANES-1:0] crypt_ready,

	input [2*LANES-1:0] rd_en,
	output [2*LANES-1:0] empty,
	output [2*LANES-1:0] dout
	);

	localparam OW = (LANES <= 1) ? 1 : $clog2(LANES);
	localparam IW = $clog2(IDLE_WAIT + 1);
	localparam QW = $clog2(QUIET_WAIT + 1);

	wire [LANES-1:0] wr_x = phase ? wr_en[2*LANES-1:LANES] : wr_en[LANES-1:0];
	wire [LANES-1:0] rd_x = phase ? rd_en[2*LANES-1:LANES] : rd_en[LANES-1:0];

	//
	// Input.
	//
	wire gsel = |wr_x;

	reg start_r1 = 0, start_r = 0;
	reg wr_b3_1 = 0, wr_b3 = 0, wr_b2_1 = 0, wr_b2 = 0, sb1 = 0, sb = 0;
	reg [LANES-1:0] sel_r1 = 0, sel_r = 0;
	reg rd_en_r1 = 0, rd_en_r = 0;

	// The bus carries the whole word on every beat of it, so the word needs no byte enables. A two
	// register delay shows each context the bus of its own cycle.
	reg [31:0] din_1 = 0;
	reg [`SETTING_MAX:0] din_lo = 0;

	always @(posedge CLK) begin
		start_r1 <= (bwe[0] & gsel) ? start : start_r;
		wr_b3_1  <= bwe[3] & gsel;
		wr_b2_1  <= bwe[2] & gsel;
		sb1      <= bwe[0] & gsel & start;
		sel_r1   <= wr_x;
		rd_en_r1 <= |rd_x;
		din_1    <= din;

		start_r <= start_r1;
		wr_b3   <= wr_b3_1;
		wr_b2   <= wr_b2_1;
		sb      <= sb1;
		sel_r   <= sel_r1;
		rd_en_r <= rd_en_r1;
		din_lo  <= din_1[`SETTING_MAX:0];
	end


	//
	// Microcode and control, as fsm_c2.
	//
	reg [`MC_ADDR_MSB:0] IP1 = 0, IP = 0, IP_saved1 = 0, IP_saved = 0;

	wire [`MC_NBITS_TOTAL-1:0] MC_output;
	MC_simd2 MC(
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

	localparam CW = `MC_NBITS_E + 2 + `MC_NBITS_P + `MC_NBITS_LR + `MC_NBITS_S;

	reg [CW-1:0] ctl1 = 0, ctl = 0;

	wire [`MC_NBITS_E-1:0] Extra_Controls;
	wire PS_input_select, decr;
	wire PN_wr_en, PD_wr_en;
	wire [3:0] PNWAR_op, PNAR_op;
	wire [4:0] PDAR_op;
	wire L_input_select, Ltmp_wr_en, LR_zero, L_wr_en, R_wr_en;
	wire S_wr_en, S_rd_en, S_rst;
	wire [2:0] SWAR_op;

	assign { Extra_Controls, decr, PS_input_select,
		PN_wr_en, PD_wr_en, PNWAR_op, PNAR_op, PDAR_op,
		L_input_select, Ltmp_wr_en, LR_zero, L_wr_en, R_wr_en,
		S_wr_en, S_rd_en, S_rst, SWAR_op } = ctl;

	wire [`MC_NBITS_LR-1:0] ctl1_LR = ctl1[`MC_NBITS_S +: `MC_NBITS_LR];
	wire [`MC_NBITS_S-1:0] ctl1_S = ctl1[0 +: `MC_NBITS_S];
	wire [`MC_NBITS_P-1:0] ctl1_P = ctl1[(`MC_NBITS_S + `MC_NBITS_LR) +: `MC_NBITS_P];
	wire [1:0] ctl1_PN_input_select = ctl1[(`MC_NBITS_S + `MC_NBITS_LR + `MC_NBITS_P) +: 2];

	// Every lane's copies of the per lane controls are second stages, loaded from the group's first.
	wire [9:0] lane_ctl_next = rst ? 10'd0 :
		{ ctl1_LR, ctl1_PN_input_select[0], ctl1_P[14], ctl1_S[5:3] };

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
			ctl1 <= 0; ctl <= 0;
			IP1 <= 0; IP <= 0;
			IP_saved1 <= 0; IP_saved <= 0;
		end
		else begin
			ctl1 <= { MC_E, MC_PN_input_select, MC_P, MC_LR, MC_S };
			ctl  <= ctl1;

			IP_saved1 <= (MC_flow == `FLOW_CALL) ? IP : IP_saved;
			IP1       <= IP_next;

			IP_saved <= IP_saved1;
			IP       <= IP1;
		end
	end


	//
	// Counters and flags.
	//
	reg [1:0] MW_count1 = 0, MW_count = 0;
	reg [4:0] output_cnt1 = 0, output_cnt = 0;
	reg init_ready1 = 1, init_ready_r = 1;

	always @(posedge CLK) begin
		MW_count1 <=
			(Extra_Controls == `E_MW_COUNT_RST) ? 2'd0 :
			(Extra_Controls == `E_MW_COUNT_INC) ? (MW_count + 1'b1) : MW_count;
		MW_count <= MW_count1;

		output_cnt1 <=
			(Extra_Controls == `E_RST) ? 5'd0 :
			(Extra_Controls == `E_OUTPUT_DATA) ? (output_cnt + 1'b1) : output_cnt;
		output_cnt <= output_cnt1;

		if (rst) begin
			init_ready1  <= 1;
			init_ready_r <= 1;
		end
		else begin
			init_ready1 <=
				(Extra_Controls == `E_SET_INIT_READY) ? 1'b1 :
				(Extra_Controls == `E_RST_INIT_READY) ? 1'b0 : init_ready_r;
			init_ready_r <= init_ready1;
		end
	end


	//
	// Address registers, with the next values the lanes copy.
	//
	reg [9:0] S_wr_addr1 = 10'b01, S_wr_addr = 10'b01;
	reg [4:0] PN_wr_addr1 = `PN_ADDR_P, PN_wr_addr = `PN_ADDR_P;
	reg [4:0] PN_addr1 = `PN_ADDR_P, PN_addr = `PN_ADDR_P;
	reg [4:0] PD_addr1 = `PD_ADDR_EK, PD_addr = `PD_ADDR_EK;

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
		PNAR_op == `PNAR_LD_ADDR_P_PLUS1 ? `PN_ADDR_P + 1'b1 :
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
		S_wr_addr1  <= S_wr_addr_next;
		PN_wr_addr1 <= PN_wr_addr_next;
		PN_addr1    <= PN_addr_next;
		PD_addr1    <= PD_addr_next;

		S_wr_addr  <= S_wr_addr1;
		PN_wr_addr <= PN_wr_addr1;
		PN_addr    <= PN_addr1;
		PD_addr    <= PD_addr1;
	end

	wire SWAR_eq1022 = S_wr_addr[9:1] == 1022/2;
	wire SWAR_eq1023 = SWAR_eq1022 & S_wr_addr[0];
	wire PNWAR_eq29 = PN_wr_addr == `PN_ADDR_P + 29;
	wire PNWAR_eq15 = PN_wr_addr == `PN_ADDR_P + 15;
	wire PNWAR41_ne8 = PN_wr_addr[4:1] != (`PN_ADDR_P + 16)/2;
	wire PNAR_eq14 = PN_addr == 14;
	wire PNAR_eq29 = PN_addr == `PNAR_LD_ADDR_MW + 5;


	//
	// Cost counter.
	//
	reg [`SETTING_MAX:0] iter_load1 = 0, iter_load = 0;
	reg [`SETTING_MAX:0] iter_cnt1 = 0, iter_cnt = 0;
	reg ZF1 = 0, ZF = 0;

	always @(posedge CLK) begin
		iter_cnt1 <=
			(PN_wr_en & decr) ? iter_cnt - 1'b1 :
			(PN_wr_en & (PN_wr_addr == `PN_ADDR_ITER_CURR)) ? ((PD_addr == `PD_ADDR_ITER) ? iter_load : 64) :
			iter_cnt;

		ZF1 <= (Extra_Controls == `E_WR_ZF) ? ((iter_cnt - 1'b1) == 0) : ZF;

		iter_cnt <= iter_cnt1;
		ZF <= ZF1;
	end


	//
	// Data load and the start of a group, one per context.
	//
	wire in_load = (IP == 7'd4);

	reg ld_busy1 = 0, ld_busy = 0;
	reg [4:0] ld_ptr1 = 0, ld_ptr = 0;
	reg [LANES-1:0] ld_lane1 = 0, ld_lane = 0;
	reg [LANES-1:0] ld_done1 = 0, ld_done = 0;
	reg [LANES-1:0] cr1 = 0, cr = 0;
	reg closing1 = 0, closing = 0;
	reg [IW-1:0] idle1 = 0, idle = 0;
	reg [QW-1:0] quiet1 = 0, quiet = 0;

	reg [LANES-1:0] active1 = 0, active = 0;
	reg [LANES-1:0] out_done1 = 0, out_done = 0;
	reg [OW-1:0] oc1 = 0, oc = 0;

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

	wire [LANES-1:0] lane1 = 1;

	always @(posedge CLK) begin
		// Loader.
		ld_busy1 <= ld_busy;
		ld_ptr1 <= ld_ptr;
		ld_lane1 <= ld_lane;
		ld_done1 <= ld_done;
		active1 <= active;
		iter_load1 <= iter_load;

		if (rst) begin
			ld_busy1 <= 0;
			ld_done1 <= 0;
			active1 <= 0;
		end
		else if (in_load) begin
			if (go) begin
				active1 <= ld_done;
				ld_done1 <= 0;
			end
			else if (sb) begin
				ld_busy1 <= 1;
				ld_ptr1 <= 0;
				ld_lane1 <= sel_r;
			end
			else if (ld_busy & wr_b3) begin
				ld_ptr1 <= ld_ptr + 1'b1;
				if (ld_ptr == `PD_ADDR_ITER)
					iter_load1 <= din_lo;
				if (ld_ptr == 5'd30) begin
					ld_busy1 <= 0;
					ld_done1 <= ld_done | ld_lane;
				end
			end
		end

		// Idle timeout.
		if (rst || !in_load) begin
			closing1 <= 0;
			idle1 <= 0;
			quiet1 <= 0;
		end
		else begin
			idle1 <= (activity || !any_done) ? {IW{1'b0}} :
				(idle != IDLE_WAIT) ? idle + 1'b1 : idle;

			closing1 <= closing | (idle == IDLE_WAIT);

			quiet1 <= activity ? {QW{1'b0}} :
				(closing && (quiet != QUIET_WAIT)) ? quiet + 1'b1 : quiet;
		end

		// crypt_ready. A context that starts drops every lane's crypt_ready in the same step. MC[5]
		// does it a step later, after closing has let go of crypt_ready, which showed the lanes a
		// part loaded context started without as ready for that step: the feed could send one of
		// them a candidate that the running context then never loads.
		if (rst || (Extra_Controls == `E_RST) || (Extra_Controls == `E_RST_CRYPT_READY) || (in_load & go))
			cr1 <= 0;
		else if (Extra_Controls == `E_SET_CRYPT_READY)
			cr1 <= {LANES{1'b1}};
		else if (sb)
			cr1 <= cr & ~sel_r;
		else
			cr1 <= cr;

		// Output order.
		out_done1 <= out_done;
		oc1 <= oc;

		if (rst) begin
			out_done1 <= 0;
			oc1 <= 0;
		end
		else if (in_load & go) begin
			out_done1 <= 0;
			oc1 <= first1(ld_done);
		end
		else begin
			if (Extra_Controls == `E_SET_EMPTY)
				out_done1 <= out_done | (lane1 << oc);
			if ((IP == 7'd77) && (pend != 0))
				oc1 <= first1(pend);
		end

		ld_busy <= ld_busy1;
		ld_ptr <= ld_ptr1;
		ld_lane <= ld_lane1;
		ld_done <= ld_done1;
		cr <= cr1;
		closing <= closing1;
		idle <= idle1;
		quiet <= quiet1;
		active <= active1;
		out_done <= out_done1;
		oc <= oc1;
		iter_load <= iter_load1;
	end


	//
	// Output, one lane at a time.
	//
	reg [LANES-1:0] emp1 = {LANES{1'b1}}, emp = {LANES{1'b1}};

	always @(posedge CLK) begin
		if (rst)
			emp1 <= {LANES{1'b1}};
		else if (Extra_Controls == `E_SET_EMPTY)
			emp1 <= emp | (lane1 << oc);
		else if (Extra_Controls == `E_RST_EMPTY)
			emp1 <= emp & ~(lane1 << oc);
		else
			emp1 <= emp;

		emp <= emp1;
	end

	wire [LANES-1:0] obit;

	reg e_hdr1_1 = 0, e_hdr1 = 0, e_dat1_1 = 0, e_dat1 = 0, dout_g1 = 0, dout_g = 0;
	reg [LANES-1:0] oc_hot1 = 0, oc_hot = 0;

	always @(posedge CLK) begin
		e_hdr1_1 <= Extra_Controls == `E_OUTPUT_HEADER;
		e_dat1_1 <= Extra_Controls == `E_OUTPUT_DATA;
		dout_g1  <= e_hdr1 | (e_dat1 & obit[oc]);
		oc_hot1  <= lane1 << oc;

		e_hdr1 <= e_hdr1_1;
		e_dat1 <= e_dat1_1;
		dout_g <= dout_g1;
		oc_hot <= oc_hot1;
	end


	//
	// The outputs: context 0's held from the end of its cycle, context 1's live in its own.
	//
	wire [LANES-1:0] cr_out = cr & {LANES{~closing}};
	wire [LANES-1:0] dout_out = {LANES{dout_g}} & oc_hot;

	reg init_ready_0 = 1;
	reg [LANES-1:0] crypt_ready_0 = 0, empty_0 = {LANES{1'b1}}, dout_0 = 0;

	always @(posedge CLK)
		if (phase == 1'b0) begin
			init_ready_0  <= init_ready_r;
			crypt_ready_0 <= cr_out;
			empty_0       <= emp;
			dout_0        <= dout_out;
		end

	assign init_ready  = { {LANES{init_ready_r}}, {LANES{init_ready_0}} };
	assign crypt_ready = { cr_out, crypt_ready_0 };
	assign empty       = { emp, empty_0 };
	assign dout        = { dout_out, dout_0 };


	//
	// Collision: registered in each lane, ORed here, and registered again as the second stage.
	//
	wire [LANES-1:0] coll_1;
	wire exc_any = |coll_1;

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


	// The PD write enable and address of the next cycle, from the first stages of the registers that
	// make them, for each lane to register its own copy as it does its controls: ld_ptr alone would
	// otherwise drive the write address of every lane's PD.
	wire pd_we_next = ~rst & ld_busy1 & wr_b3_1 & (IP1 == 7'd4);

	genvar i;
	generate
	for (i = 0; i < LANES; i = i + 1) begin : lane
		localparam LANE_S_STYLE = (i >= LANES - LANES_DIST) ? "distributed" :
		                          (i >= LANES - LANES_DIST - LANES_ULTRA) ? "ultra" : "block";

		bcrypt_simd2_lane #(.PD_M20K(PD_M20K), .S_STYLE(LANE_S_STYLE)) l (
			.CLK(CLK), .phase_next(phase_next),
			.din_1(din_1),
			.ctl_next(lane_ctl_next),
			.PN_addr_next(PN_addr_next), .PD_addr_next(PD_addr_next),
			.PN_wr_addr_1(PN_wr_addr1), .S_wr_addr_1(S_wr_addr1),
			.pd_we_next(pd_we_next & ld_lane1[i]), .pd_wa_next(ld_ptr1),
			.act(active[i]),
			.exc_next(exc_any),
			.output_cnt(output_cnt),
			.coll_1(coll_1[i]), .obit(obit[i])
		);
	end
	endgenerate

endmodule


//
// One lane, C-slowed. The read address of PD, PN and the S banks and the write address of every
// memory take the context as the top bit.
//
module bcrypt_simd2_lane #(
	// 1 keeps PD in block RAM, 0 in LUTRAM. Block RAM saves about 40 ALMs a lane for one M20K.
	parameter PD_M20K = 1,
	// The S banks' storage, see S_bank_simd2.
	parameter S_STYLE = "block"
	)(
	input CLK,
	input phase_next,

	input [31:0] din_1,

	input [9:0] ctl_next,
	input [4:0] PN_addr_next,
	input [4:0] PD_addr_next,
	input [4:0] PN_wr_addr_1,
	input [9:0] S_wr_addr_1,

	input pd_we_next,
	input [4:0] pd_wa_next,

	input act,
	input exc_next,
	input [4:0] output_cnt,

	output reg coll_1 = 0,
	output reg obit = 0
	);

	`HC_KEEP reg phase = 0;
	`HC_KEEP reg L_input_select = 0, Ltmp_wr_en = 0, LR_zero = 0, L_wr_en = 0, R_wr_en = 0;
	`HC_KEEP reg PS_input_select = 0, PN_wr_en = 0;
	`HC_KEEP reg S_wr_en = 0, S_rd_en = 0, S_rst = 0;
	`HC_KEEP reg [4:0] pn_a1 = `PN_ADDR_P, PN_wr_addr = `PN_ADDR_P;
	`HC_KEEP reg [9:0] S_wr_addr = 10'b01;
	`HC_KEEP reg exc = 0;
	`HC_KEEP reg pd_we = 0;
	`HC_KEEP reg [4:0] pd_wa = 0;
	reg exc_r1 = 0, exc_r = 0;

	reg [31:0] din_r;

	always @(posedge CLK) begin
		phase <= phase_next;
		pd_we <= pd_we_next;
		pd_wa <= pd_wa_next;
		{ L_input_select, Ltmp_wr_en, LR_zero, L_wr_en, R_wr_en,
		  PS_input_select, PN_wr_en, S_wr_en, S_rd_en, S_rst } <= ctl_next;
		pn_a1      <= PN_addr_next;
		PN_wr_addr <= PN_wr_addr_1;
		S_wr_addr  <= S_wr_addr_1;
		din_r      <= din_1;

		exc    <= exc_next;
		exc_r1 <= exc;
		exc_r  <= exc_r1;
	end


	//
	// PD and PN, 64 deep, read a cycle early: the context in the second stage this cycle is the one
	// the next cycle serves only one cycle later, so each read takes the address of the context about
	// to run.
	//
	// PD is written only while the group waits for its loads, when nothing uses what it reads. As a
	// block RAM (PD_M20K) its read goes through the block's address register, loaded at the end of a
	// context's cycle with the address of that context's next one; as a LUTRAM it reads from a copy
	// of that address. PN is a LUTRAM.
	//
	wire [31:0] pd_rd;

	generate
	if (PD_M20K) begin : pd_block

`ifdef ALTERA_RESERVED_QIS
		(* RAM_STYLE="block", ramstyle = "M20K, no_rw_check" *)
`else
		(* RAM_STYLE="block" *)
`endif
		reg [31:0] PD [63:0];

		initial begin
			PD[31] = 0;
			PD[63] = 0;
		end

		reg [31:0] pd_q;

		always @(posedge CLK) begin
			if (pd_we)
				PD[{phase, pd_wa}] <= din_r;
			pd_q <= PD[{phase, PD_addr_next}];
		end

		assign pd_rd = pd_q;

	end
	else begin : pd_lut

`ifdef ALTERA_RESERVED_QIS
		(* RAM_STYLE="DISTRIBUTED", ramstyle = "MLAB, no_rw_check" *)
`else
		(* RAM_STYLE="DISTRIBUTED" *)
`endif
		reg [31:0] PD [63:0];

		initial begin
			PD[31] = 0;
			PD[63] = 0;
		end

		`HC_KEEP reg [4:0] pd_a = `PD_ADDR_EK;

		always @(posedge CLK) begin
			if (pd_we)
				PD[{phase, pd_wa}] <= din_r;
			pd_a <= PD_addr_next;
		end

		assign pd_rd = PD[{~phase, pd_a}];

	end
	endgenerate

`ifdef ALTERA_RESERVED_QIS
	(* RAM_STYLE="DISTRIBUTED", ramstyle = "MLAB, no_rw_check" *)
`else
	(* RAM_STYLE="DISTRIBUTED" *)
`endif
	reg [31:0] PN [63:0];

	initial begin
		PN[30] = 0;
		PN[31] = 0;
		PN[62] = 0;
		PN[63] = 0;
	end

	reg [31:0] L1, L, R1, R, Ltmp1, Ltmp;

	wire [31:0] PN_input = PS_input_select ? Ltmp : din_r;

	always @(posedge CLK)
		if (PN_wr_en)
			PN[{phase, PN_wr_addr}] <= PN_input;

	reg [31:0] PDPN;

	always @(posedge CLK)
		PDPN <= pd_rd ^ PN[{~phase, pn_a1}];


	//
	// S.
	//
	wire [31:0] S_dout;
	wire [31:0] L_in;

	S_simd2 #(.S_STYLE(S_STYLE)) S(
		.CLK(CLK), .phase(phase),
		.din(PN_input),
		.addr_wr(S_wr_addr), .wr_en(S_wr_en),
		.addr_rd(L_in), .out(S_dout), .rd_en(S_rd_en), .rst_rd(S_rst)
	);


	//
	// L, R, Ltmp.
	//
	assign L_in = (L_input_select ? L : R ^ S_dout) ^ PDPN;

	wire LR_wr_ok = ~exc & ~exc_r;

	always @(posedge CLK) begin
		Ltmp1 <= Ltmp_wr_en ? L_in : Ltmp;
		L1 <= LR_zero ? 32'd0 : (L_wr_en & LR_wr_ok) ? L_in : L;
		R1 <= LR_zero ? 32'd0 : (R_wr_en & LR_wr_ok) ? L : R;

		Ltmp <= Ltmp1;
		L    <= L1;
		R    <= R1;
	end

	// PD is at its zero word wherever S_RW is used, so L ^ PDPN is L ^ PN as the detector wants it.
	wire coll;

	S_rd_collision_detector S_rd_collision_detector(
		.din(L ^ PDPN), .S_wr_addr(S_wr_addr),
		.en(S_rd_en & S_wr_en & act), .dout(coll)
	);

	reg obit1 = 0;

	always @(posedge CLK) begin
		coll_1 <= coll;
		obit1 <= Ltmp[output_cnt];
		obit <= obit1;
	end


`ifdef HC_SIM_CHECKS
	// PN and PD are read one cycle before their use, so a word written in one step and used in the
	// next would be read in the cycle after its write, which a LUTRAM does not promise.
	reg pn_w1 = 0, pd_w1 = 0, pn_haz = 0, pd_haz = 0;
	reg [4:0] pd_a1 = 0;
	reg [5:0] pn_wa1 = 0, pd_wa1 = 0;
	always @(posedge CLK) begin
		pd_a1  <= PD_addr_next;
		pn_w1  <= PN_wr_en;
		pn_wa1 <= {phase, PN_wr_addr};
		pd_w1  <= pd_we;
		pd_wa1 <= {phase, pd_wa};
		pn_haz <= pn_w1 && (pn_wa1 == {~phase, pn_a1});
		pd_haz <= pd_w1 && (pd_wa1 == {~phase, pd_a1});
		if ((pn_haz || pd_haz) && (L_wr_en || Ltmp_wr_en || S_rd_en)) begin
			$display("[simd2] %s read in the cycle after its write and used: LUTRAM hazard", pn_haz ? "PN" : "PD");
			$finish;
		end
	end
`endif

endmodule


//
// The four S banks of both contexts, as S_c2, without power up values on the data registers so the
// retimer may move them.
//
module S_simd2 #(
	parameter S_STYLE = "block"
	)(
	input CLK,
	input phase,
	input [31:0] din,
	input wr_en,
	input [9:0] addr_wr,

	input rd_en,
	input rst_rd,
	input [31:0] addr_rd,

	output [31:0] out
	);

	wire [31:0] S0_l, S1_l, S2_l, S3_l;
	reg [31:0] U_q, S2_q, S3_q;

	S_bank_simd2 #(.S_STYLE(S_STYLE)) S0 (.CLK(CLK),
		.wr_en(wr_en && addr_wr[9:8] == 2'b00), .addr_wr({phase, addr_wr[7:0]}), .din(din),
		.rd_en(rd_en), .addr_rd({phase, addr_rd[31:24]}), .dout(S0_l) );

	S_bank_simd2 #(.S_STYLE(S_STYLE)) S1 (.CLK(CLK),
		.wr_en(wr_en && addr_wr[9:8] == 2'b01), .addr_wr({phase, addr_wr[7:0]}), .din(din),
		.rd_en(rd_en), .addr_rd({phase, addr_rd[23:16]}), .dout(S1_l) );

	S_bank_simd2 #(.S_STYLE(S_STYLE)) S2 (.CLK(CLK),
		.wr_en(wr_en && addr_wr[9:8] == 2'b10), .addr_wr({phase, addr_wr[7:0]}), .din(din),
		.rd_en(rd_en), .addr_rd({phase, addr_rd[15:8]}), .dout(S2_l) );

	S_bank_simd2 #(.S_STYLE(S_STYLE)) S3 (.CLK(CLK),
		.wr_en(wr_en && addr_wr[9:8] == 2'b11), .addr_wr({phase, addr_wr[7:0]}), .din(din),
		.rd_en(rd_en), .addr_rd({phase, addr_rd[7:0]}), .dout(S3_l) );

	reg z1 = 1, z = 1;

	always @(posedge CLK) begin
		z1 <= rst_rd ? 1'b1 : (rd_en ? 1'b0 : z);
		z  <= z1;

		if (z1) begin
			U_q  <= 0;
			S2_q <= 0;
			S3_q <= 0;
		end
		else begin
			U_q  <= S1_l + S0_l;
			S2_q <= S2_l;
			S3_q <= S3_l;
		end
	end

	assign out = S3_q + (S2_q ^ U_q);

endmodule


//
// One S bank of both contexts, 512 x 32, and its read latch, as S_bank_c2 but without a power up value
// on the latch. S_STYLE is "block", "ultra" or "distributed": block RAM, UltraRAM or LUTRAM. A synthesis
// attribute takes a literal, so each style is its own branch around the same write and latched read.
// An UltraRAM bank leaves most of the block empty, it is there for its two ports. UltraRAM is
// Vivado's, Quartus builds that branch from M20K.
//
module S_bank_simd2 #(
	parameter S_STYLE = "block"
	)(
	input CLK,
	input wr_en,
	input [8:0] addr_wr,
	input [31:0] din,
	input rd_en,
	input [8:0] addr_rd,
	output reg [31:0] dout
	);

	generate
	if (S_STYLE == "ultra") begin : ultra

		(* RAM_STYLE = "ultra" *) reg [31:0] S [511:0];

		always @(posedge CLK) begin
			if (wr_en)
				S [addr_wr] <= din;
			if (rd_en)
				dout <= S [addr_rd];
		end

	end
	else if (S_STYLE == "distributed") begin : distributed

`ifdef ALTERA_RESERVED_QIS
		(* RAM_STYLE = "distributed", ramstyle = "MLAB" *)
`else
		(* RAM_STYLE = "distributed" *)
`endif
		reg [31:0] S [511:0];

		always @(posedge CLK) begin
			if (wr_en)
				S [addr_wr] <= din;
			if (rd_en)
				dout <= S [addr_rd];
		end

	end
	else begin : block

`ifdef ALTERA_RESERVED_QIS
		(* RAM_STYLE = "block", ramstyle = "M20K" *)
`else
		(* RAM_STYLE = "block" *)
`endif
		reg [31:0] S [511:0];

		always @(posedge CLK) begin
			if (wr_en)
				S [addr_wr] <= din;
			if (rd_en)
				dout <= S [addr_rd];
		end

	end
	endgenerate

endmodule


// The microcode of fsm.v with bcrypt_core_c2's re-read change and bcrypt_simd_group's changes.
module MC_simd2(
	input [`MC_ADDR_MSB:0] addr,
	output [`MC_NBITS_TOTAL-1:0] out
	);

	wire [`MC_NBITS_TOTAL-1:0] base;

	MC_simd MC(
		.addr(addr), .out(base)
	);

	localparam [`MC_NBITS_TOTAL-1:0] MC81 = { `E_X_, `INPUT_X_,
		`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
		`LR_X_, `S_X_, `SWAR_X_,
		`MC_X_, `JMP_X_, `FLOW_NEXT };

	localparam [`MC_NBITS_TOTAL-1:0] MC82 = { `E_X_, `INPUT_X_,
		`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_P_PLUS1, `PDAR_X_,
		`LR_select_L, `S_RD, `SWAR_X_,
		7'd48, `JMP_UNCONDITIONAL, `FLOW_X_ };

	assign out =
		(addr == 7'd81) ? MC81 :
		(addr == 7'd82) ? MC82 :
		base;

endmodule
