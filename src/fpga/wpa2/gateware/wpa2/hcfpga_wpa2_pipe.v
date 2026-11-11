/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// One PBKDF2-HMAC-SHA1 pipe of wpa2's engine (hcfpga_wpa2_engine.v): an unrolled SHA-1, RPS rounds
// (1 or 2) per stage, closed into a ring, and the state of the PBKDF2 chains that circulate in it.
//
// The ring is R = 80 / RPS + 4 registers long (84, or 44): the feedback stage (FB), the first-word
// stage (PRE), the round stages (hcfpga_wpa2_round.v), the final add (FA) and one more (X). Every
// cycle every token moves one stage on, so the ring holds R tokens, one per chain, and a chain's
// token is back at FB every R cycles. Chain p is the token at X when the position counter is p; chains 2k and 2k+1 are
// candidate slot k, which runs PBKDF2 block 1 (T1) and block 2 (T2) of one candidate side by side.
// SLOTS = R / 2 candidates are in flight.
//
// A chain alternates two compressions of the PBKDF2 loop, both on 20-byte messages:
//
//   inner = SHA1-compress (ipad, U || padding)
//   U     = SHA1-compress (opad, inner || padding),   T ^= U
//
// A token carries the message (the previous U or inner) into PRE, and its phase. The midstate it
// starts from (ipad for an inner compression, opad for an outer one) is read from the MID memory,
// and read again at FA, where it is added to the state after round 79; the chain's T and its count
// of U values are read at X from the ACC memory and written back at FB. A chain starts with an outer
// compression of the candidate's inner (i) (the setup unit's work), which gives U1 = T, and ends
// after U4096: 8191 compressions, 8191 * R cycles a candidate. Both chains of a slot start in
// consecutive cycles and so end in consecutive cycles: T1's end is held, T2's end pushes the slot's
// result (T1, the first 12 bytes of T2, the candidate's id and generation) into the result FIFO.
//
// Taking a candidate (cand_load) loads the pending register; a slot whose two tokens come round
// empty takes it at FB, writing opad and ipad into MID, zero into ACC and the id into IDG as its
// tokens enter. cand_ready says the pipe has a free slot, no pending candidate and room in the FIFO
// for every candidate it holds, so a done chain always has a FIFO entry and never waits.
//
// flush (the engine's, at least R cycles) empties the pipe: every token that reaches FB dies, the
// pending candidate and the FIFO are dropped.
//
// Results: res_avail while the FIFO is not empty; res_rd pops the head, whose entry is on res_data
// two cycles later: { gen, id, slot, T1, T2[159:64] }.

`timescale 1ns / 1ps
module hcfpga_wpa2_pipe #(
  parameter RPS   = 1,
  parameter SLOTS = 42
)(
  input  wire         CLK,
  input  wire         flush,

  input  wire         cand_load,
  output reg          cand_ready = 0,
  input  wire [159:0] cand_ipad,
  input  wire [159:0] cand_opad,
  input  wire [159:0] cand_in1,
  input  wire [159:0] cand_in2,
  input  wire [31:0]  cand_id,
  input  wire [15:0]  cand_gen,

  output wire         res_avail,
  input  wire         res_rd,
  output reg  [309:0] res_data
);

  // Round stages, and the ring.
  localparam S = 80 / RPS;
  localparam R = S + 4;

  localparam PW = 7;             // position bits
  localparam SW = 6;             // slot bits
  localparam FW = 6;             // FIFO address bits; the FIFO holds 64 results

  localparam integer  R1     = R - 1;
  localparam [PW-1:0] R_LAST = R1[PW-1:0];

  localparam [SW:0]   SLOTS_N = SLOTS[SW:0];

  localparam [FW:0] FIFO_DEPTH = 1 << FW;

  localparam INNER = 1'b0, OUTER = 1'b1;

  localparam [31:0] K0 = 32'h5a827999;

  function [31:0] rol1 (input [31:0] x);
    rol1 = { x[30:0], x[31] };
  endfunction

  // The ring has exactly SLOTS * 2 stages; the wrapper's slot count has to agree.
  generate
    if ((SLOTS * 2 != R) || (RPS * S != 80))
    begin : slots_mismatch
      hcfpga_wpa2_pipe_needs_SLOTS_equal_to_R_over_2 error ();
    end
  endgenerate

  // Positions ----------------------------------------------------------------------------------
  //
  // pos_x is the chain at X, the one FB works on this cycle; the others are the chains n stages
  // upstream of X (pos_x + n), where the memories are read ahead of FB, PRE and FA.

  reg [PW-1:0] pos_x = 0;
  reg [PW-1:0] pos_1 = 1;
  reg [PW-1:0] pos_2 = 2;
  reg [PW-1:0] pos_4 = 4;

  function [PW-1:0] next_pos (input [PW-1:0] p);
    next_pos = (p == R_LAST) ? {PW{1'b0}} : p + 1'b1;
  endfunction

  always @(posedge CLK)
  begin
    pos_x <= next_pos (pos_x);
    pos_1 <= next_pos (pos_1);
    pos_2 <= next_pos (pos_2);
    pos_4 <= next_pos (pos_4);
  end

  wire [SW-1:0] slot_x = pos_x[PW-1:1];
  wire          odd_x  = pos_x[0];

  reg  flush_q = 1;

  always @(posedge CLK) flush_q <= flush;

  // Stage registers ----------------------------------------------------------------------------

  // FB: the token entering the ring. inj marks a chain's first token, whose midstate is mid, not
  // MID's.
  reg         fb_v = 0;
  reg         fb_ph = 0;
  reg         fb_inj = 0;
  reg [159:0] fb_msg;
  reg [159:0] fb_mid;

  // Round stages: tags { v, ph } and state, n the input of stage n (rounds RPS * n ..), S the
  // state after round 79.
  wire [1:0]   s_tag [0:S];
  wire [31:0]  s_a   [0:S];
  wire [31:0]  s_b   [0:S];
  wire [31:0]  s_c   [0:S];
  wire [31:0]  s_d   [0:S];
  wire [31:0]  s_h   [0:S];
  wire [511:0] s_w   [0:S];

  // FA and X.
  reg         fa_v = 0;
  reg         fa_ph = 0;
  reg [159:0] fa_dig;

  reg         x_v = 0;
  reg         x_ph = 0;
  reg [159:0] x_dig;

  // Memories -----------------------------------------------------------------------------------
  //
  // M20K, read address and data both registered: a read issued in cycle n is valid in n + 2.

  // MID: { slot, phase } -> the midstate, two copies, read for PRE and for FA.
  reg         mid_we = 0;
  reg [SW:0]  mid_wa;
  reg [159:0] mid_wd;

  (* ramstyle = "M20K" *) reg [159:0] mid1 [0:127];
  (* ramstyle = "M20K" *) reg [159:0] mid2 [0:127];

  reg [159:0] mid1_r, mid1_q, mid2_r, mid2_q;

  // MID1 is read in the cycle the chain is at FA, for its next token's phase; MID2 in the cycle
  // it is two stages before the last round stage's output, for its current one.
  wire [SW:0] mid1_ra = { pos_1[PW-1:1], ~fa_ph };
  wire [SW:0] mid2_ra = { pos_4[PW-1:1], s_tag[S-2][0] };

  always @(posedge CLK)
  begin
    if (mid_we == 1'b1)
    begin
      mid1[mid_wa] <= mid_wd;
      mid2[mid_wa] <= mid_wd;
    end

    mid1_r <= mid1[mid1_ra];
    mid1_q <= mid1_r;
    mid2_r <= mid2[mid2_ra];
    mid2_q <= mid2_r;
  end

  // ACC: chain -> { T, count of U values in T }, read two cycles before FB, written at FB.
  reg         acc_we = 0;
  reg [PW-1:0] acc_wa;
  reg [171:0] acc_wd;

  (* ramstyle = "M20K" *) reg [171:0] acc [0:127];

  reg [171:0] acc_r, acc_q;

  always @(posedge CLK)
  begin
    if (acc_we == 1'b1) acc[acc_wa] <= acc_wd;

    acc_r <= acc[pos_2];
    acc_q <= acc_r;
  end

  wire [159:0] acc_t   = acc_q[171:12];
  wire [11:0]  acc_cnt = acc_q[11:0];

  // IDG: slot -> { generation, id }, written when the slot takes its candidate.
  reg         idg_we = 0;
  reg [SW-1:0] idg_wa;
  reg [47:0]  idg_wd;

  (* ramstyle = "MLAB" *) reg [47:0] idg [0:63];

  reg [47:0] idg_r, idg_q;

  always @(posedge CLK)
  begin
    if (idg_we == 1'b1) idg[idg_wa] <= idg_wd;

    idg_r <= idg[pos_2[PW-1:1]];
    idg_q <= idg_r;
  end

  // PRE ----------------------------------------------------------------------------------------
  //
  // The message is W0..W4; round 0's input takes h = e + K0 + W0 and the window W1..W16, where
  // W16 = rol1 (W13 ^ W8 ^ W2 ^ W0) = rol1 (W2 ^ W0).

  wire [159:0] pre_mid = (fb_inj == 1'b1) ? fb_mid : mid1_q;

  reg  [1:0]   pre_tag = 0;
  reg  [31:0]  pre_a, pre_b, pre_c, pre_d, pre_h;
  reg  [31:0]  pre_w1, pre_w2, pre_w3, pre_w4, pre_w16;

  always @(posedge CLK)
  begin
    pre_tag <= { fb_v, fb_ph };
    pre_a   <= pre_mid[159:128];
    pre_b   <= pre_mid[127:96];
    pre_c   <= pre_mid[95:64];
    pre_d   <= pre_mid[63:32];
    pre_h   <= pre_mid[31:0] + K0 + fb_msg[159:128];
    pre_w1  <= fb_msg[127:96];
    pre_w2  <= fb_msg[95:64];
    pre_w3  <= fb_msg[63:32];
    pre_w4  <= fb_msg[31:0];
    pre_w16 <= rol1 (fb_msg[95:64] ^ fb_msg[159:128]);
  end

  // { tag[1] valid, tag[0] phase }
  assign s_tag[0] = pre_tag;
  assign s_a[0]   = pre_a;
  assign s_b[0]   = pre_b;
  assign s_c[0]   = pre_c;
  assign s_d[0]   = pre_d;
  assign s_h[0]   = pre_h;
  assign s_w[0]   = { pre_w16, 32'h000002a0, {9{32'd0}}, 32'h80000000, pre_w4, pre_w3, pre_w2, pre_w1 };

  // Rounds -------------------------------------------------------------------------------------

  genvar n;

  generate
    for (n = 0; n < S; n = n + 1)
    begin : rounds
      hcfpga_wpa2_round #(.T(RPS * n), .N(RPS), .TW(2)) rnd (
        .CLK(CLK),
        .tag_i(s_tag[n]),   .a_i(s_a[n]),   .b_i(s_b[n]),   .c_i(s_c[n]),   .d_i(s_d[n]),   .h_i(s_h[n]),   .w_i(s_w[n]),
        .tag_o(s_tag[n+1]), .a_o(s_a[n+1]), .b_o(s_b[n+1]), .c_o(s_c[n+1]), .d_o(s_d[n+1]), .h_o(s_h[n+1]), .w_o(s_w[n+1])
      );
    end
  endgenerate

  // FA, X --------------------------------------------------------------------------------------

  always @(posedge CLK)
  begin
    fa_v   <= s_tag[S][1];
    fa_ph  <= s_tag[S][0];
    fa_dig <= { mid2_q[159:128] + s_a[S], mid2_q[127:96] + s_b[S], mid2_q[95:64] + s_c[S],
                mid2_q[63:32]   + s_d[S], mid2_q[31:0]   + s_h[S] };

    x_v   <= fa_v;
    x_ph  <= fa_ph;
    x_dig <= fa_dig;
  end

  // Pending candidate --------------------------------------------------------------------------

  reg         pend_v = 0;
  reg [159:0] pend_ipad, pend_opad, pend_in1, pend_in2;
  reg [31:0]  pend_id;
  reg [15:0]  pend_gen;

  // The second chain of a slot being started is at X.
  reg         inj2 = 0;

  // Slots running, and candidates held (pending, running or in the FIFO).
  reg [SW:0]  busy = 0;
  reg [FW:0]  held = 0;

  // FB -----------------------------------------------------------------------------------------

  wire [159:0] t_new = acc_t ^ x_dig;
  wire         last  = (acc_cnt == 12'd4095);

  // A slot's T1 at its end, until T2 ends a cycle later.
  reg  [159:0] t1_end;

  reg          push = 0;
  reg  [309:0] push_d;

  wire inject1 = (flush_q == 1'b0) & (pend_v == 1'b1) & (odd_x == 1'b0) & (x_v == 1'b0) & (fa_v == 1'b0) & (inj2 == 1'b0);
  wire inject2 = (flush_q == 1'b0) & (inj2 == 1'b1);

  wire done_x  = (flush_q == 1'b0) & (x_v == 1'b1) & (x_ph == OUTER) & last;

  wire res_pop;

  always @(posedge CLK)
  begin
    acc_we <= 0;
    mid_we <= 0;
    idg_we <= 0;
    push   <= 0;
    fb_inj <= 0;

    acc_wa <= pos_x;

    if (flush_q == 1'b1)
      fb_v <= 1'b0;
    else if (inject1 == 1'b1)
    begin
      fb_v   <= 1'b1;
      fb_ph  <= OUTER;
      fb_inj <= 1'b1;
      fb_msg <= pend_in1;
      fb_mid <= pend_opad;

      acc_we <= 1'b1;
      acc_wd <= 0;

      mid_we <= 1'b1;
      mid_wa <= { slot_x, OUTER };
      mid_wd <= pend_opad;

      idg_we <= 1'b1;
      idg_wa <= slot_x;
      idg_wd <= { pend_gen, pend_id };
    end
    else if (inject2 == 1'b1)
    begin
      fb_v   <= 1'b1;
      fb_ph  <= OUTER;
      fb_inj <= 1'b1;
      fb_msg <= pend_in2;
      fb_mid <= pend_opad;

      acc_we <= 1'b1;
      acc_wd <= 0;

      mid_we <= 1'b1;
      mid_wa <= { slot_x, INNER };
      mid_wd <= pend_ipad;
    end
    else if (x_v == 1'b0)
      fb_v <= 1'b0;
    else if (x_ph == INNER)
    begin
      fb_v   <= 1'b1;
      fb_ph  <= OUTER;
      fb_msg <= x_dig;
    end
    else if (last == 1'b1)
    begin
      fb_v <= 1'b0;

      if (odd_x == 1'b0)
        t1_end <= t_new;
      else
      begin
        push   <= 1'b1;
        push_d <= { idg_q, slot_x, t1_end, t_new[159:64] };
      end
    end
    else
    begin
      fb_v   <= 1'b1;
      fb_ph  <= INNER;
      fb_msg <= x_dig;

      acc_we <= 1'b1;
      acc_wd <= { t_new, acc_cnt + 1'b1 };
    end
  end

  // Candidate intake and accounting ------------------------------------------------------------

  always @(posedge CLK)
  begin
    if (flush_q == 1'b1)
    begin
      pend_v <= 0;
      inj2   <= 0;
      busy   <= 0;
      held   <= 0;
    end
    else
    begin
      if (cand_load == 1'b1)
      begin
        pend_v    <= 1'b1;
        pend_ipad <= cand_ipad;
        pend_opad <= cand_opad;
        pend_in1  <= cand_in1;
        pend_in2  <= cand_in2;
        pend_id   <= cand_id;
        pend_gen  <= cand_gen;
      end
      else if (inject2 == 1'b1)
        pend_v <= 1'b0;

      inj2 <= inject1;

      busy <= busy + {{SW{1'b0}}, inject1} - {{SW{1'b0}}, done_x & odd_x};
      held <= held + {{FW{1'b0}}, cand_load} - {{FW{1'b0}}, res_pop};
    end

    // Written when nothing changes for a cycle after a load: the engine sends a candidate at most
    // every setup (well over the two cycles this takes to follow a load).
    cand_ready <= (flush_q == 1'b0) & (pend_v == 1'b0) & (cand_load == 1'b0) & (busy < SLOTS_N) & (held < FIFO_DEPTH);
  end

  // Result FIFO --------------------------------------------------------------------------------

  (* ramstyle = "M20K" *) reg [309:0] fifo [0:(1 << FW) - 1];

  reg [FW:0] wr_ptr = 0;
  reg [FW:0] rd_ptr = 0;

  reg [309:0] fifo_r;

  assign res_pop   = (res_rd == 1'b1) & (flush_q == 1'b0);
  assign res_avail = (wr_ptr != rd_ptr) & (flush_q == 1'b0);

  always @(posedge CLK)
  begin
    if (push == 1'b1) fifo[wr_ptr[FW-1:0]] <= push_d;

    fifo_r   <= fifo[rd_ptr[FW-1:0]];
    res_data <= fifo_r;

    if (flush_q == 1'b1)
    begin
      wr_ptr <= 0;
      rd_ptr <= 0;
    end
    else
    begin
      if (push == 1'b1)    wr_ptr <= wr_ptr + 1'b1;
      if (res_pop == 1'b1) rd_ptr <= rd_ptr + 1'b1;
    end
  end

endmodule
