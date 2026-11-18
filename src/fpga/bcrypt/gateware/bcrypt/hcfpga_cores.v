/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps

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

module hcfpga_cores #(
  parameter NUM_CORES = 4,
  parameter DIN_BITS  = 32,

  parameter GROUP     = 0,

  parameter WITH_DUMP = 1,

  parameter NUM_CORES_DIST = 0,

  parameter NUM_CORES_URAM = 0,

  parameter WITH_CMP = 1,

  parameter CSLOW = 1,

  parameter SHARD = 0,

  parameter SIMD = 0,

  parameter SIMD_IDLE = 4096,

  // C-slowed groups only: how many groups, counted from the last, keep PD in LUTRAM rather than
  // block RAM, to balance ALMs against M20Ks.
  parameter SIMD_PD_LUT = 0,

  parameter NSH = (SHARD == 0) ? 1 : ((NUM_CORES + SHARD - 1) / SHARD)
)(
  input  wire CLK,
  input  wire CLK_CORE,
  input  wire rst,

  input  wire mode_dump,

  input  wire [NSH*DIN_BITS-1:0] c_din,
  input  wire [NSH*4-1:0]        c_bwe,
  input  wire [NSH-1:0]          c_start,
  input  wire [NUM_CORES-1:0]    c_wr_en,

  input  wire       bm_we,
  input  wire [6:0] bm_addr,
  input  wire       bm_din,

  output wire [NUM_CORES-1:0] init_ready,
  output wire [NUM_CORES-1:0] crypt_ready,

  input  wire [NUM_CORES-1:0] rd_en,
  output wire [NUM_CORES-1:0] empty,
  output wire [NUM_CORES-1:0] dout
);

  localparam NGROUP = (GROUP == 0) ? 1 : ((NUM_CORES + GROUP - 1) / GROUP);

  localparam NBUS = (GROUP == 0) ? NSH : NGROUP;

  initial
  begin
    if ((SHARD != 0) && (GROUP != 0) && ((SHARD % GROUP) != 0))
    begin
      $display ("hcfpga_cores: FEED_SHARD=%0d is not a multiple of FEED_GROUP=%0d", SHARD, GROUP);
      $fatal;
    end
  end

  wire [DIN_BITS-1:0]  g_din   [0:NBUS-1];
  wire [3:0]           g_bwe   [0:NBUS-1];
  wire                 g_start [0:NBUS-1];
  wire [NUM_CORES-1:0] g_wr_en [0:NBUS-1];

  wire                 g_bm_we   [0:NBUS-1];
  wire [6:0]           g_bm_addr [0:NBUS-1];
  wire                 g_bm_din  [0:NBUS-1];

  genvar g;
  generate
  if (GROUP == 0) begin : nopipe
    for (g = 0; g < NBUS; g = g + 1) begin : grp
      assign g_din[g]   = c_din[DIN_BITS*g +: DIN_BITS];
      assign g_bwe[g]   = c_bwe[4*g +: 4];
      assign g_start[g] = c_start[g];
      assign g_wr_en[g] = c_wr_en;

      assign g_bm_we[g]   = bm_we;
      assign g_bm_addr[g] = bm_addr;
      assign g_bm_din[g]  = bm_din;
    end
  end
  else begin : pipe
    for (g = 0; g < NBUS; g = g + 1) begin : grp
      localparam integer SB = (SHARD == 0) ? 0 : ((g * GROUP) / SHARD);
      (* max_fanout = 32 *) reg [DIN_BITS-1:0]  din_p   = 0;
      (* max_fanout = 32 *) reg [3:0]           bwe_p   = 0;
      (* max_fanout = 32 *) reg                 start_p = 0;
                            reg [NUM_CORES-1:0] wr_en_p = 0;

      (* max_fanout = 32 *) reg                 bm_we_p   = 0;
      (* max_fanout = 32 *) reg [6:0]           bm_addr_p = 0;
      (* max_fanout = 32 *) reg                 bm_din_p  = 0;

      always @(posedge CLK)
      begin
        din_p   <= c_din[DIN_BITS*SB +: DIN_BITS];
        bwe_p   <= c_bwe[4*SB +: 4];
        start_p <= c_start[SB];
        wr_en_p <= c_wr_en;

        bm_we_p   <= bm_we;
        bm_addr_p <= bm_addr;
        bm_din_p  <= bm_din;
      end
      assign g_din[g]   = din_p;
      assign g_bwe[g]   = bwe_p;
      assign g_start[g] = start_p;
      assign g_wr_en[g] = wr_en_p;

      assign g_bm_we[g]   = bm_we_p;
      assign g_bm_addr[g] = bm_addr_p;
      assign g_bm_din[g]  = bm_din_p;
    end
  end
  endgenerate

  initial
  begin
    if ((CSLOW == 2) && (((NUM_CORES % 2) != 0) || ((NUM_CORES_DIST % 2) != 0) || ((NUM_CORES_URAM % 2) != 0) || (WITH_DUMP != 0) || ((GROUP % 2) != 0) || ((SHARD % 2) != 0)))
    begin
      $display ("hcfpga_cores: CSLOW=2 needs an even NUM_CORES, NUM_CORES_DIST, NUM_CORES_URAM, GROUP and SHARD, and no dump");
      $fatal;
    end

    if ((CSLOW != 2) && (NUM_CORES_URAM != 0))
    begin
      $display ("hcfpga_cores: NUM_CORES_URAM needs CSLOW=2");
      $fatal;
    end

    if ((NUM_CORES_DIST + NUM_CORES_URAM) > NUM_CORES)
    begin
      $display ("hcfpga_cores: NUM_CORES_DIST=%0d and NUM_CORES_URAM=%0d add up to more than NUM_CORES=%0d", NUM_CORES_DIST, NUM_CORES_URAM, NUM_CORES);
      $fatal;
    end
  end

  initial
  begin
    if ((SIMD > 1) && ((DIN_BITS != 32) || (NUM_CORES_DIST != 0) || (WITH_DUMP != 0) ||
                       ((GROUP != 0) && ((GROUP % (CSLOW * SIMD)) != 0)) || ((SHARD != 0) && ((SHARD % (CSLOW * SIMD)) != 0))))
    begin
      $display ("hcfpga_cores: SIMD=%0d needs DIN_BITS=32, no distributed cores, no dump, and GROUP and SHARD multiples of CSLOW x SIMD", SIMD);
      $fatal;
    end
  end

  genvar i;
  generate
  if ((SIMD > 1) && (CSLOW == 2)) begin : simd2

  // Lockstep groups C-slowed by two, see bcrypt_core_simd2.v: SIMD lanes, each two virtual cores, on
  // CLK_CORE at twice CLK. A group's first SIMD virtual cores are its context 0, the next SIMD its
  // context 1. The phase and output capture follow the CSLOW=2 branch below.
  wire [NBUS-1:0] rst_bus;

  for (g = 0; g < NBUS; g = g + 1) begin : rtree
    `HC_KEEP reg r = 1'b1;

    always @(posedge CLK) r <= rst;

    assign rst_bus[g] = r;
  end

  for (i = 0; i < (NUM_CORES + 2*SIMD - 1) / (2*SIMD); i = i + 1) begin : grp
    localparam integer B  = i * 2 * SIMD;
    localparam integer NV = ((B + 2*SIMD) <= NUM_CORES) ? (2*SIMD) : (NUM_CORES - B);
    localparam integer NL = NV / 2;
    localparam integer GI = (GROUP == 0) ? ((SHARD == 0) ? 0 : (B / SHARD)) : (B / GROUP);

    `HC_KEEP reg rst_g = 1'b1;

    always @(posedge CLK) rst_g <= rst_bus[GI];

    (* keep = "true" *) reg t = 1'b0;

    always @(posedge CLK) t <= rst_g ? 1'b0 : ~t;

    reg t_d   = 1'b0;
    reg phase = 1'b0;

    wire phase_next = (t != t_d);

    `HC_KEEP reg rst_c = 1'b1;

    always @(posedge CLK_CORE)
    begin
      t_d   <= t;
      phase <= phase_next;
      rst_c <= rst_g;
    end

    wire [NV-1:0] core_rd_en;
    wire [NV-1:0] c_empty;
    wire [NV-1:0] c_dout;
    wire [NV-1:0] c_init_ready;
    wire [NV-1:0] c_crypt_ready;

    // The bus and rd_en pass one more CLK register next to the group, so a path into CLK_CORE, which
    // has one core cycle, starts beside the group and not at a register shared by several. HC_KEEP
    // keeps each group's copy: the copies have the same inputs and would otherwise be merged.
    `HC_KEEP reg [DIN_BITS-1:0] din_s   = 0;
    `HC_KEEP reg [3:0]          bwe_s   = 0;
    `HC_KEEP reg                start_s = 0;
    `HC_KEEP reg [NV-1:0]       wr_en_s = 0;
    `HC_KEEP reg [NV-1:0]       rd_en_s = 0;

    always @(posedge CLK)
    begin
      din_s   <= g_din[GI];
      bwe_s   <= g_bwe[GI];
      start_s <= g_start[GI];
      wr_en_s <= g_wr_en[GI][B +: NV];
      rd_en_s <= core_rd_en;
    end

    localparam integer NG2 = (NUM_CORES + 2*SIMD - 1) / (2*SIMD);

    bcrypt_simd2_group #(.LANES(NL), .IDLE_WAIT(SIMD_IDLE), .PD_M20K((i >= NG2 - SIMD_PD_LUT) ? 0 : 1)) g (
      .CLK(CLK_CORE), .rst(rst_c), .phase(phase), .phase_next(phase_next),
      .din(din_s), .bwe(bwe_s), .start(start_s), .wr_en(wr_en_s),
      .init_ready(c_init_ready), .crypt_ready(c_crypt_ready),
      .rd_en(rd_en_s), .empty(c_empty), .dout(c_dout)
    );

    reg [NV-1:0] init_ready_s  = {NV{1'b1}};
    reg [NV-1:0] crypt_ready_s = {NV{1'b0}};
    reg [NV-1:0] core_empty    = {NV{1'b1}};
    reg [NV-1:0] core_dout     = {NV{1'b0}};

    always @(posedge CLK)
    begin
      init_ready_s  <= c_init_ready;
      crypt_ready_s <= c_crypt_ready;
      core_empty    <= c_empty;
      core_dout     <= c_dout;
    end

    assign init_ready[B +: NV]  = init_ready_s;
    assign crypt_ready[B +: NV] = crypt_ready_s;

    genvar h;
    for (h = 0; h < NV; h = h + 1) begin : vc
      if (WITH_CMP != 0) begin : filt
        hcfpga_result_filter f (
          .CLK(CLK), .rst(rst),
          .bm_we(g_bm_we[GI]), .bm_addr(g_bm_addr[GI]), .bm_din(g_bm_din[GI]),
          .core_empty(core_empty[h]), .core_dout(core_dout[h]), .core_rd_en(core_rd_en[h]),
          .f_rd_en(rd_en[B + h]), .f_empty(empty[B + h]), .f_dout(dout[B + h])
        );
      end
      else begin : nofilt
        assign core_rd_en[h] = rd_en[B + h];
        assign empty[B + h]  = core_empty[h];
        assign dout[B + h]   = core_dout[h];
      end
    end
  end

  end
  else if (SIMD > 1) begin : simd

  // Lockstep groups of SIMD cores, see bcrypt_core_simd.v. A group sits inside one feed group and one
  // feed engine, so its lanes share one bus and are loaded one at a time. The last group may be short.
  //
  // The reset reaches the groups through a register per feed bus and one per group. HC_KEEP keeps the
  // copies apart, where merging or retiming would make one register drive the whole array again.
  wire [NBUS-1:0] rst_bus;

  for (g = 0; g < NBUS; g = g + 1) begin : rtree
    `HC_KEEP reg r = 1'b1;

    always @(posedge CLK) r <= rst;

    assign rst_bus[g] = r;
  end

  for (i = 0; i < (NUM_CORES + SIMD - 1) / SIMD; i = i + 1) begin : grp
    localparam integer B  = i * SIMD;
    localparam integer NL = ((B + SIMD) <= NUM_CORES) ? SIMD : (NUM_CORES - B);
    localparam integer GI = (GROUP == 0) ? ((SHARD == 0) ? 0 : (B / SHARD)) : (B / GROUP);

    wire [NL-1:0] c_rd_en;
    wire [NL-1:0] c_empty;
    wire [NL-1:0] c_dout;

    `HC_KEEP reg rst_g = 1'b1;

    always @(posedge CLK) rst_g <= rst_bus[GI];

    bcrypt_simd_group #(.LANES(NL), .IDLE_WAIT(SIMD_IDLE)) g (
      .CLK(CLK), .rst(rst_g),
      .din(g_din[GI]), .bwe(g_bwe[GI]), .start(g_start[GI]), .wr_en(g_wr_en[GI][B +: NL]),
      .init_ready(init_ready[B +: NL]), .crypt_ready(crypt_ready[B +: NL]),
      .rd_en(c_rd_en), .empty(c_empty), .dout(c_dout)
    );

    genvar h;
    for (h = 0; h < NL; h = h + 1) begin : vc
      if (WITH_CMP != 0) begin : filt
        hcfpga_result_filter f (
          .CLK(CLK), .rst(rst),
          .bm_we(g_bm_we[GI]), .bm_addr(g_bm_addr[GI]), .bm_din(g_bm_din[GI]),
          .core_empty(c_empty[h]), .core_dout(c_dout[h]), .core_rd_en(c_rd_en[h]),
          .f_rd_en(rd_en[B + h]), .f_empty(empty[B + h]), .f_dout(dout[B + h])
        );
      end
      else begin : nofilt
        assign c_rd_en[h]    = rd_en[B + h];
        assign empty[B + h]  = c_empty[h];
        assign dout[B + h]   = c_dout[h];
      end
    end
  end

  end
  else if (CSLOW == 2) begin : c2

  for (i = 0; i < NUM_CORES / 2; i = i + 1) begin : pair
    localparam integer V0 = 2 * i;
    localparam integer V1 = 2 * i + 1;

    localparam integer GI = (GROUP == 0) ? ((SHARD == 0) ? 0 : (V0 / SHARD)) : (V0 / GROUP);

    localparam PAIR_S_STYLE = (V0 >= (NUM_CORES - NUM_CORES_DIST)) ? "distributed" :
                              (V0 >= (NUM_CORES - NUM_CORES_DIST - NUM_CORES_URAM)) ? "ultra" : "block";

    (* keep = "true" *) reg t = 1'b0;

    always @(posedge CLK) t <= rst ? 1'b0 : ~t;

    reg t_d   = 1'b0;
    reg phase = 1'b0;

    reg rst_c = 1'b1;

    always @(posedge CLK_CORE)
    begin
      t_d   <= t;
      phase <= (t != t_d);
      rst_c <= rst;
    end

    wire [1:0] core_rd_en;
    wire [1:0] c_empty;
    wire [1:0] c_dout;
    wire [1:0] c_init_ready;
    wire [1:0] c_crypt_ready;

    bcrypt_core_c2 #(.DIN_BITS(DIN_BITS), .S_STYLE(PAIR_S_STYLE)) core (
      .CLK(CLK_CORE), .rst(rst_c), .phase(phase),
      .din(g_din[GI]), .byte_wr_en(g_bwe[GI]), .start(g_start[GI]),
      .wr_sel({g_wr_en[GI][V1], g_wr_en[GI][V0]}),
      .rd_en_vc(core_rd_en),
      .init_ready_vc(c_init_ready), .crypt_ready_vc(c_crypt_ready),
      .empty_vc(c_empty), .dout_vc(c_dout)
    );

    reg [1:0] init_ready_s  = 2'b11;
    reg [1:0] crypt_ready_s = 2'b00;
    reg [1:0] core_empty    = 2'b11;
    reg [1:0] core_dout     = 2'b00;

    always @(posedge CLK)
    begin
      init_ready_s  <= c_init_ready;
      crypt_ready_s <= c_crypt_ready;
      core_empty    <= c_empty;
      core_dout     <= c_dout;
    end

    assign init_ready[V1:V0]  = init_ready_s;
    assign crypt_ready[V1:V0] = crypt_ready_s;

    genvar h;
    for (h = 0; h < 2; h = h + 1) begin : vc
      if (WITH_CMP != 0) begin : filt
        hcfpga_result_filter f (
          .CLK(CLK), .rst(rst),
          .bm_we(g_bm_we[GI]), .bm_addr(g_bm_addr[GI]), .bm_din(g_bm_din[GI]),
          .core_empty(core_empty[h]), .core_dout(core_dout[h]), .core_rd_en(core_rd_en[h]),
          .f_rd_en(rd_en[V0 + h]), .f_empty(empty[V0 + h]), .f_dout(dout[V0 + h])
        );
      end
      else begin : nofilt
        assign core_rd_en[h]  = rd_en[V0 + h];
        assign empty[V0 + h]  = core_empty[h];
        assign dout[V0 + h]   = core_dout[h];
      end
    end
  end

  end
  else begin : c1

  for (i = 0; i < NUM_CORES; i = i + 1) begin : cores
    localparam integer GI = (GROUP == 0) ? ((SHARD == 0) ? 0 : (i / SHARD)) : (i / GROUP);

    wire [3:0] core_bwe = g_bwe[GI] & {4{g_wr_en[GI][i]}};
    wire       core_start = g_start[GI] & g_wr_en[GI][i];

    localparam CORE_S_STYLE = (i >= (NUM_CORES - NUM_CORES_DIST)) ? "distributed" : "block";

    wire core_rd_en;
    wire core_empty;
    wire core_dout;

    bcrypt_core #(.DIN_BITS(DIN_BITS), .S_STYLE(CORE_S_STYLE)) core (
      .CLK(CLK), .rst(rst), .mode_cmp(1'b0), .mode_dump(WITH_DUMP ? mode_dump : 1'b0),
      .din(g_din[GI]), .byte_wr_en(core_bwe), .start(core_start),
      .init_ready(init_ready[i]), .crypt_ready(crypt_ready[i]),
      .rd_en(core_rd_en), .empty(core_empty), .dout(core_dout)
    );

    if (WITH_CMP != 0) begin : filt
      hcfpga_result_filter f (
        .CLK(CLK), .rst(rst),
        .bm_we(g_bm_we[GI]), .bm_addr(g_bm_addr[GI]), .bm_din(g_bm_din[GI]),
        .core_empty(core_empty), .core_dout(core_dout), .core_rd_en(core_rd_en),
        .f_rd_en(rd_en[i]), .f_empty(empty[i]), .f_dout(dout[i])
      );
    end
    else begin : nofilt
      assign core_rd_en = rd_en[i];
      assign empty[i]   = core_empty;
      assign dout[i]    = core_dout;
    end
  end

  end
  endgenerate

endmodule
