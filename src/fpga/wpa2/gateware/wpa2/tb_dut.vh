// wpa2's top in the shared bench (tb_hcfpga.v): NUM_UNITS PBKDF2 pipes of RPS rounds a stage, and
// the extra registers cfg[16..20] in EXTRA_CSRS order: salt_len, salt4..7.
//
// The die temperature the thermal stop reads (XADC encoding): cfg[28] from cycle cfg[21], cfg[29]
// from cycle cfg[22], 0 again from cycle cfg[23]. With those words 0 the die stays cold.
//
// PARTS = 1 builds the top with 40-byte C2H records. The bench reads 32-byte records, so each one
// is taken apart here the way the bridge takes it apart: a result into its two parts (the second
// with flags 0x0100, PMK bytes 24..31 at bytes 4..11 and zeros to byte 27), an end-of-batch record
// into its first 32 bytes. A record of another length, or an end-of-batch record whose last 8 bytes
// are not zero, prints an ERR line.

  parameter RPS   = 2;
  parameter PARTS = 2;

  reg [31:0] dut_cycles = 0;

  always @(posedge CLK) dut_cycles <= dut_cycles + 1;

  wire [11:0] dut_die_temp = (dut_cycles < cfg[21]) ? 12'd0
                           : (dut_cycles < cfg[22]) ? cfg[28][11:0]
                           : (dut_cycles < cfg[23]) ? cfg[29][11:0]
                           :                          12'd0;

  generate
    if (PARTS == 1)
    begin : rec40
      wire [7:0] dut_m_data;
      wire       dut_m_valid;
      wire       dut_m_ready;
      wire       dut_m_last;

      hcfpga_wpa2_top #(.PIPES(NUM_UNITS), .RPS(RPS), .WITH_CMP(WITH_CMP), .PARTS(1)) dut (
        .CLK(CLK), .rst(rst),
        .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last),
        .frame_status(frame_status),
        .salt0(cfg[0]), .salt1(cfg[1]), .salt2(cfg[2]), .salt3(cfg[3]),
        .iter_count(cfg[4]),
        .cmp_bitmap(bitmap), .cmp_load(cmp_load),
        .batch_target(batch_target), .batch_arm(batch_arm),
        .pad_recs(cfg[11][15:0]),
        .retired_cnt(retired_cnt),
        .m_data(dut_m_data), .m_valid(dut_m_valid), .m_ready(dut_m_ready), .m_last(dut_m_last),
        .die_temp(dut_die_temp),
        .salt_len(cfg[16]), .salt4(cfg[17]), .salt5(cfg[18]), .salt6(cfg[19]), .salt7(cfg[20])
      );

      // Bytes 0..38 of a record collect in pk, byte j at pk[8j+15 -: 8]; byte 39 is on dut_m_data
      // when the record ends. ob holds the 32-byte records it becomes, byte 0 first.
      reg [319:0] pk    = 0;
      reg [5:0]   pcnt  = 0;
      reg [511:0] ob    = 0;
      reg [6:0]   oleft = 0;

      assign dut_m_ready = (oleft == 0);

      assign m_data  = ob[7:0];
      assign m_valid = (oleft != 0);
      assign m_last  = (oleft == 7'd1) | (oleft == 7'd33);

      // A framing reset abandons a record in the middle, as the top does.
      always @(posedge CLK)
      begin
        if (rst)
        begin
          pcnt  <= 0;
          oleft <= 0;
        end
        else if (oleft != 0)
        begin
          if (m_ready)
          begin
            ob    <= ob >> 8;
            oleft <= oleft - 1'b1;
          end
        end
        else if (dut_m_valid)
        begin
          if (dut_m_last)
          begin
            if (pcnt != 6'd39)
              $display("ERR packed record of %0d bytes", pcnt + 1);
            else if (pk[263:248] == 16'h8000)
            begin
              if ((dut_m_data != 8'h00) || (pk[319:264] != 56'd0))
                $display("ERR end-of-batch record with bytes past 31 not zero");
              ob    <= {256'd0, pk[263:8]};
              oleft <= 7'd32;
            end
            else
            begin
              ob    <= {16'h0100, pk[247:232], 128'd0, dut_m_data, pk[319:264], pk[39:8],
                        pk[263:8]};
              oleft <= 7'd64;
            end
            pcnt <= 0;
          end
          else
          begin
            pk   <= {dut_m_data, pk[319:8]};
            pcnt <= pcnt + 1'b1;
          end
        end
      end
    end
    else
    begin : rec32
      hcfpga_wpa2_top #(.PIPES(NUM_UNITS), .RPS(RPS), .WITH_CMP(WITH_CMP)) dut (
        `HCFPGA_TB_PORTS,
        .die_temp(dut_die_temp),
        .salt_len(cfg[16]), .salt4(cfg[17]), .salt5(cfg[18]), .salt6(cfg[19]), .salt7(cfg[20])
      );
    end
  endgenerate
